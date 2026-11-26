//! Paint: rasterize a layout tree into an RGBA pixel buffer.
//!
//! A pure-software renderer in the Kitesurf spirit: no GPU, no font files, no
//! platform dependency. Text uses an embedded 8x16 ASCII bitmap face scaled
//! to the computed font size (nearest-neighbor); non-ASCII glyphs draw as a
//! filled box approximation so layout extent still matches. Painting order is
//! the layout tree's box order (backgrounds and borders first per box, then
//! its text), which matches CSS painting for the non-overlapping flows the
//! layout stage produces.

use crate::browser_core::css::Color;
use crate::browser_core::layout::{BoxContent, LayoutTree};

/// An RGBA framebuffer.
#[derive(Debug, Clone)]
pub struct Canvas {
    pub width: u32,
    pub height: u32,
    /// RGBA8, row-major, `width * height * 4` bytes.
    pub pixels: Vec<u8>,
}

impl Canvas {
    /// A canvas filled with `bg`.
    pub fn new(width: u32, height: u32, bg: Color) -> Canvas {
        let (width, height) = (width.max(1), height.max(1));
        let px_count = (width as usize) * (height as usize);
        // Build one 4-byte pattern and repeat it: a single memset-style fill
        // instead of a per-pixel loop over the whole framebuffer (the canvas
        // is up to 64 MiB, so this init used to show up in rasterize time).
        let pattern = [bg.r, bg.g, bg.b, 255u8];
        let mut pixels = Vec::with_capacity(px_count * 4);
        // Fill in one pass; extend_from_slice on a growing doubling buffer
        // amortizes to a memcpy-dominated fill.
        pixels.extend_from_slice(&pattern);
        while pixels.len() < px_count * 4 {
            let take = (px_count * 4 - pixels.len()).min(pixels.len());
            let end = pixels.len();
            pixels.extend_from_within(end - take..end);
        }
        Canvas {
            width,
            height,
            pixels,
        }
    }

    #[inline]
    fn blend_pixel(&mut self, x: i32, y: i32, c: Color) {
        if c.a == 0 || x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        let idx = ((y as usize) * (self.width as usize) + (x as usize)) * 4;
        let Some(px) = self.pixels.get_mut(idx..idx + 4) else {
            return;
        };
        if c.a == 255 {
            px[0] = c.r;
            px[1] = c.g;
            px[2] = c.b;
            px[3] = 255;
        } else {
            let a = c.a as u32;
            let ia = 255 - a;
            px[0] = ((c.r as u32 * a + px[0] as u32 * ia) / 255) as u8;
            px[1] = ((c.g as u32 * a + px[1] as u32 * ia) / 255) as u8;
            px[2] = ((c.b as u32 * a + px[2] as u32 * ia) / 255) as u8;
            px[3] = 255;
        }
    }

    /// Fill an axis-aligned rect (clipped to the canvas).
    pub fn fill_rect(&mut self, x: f32, y: f32, w: f32, h: f32, c: Color) {
        if c.a == 0 || w <= 0.0 || h <= 0.0 {
            return;
        }
        let x0 = x.floor().max(0.0) as i32;
        let y0 = y.floor().max(0.0) as i32;
        let x1 = ((x + w).ceil() as i32).min(self.width as i32);
        let y1 = ((y + h).ceil() as i32).min(self.height as i32);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        if c.a == 255 {
            // Opaque fast path: write the first covered row pixel-by-pixel,
            // then memmove it into every later row (no per-fill allocation,
            // no per-pixel blend). Backgrounds and borders are almost always
            // opaque, and per-pixel blend_pixel calls here dominated raster
            // time.
            let row_px = (x1 - x0) as usize;
            let width = self.width as usize;
            let first = ((y0 as usize) * width + (x0 as usize)) * 4;
            if let Some(row) = self.pixels.get_mut(first..first + row_px * 4) {
                for px in row.chunks_exact_mut(4) {
                    px[0] = c.r;
                    px[1] = c.g;
                    px[2] = c.b;
                    px[3] = 255;
                }
            }
            for py in (y0 + 1)..y1 {
                let start = ((py as usize) * width + (x0 as usize)) * 4;
                if start + row_px * 4 <= self.pixels.len() {
                    self.pixels.copy_within(first..first + row_px * 4, start);
                }
            }
            return;
        }
        for py in y0..y1 {
            for px in x0..x1 {
                self.blend_pixel(px, py, c);
            }
        }
    }
}

/// Rasterize a layout tree onto a canvas of the layout's page size.
pub fn rasterize(tree: &LayoutTree) -> Canvas {
    rasterize_scaled(tree, 1.0)
}

/// Rasterize with a device scale factor (2.0 = retina-style).
pub fn rasterize_scaled(tree: &LayoutTree, scale: f32) -> Canvas {
    let scale = if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    };
    let w = (tree.page_width * scale).ceil().max(1.0) as u32;
    let h = (tree.page_height * scale).ceil().max(1.0) as u32;
    // Cap the buffer to keep memory bounded (Kitesurf-style cost control):
    // at most ~64 MiB of pixels.
    let (w, h) = cap_dimensions(w, h, 64 * 1024 * 1024 / 4);
    let bg = tree.canvas_background.unwrap_or(Color::WHITE);
    let mut canvas = Canvas::new(w, h, bg);

    for b in &tree.boxes {
        if !b.visible {
            continue;
        }
        let r = b.rect;
        // Background.
        if b.background.a > 0 {
            canvas.fill_rect(
                r.x * scale,
                r.y * scale,
                r.width * scale,
                r.height * scale,
                b.background,
            );
        }
        // Borders (top, right, bottom, left).
        let (bt, br, bb, bl) = (b.border.top, b.border.right, b.border.bottom, b.border.left);
        if b.border_color.a > 0 {
            if bt > 0.0 {
                canvas.fill_rect(
                    r.x * scale,
                    r.y * scale,
                    r.width * scale,
                    bt * scale,
                    b.border_color,
                );
            }
            if bb > 0.0 {
                canvas.fill_rect(
                    r.x * scale,
                    (r.bottom() - bb) * scale,
                    r.width * scale,
                    bb * scale,
                    b.border_color,
                );
            }
            if bl > 0.0 {
                canvas.fill_rect(
                    r.x * scale,
                    r.y * scale,
                    bl * scale,
                    r.height * scale,
                    b.border_color,
                );
            }
            if br > 0.0 {
                canvas.fill_rect(
                    (r.right() - br) * scale,
                    r.y * scale,
                    br * scale,
                    r.height * scale,
                    b.border_color,
                );
            }
        }
        // Text.
        if let BoxContent::Text {
            text,
            color,
            font_size,
            bold,
            monospace,
            ..
        } = &b.content
        {
            draw_text(
                &mut canvas,
                text,
                r.x * scale,
                r.y * scale,
                font_size * scale,
                *color,
                *bold,
                *monospace,
            );
        }
        // Replaced content (<img>): blit decoded pixels scaled into the box,
        // or a light placeholder frame when the image did not decode.
        if let BoxContent::Image { pixels } = &b.content {
            match pixels {
                Some(img) => draw_image(
                    &mut canvas,
                    img,
                    r.x * scale,
                    r.y * scale,
                    r.width * scale,
                    r.height * scale,
                ),
                None => {
                    let frame = Color {
                        r: 200,
                        g: 200,
                        b: 200,
                        a: 255,
                    };
                    canvas.fill_rect(
                        r.x * scale,
                        r.y * scale,
                        r.width * scale,
                        1.0f32.max(scale),
                        frame,
                    );
                    canvas.fill_rect(
                        r.x * scale,
                        (r.bottom() - 1.0) * scale,
                        r.width * scale,
                        1.0f32.max(scale),
                        frame,
                    );
                    canvas.fill_rect(
                        r.x * scale,
                        r.y * scale,
                        1.0f32.max(scale),
                        r.height * scale,
                        frame,
                    );
                    canvas.fill_rect(
                        (r.right() - 1.0) * scale,
                        r.y * scale,
                        1.0f32.max(scale),
                        r.height * scale,
                        frame,
                    );
                }
            }
        }
    }
    canvas
}

/// Blit a decoded RGBA image into the destination rect with nearest-neighbour
/// scaling and alpha blending. Panic-free: every access is bounds-checked.
fn draw_image(
    canvas: &mut Canvas,
    img: &crate::browser_core::image::DecodedImage,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
) {
    if w <= 0.0 || h <= 0.0 || img.width == 0 || img.height == 0 {
        return;
    }
    let x0 = x.floor().max(0.0) as i32;
    let y0 = y.floor().max(0.0) as i32;
    let x1 = ((x + w).ceil() as i32).min(canvas.width as i32);
    let y1 = ((y + h).ceil() as i32).min(canvas.height as i32);
    for py in y0..y1 {
        // Source row via nearest-neighbour mapping.
        let sy = (((py as f32 - y) / h) * img.height as f32) as usize;
        let sy = sy.min(img.height.saturating_sub(1));
        for px in x0..x1 {
            let sx = (((px as f32 - x) / w) * img.width as f32) as usize;
            let sx = sx.min(img.width.saturating_sub(1));
            let si = (sy.saturating_mul(img.width).saturating_add(sx)).saturating_mul(4);
            let (Some(r), Some(g), Some(b), Some(a)) = (
                img.rgba.get(si).copied(),
                img.rgba.get(si.saturating_add(1)).copied(),
                img.rgba.get(si.saturating_add(2)).copied(),
                img.rgba.get(si.saturating_add(3)).copied(),
            ) else {
                continue;
            };
            if a == 0 {
                continue;
            }
            canvas.blend_pixel(px, py, Color { r, g, b, a });
        }
    }
}

fn cap_dimensions(w: u32, h: u32, max_pixels: usize) -> (u32, u32) {
    let px = (w as usize).saturating_mul(h as usize);
    if px <= max_pixels || px == 0 {
        return (w, h);
    }
    let ratio = (max_pixels as f64 / px as f64).sqrt();
    (
        ((w as f64 * ratio) as u32).max(1),
        ((h as f64 * ratio) as u32).max(1),
    )
}

// Embedded 8x16 bitmap font (ASCII 0x20..0x7E), classic VGA-style glyphs.
// Each glyph is 16 bytes, one byte per row, MSB = leftmost pixel.

/// Glyph cell width in font units.
pub const FONT_W: usize = 8;
/// Glyph cell height in font units.
pub const FONT_H: usize = 16;

/// Draw a text run at (x, y) with the box's line height; the glyph baseline
/// sits proportionally inside the box like a browser's text box.
#[allow(clippy::too_many_arguments)]
pub fn draw_text(
    canvas: &mut Canvas,
    text: &str,
    x: f32,
    y: f32,
    font_size: f32,
    color: Color,
    bold: bool,
    monospace: bool,
) {
    if font_size < 0.5 {
        // `font-size: 0` text has no ink.
        return;
    }
    let advance_frac = if monospace {
        crate::browser_core::layout::MONO_ADVANCE
    } else {
        crate::browser_core::layout::GLYPH_ADVANCE
    };
    let bold_factor = if bold { 1.05 } else { 1.0 };
    let advance = advance_frac * font_size * bold_factor;
    // Glyphs render at ~font_size tall; cell scale maps 16 rows onto it.
    let sy = font_size / FONT_H as f32;
    let sx = advance / FONT_W as f32;
    let mut pen_x = x;
    for ch in text.chars() {
        let wide = crate::browser_core::layout::is_wide(ch);
        let adv = if wide { advance * 2.0 } else { advance };
        if let Some(glyph) = glyph_bitmap(ch) {
            for (row, bits) in glyph.iter().enumerate() {
                if *bits == 0 {
                    continue;
                }
                for col in 0..FONT_W {
                    if bits & (0x80 >> col) != 0 {
                        // Scale each font pixel to a rect.
                        let px = pen_x + col as f32 * sx;
                        let py = y + row as f32 * sy;
                        canvas.fill_rect(px, py, sx.max(1.0), sy.max(1.0), color);
                        if bold {
                            canvas.fill_rect(px + 1.0, py, sx.max(1.0), sy.max(1.0), color);
                        }
                    }
                }
            }
        } else if !ch.is_whitespace() {
            // Non-ASCII: draw a box glyph so extent is visible.
            let inset = font_size * 0.12;
            canvas.fill_rect(
                pen_x + inset * 0.5,
                y + inset,
                adv - inset,
                font_size - inset * 1.6,
                Color {
                    r: color.r,
                    g: color.g,
                    b: color.b,
                    a: (color.a / 2).max(64),
                },
            );
        }
        pen_x += adv;
    }
}

/// The 8x16 bitmap for an ASCII char, if we have one.
fn glyph_bitmap(ch: char) -> Option<&'static [u8; 16]> {
    let idx = ch as usize;
    if !(0x20..=0x7E).contains(&idx) {
        return None;
    }
    FONT_8X16.get(idx - 0x20)
}

/// VGA-derived 8x16 font, printable ASCII. Public domain bitmaps.
pub static FONT_8X16: [[u8; 16]; 95] = [
    // 0x20 ' '
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    // 0x21 '!'
    [0,0,0x18,0x3C,0x3C,0x3C,0x18,0x18,0x18,0,0x18,0x18,0,0,0,0],
    // 0x22 '"'
    [0,0x66,0x66,0x66,0x24,0,0,0,0,0,0,0,0,0,0,0],
    // 0x23 '#'
    [0,0,0,0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0,0,0,0],
    // 0x24 '$'
    [0x18,0x18,0x7C,0xC6,0xC2,0xC0,0x7C,0x06,0x06,0x86,0xC6,0x7C,0x18,0x18,0,0],
    // 0x25 '%'
    [0,0,0,0,0xC2,0xC6,0x0C,0x18,0x30,0x60,0xC6,0x86,0,0,0,0],
    // 0x26 '&'
    [0,0,0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0xCC,0xCC,0x76,0,0,0,0],
    // 0x27 '''
    [0,0x30,0x30,0x30,0x60,0,0,0,0,0,0,0,0,0,0,0],
    // 0x28 '('
    [0,0,0x0C,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0C,0,0,0,0],
    // 0x29 ')'
    [0,0,0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0,0,0,0],
    // 0x2A '*'
    [0,0,0,0,0,0x66,0x3C,0xFF,0x3C,0x66,0,0,0,0,0,0],
    // 0x2B '+'
    [0,0,0,0,0,0x18,0x18,0x7E,0x18,0x18,0,0,0,0,0,0],
    // 0x2C ','
    [0,0,0,0,0,0,0,0,0,0,0x18,0x18,0x18,0x30,0,0],
    // 0x2D '-'
    [0,0,0,0,0,0,0,0x7E,0,0,0,0,0,0,0,0],
    // 0x2E '.'
    [0,0,0,0,0,0,0,0,0,0,0x18,0x18,0,0,0,0],
    // 0x2F '/'
    [0,0,0,0,0x02,0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0,0,0,0],
    // 0x30 '0'
    [0,0,0x38,0x6C,0xC6,0xC6,0xD6,0xD6,0xC6,0xC6,0x6C,0x38,0,0,0,0],
    // 0x31 '1'
    [0,0,0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0],
    // 0x32 '2'
    [0,0,0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xC0,0xC6,0xFE,0,0,0,0],
    // 0x33 '3'
    [0,0,0x7C,0xC6,0x06,0x06,0x3C,0x06,0x06,0x06,0xC6,0x7C,0,0,0,0],
    // 0x34 '4'
    [0,0,0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0x0C,0x1E,0,0,0,0],
    // 0x35 '5'
    [0,0,0xFE,0xC0,0xC0,0xC0,0xFC,0x06,0x06,0x06,0xC6,0x7C,0,0,0,0],
    // 0x36 '6'
    [0,0,0x38,0x60,0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x37 '7'
    [0,0,0xFE,0xC6,0x06,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0,0,0,0],
    // 0x38 '8'
    [0,0,0x7C,0xC6,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x39 '9'
    [0,0,0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x06,0x06,0x0C,0x78,0,0,0,0],
    // 0x3A ':'
    [0,0,0,0,0x18,0x18,0,0,0,0x18,0x18,0,0,0,0,0],
    // 0x3B ';'
    [0,0,0,0,0x18,0x18,0,0,0,0x18,0x18,0x30,0,0,0,0],
    // 0x3C '<'
    [0,0,0,0x06,0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x06,0,0,0,0],
    // 0x3D '='
    [0,0,0,0,0,0x7E,0,0,0x7E,0,0,0,0,0,0,0],
    // 0x3E '>'
    [0,0,0,0x60,0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x60,0,0,0,0],
    // 0x3F '?'
    [0,0,0x7C,0xC6,0xC6,0x0C,0x18,0x18,0x18,0,0x18,0x18,0,0,0,0],
    // 0x40 '@'
    [0,0,0x7C,0xC6,0xC6,0xDE,0xDE,0xDE,0xDC,0xC0,0xC2,0x7C,0,0,0,0],
    // 0x41 'A'
    [0,0,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0,0,0,0],
    // 0x42 'B'
    [0,0,0xFC,0x66,0x66,0x66,0x7C,0x66,0x66,0x66,0x66,0xFC,0,0,0,0],
    // 0x43 'C'
    [0,0,0x3C,0x66,0xC2,0xC0,0xC0,0xC0,0xC0,0xC2,0x66,0x3C,0,0,0,0],
    // 0x44 'D'
    [0,0,0xF8,0x6C,0x66,0x66,0x66,0x66,0x66,0x66,0x6C,0xF8,0,0,0,0],
    // 0x45 'E'
    [0,0,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x62,0x66,0xFE,0,0,0,0],
    // 0x46 'F'
    [0,0,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x60,0x60,0xF0,0,0,0,0],
    // 0x47 'G'
    [0,0,0x3C,0x66,0xC2,0xC0,0xC0,0xDE,0xC6,0xC6,0x66,0x3A,0,0,0,0],
    // 0x48 'H'
    [0,0,0xC6,0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0],
    // 0x49 'I'
    [0,0,0x3C,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0],
    // 0x4A 'J'
    [0,0,0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0xCC,0xCC,0x78,0,0,0,0],
    // 0x4B 'K'
    [0,0,0xE6,0x66,0x66,0x6C,0x78,0x78,0x6C,0x66,0x66,0xE6,0,0,0,0],
    // 0x4C 'L'
    [0,0,0xF0,0x60,0x60,0x60,0x60,0x60,0x60,0x62,0x66,0xFE,0,0,0,0],
    // 0x4D 'M'
    [0,0,0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0],
    // 0x4E 'N'
    [0,0,0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0xC6,0xC6,0,0,0,0],
    // 0x4F 'O'
    [0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x50 'P'
    [0,0,0xFC,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0xF0,0,0,0,0],
    // 0x51 'Q'
    [0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x0C,0x0E,0,0],
    // 0x52 'R'
    [0,0,0xFC,0x66,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0xE6,0,0,0,0],
    // 0x53 'S'
    [0,0,0x7C,0xC6,0xC6,0x60,0x38,0x0C,0x06,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x54 'T'
    [0,0,0x7E,0x7E,0x5A,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0],
    // 0x55 'U'
    [0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x56 'V'
    [0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0],
    // 0x57 'W'
    [0,0,0xC6,0xC6,0xC6,0xC6,0xD6,0xD6,0xD6,0xFE,0xEE,0x6C,0,0,0,0],
    // 0x58 'X'
    [0,0,0xC6,0xC6,0x6C,0x7C,0x38,0x38,0x7C,0x6C,0xC6,0xC6,0,0,0,0],
    // 0x59 'Y'
    [0,0,0x66,0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x18,0x3C,0,0,0,0],
    // 0x5A 'Z'
    [0,0,0xFE,0xC6,0x86,0x0C,0x18,0x30,0x60,0xC2,0xC6,0xFE,0,0,0,0],
    // 0x5B '['
    [0,0,0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0,0,0,0],
    // 0x5C '\'
    [0,0,0,0x80,0xC0,0xE0,0x70,0x38,0x1C,0x0E,0x06,0x02,0,0,0,0],
    // 0x5D ']'
    [0,0,0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0,0,0,0],
    // 0x5E '^'
    [0x10,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0,0,0,0,0],
    // 0x5F '_'
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0xFF,0,0],
    // 0x60 '`'
    [0x30,0x30,0x18,0,0,0,0,0,0,0,0,0,0,0,0,0],
    // 0x61 'a'
    [0,0,0,0,0,0x78,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0,0,0,0],
    // 0x62 'b'
    [0,0,0xE0,0x60,0x60,0x78,0x6C,0x66,0x66,0x66,0x66,0x7C,0,0,0,0],
    // 0x63 'c'
    [0,0,0,0,0,0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0,0,0,0],
    // 0x64 'd'
    [0,0,0x1C,0x0C,0x0C,0x3C,0x6C,0xCC,0xCC,0xCC,0xCC,0x76,0,0,0,0],
    // 0x65 'e'
    [0,0,0,0,0,0x7C,0xC6,0xFE,0xC0,0xC0,0xC6,0x7C,0,0,0,0],
    // 0x66 'f'
    [0,0,0x38,0x6C,0x64,0x60,0xF0,0x60,0x60,0x60,0x60,0xF0,0,0,0,0],
    // 0x67 'g'
    [0,0,0,0,0,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0xCC,0x78,0],
    // 0x68 'h'
    [0,0,0xE0,0x60,0x60,0x6C,0x76,0x66,0x66,0x66,0x66,0xE6,0,0,0,0],
    // 0x69 'i'
    [0,0,0x18,0x18,0,0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0],
    // 0x6A 'j'
    [0,0,0x06,0x06,0,0x0E,0x06,0x06,0x06,0x06,0x06,0x06,0x66,0x66,0x3C,0],
    // 0x6B 'k'
    [0,0,0xE0,0x60,0x60,0x66,0x6C,0x78,0x78,0x6C,0x66,0xE6,0,0,0,0],
    // 0x6C 'l'
    [0,0,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0],
    // 0x6D 'm'
    [0,0,0,0,0,0xEC,0xFE,0xD6,0xD6,0xD6,0xD6,0xC6,0,0,0,0],
    // 0x6E 'n'
    [0,0,0,0,0,0xDC,0x66,0x66,0x66,0x66,0x66,0x66,0,0,0,0],
    // 0x6F 'o'
    [0,0,0,0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0],
    // 0x70 'p'
    [0,0,0,0,0,0xDC,0x66,0x66,0x66,0x66,0x66,0x7C,0x60,0x60,0xF0,0],
    // 0x71 'q'
    [0,0,0,0,0,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0x0C,0x1E,0],
    // 0x72 'r'
    [0,0,0,0,0,0xDC,0x76,0x66,0x60,0x60,0x60,0xF0,0,0,0,0],
    // 0x73 's'
    [0,0,0,0,0,0x7C,0xC6,0x60,0x38,0x0C,0xC6,0x7C,0,0,0,0],
    // 0x74 't'
    [0,0,0x10,0x30,0x30,0xFC,0x30,0x30,0x30,0x30,0x36,0x1C,0,0,0,0],
    // 0x75 'u'
    [0,0,0,0,0,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x76,0,0,0,0],
    // 0x76 'v'
    [0,0,0,0,0,0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0,0,0,0],
    // 0x77 'w'
    [0,0,0,0,0,0xC6,0xC6,0xD6,0xD6,0xD6,0xFE,0x6C,0,0,0,0],
    // 0x78 'x'
    [0,0,0,0,0,0xC6,0x6C,0x38,0x38,0x38,0x6C,0xC6,0,0,0,0],
    // 0x79 'y'
    [0,0,0,0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0xF8,0],
    // 0x7A 'z'
    [0,0,0,0,0,0xFE,0xCC,0x18,0x30,0x60,0xC6,0xFE,0,0,0,0],
    // 0x7B '{'
    [0,0,0x0E,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x18,0x0E,0,0,0,0],
    // 0x7C '|'
    [0,0,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0,0,0],
    // 0x7D '}'
    [0,0,0x70,0x18,0x18,0x18,0x0E,0x18,0x18,0x18,0x18,0x70,0,0,0,0],
    // 0x7E '~'
    [0,0,0x76,0xDC,0,0,0,0,0,0,0,0,0,0,0,0],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_core::layout::{BoxContent, LayoutBox, LayoutTree, Rect};
    use crate::browser_core::style::ResolvedEdges;

    fn tree_with(boxes: Vec<LayoutBox>, w: f32, h: f32) -> LayoutTree {
        LayoutTree {
            boxes,
            page_width: w,
            page_height: h,
            canvas_background: None,
        }
    }

    #[test]
    fn fills_background() {
        let t = tree_with(
            vec![LayoutBox {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 4.0,
                    height: 4.0,
                },
                node: None,
                content: BoxContent::Block,
                background: Color::rgb(255, 0, 0),
                border_color: Color::TRANSPARENT,
                border: ResolvedEdges::default(),
                visible: true,
            }],
            4.0,
            4.0,
        );
        let c = rasterize(&t);
        assert_eq!(c.width, 4);
        assert_eq!(c.height, 4);
        assert_eq!(&c.pixels[0..4], &[255, 0, 0, 255]);
    }

    #[test]
    fn hidden_boxes_do_not_paint() {
        let t = tree_with(
            vec![LayoutBox {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 4.0,
                    height: 4.0,
                },
                node: None,
                content: BoxContent::Block,
                background: Color::rgb(255, 0, 0),
                border_color: Color::TRANSPARENT,
                border: ResolvedEdges::default(),
                visible: false,
            }],
            4.0,
            4.0,
        );
        let c = rasterize(&t);
        assert_eq!(&c.pixels[0..4], &[255, 255, 255, 255]);
    }

    #[test]
    fn text_paints_some_ink() {
        let t = tree_with(
            vec![LayoutBox {
                rect: Rect {
                    x: 0.0,
                    y: 0.0,
                    width: 100.0,
                    height: 20.0,
                },
                node: None,
                content: BoxContent::Text {
                    text: "Hi".into(),
                    color: Color::BLACK,
                    font_size: 16.0,
                    bold: false,
                    italic: false,
                    monospace: false,
                },
                background: Color::TRANSPARENT,
                border_color: Color::TRANSPARENT,
                border: ResolvedEdges::default(),
                visible: true,
            }],
            100.0,
            20.0,
        );
        let c = rasterize(&t);
        let dark = c
            .pixels
            .chunks_exact(4)
            .filter(|p| p[0] < 128 && p[1] < 128 && p[2] < 128)
            .count();
        assert!(dark > 10, "expected glyph ink, got {dark} dark pixels");
    }

    #[test]
    fn alpha_blending() {
        let mut c = Canvas::new(1, 1, Color::WHITE);
        c.fill_rect(
            0.0,
            0.0,
            1.0,
            1.0,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 128,
            },
        );
        // ~50% gray
        assert!(c.pixels[0] > 100 && c.pixels[0] < 150);
    }

    #[test]
    fn dimension_cap() {
        let (w, h) = cap_dimensions(100_000, 100_000, 1_000_000);
        assert!((w as usize) * (h as usize) <= 1_000_000);
        assert!(w >= 1 && h >= 1);
    }

    #[test]
    fn zero_sized_tree_is_safe() {
        let t = tree_with(vec![], 0.0, 0.0);
        let c = rasterize(&t);
        assert_eq!(c.width, 1);
        assert_eq!(c.height, 1);
    }
}
