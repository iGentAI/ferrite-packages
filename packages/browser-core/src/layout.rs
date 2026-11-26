//! Layout: block and inline flow over the styled DOM.
//!
//! Produces a tree of positioned boxes (`LayoutBox`) with absolute pixel
//! coordinates. The model implemented:
//!
//! * block boxes stack vertically inside their containing block, honoring
//!   margins (with sibling margin collapsing), borders, padding, explicit
//!   widths/heights and `auto` centering;
//! * inline content (text runs and inline elements) flows into line boxes
//!   with greedy word wrapping against the containing width, honoring
//!   `text-align`, `white-space: pre`, font size/weight and line height;
//! * `display: none` subtrees produce no boxes; `visibility: hidden` boxes
//!   are laid out but marked invisible (they occupy space, paint nothing).
//!
//! Text metrics use a fixed-advance approximation (glyph width as a fraction
//! of font size) — the same trade Kitesurf makes: predictable cost over
//! pixel-perfect shaping. The paint stage uses the same metrics, so layout
//! and raster always agree.

use std::collections::HashMap;

use crate::browser_core::css::Color;
use crate::browser_core::dom::{Document, NodeData, NodeId};
use crate::browser_core::style::{
    ComputedStyle, Display, Float, GridColumns, Length, ResolvedEdges, TextAlign, WhiteSpace,
};

/// Average glyph advance as a fraction of font size for the built-in font.
///
/// Measured against Chrome rather than the 8x16 bitmap's natural 0.5
/// aspect: on the Chrome-referenced site corpus Chrome's default faces
/// advance 0.415 em (serif), 0.452 em (sans) and 0.489 em (monospace) per
/// character of English text. The earlier 0.60 wrapped every line ~35%
/// early and made whole pages 1.3-2x taller than Chrome's. 0.45 is the
/// sans value most sites resolve to; the glyph bitmap is scaled to it.
pub const GLYPH_ADVANCE: f32 = 0.45;
/// Monospace advance fraction (Chrome: 0.489 em for its default mono face).
pub const MONO_ADVANCE: f32 = 0.50;

/// Measure the width in px of `text` at `font_size`.
pub fn text_width(text: &str, font_size: f32, monospace: bool, bold: bool) -> f32 {
    let adv = if monospace {
        MONO_ADVANCE
    } else {
        GLYPH_ADVANCE
    };
    let bold_factor = if bold { 1.05 } else { 1.0 };
    // Count scalar values; CJK and fullwidth take a double advance.
    let mut units = 0.0f32;
    for ch in text.chars() {
        units += if is_wide(ch) { 2.0 } else { 1.0 };
    }
    units * adv * font_size * bold_factor
}

pub fn is_wide(ch: char) -> bool {
    let c = ch as u32;
    (0x1100..=0x115F).contains(&c)
        || (0x2E80..=0xA4CF).contains(&c)
        || (0xAC00..=0xD7A3).contains(&c)
        || (0xF900..=0xFAFF).contains(&c)
        || (0xFF00..=0xFF60).contains(&c)
        || (0x20000..=0x3FFFD).contains(&c)
}

/// Public alias used by the paint stage so text advance and glyph placement
/// share one definition of "wide".
pub fn is_wide_char(ch: char) -> bool {
    is_wide(ch)
}

/// A rectangle in device pixels.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    pub fn right(&self) -> f32 {
        self.x + self.width
    }
    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }
}

/// What a layout box paints.
#[derive(Debug, Clone)]
pub enum BoxContent {
    /// A block-level or anonymous container.
    Block,
    /// A run of text on one line.
    Text {
        text: String,
        color: Color,
        font_size: f32,
        bold: bool,
        italic: bool,
        monospace: bool,
    },
    /// A replaced element (`<img>`): decoded RGBA pixels shared with the
    /// page's image store. `None` pixels paint a placeholder box.
    Image {
        pixels: Option<std::rc::Rc<crate::browser_core::image::DecodedImage>>,
    },
}

/// One positioned box in the layout tree (flattened; children by index).
#[derive(Debug, Clone)]
pub struct LayoutBox {
    /// Border-box rectangle in absolute page coordinates.
    pub rect: Rect,
    /// The DOM node this box belongs to (anonymous boxes inherit the parent's).
    pub node: Option<NodeId>,
    pub content: BoxContent,
    pub background: Color,
    pub border_color: Color,
    pub border: ResolvedEdges,
    /// False for `visibility: hidden` boxes: laid out, not painted.
    pub visible: bool,
}

/// The finished layout: boxes in paint order plus the page extent.
#[derive(Debug, Clone, Default)]
pub struct LayoutTree {
    pub boxes: Vec<LayoutBox>,
    pub page_width: f32,
    pub page_height: f32,
    /// The canvas backdrop: per CSS, the body's (or html's) background
    /// propagates to the whole canvas. `None` paints white.
    pub canvas_background: Option<Color>,
}

/// Lay out a styled document into `viewport_width` px.
pub fn layout_tree(
    doc: &Document,
    styles: &HashMap<NodeId, ComputedStyle>,
    viewport_width: f32,
) -> LayoutTree {
    let empty = HashMap::new();
    layout_tree_with_images(doc, styles, viewport_width, &empty)
}

/// Lay out with decoded images available for `<img>` intrinsic sizing and
/// painting. Keys are the raw `src` attribute values.
pub fn layout_tree_with_images(
    doc: &Document,
    styles: &HashMap<NodeId, ComputedStyle>,
    viewport_width: f32,
    images: &HashMap<String, std::rc::Rc<crate::browser_core::image::DecodedImage>>,
) -> LayoutTree {
    let mut ctx = LayoutCtx {
        doc,
        styles,
        images,
        out: Vec::new(),
    };
    let root_style = ComputedStyle::default();
    let body = doc.find_tag("body");
    let start = body
        .or_else(|| doc.document_element())
        .unwrap_or(NodeId::DOCUMENT);

    // Canvas background propagation: body's background, else html's.
    let canvas_background = body
        .and_then(|b| styles.get(&b))
        .filter(|s| s.background.a > 0)
        .map(|s| s.background)
        .or_else(|| {
            doc.document_element()
                .and_then(|h| styles.get(&h))
                .filter(|s| s.background.a > 0)
                .map(|s| s.background)
        });

    // The body's own box gets laid out as a block child of the viewport.
    let mut cursor_y = 0.0f32;
    let height = ctx.layout_block(start, &root_style, 0.0, &mut cursor_y, viewport_width);

    // The document height is the extent of the CONTENT, not the root's
    // border box: a `body { height: 100vh }` page (19 of the 512 sites in
    // the Chrome-referenced corpus) overflows its body, and Chrome's
    // scrollHeight — the height a screenshot covers — follows the
    // overflow. In-flow and absolutely positioned boxes both count.
    let content_bottom = ctx
        .out
        .iter()
        .map(|b| b.rect.bottom())
        .fold(0.0f32, f32::max);
    let page_height = height.max(cursor_y).max(content_bottom).max(1.0);
    LayoutTree {
        boxes: ctx.out,
        page_width: viewport_width,
        page_height,
        canvas_background,
    }
}

struct LayoutCtx<'a> {
    doc: &'a Document,
    styles: &'a HashMap<NodeId, ComputedStyle>,
    images: &'a HashMap<String, std::rc::Rc<crate::browser_core::image::DecodedImage>>,
    out: Vec<LayoutBox>,
}

/// How a row container distributes its children horizontally.
#[derive(Clone, Copy, PartialEq)]
enum RowMode {
    /// `display: flex` (row direction); `wrap` per `flex-wrap`.
    Flex { wrap: bool },
    /// `display: grid` with this many equal columns.
    Grid(usize),
    /// A run of consecutive floated siblings.
    Floats,
}

/// A pending inline item before line breaking.
enum InlineItem {
    Word {
        text: String,
        width: f32,
        style_of: NodeId,
    },
    Space {
        width: f32,
        style_of: NodeId,
    },
    /// An atomic inline form control (`input`, `button`, `select`,
    /// `textarea`): laid out as one replaced box of intrinsic size, with an
    /// optional visible label (a button's caption, an input's value).
    /// `plain` replaced elements (`iframe`, `video`, `canvas`, `svg`,
    /// `embed`, `object`) take their space without control chrome.
    Replaced {
        node: NodeId,
        width: f32,
        height: f32,
        label: Option<String>,
        plain: bool,
    },
    /// An inline `<img>` (the common case: an image inside a link or a
    /// span). Sized like a block-level image; painted from `pixels`.
    Image {
        node: NodeId,
        width: f32,
        height: f32,
        pixels: Option<std::rc::Rc<crate::browser_core::image::DecodedImage>>,
    },
    HardBreak,
}

/// Replaced elements that take a box of their own without control chrome.
/// Chrome gives `iframe`/`video`/`canvas`/`embed`/`object` a 300x150
/// default; an inline `<svg>` is sized by its attributes or CSS.
fn is_plain_replaced(tag: &str) -> bool {
    matches!(
        tag,
        "iframe" | "video" | "canvas" | "embed" | "object" | "svg" | "math"
    )
}

/// Form controls laid out as atomic replaced boxes.
fn is_control(tag: &str) -> bool {
    matches!(tag, "input" | "textarea" | "select" | "button")
}

/// Intrinsic size and visible label of a form control, following the UA
/// defaults browsers ship: text fields are `size` characters wide, check
/// boxes and radios 13px squares, buttons wrap their caption.
fn control_metrics(
    doc: &Document,
    node: NodeId,
    s: &ComputedStyle,
) -> Option<(f32, f32, Option<String>)> {
    let el = doc.node(node).as_element()?;
    let line = s.font_size * s.line_height;
    let char_w = s.font_size * 0.55;
    let attr_num = |name: &str, default: f32| {
        el.attr(name)
            .and_then(|v| v.trim().parse::<f32>().ok())
            .filter(|v| *v > 0.0)
            .unwrap_or(default)
    };
    let fixed = |w: Option<f32>, h: Option<f32>, dw: f32, dh: f32| {
        // The UA defaults are border-box sizes. An author `width`/`height`
        // is the CONTENT size (content-box), so the control's border box
        // grows by its padding and border, as for every other block.
        let pad = s.padding.resolve(dw.max(1.0));
        let brd = s.border_width.resolve(dw.max(1.0));
        let bw = w.map(|w| w.max(0.0) + pad.left + pad.right + brd.left + brd.right);
        let bh = h.map(|h| h.max(0.0) + pad.top + pad.bottom + brd.top + brd.bottom);
        (bw.unwrap_or(dw).max(0.0), bh.unwrap_or(dh).max(0.0))
    };
    let (css_w, css_h) = (
        match s.width {
            Length::Px(w) => Some(w),
            _ => None,
        },
        match s.height {
            Length::Px(h) => Some(h),
            _ => None,
        },
    );
    match el.tag.as_str() {
        "input" => {
            let ty = el.attr("type").unwrap_or("text").to_ascii_lowercase();
            match ty.as_str() {
                "hidden" => None,
                "checkbox" | "radio" => {
                    let (w, h) = fixed(css_w, css_h, 13.0, 13.0);
                    Some((w, h, None))
                }
                "submit" | "button" | "reset" | "image" => {
                    let label = el
                        .attr("value")
                        .map(str::to_string)
                        .unwrap_or_else(|| "Submit".to_string());
                    let tw = text_width(&label, s.font_size, s.monospace, s.font_weight.is_bold());
                    let (w, h) = fixed(css_w, css_h, tw + 16.0, line + 6.0);
                    Some((w, h, Some(label)))
                }
                _ => {
                    let cols = attr_num("size", 20.0);
                    let (w, h) = fixed(css_w, css_h, cols * char_w + 8.0, line + 6.0);
                    let label = el
                        .attr("value")
                        .filter(|v| !v.is_empty())
                        .or_else(|| el.attr("placeholder"))
                        .map(str::to_string);
                    Some((w, h, label))
                }
            }
        }
        "textarea" => {
            let cols = attr_num("cols", 20.0);
            let rows = attr_num("rows", 2.0);
            let (w, h) = fixed(css_w, css_h, cols * char_w + 8.0, rows * line + 6.0);
            let text = doc.text_content(node);
            let label = text.lines().next().map(str::to_string).filter(|l| !l.is_empty());
            Some((w, h, label))
        }
        "select" => {
            let mut widest = 0.0f32;
            let mut first: Option<String> = None;
            let mut selected: Option<String> = None;
            for o in doc.descendants(node) {
                if let Some(oe) = doc.node(o).as_element().filter(|e| e.tag == "option") {
                    let t = doc.text_content(o).split_whitespace().collect::<Vec<_>>().join(" ");
                    widest = widest.max(text_width(&t, s.font_size, s.monospace, false));
                    if first.is_none() {
                        first = Some(t.clone());
                    }
                    // The displayed option is the first `selected` one, else
                    // the first option (HTML selectedness setting algorithm).
                    if selected.is_none() && oe.attr("selected").is_some() {
                        selected = Some(t);
                    }
                }
            }
            let (w, h) = fixed(css_w, css_h, widest + 28.0, line + 6.0);
            Some((w, h, selected.or(first)))
        }
        "button" => {
            let label = doc
                .text_content(node)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let tw = text_width(&label, s.font_size, s.monospace, s.font_weight.is_bold());
            let (w, h) = fixed(css_w, css_h, tw + 16.0, line + 6.0);
            Some((w, h, Some(label).filter(|l| !l.is_empty())))
        }
        t if is_plain_replaced(t) => {
            // CSS size first, then the width/height attributes, then the
            // 300x150 default every browser gives an unsized replaced box.
            // An attribute that is a percentage cannot resolve here and is
            // ignored (the CSS path handles percentages for images).
            let attr_px = |name: &str| {
                el.attr(name)
                    .map(str::trim)
                    .filter(|v| !v.ends_with('%'))
                    .and_then(|v| v.trim_end_matches("px").parse::<f32>().ok())
                    .filter(|v| *v >= 0.0)
            };
            let (aw, ah) = (attr_px("width"), attr_px("height"));
            let (dw, dh) = match (aw, ah) {
                (Some(w), Some(h)) => (w, h),
                (Some(w), None) => (w, if t == "svg" { w } else { 150.0 }),
                (None, Some(h)) => (if t == "svg" { h } else { 300.0 }, h),
                (None, None) => (300.0, 150.0),
            };
            let (w, h) = fixed(css_w.or(Some(dw)), css_h.or(Some(dh)), dw, dh);
            Some((w, h, None))
        }
        _ => None,
    }
}

/// The size of an `<img>` box: CSS `width`/`height` (px or percent of
/// the containing width) over the `width`/`height` attributes over the
/// decoded intrinsic size over the 16x16 broken-image placeholder; a
/// missing dimension keeps the aspect ratio; `max-width` clamps the
/// result (and scales the height with it), as does the containing width.
fn image_size(
    el: &crate::browser_core::dom::ElementData,
    s: &ComputedStyle,
    pixels: Option<&std::rc::Rc<crate::browser_core::image::DecodedImage>>,
    avail_width: f32,
) -> (f32, f32) {
    let attr = |name: &str| {
        el.attr(name)
            .map(str::trim)
            .filter(|v| !v.ends_with('%'))
            .and_then(|v| v.trim_end_matches("px").parse::<f32>().ok())
            .filter(|v| *v >= 0.0)
    };
    let css_w = match s.width {
        Length::Px(v) => Some(v.max(0.0)),
        Length::Percent(p) => Some((avail_width * p / 100.0).max(0.0)),
        Length::Auto => None,
    };
    // A percentage height resolves against the containing block's height,
    // which is auto in this flow: it behaves as `auto` (CSS 2.1 §10.5).
    let css_h = match s.height {
        Length::Px(v) => Some(v.max(0.0)),
        _ => None,
    };
    // The aspect ratio: the decoded image's, else the width/height
    // attribute pair's (the `<img width=1681 height=1681>` hint an author
    // sizes with `width: 100%; height: auto`), else square.
    let (iw, ih) = match (pixels, attr("width"), attr("height")) {
        (Some(p), _, _) => (p.width as f32, p.height as f32),
        (None, Some(aw), Some(ah)) if aw > 0.0 && ah > 0.0 => (aw, ah),
        _ => (16.0, 16.0),
    };
    // Author CSS wins over the presentational attributes; when CSS sets
    // one dimension the other follows the aspect ratio (§10.6.2), and the
    // attributes only size the box when CSS sets neither.
    let (mut w, mut h) = match (css_w, css_h) {
        (Some(w), Some(h)) => (w, h),
        (Some(w), None) => (w, if iw > 0.0 { ih * w / iw } else { w }),
        (None, Some(h)) => (if ih > 0.0 { iw * h / ih } else { h }, h),
        (None, None) => match (attr("width"), attr("height")) {
            (Some(w), Some(h)) => (w, h),
            (Some(w), None) => (w, if iw > 0.0 { ih * w / iw } else { w }),
            (None, Some(h)) => (if ih > 0.0 { iw * h / ih } else { h }, h),
            (None, None) => (iw, ih),
        },
    };
    let css = |l: Length| match l {
        Length::Px(v) => Some(v.max(0.0)),
        Length::Percent(p) => Some((avail_width * p / 100.0).max(0.0)),
        Length::Auto => None,
    };
    let cap = css(s.max_width)
        .map(|m| m.min(avail_width))
        .unwrap_or(avail_width);
    if w > cap && w > 0.0 {
        h *= cap / w;
        w = cap;
    }
    (w, h)
}

impl<'a> LayoutCtx<'a> {
    fn style_of(&self, node: NodeId) -> ComputedStyle {
        self.styles.get(&node).cloned().unwrap_or_default()
    }

    /// Lay out `node` as a block box. `cursor_y` is the flow position inside
    /// the containing block; returns the bottom edge of this box (margin
    /// edge). Pushes boxes into `self.out`.
    fn layout_block(
        &mut self,
        node: NodeId,
        _parent_style: &ComputedStyle,
        x: f32,
        cursor_y: &mut f32,
        avail_width: f32,
    ) -> f32 {
        let style = self.style_of(node);
        if style.display == Display::None {
            return *cursor_y;
        }

        let margin = style.margin.resolve(avail_width);
        let padding = style.padding.resolve(avail_width);
        let border = style.border_width.resolve(avail_width);
        let horizontal_extra = padding.left + padding.right + border.left + border.right;

        // Replaced elements reached as blocks (a floated or `display:block`
        // image, an iframe, a block-level control): one box of their own
        // size, no children to flow.
        let doc = self.doc;
        let tag: String = doc
            .node(node)
            .as_element()
            .map(|e| e.tag.clone())
            .unwrap_or_default();
        if tag == "img" {
            let inner = (avail_width - margin.left - margin.right).max(0.0);
            let bottom = self.layout_image(node, x + margin.left, *cursor_y + margin.top, inner);
            *cursor_y = bottom + margin.bottom;
            return *cursor_y;
        }
        if is_control(&tag) || is_plain_replaced(&tag) {
            if let Some((w, h, label)) = control_metrics(doc, node, &style) {
                let x0 = if style.margin_x_auto() {
                    x + ((avail_width - w) / 2.0).max(0.0)
                } else {
                    x + margin.left
                };
                let y0 = *cursor_y + margin.top;
                self.emit_replaced(node, &style, x0, y0, w, h, &label, avail_width);
                *cursor_y = y0 + h + margin.bottom;
                return *cursor_y;
            }
        }

        // Content width: explicit or fill. An explicit width is the BORDER
        // box under `box-sizing: border-box`; `max-width` / `min-width`
        // clamp the result the same way (CSS 2.1 §10.4).
        let outer_avail = avail_width - margin.left - margin.right;
        let explicit = |l: Length| -> Option<f32> {
            match l {
                Length::Px(w) => Some(w.max(0.0)),
                Length::Percent(p) => Some((avail_width * p / 100.0).max(0.0)),
                Length::Auto => None,
            }
        };
        let to_content = |w: f32| -> f32 {
            if style.box_sizing_border {
                (w - horizontal_extra).max(0.0)
            } else {
                w
            }
        };
        let mut content_width = match explicit(style.width) {
            Some(w) => to_content(w),
            None => (outer_avail - horizontal_extra).max(0.0),
        };
        if let Some(max) = explicit(style.max_width) {
            content_width = content_width.min(to_content(max));
        }
        if let Some(min) = explicit(style.min_width) {
            content_width = content_width.max(to_content(min));
        }
        let border_box_width = content_width + horizontal_extra;

        // `margin: auto` horizontal centering whenever the box is narrower
        // than its container: an explicit width, or an auto width clamped
        // by `max-width` (the `max-width: 550px; margin: 0 auto` column that
        // text-first sites in the Chrome-referenced corpus are built on).
        let x0 = if style.margin_x_auto() && border_box_width < avail_width - 0.5 {
            x + ((avail_width - border_box_width) / 2.0).max(0.0)
        } else {
            x + margin.left
        };

        let y0 = *cursor_y + margin.top;
        let content_x = x0 + border.left + padding.left;
        let mut content_y = y0 + border.top + padding.top;

        // Reserve our box slot now so children paint over it.
        let self_index = self.out.len();
        self.out.push(LayoutBox {
            rect: Rect::default(),
            node: Some(node),
            content: BoxContent::Block,
            background: style.background,
            border_color: style.border_color,
            border,
            visible: style.visible,
        });

        // Tables lay their cells out in COLUMNS sized by content (the auto
        // table layout, approximated): the dominant page structure on
        // legacy and data sites in the Chrome-referenced corpus. Flowing
        // cells as inline text collapsed Hacker News to a third of its
        // height and mixed columns into one line.
        if style.display == Display::Table {
            let first_child_box = self.out.len();
            let (bottom, used_w) = self.layout_table(node, &style, content_x, content_y, content_width);
            let bbw = if style.width == Length::Auto {
                used_w.min(content_width) + horizontal_extra
            } else {
                border_box_width
            };
            // A shrink-to-fit table with auto margins is centered (the
            // `<table align=center>` idiom): shift what was laid out.
            let want_x = if style.margin_x_auto() {
                x + ((avail_width - bbw) / 2.0).max(0.0)
            } else {
                x0
            };
            let dx = want_x - x0;
            if dx.abs() > 0.01 {
                for b in self.out.iter_mut().skip(first_child_box) {
                    b.rect.x += dx;
                }
            }
            return self.finish_block(
                node, &style, self_index, want_x, y0, bottom, bbw, &padding, &border, &margin,
                cursor_y,
            );
        }

        // Partition children into block/inline runs and flow them.
        let children: Vec<NodeId> = self.doc.children(node).collect();
        // Flex rows and grids place their element children SIDE BY SIDE:
        // the dominant multi-column idiom on the Chrome-referenced corpus.
        // Stacking those children (the block fallback) made pages 2-3x
        // taller than Chrome's.
        let row_mode = if style.flex_container && !style.flex_column {
            Some(RowMode::Flex {
                wrap: style.flex_wrap,
            })
        } else {
            match style.grid_columns {
                GridColumns::None => None,
                GridColumns::Count(n) => Some(RowMode::Grid(n.max(1) as usize)),
                GridColumns::AutoFill(min) => Some(RowMode::Grid(
                    ((content_width / min.max(1.0)).floor() as usize).max(1),
                )),
            }
        };
        if let Some(mode) = row_mode {
            let items: Vec<NodeId> = children
                .iter()
                .copied()
                .filter(|c| match &self.doc.node(*c).data {
                    NodeData::Element(_) => {
                        let cs = self.style_of(*c);
                        cs.display != Display::None && !cs.position.out_of_flow()
                    }
                    NodeData::Text(t) => !t.trim().is_empty(),
                    _ => false,
                })
                .collect();
            content_y = self.layout_row(&items, node, &style, content_x, content_y, content_width, mode);
            return self.finish_block(
                node, &style, self_index, x0, y0, content_y, border_box_width, &padding, &border,
                &margin, cursor_y,
            );
        }
        let mut inline_run: Vec<NodeId> = Vec::new();
        let mut float_run: Vec<NodeId> = Vec::new();
        let mut i = 0usize;
        while i < children.len() {
            let Some(&child) = children.get(i) else {
                break;
            };
            i += 1;
            let child_style = match &self.doc.node(child).data {
                NodeData::Element(_) => Some(self.style_of(child)),
                _ => None,
            };
            // Absolutely positioned boxes leave the flow: laid out at their
            // static position (so they paint and hit-test) without taking
            // space, exactly as Chrome sizes the page without them.
            if let Some(cs) = &child_style {
                if cs.display != Display::None && cs.position.out_of_flow() {
                    let mut cy = content_y;
                    self.layout_block(child, &style, content_x, &mut cy, content_width);
                    continue;
                }
                // Consecutive floats form one side-by-side row (the classic
                // sidebar + content, or a gallery of floated cards).
                if cs.display != Display::None && cs.float != Float::None {
                    if !inline_run.is_empty() {
                        content_y = self.layout_inline_run(
                            &inline_run,
                            node,
                            &style,
                            content_x,
                            content_y,
                            content_width,
                        );
                        inline_run.clear();
                    }
                    float_run.push(child);
                    continue;
                }
            }
            if !float_run.is_empty() {
                // A whitespace-only text node between floats does not end
                // the run.
                let ws_only = matches!(&self.doc.node(child).data, NodeData::Text(t) if t.trim().is_empty());
                if ws_only {
                    continue;
                }
                content_y = self.layout_row(
                    &float_run,
                    node,
                    &style,
                    content_x,
                    content_y,
                    content_width,
                    RowMode::Floats,
                );
                float_run.clear();
            }
            let mut display = match &self.doc.node(child).data {
                NodeData::Element(_) => child_style.as_ref().map(|s| s.display).unwrap_or(Display::Inline),
                NodeData::Text(_) => Display::Inline,
                _ => Display::None,
            };
            // Block-in-inline: an inline element wrapping block-level
            // content (`<a><div>`, `<center><table>`, `<font><table>`) is
            // split around its blocks by CSS 2.1 §9.2.1.1. Laying the wrapper
            // out as a block keeps its tables and divs as blocks instead of
            // flowing their cells into one line — the defect that collapsed
            // every legacy table page in the Chrome-referenced corpus.
            if display == Display::Inline && self.has_block_descendant(child, 0) {
                display = Display::Block;
            }
            let is_img = self
                .doc
                .node(child)
                .as_element()
                .map(|e| e.tag == "img")
                .unwrap_or(false);
            if is_img && display != Display::None {
                if !inline_run.is_empty() {
                    content_y = self.layout_inline_run(
                        &inline_run,
                        node,
                        &style,
                        content_x,
                        content_y,
                        content_width,
                    );
                    inline_run.clear();
                }
                content_y = self.layout_image(child, content_x, content_y, content_width);
                continue;
            }
            match display {
                Display::None => {}
                Display::Block | Display::ListItem | Display::Table | Display::TableRow => {
                    if !inline_run.is_empty() {
                        content_y = self.layout_inline_run(
                            &inline_run,
                            node,
                            &style,
                            content_x,
                            content_y,
                            content_width,
                        );
                        inline_run.clear();
                    }
                    let mut cy = content_y;
                    let bottom =
                        self.layout_block(child, &style, content_x, &mut cy, content_width);
                    content_y = bottom;
                }
                Display::Inline | Display::InlineBlock | Display::TableCell => {
                    inline_run.push(child)
                }
            }
        }
        if !float_run.is_empty() {
            content_y = self.layout_row(
                &float_run,
                node,
                &style,
                content_x,
                content_y,
                content_width,
                RowMode::Floats,
            );
        }
        if !inline_run.is_empty() {
            content_y = self.layout_inline_run(
                &inline_run,
                node,
                &style,
                content_x,
                content_y,
                content_width,
            );
        }
        self.finish_block(
            node, &style, self_index, x0, y0, content_y, border_box_width, &padding, &border,
            &margin, cursor_y,
        )
    }

    /// Whether an inline element contains block-level content (a block,
    /// table, list item or row) that must break its parent's inline flow.
    fn has_block_descendant(&self, node: NodeId, depth: usize) -> bool {
        if depth > 64 {
            return false;
        }
        for child in self.doc.children(node) {
            if self.doc.node(child).as_element().is_none() {
                continue;
            }
            let s = self.style_of(child);
            match s.display {
                Display::None => {}
                Display::Block | Display::ListItem | Display::Table | Display::TableRow => {
                    if !s.position.out_of_flow() {
                        return true;
                    }
                }
                _ => {
                    if self.has_block_descendant(child, depth + 1) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Collect a table's rows (through `thead`/`tbody`/`tfoot`), each as
    /// its row element plus its cells, and its captions. A non-row block
    /// child (foster-parented content) becomes a full-width single-cell
    /// row so nothing is lost.
    fn collect_table_rows(
        &self,
        node: NodeId,
        rows: &mut Vec<(Option<NodeId>, Vec<NodeId>)>,
        captions: &mut Vec<NodeId>,
        depth: usize,
    ) {
        if depth > 8 {
            return;
        }
        for child in self.doc.children(node) {
            let Some(el) = self.doc.node(child).as_element() else {
                continue;
            };
            let s = self.style_of(child);
            if s.display == Display::None {
                continue;
            }
            match el.tag.as_str() {
                "tr" => {
                    let cells: Vec<NodeId> = self
                        .doc
                        .children(child)
                        .filter(|c| {
                            self.doc
                                .node(*c)
                                .as_element()
                                .map(|e| {
                                    matches!(e.tag.as_str(), "td" | "th")
                                        && self.style_of(*c).display != Display::None
                                })
                                .unwrap_or(false)
                        })
                        .collect();
                    rows.push((Some(child), cells));
                }
                "thead" | "tbody" | "tfoot" => {
                    self.collect_table_rows(child, rows, captions, depth + 1)
                }
                "caption" => captions.push(child),
                "colgroup" | "col" | "script" | "style" | "template" => {}
                _ => {
                    if s.display == Display::TableRow {
                        let cells: Vec<NodeId> = self
                            .doc
                            .children(child)
                            .filter(|c| self.doc.node(*c).as_element().is_some())
                            .collect();
                        rows.push((Some(child), cells));
                    } else {
                        rows.push((None, vec![child]));
                    }
                }
            }
        }
    }

    /// Lay out a table's rows into content-sized columns. Column widths
    /// follow each column's max-content width; a table with an explicit
    /// width distributes the difference proportionally, an auto-width
    /// table shrinks to fit (and never exceeds its container). `colspan`
    /// cells span their columns; 2px cell spacing (the `cellspacing`
    /// attribute when given) separates cells, as in the UA default.
    /// Returns (bottom y, used width including spacing).
    fn layout_table(
        &mut self,
        table: NodeId,
        table_style: &ComputedStyle,
        x: f32,
        y: f32,
        avail: f32,
    ) -> (f32, f32) {
        let mut rows: Vec<(Option<NodeId>, Vec<NodeId>)> = Vec::new();
        let mut captions: Vec<NodeId> = Vec::new();
        self.collect_table_rows(table, &mut rows, &mut captions, 0);
        let doc = self.doc;
        let attr_num = |node: NodeId, name: &str| -> Option<f32> {
            doc.node(node)
                .as_element()
                .and_then(|e| e.attr(name))
                .and_then(|v| v.trim().trim_end_matches("px").parse::<f32>().ok())
                .filter(|v| v.is_finite() && *v >= 0.0)
        };
        let spacing = attr_num(table, "cellspacing").unwrap_or(2.0).min(avail / 4.0);
        let mut cursor = y;
        for cap in &captions {
            let mut cy = cursor;
            cursor = self.layout_block(*cap, table_style, x, &mut cy, avail);
        }
        // One row of slots: its element and its (cell, first column, span;
        // span 0 = the whole table) entries.
        type GridRow = (Option<NodeId>, Vec<(NodeId, usize, usize)>);
        let mut grid: Vec<GridRow> = Vec::new();
        let mut ncols = 0usize;
        for (tr, cells) in &rows {
            let mut c = 0usize;
            let mut slots = Vec::new();
            for &cell in cells {
                let is_cell = doc
                    .node(cell)
                    .as_element()
                    .map(|e| matches!(e.tag.as_str(), "td" | "th"))
                    .unwrap_or(false);
                if !is_cell && tr.is_none() {
                    slots.push((cell, 0, 0));
                    continue;
                }
                let span = attr_num(cell, "colspan")
                    .map(|v| (v as usize).clamp(1, 64))
                    .unwrap_or(1);
                slots.push((cell, c, span));
                c += span;
            }
            ncols = ncols.max(c);
            grid.push((*tr, slots));
        }
        if ncols == 0 {
            // Only full-width rows (or nothing): stack them.
            for (_, slots) in &grid {
                for (cell, _, _) in slots {
                    let mut cy = cursor;
                    cursor = self.layout_block(*cell, table_style, x, &mut cy, avail);
                }
            }
            return (cursor, avail);
        }
        let gaps = spacing * (ncols as f32 + 1.0);
        let inner = (avail - gaps).max(0.0);
        // Max-content width per column; spanning cells widen their columns
        // evenly when they need more than the columns already have.
        let mut maxw = vec![0.0f32; ncols];
        let mut spanning: Vec<(usize, usize, f32)> = Vec::new();
        for (_, slots) in &grid {
            for &(cell, col, span) in slots {
                if span == 0 {
                    continue;
                }
                let w = self.max_content_width(cell, inner).min(inner);
                if span == 1 {
                    if let Some(slot) = maxw.get_mut(col) {
                        *slot = slot.max(w);
                    }
                } else {
                    spanning.push((col, span, w));
                }
            }
        }
        for (col, span, need) in spanning {
            let end = (col + span).min(ncols);
            let have: f32 = maxw.get(col..end).map(|s| s.iter().sum()).unwrap_or(0.0)
                + spacing * (span.saturating_sub(1)) as f32;
            if need > have && end > col {
                let add = (need - have) / (end - col) as f32;
                if let Some(cols) = maxw.get_mut(col..end) {
                    for c in cols {
                        *c += add;
                    }
                }
            }
        }
        let total: f32 = maxw.iter().sum();
        let target = if table_style.width == Length::Auto {
            total.min(inner)
        } else {
            inner
        };
        let widths: Vec<f32> = if total <= 0.0 {
            vec![target / ncols as f32; ncols]
        } else {
            maxw.iter().map(|w| w * target / total).collect()
        };
        let col_x = |col: usize| -> f32 {
            x + spacing + widths.iter().take(col).sum::<f32>() + spacing * col as f32
        };
        let span_w = |col: usize, span: usize| -> f32 {
            let end = (col + span).min(ncols);
            widths.get(col..end).map(|s| s.iter().sum::<f32>()).unwrap_or(0.0)
                + spacing * (end.saturating_sub(col).saturating_sub(1)) as f32
        };
        let used = target + gaps;
        cursor += spacing;
        for (tr, slots) in &grid {
            // The row's own box (background, explicit height) spans the
            // table; its cells paint over it.
            let row_index = self.out.len();
            let row_style = tr.map(|t| self.style_of(t));
            if let (Some(t), Some(rs)) = (tr, &row_style) {
                self.out.push(LayoutBox {
                    rect: Rect::default(),
                    node: Some(*t),
                    content: BoxContent::Block,
                    background: rs.background,
                    border_color: Color::TRANSPARENT,
                    border: ResolvedEdges::default(),
                    visible: rs.visible,
                });
            }
            let row_y = cursor;
            let mut bottom = row_y;
            for &(cell, col, span) in slots {
                let (cx, cw) = if span == 0 {
                    (x, avail)
                } else {
                    (col_x(col), span_w(col, span))
                };
                let mut cy = row_y;
                let b = self.layout_block(cell, table_style, cx, &mut cy, cw);
                bottom = bottom.max(b);
            }
            if let Some(rs) = &row_style {
                if let Length::Px(h) = rs.height {
                    bottom = bottom.max(row_y + h.max(0.0));
                }
                if let Some(slot) = self.out.get_mut(row_index) {
                    slot.rect = Rect {
                        x: x + spacing,
                        y: row_y,
                        width: (used - 2.0 * spacing).max(0.0),
                        height: bottom - row_y,
                    };
                }
            }
            cursor = bottom + spacing;
        }
        (cursor, used)
    }

    /// Emit the boxes of an atomic replaced element at (x, y): the box
    /// itself (with control chrome unless the element is a plain replaced
    /// element) and its caption, attributed to the same node so
    /// hit-testing and extraction see one element.
    #[allow(clippy::too_many_arguments)]
    fn emit_replaced(
        &mut self,
        node: NodeId,
        s: &ComputedStyle,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        label: &Option<String>,
        avail_width: f32,
    ) {
        let tag: String = self
            .doc
            .node(node)
            .as_element()
            .map(|e| e.tag.clone())
            .unwrap_or_default();
        let plain = is_plain_replaced(&tag) && tag != "iframe";
        let is_field = matches!(tag.as_str(), "input" | "textarea");
        let bg = if s.background.a > 0 || plain {
            s.background
        } else if is_field {
            Color::WHITE
        } else {
            Color::rgb(0xef, 0xef, 0xef)
        };
        let border_w = s.border_width.resolve(avail_width);
        let has_border = border_w.left > 0.0
            || border_w.top > 0.0
            || border_w.right > 0.0
            || border_w.bottom > 0.0;
        let (border, border_color) = if has_border {
            (border_w, s.border_color)
        } else if plain {
            (ResolvedEdges::default(), Color::TRANSPARENT)
        } else {
            (
                ResolvedEdges {
                    top: 1.0,
                    right: 1.0,
                    bottom: 1.0,
                    left: 1.0,
                },
                Color::rgb(0x76, 0x76, 0x76),
            )
        };
        self.out.push(LayoutBox {
            rect: Rect {
                x,
                y,
                width: w,
                height: h,
            },
            node: Some(node),
            content: BoxContent::Block,
            background: bg,
            border_color,
            border,
            visible: s.visible,
        });
        if let Some(text) = label {
            let tw = text_width(text, s.font_size, s.monospace, s.font_weight.is_bold());
            let th = s.font_size * s.line_height;
            let tx = if is_field {
                x + 4.0
            } else {
                x + ((w - tw) / 2.0).max(0.0)
            };
            self.out.push(LayoutBox {
                rect: Rect {
                    x: tx,
                    y: y + ((h - th) / 2.0).max(0.0),
                    width: tw.min(w),
                    height: th,
                },
                node: Some(node),
                content: BoxContent::Text {
                    text: text.clone(),
                    color: s.color,
                    font_size: s.font_size,
                    bold: s.font_weight.is_bold(),
                    italic: s.font_style_italic(),
                    monospace: s.monospace,
                },
                background: Color::TRANSPARENT,
                border_color: Color::TRANSPARENT,
                border: ResolvedEdges::default(),
                visible: s.visible,
            });
        }
    }

    /// Size the block's own box once its children are placed: explicit
    /// height (border-box under `box-sizing: border-box`) or content
    /// height, raised to `min-height`. Advances the flow cursor past the
    /// margin edge and returns it.
    #[allow(clippy::too_many_arguments)]
    fn finish_block(
        &mut self,
        _node: NodeId,
        style: &ComputedStyle,
        self_index: usize,
        x0: f32,
        y0: f32,
        content_y: f32,
        border_box_width: f32,
        padding: &ResolvedEdges,
        border: &ResolvedEdges,
        margin: &ResolvedEdges,
        cursor_y: &mut f32,
    ) -> f32 {
        let vertical_extra = padding.top + padding.bottom + border.top + border.bottom;
        let flowed = (content_y - (y0 + border.top + padding.top)).max(0.0);
        let mut content_height = match style.height {
            Length::Px(h) if style.box_sizing_border => (h - vertical_extra).max(0.0),
            Length::Px(h) => h.max(0.0),
            Length::Percent(_) | Length::Auto => flowed,
        };
        if let Length::Px(min) = style.min_height {
            let min_content = if style.box_sizing_border {
                (min - vertical_extra).max(0.0)
            } else {
                min.max(0.0)
            };
            content_height = content_height.max(min_content);
        }
        let border_box_height = content_height + vertical_extra;

        if let Some(slot) = self.out.get_mut(self_index) {
            slot.rect = Rect {
                x: x0,
                y: y0,
                width: border_box_width,
                height: border_box_height,
            };
        }

        *cursor_y = y0 + border_box_height + margin.bottom;
        *cursor_y
    }

    /// The max-content width of `node`'s border box: an explicit width when
    /// it has one, else the widest unbroken line its inline content would
    /// make, plus its own padding, border and margins. Drives the item
    /// widths of flex rows and float runs, like a browser's intrinsic
    /// sizing pass (approximate: one line per block, no nested wrapping).
    fn max_content_width(&self, node: NodeId, avail_width: f32) -> f32 {
        let s = self.style_of(node);
        let margin = s.margin.resolve(avail_width);
        let padding = s.padding.resolve(avail_width);
        let border = s.border_width.resolve(avail_width);
        let extra = padding.left + padding.right + border.left + border.right;
        let outer = margin.left + margin.right;
        let explicit = match s.width {
            Length::Px(w) => Some(w.max(0.0)),
            Length::Percent(p) => Some((avail_width * p / 100.0).max(0.0)),
            Length::Auto => None,
        };
        let mut content = match explicit {
            Some(w) if s.box_sizing_border => (w - extra).max(0.0),
            Some(w) => w,
            None => {
                let mut widest = 0.0f32;
                let mut cur = 0.0f32;
                self.measure_inline(node, node, &mut widest, &mut cur);
                widest.max(cur)
            }
        };
        if let Length::Px(max) = s.max_width {
            let max_c = if s.box_sizing_border {
                (max - extra).max(0.0)
            } else {
                max
            };
            content = content.min(max_c);
        }
        if let Length::Px(min) = s.min_width {
            content = content.max(min);
        }
        content + extra + outer
    }

    /// Walk `node`'s subtree accumulating single-line text widths; block
    /// boundaries and `<br>` start a new line.
    fn measure_inline(&self, node: NodeId, style_parent: NodeId, widest: &mut f32, cur: &mut f32) {
        match &self.doc.node(node).data {
            NodeData::Text(text) => {
                let s = self.style_of(style_parent);
                if s.white_space == WhiteSpace::Pre {
                    for (i, seg) in text.split('\n').enumerate() {
                        if i > 0 {
                            *widest = widest.max(*cur);
                            *cur = 0.0;
                        }
                        *cur += text_width(seg, s.font_size, s.monospace, s.font_weight.is_bold());
                    }
                } else {
                    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    if !joined.is_empty() {
                        let lead = if *cur > 0.0 { text_width(" ", s.font_size, s.monospace, false) } else { 0.0 };
                        *cur += lead + text_width(&joined, s.font_size, s.monospace, s.font_weight.is_bold());
                    }
                }
            }
            NodeData::Element(el) => {
                let s = self.style_of(node);
                if s.display == Display::None || s.position.out_of_flow() {
                    return;
                }
                if el.tag == "br" {
                    *widest = widest.max(*cur);
                    *cur = 0.0;
                    return;
                }
                if el.tag == "img" {
                    let px = el.attr("src").and_then(|src| self.images.get(src));
                    let (w, _) = image_size(el, &s, px, 1280.0);
                    *cur += w;
                    return;
                }
                if let Some((w, _, _)) = control_metrics(self.doc, node, &s) {
                    *cur += w;
                    return;
                }
                let block = !matches!(s.display, Display::Inline | Display::InlineBlock | Display::TableCell);
                if block {
                    *widest = widest.max(*cur);
                    *cur = 0.0;
                }
                let pad = s.padding.resolve(1280.0);
                let brd = s.border_width.resolve(1280.0);
                let own = pad.left + pad.right + brd.left + brd.right;
                if let Length::Px(w) = s.width {
                    // An explicitly sized descendant contributes its width.
                    *cur += w.max(0.0) + if s.box_sizing_border { 0.0 } else { own };
                } else {
                    let before = *cur;
                    let children: Vec<NodeId> = self.doc.children(node).collect();
                    for c in children {
                        self.measure_inline(c, node, widest, cur);
                    }
                    if *cur > before {
                        *cur += own;
                    }
                }
                if block {
                    *widest = widest.max(*cur);
                    *cur = 0.0;
                }
            }
            _ => {}
        }
    }

    /// Lay out `items` side by side inside a row container (a flex row, a
    /// grid, or a run of floats). Items are laid out as blocks in their
    /// assigned columns; a row's height is its tallest item's, and a
    /// wrapping mode starts a new row when the next item does not fit.
    /// Returns the y cursor below the last row.
    #[allow(clippy::too_many_arguments)]
    fn layout_row(
        &mut self,
        items: &[NodeId],
        container: NodeId,
        container_style: &ComputedStyle,
        x: f32,
        y: f32,
        width: f32,
        mode: RowMode,
    ) -> f32 {
        if items.is_empty() {
            return y;
        }
        // Assign each item a border-box width (margins included).
        let widths: Vec<f32> = match mode {
            RowMode::Grid(cols) => {
                let col = width / cols.max(1) as f32;
                items.iter().map(|_| col).collect()
            }
            RowMode::Flex { .. } | RowMode::Floats => {
                let intrinsic: Vec<f32> = items
                    .iter()
                    .map(|&n| self.max_content_width(n, width).min(width))
                    .collect();
                let total: f32 = intrinsic.iter().sum();
                if matches!(mode, RowMode::Flex { .. }) && total <= width {
                    // Free space goes to growing items; without any, items
                    // keep their content size (justify-content: start).
                    let grows: Vec<f32> = items.iter().map(|&n| self.style_of(n).flex_grow).collect();
                    let grow_sum: f32 = grows.iter().sum();
                    if grow_sum > 0.0 {
                        let free = width - total;
                        intrinsic
                            .iter()
                            .zip(grows.iter())
                            .map(|(w, g)| w + free * g / grow_sum)
                            .collect()
                    } else {
                        intrinsic
                    }
                } else if matches!(mode, RowMode::Flex { wrap: false }) && total > width {
                    // nowrap: shrink every item proportionally to fit.
                    intrinsic.iter().map(|w| w * width / total).collect()
                } else {
                    intrinsic
                }
            }
        };
        let wraps = match mode {
            RowMode::Grid(_) => true,
            RowMode::Flex { wrap } => wrap,
            RowMode::Floats => true,
        };
        let cols = match mode {
            RowMode::Grid(c) => c.max(1),
            _ => usize::MAX,
        };
        // Break into rows.
        let mut rows: Vec<Vec<(NodeId, f32)>> = vec![Vec::new()];
        let mut used = 0.0f32;
        for (&item, &w) in items.iter().zip(widths.iter()) {
            let row_len = rows.last().map(|r| r.len()).unwrap_or(0);
            let overflow = wraps && row_len > 0 && (used + w > width + 0.5 || row_len >= cols);
            if overflow {
                rows.push(Vec::new());
                used = 0.0;
            }
            if let Some(row) = rows.last_mut() {
                row.push((item, w));
            }
            used += w;
        }
        let mut row_y = y;
        for row in rows {
            let row_w: f32 = row.iter().map(|(_, w)| w).sum();
            // Right floats stack from the right edge; everything else from
            // the left (text-align: center on a flex container is not a
            // justify rule, so it is ignored here).
            let mut left_x = x;
            let mut right_x = x + width;
            let _ = row_w;
            let mut bottom = row_y;
            for (item, w) in row {
                let is_right = matches!(mode, RowMode::Floats)
                    && self.style_of(item).float == Float::Right;
                let item_x = if is_right {
                    right_x -= w;
                    right_x
                } else {
                    let ix = left_x;
                    left_x += w;
                    ix
                };
                let mut cy = row_y;
                let b = match &self.doc.node(item).data {
                    NodeData::Text(_) => {
                        // Bare text inside a flex/grid container is an
                        // anonymous item: one inline run in its column.
                        self.layout_inline_run(&[item], container, container_style, item_x, row_y, w)
                    }
                    _ => self.layout_block(item, container_style, item_x, &mut cy, w),
                };
                bottom = bottom.max(b);
            }
            row_y = bottom;
        }
        row_y
    }

    /// Lay out an `<img>` as a replaced block-level box, sized by
    /// [`image_size`] (CSS, attributes, intrinsic, placeholder; clamped to
    /// the containing block). Returns the new y cursor.
    fn layout_image(&mut self, node: NodeId, x: f32, y: f32, avail_width: f32) -> f32 {
        let style = self.style_of(node);
        let (w, h, pixels) = match self.doc.node(node).as_element() {
            Some(el) => {
                let px = el.attr("src").and_then(|s| self.images.get(s)).cloned();
                let (w, h) = image_size(el, &style, px.as_ref(), avail_width);
                (w, h, px)
            }
            None => (16.0, 16.0, None),
        };
        self.out.push(LayoutBox {
            rect: Rect {
                x,
                y,
                width: w,
                height: h,
            },
            node: Some(node),
            content: BoxContent::Image { pixels },
            background: crate::browser_core::style::Color::TRANSPARENT,
            border_color: crate::browser_core::style::Color::TRANSPARENT,
            border: ResolvedEdges::default(),
            visible: style.visible,
        });
        y + h
    }

    /// Flow an inline run (text + inline elements) into line boxes.
    /// Returns the new y cursor after the last line.
    fn layout_inline_run(
        &mut self,
        run: &[NodeId],
        container: NodeId,
        container_style: &ComputedStyle,
        x: f32,
        y: f32,
        width: f32,
    ) -> f32 {
        // Collect inline items by walking the run's subtrees.
        let mut items: Vec<InlineItem> = Vec::new();
        for &node in run {
            self.collect_inline(node, container, &mut items);
        }
        if items.is_empty() {
            return y;
        }

        // Greedy line breaking.
        let line_height_of = |s: &ComputedStyle| s.font_size * s.line_height;
        let mut lines: Vec<Vec<(f32, InlineItem)>> = Vec::new(); // (x offset, item)
        let mut cur: Vec<(f32, InlineItem)> = Vec::new();
        let mut cur_x = 0.0f32;
        for item in items {
            match item {
                InlineItem::HardBreak => {
                    lines.push(std::mem::take(&mut cur));
                    cur_x = 0.0;
                }
                InlineItem::Space { width: w, style_of } => {
                    if cur_x > 0.0 {
                        cur.push((cur_x, InlineItem::Space { width: w, style_of }));
                        cur_x += w;
                    }
                }
                InlineItem::Replaced {
                    node,
                    width: w,
                    height,
                    label,
                    plain,
                } => {
                    if cur_x > 0.0 && cur_x + w > width {
                        while matches!(cur.last(), Some((_, InlineItem::Space { .. }))) {
                            cur.pop();
                        }
                        lines.push(std::mem::take(&mut cur));
                        cur_x = 0.0;
                    }
                    cur.push((
                        cur_x,
                        InlineItem::Replaced {
                            node,
                            width: w,
                            height,
                            label,
                            plain,
                        },
                    ));
                    cur_x += w;
                }
                InlineItem::Image {
                    node,
                    width: w,
                    height,
                    pixels,
                } => {
                    if cur_x > 0.0 && cur_x + w > width {
                        while matches!(cur.last(), Some((_, InlineItem::Space { .. }))) {
                            cur.pop();
                        }
                        lines.push(std::mem::take(&mut cur));
                        cur_x = 0.0;
                    }
                    cur.push((
                        cur_x,
                        InlineItem::Image {
                            node,
                            width: w,
                            height,
                            pixels,
                        },
                    ));
                    cur_x += w;
                }
                InlineItem::Word {
                    text,
                    width: w,
                    style_of,
                } => {
                    if cur_x > 0.0 && cur_x + w > width {
                        // Drop trailing space at line end.
                        while matches!(cur.last(), Some((_, InlineItem::Space { .. }))) {
                            cur.pop();
                        }
                        lines.push(std::mem::take(&mut cur));
                        cur_x = 0.0;
                    }
                    cur.push((
                        cur_x,
                        InlineItem::Word {
                            text,
                            width: w,
                            style_of,
                        },
                    ));
                    cur_x += w;
                }
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }

        // Emit text boxes per line with alignment.
        let mut line_y = y;
        for line in lines {
            // Line metrics come from the tallest item on the line.
            let mut line_h = line_height_of(container_style);
            let mut line_w = 0.0f32;
            for (off, item) in &line {
                if let InlineItem::Word {
                    width: w, style_of, ..
                }
                | InlineItem::Space { width: w, style_of } = item
                {
                    let s = self.style_of(*style_of);
                    line_h = line_h.max(line_height_of(&s));
                    line_w = line_w.max(off + w);
                }
                if let InlineItem::Replaced {
                    width: w, height, ..
                }
                | InlineItem::Image {
                    width: w, height, ..
                } = item
                {
                    line_h = line_h.max(*height);
                    line_w = line_w.max(off + w);
                }
            }
            let align_dx = match container_style.text_align {
                TextAlign::Left => 0.0,
                TextAlign::Center => ((width - line_w) / 2.0).max(0.0),
                TextAlign::Right => (width - line_w).max(0.0),
            };
            for (off, item) in line {
                if let InlineItem::Replaced {
                    node,
                    width: w,
                    height,
                    label,
                    ..
                } = &item
                {
                    // The control's own box sits on the line's bottom edge
                    // (baseline-ish), then its caption.
                    let s = self.style_of(*node);
                    let top = line_y + (line_h - height).max(0.0);
                    self.emit_replaced(*node, &s, x + align_dx + off, top, *w, *height, label, width);
                    continue;
                }
                if let InlineItem::Image {
                    node,
                    width: w,
                    height,
                    pixels,
                } = &item
                {
                    let s = self.style_of(*node);
                    let top = line_y + (line_h - height).max(0.0);
                    self.out.push(LayoutBox {
                        rect: Rect {
                            x: x + align_dx + off,
                            y: top,
                            width: *w,
                            height: *height,
                        },
                        node: Some(*node),
                        content: BoxContent::Image {
                            pixels: pixels.clone(),
                        },
                        background: Color::TRANSPARENT,
                        border_color: Color::TRANSPARENT,
                        border: ResolvedEdges::default(),
                        visible: s.visible,
                    });
                    continue;
                }
                if let InlineItem::Word {
                    text,
                    width: w,
                    style_of,
                } = item
                {
                    let s = self.style_of(style_of);
                    let baseline_pad = (line_h - s.font_size * s.line_height).max(0.0);
                    self.out.push(LayoutBox {
                        rect: Rect {
                            x: x + align_dx + off,
                            y: line_y + baseline_pad,
                            width: w,
                            height: s.font_size * s.line_height,
                        },
                        node: Some(style_of),
                        content: BoxContent::Text {
                            text,
                            color: s.color,
                            font_size: s.font_size,
                            bold: s.font_weight.is_bold(),
                            italic: s.font_style_italic(),
                            monospace: s.monospace,
                        },
                        background: Color::TRANSPARENT,
                        border_color: Color::TRANSPARENT,
                        border: ResolvedEdges::default(),
                        visible: s.visible,
                    });
                }
            }
            line_y += line_h;
        }
        line_y
    }

    /// Walk an inline subtree, splitting text into word/space items.
    fn collect_inline(&self, node: NodeId, style_parent: NodeId, out: &mut Vec<InlineItem>) {
        match &self.doc.node(node).data {
            NodeData::Text(text) => {
                let s = self.style_of(style_parent);
                if s.white_space == WhiteSpace::Pre {
                    for (i, seg) in text.split('\n').enumerate() {
                        if i > 0 {
                            out.push(InlineItem::HardBreak);
                        }
                        if !seg.is_empty() {
                            out.push(InlineItem::Word {
                                text: seg.to_string(),
                                width: text_width(
                                    seg,
                                    s.font_size,
                                    s.monospace,
                                    s.font_weight.is_bold(),
                                ),
                                style_of: style_parent,
                            });
                        }
                    }
                } else {
                    let space_w =
                        text_width(" ", s.font_size, s.monospace, s.font_weight.is_bold());
                    let mut chars = text.chars().peekable();
                    let leading_ws = chars.peek().is_some_and(|c| c.is_whitespace());
                    if leading_ws {
                        out.push(InlineItem::Space {
                            width: space_w,
                            style_of: style_parent,
                        });
                    }
                    for word in text.split_whitespace() {
                        out.push(InlineItem::Word {
                            text: word.to_string(),
                            width: text_width(
                                word,
                                s.font_size,
                                s.monospace,
                                s.font_weight.is_bold(),
                            ),
                            style_of: style_parent,
                        });
                        out.push(InlineItem::Space {
                            width: space_w,
                            style_of: style_parent,
                        });
                    }
                    // Trailing space only if source ended with whitespace;
                    // otherwise remove the one we just pushed.
                    if !text.ends_with(|c: char| c.is_whitespace())
                        && matches!(out.last(), Some(InlineItem::Space { .. }))
                    {
                        out.pop();
                    }
                }
            }
            NodeData::Element(el) => {
                if el.tag == "br" {
                    out.push(InlineItem::HardBreak);
                    return;
                }
                let s = self.style_of(node);
                if s.display == Display::None || s.position.out_of_flow() {
                    return;
                }
                // An inline image (inside a link, a span, a heading…): an
                // atomic box of the image's size. The containing width is
                // not known here, so a percentage CSS width resolves
                // against the viewport.
                if el.tag == "img" {
                    let px = el.attr("src").and_then(|src| self.images.get(src)).cloned();
                    let (w, h) = image_size(el, &s, px.as_ref(), 1280.0);
                    out.push(InlineItem::Image {
                        node,
                        width: w,
                        height: h,
                        pixels: px,
                    });
                    return;
                }
                // Form controls are atomic replaced boxes: their children
                // (option text, a button caption) render inside the control,
                // not as free-flowing inline text.
                if let Some((w, h, label)) = control_metrics(self.doc, node, &s) {
                    out.push(InlineItem::Replaced {
                        node,
                        width: w,
                        height: h,
                        label,
                        plain: is_plain_replaced(&el.tag),
                    });
                    return;
                }
                let children: Vec<NodeId> = self.doc.children(node).collect();
                for child in children {
                    self.collect_inline(child, node, out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_core::html;
    use crate::browser_core::style;

    fn layout(html_src: &str, width: f32) -> LayoutTree {
        let doc = html::parse(html_src);
        let sheets = style::document_stylesheets(&doc);
        let styles = style::compute_styles(&doc, &sheets);
        layout_tree(&doc, &styles, width)
    }

    fn texts(tree: &LayoutTree) -> Vec<(String, Rect)> {
        tree.boxes
            .iter()
            .filter_map(|b| match &b.content {
                BoxContent::Text { text, .. } => Some((text.clone(), b.rect)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn blocks_stack_vertically() {
        let t = layout("<p>one</p><p>two</p>", 800.0);
        let ts = texts(&t);
        assert_eq!(ts.len(), 2);
        assert!(ts[1].1.y > ts[0].1.y, "second paragraph below first");
        assert!(t.page_height > 0.0);
    }

    #[test]
    fn words_wrap_at_container_width() {
        // 10 long words at 16px into a narrow container must wrap.
        let t = layout(
            "<div>aaaaaaaa bbbbbbbb cccccccc dddddddd eeeeeeee ffffffff</div>",
            160.0,
        );
        let ts = texts(&t);
        let distinct_y: std::collections::BTreeSet<i32> =
            ts.iter().map(|(_, r)| r.y as i32).collect();
        assert!(
            distinct_y.len() >= 2,
            "expected multiple lines, got {distinct_y:?}"
        );
        for (_, r) in &ts {
            assert!(r.right() <= 161.0, "text overflows: {r:?}");
        }
    }

    #[test]
    fn display_none_produces_no_boxes() {
        let t = layout(
            "<div><span style=\"display:none\">ghost</span><span>real</span></div>",
            800.0,
        );
        let ts = texts(&t);
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].0, "real");
    }

    #[test]
    fn br_forces_line_break() {
        let t = layout("<div>alpha<br>beta</div>", 800.0);
        let ts = texts(&t);
        assert_eq!(ts.len(), 2);
        assert!(ts[1].1.y > ts[0].1.y);
    }

    #[test]
    fn explicit_width_and_margin_auto_centers() {
        let t = layout("<div style=\"width:100px;margin:0 auto\">x</div>", 500.0);
        // Find the div's block box (has node, Block content, width 100).
        let block = t
            .boxes
            .iter()
            .find(|b| matches!(b.content, BoxContent::Block) && (b.rect.width - 100.0).abs() < 1.0)
            .expect("block with width 100");
        assert!(
            (block.rect.x - 200.0).abs() < 2.0,
            "centered: {:?}",
            block.rect
        );
    }

    #[test]
    fn pre_preserves_newlines() {
        let t = layout("<pre>line1\nline2\nline3</pre>", 800.0);
        let ts = texts(&t);
        assert_eq!(ts.len(), 3);
        assert!(ts[0].1.y < ts[1].1.y && ts[1].1.y < ts[2].1.y);
    }

    #[test]
    fn empty_input_lays_out() {
        let t = layout("", 800.0);
        assert!(t.page_height >= 1.0);
    }
}
