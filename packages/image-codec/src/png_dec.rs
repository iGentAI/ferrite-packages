//! png_dec — dependency-free PNG decoder.
//!
//! Supports the baseline that dominates the web: 8-bit greyscale, RGB,
//! palette, greyscale+alpha, and RGBA, non-interlaced, with tRNS
//! transparency. 16-bit channels are downsampled to 8. Adam7 interlacing is
//! rejected (rare on the web). Hostile input yields `None`, never a panic.

use super::inflate;
use super::{DecodedImage, MAX_PIXELS};

/// Header-only dimensions.
pub fn dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    // 8-byte signature, then IHDR: len(4) 'IHDR'(4) w(4) h(4) ...
    if bytes.len() < 24 || bytes.get(12..16) != Some(b"IHDR") {
        return None;
    }
    let w = be32(bytes.get(16..20)?)? as usize;
    let h = be32(bytes.get(20..24)?)? as usize;
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

/// Decode a whole PNG into RGBA8.
pub fn decode(bytes: &[u8]) -> Option<DecodedImage> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    let mut pos = 8usize;
    let mut width = 0usize;
    let mut height = 0usize;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut palette: Vec<[u8; 3]> = Vec::new();
    let mut trns: Vec<u8> = Vec::new();
    let mut idat: Vec<u8> = Vec::new();
    let mut saw_ihdr = false;

    while pos.checked_add(8)? <= bytes.len() {
        let len = be32(bytes.get(pos..pos + 4)?)? as usize;
        let ctype = bytes.get(pos + 4..pos + 8)?;
        let data_start = pos.checked_add(8)?;
        let data_end = data_start.checked_add(len)?;
        if data_end.checked_add(4)? > bytes.len() {
            break; // truncated chunk — decode what we have
        }
        let data = bytes.get(data_start..data_end)?;
        match ctype {
            b"IHDR" => {
                if len < 13 {
                    return None;
                }
                width = be32(data.get(0..4)?)? as usize;
                height = be32(data.get(4..8)?)? as usize;
                bit_depth = *data.get(8)?;
                color_type = *data.get(9)?;
                interlace = *data.get(12)?;
                saw_ihdr = true;
            }
            b"PLTE" => {
                palette = data.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect();
            }
            b"tRNS" => trns = data.to_vec(),
            b"IDAT" => idat.extend_from_slice(data),
            b"IEND" => break,
            _ => {}
        }
        pos = data_end.checked_add(4)?; // skip CRC
    }

    if !saw_ihdr || width == 0 || height == 0 || interlace != 0 {
        return None;
    }
    if width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    // Channels per pixel before palette expansion.
    let channels: usize = match color_type {
        0 => 1, // grey
        2 => 3, // rgb
        3 => 1, // palette index
        4 => 2, // grey+alpha
        6 => 4, // rgba
        _ => return None,
    };
    if !matches!(bit_depth, 1 | 2 | 4 | 8 | 16) {
        return None;
    }
    // Palette requires <= 8-bit depth; 16-bit only valid for non-palette.
    if color_type == 3 && bit_depth == 16 {
        return None;
    }

    // Pixel budget bounds decompression: worst case stride+filter byte per row.
    let px = width.checked_mul(height)?;
    if px > MAX_PIXELS {
        return None;
    }
    let max_raw = height
        .checked_mul(width.checked_mul(8)?.checked_add(1)?)?
        .checked_add(1024)?;
    let raw = inflate::inflate_zlib(&idat, max_raw)?;
    let bits_per_pixel = channels.checked_mul(bit_depth as usize)?;
    let stride = bits_per_pixel.checked_mul(width)?.div_ceil(8);
    let expected = height.checked_mul(stride.checked_add(1)?)?;
    if raw.len() < expected {
        return None;
    }

    // Un-filter scanlines.
    let bpp = bits_per_pixel.div_ceil(8).max(1);
    let mut lines: Vec<u8> = vec![0; height.checked_mul(stride)?];
    for y in 0..height {
        let in_start = y.checked_mul(stride + 1)?;
        let filter = *raw.get(in_start)?;
        let line_in = raw.get(in_start + 1..in_start + 1 + stride)?;
        let out_start = y.checked_mul(stride)?;
        for x in 0..stride {
            let cur = *line_in.get(x)?;
            let a = if x >= bpp {
                *lines.get(out_start + x - bpp)?
            } else {
                0
            }; // left
            let b = if y > 0 {
                *lines.get(out_start - stride + x)?
            } else {
                0
            }; // up
            let c = if x >= bpp && y > 0 {
                *lines.get(out_start - stride + x - bpp)?
            } else {
                0
            };
            let v = match filter {
                0 => cur,
                1 => cur.wrapping_add(a),
                2 => cur.wrapping_add(b),
                3 => cur.wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => cur.wrapping_add(paeth(a, b, c)),
                _ => return None,
            };
            if let Some(slot) = lines.get_mut(out_start + x) {
                *slot = v;
            }
        }
    }

    // Expand to RGBA8.
    let mut rgba = Vec::with_capacity(width.checked_mul(height)?.checked_mul(4)?);
    for y in 0..height {
        let line = lines.get(y * stride..(y + 1) * stride)?;
        for x in 0..width {
            let px = read_pixel(line, x, bit_depth, channels)?;
            match color_type {
                0 => {
                    // Low-depth greyscale: read_pixel returns [raw, scaled];
                    // the SCALED value is the sample (raw is for palettes).
                    let g = if bit_depth < 8 { px[1] } else { px[0] };
                    let alpha = grey_trns_alpha(&trns, g, bit_depth);
                    rgba.extend_from_slice(&[g, g, g, alpha]);
                }
                2 => {
                    let alpha = rgb_trns_alpha(&trns, &px, bit_depth);
                    rgba.extend_from_slice(&[px[0], px[1], px[2], alpha]);
                }
                3 => {
                    let idx = px[0] as usize;
                    let [r, g, b] = palette.get(idx).copied().unwrap_or([0, 0, 0]);
                    let a = trns.get(idx).copied().unwrap_or(255);
                    rgba.extend_from_slice(&[r, g, b, a]);
                }
                4 => {
                    let g = px[0];
                    rgba.extend_from_slice(&[g, g, g, px[1]]);
                }
                6 => rgba.extend_from_slice(&[px[0], px[1], px[2], px[3]]),
                _ => return None,
            }
        }
    }
    DecodedImage::new(width, height, rgba)
}

/// Read pixel `x` from an unfiltered scanline, normalized to 8-bit channels.
fn read_pixel(line: &[u8], x: usize, depth: u8, channels: usize) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    match depth {
        8 => {
            let start = x.checked_mul(channels)?;
            for (i, slot) in out.iter_mut().take(channels).enumerate() {
                *slot = *line.get(start + i)?;
            }
        }
        16 => {
            let start = x.checked_mul(channels)?.checked_mul(2)?;
            for (i, slot) in out.iter_mut().take(channels).enumerate() {
                *slot = *line.get(start + i * 2)?; // high byte ≈ 8-bit value
            }
        }
        1 | 2 | 4 => {
            // Sub-byte packed: greyscale or palette index only (channels==1).
            let d = depth as usize;
            let bit = x.checked_mul(d)?;
            let byte = *line.get(bit / 8)?;
            let shift = 8 - d - (bit % 8);
            let mask = (1u16 << d) - 1;
            let v = ((byte as u16) >> shift) & mask;
            // Scale to 0..=255 for greyscale; palette indices used raw.
            let scaled = (v * 255).checked_div(mask).unwrap_or(0) as u8;
            out[0] = if channels == 1 && mask > 0 {
                scaled
            } else {
                v as u8
            };
            // For palette (color_type 3), the caller uses the RAW index, so
            // store it too when depth < 8: recover index from scaled value is
            // lossy, so overwrite with the raw index below.
            if d < 8 {
                out[0] = v as u8; // palette index or low-depth grey (rescaled by caller)
                if channels == 1 {
                    // Greyscale at low depth still wants scaling; the caller
                    // cannot tell, so do the standard thing: greyscale scales.
                    // Palette callers ignore scaling because indices < 2^d.
                    out[3] = scaled; // stash scaled grey in the alpha slot
                }
            }
        }
        _ => return None,
    }
    // Low-depth greyscale fixup: use the stashed scaled value.
    if depth < 8 && channels == 1 {
        // The caller distinguishes palette (uses out[0] as index) from
        // greyscale (uses out[0] as value); provide the scaled grey in out[0]
        // only for greyscale via a second slot. Simplest correct behavior:
        // return both and let color_type decide. Here: out = [raw, scaled,0,0]
        let raw = out[0];
        let scaled = out[3];
        out = [raw, scaled, 0, 0];
    }
    Some(out)
}

fn grey_trns_alpha(trns: &[u8], g: u8, depth: u8) -> u8 {
    if trns.len() >= 2 {
        let key = u16::from_be_bytes([trns[0], trns[1]]);
        let sample = if depth == 16 {
            (g as u16) << 8 | g as u16
        } else {
            g as u16
        };
        if sample == key {
            return 0;
        }
    }
    255
}

fn rgb_trns_alpha(trns: &[u8], px: &[u8; 4], depth: u8) -> u8 {
    if trns.len() >= 6 {
        let kr = u16::from_be_bytes([trns[0], trns[1]]);
        let kg = u16::from_be_bytes([trns[2], trns[3]]);
        let kb = u16::from_be_bytes([trns[4], trns[5]]);
        let (r, g, b) = if depth == 16 {
            (
                ((px[0] as u16) << 8) | px[0] as u16,
                ((px[1] as u16) << 8) | px[1] as u16,
                ((px[2] as u16) << 8) | px[2] as u16,
            )
        } else {
            (px[0] as u16, px[1] as u16, px[2] as u16)
        };
        if r == kr && g == kg && b == kb {
            return 0;
        }
    }
    255
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let pa = (p - a as i16).abs();
    let pb = (p - b as i16).abs();
    let pc = (p - c as i16).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::decode;

    /// Build a tiny valid PNG in-test via our own encoder, then decode it.
    #[test]
    fn roundtrip_via_own_encoder() {
        // 2x2 RGBA: red, green, blue, white.
        let px: Vec<u8> = vec![
            255, 0, 0, 255, 0, 255, 0, 255, //
            0, 0, 255, 255, 255, 255, 255, 255,
        ];
        let png = super::super::png::encode(2, 2, &px);
        let img = decode(&png).expect("decode own PNG");
        assert_eq!((img.width, img.height), (2, 2));
        assert_eq!(img.rgba, px);
    }

    #[test]
    fn hostile_inputs_yield_none() {
        assert!(decode(b"").is_none());
        assert!(decode(b"\x89PNG\r\n\x1a\n").is_none());
        assert!(decode(&[0x89u8; 64]).is_none());
        let mut junk = b"\x89PNG\r\n\x1a\n".to_vec();
        junk.extend_from_slice(&[0xffu8; 100]);
        assert!(decode(&junk).is_none());
    }
}
