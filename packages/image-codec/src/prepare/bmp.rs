//! Windows and OS/2 BMP with raw RGB or bitfield rows.

use super::{DecodedImage, MAX_PIXELS};

pub fn sniff(data: &[u8]) -> bool {
    header(data).is_some()
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}
fn le32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn header(data: &[u8]) -> Option<(usize, usize, usize, u16)> {
    if !data.starts_with(b"BM") {
        return None;
    }
    let declared = le32(data, 2)? as usize;
    let pixels = le32(data, 10)? as usize;
    let dib = le32(data, 14)? as usize;
    let plane = match dib {
        12 => 22,
        40..=124 => 26,
        _ => return None,
    };
    if (declared != 0 && (declared < 26 || pixels >= declared))
        || pixels < 14 + dib
        || le16(data, plane)? != 1
    {
        return None;
    }
    let bits = le16(data, plane + 2)?;
    matches!(bits, 1 | 4 | 8 | 16 | 24 | 32).then_some((declared, pixels, dib, bits))
}

pub fn decode(data: &[u8]) -> Option<DecodedImage> {
    let (declared, offset, dib, bits) = header(data)?;
    if declared != 0 && declared > data.len() {
        return None;
    }
    let (width, height, top_down, compression, colors) = if dib == 12 {
        (
            usize::from(le16(data, 18)?),
            usize::from(le16(data, 20)?),
            false,
            0,
            0,
        )
    } else {
        let width = usize::try_from(le32(data, 18)? as i32).ok()?;
        let height = le32(data, 22)? as i32;
        (
            width,
            height.unsigned_abs() as usize,
            height < 0,
            le32(data, 30)?,
            le32(data, 46)? as usize,
        )
    };
    let total = width.checked_mul(height)?;
    if total == 0
        || total > MAX_PIXELS
        || !matches!(compression, 0 | 3 | 6)
        || compression != 0 && !matches!(bits, 16 | 32)
    {
        return None;
    }
    let row_bytes = width
        .checked_mul(bits as usize)?
        .div_ceil(32)
        .checked_mul(4)?;
    let size = row_bytes.checked_mul(height)?;
    let end = offset.checked_add(size)?;
    if declared != 0 && end > declared {
        return None;
    }
    let pixels = data.get(offset..end)?;
    let palette_start = 14 + dib;
    let palette_stride = if dib == 12 { 3 } else { 4 };
    let palette = if bits <= 8 {
        let count = if colors == 0 { 1 << bits } else { colors };
        if count > 1 << bits {
            return None;
        }
        let end = palette_start.checked_add(count.checked_mul(palette_stride)?)?;
        if end > offset {
            return None;
        }
        data.get(palette_start..end)?
    } else {
        &[]
    };
    let masks = if matches!(compression, 3 | 6) {
        if offset < 66 || compression == 6 && offset < 70 {
            return None;
        }
        let alpha = if compression == 6 || dib >= 56 {
            le32(data, 66)?
        } else {
            0
        };
        [le32(data, 54)?, le32(data, 58)?, le32(data, 62)?, alpha]
    } else if bits == 16 {
        [0x7c00, 0x03e0, 0x001f, 0]
    } else {
        [0x00ff_0000, 0x0000_ff00, 0x0000_00ff, 0]
    };
    if bits == 16 || bits == 32 {
        let mut used = 0;
        for (i, mask) in masks.into_iter().enumerate() {
            if mask == 0 && i == 3 {
                continue;
            }
            if mask == 0
                || mask & used != 0
                || mask.leading_zeros() < 32 - u32::from(bits)
                || (mask >> mask.trailing_zeros())
                    .checked_add(1)
                    .is_none_or(|value| !value.is_power_of_two())
            {
                return None;
            }
            used |= mask;
        }
    }
    let mut rgba = Vec::with_capacity(total.checked_mul(4)?);
    for y in 0..height {
        let row = if top_down { y } else { height - 1 - y };
        let line = pixels.get(row * row_bytes..(row + 1) * row_bytes)?;
        for x in 0..width {
            match bits {
                1 | 4 | 8 => {
                    let index = match bits {
                        1 => (*line.get(x / 8)? >> (7 - x % 8)) & 1,
                        4 => (*line.get(x / 2)? >> (4 - 4 * (x % 2))) & 15,
                        _ => *line.get(x)?,
                    } as usize;
                    let bgr = palette.get(index * palette_stride..index * palette_stride + 3)?;
                    rgba.extend([bgr[2], bgr[1], bgr[0], 255]);
                }
                24 => {
                    let bgr = line.get(x * 3..x * 3 + 3)?;
                    rgba.extend([bgr[2], bgr[1], bgr[0], 255]);
                }
                _ => {
                    let rgb = if bits == 16 {
                        u32::from(le16(line, x * 2)?)
                    } else {
                        le32(line, x * 4)?
                    };
                    rgba.extend(masks.map(|mask| {
                        if mask == 0 {
                            return 255;
                        }
                        let shift = mask.trailing_zeros();
                        let max = u64::from(mask >> shift);
                        ((u64::from((rgb & mask) >> shift) * 255 + max / 2) / max) as u8
                    }));
                }
            }
        }
    }
    DecodedImage::new(width, height, rgba)
}
