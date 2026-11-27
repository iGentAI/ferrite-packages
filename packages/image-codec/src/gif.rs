//! gif — dependency-free GIF decoder (first frame).
//!
//! Supports GIF87a/GIF89a: global and local color tables, interlacing, and
//! the transparent-color extension. Animation is out of scope: the FIRST
//! frame is composited and returned. Hostile input yields `None`, never a
//! panic.

use super::{DecodedImage, MAX_PIXELS};

/// Header-only dimensions (logical screen descriptor).
pub fn dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 10 || (!bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a")) {
        return None;
    }
    let w = u16::from_le_bytes([*bytes.get(6)?, *bytes.get(7)?]) as usize;
    let h = u16::from_le_bytes([*bytes.get(8)?, *bytes.get(9)?]) as usize;
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

/// Decode the first frame into RGBA8 at the logical screen size.
pub fn decode(bytes: &[u8]) -> Option<DecodedImage> {
    let (sw, sh) = dimensions(bytes)?;
    if sw.checked_mul(sh)? > MAX_PIXELS {
        return None;
    }
    let mut pos = 10usize;
    let packed = *bytes.get(pos)?;
    pos = pos.checked_add(3)?; // packed, bg index, aspect
    let mut global_table: Vec<[u8; 3]> = Vec::new();
    if packed & 0x80 != 0 {
        let n = 2usize << (packed & 0x07);
        global_table = read_color_table(bytes, &mut pos, n)?;
    }

    let mut transparent: Option<u8> = None;
    loop {
        match bytes.get(pos)? {
            0x21 => {
                // Extension block: label + sub-blocks.
                let label = *bytes.get(pos.checked_add(1)?)?;
                pos = pos.checked_add(2)?;
                if label == 0xF9 {
                    // Graphic control: size(4) packed delay(2) transparent_idx
                    let size = *bytes.get(pos)? as usize;
                    if size >= 4 {
                        let gc_packed = *bytes.get(pos.checked_add(1)?)?;
                        if gc_packed & 0x01 != 0 {
                            transparent = Some(*bytes.get(pos.checked_add(4)?)?);
                        }
                    }
                }
                skip_sub_blocks(bytes, &mut pos)?;
            }
            0x2C => {
                // Image descriptor — decode this (first) frame.
                pos = pos.checked_add(1)?;
                let fx = u16::from_le_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                let fy = u16::from_le_bytes([*bytes.get(pos + 2)?, *bytes.get(pos + 3)?]) as usize;
                let fw = u16::from_le_bytes([*bytes.get(pos + 4)?, *bytes.get(pos + 5)?]) as usize;
                let fh = u16::from_le_bytes([*bytes.get(pos + 6)?, *bytes.get(pos + 7)?]) as usize;
                let ipacked = *bytes.get(pos + 8)?;
                pos = pos.checked_add(9)?;
                let mut table = global_table;
                if ipacked & 0x80 != 0 {
                    let n = 2usize << (ipacked & 0x07);
                    table = read_color_table(bytes, &mut pos, n)?;
                }
                if table.is_empty() || fw == 0 || fh == 0 {
                    return None;
                }
                let interlaced = ipacked & 0x40 != 0;
                let min_code_size = *bytes.get(pos)?;
                pos = pos.checked_add(1)?;
                let mut lzw_data: Vec<u8> = Vec::new();
                loop {
                    let n = *bytes.get(pos)? as usize;
                    pos = pos.checked_add(1)?;
                    if n == 0 {
                        break;
                    }
                    lzw_data.extend_from_slice(bytes.get(pos..pos.checked_add(n)?)?);
                    pos = pos.checked_add(n)?;
                }
                let indices = lzw_decode(&lzw_data, min_code_size, fw.checked_mul(fh)?)?;
                // Composite into the logical screen (transparent background).
                let mut rgba = vec![0u8; sw.checked_mul(sh)?.checked_mul(4)?];
                let rows: Vec<usize> = if interlaced {
                    interlace_rows(fh)
                } else {
                    (0..fh).collect()
                };
                for (src_row, dst_row) in rows.iter().enumerate() {
                    for x in 0..fw {
                        let idx = *indices.get(src_row.checked_mul(fw)?.checked_add(x)?)?;
                        if Some(idx) == transparent {
                            continue;
                        }
                        let [r, g, b] = *table.get(idx as usize)?;
                        let dy = fy.checked_add(*dst_row)?;
                        let dx = fx.checked_add(x)?;
                        if dy >= sh || dx >= sw {
                            continue;
                        }
                        let off = dy.checked_mul(sw)?.checked_add(dx)?.checked_mul(4)?;
                        if let Some(px) = rgba.get_mut(off..off.checked_add(4)?) {
                            px.copy_from_slice(&[r, g, b, 255]);
                        }
                    }
                }
                return DecodedImage::new(sw, sh, rgba);
            }
            0x3B => return None, // trailer before any image
            _ => return None,
        }
    }
}

fn read_color_table(bytes: &[u8], pos: &mut usize, n: usize) -> Option<Vec<[u8; 3]>> {
    let end = pos.checked_add(n.checked_mul(3)?)?;
    let data = bytes.get(*pos..end)?;
    *pos = end;
    Some(data.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect())
}

fn skip_sub_blocks(bytes: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let n = *bytes.get(*pos)? as usize;
        *pos = pos.checked_add(1)?;
        if n == 0 {
            return Some(());
        }
        *pos = pos.checked_add(n)?;
    }
}

/// GIF interlace pass row order.
fn interlace_rows(h: usize) -> Vec<usize> {
    let mut rows = Vec::with_capacity(h);
    for (start, step) in [(0usize, 8usize), (4, 8), (2, 4), (1, 2)] {
        let mut y = start;
        while y < h {
            rows.push(y);
            y = y.saturating_add(step);
        }
    }
    rows
}

/// LZW decompression (GIF variant, variable code width, clear/end codes).
fn lzw_decode(data: &[u8], min_code_size: u8, max_pixels: usize) -> Option<Vec<u8>> {
    if min_code_size > 11 {
        return None;
    }
    let clear = 1u16 << min_code_size;
    let end = clear + 1;
    let mut code_size = min_code_size as u32 + 1;
    // Dictionary: each entry is (prefix_code, suffix_byte); roots are inline.
    let mut dict: Vec<(u16, u8)> = Vec::new();
    let mut next_code = end + 1;
    let mut out: Vec<u8> = Vec::new();
    let mut prev: Option<u16> = None;
    let mut acc = 0u32;
    let mut acc_bits = 0u32;

    let expand = |code: u16, dict: &Vec<(u16, u8)>, clear: u16, out: &mut Vec<u8>| -> Option<u8> {
        // Walk the chain, then reverse in place. Returns the FIRST byte.
        let start = out.len();
        let mut c = code;
        let mut guard = 0usize;
        loop {
            guard = guard.saturating_add(1);
            if guard > 1 << 16 {
                return None;
            }
            if c < clear {
                out.push(c as u8);
                break;
            }
            let e = dict.get(c.checked_sub(clear.checked_add(2)?)? as usize)?;
            out.push(e.1);
            c = e.0;
        }
        out.get(start..)?.to_vec(); // bounds sanity
        let slice = out.get_mut(start..)?;
        slice.reverse();
        slice.first().copied()
    };

    for &byte in data {
        acc |= (byte as u32) << acc_bits;
        acc_bits += 8;
        while acc_bits >= code_size {
            let code = (acc & ((1u32 << code_size) - 1)) as u16;
            acc >>= code_size;
            acc_bits -= code_size;
            if code == clear {
                dict.clear();
                next_code = end + 1;
                code_size = min_code_size as u32 + 1;
                prev = None;
                continue;
            }
            if code == end {
                return Some(out);
            }
            if out.len() > max_pixels {
                return Some(out);
            }
            match prev {
                None => {
                    if code >= clear {
                        return None;
                    }
                    out.push(code as u8);
                    prev = Some(code);
                }
                Some(p) => {
                    let first = if code < next_code {
                        expand(code, &dict, clear, &mut out)?
                    } else if code == next_code {
                        // KwKwK case: emit prev's expansion + its first byte.
                        let f = first_byte(p, &dict, clear)?;
                        let start = out.len();
                        let mut c = p;
                        let mut chain: Vec<u8> = Vec::new();
                        let mut guard = 0usize;
                        loop {
                            guard = guard.saturating_add(1);
                            if guard > 1 << 16 {
                                return None;
                            }
                            if c < clear {
                                chain.push(c as u8);
                                break;
                            }
                            let e = dict.get(c.checked_sub(clear.checked_add(2)?)? as usize)?;
                            chain.push(e.1);
                            c = e.0;
                        }
                        chain.reverse();
                        out.extend_from_slice(&chain);
                        out.push(f);
                        let _ = start;
                        f
                    } else {
                        return None;
                    };
                    if next_code < 4096 {
                        dict.push((p, first));
                        next_code = next_code.saturating_add(1);
                        if next_code == (1 << code_size) && code_size < 12 {
                            code_size += 1;
                        }
                    }
                    prev = Some(code);
                }
            }
        }
    }
    Some(out)
}

/// First byte of a code's expansion without emitting it.
fn first_byte(code: u16, dict: &[(u16, u8)], clear: u16) -> Option<u8> {
    let mut c = code;
    let mut guard = 0usize;
    loop {
        guard = guard.saturating_add(1);
        if guard > 1 << 16 {
            return None;
        }
        if c < clear {
            return Some(c as u8);
        }
        c = dict.get(c.checked_sub(clear.checked_add(2)?)? as usize)?.0;
    }
}
