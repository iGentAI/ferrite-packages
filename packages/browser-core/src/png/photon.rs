//! RGBA8 PNG preparation compatible with image/png's pinned Fast profile.
//! The screenshot writer keeps its current format. See the package notices.

use std::io::{self, Cursor, Write};

use super::write_chunk;

mod deflate;
mod tables;
use deflate::{Compressor, StoredOnlyCompressor};

const PNG_OVERHEAD: usize = 57; // signature, IHDR, one IDAT, IEND

pub(crate) fn encode(width: u32, height: u32, rgba: &[u8], limit: usize) -> Option<Vec<u8>> {
    let max_payload = limit.checked_sub(PNG_OVERHEAD)?;
    let row_bytes = (width as usize).checked_mul(4)?;
    let raw = row_bytes.checked_add(1)?.checked_mul(height as usize)?;
    if width == 0
        || height == 0
        || (width as usize).checked_mul(height as usize)? > crate::browser_core::image::MAX_PIXELS
        || rgba.len() != row_bytes.checked_mul(height as usize)?
    {
        return None;
    }
    // The pinned encoder caps the fast candidate at its own stored-size
    // comparison, including the reference's exact-65535-multiple behavior.
    let threshold = StoredOnlyCompressor::<Cursor<Vec<u8>>>::compressed_size(raw);
    let work_limit = threshold.min(max_payload);
    let compressed = fast(rgba, row_bytes, work_limit).ok();
    let payload = match compressed {
        Some(payload) => payload,
        None => {
            let stored_bytes = raw
                .checked_add(raw.div_ceil(65_535).checked_mul(5)?)?
                .checked_add(6)?;
            if stored_bytes > max_payload {
                return None;
            }
            stored(rgba, row_bytes, stored_bytes).ok()?
        }
    };
    let mut out = Vec::with_capacity(PNG_OVERHEAD + payload.len());
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = [0; 13];
    ihdr[..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8;
    ihdr[9] = 6;
    write_chunk(&mut out, b"IHDR", &ihdr);
    write_chunk(&mut out, b"IDAT", &payload);
    write_chunk(&mut out, b"IEND", &[]);
    Some(out)
}

fn fast(rgba: &[u8], row_bytes: usize, limit: usize) -> io::Result<Vec<u8>> {
    let zero = vec![0; row_bytes];
    let mut previous = zero.as_slice();
    let mut filtered = vec![0; row_bytes + 1];
    let mut scratch = vec![0; row_bytes];
    let mut compressor = Compressor::new(Limited {
        bytes: Vec::new(),
        limit,
    })?;
    for row in rgba.chunks_exact(row_bytes) {
        let mut best = u64::MAX;
        for kind in 1..=4 {
            let mut score = 0;
            for (i, (&byte, filtered)) in row.iter().zip(&mut scratch).enumerate() {
                let left = i.checked_sub(4).map_or(0, |at| row[at]);
                let above = previous[i];
                let upper_left = i.checked_sub(4).map_or(0, |at| previous[at]);
                let predictor = match kind {
                    1 => left,
                    2 => above,
                    3 => ((u16::from(left) + u16::from(above)) / 2) as u8,
                    _ => paeth(left, above, upper_left),
                };
                *filtered = byte.wrapping_sub(predictor);
                score += u64::from((*filtered as i8).unsigned_abs());
            }
            // Ties select the later filter, so Paeth wins a four-way tie.
            if score <= best {
                best = score;
                filtered[0] = kind;
                filtered[1..].copy_from_slice(&scratch);
            }
        }
        // The compressor's zero-run choices reset at each write_data call.
        compressor.write_data(&filtered)?;
        previous = row;
    }
    Ok(compressor.finish()?.bytes)
}

fn stored(rgba: &[u8], row_bytes: usize, cap: usize) -> io::Result<Vec<u8>> {
    let mut compressor = StoredOnlyCompressor::new(Cursor::new(Vec::with_capacity(cap)))?;
    for row in rgba.chunks_exact(row_bytes) {
        compressor.write_data(&[0])?;
        compressor.write_data(row)?;
    }
    Ok(compressor.finish()?.into_inner())
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (i16::from(a), i16::from(b), i16::from(c));
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

struct Limited {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Limited {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("PNG candidate exceeded its output budget"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
