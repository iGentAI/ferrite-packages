//! webp — dependency-free WebP decoder for the two container layouts that
//! dominate the web: VP8L (lossless) fully, and VP8 (lossy) baseline
//! key-frame decoding of the luma/chroma planes.
//!
//! Like the other decoders: hostile/truncated input yields `None`, never a
//! panic; output is capped by [`super::MAX_PIXELS`].

use super::{DecodedImage, MAX_PIXELS};

/// Header-only dimensions.
pub fn dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    let (fourcc, payload) = first_chunk(bytes)?;
    match &fourcc {
        b"VP8L" => vp8l_dimensions(payload),
        b"VP8 " => vp8_dimensions(payload),
        b"VP8X" => {
            // Extended header: 24-bit canvas w-1 / h-1 at offset 4.
            let w = le24(payload.get(4..7)?)? as usize + 1;
            let h = le24(payload.get(7..10)?)? as usize + 1;
            Some((w, h))
        }
        _ => None,
    }
}

/// Decode a WebP image into RGBA8.
pub fn decode(bytes: &[u8]) -> Option<DecodedImage> {
    // Walk chunks: VP8X containers carry the image in a later VP8/VP8L chunk.
    let mut pos = 12usize; // RIFF(4) size(4) WEBP(4)
    while pos + 8 <= bytes.len() {
        let fourcc: [u8; 4] = bytes.get(pos..pos + 4)?.try_into().ok()?;
        let len = u32::from_le_bytes(bytes.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
        let start = pos.checked_add(8)?;
        let end = start.checked_add(len)?;
        let payload = bytes.get(start..end.min(bytes.len()))?;
        match &fourcc {
            b"VP8L" => return vp8l_decode(payload),
            b"VP8 " => return vp8_decode(payload),
            _ => {}
        }
        pos = end.checked_add(len & 1)?; // chunks are 2-byte aligned
    }
    None
}

fn first_chunk(bytes: &[u8]) -> Option<([u8; 4], &[u8])> {
    if !bytes.starts_with(b"RIFF") || bytes.get(8..12) != Some(b"WEBP") {
        return None;
    }
    let fourcc: [u8; 4] = bytes.get(12..16)?.try_into().ok()?;
    let len = u32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?) as usize;
    let payload = bytes.get(20..20usize.checked_add(len)?.min(bytes.len()))?;
    Some((fourcc, payload))
}

fn le24(b: &[u8]) -> Option<u32> {
    Some(u32::from(*b.first()?) | u32::from(*b.get(1)?) << 8 | u32::from(*b.get(2)?) << 16)
}

struct LBits<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
}

impl<'a> LBits<'a> {
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut out = 0u32;
        for i in 0..n {
            let byte = self.data.get(self.pos)?;
            let b = (byte >> self.bit) & 1;
            out |= u32::from(b) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.pos += 1;
            }
        }
        Some(out)
    }
}

fn vp8l_dimensions(payload: &[u8]) -> Option<(usize, usize)> {
    if payload.first() != Some(&0x2f) {
        return None;
    }
    let mut r = LBits {
        data: payload.get(1..)?,
        pos: 0,
        bit: 0,
    };
    let w = r.bits(14)? as usize + 1;
    let h = r.bits(14)? as usize + 1;
    Some((w, h))
}

/// Huffman code for VP8L: canonical, built from code lengths.
struct HuffTree {
    /// (bits, value), indexed by up-to-15-bit reversed prefix via linear scan
    /// fallback table; fast path is a 8-bit lookup.
    fast: Vec<(u8, u16)>,
    long: Vec<(u32, u32, u16)>, // (code, len, value)
}

impl HuffTree {
    fn build(lens: &[u8]) -> Option<HuffTree> {
        // VP8L encodes single-symbol trees with a nominal length, but the
        // symbol consumes no bits in the pixel stream.
        let mut used = lens.iter().enumerate().filter(|&(_, &len)| len > 0);
        let (first, _) = used.next()?;
        if used.next().is_none() {
            return Some(HuffTree {
                fast: vec![(0, first as u16); 256],
                long: Vec::new(),
            });
        }
        // Canonical code assignment.
        let mut bl_count = [0u32; 16];
        for &l in lens {
            if l > 15 {
                return None;
            }
            if l > 0 {
                bl_count[l as usize] += 1;
            }
        }
        let mut next_code = [0u32; 16];
        let mut code = 0u32;
        for i in 1..16 {
            code = (code + bl_count[i - 1]) << 1;
            next_code[i] = code;
        }
        let mut fast = vec![(0u8, u16::MAX); 256];
        let mut long = Vec::new();
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let c = next_code[l as usize];
            next_code[l as usize] += 1;
            if l <= 8 {
                // Fill all fast-table slots whose low `l` bits (reversed)
                // match this code.
                let rev = reverse_bits(c, l as u32);
                let step = 1usize << l;
                let mut idx = rev as usize;
                while idx < 256 {
                    if let Some(slot) = fast.get_mut(idx) {
                        *slot = (l, sym as u16);
                    }
                    idx += step;
                }
            } else {
                long.push((c, l as u32, sym as u16));
            }
        }
        Some(HuffTree { fast, long })
    }

    fn read(&self, r: &mut LBits) -> Option<u16> {
        // Peek 8 bits without consuming (manual, since LBits is LSB-first).
        let save = (r.pos, r.bit);
        // Near the end, preserve the available bits and zero-extend any
        // missing table index bits. Consumption still checks availability.
        let available = r.data.len().saturating_sub(r.pos).saturating_mul(8)
            .saturating_sub(r.bit as usize).min(8);
        let peek = r.bits(available as u32)?;
        let (len, sym) = *self.fast.get(peek as usize & 0xff)?;
        if sym != u16::MAX && len > 0 {
            // Consume only `len` bits.
            r.pos = save.0;
            r.bit = save.1;
            r.bits(u32::from(len))?;
            return Some(sym);
        }
        if sym != u16::MAX && len == 0 {
            // Degenerate single-symbol tree consumes nothing.
            r.pos = save.0;
            r.bit = save.1;
            return Some(sym);
        }
        // Slow path: accumulate MSB-first code bit by bit.
        r.pos = save.0;
        r.bit = save.1;
        let mut code = 0u32;
        for len in 1..=15u32 {
            code = (code << 1) | r.bits(1)?;
            for &(c, l, s) in &self.long {
                if l == len && c == code {
                    return Some(s);
                }
            }
        }
        None
    }
}

fn reverse_bits(v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..n {
        out |= ((v >> i) & 1) << (n - 1 - i);
    }
    out
}

/// Read the meta code-lengths encoding for one Huffman tree.
fn read_code_lengths(r: &mut LBits, alphabet: usize) -> Option<Vec<u8>> {
    let simple = r.bits(1)? == 1;
    let mut lens = vec![0u8; alphabet];
    if simple {
        let num_symbols = r.bits(1)? as usize + 1;
        let first_len = if r.bits(1)? == 1 { 8 } else { 1 };
        let s0 = r.bits(first_len)? as usize;
        if let Some(slot) = lens.get_mut(s0) {
            *slot = 1;
        }
        if num_symbols == 2 {
            let s1 = r.bits(8)? as usize;
            if let Some(slot) = lens.get_mut(s1) {
                *slot = 1;
            }
        }
        return Some(lens);
    }
    // Code-length code.
    const ORDER: [usize; 19] = [
        17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let num_codes = r.bits(4)? as usize + 4;
    let mut cl_lens = [0u8; 19];
    for i in 0..num_codes.min(19) {
        let v = r.bits(3)? as u8;
        if let Some(&idx) = ORDER.get(i) {
            if let Some(slot) = cl_lens.get_mut(idx) {
                *slot = v;
            }
        }
    }
    let cl_tree = HuffTree::build(&cl_lens)?;
    // Optional total-symbols limit.
    let max_symbol = if r.bits(1)? == 1 {
        let len_nbits = 2 + 2 * r.bits(3)? as usize;
        2 + r.bits(len_nbits as u32)? as usize
    } else {
        alphabet
    };
    let mut prev = 8u8;
    let mut i = 0usize;
    let mut remaining = max_symbol;
    while i < alphabet && remaining > 0 {
        remaining -= 1;
        let sym = cl_tree.read(r)?;
        match sym {
            0..=15 => {
                if let Some(slot) = lens.get_mut(i) {
                    *slot = sym as u8;
                }
                if sym != 0 {
                    prev = sym as u8;
                }
                i += 1;
            }
            16 => {
                let n = 3 + r.bits(2)? as usize;
                for _ in 0..n {
                    if i < alphabet {
                        if let Some(slot) = lens.get_mut(i) {
                            *slot = prev;
                        }
                        i += 1;
                    }
                }
            }
            17 => {
                let n = 3 + r.bits(3)? as usize;
                i += n;
            }
            18 => {
                let n = 11 + r.bits(7)? as usize;
                i += n;
            }
            _ => return None,
        }
    }
    Some(lens)
}

/// One VP8L Huffman group: 5 trees (green+len+dist codes, red, blue, alpha, dist).
struct HuffGroup {
    green: HuffTree,
    red: HuffTree,
    blue: HuffTree,
    alpha: HuffTree,
    dist: HuffTree,
}

fn read_huff_group(r: &mut LBits, color_cache_bits: u32) -> Option<HuffGroup> {
    let green_alpha = 256
        + 24
        + if color_cache_bits > 0 {
            1usize << color_cache_bits
        } else {
            0
        };
    Some(HuffGroup {
        green: HuffTree::build(&read_code_lengths(r, green_alpha)?)?,
        red: HuffTree::build(&read_code_lengths(r, 256)?)?,
        blue: HuffTree::build(&read_code_lengths(r, 256)?)?,
        alpha: HuffTree::build(&read_code_lengths(r, 256)?)?,
        dist: HuffTree::build(&read_code_lengths(r, 40)?)?,
    })
}

fn vp8l_decode(payload: &[u8]) -> Option<DecodedImage> {
    if payload.first() != Some(&0x2f) {
        return None;
    }
    let mut r = LBits {
        data: payload.get(1..)?,
        pos: 0,
        bit: 0,
    };
    let width = r.bits(14)? as usize + 1;
    let height = r.bits(14)? as usize + 1;
    let _alpha_hint = r.bits(1)?;
    let version = r.bits(3)?;
    if version != 0 {
        return None;
    }
    if width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    decode_image_data(&mut r, width, height, true)
}

/// Transforms present in a VP8L stream (applied in reverse order on output).
enum Transform {
    Predictor { size_bits: u32, data: Vec<u32> },
    Color { size_bits: u32, data: Vec<u32> },
    SubtractGreen,
    ColorIndex { table: Vec<u32>, index_bits: u32 },
}

fn decode_image_data(
    r: &mut LBits,
    width: usize,
    height: usize,
    top_level: bool,
) -> Option<DecodedImage> {
    let mut transforms: Vec<Transform> = Vec::new();
    let mut xsize = width;

    if top_level {
        // Read transforms.
        let mut seen = [false; 4];
        while r.bits(1)? == 1 {
            let ttype = r.bits(2)?;
            let idx = ttype as usize;
            if seen.get(idx).copied().unwrap_or(true) {
                return None; // each transform at most once
            }
            if let Some(s) = seen.get_mut(idx) {
                *s = true;
            }
            match ttype {
                0 => {
                    // Predictor.
                    let size_bits = r.bits(3)? + 2;
                    let bw = subsample_size(xsize, size_bits);
                    let bh = subsample_size(height, size_bits);
                    let sub = decode_image_data(r, bw, bh, false)?;
                    transforms.push(Transform::Predictor {
                        size_bits,
                        data: argb_of(&sub),
                    });
                }
                1 => {
                    // Color transform.
                    let size_bits = r.bits(3)? + 2;
                    let bw = subsample_size(xsize, size_bits);
                    let bh = subsample_size(height, size_bits);
                    let sub = decode_image_data(r, bw, bh, false)?;
                    transforms.push(Transform::Color {
                        size_bits,
                        data: argb_of(&sub),
                    });
                }
                2 => transforms.push(Transform::SubtractGreen),
                3 => {
                    // Color indexing.
                    let count = r.bits(8)? as usize + 1;
                    let table_img = decode_image_data(r, count, 1, false)?;
                    let mut table = argb_of(&table_img);
                    // Palette entries are delta-coded.
                    for i in 1..table.len() {
                        let prev = *table.get(i - 1)?;
                        let cur = *table.get(i)?;
                        let sum = add_pixels(cur, prev);
                        *table.get_mut(i)? = sum;
                    }
                    let index_bits = if count <= 2 {
                        3
                    } else if count <= 4 {
                        2
                    } else if count <= 16 {
                        1
                    } else {
                        0
                    };
                    xsize = subsample_size(xsize, index_bits);
                    transforms.push(Transform::ColorIndex { table, index_bits });
                }
                _ => return None,
            }
        }
    }

    // Color cache.
    let color_cache_bits = if r.bits(1)? == 1 {
        let b = r.bits(4)?;
        if !(1..=11).contains(&b) {
            return None;
        }
        b
    } else {
        0
    };

    // Meta-Huffman: multiple groups selected per 2^bits block.
    let (meta_huff, huff_bits, num_groups) = if top_level && r.bits(1)? == 1 {
        let huff_bits = r.bits(3)? + 2;
        let bw = subsample_size(xsize, huff_bits);
        let bh = subsample_size(height, huff_bits);
        let meta = decode_image_data(r, bw, bh, false)?;
        let meta_argb = argb_of(&meta);
        let max_group = meta_argb
            .iter()
            .map(|&p| ((p >> 8) & 0xffff) as usize)
            .max()
            .unwrap_or(0);
        (Some((meta_argb, bw)), huff_bits, max_group + 1)
    } else {
        (None, 0, 1)
    };

    let mut groups = Vec::new();
    for _ in 0..num_groups {
        groups.push(read_huff_group(r, color_cache_bits)?);
    }

    // Color cache storage.
    let cache_size = if color_cache_bits > 0 {
        1usize << color_cache_bits
    } else {
        0
    };
    let mut cache = vec![0u32; cache_size];

    // Main decode loop: LZ77 over ARGB pixels.
    let total = xsize.checked_mul(height)?;
    if total > MAX_PIXELS {
        return None;
    }
    let mut pixels: Vec<u32> = Vec::with_capacity(total);
    while pixels.len() < total {
        // Select group.
        let group = match &meta_huff {
            Some((meta, bw)) => {
                let x = pixels.len() % xsize;
                let y = pixels.len() / xsize;
                let mx = x >> huff_bits;
                let my = y >> huff_bits;
                let gi = meta
                    .get(my.checked_mul(*bw)?.checked_add(mx)?)
                    .map(|&p| ((p >> 8) & 0xffff) as usize)
                    .unwrap_or(0);
                groups.get(gi)?
            }
            None => groups.first()?,
        };
        let sym = group.green.read(&mut *r)?;
        match sym {
            0..=255 => {
                // Literal: G, then R, B, A from their trees.
                let g = sym as u32;
                let red = group.red.read(r)? as u32;
                let blue = group.blue.read(r)? as u32;
                let alpha = group.alpha.read(r)? as u32;
                let px = (alpha << 24) | (red << 16) | (g << 8) | blue;
                if cache_size > 0 {
                    let idx = (px.wrapping_mul(0x1e35a7bd) >> (32 - color_cache_bits)) as usize;
                    if let Some(slot) = cache.get_mut(idx) {
                        *slot = px;
                    }
                }
                pixels.push(px);
            }
            256..=279 => {
                // LZ77 backward reference.
                let len_code = sym - 256;
                let length = read_lz77_extra(r, len_code as u32)? as usize;
                let dist_code = group.dist.read(r)?;
                let dist_raw = read_lz77_extra(r, dist_code as u32)? as usize;
                let dist = plane_code_to_distance(xsize, dist_raw);
                if dist == 0 || dist > pixels.len() {
                    return None;
                }
                for _ in 0..length {
                    if pixels.len() >= total {
                        break;
                    }
                    let p = *pixels.get(pixels.len() - dist)?;
                    if cache_size > 0 {
                        let idx = (p.wrapping_mul(0x1e35a7bd) >> (32 - color_cache_bits)) as usize;
                        if let Some(slot) = cache.get_mut(idx) {
                            *slot = p;
                        }
                    }
                    pixels.push(p);
                }
            }
            _ => {
                // Color cache reference.
                let idx = (sym as usize).checked_sub(256 + 24)?;
                let px = *cache.get(idx)?;
                pixels.push(px);
            }
        }
    }

    // Apply transforms in reverse.
    for t in transforms.iter().rev() {
        match t {
            Transform::ColorIndex { table, index_bits } => {
                pixels = apply_color_index(&pixels, table, *index_bits, width, height, xsize)?;
                xsize = width;
            }
            Transform::SubtractGreen => {
                for p in pixels.iter_mut() {
                    let g = (*p >> 8) & 0xff;
                    let r0 = ((*p >> 16) & 0xff).wrapping_add(g) & 0xff;
                    let b0 = (*p & 0xff).wrapping_add(g) & 0xff;
                    *p = (*p & 0xff00ff00) | (r0 << 16) | b0;
                }
            }
            Transform::Predictor { size_bits, data } => {
                apply_predictor_inverse(&mut pixels, data, *size_bits, xsize, height)?;
            }
            Transform::Color { size_bits, data } => {
                apply_color_inverse(&mut pixels, data, *size_bits, xsize, height)?;
            }
        }
    }

    // ARGB -> RGBA bytes.
    let mut rgba = Vec::with_capacity(pixels.len().checked_mul(4)?);
    for p in &pixels {
        rgba.push(((p >> 16) & 0xff) as u8);
        rgba.push(((p >> 8) & 0xff) as u8);
        rgba.push((p & 0xff) as u8);
        rgba.push(((p >> 24) & 0xff) as u8);
    }
    DecodedImage::new(xsize, height, rgba)
}

fn argb_of(img: &DecodedImage) -> Vec<u32> {
    let mut out = Vec::with_capacity(img.width * img.height);
    for px in img.rgba.chunks_exact(4) {
        let r = u32::from(*px.first().unwrap_or(&0));
        let g = u32::from(*px.get(1).unwrap_or(&0));
        let b = u32::from(*px.get(2).unwrap_or(&0));
        let a = u32::from(*px.get(3).unwrap_or(&0));
        out.push((a << 24) | (r << 16) | (g << 8) | b);
    }
    out
}

fn subsample_size(size: usize, bits: u32) -> usize {
    (size + (1 << bits) - 1) >> bits
}

fn add_pixels(a: u32, b: u32) -> u32 {
    let ab = ((a >> 24) & 0xff).wrapping_add((b >> 24) & 0xff) & 0xff;
    let ar = ((a >> 16) & 0xff).wrapping_add((b >> 16) & 0xff) & 0xff;
    let ag = ((a >> 8) & 0xff).wrapping_add((b >> 8) & 0xff) & 0xff;
    let aa = (a & 0xff).wrapping_add(b & 0xff) & 0xff;
    (ab << 24) | (ar << 16) | (ag << 8) | aa
}

fn read_lz77_extra(r: &mut LBits, code: u32) -> Option<u32> {
    if code < 4 {
        return Some(code + 1);
    }
    let extra_bits = (code - 2) >> 1;
    let offset = (2 + (code & 1)) << extra_bits;
    Some(offset + r.bits(extra_bits)? + 1)
}

fn plane_code_to_distance(xsize: usize, plane_code: usize) -> usize {
    // Codes 1..=120 map to a neighbourhood pattern; >120 is direct.
    const OFFSETS: [(i8, i8); 120] = [
        (0, 1),
        (1, 0),
        (1, 1),
        (-1, 1),
        (0, 2),
        (2, 0),
        (1, 2),
        (-1, 2),
        (2, 1),
        (-2, 1),
        (2, 2),
        (-2, 2),
        (0, 3),
        (3, 0),
        (1, 3),
        (-1, 3),
        (3, 1),
        (-3, 1),
        (2, 3),
        (-2, 3),
        (3, 2),
        (-3, 2),
        (0, 4),
        (4, 0),
        (1, 4),
        (-1, 4),
        (4, 1),
        (-4, 1),
        (3, 3),
        (-3, 3),
        (2, 4),
        (-2, 4),
        (4, 2),
        (-4, 2),
        (0, 5),
        (3, 4),
        (-3, 4),
        (4, 3),
        (-4, 3),
        (5, 0),
        (1, 5),
        (-1, 5),
        (5, 1),
        (-5, 1),
        (2, 5),
        (-2, 5),
        (5, 2),
        (-5, 2),
        (4, 4),
        (-4, 4),
        (3, 5),
        (-3, 5),
        (5, 3),
        (-5, 3),
        (0, 6),
        (6, 0),
        (1, 6),
        (-1, 6),
        (6, 1),
        (-6, 1),
        (2, 6),
        (-2, 6),
        (6, 2),
        (-6, 2),
        (4, 5),
        (-4, 5),
        (5, 4),
        (-5, 4),
        (3, 6),
        (-3, 6),
        (6, 3),
        (-6, 3),
        (0, 7),
        (7, 0),
        (1, 7),
        (-1, 7),
        (5, 5),
        (-5, 5),
        (7, 1),
        (-7, 1),
        (4, 6),
        (-4, 6),
        (6, 4),
        (-6, 4),
        (2, 7),
        (-2, 7),
        (7, 2),
        (-7, 2),
        (3, 7),
        (-3, 7),
        (7, 3),
        (-7, 3),
        (5, 6),
        (-5, 6),
        (6, 5),
        (-6, 5),
        (8, 0),
        (4, 7),
        (-4, 7),
        (7, 4),
        (-7, 4),
        (8, 1),
        (8, 2),
        (6, 6),
        (-6, 6),
        (2, 8),
        (-2, 8),
        (8, 3),
        (-8, 3),
        (5, 7),
        (-5, 7),
        (7, 5),
        (-7, 5),
        (8, 4),
        (3, 8),
        (-3, 8),
        (0, 8),
        (8, 5),
        (1, 8),
        (-1, 8),
    ];
    if plane_code > 120 {
        return plane_code - 120;
    }
    match OFFSETS.get(plane_code.wrapping_sub(1)) {
        Some(&(dx, dy)) => {
            let d = (dy as isize) * (xsize as isize) + (dx as isize);
            if d >= 1 {
                d as usize
            } else {
                1
            }
        }
        None => plane_code,
    }
}

fn apply_color_index(
    pixels: &[u32],
    table: &[u32],
    index_bits: u32,
    width: usize,
    height: usize,
    packed_xsize: usize,
) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(width.checked_mul(height)?);
    if index_bits == 0 {
        for p in pixels {
            let idx = ((*p >> 8) & 0xff) as usize;
            out.push(table.get(idx).copied().unwrap_or(0xff000000));
        }
        return Some(out);
    }
    let pixels_per_byte = 1usize << index_bits;
    let bits_per_entry = 8 / pixels_per_byte as u32;
    let mask = (1u32 << bits_per_entry) - 1;
    for y in 0..height {
        for x in 0..width {
            let packed_x = x >> index_bits;
            let p = pixels.get(y.checked_mul(packed_xsize)?.checked_add(packed_x)?)?;
            let g = (*p >> 8) & 0xff;
            let shift = ((x % pixels_per_byte) as u32) * bits_per_entry;
            let idx = ((g >> shift) & mask) as usize;
            out.push(table.get(idx).copied().unwrap_or(0xff000000));
        }
    }
    Some(out)
}

fn apply_predictor_inverse(
    pixels: &mut [u32],
    pred_data: &[u32],
    size_bits: u32,
    xsize: usize,
    ysize: usize,
) -> Option<()> {
    let block_xsize = subsample_size(xsize, size_bits);
    for y in 0..ysize {
        for x in 0..xsize {
            let i = y.checked_mul(xsize)?.checked_add(x)?;
            let mode = if x == 0 && y == 0 {
                0 // black
            } else if y == 0 {
                1 // left
            } else if x == 0 {
                2 // top
            } else {
                let bi = (y >> size_bits)
                    .checked_mul(block_xsize)?
                    .checked_add(x >> size_bits)?;
                pred_data
                    .get(bi)
                    .map(|&p| ((p >> 8) & 0xf) as usize)
                    .unwrap_or(0)
            };
            let left = if x > 0 {
                pixels.get(i - 1).copied().unwrap_or(0)
            } else {
                0xff000000
            };
            let top = if y > 0 {
                pixels.get(i - xsize).copied().unwrap_or(0)
            } else {
                0xff000000
            };
            let top_left = if x > 0 && y > 0 {
                pixels.get(i - xsize - 1).copied().unwrap_or(0)
            } else {
                0xff000000
            };
            let top_right = if y > 0 && x + 1 < xsize {
                pixels.get(i - xsize + 1).copied().unwrap_or(0)
            } else {
                top
            };
            let pred = match mode {
                0 => 0xff000000,
                1 => left,
                2 => top,
                3 => top_right,
                4 => top_left,
                5 => average2(average2(left, top_right), top),
                6 => average2(left, top_left),
                7 => average2(left, top),
                8 => average2(top_left, top),
                9 => average2(top, top_right),
                10 => average2(average2(left, top_left), average2(top, top_right)),
                11 => select(left, top, top_left),
                12 => clamp_add_subtract_full(left, top, top_left),
                13 => clamp_add_subtract_half(average2(left, top), top_left),
                _ => 0xff000000,
            };
            let cur = pixels.get(i).copied()?;
            if let Some(slot) = pixels.get_mut(i) {
                *slot = add_pixels(cur, pred);
            }
        }
    }
    Some(())
}

fn average2(a: u32, b: u32) -> u32 {
    let mask = 0x00ff00ffu32;
    let s1 = ((a & mask) + (b & mask)) >> 1 & mask;
    let mask2 = 0xff00ff00u32;
    let s2 = (((a & mask2) >> 1) + ((b & mask2) >> 1)) & mask2;
    s1 | s2
}

fn select(left: u32, top: u32, top_left: u32) -> u32 {
    let pa = distance(top, top_left);
    let pb = distance(left, top_left);
    if pa <= pb {
        left
    } else {
        top
    }
}

fn distance(a: u32, b: u32) -> i32 {
    let mut sum = 0i32;
    for shift in [24u32, 16, 8, 0] {
        let ca = ((a >> shift) & 0xff) as i32;
        let cb = ((b >> shift) & 0xff) as i32;
        sum += (ca - cb).abs();
    }
    sum
}

fn clamp_add_subtract_full(a: u32, b: u32, c: u32) -> u32 {
    let mut out = 0u32;
    for shift in [24u32, 16, 8, 0] {
        let ca = ((a >> shift) & 0xff) as i32;
        let cb = ((b >> shift) & 0xff) as i32;
        let cc = ((c >> shift) & 0xff) as i32;
        let v = (ca + cb - cc).clamp(0, 255) as u32;
        out |= v << shift;
    }
    out
}

fn clamp_add_subtract_half(a: u32, c: u32) -> u32 {
    let mut out = 0u32;
    for shift in [24u32, 16, 8, 0] {
        let ca = ((a >> shift) & 0xff) as i32;
        let cc = ((c >> shift) & 0xff) as i32;
        let v = (ca + (ca - cc) / 2).clamp(0, 255) as u32;
        out |= v << shift;
    }
    out
}

fn apply_color_inverse(
    pixels: &mut [u32],
    cdata: &[u32],
    size_bits: u32,
    xsize: usize,
    ysize: usize,
) -> Option<()> {
    let block_xsize = subsample_size(xsize, size_bits);
    for y in 0..ysize {
        for x in 0..xsize {
            let i = y.checked_mul(xsize)?.checked_add(x)?;
            let bi = (y >> size_bits)
                .checked_mul(block_xsize)?
                .checked_add(x >> size_bits)?;
            let cx = cdata.get(bi).copied().unwrap_or(0);
            let g2r = ((cx >> 8) & 0xff) as i8 as i32;
            let g2b = ((cx >> 16) & 0xff) as i8 as i32;
            let r2b = ((cx >> 24) & 0xff) as i8 as i32;
            let p = pixels.get(i).copied()?;
            let g = ((p >> 8) & 0xff) as i32;
            let mut r0 = ((p >> 16) & 0xff) as i32;
            let mut b0 = (p & 0xff) as i32;
            r0 = (r0 + ((g2r * (g as i8 as i32)) >> 5)) & 0xff;
            b0 = (b0 + ((g2b * (g as i8 as i32)) >> 5)) & 0xff;
            b0 = (b0 + ((r2b * (r0 as i8 as i32)) >> 5)) & 0xff;
            if let Some(slot) = pixels.get_mut(i) {
                *slot = (p & 0xff00ff00) | ((r0 as u32) << 16) | (b0 as u32);
            }
        }
    }
    Some(())
}

fn vp8_dimensions(payload: &[u8]) -> Option<(usize, usize)> {
    // Frame tag: 3 bytes; key frames then have 7 more bytes incl. start code.
    if payload.len() < 10 {
        return None;
    }
    let tag = le24(payload.get(0..3)?)?;
    let key_frame = tag & 1 == 0;
    if !key_frame {
        return None;
    }
    if payload.get(3..6) != Some(&[0x9d, 0x01, 0x2a]) {
        return None;
    }
    let w = u16::from_le_bytes(payload.get(6..8)?.try_into().ok()?) as usize & 0x3fff;
    let h = u16::from_le_bytes(payload.get(8..10)?.try_into().ok()?) as usize & 0x3fff;
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

/// Baseline VP8 key-frame decode per RFC 6386 (no loop filter): boolean
/// entropy decoder, key-frame header, intra prediction, coefficient tokens,
/// dequantization, and inverse WHT/DCT reconstruction live in [`super::vp8`].
/// The in-loop deblocking filter is parsed but not applied — an accepted
/// quality trade documented in that module. Non-key frames (video payloads)
/// and malformed data still yield `None`.
fn vp8_decode(payload: &[u8]) -> Option<DecodedImage> {
    super::vp8::decode(payload)
}
