//! inflate — a dependency-free RFC 1951 DEFLATE decompressor (plus the
//! RFC 1950 zlib wrapper PNG uses).
//!
//! Panic-free: all reads are bounds-checked; corrupt streams yield `None`.
//! Output is capped by the caller-provided limit so a zip bomb cannot
//! exhaust memory.

/// Inflate a raw DEFLATE stream. `max_out` caps the output size.
pub fn inflate(data: &[u8], max_out: usize) -> Option<Vec<u8>> {
    let mut r = BitReader {
        data,
        pos: 0,
        bit: 0,
    };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = r.bits(1)?;
        let btype = r.bits(2)?;
        match btype {
            0 => {
                // Stored: align to byte, LEN/NLEN, raw copy.
                r.align();
                let len = r.u16le()? as usize;
                let nlen = r.u16le()? as usize;
                if len != (!nlen & 0xffff) {
                    return None;
                }
                for _ in 0..len {
                    let b = r.byte()?;
                    if out.len() >= max_out {
                        return None;
                    }
                    out.push(b);
                }
            }
            1 => {
                // Fixed Huffman tables.
                let (lit, dist) = fixed_tables();
                inflate_block(&mut r, &lit, &dist, &mut out, max_out)?;
            }
            2 => {
                // Dynamic Huffman tables.
                let hlit = r.bits(5)? as usize + 257;
                let hdist = r.bits(5)? as usize + 1;
                let hclen = r.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl_lens = [0u8; 19];
                for i in 0..hclen {
                    let l = r.bits(3)? as u8;
                    let idx = ORDER.get(i)?;
                    if let Some(slot) = cl_lens.get_mut(*idx) {
                        *slot = l;
                    }
                }
                let cl_tree = Huffman::new(&cl_lens)?;
                let mut lens = vec![0u8; hlit + hdist];
                let mut i = 0usize;
                while i < lens.len() {
                    let sym = cl_tree.decode(&mut r)?;
                    match sym {
                        0..=15 => {
                            if let Some(slot) = lens.get_mut(i) {
                                *slot = sym as u8;
                            }
                            i += 1;
                        }
                        16 => {
                            let prev = if i > 0 {
                                lens.get(i - 1).copied().unwrap_or(0)
                            } else {
                                return None;
                            };
                            let n = 3 + r.bits(2)? as usize;
                            for _ in 0..n {
                                if let Some(slot) = lens.get_mut(i) {
                                    *slot = prev;
                                }
                                i += 1;
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
                    if i > lens.len() {
                        return None;
                    }
                }
                let lit_lens = lens.get(..hlit)?;
                let dist_lens = lens.get(hlit..)?;
                let lit = Huffman::new(lit_lens)?;
                let dist = Huffman::new(dist_lens)?;
                inflate_block(&mut r, &lit, &dist, &mut out, max_out)?;
            }
            _ => return None,
        }
        if bfinal == 1 {
            return Some(out);
        }
    }
}

/// Inflate a zlib (RFC 1950) stream: 2-byte header, DEFLATE body, Adler32.
pub fn inflate_zlib(data: &[u8], max_out: usize) -> Option<Vec<u8>> {
    if data.len() < 6 {
        return None;
    }
    let cmf = *data.first()?;
    if cmf & 0x0f != 8 {
        return None; // not deflate
    }
    inflate(data.get(2..)?, max_out)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
}

impl<'a> BitReader<'a> {
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            let byte = *self.data.get(self.pos)?;
            let b = (byte >> self.bit) & 1;
            v |= (b as u32) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.pos += 1;
            }
        }
        Some(v)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16le(&mut self) -> Option<u16> {
        let a = self.byte()? as u16;
        let b = self.byte()? as u16;
        Some(a | (b << 8))
    }
}

/// Canonical Huffman decoder built from code lengths.
struct Huffman {
    /// (count of codes per length, first code per length, symbols in order).
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lens: &[u8]) -> Option<Huffman> {
        let mut counts = [0u16; 16];
        for &l in lens {
            let l = l as usize;
            if l > 15 {
                return None;
            }
            if l > 0 {
                if let Some(c) = counts.get_mut(l) {
                    *c = c.saturating_add(1);
                }
            }
        }
        let mut offsets = [0u16; 16];
        let mut total = 0u16;
        for l in 1..16 {
            if let (Some(o), Some(c)) = (offsets.get_mut(l), counts.get(l)) {
                *o = total;
                total = total.saturating_add(*c);
            }
        }
        let mut symbols = vec![0u16; total as usize];
        for (sym, &l) in lens.iter().enumerate() {
            if l > 0 {
                let li = l as usize;
                if let Some(off) = offsets.get_mut(li) {
                    if let Some(slot) = symbols.get_mut(*off as usize) {
                        *slot = sym as u16;
                    }
                    *off = off.saturating_add(1);
                }
            }
        }
        Some(Huffman { counts, symbols })
    }

    fn decode(&self, r: &mut BitReader) -> Option<u16> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= r.bits(1)? as i32;
            let count = *self.counts.get(len)? as i32;
            if code - count < first {
                let sym_index = (index + (code - first)) as usize;
                return self.symbols.get(sym_index).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lit_lens = [0u8; 288];
    for (i, l) in lit_lens.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist_lens = [5u8; 30];
    // Both constructions succeed for the fixed tables; fall back to empty
    // tables (which decode nothing) rather than panicking if they somehow
    // do not.
    let lit = Huffman::new(&lit_lens).unwrap_or(Huffman {
        counts: [0; 16],
        symbols: Vec::new(),
    });
    let dist = Huffman::new(&dist_lens).unwrap_or(Huffman {
        counts: [0; 16],
        symbols: Vec::new(),
    });
    (lit, dist)
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn inflate_block(
    r: &mut BitReader,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
    max_out: usize,
) -> Option<()> {
    loop {
        let sym = lit.decode(r)?;
        match sym {
            0..=255 => {
                if out.len() >= max_out {
                    return None;
                }
                out.push(sym as u8);
            }
            256 => return Some(()),
            257..=285 => {
                let idx = (sym - 257) as usize;
                let base = *LENGTH_BASE.get(idx)? as usize;
                let extra = *LENGTH_EXTRA.get(idx)? as u32;
                let len = base + r.bits(extra)? as usize;
                let dsym = dist.decode(r)? as usize;
                let dbase = *DIST_BASE.get(dsym)? as usize;
                let dextra = *DIST_EXTRA.get(dsym)? as u32;
                let d = dbase + r.bits(dextra)? as usize;
                if d == 0 || d > out.len() {
                    return None;
                }
                if out.len().saturating_add(len) > max_out {
                    return None;
                }
                let start = out.len() - d;
                for i in 0..len {
                    let b = *out.get(start + i)?;
                    out.push(b);
                }
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_block_roundtrip() {
        // BFINAL=1, BTYPE=00, then LEN=3, NLEN=~3, "abc"
        let data = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c'];
        assert_eq!(inflate(&data, 1024), Some(b"abc".to_vec()));
    }

    #[test]
    fn corrupt_streams_yield_none() {
        assert_eq!(inflate(&[0xff, 0xff, 0xff], 1024), None);
        assert_eq!(inflate(&[], 1024), None);
        // Truncated stored block.
        assert_eq!(inflate(&[0x01, 0x10, 0x00, 0xef, 0xff, b'x'], 1024), None);
    }
}
