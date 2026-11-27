//! jpeg: dependency-free JPEG decoder.
//!
//! Supports baseline sequential DCT (SOF0), extended sequential (SOF1) and
//! progressive (SOF2) Huffman-coded images, the formats that dominate web
//! JPEGs, with 1-component (greyscale) and 3-component (YCbCr) images, 8-bit
//! precision, and restart markers. Chroma subsampling 4:4:4, 4:2:2 and 4:2:0
//! are handled. Anything else yields `None`, never a panic.
//!
//! Panic-free: all access bounds-checked; saturating arithmetic in the IDCT.

use super::{DecodedImage, MAX_PIXELS};

pub(crate) mod encode;
mod progressive;
mod scalar_idct;

/// Header-only dimensions: scan for SOFn.
pub fn dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 2usize;
    while pos.checked_add(4)? <= bytes.len() {
        if bytes.get(pos) != Some(&0xff) {
            pos = pos.checked_add(1)?;
            continue;
        }
        let marker = *bytes.get(pos + 1)?;
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            let h = u16::from_be_bytes([*bytes.get(pos + 5)?, *bytes.get(pos + 6)?]) as usize;
            let w = u16::from_be_bytes([*bytes.get(pos + 7)?, *bytes.get(pos + 8)?]) as usize;
            if w == 0 || h == 0 {
                return None;
            }
            return Some((w, h));
        }
        if marker == 0xd8 || (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            pos = pos.checked_add(2)?;
            continue;
        }
        let len = u16::from_be_bytes([*bytes.get(pos + 2)?, *bytes.get(pos + 3)?]) as usize;
        pos = pos.checked_add(2)?.checked_add(len)?;
    }
    None
}

struct Component {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
    td: usize,
    ta: usize,
    dc_pred: i32,
}

struct HuffTable {
    symbols: Vec<u8>,
    /// min/max code per length for canonical decoding.
    min_code: [i32; 17],
    max_code: [i32; 17],
    val_ptr: [usize; 17],
}

impl HuffTable {
    fn build(counts_in: &[u8], symbols: Vec<u8>) -> Option<HuffTable> {
        let mut counts = [0u16; 17];
        for (i, c) in counts_in.iter().enumerate() {
            *counts.get_mut(i + 1)? = *c as u16;
        }
        let mut min_code = [0i32; 17];
        let mut max_code = [-1i32; 17];
        let mut val_ptr = [0usize; 17];
        let mut code = 0i32;
        let mut k = 0usize;
        for l in 1..=16usize {
            let n = *counts.get(l)? as usize;
            if n > 0 {
                *val_ptr.get_mut(l)? = k;
                *min_code.get_mut(l)? = code;
                code = code.checked_add(n as i32)?;
                if code > 1 << l {
                    return None;
                }
                *max_code.get_mut(l)? = code - 1;
                k = k.checked_add(n)?;
            } else {
                *max_code.get_mut(l)? = -1;
            }
            code <<= 1;
        }
        Some(HuffTable {
            symbols,
            min_code,
            max_code,
            val_ptr,
        })
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bits: u32,
    nbits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bits: 0,
            nbits: 0,
        }
    }

    /// Refill respecting JPEG byte stuffing (0xFF 0x00) and stopping at
    /// markers.
    fn fill(&mut self) {
        while self.nbits <= 24 {
            let Some(&b) = self.data.get(self.pos) else {
                // Feed 1s past the end per spec recommendation.
                self.bits |= 0xff << (24 - self.nbits);
                self.nbits += 8;
                continue;
            };
            if b == 0xff {
                match self.data.get(self.pos + 1) {
                    Some(&0x00) => {
                        self.pos += 2;
                        self.bits |= (0xffu32) << (24 - self.nbits);
                        self.nbits += 8;
                        continue;
                    }
                    _ => {
                        // A real marker: feed 1s, do not consume.
                        self.bits |= 0xff << (24 - self.nbits);
                        self.nbits += 8;
                        continue;
                    }
                }
            }
            self.pos += 1;
            self.bits |= (b as u32) << (24 - self.nbits);
            self.nbits += 8;
        }
    }

    fn bit(&mut self) -> u32 {
        if self.nbits == 0 {
            self.fill();
        }
        let b = self.bits >> 31;
        self.bits <<= 1;
        self.nbits = self.nbits.saturating_sub(1);
        b
    }

    fn bits_n(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit();
        }
        v
    }

    /// Decode one Huffman symbol.
    fn huff(&mut self, t: &HuffTable) -> Option<u8> {
        let mut code = 0i32;
        for l in 1..=16usize {
            code = (code << 1) | self.bit() as i32;
            if *t.max_code.get(l)? >= code && code >= *t.min_code.get(l)? {
                let idx = t
                    .val_ptr
                    .get(l)?
                    .checked_add((code - t.min_code.get(l)?) as usize)?;
                return t.symbols.get(idx).copied();
            }
        }
        None
    }

    /// Receive-and-extend: read `s` magnitude bits and sign-extend.
    fn receive_extend(&mut self, s: u8) -> i32 {
        if s == 0 {
            return 0;
        }
        let v = self.bits_n(s as u32) as i32;
        let vt = 1i32 << (s as i32 - 1);
        if v < vt {
            v - (1 << s as i32) + 1
        } else {
            v
        }
    }

    /// Align to byte boundary and skip an RSTn marker if present.
    fn restart(&mut self) -> bool {
        self.bits = 0;
        self.nbits = 0;
        while let Some(&b) = self.data.get(self.pos) {
            if b != 0xff {
                self.pos += 1;
                continue;
            }
            match self.data.get(self.pos + 1) {
                Some(&m) if (0xd0..=0xd7).contains(&m) => {
                    self.pos += 2;
                    return true;
                }
                _ => return false,
            }
        }
        false
    }
}

/// The zigzag scan order.
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

fn idct_block(block: &mut [i32; 64], model: bool) {
    if model {
        *block = scalar_idct::pixels(block).map(|pixel| i32::from(pixel) - 128);
        return;
    }
    static BASIS: std::sync::OnceLock<[[f32; 8]; 8]> = std::sync::OnceLock::new();
    let basis = BASIS.get_or_init(|| {
        std::array::from_fn(|x| {
            std::array::from_fn(|u| {
                let norm = if u == 0 {
                    core::f32::consts::FRAC_1_SQRT_2
                } else {
                    1.0
                };
                let angle = (2.0 * x as f32 + 1.0) * u as f32 * core::f32::consts::PI / 16.0;
                norm * angle.cos()
            })
        })
    });
    let mut rows = [[0.0_f32; 8]; 8];
    for (out, row) in rows.iter_mut().zip(block.chunks_exact(8)) {
        for (result, filter) in out.iter_mut().zip(basis) {
            *result = filter
                .iter()
                .zip(row)
                .map(|(weight, value)| weight * (*value as f32))
                .sum::<f32>()
                / 2.0;
        }
    }
    for (row, filter) in block.chunks_exact_mut(8).zip(basis) {
        for (x, result) in row.iter_mut().enumerate() {
            let value = filter
                .iter()
                .zip(&rows)
                .map(|(weight, y)| weight * y[x])
                .sum::<f32>()
                / 2.0;
            *result = value.round() as i32;
        }
    }
}

/// Decode a baseline or progressive Huffman JPEG into RGBA8.
pub fn decode(bytes: &[u8]) -> Option<DecodedImage> {
    decode_profile(bytes, false)
}

pub(super) fn decode_for_model(bytes: &[u8]) -> Option<DecodedImage> {
    decode_profile(bytes, true)
}

fn decode_profile(bytes: &[u8], model: bool) -> Option<DecodedImage> {
    if !bytes.starts_with(b"\xff\xd8\xff") {
        return None;
    }
    let mut pos = 2usize;
    let mut qtables: [[u16; 64]; 4] = [[0; 64]; 4];
    let mut dc_tables: Vec<Option<HuffTable>> = (0..4).map(|_| None).collect();
    let mut ac_tables: Vec<Option<HuffTable>> = (0..4).map(|_| None).collect();
    let mut comps: Vec<Component> = Vec::new();
    let mut width = 0usize;
    let mut height = 0usize;
    let mut restart_interval = 0usize;
    let mut progressive: Option<progressive::Progressive> = None;

    loop {
        // Seek to next marker.
        while bytes.get(pos) != Some(&0xff) {
            pos = pos.checked_add(1)?;
            if pos >= bytes.len() {
                return None;
            }
        }
        let mut mpos = pos;
        while bytes.get(mpos) == Some(&0xff) {
            mpos = mpos.checked_add(1)?;
        }
        let marker = *bytes.get(mpos)?;
        pos = mpos.checked_add(1)?;
        match marker {
            0xd8 => continue, // SOI
            0xd9 => return progressive?.finish(&comps, &qtables, model),
            0x01 | 0xd0..=0xd7 => continue,
            0xc0 | 0xc1 | 0xc2 => {
                if !comps.is_empty() {
                    return None;
                }
                // Huffman-coded baseline/extended sequential or progressive.
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                let seg = bytes.get(pos..pos.checked_add(len)?)?;
                height = u16::from_be_bytes([*seg.get(3)?, *seg.get(4)?]) as usize;
                width = u16::from_be_bytes([*seg.get(5)?, *seg.get(6)?]) as usize;
                let n = *seg.get(7)? as usize;
                if *seg.get(2)? != 8 || !(n == 1 || n == 3) || width == 0 || height == 0 {
                    return None;
                }
                if width.checked_mul(height)? > MAX_PIXELS {
                    return None;
                }
                comps.clear();
                for i in 0..n {
                    let off = 8 + i * 3;
                    let id = *seg.get(off)?;
                    let hv = *seg.get(off + 1)?;
                    let tq = *seg.get(off + 2)? as usize;
                    let h = (hv >> 4) as usize;
                    let v = (hv & 0xf) as usize;
                    if !(1..=4).contains(&h)
                        || !(1..=4).contains(&v)
                        || tq > 3
                        || comps.iter().any(|comp| comp.id == id)
                    {
                        return None;
                    }
                    comps.push(Component {
                        id,
                        h,
                        v,
                        tq,
                        td: 0,
                        ta: 0,
                        dc_pred: 0,
                    });
                }
                if marker == 0xc2 {
                    progressive = Some(progressive::Progressive::new(width, height, &comps)?);
                }
                pos = pos.checked_add(len)?;
            }
            0xc4 => {
                // DHT
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                let seg = bytes.get(pos + 2..pos.checked_add(len)?)?;
                let mut off = 0usize;
                while off < seg.len() {
                    let tc_th = *seg.get(off)?;
                    let tc = (tc_th >> 4) as usize;
                    let th = (tc_th & 0xf) as usize;
                    let counts = seg.get(off + 1..off + 17)?;
                    let total: usize = counts.iter().map(|&c| c as usize).sum();
                    let symbols = seg.get(off + 17..off + 17 + total)?.to_vec();
                    let table = HuffTable::build(counts, symbols)?;
                    if tc == 0 {
                        *dc_tables.get_mut(th)? = Some(table);
                    } else {
                        *ac_tables.get_mut(th)? = Some(table);
                    }
                    off = off.checked_add(17)?.checked_add(total)?;
                }
                pos = pos.checked_add(len)?;
            }
            0xdb => {
                // DQT
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                let seg = bytes.get(pos + 2..pos.checked_add(len)?)?;
                let mut off = 0usize;
                while off < seg.len() {
                    let pq_tq = *seg.get(off)?;
                    let pq = (pq_tq >> 4) as usize;
                    let tq = (pq_tq & 0xf) as usize;
                    let table = qtables.get_mut(tq)?;
                    if pq == 0 {
                        for i in 0..64 {
                            *table.get_mut(i)? = *seg.get(off + 1 + i)? as u16;
                        }
                        off = off.checked_add(65)?;
                    } else if pq == 1 {
                        for i in 0..64 {
                            let hi = *seg.get(off + 1 + i * 2)? as u16;
                            let lo = *seg.get(off + 2 + i * 2)? as u16;
                            *table.get_mut(i)? = (hi << 8) | lo;
                        }
                        off = off.checked_add(129)?;
                    } else {
                        return None;
                    }
                }
                pos = pos.checked_add(len)?;
            }
            0xdd => {
                // DRI
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                restart_interval =
                    u16::from_be_bytes([*bytes.get(pos + 2)?, *bytes.get(pos + 3)?]) as usize;
                pos = pos.checked_add(len)?;
            }
            0xda => {
                // SOS
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                let seg = bytes.get(pos + 2..pos.checked_add(len)?)?;
                if let Some(frame) = progressive.as_mut() {
                    let scan = pos.checked_add(len)?;
                    let consumed = frame.scan(
                        seg,
                        bytes.get(scan..)?,
                        &comps,
                        &dc_tables,
                        &ac_tables,
                        restart_interval,
                    )?;
                    pos = scan.checked_add(consumed)?;
                    continue;
                }
                let ns = *seg.first()? as usize;
                for i in 0..ns {
                    let cs = *seg.get(1 + i * 2)?;
                    let td_ta = *seg.get(2 + i * 2)?;
                    if let Some(c) = comps.iter_mut().find(|c| c.id == cs) {
                        c.td = (td_ta >> 4) as usize;
                        c.ta = (td_ta & 0xf) as usize;
                    }
                }
                pos = pos.checked_add(len)?;
                // Entropy-coded data starts here.
                return decode_scan(
                    bytes.get(pos..)?,
                    &mut comps,
                    &qtables,
                    &dc_tables,
                    &ac_tables,
                    width,
                    height,
                    restart_interval,
                    model,
                );
            }
            _ => {
                let len = u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]) as usize;
                pos = pos.checked_add(len)?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_scan(
    data: &[u8],
    comps: &mut [Component],
    qtables: &[[u16; 64]; 4],
    dc_tables: &[Option<HuffTable>],
    ac_tables: &[Option<HuffTable>],
    width: usize,
    height: usize,
    restart_interval: usize,
    model: bool,
) -> Option<DecodedImage> {
    let hmax = comps.iter().map(|c| c.h).max()?.max(1);
    let vmax = comps.iter().map(|c| c.v).max()?.max(1);
    let mcux = width.checked_add(8 * hmax - 1)? / (8 * hmax);
    let mcuy = height.checked_add(8 * vmax - 1)? / (8 * vmax);

    // Per-component pixel planes at full MCU resolution.
    let mut planes: Vec<Plane> = Vec::new();
    for c in comps.iter() {
        let w = mcux.checked_mul(8 * c.h)?;
        let h = mcuy.checked_mul(8 * c.v)?;
        planes.push(Plane {
            w,
            h,
            data: vec![0u8; w.checked_mul(h)?],
        });
    }

    let mut r = BitReader::new(data);
    let mut mcu_count = 0usize;

    for my in 0..mcuy {
        for mx in 0..mcux {
            if restart_interval > 0 && mcu_count > 0 && mcu_count.is_multiple_of(restart_interval) {
                for c in comps.iter_mut() {
                    c.dc_pred = 0;
                }
                if !r.restart() {
                    // Missing restart marker: tolerate and continue.
                }
            }
            mcu_count = mcu_count.saturating_add(1);
            for (ci, c) in comps.iter_mut().enumerate() {
                for by in 0..c.v {
                    for bx in 0..c.h {
                        let dc_t = dc_tables.get(c.td)?.as_ref()?;
                        let ac_t = ac_tables.get(c.ta)?.as_ref()?;
                        let q = qtables.get(c.tq)?;
                        let mut block = [0i32; 64];
                        // DC
                        let s = r.huff(dc_t)?;
                        // An untrusted DHT symbol is not necessarily a legal
                        // magnitude for this precision. Reject before shifts.
                        if s > 11 {
                            return None;
                        }
                        let diff = r.receive_extend(s);
                        c.dc_pred = c.dc_pred.saturating_add(diff);
                        block[0] = c.dc_pred.saturating_mul(*q.first()? as i32);
                        // AC
                        let mut k = 1usize;
                        while k < 64 {
                            let rs = r.huff(ac_t)?;
                            let rlen = (rs >> 4) as usize;
                            let s = rs & 0xf;
                            if s > 10 {
                                return None;
                            }
                            if s == 0 {
                                if rlen == 15 {
                                    k = k.checked_add(16)?;
                                    continue;
                                }
                                break; // EOB
                            }
                            k = k.checked_add(rlen)?;
                            if k >= 64 {
                                break;
                            }
                            let val = r.receive_extend(s);
                            let zz = *ZIGZAG.get(k)?;
                            if let Some(slot) = block.get_mut(zz) {
                                *slot = val.saturating_mul(*q.get(k)? as i32);
                            }
                            k = k.checked_add(1)?;
                        }
                        idct_block(&mut block, model);
                        // Write the 8x8 block into the plane.
                        let plane = planes.get_mut(ci)?;
                        let px0 = mx.checked_mul(8 * c.h)?.checked_add(bx * 8)?;
                        let py0 = my.checked_mul(8 * c.v)?.checked_add(by * 8)?;
                        for y in 0..8 {
                            for x in 0..8 {
                                let v = block.get(y * 8 + x).copied().unwrap_or(0);
                                let px = px0 + x;
                                let py = py0 + y;
                                if px < plane.w && py < plane.h {
                                    let idx = py.checked_mul(plane.w)?.checked_add(px)?;
                                    if let Some(slot) = plane.data.get_mut(idx) {
                                        *slot = (v.saturating_add(128)).clamp(0, 255) as u8;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    planes_to_image(width, height, hmax, vmax, comps, &planes, model)
}

struct Plane {
    w: usize,
    h: usize,
    data: Vec<u8>,
}

fn planes_to_image(
    width: usize,
    height: usize,
    hmax: usize,
    vmax: usize,
    comps: &[Component],
    planes: &[Plane],
    model: bool,
) -> Option<DecodedImage> {
    // Color conversion: upsample chroma to luma resolution and convert.
    let px_total = width.checked_mul(height)?;
    let mut rgba = vec![0u8; px_total.checked_mul(4)?];
    let grey = comps.len() == 1;
    for y in 0..height {
        for x in 0..width {
            let (rv, gv, bv);
            if grey {
                let p = planes.first()?;
                let l = *p.data.get(y.checked_mul(p.w)?.checked_add(x)?)?;
                rv = l;
                gv = l;
                bv = l;
            } else {
                let (yp, cbp, crp) = (planes.first()?, planes.get(1)?, planes.get(2)?);
                let c0 = comps.first()?;
                let c1 = comps.get(1)?;
                let c2 = comps.get(2)?;
                let l = *yp.data.get(
                    (y * c0.v / vmax)
                        .min(yp.h - 1)
                        .checked_mul(yp.w)?
                        .checked_add((x * c0.h / hmax).min(yp.w - 1))?,
                )?;
                let cb = *cbp.data.get(
                    (y * c1.v / vmax)
                        .min(cbp.h - 1)
                        .checked_mul(cbp.w)?
                        .checked_add((x * c1.h / hmax).min(cbp.w - 1))?,
                )?;
                let cr = *crp.data.get(
                    (y * c2.v / vmax)
                        .min(crp.h - 1)
                        .checked_mul(crp.w)?
                        .checked_add((x * c2.h / hmax).min(crp.w - 1))?,
                )?;
                (rv, gv, bv) = if model {
                    scalar_ycbcr(l, cb, cr)
                } else {
                    let (l, cb, cr) = (f32::from(l), f32::from(cb) - 128.0, f32::from(cr) - 128.0);
                    let cast = |v: f32| v.clamp(0.0, 255.0) as u8;
                    (
                        cast(l + 1.402 * cr),
                        cast(l - 0.344136 * cb - 0.714136 * cr),
                        cast(l + 1.772 * cb),
                    )
                };
            }
            let o = y.checked_mul(width)?.checked_add(x)?.checked_mul(4)?;
            *rgba.get_mut(o)? = rv;
            *rgba.get_mut(o + 1)? = gv;
            *rgba.get_mut(o + 2)? = bv;
            *rgba.get_mut(o + 3)? = 255;
        }
    }
    DecodedImage::new(width, height, rgba)
}

// Scalar BT.601 fixed-point conversion from jpeg-decoder 0.3.1 (MIT).
fn scalar_ycbcr(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
    const SHIFT: u32 = 20;
    let y = i32::from(y) * (1 << SHIFT) + (1 << (SHIFT - 1));
    let cb = i32::from(cb) - 128;
    let cr = i32::from(cr) - 128;
    let coefficient = |x: f32| (x * ((1 << SHIFT) as f32) + 0.5) as i32;
    let channel = |v: i32| (v >> SHIFT).clamp(0, 255) as u8;
    (
        channel(y + coefficient(1.40200) * cr),
        channel(y - coefficient(0.34414) * cb - coefficient(0.71414) * cr),
        channel(y + coefficient(1.77200) * cb),
    )
}
