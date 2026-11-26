//! Photon-compatible RGBA JPEG writer, adapted from image 0.24.9 (MIT).
//! The alpha channel is discarded just as in Photon. DCTs are cached across
//! quality attempts. See the package notices for the Independent JPEG Group DCT.

mod ijg_fdct;

use super::ZIGZAG;

const MAX_ENCODE_PIXELS: usize = 4_194_304;
pub(crate) const MIN_OUTPUT_BYTES: usize = 625;

// Natural-order JPEG luminance and chrominance quantization tables.
const LUMA: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const CHROMA: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

// JPEG Annex K.3 and K.5 canonical entropy table data.
const DC_CODE_LENGTHS: [u8; 16] = [
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DC_VALUES: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
];
const AC_CODE_LENGTHS: [u8; 16] = [
    0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
];
const AC_VALUES: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
    0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA,
];

const CHROMA_DC_CODE_LENGTHS: [u8; 16] = [
    0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const CHROMA_DC_VALUES: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
];

const CHROMA_AC_CODE_LENGTHS: [u8; 16] = [
    0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x03, 0x04, 0x07, 0x05, 0x04, 0x04, 0x00, 0x01, 0x02, 0x77,
];

const CHROMA_AC_VALUES: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33, 0x52, 0xF0,
    0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26,
    0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5,
    0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3,
    0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
    0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA,
];

pub(crate) struct PreparedDct {
    width: u16,
    height: u16,
    blocks: Vec<[[i16; 64]; 3]>,
}

impl PreparedDct {
    pub(crate) fn new(width: usize, height: usize, rgba: &[u8]) -> Option<Self> {
        let pixels = width.checked_mul(height)?;
        if pixels == 0 || pixels > MAX_ENCODE_PIXELS || rgba.len() != pixels.checked_mul(4)? {
            return None;
        }
        let width16 = u16::try_from(width).ok()?;
        let height16 = u16::try_from(height).ok()?;
        let cols = width.div_ceil(8);
        let rows = height.div_ceil(8);
        let mut blocks = Vec::with_capacity(cols.checked_mul(rows)?);
        for by in 0..rows {
            for bx in 0..cols {
                let mut channels = [[0u8; 64]; 3];
                for y in 0..8 {
                    let sy = (by * 8 + y).min(height - 1);
                    for x in 0..8 {
                        let sx = (bx * 8 + x).min(width - 1);
                        let at = (sy * width + sx) * 4;
                        let r = f32::from(*rgba.get(at)?);
                        let g = f32::from(*rgba.get(at + 1)?);
                        let b = f32::from(*rgba.get(at + 2)?);
                        let i = y * 8 + x;
                        channels[0][i] = (76.245_f32 / 255.0 * r
                            + 149.685_f32 / 255.0 * g
                            + 29.07_f32 / 255.0 * b) as u8;
                        channels[1][i] = (-43.0185_f32 / 255.0 * r - 84.4815_f32 / 255.0 * g
                            + 127.5_f32 / 255.0 * b
                            + 128.0) as u8;
                        channels[2][i] = (127.5_f32 / 255.0 * r
                            - 106.7685_f32 / 255.0 * g
                            - 20.7315_f32 / 255.0 * b
                            + 128.0) as u8;
                    }
                }
                blocks.push(channels.map(dct));
            }
        }
        Some(Self {
            width: width16,
            height: height16,
            blocks,
        })
    }

    pub(crate) fn encode(&self, quality: u8, limit: usize) -> Option<Vec<u8>> {
        if limit < MIN_OUTPUT_BYTES {
            return None;
        }
        let tables = [scaled(LUMA, quality), scaled(CHROMA, quality)];
        let mut out = vec![0xff, 0xd8];
        marker(&mut out, 0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0")?;
        let [h0, h1] = self.height.to_be_bytes();
        let [w0, w1] = self.width.to_be_bytes();
        // Three YCbCr components, no subsampling. Preserve thin colored
        // strokes rather than trading resolution for JPEG byte efficiency.
        marker(
            &mut out,
            0xc0,
            &[8, h0, h1, w0, w1, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1],
        )?;

        for (index, table) in tables.iter().enumerate() {
            let mut dqt = Vec::with_capacity(65);
            dqt.push(index as u8);
            dqt.extend(table);
            marker(&mut out, 0xdb, &dqt)?;
        }
        for (tag, counts, values) in [
            (0x00, &DC_CODE_LENGTHS, DC_VALUES.as_slice()),
            (0x10, &AC_CODE_LENGTHS, AC_VALUES.as_slice()),
            (0x01, &CHROMA_DC_CODE_LENGTHS, CHROMA_DC_VALUES.as_slice()),
            (0x11, &CHROMA_AC_CODE_LENGTHS, CHROMA_AC_VALUES.as_slice()),
        ] {
            let mut payload = vec![tag];
            payload.extend(counts);
            payload.extend(values);
            marker(&mut out, 0xc4, &payload)?;
        }
        let dc = [
            code_lookup(&DC_CODE_LENGTHS, &DC_VALUES),
            code_lookup(&CHROMA_DC_CODE_LENGTHS, &CHROMA_DC_VALUES),
        ];
        let ac = [
            code_lookup(&AC_CODE_LENGTHS, &AC_VALUES),
            code_lookup(&CHROMA_AC_CODE_LENGTHS, &CHROMA_AC_VALUES),
        ];
        marker(&mut out, 0xda, &[3, 1, 0, 2, 0x11, 3, 0x11, 0, 63, 0])?;
        let mut stream = EntropyWriter {
            out,
            limit,
            held: 0,
            count: 0,
        };
        let mut previous = [0; 3];
        for components in &self.blocks {
            for (index, block) in components.iter().enumerate() {
                let table = usize::from(index != 0);
                let q = &tables[table];
                let dc_table = &dc[table];
                let ac_table = &ac[table];
                let dc = quant(block[0], q[0]);
                let delta = dc - previous[index];
                previous[index] = dc;
                let (n, bits) = magnitude(delta);
                if n > 11 {
                    return None;
                }
                stream.symbol(dc_table, n)?;
                stream.put(bits, n)?;
                let mut zeros = 0;
                for (&value, &q) in block.iter().zip(q).skip(1) {
                    let value = quant(value, q);
                    if value == 0 {
                        zeros += 1;
                        continue;
                    }
                    while zeros >= 16 {
                        stream.symbol(ac_table, 0xf0)?;
                        zeros -= 16;
                    }
                    let (n, bits) = magnitude(value);
                    if n == 0 || n > 10 {
                        return None;
                    }
                    stream.symbol(ac_table, (zeros << 4) | n)?;
                    stream.put(bits, n)?;
                    zeros = 0;
                }
                if zeros > 0 {
                    stream.symbol(ac_table, 0)?;
                }
            }
        }
        stream.finish()
    }
}

fn code_lookup(lengths: &[u8; 16], values: &[u8]) -> [(u32, u8); 256] {
    let mut all = [(0, 0); 256];
    let mut code = 0;
    let mut offset = 0;
    for (index, count) in lengths.iter().enumerate() {
        for symbol in values.iter().skip(offset).take(usize::from(*count)) {
            all[usize::from(*symbol)] = (code, (index + 1) as u8);
            code += 1;
        }
        offset += usize::from(*count);
        code <<= 1;
    }
    all
}

fn dct(samples: [u8; 64]) -> [i16; 64] {
    let mut coefficients = [0i32; 64];
    ijg_fdct::fdct(&samples, &mut coefficients);
    ZIGZAG.map(|at| (coefficients[at] / 8) as i16)
}

fn scaled(table: [u8; 64], quality: u8) -> [u8; 64] {
    let q = u32::from(quality.clamp(1, 100));
    let scale = if q < 50 { 5000 / q } else { 200 - 2 * q };
    ZIGZAG.map(|i| ((u32::from(table[i]) * scale + 50) / 100).clamp(1, 255) as u8)
}

fn quant(value: i16, q: u8) -> i32 {
    let (value, q) = (i32::from(value), i32::from(q));
    (value.abs() + q / 2) / q * value.signum()
}

fn magnitude(value: i32) -> (u8, u32) {
    if value == 0 {
        return (0, 0);
    }
    let size = (32 - value.unsigned_abs().leading_zeros()) as u8;
    let bits = if value < 0 {
        ((1 << size) - 1 + value) as u32
    } else {
        value as u32
    };
    (size, bits)
}

fn marker(out: &mut Vec<u8>, marker: u8, data: &[u8]) -> Option<()> {
    out.extend([0xff, marker]);
    out.extend(
        u16::try_from(data.len().checked_add(2)?)
            .ok()?
            .to_be_bytes(),
    );
    out.extend(data);
    Some(())
}

struct EntropyWriter {
    out: Vec<u8>,
    limit: usize,
    held: u32,
    count: u8,
}

impl EntropyWriter {
    fn symbol(&mut self, table: &[(u32, u8); 256], symbol: u8) -> Option<()> {
        let (value, len) = table[usize::from(symbol)];
        if len == 0 {
            return None;
        }
        self.put(value, len)
    }

    fn put(&mut self, value: u32, bits: u8) -> Option<()> {
        self.held = self.held << bits | value;
        self.count += bits;
        while self.count >= 8 {
            self.count -= 8;
            let byte = (self.held >> self.count) as u8;
            self.out.push(byte);
            if byte == 0xff {
                self.out.push(0);
            }
            if self.out.len() > self.limit {
                return None;
            }
        }
        self.held &= (1 << self.count) - 1;
        Some(())
    }

    fn finish(mut self) -> Option<Vec<u8>> {
        let missing = (8 - self.count) % 8;
        self.put((1 << missing) - 1, missing)?;
        self.out.extend([0xff, 0xd9]);
        (self.out.len() <= self.limit).then_some(self.out)
    }
}
