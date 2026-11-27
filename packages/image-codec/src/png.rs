//! PNG encoding: a zero-dependency writer for RGBA pixel buffers.
//!
//! Emits a valid PNG (8-bit RGBA, non-interlaced) whose IDAT is a real
//! DEFLATE stream using FIXED HUFFMAN codes with RLE-style LZ77 matching
//! (distance 4 = "repeat the previous pixel"). Screenshots are dominated by
//! solid-color runs, so this typically shrinks the output by an order of
//! magnitude over stored blocks while staying ~200 lines and dependency-free.
//! Incompressible input degrades gracefully (worst case ~9/8 of raw).
//!
//! MEMORY: the encoder streams scanlines through a single reusable row
//! buffer straight into the output vec. Peak transient cost is the OUTPUT
//! allocation (usually a few percent of the raw stream now that runs
//! compress). This matters because the service runs under a hard per-process
//! memory cap — an encoder that made whole-image copies took peak RSS to
//! several multiples of the framebuffer and got the app killed mid-request
//! (which a durable queue then redelivers: a poison pill).

pub(crate) mod photon;

/// Encode an RGBA buffer (`width * height * 4` bytes) as a PNG file.
///
/// Rows beyond the provided buffer are zero-padded, a longer buffer is
/// ignored past the expected size — a malformed caller still gets a valid
/// image rather than a panic.
pub fn encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let w = width.max(1);
    let h = height.max(1);
    let stride = (w as usize).saturating_mul(4);
    let raw_len = (h as usize).saturating_mul(stride.saturating_add(1));

    let mut out = Vec::with_capacity(64 * 1024);
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, RGBA, deflate, adaptive, no interlace
    write_chunk(&mut out, b"IHDR", &ihdr);

    // IDAT: zlib header, then ONE fixed-Huffman deflate block for the whole
    // filtered stream (Huffman blocks have no 64 KiB length limit).
    let idat_start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0]); // chunk length placeholder
    out.extend_from_slice(b"IDAT");
    let data_start = out.len();
    out.extend_from_slice(&[0x78, 0x01]); // zlib CMF/FLG (31-check passes)

    let mut adler = Adler32::new();
    let mut bits = BitWriter { acc: 0, nbits: 0 };
    // Block header: BFINAL=1, BTYPE=01 (fixed Huffman), LSB-first.
    bits.push(&mut out, 1, 1);
    bits.push(&mut out, 1, 2);

    // One reusable row buffer: filter byte + row pixels (zero-padded tail).
    let mut row_buf = vec![0u8; stride + 1];
    for row in 0..h as usize {
        let start = row.saturating_mul(stride);
        let avail = rgba.len().saturating_sub(start).min(stride);
        if let Some(slot) = row_buf.get_mut(0..1) {
            slot[0] = 0; // filter: None
        }
        if avail > 0 {
            if let (Some(dst), Some(src)) = (
                row_buf.get_mut(1..1 + avail),
                rgba.get(start..start + avail),
            ) {
                dst.copy_from_slice(src);
            }
        }
        if avail < stride {
            if let Some(tail) = row_buf.get_mut(1 + avail..) {
                tail.fill(0);
            }
        }
        adler.update(&row_buf);
        compress_row(&mut out, &mut bits, &row_buf);
    }
    // End-of-block symbol (code 256: 7 bits, value 0 in fixed Huffman).
    bits.push(&mut out, 0, 7);
    bits.flush(&mut out);
    let _ = raw_len;
    let _ = data_start;
    out.extend_from_slice(&adler.finish().to_be_bytes());

    // Patch the IDAT length and append its CRC.
    let idat_len = (out.len() - data_start) as u32;
    if let Some(slot) = out.get_mut(idat_start..idat_start + 4) {
        slot.copy_from_slice(&idat_len.to_be_bytes());
    }
    let mut crc = Crc32::new();
    crc.update(out.get(idat_start + 4..).unwrap_or(&[]));
    out.extend_from_slice(&crc.finish().to_be_bytes());

    // IEND
    write_chunk(&mut out, b"IEND", &[]);
    out
}

/// Compress one filtered row into the fixed-Huffman stream. Literals for the
/// filter byte and the first pixel, then greedy RLE: a run matching the
/// bytes 4 back (the previous RGBA pixel) becomes a length/distance pair.
fn compress_row(out: &mut Vec<u8>, bits: &mut BitWriter, row: &[u8]) {
    let mut i = 0usize;
    while i < row.len() {
        if i >= 5 {
            // Count how many upcoming bytes replicate the byte 4 positions
            // back — a run of identical pixels. DEFLATE allows overlapping
            // matches, so one pair can cover up to 258 bytes.
            let mut len = 0usize;
            while len < 258 && i + len < row.len() {
                let (Some(&a), Some(&b)) = (row.get(i + len), row.get(i + len - 4)) else {
                    break;
                };
                if a != b {
                    break;
                }
                len += 1;
            }
            if len >= 6 {
                emit_length(out, bits, len as u32);
                // Distance 4 = fixed code 3, 5 bits, no extra bits.
                bits.push_rev(out, 3, 5);
                i += len;
                continue;
            }
        }
        emit_literal(out, bits, row.get(i).copied().unwrap_or(0));
        i += 1;
    }
}

/// Emit one literal byte with the fixed-Huffman literal code.
fn emit_literal(out: &mut Vec<u8>, bits: &mut BitWriter, byte: u8) {
    let v = byte as u32;
    if v < 144 {
        bits.push_rev(out, 0x30 + v, 8);
    } else {
        bits.push_rev(out, 0x190 + (v - 144), 9);
    }
}

/// Emit a length symbol (3..=258) with the fixed-Huffman code + extra bits.
fn emit_length(out: &mut Vec<u8>, bits: &mut BitWriter, len: u32) {
    // (code, base, extra_bits) per RFC 1951 §3.2.5.
    const TABLE: [(u32, u32, u32); 29] = [
        (257, 3, 0),
        (258, 4, 0),
        (259, 5, 0),
        (260, 6, 0),
        (261, 7, 0),
        (262, 8, 0),
        (263, 9, 0),
        (264, 10, 0),
        (265, 11, 1),
        (266, 13, 1),
        (267, 15, 1),
        (268, 17, 1),
        (269, 19, 2),
        (270, 23, 2),
        (271, 27, 2),
        (272, 31, 2),
        (273, 35, 3),
        (274, 43, 3),
        (275, 51, 3),
        (276, 59, 3),
        (277, 67, 4),
        (278, 83, 4),
        (279, 99, 4),
        (280, 115, 4),
        (281, 131, 5),
        (282, 163, 5),
        (283, 195, 5),
        (284, 227, 5),
        (285, 258, 0),
    ];
    let len = len.clamp(3, 258);
    // Find the last entry whose base <= len (285 wins only for exactly 258).
    let mut chosen = (257u32, 3u32, 0u32);
    for &(code, base, extra) in TABLE.iter() {
        if base <= len && !(code == 285 && len != 258) {
            chosen = (code, base, extra);
        }
    }
    let (code, base, extra) = chosen;
    // Fixed Huffman for length codes: 256-279 are 7 bits (value code-256),
    // 280-287 are 8 bits (value 0xC0 + code-280).
    if code < 280 {
        bits.push_rev(out, code - 256, 7);
    } else {
        bits.push_rev(out, 0xC0 + (code - 280), 8);
    }
    if extra > 0 {
        bits.push(out, len - base, extra);
    }
}

/// LSB-first bit accumulator per RFC 1951.
struct BitWriter {
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    /// Push `n` bits LSB-first (extra bits, block header).
    fn push(&mut self, out: &mut Vec<u8>, value: u32, n: u32) {
        self.acc |= (value as u64) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            out.push((self.acc & 0xFF) as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }
    /// Push a Huffman CODE: codes are written MSB-first, so bit-reverse.
    fn push_rev(&mut self, out: &mut Vec<u8>, code: u32, n: u32) {
        let mut rev = 0u32;
        for k in 0..n {
            rev |= ((code >> k) & 1) << (n - 1 - k);
        }
        self.push(out, rev, n);
    }
    fn flush(&mut self, out: &mut Vec<u8>) {
        if self.nbits > 0 {
            out.push((self.acc & 0xFF) as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }
}

/// The projected ENCODER memory cost (bytes) for a canvas of w×h. Callers
/// enforce budgets BEFORE rasterizing: canvas + worst-case compressed output
/// (incompressible input costs ~9/8 of the raw stream in fixed Huffman).
pub fn projected_encode_cost(width: u32, height: u32) -> usize {
    let px = (width as usize).saturating_mul(height as usize);
    let canvas = px.saturating_mul(4);
    let raw = canvas.saturating_add(height as usize);
    canvas
        .saturating_add(raw.saturating_mul(9) / 8)
        .saturating_add(4096)
}

fn write_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(tag);
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// Incremental Adler-32 over a streamed byte sequence.
struct Adler32 {
    a: u32,
    b: u32,
}

impl Adler32 {
    fn new() -> Self {
        Adler32 { a: 1, b: 0 }
    }
    fn update(&mut self, data: &[u8]) {
        const MOD: u32 = 65_521;
        for chunk in data.chunks(5_552) {
            for &byte in chunk {
                self.a += byte as u32;
                self.b += self.a;
            }
            self.a %= MOD;
            self.b %= MOD;
        }
    }
    fn finish(&self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// CRC-32 (IEEE), table-driven. The IDAT CRC runs over the WHOLE encoded
/// stream; the previous bitwise version did 8 shift/xor steps per byte and
/// dominated encode time. A 256-entry table computed once per encode is far
/// cheaper per byte (and const-free under the zero-dependency contract).
struct Crc32 {
    state: u32,
    table: [u32; 256],
}

impl Crc32 {
    fn new() -> Self {
        let mut table = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            if let Some(slot) = table.get_mut(i) {
                *slot = c;
            }
            i += 1;
        }
        Crc32 {
            state: 0xFFFF_FFFF,
            table,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut s = self.state;
        for &byte in data {
            let idx = ((s ^ byte as u32) & 0xFF) as usize;
            s = (s >> 8) ^ self.table.get(idx).copied().unwrap_or(0);
        }
        self.state = s;
    }

    fn finish(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adler32(data: &[u8]) -> u32 {
        let mut a = Adler32::new();
        a.update(data);
        a.finish()
    }

    #[test]
    fn valid_signature_and_chunks() {
        let png = encode(2, 2, &[255u8; 16]);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(&png[8..12], &13u32.to_be_bytes());
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    #[test]
    fn adler_known_value() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn short_buffer_is_zero_padded() {
        let png = encode(4, 4, &[1, 2, 3]);
        let img = crate::image_codec::png_dec::decode(&png).expect("valid PNG");
        assert_eq!((img.width, img.height), (4, 4));
        let mut expected = vec![0u8; 64];
        expected[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(img.rgba, expected);
    }

    #[test]
    fn zero_dims_clamped() {
        let png = encode(0, 0, &[]);
        let img = crate::image_codec::png_dec::decode(&png).expect("valid PNG");
        assert_eq!((img.width, img.height), (1, 1));
        assert_eq!(img.rgba, vec![0u8; 4]);
    }

    /// The fixed-Huffman stream must round-trip byte-exactly through our own
    /// inflate: decode the IDAT and compare to the expected filtered rows.
    #[test]
    fn stream_roundtrips_through_inflate() {
        // Mixed content: gradient rows (literals) + solid rows (RLE matches),
        // spanning well past one pixel so distance-4 matches are exercised.
        let (w, h) = (300u32, 60u32);
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                if y % 2 == 0 {
                    // Solid color row: long runs.
                    rgba.extend_from_slice(&[10, 200, 30, 255]);
                } else {
                    // Gradient row: literals.
                    rgba.extend_from_slice(&[
                        (x % 251) as u8,
                        (y % 251) as u8,
                        ((x + y) % 251) as u8,
                        255,
                    ]);
                }
            }
        }
        let png = encode(w, h, &rgba);
        // Compressed output must be smaller than raw for this content: the
        // solid rows compress to near-nothing (RLE matches), the gradient
        // rows stay literal-heavy, so the mix lands around ~55% of raw.
        let raw_size = ((w * 4 + 1) * h) as usize;
        assert!(
            png.len() < raw_size * 3 / 5,
            "png {} vs raw {}",
            png.len(),
            raw_size
        );
        // Locate IDAT payload.
        let mut pos = 8usize;
        let mut idat: Vec<u8> = Vec::new();
        while pos + 8 <= png.len() {
            let len =
                u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
            let tag = &png[pos + 4..pos + 8];
            if tag == b"IDAT" {
                idat.extend_from_slice(&png[pos + 8..pos + 8 + len]);
            }
            pos += 12 + len;
        }
        let raw = crate::image_codec::inflate::inflate_zlib(&idat, 10 << 20)
            .expect("valid zlib stream");
        assert_eq!(raw.len(), raw_size);
        // Reconstruct the expected filtered stream and compare exactly.
        let stride = (w * 4) as usize;
        for y in 0..h as usize {
            let row = &raw[y * (stride + 1)..(y + 1) * (stride + 1)];
            assert_eq!(row[0], 0, "filter byte row {y}");
            assert_eq!(&row[1..], &rgba[y * stride..(y + 1) * stride], "row {y}");
        }
    }

    #[test]
    fn projected_cost_is_monotonic() {
        assert!(projected_encode_cost(100, 100) < projected_encode_cost(1000, 1000));
        // 1280x8192 (the default cap) stays under 100 MiB projected.
        assert!(projected_encode_cost(1280, 8192) < 100 * 1024 * 1024);
    }
}
