//! image — dependency-free raster image decoding for the browser engine.
//!
//! Decodes the four formats that dominate the web — PNG, JPEG (baseline and progressive),
//! GIF (first frame), and WebP — into straight RGBA8 buffers so pages with
//! images lay out with real intrinsic sizes and screenshots composite the
//! actual pixels.
//!
//! Like every other stage of the engine it is infallible by construction:
//! truncated, hostile, or garbage bytes yield `None`, never a panic. No
//! indexing, no unwrap — all access is bounds-checked (`get`), all arithmetic
//! saturating or checked.

pub mod gif;
pub mod inflate;
pub mod jpeg;
pub mod png_dec;
pub mod prepare;
pub mod vp8;
pub mod webp;

/// A decoded raster image: straight (non-premultiplied) RGBA8, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedImage {
    pub width: usize,
    pub height: usize,
    /// Exactly `width * height * 4` bytes, RGBA order.
    pub rgba: Vec<u8>,
}

impl DecodedImage {
    /// Construct with a validated buffer size; rejects overflow and mismatch.
    pub fn new(width: usize, height: usize, rgba: Vec<u8>) -> Option<Self> {
        let px = width.checked_mul(height)?;
        let bytes = px.checked_mul(4)?;
        if rgba.len() != bytes || width == 0 || height == 0 {
            return None;
        }
        Some(Self {
            width,
            height,
            rgba,
        })
    }
}

/// The image formats the engine can identify from magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    Webp,
}

/// Identify an image format from its leading magic bytes.
pub fn sniff(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(ImageFormat::Png);
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return Some(ImageFormat::Jpeg);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(ImageFormat::Gif);
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return Some(ImageFormat::Webp);
    }
    None
}

/// Pixel budget shared by all decoders: 64 MiB of RGBA (16 Mpx) — the same
/// bound the rasterizer enforces, so a decoded image can never out-size the
/// canvas it composites onto.
pub const MAX_PIXELS: usize = 16 * 1024 * 1024;

/// Decode any supported image format into RGBA8.
///
/// Returns `None` for unknown formats, corrupt data, or images exceeding the
/// pixel budget. Never panics.
pub fn decode(bytes: &[u8]) -> Option<DecodedImage> {
    match sniff(bytes)? {
        ImageFormat::Png => png_dec::decode(bytes),
        ImageFormat::Jpeg => jpeg::decode(bytes),
        ImageFormat::Gif => gif::decode(bytes),
        ImageFormat::Webp => webp::decode(bytes),
    }
}

/// Read the intrinsic dimensions cheaply (header only) — used by layout when
/// only the size is needed.
pub fn dimensions(bytes: &[u8]) -> Option<(usize, usize)> {
    match sniff(bytes)? {
        ImageFormat::Png => png_dec::dimensions(bytes),
        ImageFormat::Jpeg => jpeg::dimensions(bytes),
        ImageFormat::Gif => gif::dimensions(bytes),
        ImageFormat::Webp => webp::dimensions(bytes),
    }
}
