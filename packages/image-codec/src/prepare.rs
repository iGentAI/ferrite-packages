//! Model-facing raster normalization. Bytes stay borrowed when validation
//! succeeds and no resize, re-encoding or EXIF orientation is needed.

use std::borrow::Cow;

use super::{DecodedImage, MAX_PIXELS};

mod bmp;
mod exif;

/// Fixed source bound before parsing or allocation. Output is additionally
/// bounded by the selected model's base64 and dimension limits.
pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageLimits {
    pub width: usize,
    pub height: usize,
    pub base64_bytes: usize,
}

impl Default for ImageLimits {
    fn default() -> Self {
        Self {
            width: 2000,
            height: 2000,
            base64_bytes: 9 * 512 * 1024,
        }
    }
}

pub struct PreparedImage<'a> {
    pub bytes: Cow<'a, [u8]>,
    pub mime: &'static str,
    pub source_mime: &'static str,
    /// Upright dimensions of the input and the output.
    pub original: (usize, usize),
    pub size: (usize, usize),
}

pub fn sniff_classic(bytes: &[u8]) -> Option<&'static str> {
    sniff_model_image(bytes.get(..4100).unwrap_or(bytes))
}

/// Match Durable's whole-source classification, including APNG's acTL test.
pub fn sniff_model_image(bytes: &[u8]) -> Option<&'static str> {
    let mime = match super::sniff(bytes) {
        Some(super::ImageFormat::Png) => {
            if bytes.get(8..16) != Some(b"\0\0\0\x0dIHDR") || animated_png(bytes) {
                return None;
            }
            "image/png"
        }
        Some(super::ImageFormat::Jpeg) if bytes.get(3) != Some(&0xf7) => "image/jpeg",
        Some(super::ImageFormat::Gif) => "image/gif",
        Some(super::ImageFormat::Webp) => "image/webp",
        None if bmp::sniff(bytes) => "image/bmp",
        _ => return None,
    };
    Some(mime)
}

fn animated_png(bytes: &[u8]) -> bool {
    let mut at = 8usize;
    while let Some(header) = at.checked_add(8).and_then(|end| bytes.get(at..end)) {
        match &header[4..] {
            b"acTL" => return true,
            b"IDAT" => return false,
            _ => {}
        }
        let Some(len) = header[..4].try_into().ok().map(u32::from_be_bytes) else {
            break;
        };
        let Some(next) = at
            .checked_add(12)
            .and_then(|base| base.checked_add(len as usize))
        else {
            break;
        };
        at = next;
    }
    false
}

/// Use the detected MIME type, not an untrusted extension or declared type.
/// The decoder must accept the bytes even when no conversion is needed.
pub fn prepare(bytes: &[u8], limits: ImageLimits) -> Option<PreparedImage<'_>> {
    if bytes.len() > MAX_SOURCE_BYTES || limits.width == 0 || limits.height == 0 {
        return None;
    }
    let source_mime = sniff_model_image(bytes)?;
    let image = match source_mime {
        "image/bmp" => bmp::decode(bytes)?,
        "image/jpeg" => super::jpeg::decode_for_model(bytes)?,
        _ => super::decode(bytes)?,
    };
    let orientation = exif::read(bytes, source_mime).unwrap_or(1);
    let original = if orientation >= 5 {
        (image.height, image.width)
    } else {
        (image.width, image.height)
    };
    if orientation == 1
        && source_mime != "image/bmp"
        && original.0 <= limits.width
        && original.1 <= limits.height
        && fits(bytes.len(), limits.base64_bytes)
    {
        return Some(PreparedImage {
            bytes: Cow::Borrowed(bytes),
            mime: source_mime,
            source_mime,
            original,
            size: original,
        });
    }
    let scale = 1.0_f64
        .min(limits.width as f64 / original.0 as f64)
        .min(limits.height as f64 / original.1 as f64);
    let mut size = (
        (original.0 as f64 * scale).round() as usize,
        (original.1 as f64 * scale).round() as usize,
    );
    size = (
        size.0.clamp(1, limits.width),
        size.1.clamp(1, limits.height),
    );
    loop {
        let oriented;
        let pixels = if orientation == 1 && size == original {
            image.rgba.as_slice()
        } else {
            oriented = sample(&image, orientation, original, size)?;
            &oriented
        };
        if let Some((encoded, mime)) = encode_candidate(
            size,
            pixels,
            source_mime == "image/jpeg",
            limits.base64_bytes,
        ) {
            return Some(PreparedImage {
                bytes: Cow::Owned(encoded),
                mime,
                source_mime,
                original,
                size,
            });
        }
        if size == (1, 1) {
            return None;
        }
        size = ((size.0 * 3 / 4).max(1), (size.1 * 3 / 4).max(1));
    }
}

fn encode_candidate(
    size: (usize, usize),
    pixels: &[u8],
    jpeg_first: bool,
    base64_limit: usize,
) -> Option<(Vec<u8>, &'static str)> {
    use super::jpeg::encode::{PreparedDct, MIN_OUTPUT_BYTES};
    let png = || {
        super::png::photon::encode(
            u32::try_from(size.0).ok()?,
            u32::try_from(size.1).ok()?,
            pixels,
            (base64_limit / 4) * 3,
        )
        .map(|bytes| (bytes, "image/png"))
    };
    let jpeg = || {
        let max_bytes = (base64_limit / 4) * 3;
        if max_bytes < MIN_OUTPUT_BYTES {
            return None;
        }
        let dct = PreparedDct::new(size.0, size.1, pixels)?;
        [80, 70, 55, 40].into_iter().find_map(|quality| {
            dct.encode(quality, max_bytes)
                .map(|image| (image, "image/jpeg"))
        })
    };
    if jpeg_first {
        jpeg().or_else(png)
    } else {
        png().or_else(jpeg)
    }
}

fn fits(bytes: usize, base64: usize) -> bool {
    bytes.div_ceil(3) <= base64 / 4
}

/// Inverse orientation mapping reuses the decoded raster without allocating
/// an unscaled rotated copy. The separable Lanczos3 kernel keeps only one
/// intermediate row instead of an entire floating-point raster.
fn sample(
    image: &DecodedImage,
    orientation: u16,
    original: (usize, usize),
    target: (usize, usize),
) -> Option<Vec<u8>> {
    let pixels = target.0.checked_mul(target.1)?;
    if pixels > MAX_PIXELS {
        return None;
    }
    let mut out = Vec::with_capacity(pixels * 4);
    let pixel = |x: usize, y: usize| {
        let (w, h) = (image.width, image.height);
        let (sx, sy) = match orientation {
            2 => (w - 1 - x, y),
            3 => (w - 1 - x, h - 1 - y),
            4 => (x, h - 1 - y),
            5 => (y, x),
            6 => (y, h - 1 - x),
            7 => (w - 1 - y, h - 1 - x),
            8 => (w - 1 - y, x),
            _ => (x, y),
        };
        let at = (sy * w + sx) * 4;
        image.rgba.get(at..at + 4)
    };
    if original == target {
        for y in 0..target.1 {
            for x in 0..target.0 {
                out.extend_from_slice(pixel(x, y)?);
            }
        }
        return Some(out);
    }
    const MAX_FILTER_AXIS: usize = 16_384;
    if original.0 > MAX_FILTER_AXIS || original.1 > MAX_FILTER_AXIS {
        return None;
    }

    let horizontal = (0..target.0)
        .map(|x| weights(x, original.0, target.0))
        .collect::<Vec<_>>();
    let mut vertical_row = vec![[0.0_f32; 4]; original.0];
    for y in 0..target.1 {
        let (start, vertical) = weights(y, original.1, target.1);
        for (x, dest) in vertical_row.iter_mut().enumerate() {
            *dest = [0.0; 4];
            for (i, weight) in vertical.iter().copied().enumerate() {
                for (channel, byte) in dest.iter_mut().zip(pixel(x, start + i)?) {
                    *channel += f32::from(*byte) * weight;
                }
            }
        }
        for (start, weights) in &horizontal {
            let mut rgba = [0.0; 4];
            for (pixel, weight) in vertical_row
                .get(*start..*start + weights.len())?
                .iter()
                .zip(weights)
            {
                for (channel, value) in rgba.iter_mut().zip(pixel) {
                    *channel += value * weight;
                }
            }
            out.extend(rgba.map(|channel| channel.round().clamp(0.0, 255.0) as u8));
        }
    }
    Some(out)
}

// Precompute the clipped, normalized window for one sample. Widen the filter
// footprint on downsampling so pixels between output centers contribute.
fn weights(dest: usize, source_len: usize, target_len: usize) -> (usize, Vec<f32>) {
    if source_len == target_len {
        return (dest, vec![1.0]);
    }
    let ratio = source_len as f32 / target_len as f32;
    let center = (dest as f32 + 0.5) * ratio;
    let stretch = ratio.max(1.0);
    let radius = 3.0 * stretch;
    let start = ((center - radius).floor() as usize).min(source_len - 1);
    let end = ((center + radius).ceil() as usize).clamp(start + 1, source_len);
    let mut weights = (start..end)
        .map(|index| {
            let x = (index as f32 + 0.5 - center) / stretch;
            if x == 0.0 {
                1.0
            } else if x.abs() < 3.0 {
                let a = std::f32::consts::PI * x;
                let b = a / 3.0;
                a.sin() / a * (b.sin() / b)
            } else {
                0.0
            }
        })
        .collect::<Vec<_>>();
    let sum: f32 = weights.iter().sum();
    weights.iter_mut().for_each(|weight| *weight /= sum);
    (start, weights)
}
