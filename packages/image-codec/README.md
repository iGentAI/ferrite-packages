# image-codec

Raster image decoding, PNG encoding and model-input preparation, as a Ferrite source package. An application uses it to read the size or the pixels of an image it was given, to write pixels as a PNG, and to fit an attachment to the dimension and payload limits of the model that will receive it.

The package has no dependencies beyond `std` and does no I/O. Every decoder is written for hostile input: truncated, malformed or adversarial bytes return `None` and never panic, all access is bounds-checked, and decoded output is capped at `MAX_PIXELS` (16 million pixels, 64 MiB of RGBA). It mounts at `image_codec`.

## API

| Item | Contents |
| --- | --- |
| `sniff`, `ImageFormat` | Identify PNG, JPEG, GIF or WebP from the leading bytes. |
| `dimensions` | Read the width and height from the header without decoding. |
| `decode`, `DecodedImage` | Decode any supported format into straight (non-premultiplied) RGBA8, row-major. |
| `png_dec` | PNG decoder: greyscale, RGB, palette, greyscale with alpha and RGBA, with `tRNS` transparency. 16-bit channels are reduced to 8. Adam7 interlaced files are refused. |
| `jpeg` | JPEG decoder: baseline, extended sequential and progressive DCT, greyscale and YCbCr, 4:4:4, 4:2:2 and 4:2:0 subsampling, restart markers. |
| `gif` | GIF87a and GIF89a decoder: global and local colour tables, interlacing, transparency. The first frame is returned. |
| `webp`, `vp8` | WebP decoder: VP8L (lossless) in full, and VP8 (lossy) key frames per RFC 6386. The VP8 in-loop deblocking filter is parsed and not applied. |
| `inflate` | Bounded DEFLATE and zlib decompression (`inflate`, `inflate_zlib`), each with a caller-supplied output limit. |
| `png` | `png::encode` writes RGBA8 as a PNG using fixed-Huffman DEFLATE with run matching, streaming one row at a time. `png::projected_encode_cost` gives the memory a caller should budget before encoding. |
| `prepare` | Model-input preparation, described below. |

## Preparing an image for a model

`prepare::sniff_model_image` classifies bytes as `image/png`, `image/jpeg`, `image/gif`, `image/webp` or `image/bmp` from their content, never from a file name or a declared type, and refuses animated PNG. `prepare::sniff_classic` does the same from the first 4,100 bytes.

`prepare::prepare(bytes, limits)` takes an `ImageLimits` (maximum width, maximum height and maximum base64 length) and returns a `PreparedImage`:

- A source larger than `MAX_SOURCE_BYTES` (8 MiB) is refused before any parsing.
- The bytes must decode. An image that already fits the limits and needs no rotation is returned borrowed, byte for byte.
- Otherwise the image is turned upright according to its EXIF orientation, scaled down with a Lanczos3 filter to fit the limits, and re-encoded. A JPEG source is tried as JPEG first (quality 80, 70, 55, then 40) and then as PNG; any other source is tried as PNG first. If no candidate fits the payload limit, the size is reduced by a quarter and the attempt repeats down to one pixel.
- `PreparedImage` reports the output bytes and MIME type, the source MIME type, and the upright dimensions of the input and of the output.

```bash
ferrite add image-codec
```

Declare `pub mod image_codec;` in the crate root:

```rust
use crate::image_codec::prepare::{prepare, ImageLimits};

let limits = ImageLimits { width: 2000, height: 2000, base64_bytes: 4 * 1024 * 1024 };
if let Some(image) = prepare(&upload, limits) {
    // image.bytes is at most 3 MiB, image.mime names its format, and
    // image.size is at most 2000 by 2000.
}
```

Installed copies are generated: edit the package source and recompose with `ferrite-pkg`, never by modifying a vendored copy.

## Notices

The JPEG writer, the attachment PNG writer, its zlib bitstream and the scalar JPEG inverse DCT adapt code from the `image`, `png`, `fdeflate` and `jpeg-decoder` crates (MIT) and from the Independent JPEG Group's software. `src/codec-notices/README.md` says which file adapts what, and the licence texts beside it are installed with the package into every application. The VP8, VP8L, GIF, PNG and DEFLATE decoders are written from their specifications.

## Status

Active source package compiled directly into constrained Ferrite applications. It has no dependencies beyond `std`.

## Not claimed

This package decodes still images only: an animated GIF yields its first frame, WebP animation is not supported, and animated PNG is refused by `prepare`. Interlaced PNG is refused. It does not apply the VP8 loop filter, so a lossy WebP decodes with slightly harder block edges than a reference decoder produces. It has no general-purpose JPEG or WebP encoder; the JPEG writer exists for `prepare` and is not exported. It is not independently deployable.

## Validation

This directory includes a standalone test harness (`Cargo.toml` and `harness/lib.rs`, ignored by `ferrite-pkg` and `ferrite add`) that runs the unit tests:

```bash
cargo test --manifest-path packages/image-codec/Cargo.toml
node tools/ferrite-pkg/ferrite-pkg.mjs check
```

The model-input preparation is also tested in `apps/ferrite-durable` (`tests/image_tool.rs`) against recorded output of an independent reference implementation.
