# Image writer notices

The attachment JPEG writer adapts marker layout, RGB conversion, component tables and quantization from [image 0.24.9](https://github.com/image-rs/image/tree/v0.24.9/src/codecs/jpeg), under the MIT license (image-MIT.txt). It uses a bounded local byte sink, caches the level shifted coefficient blocks between quality attempts, and works only on RGBA8 input.

This software is based in part on the work of the Independent JPEG Group. The integer forward DCT is the unmodified Rust translation in image 0.24.9 of the IJG's `jfdctint.c`. The upstream source and original IJG 9a README (IJG-9a-README.txt) retain their copyright and warranty terms. Only the README line endings were normalized from CRLF to LF; the complete original text is retained. No modifications were made to the IJG-derived transform.

The attachment PNG writer adapts the RGBA8 filter order, signed-byte scoring, and compressed/stored decision from [png 0.17.14](https://github.com/image-rs/image-png/tree/v0.17.14/src), under the MIT license (png-MIT.txt). Only encoding is used. It computes predictors in one bounded row scratch and uses the existing package's PNG chunk writer and scalar checksums.

The zlib bitstream is adapted from the compressor and tables in [fdeflate 0.3.6](https://github.com/image-rs/fdeflate/tree/v0.3.6/src), under the MIT license (fdeflate-MIT.txt). The adaptation removes decoding tables and development tests, replaces the SIMD Adler implementation with the equivalent scalar checksum, and propagates bounded-writer I/O errors. The code retains the same row feed boundaries and stored block selection.

The scalar JPEG input IDCT and BT.601 conversion adapt the safe full-resolution scalar implementations in [jpeg-decoder 0.3.1](https://github.com/image-rs/jpeg-decoder/tree/v0.3.1/src), under the MIT license (jpeg-decoder-MIT.txt). The IDCT uses the block that this package's JPEG decoder has already dequantized and returns a fixed 8×8 pixel array. The algorithm in that implementation traces its IDCT to stb_image. SIMD, subsampling changes and parser changes are not included.
