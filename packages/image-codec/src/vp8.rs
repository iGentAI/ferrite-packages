//! vp8 — baseline VP8 (lossy WebP) key-frame decoder per RFC 6386.
//!
//! Decodes intra-only key frames — which is every still lossy WebP image —
//! into Y/Cb/Cr planes and converts to RGBA. Implemented from the spec:
//!
//! * §7 boolean entropy decoder (bit-at-a-time, zero-fed past the end of a
//!   partition so truncated data terminates instead of reading wild)
//! * §9 frame header: color space bits, segmentation (quantizer deltas
//!   applied; loop-filter deltas parsed and ignored), loop filter parameters
//!   (parsed and ignored, see below), token partitions, dequantization
//!   indices, refresh-entropy bit, coefficient probability updates, and
//!   `mb_no_coeff_skip`
//! * §10 segment-id decoding per macroblock
//! * §11 key-frame macroblock prediction records: Y mode via
//!   `kf_ymode_tree`, contextual 4x4 submodes via `kf_bmode_prob`
//!   \[above]\[left], chroma mode via `kf_uv_mode_prob`
//! * §12 intra prediction: 16x16 luma and 8x8 chroma DC/V/H/TM with the 127
//!   (above) / 129 (left) frame-border values, and all ten 4x4 B_PRED
//!   submodes including the above-right edge duplication rule
//! * §13 DCT coefficient decoding: token tree with plane/band/neighbour
//!   contexts, DCT_CAT1..6 extra bits, sign, zigzag placement
//! * §14 dequantization (with the Y2 2x DC / 155/100 AC scaling and the
//!   chroma-DC 132 clamp), inverse WHT for Y2, the exact integer inverse DCT
//!   (20091 / 35468 multipliers), predictor + residue summation with
//!   clamping
//!
//! Deliberately **not** implemented:
//!
//! * §15 loop filter. The in-loop deblocking filter is parsed but not
//!   applied. For still images this trades a small amount of smoothing at
//!   block edges (visible mostly at very low quality settings) for a
//!   substantially smaller decoder; the image structure, colors, and
//!   dimensions are unaffected. Every other stage is bit-exact per spec.
//! * §16-18 interframes. A still WebP is always a key frame; non-key frames
//!   yield `None`.
//!
//! Hostile-input contract matches the rest of the `image` module: malformed,
//! truncated, or adversarial bytes return `None` — never a panic — and all
//! loops are bounded by the (validated) frame dimensions, so garbage input
//! terminates quickly. No indexing, no unwrap; all access is bounds-checked.
//!
//! The probability / quantizer tables below are transcribed from the
//! normative tables in RFC 6386 §11.5, §13.4, §13.5, and §14.1.

use super::{DecodedImage, MAX_PIXELS};

/// Zigzag order: maps coefficient position to raster position (§13, §20.16).
const ZIGZAG: [u8; 16] = [0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15];

/// Coefficient position -> probability band (§13.3).
const COEFF_BANDS: [u8; 16] = [0, 1, 2, 3, 6, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7];

/// Per-4x4-block "left" / "above" non-zero context slots (§13.3, tokens.c).
/// Blocks 0..16 are Y, 16..20 U, 20..24 V; the Y2 block uses slot 8.
const LEFT_CTX_IDX: [u8; 24] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
];
const ABOVE_CTX_IDX: [u8; 24] = [
    0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 4, 5, 4, 5, 6, 7, 6, 7,
];

/// Key-frame luma mode tree and probabilities (§11.2). Leaves are negated
/// mode values: DC=0, V=1, H=2, TM=3, B_PRED=4.
const KF_YMODE_TREE: [i8; 8] = [-4, 2, 4, 6, 0, -1, -2, -3];
const KF_YMODE_PROB: [u8; 4] = [145, 156, 163, 128];

/// Chroma mode tree and key-frame probabilities (§11.4).
const UV_MODE_TREE: [i8; 6] = [0, 2, -1, 4, -2, -3];
const KF_UV_MODE_PROB: [u8; 3] = [142, 114, 183];

/// 4x4 submode tree (§11.2). Leaves: B_DC=0, B_TM=1, B_VE=2, B_HE=3, B_LD=4,
/// B_RD=5, B_VR=6, B_VL=7, B_HD=8, B_HU=9.
const BMODE_TREE: [i8; 18] = [
    0, 2, -1, 4, -2, 6, 8, 12, -3, 10, -5, -6, -4, 14, -7, 16, -8, -9,
];

/// DCT token tree (§13.2). Leaves: literal 0..4, cat1..cat6 = 5..10, EOB=11.
const COEFF_TREE: [i8; 22] = [
    -11, 2, 0, 4, -1, 6, 8, 12, -2, 10, -3, -4, 14, 16, -5, -6, 18, 20, -7, -8, -9, -10,
];
const TOKEN_EOB: u32 = 11;

/// DCT_CAT1..6 base values and extra-bit probabilities (§13.2).
const CAT_BASE: [i32; 6] = [5, 7, 11, 19, 35, 67];
const PCAT1: [u8; 1] = [159];
const PCAT2: [u8; 2] = [165, 145];
const PCAT3: [u8; 3] = [173, 148, 140];
const PCAT4: [u8; 4] = [176, 155, 140, 135];
const PCAT5: [u8; 5] = [180, 157, 141, 134, 130];
const PCAT6: [u8; 11] = [254, 254, 243, 230, 196, 177, 153, 140, 133, 130, 129];

fn cat_probs(cat: usize) -> &'static [u8] {
    match cat {
        0 => &PCAT1,
        1 => &PCAT2,
        2 => &PCAT3,
        3 => &PCAT4,
        4 => &PCAT5,
        _ => &PCAT6,
    }
}

/// Key-frame 4x4 submode probabilities, `kf_bmode_prob[above][left][node]`
/// flattened to `[(above*10 + left)*9 + node]` (§11.5).
const KF_BMODE_PROB: [u8; 900] = [
    231, 120, 48, 89, 115, 113, 120, 152, 112, 152, 179, 64, 126, 170, 118, 46, 70, 95, 175, 69,
    143, 80, 85, 82, 72, 155, 103, 56, 58, 10, 171, 218, 189, 17, 13, 152, 144, 71, 10, 38, 171,
    213, 144, 34, 26, 114, 26, 17, 163, 44, 195, 21, 10, 173, 121, 24, 80, 195, 26, 62, 44, 64, 85,
    170, 46, 55, 19, 136, 160, 33, 206, 71, 63, 20, 8, 114, 114, 208, 12, 9, 226, 81, 40, 11, 96,
    182, 84, 29, 16, 36, 134, 183, 89, 137, 98, 101, 106, 165, 148, 72, 187, 100, 130, 157, 111,
    32, 75, 80, 66, 102, 167, 99, 74, 62, 40, 234, 128, 41, 53, 9, 178, 241, 141, 26, 8, 107, 104,
    79, 12, 27, 217, 255, 87, 17, 7, 74, 43, 26, 146, 73, 166, 49, 23, 157, 65, 38, 105, 160, 51,
    52, 31, 115, 128, 87, 68, 71, 44, 114, 51, 15, 186, 23, 47, 41, 14, 110, 182, 183, 21, 17, 194,
    66, 45, 25, 102, 197, 189, 23, 18, 22, 88, 88, 147, 150, 42, 46, 45, 196, 205, 43, 97, 183,
    117, 85, 38, 35, 179, 61, 39, 53, 200, 87, 26, 21, 43, 232, 171, 56, 34, 51, 104, 114, 102, 29,
    93, 77, 107, 54, 32, 26, 51, 1, 81, 43, 31, 39, 28, 85, 171, 58, 165, 90, 98, 64, 34, 22, 116,
    206, 23, 34, 43, 166, 73, 68, 25, 106, 22, 64, 171, 36, 225, 114, 34, 19, 21, 102, 132, 188,
    16, 76, 124, 62, 18, 78, 95, 85, 57, 50, 48, 51, 193, 101, 35, 159, 215, 111, 89, 46, 111, 60,
    148, 31, 172, 219, 228, 21, 18, 111, 112, 113, 77, 85, 179, 255, 38, 120, 114, 40, 42, 1, 196,
    245, 209, 10, 25, 109, 100, 80, 8, 43, 154, 1, 51, 26, 71, 88, 43, 29, 140, 166, 213, 37, 43,
    154, 61, 63, 30, 155, 67, 45, 68, 1, 209, 142, 78, 78, 16, 255, 128, 34, 197, 171, 41, 40, 5,
    102, 211, 183, 4, 1, 221, 51, 50, 17, 168, 209, 192, 23, 25, 82, 125, 98, 42, 88, 104, 85, 117,
    175, 82, 95, 84, 53, 89, 128, 100, 113, 101, 45, 75, 79, 123, 47, 51, 128, 81, 171, 1, 57, 17,
    5, 71, 102, 57, 53, 41, 49, 115, 21, 2, 10, 102, 255, 166, 23, 6, 38, 33, 13, 121, 57, 73, 26,
    1, 85, 41, 10, 67, 138, 77, 110, 90, 47, 114, 101, 29, 16, 10, 85, 128, 101, 196, 26, 57, 18,
    10, 102, 102, 213, 34, 20, 43, 117, 20, 15, 36, 163, 128, 68, 1, 26, 138, 31, 36, 171, 27, 166,
    38, 44, 229, 67, 87, 58, 169, 82, 115, 26, 59, 179, 63, 59, 90, 180, 59, 166, 93, 73, 154, 40,
    40, 21, 116, 143, 209, 34, 39, 175, 57, 46, 22, 24, 128, 1, 54, 17, 37, 47, 15, 16, 183, 34,
    223, 49, 45, 183, 46, 17, 33, 183, 6, 98, 15, 32, 183, 65, 32, 73, 115, 28, 128, 23, 128, 205,
    40, 3, 9, 115, 51, 192, 18, 6, 223, 87, 37, 9, 115, 59, 77, 64, 21, 47, 104, 55, 44, 218, 9,
    54, 53, 130, 226, 64, 90, 70, 205, 40, 41, 23, 26, 57, 54, 57, 112, 184, 5, 41, 38, 166, 213,
    30, 34, 26, 133, 152, 116, 10, 32, 134, 75, 32, 12, 51, 192, 255, 160, 43, 51, 39, 19, 53, 221,
    26, 114, 32, 73, 255, 31, 9, 65, 234, 2, 15, 1, 118, 73, 88, 31, 35, 67, 102, 85, 55, 186, 85,
    56, 21, 23, 111, 59, 205, 45, 37, 192, 55, 38, 70, 124, 73, 102, 1, 34, 98, 102, 61, 71, 37,
    34, 53, 31, 243, 192, 69, 60, 71, 38, 73, 119, 28, 222, 37, 68, 45, 128, 34, 1, 47, 11, 245,
    171, 62, 17, 19, 70, 146, 85, 55, 62, 70, 75, 15, 9, 9, 64, 255, 184, 119, 16, 37, 43, 37, 154,
    100, 163, 85, 160, 1, 63, 9, 92, 136, 28, 64, 32, 201, 85, 86, 6, 28, 5, 64, 255, 25, 248, 1,
    56, 8, 17, 132, 137, 255, 55, 116, 128, 58, 15, 20, 82, 135, 57, 26, 121, 40, 164, 50, 31, 137,
    154, 133, 25, 35, 218, 51, 103, 44, 131, 131, 123, 31, 6, 158, 86, 40, 64, 135, 148, 224, 45,
    183, 128, 22, 26, 17, 131, 240, 154, 14, 1, 209, 83, 12, 13, 54, 192, 255, 68, 47, 28, 45, 16,
    21, 91, 64, 222, 7, 1, 197, 56, 21, 39, 155, 60, 138, 23, 102, 213, 85, 26, 85, 85, 128, 128,
    32, 146, 171, 18, 11, 7, 63, 144, 171, 4, 4, 246, 35, 27, 10, 146, 174, 171, 12, 26, 128, 190,
    80, 35, 99, 180, 80, 126, 54, 45, 85, 126, 47, 87, 176, 51, 41, 20, 32, 101, 75, 128, 139, 118,
    146, 116, 128, 85, 56, 41, 15, 176, 236, 85, 37, 9, 62, 146, 36, 19, 30, 171, 255, 97, 27, 20,
    71, 30, 17, 119, 118, 255, 17, 18, 138, 101, 38, 60, 138, 55, 70, 43, 26, 142, 138, 45, 61, 62,
    219, 1, 81, 188, 64, 32, 41, 20, 117, 151, 142, 20, 21, 163, 112, 19, 12, 61, 195, 128, 48, 4,
    24,
];

/// Probabilities that each coefficient probability is updated in the frame
/// header, `[4][8][3][11]` flattened (§13.4).
const COEFF_UPDATE_PROBS: [u8; 1056] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 176, 246, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 223, 241, 252, 255, 255, 255, 255, 255, 255, 255, 255, 249, 253,
    253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 244, 252, 255, 255, 255, 255, 255, 255, 255,
    255, 234, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 246, 254, 255, 255, 255, 255, 255, 255, 255, 255, 239, 253, 254, 255,
    255, 255, 255, 255, 255, 255, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    248, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251, 255, 254, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 254, 255, 255, 255,
    255, 255, 255, 255, 255, 251, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 254,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 253, 255, 254, 255, 255, 255, 255, 255, 255,
    250, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 217, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 225, 252, 241, 253, 255, 255, 254, 255, 255, 255,
    255, 234, 250, 241, 250, 253, 255, 253, 254, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 223, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 238, 253, 254, 254,
    255, 255, 255, 255, 255, 255, 255, 255, 248, 254, 255, 255, 255, 255, 255, 255, 255, 255, 249,
    254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 247, 254, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 254,
    255, 255, 255, 255, 255, 255, 255, 255, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 254, 255, 255, 255, 255, 255,
    255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255, 250, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 186, 251, 250, 255,
    255, 255, 255, 255, 255, 255, 255, 234, 251, 244, 254, 255, 255, 255, 255, 255, 255, 255, 251,
    251, 243, 253, 254, 255, 254, 255, 255, 255, 255, 255, 253, 254, 255, 255, 255, 255, 255, 255,
    255, 255, 236, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251, 253, 253, 254, 254, 255,
    255, 255, 255, 255, 255, 255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 254, 254, 254,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 254, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 248, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 250, 254, 252, 254, 255, 255, 255, 255, 255, 255, 255, 248, 254, 249,
    253, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255,
    246, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255, 252, 254, 251, 254, 254, 255, 255, 255,
    255, 255, 255, 255, 254, 252, 255, 255, 255, 255, 255, 255, 255, 255, 248, 254, 253, 255, 255,
    255, 255, 255, 255, 255, 255, 253, 255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251,
    254, 255, 255, 255, 255, 255, 255, 255, 255, 245, 251, 254, 255, 255, 255, 255, 255, 255, 255,
    255, 253, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 251, 253, 255, 255, 255, 255,
    255, 255, 255, 255, 252, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 249,
    255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 250, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

/// Default coefficient probabilities, `[4][8][3][11]` flattened (§13.5).
const DEFAULT_COEFF_PROBS: [u8; 1056] = [
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 253, 136, 254, 255, 228,
    219, 128, 128, 128, 128, 128, 189, 129, 242, 255, 227, 213, 255, 219, 128, 128, 128, 106, 126,
    227, 252, 214, 209, 255, 255, 128, 128, 128, 1, 98, 248, 255, 236, 226, 255, 255, 128, 128,
    128, 181, 133, 238, 254, 221, 234, 255, 154, 128, 128, 128, 78, 134, 202, 247, 198, 180, 255,
    219, 128, 128, 128, 1, 185, 249, 255, 243, 255, 128, 128, 128, 128, 128, 184, 150, 247, 255,
    236, 224, 128, 128, 128, 128, 128, 77, 110, 216, 255, 236, 230, 128, 128, 128, 128, 128, 1,
    101, 251, 255, 241, 255, 128, 128, 128, 128, 128, 170, 139, 241, 252, 236, 209, 255, 255, 128,
    128, 128, 37, 116, 196, 243, 228, 255, 255, 255, 128, 128, 128, 1, 204, 254, 255, 245, 255,
    128, 128, 128, 128, 128, 207, 160, 250, 255, 238, 128, 128, 128, 128, 128, 128, 102, 103, 231,
    255, 211, 171, 128, 128, 128, 128, 128, 1, 152, 252, 255, 240, 255, 128, 128, 128, 128, 128,
    177, 135, 243, 255, 234, 225, 128, 128, 128, 128, 128, 80, 129, 211, 255, 194, 224, 128, 128,
    128, 128, 128, 1, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 246, 1, 255, 128, 128, 128,
    128, 128, 128, 128, 128, 255, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 198, 35, 237,
    223, 193, 187, 162, 160, 145, 155, 62, 131, 45, 198, 221, 172, 176, 220, 157, 252, 221, 1, 68,
    47, 146, 208, 149, 167, 221, 162, 255, 223, 128, 1, 149, 241, 255, 221, 224, 255, 255, 128,
    128, 128, 184, 141, 234, 253, 222, 220, 255, 199, 128, 128, 128, 81, 99, 181, 242, 176, 190,
    249, 202, 255, 255, 128, 1, 129, 232, 253, 214, 197, 242, 196, 255, 255, 128, 99, 121, 210,
    250, 201, 198, 255, 202, 128, 128, 128, 23, 91, 163, 242, 170, 187, 247, 210, 255, 255, 128, 1,
    200, 246, 255, 234, 255, 128, 128, 128, 128, 128, 109, 178, 241, 255, 231, 245, 255, 255, 128,
    128, 128, 44, 130, 201, 253, 205, 192, 255, 255, 128, 128, 128, 1, 132, 239, 251, 219, 209,
    255, 165, 128, 128, 128, 94, 136, 225, 251, 218, 190, 255, 255, 128, 128, 128, 22, 100, 174,
    245, 186, 161, 255, 199, 128, 128, 128, 1, 182, 249, 255, 232, 235, 128, 128, 128, 128, 128,
    124, 143, 241, 255, 227, 234, 128, 128, 128, 128, 128, 35, 77, 181, 251, 193, 211, 255, 205,
    128, 128, 128, 1, 157, 247, 255, 236, 231, 255, 255, 128, 128, 128, 121, 141, 235, 255, 225,
    227, 255, 255, 128, 128, 128, 45, 99, 188, 251, 195, 217, 255, 224, 128, 128, 128, 1, 1, 251,
    255, 213, 255, 128, 128, 128, 128, 128, 203, 1, 248, 255, 255, 128, 128, 128, 128, 128, 128,
    137, 1, 177, 255, 224, 255, 128, 128, 128, 128, 128, 253, 9, 248, 251, 207, 208, 255, 192, 128,
    128, 128, 175, 13, 224, 243, 193, 185, 249, 198, 255, 255, 128, 73, 17, 171, 221, 161, 179,
    236, 167, 255, 234, 128, 1, 95, 247, 253, 212, 183, 255, 255, 128, 128, 128, 239, 90, 244, 250,
    211, 209, 255, 255, 128, 128, 128, 155, 77, 195, 248, 188, 195, 255, 255, 128, 128, 128, 1, 24,
    239, 251, 218, 219, 255, 205, 128, 128, 128, 201, 51, 219, 255, 196, 186, 128, 128, 128, 128,
    128, 69, 46, 190, 239, 201, 218, 255, 228, 128, 128, 128, 1, 191, 251, 255, 255, 128, 128, 128,
    128, 128, 128, 223, 165, 249, 255, 213, 255, 128, 128, 128, 128, 128, 141, 124, 248, 255, 255,
    128, 128, 128, 128, 128, 128, 1, 16, 248, 255, 255, 128, 128, 128, 128, 128, 128, 190, 36, 230,
    255, 236, 255, 128, 128, 128, 128, 128, 149, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 1,
    226, 255, 128, 128, 128, 128, 128, 128, 128, 128, 247, 192, 255, 128, 128, 128, 128, 128, 128,
    128, 128, 240, 128, 255, 128, 128, 128, 128, 128, 128, 128, 128, 1, 134, 252, 255, 255, 128,
    128, 128, 128, 128, 128, 213, 62, 250, 255, 255, 128, 128, 128, 128, 128, 128, 55, 93, 255,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 202, 24, 213, 235, 186, 191, 220, 160, 240, 175, 255, 126, 38, 182, 232, 169,
    184, 228, 174, 255, 187, 128, 61, 46, 138, 219, 151, 178, 240, 170, 255, 216, 128, 1, 112, 230,
    250, 199, 191, 247, 159, 255, 255, 128, 166, 109, 228, 252, 211, 215, 255, 174, 128, 128, 128,
    39, 77, 162, 232, 172, 180, 245, 178, 255, 255, 128, 1, 52, 220, 246, 198, 199, 249, 220, 255,
    255, 128, 124, 74, 191, 243, 183, 193, 250, 221, 255, 255, 128, 24, 71, 130, 219, 154, 170,
    243, 182, 255, 255, 128, 1, 182, 225, 249, 219, 240, 255, 224, 128, 128, 128, 149, 150, 226,
    252, 216, 205, 255, 171, 128, 128, 128, 28, 108, 170, 242, 183, 194, 254, 223, 255, 255, 128,
    1, 81, 230, 252, 204, 203, 255, 192, 128, 128, 128, 123, 102, 209, 247, 188, 196, 255, 233,
    128, 128, 128, 20, 95, 153, 243, 164, 173, 255, 203, 128, 128, 128, 1, 222, 248, 255, 216, 213,
    128, 128, 128, 128, 128, 168, 175, 246, 252, 235, 205, 255, 255, 128, 128, 128, 47, 116, 215,
    255, 211, 212, 255, 255, 128, 128, 128, 1, 121, 236, 253, 212, 214, 255, 255, 128, 128, 128,
    141, 84, 213, 252, 201, 202, 255, 219, 128, 128, 128, 42, 80, 160, 240, 162, 185, 255, 205,
    128, 128, 128, 1, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 244, 1, 255, 128, 128, 128,
    128, 128, 128, 128, 128, 238, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128,
];

/// DC dequantization factors indexed by clamped quantizer index (§14.1).
const DC_QLOOKUP: [u16; 128] = [
    4, 5, 6, 7, 8, 9, 10, 10, 11, 12, 13, 14, 15, 16, 17, 17, 18, 19, 20, 20, 21, 21, 22, 22, 23,
    23, 24, 25, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
    68, 69, 70, 71, 72, 73, 74, 75, 76, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 91,
    93, 95, 96, 98, 100, 101, 102, 104, 106, 108, 110, 112, 114, 116, 118, 122, 124, 126, 128, 130,
    132, 134, 136, 138, 140, 143, 145, 148, 151, 154, 157,
];

/// AC dequantization factors indexed by clamped quantizer index (§14.1).
const AC_QLOOKUP: [u16; 128] = [
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
    96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 119, 122, 125, 128, 131, 134, 137, 140,
    143, 146, 149, 152, 155, 158, 161, 164, 167, 170, 173, 177, 181, 185, 189, 193, 197, 201, 205,
    209, 213, 217, 221, 225, 229, 234, 239, 245, 249, 254, 259, 264, 269, 274, 279, 284,
];

#[inline]
fn ag<T: Copy + Default>(a: &[T], i: usize) -> T {
    a.get(i).copied().unwrap_or_default()
}

#[inline]
fn aset<T>(a: &mut [T], i: usize, v: T) {
    if let Some(slot) = a.get_mut(i) {
        *slot = v;
    }
}

fn le24(b: &[u8]) -> Option<u32> {
    Some(u32::from(*b.first()?) | u32::from(*b.get(1)?) << 8 | u32::from(*b.get(2)?) << 16)
}

/// The RFC's `bool_decoder`. Reads past the end of the partition return zero
/// bytes, so corrupt or truncated streams decode bounded garbage and stop at
/// the (validated) frame dimensions instead of running away.
struct BoolDec<'a> {
    data: &'a [u8],
    pos: usize,
    value: u32,
    range: u32,
    bit_count: u32,
}

impl<'a> BoolDec<'a> {
    fn new(data: &'a [u8]) -> Self {
        let b0 = u32::from(data.first().copied().unwrap_or(0));
        let b1 = u32::from(data.get(1).copied().unwrap_or(0));
        BoolDec {
            data,
            pos: 2,
            value: (b0 << 8) | b1,
            range: 255,
            bit_count: 0,
        }
    }

    /// `read_bool`: one bool coded at probability `prob`/256 of being 0.
    fn bit(&mut self, prob: u8) -> u32 {
        let split = 1 + (((self.range - 1) * u32::from(prob)) >> 8);
        let big_split = split << 8;
        let ret = if self.value >= big_split {
            self.range -= split;
            self.value -= big_split;
            1
        } else {
            self.range = split;
            0
        };
        while self.range < 128 {
            self.value <<= 1;
            self.range <<= 1;
            self.bit_count += 1;
            if self.bit_count == 8 {
                self.bit_count = 0;
                // Feed zeros past end-of-partition.
                self.value |= u32::from(self.data.get(self.pos).copied().unwrap_or(0));
                self.pos = self.pos.saturating_add(1);
            }
        }
        ret
    }

    fn flag(&mut self) -> bool {
        self.bit(128) == 1
    }

    /// `read_literal`: an unsigned `n`-bit value, MSB first, each bit at 1/2.
    fn literal(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit(128);
        }
        v
    }

    /// `bool_maybe_get_int`: flag, then `n`-bit magnitude, then sign.
    fn maybe_signed(&mut self, n: u32) -> i32 {
        if !self.flag() {
            return 0;
        }
        let mag = self.literal(n) as i32;
        if self.flag() {
            -mag
        } else {
            mag
        }
    }

    /// `treed_read` (§8.1): walk `tree` from entry `start`, reading one bool
    /// per interior node with probability `probs[poff + node/2]`. Leaves are
    /// stored negated. Iterations are bounded by the tree size.
    fn tree(&mut self, tree: &[i8], probs: &[u8], poff: usize, start: usize) -> u32 {
        let mut i = start as i32;
        for _ in 0..tree.len() {
            let p = probs.get(poff + (i as usize >> 1)).copied().unwrap_or(128);
            let b = self.bit(p);
            i = i32::from(ag(tree, i as usize + b as usize));
            if i <= 0 {
                return (-i) as u32;
            }
        }
        0
    }
}

/// Inverse Walsh-Hadamard transform for the Y2 block (`vp8_short_inv_walsh4x4_c`).
fn iwht4x4(input: &[i32; 16]) -> [i32; 16] {
    let mut tmp = [0i32; 16];
    for i in 0..4 {
        let a1 = ag(input, i) + ag(input, 12 + i);
        let b1 = ag(input, 4 + i) + ag(input, 8 + i);
        let c1 = ag(input, 4 + i) - ag(input, 8 + i);
        let d1 = ag(input, i) - ag(input, 12 + i);
        aset(&mut tmp, i, a1 + b1);
        aset(&mut tmp, 4 + i, c1 + d1);
        aset(&mut tmp, 8 + i, a1 - b1);
        aset(&mut tmp, 12 + i, d1 - c1);
    }
    let mut out = [0i32; 16];
    for i in 0..4 {
        let base = 4 * i;
        let a1 = ag(&tmp, base) + ag(&tmp, base + 3);
        let b1 = ag(&tmp, base + 1) + ag(&tmp, base + 2);
        let c1 = ag(&tmp, base + 1) - ag(&tmp, base + 2);
        let d1 = ag(&tmp, base) - ag(&tmp, base + 3);
        aset(&mut out, base, (a1 + b1 + 3) >> 3);
        aset(&mut out, base + 1, (c1 + d1 + 3) >> 3);
        aset(&mut out, base + 2, (a1 - b1 + 3) >> 3);
        aset(&mut out, base + 3, (d1 - c1 + 3) >> 3);
    }
    out
}

/// The exact integer inverse DCT (`short_idct4x4llm_c`), computed in i64 so
/// even hostile coefficient values cannot overflow.
fn idct4x4(input: &[i32; 16]) -> [i32; 16] {
    const C1: i64 = 20091; // sqrt(2)*cos(pi/8) - 1, 16-bit fixed point
    const C2: i64 = 35468; // sqrt(2)*sin(pi/8), 16-bit fixed point
    let mut tmp = [0i64; 16];
    for i in 0..4 {
        let i0 = i64::from(ag(input, i));
        let i4 = i64::from(ag(input, 4 + i));
        let i8v = i64::from(ag(input, 8 + i));
        let i12 = i64::from(ag(input, 12 + i));
        let a1 = i0 + i8v;
        let b1 = i0 - i8v;
        let c1 = ((i4 * C2) >> 16) - (i12 + ((i12 * C1) >> 16));
        let d1 = (i4 + ((i4 * C1) >> 16)) + ((i12 * C2) >> 16);
        aset(&mut tmp, i, a1 + d1);
        aset(&mut tmp, 12 + i, a1 - d1);
        aset(&mut tmp, 4 + i, b1 + c1);
        aset(&mut tmp, 8 + i, b1 - c1);
    }
    let mut out = [0i32; 16];
    for i in 0..4 {
        let base = 4 * i;
        let i0 = ag(&tmp, base);
        let i1 = ag(&tmp, base + 1);
        let i2 = ag(&tmp, base + 2);
        let i3 = ag(&tmp, base + 3);
        let a1 = i0 + i2;
        let b1 = i0 - i2;
        let c1 = ((i1 * C2) >> 16) - (i3 + ((i3 * C1) >> 16));
        let d1 = (i1 + ((i1 * C1) >> 16)) + ((i3 * C2) >> 16);
        aset(&mut out, base, ((a1 + d1 + 4) >> 3) as i32);
        aset(&mut out, base + 3, ((a1 - d1 + 4) >> 3) as i32);
        aset(&mut out, base + 1, ((b1 + c1 + 4) >> 3) as i32);
        aset(&mut out, base + 2, ((b1 - c1 + 4) >> 3) as i32);
    }
    out
}

/// One reconstructed plane, padded to whole macroblocks.
struct Plane {
    w: usize,
    h: usize,
    data: Vec<u8>,
}

impl Plane {
    fn new(w: usize, h: usize) -> Option<Plane> {
        let n = w.checked_mul(h)?;
        Some(Plane {
            w,
            h,
            data: vec![0u8; n],
        })
    }

    /// Border-aware read (§12): pixels above the frame read 127, pixels left
    /// of the frame read 129 (the above-left corner counts as "above").
    /// Reads right of the plane clamp to the last column — exactly the
    /// above-right duplication rule for the rightmost macroblock.
    fn px(&self, x: isize, y: isize) -> i32 {
        if y < 0 {
            return 127;
        }
        if x < 0 {
            return 129;
        }
        let xi = (x as usize).min(self.w.saturating_sub(1));
        let yi = (y as usize).min(self.h.saturating_sub(1));
        self.data
            .get(yi * self.w + xi)
            .copied()
            .map(i32::from)
            .unwrap_or(128)
    }

    fn get(&self, x: usize, y: usize) -> i32 {
        self.data
            .get(y * self.w + x)
            .copied()
            .map(i32::from)
            .unwrap_or(0)
    }

    /// Clamped write (§14.5 `clamp255`).
    fn put(&mut self, x: usize, y: usize, v: i32) {
        let idx = y * self.w + x;
        if let Some(slot) = self.data.get_mut(idx) {
            *slot = v.clamp(0, 255) as u8;
        }
    }
}

/// Add an inverse-transformed residual block to the prediction in `plane`.
fn idct_add(plane: &mut Plane, x0: usize, y0: usize, coeffs: &[i32; 16]) {
    if coeffs.iter().all(|&c| c == 0) {
        return; // prediction already in place
    }
    let res = idct4x4(coeffs);
    for r in 0..4 {
        for c in 0..4 {
            let v = plane.get(x0 + c, y0 + r) + ag(&res, 4 * r + c);
            plane.put(x0 + c, y0 + r, v);
        }
    }
}

/// Whole-block DC/V/H/TM prediction for 16x16 luma (`n`=16) or 8x8 chroma
/// (`n`=8), written straight into the plane.
fn predict_full(p: &mut Plane, x0: usize, y0: usize, n: usize, mode: u8) {
    let xi = x0 as isize;
    let yi = y0 as isize;
    match mode {
        1 => {
            // V_PRED: copy the above row (127 when on the top edge).
            for c in 0..n {
                let v = p.px(xi + c as isize, yi - 1);
                for r in 0..n {
                    p.put(x0 + c, y0 + r, v);
                }
            }
        }
        2 => {
            // H_PRED: copy the left column (129 when on the left edge).
            for r in 0..n {
                let v = p.px(xi - 1, yi + r as isize);
                for c in 0..n {
                    p.put(x0 + c, y0 + r, v);
                }
            }
        }
        3 => {
            // TM_PRED: L[r] + A[c] - P, clamped; uses 127/129 off-frame.
            let corner = p.px(xi - 1, yi - 1);
            let mut above = [0i32; 16];
            for c in 0..n {
                aset(&mut above, c, p.px(xi + c as isize, yi - 1));
            }
            for r in 0..n {
                let left = p.px(xi - 1, yi + r as isize);
                for c in 0..n {
                    p.put(x0 + c, y0 + r, left + ag(&above, c) - corner);
                }
            }
        }
        _ => {
            // DC_PRED: average of the available edges; 128 at the frame's
            // top-left corner. Rounding per §12.2.
            let mut sum = 0i32;
            let mut count = 0usize;
            if y0 > 0 {
                for c in 0..n {
                    sum += p.px(xi + c as isize, yi - 1);
                }
                count += n;
            }
            if x0 > 0 {
                for r in 0..n {
                    sum += p.px(xi - 1, yi + r as isize);
                }
                count += n;
            }
            let v = if count == 0 {
                128
            } else {
                let shf = count.trailing_zeros();
                (sum + (1 << (shf - 1))) >> shf
            };
            for r in 0..n {
                for c in 0..n {
                    p.put(x0 + c, y0 + r, v);
                }
            }
        }
    }
}

/// 4x4 B_PRED subblock prediction (§12.3), all ten submodes. `mbx0`/`mby0`
/// are the luma origin of the containing macroblock (needed for the
/// above-right rule of right-edge subblocks 3/7/11/15).
fn predict_subblock(p: &mut Plane, x0: usize, y0: usize, mbx0: usize, mby0: usize, mode: u8) {
    let xi = x0 as isize;
    let yi = y0 as isize;
    // Above row A[0..8] (A[4..8] = above-right), left column L[0..4], corner P.
    let mut av = [0i32; 8];
    for t in 0..4 {
        aset(&mut av, t, p.px(xi + t as isize, yi - 1));
    }
    let right_edge = (x0 - mbx0) / 4 == 3;
    for t in 0..4 {
        let v = if right_edge {
            // Subblocks 3, 7, 11, 15 all use pixels (-1, 16..20) relative to
            // the macroblock; px() duplicates (-1,15) at the right frame edge
            // and yields 127 on the top row (§12.3).
            p.px((mbx0 + 16 + t) as isize, mby0 as isize - 1)
        } else {
            p.px(xi + 4 + t as isize, yi - 1)
        };
        aset(&mut av, 4 + t, v);
    }
    let mut lv = [0i32; 4];
    for t in 0..4 {
        aset(&mut lv, t, p.px(xi - 1, yi + t as isize));
    }
    let corner = p.px(xi - 1, yi - 1);
    // E[9]: L reversed, P, A[0..4] — the "already-constructed edge" (§12.3).
    let ev = [
        ag(&lv, 3),
        ag(&lv, 2),
        ag(&lv, 1),
        ag(&lv, 0),
        corner,
        ag(&av, 0),
        ag(&av, 1),
        ag(&av, 2),
        ag(&av, 3),
    ];

    let avg3 = |x: i32, y: i32, z: i32| (x + y + y + z + 2) >> 2;
    let avg2 = |x: i32, y: i32| (x + y + 1) >> 1;
    // avg3p / avg2p over A (index -1 = P), E, and L.
    let a3 = |i: usize| {
        let prev = if i == 0 { corner } else { ag(&av, i - 1) };
        avg3(prev, ag(&av, i), ag(&av, i + 1))
    };
    let a2 = |i: usize| avg2(ag(&av, i), ag(&av, i + 1));
    let e3 = |i: usize| avg3(ag(&ev, i - 1), ag(&ev, i), ag(&ev, i + 1));
    let e2 = |i: usize| avg2(ag(&ev, i), ag(&ev, i + 1));
    let l3 = |i: usize| avg3(ag(&lv, i - 1), ag(&lv, i), ag(&lv, i + 1));
    let l2 = |i: usize| avg2(ag(&lv, i), ag(&lv, i + 1));

    let mut b = [0i32; 16];
    let set = |arr: &mut [i32; 16], r: usize, c: usize, v: i32| aset(arr, 4 * r + c, v);
    match mode {
        1 => {
            // B_TM_PRED
            for r in 0..4 {
                for c in 0..4 {
                    set(
                        &mut b,
                        r,
                        c,
                        (ag(&lv, r) + ag(&av, c) - corner).clamp(0, 255),
                    );
                }
            }
        }
        2 => {
            // B_VE_PRED: smoothed top row (uses P and above-right A[4]).
            for c in 0..4 {
                let v = a3(c);
                for r in 0..4 {
                    set(&mut b, r, c, v);
                }
            }
        }
        3 => {
            // B_HE_PRED: smoothed left column; bottom row replicates L[3].
            for r in 0..4 {
                let v = if r == 3 {
                    avg3(ag(&lv, 2), ag(&lv, 3), ag(&lv, 3))
                } else if r == 0 {
                    avg3(corner, ag(&lv, 0), ag(&lv, 1))
                } else {
                    l3(r)
                };
                for c in 0..4 {
                    set(&mut b, r, c, v);
                }
            }
        }
        4 => {
            // B_LD_PRED (southwest diagonal).
            set(&mut b, 0, 0, a3(1));
            let v = a3(2);
            set(&mut b, 0, 1, v);
            set(&mut b, 1, 0, v);
            let v = a3(3);
            set(&mut b, 0, 2, v);
            set(&mut b, 1, 1, v);
            set(&mut b, 2, 0, v);
            let v = a3(4);
            set(&mut b, 0, 3, v);
            set(&mut b, 1, 2, v);
            set(&mut b, 2, 1, v);
            set(&mut b, 3, 0, v);
            let v = a3(5);
            set(&mut b, 1, 3, v);
            set(&mut b, 2, 2, v);
            set(&mut b, 3, 1, v);
            let v = a3(6);
            set(&mut b, 2, 3, v);
            set(&mut b, 3, 2, v);
            set(&mut b, 3, 3, avg3(ag(&av, 6), ag(&av, 7), ag(&av, 7)));
        }
        5 => {
            // B_RD_PRED (southeast diagonal).
            set(&mut b, 3, 0, e3(1));
            let v = e3(2);
            set(&mut b, 3, 1, v);
            set(&mut b, 2, 0, v);
            let v = e3(3);
            set(&mut b, 3, 2, v);
            set(&mut b, 2, 1, v);
            set(&mut b, 1, 0, v);
            let v = e3(4);
            set(&mut b, 3, 3, v);
            set(&mut b, 2, 2, v);
            set(&mut b, 1, 1, v);
            set(&mut b, 0, 0, v);
            let v = e3(5);
            set(&mut b, 2, 3, v);
            set(&mut b, 1, 2, v);
            set(&mut b, 0, 1, v);
            let v = e3(6);
            set(&mut b, 1, 3, v);
            set(&mut b, 0, 2, v);
            set(&mut b, 0, 3, e3(7));
        }
        6 => {
            // B_VR_PRED (vertical-right).
            set(&mut b, 3, 0, e3(2));
            set(&mut b, 2, 0, e3(3));
            let v = e3(4);
            set(&mut b, 3, 1, v);
            set(&mut b, 1, 0, v);
            let v = e2(4);
            set(&mut b, 2, 1, v);
            set(&mut b, 0, 0, v);
            let v = e3(5);
            set(&mut b, 3, 2, v);
            set(&mut b, 1, 1, v);
            let v = e2(5);
            set(&mut b, 2, 2, v);
            set(&mut b, 0, 1, v);
            let v = e3(6);
            set(&mut b, 3, 3, v);
            set(&mut b, 1, 2, v);
            let v = e2(6);
            set(&mut b, 2, 3, v);
            set(&mut b, 0, 2, v);
            set(&mut b, 1, 3, e3(7));
            set(&mut b, 0, 3, e2(7));
        }
        7 => {
            // B_VL_PRED (vertical-left).
            set(&mut b, 0, 0, a2(0));
            set(&mut b, 1, 0, a3(1));
            let v = a2(1);
            set(&mut b, 2, 0, v);
            set(&mut b, 0, 1, v);
            let v = a3(2);
            set(&mut b, 1, 1, v);
            set(&mut b, 3, 0, v);
            let v = a2(2);
            set(&mut b, 2, 1, v);
            set(&mut b, 0, 2, v);
            let v = a3(3);
            set(&mut b, 3, 1, v);
            set(&mut b, 1, 2, v);
            let v = a2(3);
            set(&mut b, 2, 2, v);
            set(&mut b, 0, 3, v);
            let v = a3(4);
            set(&mut b, 3, 2, v);
            set(&mut b, 1, 3, v);
            set(&mut b, 2, 3, a3(5));
            set(&mut b, 3, 3, a3(6));
        }
        8 => {
            // B_HD_PRED (horizontal-down).
            set(&mut b, 3, 0, e2(0));
            set(&mut b, 3, 1, e3(1));
            let v = e2(1);
            set(&mut b, 2, 0, v);
            set(&mut b, 3, 2, v);
            let v = e3(2);
            set(&mut b, 2, 1, v);
            set(&mut b, 3, 3, v);
            let v = e2(2);
            set(&mut b, 2, 2, v);
            set(&mut b, 1, 0, v);
            let v = e3(3);
            set(&mut b, 2, 3, v);
            set(&mut b, 1, 1, v);
            let v = e2(3);
            set(&mut b, 1, 2, v);
            set(&mut b, 0, 0, v);
            let v = e3(4);
            set(&mut b, 1, 3, v);
            set(&mut b, 0, 1, v);
            set(&mut b, 0, 2, e3(5));
            set(&mut b, 0, 3, e3(6));
        }
        9 => {
            // B_HU_PRED (horizontal-up).
            set(&mut b, 0, 0, l2(0));
            set(&mut b, 0, 1, l3(1));
            let v = l2(1);
            set(&mut b, 0, 2, v);
            set(&mut b, 1, 0, v);
            let v = l3(2);
            set(&mut b, 0, 3, v);
            set(&mut b, 1, 1, v);
            let v = l2(2);
            set(&mut b, 1, 2, v);
            set(&mut b, 2, 0, v);
            let v = avg3(ag(&lv, 2), ag(&lv, 3), ag(&lv, 3));
            set(&mut b, 1, 3, v);
            set(&mut b, 2, 1, v);
            let v = ag(&lv, 3);
            set(&mut b, 2, 2, v);
            set(&mut b, 2, 3, v);
            set(&mut b, 3, 0, v);
            set(&mut b, 3, 1, v);
            set(&mut b, 3, 2, v);
            set(&mut b, 3, 3, v);
        }
        _ => {
            // B_DC_PRED: average of the 8 above+left pixels, +4 rounding.
            let mut v = 4i32;
            for i in 0..4 {
                v += ag(&av, i) + ag(&lv, i);
            }
            v >>= 3;
            b = [v; 16];
        }
    }
    for r in 0..4 {
        for c in 0..4 {
            p.put(x0 + c, y0 + r, ag(&b, 4 * r + c));
        }
    }
}

/// Decode one 4x4 block's coefficients into `out` (raster order, already
/// dequantized). `plane` selects the probability plane (0 = Y-after-Y2,
/// 1 = Y2, 2 = chroma, 3 = Y-without-Y2); `first` is 1 for plane 0. `ctx0`
/// is the left+above non-zero context (0..=2). Returns 1 if the block has
/// any coefficients (feeds the neighbour context), else 0.
#[allow(clippy::too_many_arguments)]
fn decode_coeffs(
    bd: &mut BoolDec,
    probs: &[u8],
    plane: usize,
    first: usize,
    ctx0: usize,
    dq_dc: i32,
    dq_ac: i32,
    out: &mut [i32; 16],
) -> u8 {
    let mut ctx = ctx0;
    let mut c = first;
    let mut prev_zero = false;
    while c < 16 {
        let band = usize::from(ag(&COEFF_BANDS, c));
        let poff = ((plane * 8 + band) * 3 + ctx) * 11;
        // EOB cannot follow a zero token, so skip the tree's EOB arm then.
        let start = if prev_zero { 2 } else { 0 };
        let token = bd.tree(&COEFF_TREE, probs, poff, start);
        if token == TOKEN_EOB {
            break;
        }
        if token == 0 {
            // DCT_0: value stays zero, context resets, no EOB check next.
            ctx = 0;
            prev_zero = true;
            c += 1;
            continue;
        }
        prev_zero = false;
        let abs_v = if token <= 4 {
            token as i32
        } else {
            // DCT_CAT1..6: base + extra bits, MSB first (§13.2 DCTextra).
            let cat = (token as usize).saturating_sub(5);
            let mut extra = 0i32;
            for &cp in cat_probs(cat) {
                extra = (extra << 1) | bd.bit(cp) as i32;
            }
            ag(&CAT_BASE, cat) + extra
        };
        ctx = if abs_v == 1 { 1 } else { 2 };
        let signed = if bd.flag() { -abs_v } else { abs_v };
        // Dequantize; the reference stores products in a 16-bit short, so
        // reproduce that truncation exactly (§14.1, §20.16).
        let dq = if c == 0 { dq_dc } else { dq_ac };
        let v = signed.wrapping_mul(dq) as i16;
        aset(out, usize::from(ag(&ZIGZAG, c)), i32::from(v));
        c += 1;
    }
    u8::from(c != first)
}

/// The six dequantization factors for one segment (§14.1, dixie `dequant_init`).
#[derive(Clone, Copy, Default)]
struct Dqf {
    y1dc: i32,
    y1ac: i32,
    y2dc: i32,
    y2ac: i32,
    uvdc: i32,
    uvac: i32,
}

fn dc_q(q: i32) -> i32 {
    i32::from(ag(&DC_QLOOKUP, q.clamp(0, 127) as usize))
}

fn ac_q(q: i32) -> i32 {
    i32::from(ag(&AC_QLOOKUP, q.clamp(0, 127) as usize))
}

fn dqf_for(q: i32, deltas: &[i32; 5]) -> Dqf {
    let [ydc_d, y2dc_d, y2ac_d, uvdc_d, uvac_d] = *deltas;
    Dqf {
        y1dc: dc_q(q + ydc_d),
        y1ac: ac_q(q),
        y2dc: dc_q(q + y2dc_d) * 2,
        y2ac: (ac_q(q + y2ac_d) * 155 / 100).max(8),
        uvdc: dc_q(q + uvdc_d).min(132),
        uvac: ac_q(q + uvac_d),
    }
}

/// Per-macroblock prediction record (§11).
struct MbInfo {
    y_mode: u8,
    uv_mode: u8,
    segment: u8,
    skip: bool,
    /// 4x4 submodes; for non-B_PRED macroblocks, the derived constant mode
    /// used only as prediction context for later subblocks (§11.3).
    bmodes: [u8; 16],
}

const B_PRED: u8 = 4;

/// Header-only dimensions of a VP8 key-frame payload.
pub fn dimensions(payload: &[u8]) -> Option<(usize, usize)> {
    let tag = le24(payload.get(0..3)?)?;
    if tag & 1 != 0 {
        return None; // interframe: no dimensions present
    }
    if payload.get(3..6)? != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let w = usize::from(u16::from_le_bytes([
        payload.get(6).copied()?,
        payload.get(7).copied()?,
    ])) & 0x3fff;
    let h = usize::from(u16::from_le_bytes([
        payload.get(8).copied()?,
        payload.get(9).copied()?,
    ])) & 0x3fff;
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

/// Decode a VP8 key frame (the payload of a `VP8 ` WebP chunk) to RGBA.
pub fn decode(payload: &[u8]) -> Option<DecodedImage> {
    let tag = le24(payload.get(0..3)?)?;
    if tag & 1 != 0 {
        return None; // interframe — out of scope for still images
    }
    let version = (tag >> 1) & 7;
    if version > 3 {
        return None; // experimental bitstream
    }
    let part0_len = (tag >> 5) as usize; // 19-bit first-partition size
    let (w, h) = dimensions(payload)?;
    let mb_cols = w.div_ceil(16);
    let mb_rows = h.div_ceil(16);
    let yw = mb_cols.checked_mul(16)?;
    let yh = mb_rows.checked_mul(16)?;
    // The padded reconstruction buffer is the real bound the pixel budget
    // must hold for.
    if yw.checked_mul(yh)? > MAX_PIXELS {
        return None;
    }

    let part0 = payload.get(10..10usize.checked_add(part0_len)?)?;
    let mut d0 = BoolDec::new(part0);

    // §9.2: color space + clamping type. A reserved color space still decodes
    // as BT.601 YCbCr; clamping type only relaxes a requirement we meet.
    let _color_space = d0.flag();
    let _clamping = d0.flag();

    // §9.3: segment-based adjustments.
    let seg_enabled = d0.flag();
    let mut seg_update_map = false;
    let mut seg_abs = false;
    let mut seg_tree_probs = [255u8; 3];
    let mut seg_q = [0i32; 4];
    if seg_enabled {
        seg_update_map = d0.flag();
        let update_data = d0.flag();
        if update_data {
            seg_abs = d0.flag();
            for q in seg_q.iter_mut() {
                *q = d0.maybe_signed(7);
            }
            for _ in 0..4 {
                let _lf_delta = d0.maybe_signed(6); // loop filter unused here
            }
        }
        if seg_update_map {
            for p in seg_tree_probs.iter_mut() {
                *p = if d0.flag() { d0.literal(8) as u8 } else { 255 };
            }
        }
    }

    // §9.4: loop filter parameters — parsed to keep bitstream position, but
    // the filter itself is intentionally not applied (see module docs).
    let _filter_type = d0.flag();
    let _filter_level = d0.literal(6);
    let _sharpness = d0.literal(3);
    if d0.flag() {
        // mode_ref_lf_delta_enabled
        if d0.flag() {
            // mode_ref_lf_delta_update: 4 ref deltas + 4 mode deltas
            for _ in 0..8 {
                let _delta = d0.maybe_signed(6);
            }
        }
    }

    // §9.5: token partition count and sizes (3-byte LE each, after part0).
    let nparts = 1usize << d0.literal(2);
    let sizes_off = 10usize.checked_add(part0_len)?;
    let mut data_off = sizes_off.checked_add(3usize.checked_mul(nparts - 1)?)?;
    let mut partitions: Vec<&[u8]> = Vec::with_capacity(nparts);
    for i in 0..nparts {
        if i + 1 < nparts {
            let so = sizes_off.checked_add(3 * i)?;
            let sz = le24(payload.get(so..so + 3)?)? as usize;
            let end = data_off.checked_add(sz)?;
            partitions.push(payload.get(data_off..end)?);
            data_off = end;
        } else {
            partitions.push(payload.get(data_off..)?);
        }
    }

    // §9.6: dequantization indices.
    let yac_qi = d0.literal(7) as i32;
    let mut q_deltas = [0i32; 5]; // y1dc, y2dc, y2ac, uvdc, uvac
    for d in q_deltas.iter_mut() {
        *d = d0.maybe_signed(4);
    }

    // §9.7/§9.8: on key frames only the refresh-entropy bit is present, and
    // this decoder is single-frame so the value does not matter.
    let _refresh_entropy = d0.flag();

    // §9.9/§13.4: coefficient probability updates over the defaults.
    let mut coeff_probs = DEFAULT_COEFF_PROBS.to_vec();
    for i in 0..coeff_probs.len() {
        if d0.bit(ag(&COEFF_UPDATE_PROBS, i)) == 1 {
            let v = d0.literal(8) as u8;
            aset(&mut coeff_probs, i, v);
        }
    }

    // §9.11: macroblock-level skip flag support.
    let mb_no_skip = d0.flag();
    let prob_skip = if mb_no_skip { d0.literal(8) as u8 } else { 0 };

    let mb_count = mb_cols.checked_mul(mb_rows)?;
    let mut mbs: Vec<MbInfo> = Vec::with_capacity(mb_count);
    let mut above_bm: Vec<[u8; 4]> = vec![[0u8; 4]; mb_cols]; // B_DC borders
    for _mby in 0..mb_rows {
        let mut left_bm = [0u8; 4];
        for mbx in 0..mb_cols {
            let segment = if seg_enabled && seg_update_map {
                // mb_segment_tree with 3 probabilities (§10).
                let p0 = ag(&seg_tree_probs, 0);
                let p1 = ag(&seg_tree_probs, 1);
                let p2 = ag(&seg_tree_probs, 2);
                if d0.bit(p0) == 1 {
                    2 + d0.bit(p2) as u8
                } else {
                    d0.bit(p1) as u8
                }
            } else {
                0
            };
            let skip = mb_no_skip && d0.bit(prob_skip) == 1;
            let y_mode = d0.tree(&KF_YMODE_TREE, &KF_YMODE_PROB, 0, 0) as u8;
            let mut bmodes = [0u8; 16];
            if y_mode == B_PRED {
                for i in 0..16 {
                    let above = if i < 4 {
                        usize::from(ag(
                            above_bm.get(mbx).copied().as_ref().unwrap_or(&[0u8; 4]),
                            i,
                        ))
                    } else {
                        usize::from(ag(&bmodes, i - 4))
                    };
                    let left = if i % 4 == 0 {
                        usize::from(ag(&left_bm, i / 4))
                    } else {
                        usize::from(ag(&bmodes, i - 1))
                    };
                    let poff = (above * 10 + left) * 9;
                    let m = d0.tree(&BMODE_TREE, &KF_BMODE_PROB, poff, 0) as u8;
                    aset(&mut bmodes, i, m);
                }
            } else {
                // Derived context submode for whole-block modes (§11.3 #4).
                let derived = match y_mode {
                    1 => 2, // V_PRED -> B_VE
                    2 => 3, // H_PRED -> B_HE
                    3 => 1, // TM_PRED -> B_TM
                    _ => 0, // DC_PRED -> B_DC
                };
                bmodes = [derived; 16];
            }
            let uv_mode = d0.tree(&UV_MODE_TREE, &KF_UV_MODE_PROB, 0, 0) as u8;
            if let Some(slot) = above_bm.get_mut(mbx) {
                *slot = [
                    ag(&bmodes, 12),
                    ag(&bmodes, 13),
                    ag(&bmodes, 14),
                    ag(&bmodes, 15),
                ];
            }
            left_bm = [
                ag(&bmodes, 3),
                ag(&bmodes, 7),
                ag(&bmodes, 11),
                ag(&bmodes, 15),
            ];
            mbs.push(MbInfo {
                y_mode,
                uv_mode,
                segment,
                skip,
                bmodes,
            });
        }
    }

    // Per-segment dequantization factors (§10, §14.1).
    let mut factors = [Dqf::default(); 4];
    for (s, f) in factors.iter_mut().enumerate() {
        let q = if seg_enabled {
            let sq = ag(&seg_q, s);
            if seg_abs {
                sq
            } else {
                yac_qi + sq
            }
        } else {
            yac_qi
        };
        *f = dqf_for(q, &q_deltas);
    }

    let mut y_plane = Plane::new(yw, yh)?;
    let mut u_plane = Plane::new(mb_cols * 8, mb_rows * 8)?;
    let mut v_plane = Plane::new(mb_cols * 8, mb_rows * 8)?;
    let mut token_bools: Vec<BoolDec> = partitions.iter().map(|p| BoolDec::new(p)).collect();
    // Non-zero contexts: 0..=3 Y columns, 4..=5 U, 6..=7 V, 8 Y2.
    let mut above_ctx: Vec<[u8; 9]> = vec![[0u8; 9]; mb_cols];
    for mby in 0..mb_rows {
        let bd = token_bools.get_mut(mby % nparts)?;
        let mut left_ctx = [0u8; 9];
        for mbx in 0..mb_cols {
            let mb = mbs.get(mby * mb_cols + mbx)?;
            let has_y2 = mb.y_mode != B_PRED;
            let mut coeffs = [[0i32; 16]; 25];
            if mb.skip {
                // §13.1 + tokens.c reset_mb_context: clear Y/U/V contexts;
                // the Y2 context is cleared only when this mode has a Y2
                // block, otherwise it persists to the next Y2 macroblock.
                for k in 0..8 {
                    aset(&mut left_ctx, k, 0);
                    if let Some(a) = above_ctx.get_mut(mbx) {
                        aset(a, k, 0);
                    }
                }
                if has_y2 {
                    aset(&mut left_ctx, 8, 0);
                    if let Some(a) = above_ctx.get_mut(mbx) {
                        aset(a, 8, 0);
                    }
                }
            } else {
                let f = factors
                    .get(usize::from(mb.segment))
                    .copied()
                    .unwrap_or_default();
                if has_y2 {
                    let actx = above_ctx.get(mbx).map(|a| ag(a, 8)).unwrap_or(0);
                    let ctx = usize::from(ag(&left_ctx, 8)) + usize::from(actx);
                    let mut blk = [0i32; 16];
                    let nz = decode_coeffs(bd, &coeff_probs, 1, 0, ctx, f.y2dc, f.y2ac, &mut blk);
                    aset(&mut coeffs, 24, blk);
                    aset(&mut left_ctx, 8, nz);
                    if let Some(a) = above_ctx.get_mut(mbx) {
                        aset(a, 8, nz);
                    }
                }
                let (y_plane_type, y_first) = if has_y2 { (0usize, 1usize) } else { (3, 0) };
                for b in 0..24 {
                    let (ptype, first, dq_dc, dq_ac) = if b < 16 {
                        (y_plane_type, y_first, f.y1dc, f.y1ac)
                    } else {
                        (2, 0, f.uvdc, f.uvac)
                    };
                    let li = usize::from(ag(&LEFT_CTX_IDX, b));
                    let ai = usize::from(ag(&ABOVE_CTX_IDX, b));
                    let actx = above_ctx.get(mbx).map(|a| ag(a, ai)).unwrap_or(0);
                    let ctx = usize::from(ag(&left_ctx, li)) + usize::from(actx);
                    let mut blk = [0i32; 16];
                    let nz =
                        decode_coeffs(bd, &coeff_probs, ptype, first, ctx, dq_dc, dq_ac, &mut blk);
                    aset(&mut coeffs, b, blk);
                    aset(&mut left_ctx, li, nz);
                    if let Some(a) = above_ctx.get_mut(mbx) {
                        aset(a, ai, nz);
                    }
                }
            }

            // §14.2: invert Y2 first and distribute its result as the DC
            // coefficients of the 16 Y subblocks.
            if has_y2 {
                let y2 = coeffs.get(24).copied().unwrap_or([0i32; 16]);
                let dc = iwht4x4(&y2);
                for i in 0..16 {
                    let v = ag(&dc, i);
                    if let Some(blk) = coeffs.get_mut(i) {
                        aset(blk, 0, v);
                    }
                }
            }

            // §12 + §14.5: predict, then add residuals.
            let yx0 = mbx * 16;
            let yy0 = mby * 16;
            if mb.y_mode == B_PRED {
                for b in 0..16 {
                    let sx = yx0 + (b % 4) * 4;
                    let sy = yy0 + (b / 4) * 4;
                    predict_subblock(&mut y_plane, sx, sy, yx0, yy0, ag(&mb.bmodes, b));
                    let blk = coeffs.get(b).copied().unwrap_or([0i32; 16]);
                    idct_add(&mut y_plane, sx, sy, &blk);
                }
            } else {
                predict_full(&mut y_plane, yx0, yy0, 16, mb.y_mode);
                for b in 0..16 {
                    let blk = coeffs.get(b).copied().unwrap_or([0i32; 16]);
                    idct_add(&mut y_plane, yx0 + (b % 4) * 4, yy0 + (b / 4) * 4, &blk);
                }
            }
            let cx0 = mbx * 8;
            let cy0 = mby * 8;
            predict_full(&mut u_plane, cx0, cy0, 8, mb.uv_mode);
            predict_full(&mut v_plane, cx0, cy0, 8, mb.uv_mode);
            for b in 0..4 {
                let bx = cx0 + (b % 2) * 4;
                let by = cy0 + (b / 2) * 4;
                let ublk = coeffs.get(16 + b).copied().unwrap_or([0i32; 16]);
                idct_add(&mut u_plane, bx, by, &ublk);
                let vblk = coeffs.get(20 + b).copied().unwrap_or([0i32; 16]);
                idct_add(&mut v_plane, bx, by, &vblk);
            }
        }
    }

    // VP8 luma/chroma are studio swing (16..235 / 16..240). Use libwebp's
    // exact integer conversion (yuv.h) so lossy WebP renders with the same
    // colors as the reference decoder:
    //   R = clip((19077 y             + 26149 v) >> 8  - 14234) >> 6
    //   G = clip((19077 y -  6419 u - 13320 v) >> 8 +  8708) >> 6
    //   B = clip((19077 y + 33050 u            ) >> 8 - 17685) >> 6
    let mul_hi = |v: i32, coeff: i32| (v * coeff) >> 8;
    let clip8 = |v: i32| (v >> 6).clamp(0, 255) as u8;
    let mut rgba = Vec::with_capacity(w.checked_mul(h)?.checked_mul(4)?);
    for py in 0..h {
        for px in 0..w {
            let yv = y_plane.get(px, py);
            let uv = u_plane.get(px / 2, py / 2);
            let vv = v_plane.get(px / 2, py / 2);
            let r = clip8(mul_hi(yv, 19077) + mul_hi(vv, 26149) - 14234);
            let g = clip8(mul_hi(yv, 19077) - mul_hi(uv, 6419) - mul_hi(vv, 13320) + 8708);
            let b = clip8(mul_hi(yv, 19077) + mul_hi(uv, 33050) - 17685);
            rgba.push(r);
            rgba.push(g);
            rgba.push(b);
            rgba.push(255);
        }
    }
    DecodedImage::new(w, h, rgba)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::{decode, dimensions};

    /// A real 96x64 lossy WebP key frame (photographic content, multiple
    /// token partitions of size 1, B_PRED and 16x16 modes, non-trivial
    /// quantizer) — the raw `VP8 ` chunk payload of a libwebp-encoded file.
    const KF_96X64: [u8; 1526] = [
        0x50, 0x1a, 0x00, 0x9d, 0x01, 0x2a, 0x60, 0x00, 0x40, 0x00, 0x3e, 0x6d, 0x32, 0x95, 0x48,
        0x24, 0x22, 0xa2, 0x21, 0x24, 0x0b, 0x08, 0x80, 0x0d, 0x89, 0x62, 0x00, 0xa7, 0x47, 0x76,
        0xc8, 0xef, 0xd0, 0x79, 0xa2, 0xd9, 0x3b, 0x3c, 0x45, 0x97, 0xea, 0x99, 0x19, 0x73, 0x44,
        0xe7, 0x45, 0xe7, 0xb9, 0xe7, 0xab, 0xbe, 0x93, 0xbd, 0x01, 0xfe, 0x42, 0xd2, 0x6b, 0x87,
        0x58, 0xa3, 0xe9, 0x5c, 0x28, 0xea, 0xe8, 0x80, 0x5f, 0xb7, 0xf0, 0xc7, 0xfa, 0x5d, 0x6b,
        0xed, 0x15, 0xe8, 0x10, 0x3c, 0x5f, 0x93, 0xa9, 0x92, 0xf3, 0xb4, 0x7c, 0x95, 0x8b, 0xca,
        0xf7, 0x6e, 0xc9, 0x62, 0x9b, 0xb4, 0xd7, 0x0c, 0xae, 0xa7, 0x78, 0x76, 0x35, 0xc5, 0x21,
        0x75, 0x2b, 0x0f, 0xbf, 0xe2, 0x63, 0x59, 0x00, 0x9a, 0xb6, 0x94, 0xb1, 0x96, 0x37, 0x9c,
        0x5d, 0xf4, 0x69, 0x85, 0x79, 0x97, 0xad, 0x3a, 0x8e, 0xac, 0xd6, 0x17, 0x60, 0x0e, 0x3e,
        0xad, 0xf3, 0xd5, 0x14, 0xda, 0xa2, 0x05, 0x50, 0xda, 0x93, 0x5c, 0xbe, 0x89, 0xda, 0xd2,
        0x96, 0x5e, 0x4c, 0xef, 0x68, 0x65, 0x28, 0x70, 0xc6, 0x4c, 0xbd, 0x8f, 0x86, 0x42, 0xf3,
        0xc1, 0x04, 0x5b, 0x2b, 0x27, 0xe1, 0xf6, 0x75, 0x8e, 0x15, 0x8b, 0xfb, 0xb5, 0x77, 0x8a,
        0x6c, 0xd7, 0xf2, 0x7a, 0xc2, 0xc8, 0x55, 0xc0, 0xe4, 0xbf, 0xab, 0x0e, 0x8f, 0x61, 0x9a,
        0x26, 0x24, 0x4c, 0x81, 0xd9, 0x4a, 0x2d, 0x9e, 0xd7, 0x3b, 0xd6, 0x3b, 0x03, 0x98, 0x66,
        0xfa, 0xd7, 0x9c, 0xeb, 0xe5, 0xc4, 0x75, 0x43, 0x08, 0x00, 0xfe, 0xb5, 0x67, 0xf6, 0xe7,
        0x05, 0xd1, 0x0b, 0x97, 0x6f, 0x09, 0xd6, 0xad, 0x7d, 0xe2, 0x59, 0xd2, 0x7d, 0x12, 0x0b,
        0x8b, 0x43, 0xb6, 0xe6, 0x2e, 0x49, 0x34, 0x6e, 0x0c, 0x60, 0x7f, 0xf9, 0xbf, 0xd2, 0x57,
        0x96, 0xf8, 0x6e, 0x46, 0xc1, 0x40, 0x7f, 0xf3, 0xae, 0x96, 0x1c, 0xc3, 0x08, 0xe0, 0xcf,
        0x2d, 0xcb, 0x8a, 0xc6, 0x7b, 0x03, 0x97, 0xfd, 0xa0, 0xad, 0xbd, 0x73, 0xd7, 0x21, 0xeb,
        0x71, 0x91, 0xd9, 0x89, 0x96, 0xa0, 0x2f, 0x33, 0xc8, 0xb6, 0xdd, 0x11, 0xa1, 0x05, 0x9e,
        0x53, 0x36, 0x0c, 0x3e, 0x75, 0x94, 0x17, 0xd8, 0xc0, 0xa1, 0x56, 0x42, 0x93, 0x43, 0x8d,
        0x29, 0x4f, 0x15, 0x12, 0x78, 0x1f, 0xf9, 0x5c, 0xca, 0xe1, 0x0b, 0xb4, 0x21, 0xf3, 0x28,
        0x16, 0x68, 0x9d, 0x25, 0x47, 0xa3, 0xfd, 0xed, 0x5d, 0x32, 0x49, 0xb3, 0x4e, 0x76, 0xa8,
        0x61, 0xad, 0x38, 0x97, 0x99, 0xf5, 0xd9, 0x79, 0xe3, 0xec, 0xb9, 0x05, 0x8a, 0xdc, 0x9d,
        0xf3, 0x3d, 0xfe, 0x4d, 0x36, 0xe4, 0xa1, 0x37, 0x13, 0x9d, 0x1c, 0xd7, 0x95, 0x19, 0xca,
        0x94, 0x24, 0xa2, 0xf1, 0xfb, 0x2c, 0xfe, 0x16, 0xda, 0xac, 0x9e, 0xb5, 0x70, 0x31, 0xf5,
        0x98, 0xb3, 0x82, 0x33, 0x20, 0x5f, 0xaa, 0x9a, 0x9b, 0x28, 0xfa, 0x48, 0xe3, 0xac, 0x70,
        0xe2, 0x7c, 0x5d, 0x0e, 0x9f, 0x63, 0xd1, 0xfd, 0xd7, 0x45, 0x14, 0x99, 0xe8, 0x4a, 0x42,
        0xe1, 0x7c, 0xd7, 0xcf, 0x63, 0x8f, 0xca, 0x44, 0xbb, 0xdf, 0xfd, 0xd6, 0xa3, 0xd9, 0xd4,
        0x9e, 0xc8, 0x5c, 0xfe, 0xb7, 0xa9, 0x1c, 0x6c, 0x2a, 0xd0, 0xbb, 0x84, 0x29, 0x8e, 0x9d,
        0xdd, 0x49, 0x24, 0x25, 0x69, 0xe4, 0xae, 0x85, 0x00, 0xfa, 0x1c, 0xb1, 0xc1, 0x97, 0x54,
        0x6c, 0x87, 0x40, 0x6b, 0x8e, 0x30, 0x52, 0x38, 0xb3, 0xa9, 0x67, 0xda, 0xd5, 0x63, 0x1a,
        0xd4, 0xbd, 0x0e, 0x7f, 0x55, 0x47, 0x60, 0xea, 0x58, 0xd0, 0x22, 0x44, 0xff, 0x62, 0x0f,
        0x13, 0xf9, 0x70, 0x04, 0xbf, 0xe1, 0x5e, 0x8f, 0xdd, 0xa2, 0x38, 0x10, 0x0c, 0xdb, 0x6b,
        0xd1, 0xae, 0x91, 0x3c, 0x6a, 0xb4, 0x6c, 0x3a, 0x87, 0xf0, 0xfd, 0xdc, 0xf2, 0x50, 0x48,
        0x09, 0x34, 0x34, 0x51, 0x51, 0x5d, 0x8b, 0x1e, 0x89, 0xd0, 0x87, 0x0c, 0x3c, 0xf6, 0x3e,
        0x3f, 0x7f, 0xfe, 0x7c, 0xf1, 0x53, 0xcc, 0x3a, 0x56, 0x71, 0x77, 0x0e, 0xad, 0x99, 0xfe,
        0x2d, 0x6a, 0x83, 0xad, 0x8b, 0x41, 0x3e, 0x45, 0x58, 0x8e, 0x66, 0x84, 0x04, 0x26, 0xe9,
        0xb9, 0x3e, 0xc5, 0x20, 0xdb, 0xa1, 0x57, 0x05, 0x5a, 0xb7, 0xbc, 0x15, 0xcf, 0xd4, 0x7d,
        0x6e, 0x9c, 0x0c, 0x8d, 0xb7, 0x90, 0xd7, 0x60, 0x85, 0x81, 0x74, 0xfb, 0x49, 0x38, 0x9b,
        0x30, 0xf1, 0x73, 0xc9, 0x63, 0x8f, 0xdb, 0x4c, 0x13, 0x44, 0x52, 0xac, 0x34, 0x22, 0xa9,
        0x73, 0x38, 0x14, 0xc3, 0xcf, 0xd2, 0xa3, 0xa1, 0x72, 0xb7, 0x01, 0x30, 0xd9, 0xf1, 0x64,
        0x78, 0x75, 0x69, 0xf0, 0x34, 0xb1, 0x8b, 0xb6, 0xfa, 0xe1, 0x75, 0x7b, 0xfd, 0xb7, 0xe6,
        0xc8, 0x02, 0xf4, 0x20, 0x40, 0xbb, 0x6c, 0xf6, 0xe2, 0x26, 0x27, 0x4b, 0xc7, 0x94, 0xee,
        0xe9, 0x9d, 0xac, 0x22, 0x45, 0xcd, 0x01, 0x2e, 0x9f, 0x07, 0x66, 0xb9, 0xaf, 0xc8, 0x0d,
        0x47, 0xa7, 0xeb, 0x29, 0x88, 0x89, 0x4a, 0x17, 0x1e, 0x3e, 0xcf, 0x68, 0xfc, 0x40, 0x18,
        0x92, 0xa2, 0x4f, 0x15, 0x5e, 0xbd, 0x0d, 0x59, 0xf3, 0x87, 0x2d, 0x19, 0x55, 0xcb, 0xcc,
        0x5e, 0xe2, 0x11, 0x2e, 0xb8, 0x6e, 0xde, 0x8b, 0xa0, 0x7c, 0x58, 0x5c, 0xb9, 0x44, 0x51,
        0x1d, 0xb3, 0xd8, 0x4e, 0xf0, 0xf1, 0xd3, 0x76, 0x45, 0xc2, 0x40, 0xa9, 0x58, 0x7a, 0xdc,
        0xda, 0x6b, 0xcf, 0x13, 0x3d, 0x8a, 0x7e, 0xd1, 0x5d, 0xe5, 0x2f, 0x7c, 0x7d, 0xd9, 0x8e,
        0x81, 0x5d, 0x5c, 0xd9, 0x4c, 0x7b, 0xf1, 0xea, 0xf5, 0x61, 0x2e, 0x00, 0xe8, 0xf7, 0xa9,
        0x45, 0xcb, 0x91, 0x32, 0xd3, 0xf1, 0xd5, 0xe6, 0x8f, 0xfc, 0xf6, 0x8d, 0xd5, 0x9c, 0x20,
        0x1d, 0x30, 0x93, 0x37, 0x6e, 0xf0, 0x53, 0xde, 0xfc, 0x3d, 0xd5, 0x1b, 0x2f, 0x84, 0x97,
        0x79, 0x40, 0xa2, 0xf7, 0x75, 0xc4, 0xfc, 0x4b, 0xb7, 0xc9, 0x62, 0x82, 0x68, 0x14, 0xe8,
        0x3b, 0x10, 0xd9, 0xfc, 0x94, 0x65, 0xcc, 0x29, 0x4f, 0xe0, 0x99, 0x31, 0x7d, 0x8a, 0x69,
        0xb2, 0x04, 0xa7, 0x33, 0xd8, 0x89, 0x5d, 0xcb, 0xcb, 0x9b, 0x2f, 0xef, 0xe8, 0x24, 0xd8,
        0x2a, 0x97, 0xc9, 0x17, 0x9f, 0x5f, 0xe6, 0x0f, 0x33, 0x3b, 0x06, 0xf1, 0x3b, 0xd5, 0x7e,
        0x54, 0x88, 0x4b, 0x0f, 0xca, 0x01, 0x4d, 0xf7, 0xfe, 0x1f, 0x66, 0x33, 0xc6, 0x53, 0xe4,
        0xfc, 0xf2, 0x1a, 0x48, 0x4b, 0x61, 0xa2, 0xa2, 0x73, 0x00, 0x1f, 0xc6, 0xa7, 0xe0, 0x19,
        0x29, 0x2b, 0xab, 0x70, 0xa0, 0xd0, 0x81, 0x4a, 0x01, 0xb6, 0x14, 0x34, 0x00, 0xcd, 0xcb,
        0x3d, 0xeb, 0xe2, 0xe3, 0x69, 0xfe, 0xeb, 0x94, 0x26, 0xae, 0x17, 0xc0, 0x1a, 0x8d, 0x7a,
        0xb2, 0x46, 0x6f, 0x88, 0xb8, 0x85, 0xda, 0x5d, 0x4b, 0xaa, 0xc0, 0xd7, 0xfc, 0x18, 0x0d,
        0x02, 0x96, 0x26, 0x40, 0xdf, 0x08, 0xfd, 0x97, 0xb5, 0xa7, 0x67, 0x80, 0xf6, 0x4c, 0x41,
        0x22, 0xc8, 0x93, 0x5f, 0x19, 0x55, 0x29, 0x2b, 0xb5, 0x14, 0x2e, 0xd0, 0x6a, 0x09, 0x32,
        0x07, 0x83, 0x94, 0x74, 0x02, 0x7a, 0xa2, 0xf4, 0xcc, 0xe3, 0x0b, 0xbc, 0x4b, 0xd3, 0x52,
        0xa7, 0x4b, 0x4b, 0x4a, 0x80, 0x49, 0x48, 0x92, 0x24, 0xc8, 0x1a, 0x54, 0xb5, 0xd5, 0xc5,
        0x05, 0x03, 0x2e, 0xb0, 0x22, 0x3a, 0xd9, 0xa6, 0xc4, 0x20, 0xef, 0x0a, 0xca, 0x71, 0xf9,
        0x3d, 0x46, 0x1e, 0xc1, 0x45, 0x5e, 0xdc, 0x5f, 0x70, 0x3f, 0x56, 0x8b, 0x83, 0xa3, 0x3b,
        0x95, 0x3e, 0xec, 0x54, 0x40, 0xbc, 0xfc, 0xfb, 0x50, 0x65, 0xaf, 0xfc, 0x40, 0xa4, 0x6a,
        0xb6, 0x9c, 0xea, 0xcf, 0x49, 0xdd, 0x5f, 0x53, 0xf0, 0x70, 0x4e, 0x57, 0xc7, 0x06, 0x02,
        0xad, 0xa1, 0x66, 0x47, 0xfe, 0x8c, 0x29, 0x81, 0xdc, 0xe3, 0x7a, 0xaf, 0x57, 0xeb, 0xf9,
        0xf5, 0x7c, 0xde, 0xf6, 0x72, 0x4b, 0xc0, 0xb9, 0xc0, 0x0e, 0x72, 0xa5, 0xc7, 0xdf, 0x91,
        0xa3, 0x4c, 0xbb, 0x41, 0x0e, 0xf7, 0xc9, 0x3c, 0xfa, 0x68, 0xc5, 0x54, 0xbb, 0xdb, 0x6e,
        0xbd, 0x9a, 0x4b, 0x8c, 0x20, 0x96, 0x04, 0xe6, 0x22, 0x19, 0x6c, 0xa7, 0xcd, 0x4a, 0xfa,
        0xae, 0x72, 0xa8, 0x46, 0x25, 0x10, 0x06, 0x8e, 0xe7, 0x7c, 0x26, 0x27, 0xfc, 0xf3, 0xb9,
        0xe3, 0xc9, 0x25, 0x38, 0x48, 0xaf, 0x9f, 0x1b, 0x1e, 0x75, 0xc9, 0x74, 0x06, 0x79, 0x00,
        0x4f, 0x7b, 0xf6, 0x89, 0x5b, 0x4b, 0xbc, 0x91, 0x56, 0x85, 0xd9, 0x95, 0xd8, 0x6d, 0x3b,
        0xee, 0xd3, 0x10, 0x42, 0x09, 0xa4, 0x8b, 0x31, 0x11, 0xdd, 0xfc, 0x6f, 0x51, 0x01, 0x80,
        0x24, 0x34, 0x04, 0x52, 0x4c, 0xb8, 0x6a, 0x05, 0xf4, 0xf6, 0xc9, 0xf0, 0x8f, 0xd6, 0x72,
        0x3f, 0xb5, 0x34, 0x8e, 0x5a, 0xc2, 0x0e, 0xf2, 0xc7, 0x70, 0x6f, 0xf0, 0x91, 0xe7, 0x4d,
        0x71, 0x3a, 0xa9, 0x8e, 0x73, 0x66, 0xf8, 0x01, 0x5c, 0xbe, 0x7b, 0xaf, 0x2d, 0xc6, 0x73,
        0x77, 0x82, 0x0a, 0xf8, 0x71, 0x73, 0xd2, 0x09, 0x37, 0x3d, 0xf8, 0xd2, 0x10, 0xff, 0x80,
        0x21, 0x22, 0xdd, 0xd3, 0x26, 0x03, 0xb4, 0xc0, 0x10, 0x49, 0xf8, 0x15, 0xde, 0x95, 0x1f,
        0x40, 0x1c, 0xde, 0xb7, 0x84, 0x6e, 0xb4, 0x74, 0x7b, 0xbf, 0x48, 0x6f, 0x32, 0x68, 0x4f,
        0x9a, 0x6a, 0xf8, 0xce, 0x8a, 0x5c, 0x04, 0xf8, 0xfb, 0x73, 0xbd, 0x26, 0x29, 0xb1, 0x42,
        0xde, 0x9a, 0xb6, 0xd5, 0xb8, 0xc6, 0x38, 0x41, 0x4a, 0xed, 0xf8, 0x4a, 0x31, 0xee, 0xef,
        0x9f, 0x9d, 0x89, 0x17, 0xae, 0x77, 0xcc, 0x76, 0xf8, 0xc0, 0x08, 0xf5, 0x5f, 0x0a, 0xdf,
        0xe0, 0x01, 0xae, 0x37, 0xa1, 0xea, 0x76, 0x6e, 0x84, 0x61, 0x45, 0x0f, 0xfe, 0x73, 0x14,
        0xa9, 0xdf, 0x43, 0xae, 0x05, 0x12, 0x6a, 0x6f, 0x63, 0x8f, 0x10, 0x5e, 0x3b, 0xf1, 0xc6,
        0xcc, 0x7d, 0x36, 0xb2, 0x49, 0xbc, 0xbe, 0x81, 0x23, 0xa6, 0xb9, 0x11, 0xd9, 0xfe, 0xc8,
        0x05, 0x73, 0xe4, 0xc5, 0x55, 0xe2, 0xbe, 0x19, 0x04, 0x13, 0x37, 0x00, 0xb5, 0x7f, 0x84,
        0x4b, 0x46, 0xb5, 0xe8, 0xf6, 0x9d, 0x45, 0x17, 0x3d, 0x62, 0x6f, 0xd7, 0xab, 0x72, 0x1e,
        0xe8, 0xb2, 0x9d, 0x2a, 0x4b, 0x01, 0x8e, 0xc8, 0x67, 0x56, 0xfe, 0x37, 0xe3, 0x67, 0xd7,
        0xa5, 0xe1, 0xb8, 0xb9, 0xde, 0xa4, 0x2a, 0x9f, 0xa0, 0xb7, 0x19, 0x35, 0xc1, 0x1b, 0x0a,
        0xaf, 0x55, 0x5a, 0xcf, 0x70, 0xca, 0x04, 0x87, 0x29, 0x1d, 0x8e, 0xeb, 0x0f, 0xca, 0x9d,
        0x24, 0x36, 0xc1, 0xc7, 0x93, 0x53, 0x65, 0x57, 0xb4, 0x63, 0x2b, 0x17, 0x0d, 0x2a, 0xdb,
        0x29, 0x55, 0xf8, 0x5d, 0x40, 0x3c, 0xef, 0x31, 0xcf, 0x0e, 0x0c, 0x49, 0x26, 0x51, 0xab,
        0xf6, 0x90, 0x07, 0x30, 0x92, 0x6e, 0x09, 0xa0, 0x8a, 0xe7, 0x3b, 0x26, 0xaa, 0x52, 0x40,
        0x84, 0x13, 0xd1, 0x54, 0xf1, 0x5c, 0xb5, 0xfe, 0x32, 0x3b, 0xf4, 0x44, 0xe8, 0x47, 0x19,
        0xa0, 0xec, 0x98, 0x19, 0x30, 0xc8, 0x00, 0xbc, 0x2a, 0x22, 0x20, 0xd0, 0x48, 0xb9, 0xb5,
        0x5b, 0x98, 0xef, 0x44, 0x4d, 0xb0, 0xdf, 0x53, 0x94, 0x6e, 0x81, 0xa7, 0x09, 0xff, 0x66,
        0x7e, 0xa4, 0xb8, 0xa5, 0xf0, 0x08, 0x0d, 0x9d, 0x63, 0x60, 0x00,
    ];

    /// A second real key frame, 48x32, single token partition.
    const KF_48X32: [u8; 400] = [
        0x70, 0x09, 0x00, 0x9d, 0x01, 0x2a, 0x30, 0x00, 0x20, 0x00, 0x3e, 0x9d, 0x42, 0x9b, 0x49,
        0x25, 0xa3, 0xa2, 0xa1, 0x25, 0x6e, 0x60, 0xb0, 0x13, 0x89, 0x68, 0x00, 0x9d, 0x32, 0x84,
        0x77, 0xa4, 0x81, 0x2a, 0x4c, 0x30, 0x38, 0x1b, 0xe1, 0x59, 0xb8, 0xc1, 0x58, 0x8d, 0xa2,
        0x16, 0x75, 0xf0, 0xaf, 0xdc, 0x2d, 0x5a, 0x1e, 0x14, 0x83, 0x95, 0xde, 0xd4, 0x38, 0x60,
        0x5b, 0x84, 0x93, 0x70, 0xe8, 0xa3, 0x76, 0xb0, 0x8c, 0x17, 0x3a, 0xa8, 0x44, 0x17, 0xf9,
        0xed, 0x4e, 0x0c, 0xbc, 0x40, 0x30, 0x4f, 0xe0, 0xf8, 0x00, 0xfe, 0xd7, 0x2f, 0x4a, 0x94,
        0xd2, 0x6a, 0x48, 0xa6, 0xf7, 0x81, 0x7b, 0x7d, 0x23, 0x25, 0x9e, 0x6a, 0x17, 0xd3, 0x91,
        0xde, 0xe9, 0xf3, 0x7f, 0x28, 0x13, 0x0b, 0xc5, 0x31, 0xe8, 0xc6, 0xdc, 0x5e, 0x9c, 0x55,
        0x35, 0xc4, 0xff, 0xf8, 0x86, 0xec, 0x63, 0xd7, 0x87, 0xec, 0x7b, 0x9f, 0xfc, 0x56, 0xa7,
        0x27, 0xd7, 0x27, 0xe5, 0x22, 0x2f, 0x70, 0x39, 0x6b, 0x62, 0xb4, 0xc0, 0xc5, 0x89, 0x2a,
        0xdf, 0x23, 0xdb, 0x28, 0x95, 0x9e, 0xd0, 0x1d, 0x66, 0x54, 0xaf, 0x40, 0x66, 0x6c, 0x90,
        0x45, 0xb2, 0x3e, 0xd1, 0xcd, 0x30, 0xdb, 0xa1, 0xf3, 0x29, 0x15, 0xa8, 0x2e, 0x08, 0xaf,
        0xf7, 0xdc, 0xae, 0xdd, 0x54, 0x66, 0x17, 0xea, 0x6c, 0xb7, 0x09, 0x3f, 0xfb, 0x3c, 0x7a,
        0x67, 0x6d, 0xfe, 0x0c, 0xe6, 0xc1, 0x60, 0x44, 0xf1, 0x1a, 0x8c, 0xc3, 0x47, 0xb2, 0x60,
        0x3c, 0x08, 0xbe, 0x35, 0xc1, 0xd4, 0xed, 0x28, 0xbf, 0xaa, 0xdd, 0x3e, 0x41, 0xde, 0x89,
        0x39, 0x50, 0x39, 0xb1, 0x86, 0xc5, 0x97, 0x55, 0x1b, 0x7b, 0x26, 0xb2, 0x97, 0x08, 0xc1,
        0x8a, 0x98, 0xd3, 0x78, 0x7d, 0x01, 0x1b, 0xaa, 0x0a, 0x8c, 0x3d, 0x31, 0xc0, 0xa1, 0x51,
        0xe5, 0x32, 0xf6, 0x4f, 0xf0, 0x10, 0xfe, 0x14, 0x11, 0x60, 0xe0, 0x66, 0x01, 0x17, 0x08,
        0x3c, 0xfa, 0x7d, 0xef, 0xfa, 0xd1, 0xc3, 0x94, 0x89, 0x24, 0x8c, 0x24, 0x3f, 0xf2, 0x35,
        0xf1, 0xac, 0xae, 0x06, 0xc2, 0x85, 0x96, 0x67, 0x85, 0x0c, 0xae, 0xf7, 0x21, 0x91, 0xd0,
        0x26, 0x2e, 0xbd, 0x1c, 0x50, 0xbc, 0x09, 0x37, 0xa5, 0x2f, 0x5f, 0x98, 0x21, 0xd9, 0x8c,
        0xc7, 0x9f, 0x01, 0x91, 0x7d, 0x0c, 0x02, 0xa0, 0x81, 0x50, 0x8b, 0xf8, 0x6b, 0xca, 0xaf,
        0x31, 0xa7, 0x7a, 0xda, 0xae, 0xa3, 0xba, 0x54, 0x11, 0x18, 0x82, 0xc7, 0x28, 0x26, 0xca,
        0x00, 0x56, 0x4e, 0x27, 0x47, 0xa5, 0x34, 0x3b, 0x14, 0xf4, 0x5d, 0x76, 0xe9, 0xa4, 0x75,
        0xeb, 0x79, 0x0b, 0xb4, 0xe1, 0x81, 0x73, 0x77, 0xac, 0x72, 0x50, 0xa9, 0x51, 0x7f, 0x4b,
        0xe4, 0x85, 0x05, 0x87, 0x76, 0x5e, 0x9d, 0xeb, 0xba, 0x6d, 0x4a, 0x4d, 0x07, 0x3e, 0x92,
        0x2a, 0x7e, 0xa3, 0x08, 0x8f, 0x7f, 0xb7, 0x31, 0x80, 0x00,
    ];

    /// A synthetic 10-byte uncompressed key-frame header.
    fn synth_header(w: u16, h: u16, part0: u32) -> Vec<u8> {
        let tag = part0 << 5; // key frame bit 0, version 0, show_frame 0
        vec![
            (tag & 0xff) as u8,
            ((tag >> 8) & 0xff) as u8,
            ((tag >> 16) & 0xff) as u8,
            0x9d,
            0x01,
            0x2a,
            (w & 0xff) as u8,
            (w >> 8) as u8,
            (h & 0xff) as u8,
            (h >> 8) as u8,
        ]
    }

    #[test]
    fn hostile_inputs_return_none_fast() {
        assert_eq!(decode(&[]), None);
        for n in [1usize, 3, 9, 10, 40] {
            assert_eq!(decode(&KF_96X64[..n]), None, "truncated at {n} bytes");
        }
        // Random-ish bytes behind a valid start code, with a declared first
        // partition larger than the data: structurally malformed -> None.
        let mut junk = synth_header(64, 48, 4096);
        let mut state = 0x1234_5678u32;
        for _ in 0..64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            junk.push((state >> 24) as u8);
        }
        assert_eq!(decode(&junk), None);
        // Random-ish bytes that DO fit the declared partition layout must
        // terminate promptly without panicking, whatever they decode to.
        let mut junk2 = synth_header(16, 16, 8);
        let mut state = 0xdead_beefu32;
        for _ in 0..200 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            junk2.push((state >> 24) as u8);
        }
        let _ = decode(&junk2);
        // Interframe bit set -> None.
        let mut inter = synth_header(16, 16, 8);
        inter[0] |= 1;
        assert_eq!(decode(&inter), None);
    }

    #[test]
    fn dimensions_parse_from_header() {
        assert_eq!(dimensions(&synth_header(1280, 720, 0)), Some((1280, 720)));
        assert_eq!(dimensions(&synth_header(1, 1, 0)), Some((1, 1)));
        assert_eq!(dimensions(&KF_96X64), Some((96, 64)));
        assert_eq!(dimensions(&KF_48X32), Some((48, 32)));
        assert_eq!(dimensions(&synth_header(0, 16, 0)), None);
        assert_eq!(dimensions(&KF_96X64[..9]), None);
    }

    #[test]
    fn decodes_real_keyframes_to_plausible_pixels() {
        for (bytes, w, h) in [(&KF_96X64[..], 96usize, 64usize), (&KF_48X32[..], 48, 32)] {
            let img = decode(bytes).expect("real key frame must decode");
            assert_eq!((img.width, img.height), (w, h));
            assert_eq!(img.rgba.len(), w * h * 4);
            let mut min = [255u8; 3];
            let mut max = [0u8; 3];
            let mut luma_sum = 0u64;
            for px in img.rgba.chunks_exact(4) {
                for c in 0..3 {
                    min[c] = min[c].min(px[c]);
                    max[c] = max[c].max(px[c]);
                }
                assert_eq!(px[3], 255, "opaque alpha");
                luma_sum += (u64::from(px[0]) + u64::from(px[1]) + u64::from(px[2])) / 3;
            }
            let spread: i32 = (0..3)
                .map(|c| i32::from(max[c]) - i32::from(min[c]))
                .max()
                .unwrap_or(0);
            assert!(spread > 64, "photo must not decode flat (spread {spread})");
            let mean = luma_sum / (w as u64 * h as u64);
            assert!(
                (20..=235).contains(&mean),
                "mean luma {mean} outside plausible photographic range"
            );
        }
    }

    /// Reference per-row luma sums from LIBWEBP decoding the IDENTICAL
    /// bytes (Pillow 12.3 / bundled libwebp; tools/vp8_ref_rows.py emits
    /// them). Our decoder skips the loop filter and fancy chroma
    /// upsampling, so rows are close but not byte-exact: the whole-image
    /// mean |luma delta| vs libwebp measures 0.292 (96x64) / 0.418 (48x32).
    /// The assertion bounds each ROW's mean per-pixel luma deviation to
    /// <= 3.0 against the reference vector — tight enough that a wrong
    /// predictor, dequant table, IDCT, or YUV matrix fails immediately
    /// (those produce row errors of tens of luma levels), while the
    /// documented no-loop-filter gap passes.
    const REF_ROW_LUMA_96X64: [u32; 64] = [
        21552, 21329, 21209, 21160, 21342, 21201, 21187, 21251, 21819, 22081, 21698, 20307, 17748,
        13983, 11132, 10318, 9824, 9376, 9008, 8777, 8598, 8249, 7753, 7514, 7040, 6695, 6283,
        5982, 6112, 5764, 5555, 5447, 5313, 5464, 5150, 5219, 5227, 5151, 4918, 4869, 4650, 4912,
        4918, 4528, 4268, 4070, 4101, 3729, 3828, 3663, 3644, 3374, 3209, 3189, 2737, 2402, 2764,
        3773, 4331, 5009, 6158, 6357, 5334, 4025,
    ];
    const REF_ROW_LUMA_48X32: [u32; 32] = [
        10655, 10656, 10560, 10629, 10944, 10434, 7738, 5237, 4793, 4474, 4207, 3810, 3401, 3170,
        2947, 2711, 2693, 2657, 2600, 2431, 2442, 2393, 2066, 2049, 1833, 1751, 1604, 1322, 1510,
        2335, 3090, 2526,
    ];

    #[test]
    fn decode_matches_libwebp_reference_rows() {
        for (bytes, w, _h, reference) in [
            (&KF_96X64[..], 96usize, 64usize, &REF_ROW_LUMA_96X64[..]),
            (&KF_48X32[..], 48, 32, &REF_ROW_LUMA_48X32[..]),
        ] {
            let img = decode(bytes).expect("real key frame must decode");
            for (y, want) in reference.iter().enumerate() {
                let mut got = 0u32;
                for x in 0..w {
                    let i = (y * w + x) * 4;
                    let (r, g, b) = (
                        u32::from(img.rgba[i]),
                        u32::from(img.rgba[i + 1]),
                        u32::from(img.rgba[i + 2]),
                    );
                    got += (r * 299 + g * 587 + b * 114) / 1000;
                }
                let per_px = (i64::from(got) - i64::from(*want)).abs() as f64 / w as f64;
                assert!(
                    per_px <= 3.0,
                    "row {y}: per-pixel luma deviation {per_px:.2} vs libwebp (got {got}, want {want}) — decode diverges beyond the documented no-loop-filter gap"
                );
            }
        }
    }
}
