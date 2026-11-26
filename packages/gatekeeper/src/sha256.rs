//! SHA-256 on the platform SDK kernel (`ferrite_app::crypto::sha256`).
//!
//! Only `ferrite_app::crypto::sha256` is named. The SDK exports no incremental
//! hasher, no length constants and no hex encoder under a name every build of
//! it shares, and all three are a few lines of pure code, so they live here
//! and this package builds against any `ferrite-app` that can hash.
//!
//! The NIST vectors in the test module below run against whichever
//! `ferrite-app` the consuming app links, so each vendored copy proves its own
//! SDK computes SHA-256 correctly.

/// SHA-256 block size in bytes (512 bits). Also the HMAC block size.
pub const BLOCK_LEN: usize = 64;

/// SHA-256 digest size in bytes.
pub const DIGEST_LEN: usize = 32;

/// One-shot SHA-256 over `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    ferrite_app::crypto::sha256(data)
}

/// SHA-256 over the concatenation of `parts`. `sha256_concat(&[a, b])` equals
/// `sha256(&[a, b].concat())` for all inputs; the split points are invisible to
/// the digest, so callers that need domain separation must encode it
/// explicitly (length prefixes or tags).
///
/// The parts are joined into one buffer because the SDK's digest is one-shot.
/// The callers hash sharing descriptors and action bodies, which are
/// kilobytes, so the copy is cheap beside the hash itself.
#[must_use]
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    sha256(&parts.concat())
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn nist_empty_string_vector() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nist_abc_vector() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn nist_two_block_vector() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            to_hex(&sha256(msg)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn nist_million_a_vector_in_parts() {
        // A thousand 1000-byte parts, which is not a multiple of the 64-byte
        // block size, through the multi-part entry point.
        let chunk = [b'a'; 1000];
        let parts: Vec<&[u8]> = (0..1000).map(|_| &chunk[..]).collect();
        assert_eq!(
            to_hex(&sha256_concat(&parts)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn concat_matches_joined_input() {
        let a = b"the quick brown fox ".to_vec();
        let b = vec![0xffu8; 130];
        let c = b"jumps over the lazy dog".to_vec();

        let mut joined = Vec::new();
        joined.extend_from_slice(&a);
        joined.extend_from_slice(&b);
        joined.extend_from_slice(&c);

        assert_eq!(sha256_concat(&[&a, &b, &c]), sha256(&joined));
        assert_eq!(sha256_concat(&[]), sha256(b""));
        assert_eq!(sha256_concat(&[&a, &[], &b, &[], &c]), sha256(&joined));
    }

    #[test]
    fn to_hex_is_lowercase_and_total() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }
}
