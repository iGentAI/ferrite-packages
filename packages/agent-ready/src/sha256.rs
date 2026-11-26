//! SHA-256 under this package's own names, over the `sha256-hmac` package.
//!
//! The digest has one owner, the `sha256-hmac` package this package depends on
//! (mounted at `crate::crypto` unless the consumer says otherwise; `ferrite-pkg`
//! rewrites the path). This module keeps the names its consumers import, such
//! as `agent_ready::sha256::to_hex`.

pub use crate::crypto::sha256::{sha256, sha256_concat, to_hex, Sha256, BLOCK_LEN, DIGEST_LEN};
