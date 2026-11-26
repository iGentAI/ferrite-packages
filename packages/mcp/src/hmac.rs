//! HMAC-SHA-256 under this package's own names, over the `sha256-hmac` package.
//!
//! Used here for deriving PKCE verifiers and OAuth `state` values
//! ([`oauth`](super::oauth)) and for minting and verifying self-issued access
//! tokens ([`tokens`](super::tokens)). Verification must compare tags in
//! constant time — `crate::crypto::constant_time_eq`, never `==` on the hex
//! form. The MAC itself has one owner, the `sha256-hmac` package this package
//! declares as a dependency; this module is the shape its consumers import.

pub use crate::crypto::hmac::{hmac_sha256, hmac_sha256_concat};
