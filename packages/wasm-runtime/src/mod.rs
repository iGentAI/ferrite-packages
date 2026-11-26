//! Vendored tinywasm v0.9.1 (https://github.com/explodingcamera/tinywasm),
//! MIT OR Apache-2.0, types + interpreter only (no parser), transformed for the
//! constrained-app contract.

pub(crate) mod compat {
    /// Polyfill for `core::hint::cold_path` (stabilized after rustc 1.89).
    #[inline(always)]
    pub fn cold_path() {}
}

pub mod rt;
pub mod serde_arc;
pub mod types;
