//! The canonical query-string decoder, re-exported from `http-query`.
//!
//! A re-export, not a wrapper: the documentation, the contract table and the
//! tests live at `packages/http-query/src/mod.rs`. It stays because every
//! readiness consumer spells the decoder `crate::<mount>::query`.

// A consumer that mounts this package into a BINARY crate reaches the
// re-export through a private `mod`, so an entry point it does not happen to
// call is an `unused_imports` warning rather than the `dead_code` its own
// `#[allow]` already covers. The whole surface travels together by design.
#[allow(unused_imports)]
pub use crate::http_query::{param, parse_query, path_only, split_query, target_param};
