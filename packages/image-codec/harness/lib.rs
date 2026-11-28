#![forbid(unsafe_code)]
//! Test harness crate root. It mounts the package source with `#[path]`,
//! which the code gate refuses in an application and which is why this file
//! is not part of the package.

#[path = "../src/mod.rs"]
pub mod image_codec;
