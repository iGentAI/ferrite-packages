#![forbid(unsafe_code)]

#[path = "../src/mod.rs"]
pub mod alloy;
#[path = "../../sha256-hmac/src/mod.rs"]
pub mod crypto;

#[cfg(test)]
mod tests;
