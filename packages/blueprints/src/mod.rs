//! Blueprints and sharing mechanics.
//!
//! A *blueprint* captures a surface's code and *binding requirements* —
//! never its state, chat history, credentials, or live connections. A
//! recipient instantiates their own copy and wires their OWN accounts to
//! each declared binding. Instances never inherit schedules, credentials,
//! or data.
//!
//! The sharing mechanics are the three self-contained patterns worth
//! lifting wherever sharing exists:
//!
//! * share keys stored only as hashes (the server cannot reconstruct a
//!   link; a DB leak exposes nothing);
//! * lazy revocation via reachability over a permission graph that records
//!   HOW each party got access, with blast-radius preview;
//! * capability-shaped authorization: `open()` returns a different
//!   interface per role, and the restricted role fails closed.
//!
//! This is a **source package** (see `packages/README.md`), not a crate: it
//! is composed into a consuming app's `src/` tree by `tools/ferrite-pkg` and
//! runs under that app's injected authority alone. It depends on the
//! `gatekeeper` package for the `TimestampMs` vocabulary and its SHA-256
//! surface. Everything
//! here is deterministic and pure: no clock, no entropy, no I/O — every
//! timestamp is a parameter and share-key entropy is caller-supplied.

pub mod blueprint;
pub mod roles;
pub mod sharing;

pub use blueprint::{
    BindingAnnotation, BindingRequirement, Blueprint, BlueprintError, BlueprintRegistry,
    ExportArchive, Instance, MAX_ARCHIVE_BYTES,
};
pub use roles::{open, BuildSession, Role, SessionError, SurfaceSession, UseSession};
pub use sharing::{PermissionGraph, RevocationPreview, ShareKey, ShareKeyStore, SharingError};
