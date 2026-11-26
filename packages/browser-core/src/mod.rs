//! browser-core — a Kitesurf-style, agent-first headless browser engine as a
//! Ferrite source package.
//!
//! Inspired by Cloudflare's Kitesurf (Agents Week, Aug 2026): a stateless,
//! memory-efficient rendering engine built for agents, not humans. Like
//! Kitesurf it trades pixel-perfect fidelity for predictable cost: parse the
//! whole hostile web without ever panicking, degrade to an empty box rather
//! than a dead session, and keep every session disposable.
//!
//! The package is dependency-free (std + alloc only) so it satisfies the
//! constrained-app contract: consumers mount it via `ferrite-pkg` and keep
//! their single `ferrite-app` dependency.
//!
//! Pipeline (mirrors Kitesurf's Engine / PageScript / PageRenderer split):
//!
//! ```text
//!   html::parse ──► dom::Document ──► css::cascade ──► layout::layout_tree
//!        │                                                    │
//!        ├──► extract::text / extract::markdown               ▼
//!        └──► dom serialization (outer_html)          paint::rasterize ──► png::encode
//! ```
//!
//! Every stage is infallible by construction: malformed input yields a
//! best-effort tree, never an error the caller must handle.

#![allow(clippy::module_inception)]

pub mod api;
pub mod cdp;
pub mod css;
pub mod dom;
pub mod extract;
pub mod html;
pub mod image;
pub mod js;
pub mod layout;
pub mod paint;
pub mod png;
pub mod style;
