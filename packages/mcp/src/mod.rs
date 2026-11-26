//! Model Context Protocol **2026-07-28** for constrained Ferrite apps.
//!
//! A deployable Ferrite app may depend on exactly one crate (`ferrite-app`), so
//! an MCP implementation usable *inside* an app cannot be a crate. This is a
//! source package; `ferrite-pkg check` fails if a vendored copy drifts.
//!
//! # What this targets, and why the version matters
//!
//! `2026-07-28` is the largest revision since MCP launched and is
//! **wire-incompatible in both directions**:
//!
//! * the `initialize`/`initialized` handshake is **gone** — the protocol is
//!   stateless, and every request carries its own protocol version and client
//!   capabilities in [`proto`]`::META_*` keys;
//! * protocol-level **sessions are gone** — no `Mcp-Session-Id`. State that must
//!   span requests is a server-minted handle passed as an ordinary argument;
//! * server-initiated requests are replaced by **MRTR**: a server needing input
//!   answers `input_required`, and the client **retries the original request**
//!   carrying the responses;
//! * Roots, Sampling and Logging are **deprecated** and deliberately absent here.
//!
//! # Layout
//!
//! | Module | Role |
//! | --- | --- |
//! | [`proto`] | wire types, `_meta` keys, error codes, version negotiation, request/result envelopes. Pure — no I/O. |
//! | [`fetch`] | the HTTP seam. Production wraps the injected egress handle; tests script it. |
//! | [`client`] | the stateless client: discover, tools, resources, prompts, and the MRTR loop |
//! | [`oauth`] | OAuth 2.1: discovery, PKCE, the `resource` indicator, `iss` validation, step-up. Pure. |
//! | [`creds`] | credential records keyed by **(issuer, resource)**, and pending-authorization state |
//! | [`tokens`] | access-token AUTHENTICATION for the resource-server side: self-issued HMAC, or RFC 7662 introspection |
//! | [`server`] | the resource-server shell: protocol validation, authentication, authorization, and the PRM document |
//! | [`catalog`] | the connector catalog, with each endpoint's provenance recorded |
//! | [`sha256`], [`hmac`] | the digest and MAC names, over the `sha256-hmac` package this one depends on |
//! | [`b64`] | base64 and base64url (PKCE needs unpadded base64url) |
//!
//! # No entropy, no clock
//!
//! A constrained app has neither. Nothing here mints a random value: where
//! unpredictability is needed (a PKCE verifier, an OAuth `state`) it is derived
//! by HMAC under an injected secret, which is unguessable without the secret and
//! — usefully — reproducible when a request is redelivered. Time arrives as a
//! parameter, never from a system call.

pub mod b64;
pub mod catalog;
pub mod client;
pub mod content;
pub mod creds;
pub mod elicitation;
pub mod fetch;
pub mod files;
pub mod hmac;
pub mod naming;
pub mod progress;
pub mod oauth;
pub mod proto;
pub mod server;
pub mod sha256;
pub mod skills;
pub mod tokens;
pub mod tasks;
pub mod events;
