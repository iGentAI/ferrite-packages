//! agent-ready — readiness by construction for constrained Ferrite apps.
//!
//! Mount this package and hand it a declared [`surface::Surface`]; the
//! [`well_known`] router then answers every agent-readiness path (robots.txt,
//! sitemap.xml, llms.txt, the OpenAPI catalog, the A2A agent card, the MCP
//! endpoint, markdown page twins) from that one declaration. The industry's
//! readiness checklist, emitted as a side effect of declaring the surface.
//!
//! Agents: call [`well_known::handle_h`] before your catch-all and preserve
//! all response headers. Password-change discovery advertises only a page
//! the app itself serves (`PageSource::change_password_url`); the default is
//! none, which answers 404. See README.md.
//!
//! Modules, in tier order (readable → callable → payable):
//! - [`surface`] — the declared surface every artefact is projected from;
//! - [`artefacts`] — robots.txt / sitemap.xml / llms.txt / llms-full.txt;
//! - [`markdown`] — HTML→Markdown for content-page `.md` twins;
//! - [`problem`] — RFC 9457 problem+json machine-shaped errors;
//! - [`catalog`] — OpenAPI 3.1 + A2A agent card projections;
//! - [`mcp_face`] — the stateless MCP server face (tools from operations);
//! - [`a2a_face`] — the stateless A2A JSON-RPC face the agent card names;
//! - [`x402`] — HTTP 402 payment challenges + payment payload decoding;
//! - [`bot_auth`] — Web Bot Auth (RFC 9421) header parsing + policy verdicts;
//! - [`query`] — the one canonical query-string decoder, re-exported
//!   from the `http-query` package this one depends on;
//! - [`well_known`] — the single router an app calls before its own routes;
//! - [`score`] — the readiness self-report (each gap with its exact fix).

pub mod a2a_face;
pub mod artefacts;
pub mod bot_auth;
pub mod catalog;
pub mod elicitation;
pub mod events;
pub mod event_stream;
pub mod event_webhook;
pub mod files;
pub mod hmac;
pub mod markdown;
pub mod mcp_face;
pub mod poppy;
pub mod poppy_browser;
pub mod poppy_conv;
pub mod poppy_ops;
pub mod poppy_verify;
pub mod problem;
pub mod query;
pub mod score;
pub mod skills;
pub mod sha256;
pub mod surface;
pub mod tasks;
pub mod task_stream;
pub mod well_known;
pub mod x402;

/// Password-change discovery, reachable under this package's own path.
pub use crate::http_change_password as change_password;
