//! Rsx — the Ferrite-native application framework, runtime half.
//!
//! Everything here compiles against the `ferrite-app` surface only, so a
//! consumer app keeps the one-dependency contract. The rsx compiler in
//! the `ferrite` CLI generates code that calls into these modules; hand-
//! written apps may use them directly (the builder API is the template
//! language's exact target).

pub mod action;
pub mod assets;
pub mod cache;
pub mod client;
pub mod client_asset;
pub mod csrf;
pub mod html;
pub mod islands;
pub mod live;
pub mod meta;
pub mod nav;
pub mod public;
pub mod router;
pub mod server;

pub use action::{action, ActionCtx, ActionEnvelope, ActionError, ActionFn, ActionResult};
pub use assets::{stylesheet_url, is_stylesheet};
pub use cache::{Cache, CacheProfile, Cached, Freshness};
pub use live::{region, LiveFn};
pub use islands::Island;
pub use meta::Metadata;
pub use html::{
    component, document, el, escape, trusted_el, AttrRefusal, Component, Html, TrustedTag,
};
pub use nav::{Head, PagePayload, SegmentPayload};
pub use router::{parse_query, CanonicalPath, Params, PathError, PathLimits, Router};
pub use server::{
    handler, layout, middleware, page, require_assurance, require_subject, slot, Abort, RsxApp,
    RsxAppBuilder, Guard, HandlerFn, LayoutFn, LayoutRef, Limits, MiddlewareFn, MwResult, PageFn,
    PageResult, Reply, RouteCtx, SlotMode,
};
