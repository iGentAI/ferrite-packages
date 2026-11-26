//! **Ferrite Alloy** — the Rust half of a Alloy application, as a `ferrite-pkg`
//! source package.
//!
//! A Alloy app is one repository producing two artifacts: this constrained
//! Rust crate, which owns routing, data loading, mutations, caching, and
//! document assembly; and an ordinary Vite + React bundle, which owns the
//! user interface. Between them sits a generated, typed contract emitted by
//! `alloy-gen` (the CLI's generator) into `src/generated/` and
//! `web/src/generated/`.
//!
//! # Why this is a source package rather than a crate
//!
//! The platform admits an application that names exactly one Cargo
//! dependency, `ferrite-app`. A framework therefore cannot be a dependency:
//! it is composed into the consuming app's own `src/` tree by
//! `tools/ferrite-pkg`, where it runs under that app's injected authority and
//! is scanned by the same admission gate as the app's own code.
//!
//! # The modules
//!
//! | Module | What it owns |
//! |---|---|
//! | [`router`] | Route patterns, parameter extraction, specificity ranking |
//! | [`tags`] | The tag-epoch table: O(1) invalidation over one guarded APE envelope |
//! | [`cache`] | Cache envelopes, the three freshness windows, witness validation |
//! | [`ctx`] | The cached-loader path: L1/L2, stale-while-revalidate, single-flight |
//! | [`actions`] | Replay-safe mutations: markers, stamps, and the outbox |
//! | [`outbox`] | The outbox drain: durable discovery, shard leases, delivery |
//! | [`page`] | Bounded reads and the declared invalidation budget |
//! | [`saga`] | Declared write phases, durable resume, and the crash matrix |
//! | [`document`] | Shell templates, `<head>` metadata, and payload injection |
//! | [`assets`] | The binary-safe archive, the digest manifest, and blob seeding |
//! | [`error`] | The typed error surface and its RFC 9457 rendering |
//!
//! Everything here is pure computation over injected handles: no clock but
//! [`ferrite_app::AppContext::now_ms`], no I/O but the plane clients.

// A framework offers its whole surface, and any one application uses a
// SUBSET of it — the demo mounts the router, cache, actions and document
// modules but never seeds a blob asset archive. Because the package is
// COMPOSED INTO the app's own crate rather than linked as a dependency,
// every framework item an app happens not to call is "unused" from the
// compiler's point of view. Without these, mounting Alloy would emit dozens
// of warnings in EVERY consuming app, training authors to ignore their own
// build output — the surest way to make a real warning invisible.
//
// This hides nothing: every module and item below stays public and is
// exercised by this package's own tests, which run in the consuming app.
#![allow(unused_imports, dead_code)]

pub mod actions;
/// Work that outlives the request that started it.
pub mod activity;
pub mod app;
pub mod assets;
pub mod cache;
pub mod ctx;
pub mod document;
pub mod draft;
pub mod error;
pub mod outbox;
pub mod page;
pub mod router;
pub mod saga;
/// A slow part of a page must not hold back a fast one.
pub mod segments;
pub mod tags;

pub use actions::{
    action_id, invocation_digest, marker_key, outbox_key, perform, put_stamped, ActionRecord,
    ActionRunner, ActionStamp, Admitted, Effects, Invocation, OutboxIntent, OutboxRecord,
};
pub use app::{
    document, document_for, document_for_status, document_status, idempotency, idempotency_as, json_reply,
    loader_reply, loader_reply_for, method_not_allowed, params_json, problem, required_str, AlloyApp, DrainPump,
    DRAIN_EVERY_N_REQUESTS, DRAIN_INTERVAL_MS, MAX_CHAINED_PASSES,
};
pub use assets::{
    base64_decode_chunks, base64_encode, confirm_seeded, decode_assets, hex_digest, lzss_compress,
    lzss_decompress, pack_archive, seed_blob, unpack_archive, AssetFile, AssetManifest,
    AssetReply, PublicAsset, PublicAssets, Representation, CACHE_IMMUTABLE, CACHE_REVALIDATE, CACHE_SHORT, META_PATH,
    STABLE_ENTRY_CSS, STABLE_ENTRY_JS,
    MAX_ARCHIVE_BYTES, MAX_ASSET_REPLY_BYTES,
};
pub use cache::{
    cache_key, CacheBody, CacheEnvelope, CacheLife, Freshness, L1Cache, TagWitness, MAX_INLINE_BODY,
};
pub use ctx::{lease_key, CacheOutcome, CacheStore, Cached, LEASE_PREFIX, REFRESH_LEASE_MS};
pub use document::{
    escape_html_attr, escape_html_text, escape_json_for_script, LoaderPayload, Metadata, Shell,
    BODY_MARKER, DATA_SCRIPT_EMPTY, DATA_SCRIPT_ID, HEAD_MARKER,
};
pub use draft::{disable_cookie, enable_cookie, is_enabled, COOKIE_NAME};
pub use error::{ActionError, AlloyError, Result};
pub use outbox::{
    decode_pending, done_key, drain_lease_key, encode_pending, is_digest, pending_add,
    pending_remove, poison_key, record_key, shard_key, shard_of, DrainReport, OutboxDrain,
    DRAIN_LEASE_MS, MAX_INTENTS_PER_ACTION, MAX_PENDING_PER_SHARD, PENDING_SHARDS,
};
pub use page::{Completeness, Invalidation, InvalidationPlan, Page};
pub use router::{
    parse_pattern, percent_decode, query_params, try_percent_decode, try_split_path, ParamValue,
    Params, Redirect, RenderMode, Route, RouteKind, RouteTable, Segment,
};
pub use saga::{
    phase_key, CrashRun, PhaseSpec, Saga, SagaHarness, SagaSpec, StepOutcome, MAX_PHASES,
    SAGA_PREFIX,
};
pub use tags::{check_declared, tag_key, TagDeclared, TagStore, MAX_TAGS_PER_ADVANCE, VERSION_KEY};
