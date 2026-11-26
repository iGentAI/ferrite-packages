//! The server: a competing-consumer worker pool over the app's request
//! queue, strict request admission (canonical paths, ingress bounds,
//! absolute deadlines), the middleware chain, page/layout composition,
//! route handlers with globally-ordered precedence, the boundary
//! taxonomy, panic isolation, poison handling, and the platform's
//! reply-first-ack-last discipline.
//!
//! ## The admission order, and why it is this order
//!
//! 1. **Decode** the envelope — an undecodable payload is poison: acked.
//! 2. **Validate the envelope semantically** — a request with no reply
//!    channel can never be answered, so it is poison too, rather than an
//!    immortal redelivery.
//! 3. **Check the deadline** — an already-expired request runs NO
//!    application code: its answer can reach nobody, and doing the work
//!    would spend a worker slot and possibly money.
//! 4. **Bound the inputs** — body, path, query.
//! 5. **Canonicalize the path ONCE** — middleware and the router must
//!    never disagree about what path this is.
//! 6. **Run application code under the remaining time budget**, inside
//!    the spawned task so a timeout actually cancels the future rather
//!    than detaching it.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ferrite_app::{
    rt, serde_json, tracing, AppContext, FramePublish, IngressReply, IngressRequest, StreamFrame,
};

use super::action::{self, ActionEnvelope, ActionError, ActionFn};
use super::assets;
use super::cache::{Cache, CacheProfile, Freshness};
use super::html::{el, escape, Html};
use super::live::{self, LiveFn};
use super::meta::{self, Metadata};
use super::router::{
    parse_query, route_shape, CanonicalPath, Params, PathError, PathLimits, Router,
};
use super::{client, csrf, nav};

/// A boxed future (object-safe route functions).
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a page or layout returns.
pub type PageResult = Result<Html, Abort>;

/// How many redeliveries to spend trying to publish a reply before
/// settling the lease anyway. Without a bound, an envelope naming an
/// unreachable reply channel redelivers forever (ALY-SRV-004).
const MAX_REPLY_ATTEMPTS: u32 = 5;

/// The reserved handle prefix a deployment uses for the GATEWAY's own
/// outbound frame queue.
///
/// This is a difference between a local run and a real deployment, and it is
/// invisible until you deploy. Locally the gateway consumes whatever group the
/// app's own `frames` binding names, so publishing to that binding works. On
/// the platform an app's services are backed by a POOL: its `rt-frames`
/// service resolves to the app's OWN private queue resource, which the
/// gateway does not read. The deploy front therefore injects the group it does
/// read under a reserved name — exactly as it injects the reply group — and a
/// realtime app must publish there.
///
/// Getting this wrong takes the worst shape a bug can: every page renders,
/// every action commits, the event log appends, the page shows its history —
/// and the live region is silent forever, with nothing anywhere reporting a
/// failure. It was found by deploying, not by testing.
pub const GATEWAY_FRAMES_PREFIX: &str = "__gateway-frames-";

/// The handle outbound frames must be published to: the gateway's injected
/// frame queue when the deployment provides one, else the app's own declared
/// binding (the local-dev shape).
///
/// This is only the legacy fallback for envelopes without `reply_to` and the
/// startup wiring probe. A live connection names its owning gateway's frame
/// group in `reply_to`; choosing another gateway silently loses its frames.
fn frames_handle(ctx: &AppContext, declared: &str) -> String {
    ctx.payload()
        .services
        .iter()
        .find(|(name, entry)| entry.kind == "queue" && name.starts_with(GATEWAY_FRAMES_PREFIX))
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| declared.to_string())
}

/// Keep each stream attached to the gateway that admitted it. A reconnect may
/// name a different group, even for the same source and cursor.
async fn live_frames(ctx: &AppContext, declared: &str, reply_to: &str) -> io::Result<ferrite_app::client::QueueClusterClient> {
    if reply_to.is_empty() {
        ctx.queue(&frames_handle(ctx, declared))
    } else {
        ctx.reply_to_queue(reply_to).await.map(|queue| queue.into_inner())
    }
}

#[cfg(test)]
mod frames_tests {
    use super::*;
    use ferrite_app::{InjectionPayload, ServiceEntry, WireMember};

    fn queue(group: &str) -> ServiceEntry {
        // The address type is inferred from the SDK's own field: naming
        // `std::net` in a test is refused by upstream's code gate, which
        // scans every `src/` file regardless of `#[cfg(test)]`.
        ServiceEntry::single(
            "queue",
            group,
            vec![WireMember {
                zone: None,
                node_id: "unreachable".to_string(),
                client_addr: "127.0.0.1:1".parse().expect("a socket address"),
                repl_addr: "127.0.0.1:1".parse().expect("a socket address"),
            }],
            None,
            None,
            None,
        )
    }

    /// A context over a payload carrying exactly these services and nothing
    /// else. Decoded from the SDK's own serde form with only the two fields
    /// every SDK requires: a struct literal names every field, so it compiles
    /// against exactly one SDK (upstream Core's payload carries `edge_issuers`,
    /// `instance`, `generation` and `door_service`; the CLI's twin carries
    /// `native_replies`). The context's text carrier is a tagged shape the
    /// host owns, and nothing here reads it.
    fn context(entries: &[(&str, ServiceEntry)]) -> AppContext {
        let mut services = BTreeMap::new();
        for (name, entry) in entries {
            services.insert((*name).to_string(), entry.clone());
        }
        let fields: ferrite_app::serde_json::Map<String, ferrite_app::serde_json::Value> = [
            (
                "conductor_addrs".to_string(),
                ferrite_app::serde_json::Value::Array(vec![ferrite_app::serde_json::Value::String(
                    "127.0.0.1:1".to_string(),
                )]),
            ),
            (
                "services".to_string(),
                ferrite_app::serde_json::to_value(&services).expect("services serialize"),
            ),
        ]
        .into_iter()
        .collect();
        let payload: InjectionPayload =
            ferrite_app::serde_json::from_value(ferrite_app::serde_json::Value::Object(fields))
                .expect("the SDK decodes a payload naming a conductor seat and its services");
        AppContext::new(payload)
    }

    /// A DEPLOYMENT injects the gateway's own frame queue under a reserved
    /// name, because the app's declared `rt-frames` service resolves to a
    /// private resource the gateway does not read. Publishing to the declared
    /// binding there is silent failure: the region never receives anything and
    /// nothing reports a fault.
    #[test]
    fn a_deployment_injected_frame_queue_wins() {
        let ctx = context(&[
            ("frames", queue("app-own-rt-frames")),
            ("__gateway-frames-rsx-frames", queue("rsx-frames")),
        ]);
        assert_eq!(
            frames_handle(&ctx, "frames"),
            "__gateway-frames-rsx-frames"
        );
    }

    /// Locally the gateway consumes the app's own group, so the declared
    /// binding is right — and must keep working.
    #[test]
    fn without_one_the_declared_binding_is_used() {
        let ctx = context(&[("frames", queue("frames"))]);
        assert_eq!(frames_handle(&ctx, "frames"), "frames");
        // A custom handle name is honored too.
        let ctx = context(&[("rt", queue("rt"))]);
        assert_eq!(frames_handle(&ctx, "rt"), "rt");
    }

    /// Legacy group-less envelopes retain a deterministic fallback. Named
    /// stream replies never use this selection; see the two-gateway contract.
    #[test]
    fn several_injected_queues_resolve_deterministically() {
        let ctx = context(&[
            ("__gateway-frames-b", queue("b")),
            ("__gateway-frames-a", queue("a")),
            ("frames", queue("own")),
        ]);
        assert_eq!(frames_handle(&ctx, "frames"), "__gateway-frames-a");
    }

    /// A reserved NAME on a non-queue entry is not a frame queue: publishing
    /// a frame onto a store would fail at first use, and the fallback is the
    /// honest answer.
    #[test]
    fn a_reserved_name_of_the_wrong_kind_is_ignored() {
        let mut store = queue("weird");
        store.kind = "store".to_string();
        let ctx = context(&[("__gateway-frames-weird", store), ("frames", queue("own"))]);
        assert_eq!(frames_handle(&ctx, "frames"), "frames");
    }
}

/// Ingress and response bounds. Every one refuses BEFORE application
/// code runs, so a hostile request cannot spend the app's memory or CPU
/// on work it will never be charged for (ALY-SRV-003).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Path canonicalization bounds.
    pub path: PathLimits,
    /// Maximum RAW queue-payload bytes, checked BEFORE the envelope is
    /// deserialized. Everything else in this struct describes a decoded
    /// request, so this is the only bound that can protect the decode
    /// itself.
    ///
    /// It must leave room for an over-limit body to still DECODE, or an
    /// oversized body would be discarded silently instead of answering
    /// 413: the JSON envelope renders the body as an array of numbers
    /// (~4 bytes per byte), so the floor is `4 × max_body_bytes` plus
    /// headroom. [`RsxAppBuilder::build`] refuses a configuration that
    /// breaks the relationship.
    pub max_envelope_bytes: usize,
    /// Maximum raw query-string bytes.
    pub max_query_bytes: usize,
    /// Maximum decoded query pairs.
    pub max_query_pairs: usize,
    /// Maximum request-body bytes.
    pub max_body_bytes: usize,
    /// Maximum response-body bytes (a larger reply becomes a 500).
    pub max_response_bytes: usize,
    /// The server-side ceiling on one request's application time, used
    /// when the envelope carries no deadline and as a clamp when it does.
    pub max_render_ms: u64,
}

impl Limits {
    /// The smallest envelope cap that still lets an over-limit body
    /// decode far enough to be answered with 413.
    pub fn envelope_floor(&self) -> usize {
        self.max_body_bytes
            .saturating_mul(4)
            .saturating_add(64 * 1024)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            path: PathLimits::default(),
            // A JSON envelope carries the body as a number array, so it
            // is several times the body's size: budget accordingly.
            max_envelope_bytes: 8 * 1024 * 1024,
            max_query_bytes: 8 * 1024,
            max_query_pairs: 128,
            max_body_bytes: 1024 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
            max_render_ms: 30_000,
        }
    }
}

/// Boundary control flow: each variant maps to a convention rendering
/// and status.
#[derive(Debug, Clone)]
pub enum Abort {
    /// Render the not-found boundary (404).
    NotFound,
    /// Redirect with the given status and location.
    Redirect {
        /// The `location` header value.
        location: String,
        /// 303, 307 or 308.
        status: u16,
    },
    /// 401 with the unauthorized boundary.
    Unauthorized,
    /// 403 with the forbidden boundary.
    Forbidden,
    /// 500: the detail is logged server-side, never served (client-facing
    /// bodies stay generic — the redaction discipline).
    Internal(String),
}

impl Abort {
    /// A 303 See Other.
    pub fn see_other(location: impl Into<String>) -> Self {
        Abort::Redirect {
            location: location.into(),
            status: 303,
        }
    }

    /// A 307 Temporary Redirect.
    pub fn temporary(location: impl Into<String>) -> Self {
        Abort::Redirect {
            location: location.into(),
            status: 307,
        }
    }

    /// A 308 Permanent Redirect.
    pub fn permanent(location: impl Into<String>) -> Self {
        Abort::Redirect {
            location: location.into(),
            status: 308,
        }
    }
}

/// How a render treats `<Suspense>` boundaries.
///
/// The platform answers an api route with ONE buffered reply, so a
/// first-load document cannot be flushed in pieces — streamed replies
/// are a core capability (a recorded platform gap), not something a framework can
/// invent. Rsx therefore does the honest thing in each case:
///
/// * a DOCUMENT resolves every slot inline, so the first paint, a bot
///   and a reader with JavaScript disabled all get complete HTML;
/// * a SOFT NAVIGATION emits fallbacks and lets the client fill them,
///   which is where the instant-shell experience actually matters and
///   where JavaScript is present by definition;
/// * a SLOT REQUEST resolves exactly one boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotMode {
    /// Resolve every boundary in place.
    Inline,
    /// Emit fallbacks; the client resolves them.
    Shell,
    /// Resolve only this boundary.
    Only(String),
}

/// Render one `<Suspense>` boundary according to the request's mode.
///
/// Generated template code calls this; the closures keep both branches
/// unevaluated so the expensive one only runs when it is wanted.
pub fn slot<F, B>(ctx: &RouteCtx, id: &str, fallback: F, body: B) -> Html
where
    F: FnOnce() -> Html,
    B: FnOnce() -> Html,
{
    let (content, resolved) = match ctx.slot_mode() {
        SlotMode::Inline => (body(), false),
        SlotMode::Shell => (fallback(), false),
        // A requested slot may be NESTED inside another boundary, so
        // resolving one means rendering the bodies on the way to it.
        // Rendering only the matching boundary would make a nested slot
        // unreachable — it would never be visited at all.
        SlotMode::Only(want) => (body(), want == id),
    };
    if resolved {
        // The server reads the resolved body straight out of the
        // context rather than parsing it back out of the markup.
        ctx.record_slot(content.as_str());
    }
    let mut element = el("div").attr("data-rsx-slot", id);
    if matches!(ctx.slot_mode(), SlotMode::Shell) {
        // Marked PENDING so the client knows which holes to fill — and
        // so a hole that is already resolved is never re-fetched.
        element = element.bare_attr("data-rsx-slot-pending");
    }
    element.child(content).build()
}

struct CtxInner {
    app: AppContext,
    req: Arc<IngressRequest>,
    params: Params,
    path: String,
    query: String,
    pairs: Vec<(String, String)>,
    slot_mode: SlotMode,
    resolved_slot: Arc<std::sync::Mutex<Option<String>>>,
}

/// The per-request context handed to middleware, pages, layouts, and
/// handlers. Cheap to clone.
#[derive(Clone)]
pub struct RouteCtx {
    inner: Arc<CtxInner>,
}
impl RouteCtx {
    fn new(
        app: AppContext,
        req: Arc<IngressRequest>,
        params: Params,
        path: String,
        query: String,
    ) -> Self {
        // Parsed once (ALY-SRV-003): `query()` answers from these pairs.
        let pairs = parse_query(&query);
        Self {
            inner: Arc::new(CtxInner {
                app,
                req,
                params,
                path,
                query,
                pairs,
                slot_mode: SlotMode::Inline,
                resolved_slot: Arc::new(std::sync::Mutex::new(None)),
            }),
        }
    }

    /// The same context with a different slot mode.
    pub fn with_slot_mode(&self, mode: SlotMode) -> Self {
        self.rebuilt(self.inner.params.clone(), mode)
    }

    /// How this render treats `<Suspense>` boundaries.
    pub fn slot_mode(&self) -> &SlotMode {
        &self.inner.slot_mode
    }

    /// Record the HTML of the slot this render was asked to resolve.
    pub fn record_slot(&self, html: &str) {
        *self.inner.resolved_slot.lock().unwrap() = Some(html.to_string());
    }

    /// Take the recorded slot HTML, if this render resolved one.
    pub fn take_slot(&self) -> Option<String> {
        self.inner.resolved_slot.lock().unwrap().take()
    }

    fn with_params(&self, params: Params) -> Self {
        self.rebuilt(params, self.inner.slot_mode.clone())
    }

    fn rebuilt(&self, params: Params, slot_mode: SlotMode) -> Self {
        Self {
            inner: Arc::new(CtxInner {
                app: self.inner.app.clone(),
                req: Arc::clone(&self.inner.req),
                params,
                path: self.inner.path.clone(),
                query: self.inner.query.clone(),
                pairs: self.inner.pairs.clone(),
                slot_mode,
                resolved_slot: Arc::clone(&self.inner.resolved_slot),
            }),
        }
    }

    /// The injected application context (plane handles, secrets, clock).
    pub fn app(&self) -> &AppContext {
        &self.inner.app
    }

    /// The raw ingress envelope.
    pub fn request(&self) -> &IngressRequest {
        &self.inner.req
    }

    /// The HTTP method (or realtime lifecycle verb).
    pub fn method(&self) -> &str {
        &self.inner.req.method
    }

    /// The CANONICAL request path: decoded exactly once, dot-segment and
    /// separator free, trailing slash normalized. This is the same value
    /// the router matched, so a middleware comparison and a route match
    /// can never disagree.
    pub fn path(&self) -> &str {
        &self.inner.path
    }

    /// The raw query string (undecoded, without `?`).
    pub fn query_string(&self) -> &str {
        &self.inner.query
    }

    /// The captured route parameters.
    pub fn params(&self) -> &Params {
        &self.inner.params
    }

    /// One captured parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.inner.params.get(name)
    }

    /// The decoded query pairs (parsed once per request).
    pub fn query(&self) -> &[(String, String)] {
        &self.inner.pairs
    }

    /// The first query value for `name`.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.inner
            .pairs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    /// A forwarded caller header (case-insensitive; first match).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.inner
            .req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.inner.req.body
    }

    /// The client-minted idempotency key. A handler with side effects
    /// MUST key them on this: delivery is at-least-once and the gateway
    /// hedges, so the same logical request can arrive several times.
    pub fn idempotency_key(&self) -> &str {
        &self.inner.req.idempotency_key
    }

    /// The verified end-user auth context, when the platform states one.
    ///
    /// Ferrite Core's ingress envelope carries no verified subject, so this
    /// answers `Ok(None)` for every request and a route behind a [`Guard`]
    /// answers 401. That is the safe direction: a guard that could not be
    /// satisfied refuses, where one that read a caller-supplied header would
    /// admit anyone. An application that signs people in itself checks its own
    /// session in middleware and does not declare a `Guard`.
    pub fn auth(&self) -> io::Result<Option<RequestAuthContext>> {
        Ok(None)
    }

    /// The application's cache, over its `cache` store binding.
    ///
    /// Fails loudly when the app declares no cache binding: a silently
    /// absent cache would look like a very slow application.
    pub fn cache(&self) -> io::Result<Cache> {
        Ok(Cache::new(self.inner.app.store("cache")?, self.now_ms()))
    }

    /// Whether this request may be served from (or stored in) a SHARED
    /// cache.
    ///
    /// A request carrying credentials — an `authorization` header or a
    /// cookie — is personal, and putting a
    /// personal render in a shared cache is how one user is served
    /// another user's page. The check is deliberately conservative: it
    /// costs a cache miss, never a leak. The one exception is the
    /// framework's own action-token cookie, which never reaches a render
    /// (see [`csrf::only_token_cookies`]).
    pub fn is_shared(&self) -> bool {
        self.header("authorization").is_none()
            && self
                .inner
                .req
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
                .all(|(_, v)| csrf::only_token_cookies(v, csrf::Mode::of(self.app())))
    }

    /// Epoch ms per the injected clock.
    pub fn now_ms(&self) -> u64 {
        self.inner.app.now_ms()
    }

    /// The absolute reply deadline (epoch ms; 0 = none declared).
    pub fn deadline_ms(&self) -> u64 {
        self.inner.req.deadline_ms
    }
}

/// What a [`Guard`] reads about the caller: a verified subject and how
/// strongly it was authenticated.
///
/// The fields are the ones a guard and a page need. [`RouteCtx::auth`] says
/// where a value comes from, and why there is none today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAuthContext {
    /// Whether an end user is signed in.
    pub authenticated: bool,
    /// The stable subject identifier, when signed in.
    pub subject_id: Option<String>,
    /// The session the subject is acting in.
    pub session_id: Option<String>,
    /// How strongly the subject was authenticated; higher is stronger.
    pub assurance_level: u8,
}

/// Who may see a page.
///
/// Declared per route (and inherited from a layout, whose scope it is),
/// and enforced at DISPATCH — before the render cache is consulted, a
/// slot is resolved, or an action's refresh renders. Enforcing it
/// inside the render closure would let a cache HIT serve protected
/// content without ever running the check, which is exactly the shape
/// of bug a guard exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Any authenticated end user.
    Subject,
    /// An authenticated end user at this assurance level or above.
    Assurance(u8),
}

impl Guard {
    /// The stronger of two guards — how a layout's guard and a page's
    /// own combine: protection only ever increases as you descend.
    pub fn strongest(self, other: Guard) -> Guard {
        match (self, other) {
            (Guard::Assurance(a), Guard::Assurance(b)) => Guard::Assurance(a.max(b)),
            (Guard::Assurance(a), _) | (_, Guard::Assurance(a)) => Guard::Assurance(a),
            _ => Guard::Subject,
        }
    }

    /// Check this guard against a request.
    pub fn check(self, ctx: &RouteCtx) -> Result<(), Abort> {
        match self {
            Guard::Subject => require_subject(ctx).map(|_| ()),
            Guard::Assurance(level) => require_assurance(ctx, level).map(|_| ()),
        }
    }
}

/// Refuse this render unless the request carries an authenticated end
/// user.
///
/// The auth context is the GATEWAY's, credential-free and already
/// verified; an application cannot forge or amend it. A context that
/// fails its own validation is treated as absent rather than trusted —
/// the safe direction — and an unauthenticated reader gets 401, which
/// is the answer that tells a client to sign in rather than that the
/// page does not exist.
pub fn require_subject(ctx: &RouteCtx) -> Result<RequestAuthContext, Abort> {
    match ctx.auth() {
        Ok(Some(context)) if context.authenticated => Ok(context),
        Ok(_) => Err(Abort::Unauthorized),
        Err(e) => {
            // An invalid context is a gateway/platform problem, worth
            // recording, but the reader is simply not authenticated.
            tracing::warn!(error = %e, "refusing a guarded page: the auth context is invalid");
            Err(Abort::Unauthorized)
        }
    }
}

/// Refuse this render unless the authenticated user's assurance level is
/// at least `level`.
///
/// Not authenticated at all is 401 (sign in); authenticated but too
/// weakly is 403 (this account cannot see this page) — the distinction
/// a client needs to know whether to prompt for a stronger factor or to
/// stop asking.
pub fn require_assurance(ctx: &RouteCtx, level: u8) -> Result<RequestAuthContext, Abort> {
    let context = require_subject(ctx)?;
    if context.assurance_level >= level {
        Ok(context)
    } else {
        Err(Abort::Forbidden)
    }
}

/// A page function.
pub type PageFn = Arc<dyn Fn(RouteCtx) -> BoxFut<PageResult> + Send + Sync>;
/// A layout function (receives the composed children).
pub type LayoutFn = Arc<dyn Fn(RouteCtx, Html) -> BoxFut<PageResult> + Send + Sync>;
/// A route-handler function.
pub type HandlerFn = Arc<dyn Fn(RouteCtx) -> BoxFut<io::Result<Reply>> + Send + Sync>;
/// A middleware function.
pub type MiddlewareFn = Arc<dyn Fn(RouteCtx) -> BoxFut<MwResult> + Send + Sync>;

/// Wrap an async fn as a [`PageFn`].
pub fn page<F, Fut>(f: F) -> PageFn
where
    F: Fn(RouteCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = PageResult> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// Wrap an async fn as a layout, with the stable segment id that makes
/// "this layout did not change" decidable across a navigation.
///
/// The id belongs to the layout SOURCE (the compiler derives it from the
/// layout's directory: `seg:/blog`), never to its position in a chain —
/// two routes sharing a layout must agree on its id or the client would
/// re-patch chrome it already has.
pub fn layout<F, Fut>(id: impl Into<String>, f: F) -> LayoutRef
where
    F: Fn(RouteCtx, Html) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = PageResult> + Send + 'static,
{
    LayoutRef {
        id: id.into(),
        render: Arc::new(move |c, children| Box::pin(f(c, children))),
    }
}

/// A layout in a page's chain: its stable segment id and its renderer.
#[derive(Clone)]
pub struct LayoutRef {
    /// The stable segment id (`seg:/blog`).
    pub id: String,
    /// The renderer, which receives the composed children.
    pub render: LayoutFn,
}

/// Wrap an async fn as a [`HandlerFn`].
pub fn handler<F, Fut>(f: F) -> HandlerFn
where
    F: Fn(RouteCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<Reply>> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// Wrap an async fn as a [`MiddlewareFn`].
pub fn middleware<F, Fut>(f: F) -> MiddlewareFn
where
    F: Fn(RouteCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = MwResult> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// A middleware decision.
pub enum MwResult {
    /// Proceed to the next middleware / routing.
    Continue,
    /// Rewrite the request target and continue. `"/new"` keeps the
    /// current query, `"/new?"` CLEARS it, `"/new?x=1"` replaces it — a
    /// middleware that strips a credential must be able to say so
    /// (ALY-SRV-005).
    Rewrite(String),
    /// Short-circuit with a reply.
    Respond(Reply),
}

/// An HTTP token (RFC 9110 `tchar`), lowercased for header names and
/// uppercased for methods before the check.
fn is_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// A buffered response under construction.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Set when the application tried to set a header the wire cannot
    /// carry. The whole reply is then refused rather than half-honored.
    refusal: Option<String>,
}

impl Reply {
    /// An empty reply with `status`. An out-of-range status is corrected
    /// to 500 (with a log) when the reply is serialized, never emitted.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            refusal: None,
        }
    }

    /// As [`Reply::status`], refusing an out-of-range code up front.
    pub fn try_status(status: u16) -> Result<Self, String> {
        if !(100..=599).contains(&status) {
            return Err(format!("status {status} is outside 100..=599"));
        }
        Ok(Self::status(status))
    }

    /// The status this reply will serve.
    pub fn status_code(&self) -> u16 {
        self.status
    }

    /// The response body length in bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// An HTML reply (content-type set).
    pub fn html(status: u16, html: Html) -> Self {
        Self::status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(html.into_string().into_bytes())
    }

    /// A JSON reply from any serializable value.
    pub fn json<T: ferrite_app::serde::Serialize>(status: u16, value: &T) -> io::Result<Self> {
        let body = serde_json::to_vec(value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self::status(status)
            .header("content-type", "application/json")
            .body(body))
    }

    /// A plain-text reply.
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        Self::status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .body(text.into().into_bytes())
    }

    /// Set the body bytes.
    pub fn body(mut self, bytes: Vec<u8>) -> Self {
        self.body = bytes;
        self
    }

    /// Append a response header, REFUSING an invalid name or a value
    /// carrying control bytes — the response-splitting vector, closed
    /// where app-composed strings enter the response (ALY-HTTP-001).
    pub fn try_header(mut self, name: &str, value: impl Into<String>) -> Result<Self, String> {
        let name = name.to_ascii_lowercase();
        if !is_http_token(&name) {
            return Err(format!("'{name}' is not a valid header name"));
        }
        let value: String = value.into();
        if value.chars().any(|c| c.is_ascii_control()) {
            return Err(format!("header '{name}' carries a control byte"));
        }
        self.headers.push((name, value));
        Ok(self)
    }

    /// Append a response header. An invalid name or value POISONS the
    /// reply: it is refused whole at serialization and answered as a
    /// known-good 500.
    ///
    /// Dropping the offending pair and serving the rest would be worse
    /// than refusing — the application believes it set a `Set-Cookie` or
    /// a `Location`, the client reads a response that contradicts it, and
    /// nobody learns which pair vanished. This mirrors the platform
    /// gateway's own discipline for app-supplied reply headers.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        let name = name.to_ascii_lowercase();
        let value: String = value.into();
        if !is_http_token(&name) {
            self.refusal
                .get_or_insert_with(|| format!("invalid header name '{name}'"));
            return self;
        }
        if value.chars().any(|c| c.is_ascii_control()) {
            self.refusal
                .get_or_insert_with(|| format!("header '{name}' carries a control byte"));
            return self;
        }
        self.headers.push((name, value));
        self
    }

    /// Whether this reply will be refused at serialization.
    pub fn is_refused(&self) -> bool {
        self.refusal.is_some()
    }

    /// The headers accumulated so far — a test surface, so a gate can
    /// assert what a reply CARRIES without driving a whole ingress round
    /// trip.
    #[doc(hidden)]
    pub fn headers_for_test(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Convert into the wire reply for `correlation_id`, validating the
    /// status and any recorded header refusal one last time before it
    /// can reach the gateway.
    pub fn into_ingress(self, correlation_id: &str) -> IngressReply {
        if let Some(reason) = &self.refusal {
            tracing::error!(
                %correlation_id,
                %reason,
                "rsx refused a reply carrying an unserializable header"
            );
            let mut refused = IngressReply::new(correlation_id, 500, Vec::new());
            refused
                .headers
                .push(("content-type".to_string(), "text/plain; charset=utf-8".to_string()));
            return refused;
        }
        let status = if (100..=599).contains(&self.status) {
            self.status
        } else {
            tracing::error!(
                status = self.status,
                "rsx replaced an out-of-range status with 500"
            );
            500
        };
        let mut r = IngressReply::new(correlation_id, status, self.body);
        r.headers.extend(self.headers);
        r
    }
}

type MetaFn = Arc<dyn Fn() -> Metadata + Send + Sync>;

struct PageEntry {
    id: String,
    layouts: Vec<LayoutRef>,
    page: PageFn,
    cache: Option<CacheProfile>,
    metadata: Option<MetaFn>,
    /// Who may see this page. Checked at dispatch, never inside the
    /// render, so a cached entry cannot bypass it.
    guard: Option<Guard>,
}

struct HandlerEntry {
    methods: Vec<String>,
    f: HandlerFn,
}

/// The assembled application.
pub struct RsxApp {
    pages: Router<PageEntry>,
    handlers: Router<HandlerEntry>,
    actions: BTreeMap<String, ActionFn>,
    /// Live-region renderers, by SOURCE PREFIX. A subscription's source
    /// must match one, so a client cannot invent a stream.
    live: BTreeMap<String, LiveFn>,
    middleware: Vec<MiddlewareFn>,
    not_found: Option<PageEntry>,
    /// The application's own 500 page, rendered in its layout. Absent,
    /// the framework's plain document is served.
    error_page: Option<PageEntry>,
    workers: usize,
    requests: String,
    /// The queue the gateway publishes stream lifecycle envelopes onto.
    streams: String,
    /// The queue outbound frames are published to.
    frames: String,
    /// The log a live region tails.
    events: String,
    limits: Limits,
    /// The site's public base URL, when it declares one. Serving
    /// `robots.txt` and `sitemap.xml` needs to know where the site
    /// lives, and guessing from a Host header is how a sitemap ends up
    /// advertising an attacker's domain.
    site: Option<String>,
    /// Page patterns with no dynamic segment, in route order — the only
    /// ones a sitemap can honestly list.
    static_paths: Vec<String>,
    /// The app's aggregated, scoped stylesheet (the compiler's
    /// `__rsx::assets::STYLESHEET`). Served content-addressed and
    /// linked from every document.
    stylesheet: Option<&'static str>,
    /// Files from `public/`, embedded in the source image and served at
    /// the paths their names imply.
    public: &'static [super::public::Asset],
    /// Island modules, embedded and served content-addressed. A marker
    /// without its module is a page that renders and never becomes
    /// interactive, so the compiler refuses one — by the time an app
    /// runs, every marker's module is here.
    islands: &'static [super::islands::Island],
    /// Who an action invocation belongs to, when the app vouches for it.
    action_scope: Option<action::ActionScopeFn>,
}

impl RsxApp {
    /// Start building an app.
    pub fn builder() -> RsxAppBuilder {
        RsxAppBuilder {
            pages: Vec::new(),
            metadata: Vec::new(),
            guards: Vec::new(),
            handlers: Vec::new(),
            actions: BTreeMap::new(),
            live: BTreeMap::new(),
            middleware: Vec::new(),
            not_found: None,
            error_page: None,
            workers: 4,
            requests: "requests".into(),
            streams: "streams".into(),
            frames: "frames".into(),
            events: "events".into(),
            limits: Limits::default(),
            site: None,
            stylesheet: None,
            public: &[],
            islands: &[],
            action_scope: None,
        }
    }

    /// The configured ingress bounds.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Run the app: supervise the worker pool and park (the platform's
    /// standard long-running shape).
    pub async fn run(self, ctx: AppContext) -> io::Result<()> {
        // Fail loudly at startup on a wiring mistake.
        let _probe = ctx.queue(&self.requests)?;
        // A declared stream queue needs a consumer even with no renderers:
        // unknown subscriptions must receive a terminal refusal. API-only
        // apps without that binding retain their smaller startup contract.
        let consume_streams = !self.live.is_empty()
            || ctx.payload().services.contains_key(&self.streams);
        if consume_streams {
            let _ = ctx.queue(&self.streams)?;
            let _ = ctx.queue(&frames_handle(&ctx, &self.frames))?;
        }
        // Only a registered renderer tails the log. Refusing an unknown
        // source must not require an otherwise unused events binding.
        if !self.live.is_empty() {
            let _ = ctx.log(&self.events)?;
        }
        let app = Arc::new(self);
        for id in 0..app.workers {
            let app = Arc::clone(&app);
            let ctx = ctx.clone();
            rt::spawn(async move {
                supervise(id, app, ctx).await;
            });
        }
        if consume_streams {
            let app = Arc::clone(&app);
            let ctx = ctx.clone();
            rt::spawn(async move {
                supervise_live(app, ctx).await;
            });
        }
        loop {
            ferrite_app::sleep_ms(60_000).await;
        }
    }
}

/// The builder.
pub struct RsxAppBuilder {
    pages: Vec<(String, Vec<LayoutRef>, PageFn, Option<CacheProfile>)>,
    metadata: Vec<(String, MetaFn)>,
    guards: Vec<(String, Guard)>,
    handlers: Vec<(String, Vec<String>, HandlerFn)>,
    actions: BTreeMap<String, ActionFn>,
    live: BTreeMap<String, LiveFn>,
    middleware: Vec<MiddlewareFn>,
    not_found: Option<(Vec<LayoutRef>, PageFn)>,
    error_page: Option<(Vec<LayoutRef>, PageFn)>,
    workers: usize,
    requests: String,
    streams: String,
    frames: String,
    events: String,
    limits: Limits,
    site: Option<String>,
    stylesheet: Option<&'static str>,
    public: &'static [super::public::Asset],
    islands: &'static [super::islands::Island],
    action_scope: Option<action::ActionScopeFn>,
}

impl RsxAppBuilder {
    /// Register a page at `pattern` with its root→leaf layout chain.
    pub fn page(mut self, pattern: &str, layouts: Vec<LayoutRef>, page: PageFn) -> Self {
        self.pages.push((pattern.to_string(), layouts, page, None));
        self
    }

    /// Register a page whose render is CACHED under `profile`.
    ///
    /// Only requests carrying no credentials are served from or stored
    /// in it ([`RouteCtx::is_shared`]); a personalized render is always
    /// computed fresh.
    pub fn cached_page(
        mut self,
        pattern: &str,
        layouts: Vec<LayoutRef>,
        page: PageFn,
        profile: CacheProfile,
    ) -> Self {
        self.pages
            .push((pattern.to_string(), layouts, page, Some(profile)));
        self
    }

    /// Register a route handler at `pattern` for the given methods.
    pub fn handler(mut self, pattern: &str, methods: &[&str], f: HandlerFn) -> Self {
        self.handlers.push((
            pattern.to_string(),
            methods.iter().map(|m| m.to_string()).collect(),
            f,
        ));
        self
    }

    /// Attach METADATA to the page registered at `pattern`.
    ///
    /// Separate from [`page`](Self::page) so a page's registration does
    /// not grow an argument every time the head learns a new trick, and
    /// so order does not matter: it is resolved at build time.
    pub fn metadata<F>(mut self, pattern: &str, f: F) -> Self
    where
        F: Fn() -> Metadata + Send + Sync + 'static,
    {
        self.metadata.push((pattern.to_string(), Arc::new(f)));
        self
    }

    /// Declare WHO may see the page registered at `pattern`.
    ///
    /// Resolved at build time like metadata, so a guard for a pattern
    /// that registers no page is refused rather than silently ignored —
    /// a guard nobody applies is worse than none, because it reads as
    /// protection.
    pub fn guard(mut self, pattern: &str, guard: Guard) -> Self {
        self.guards.push((pattern.to_string(), guard));
        self
    }

    /// Register an ACTION — the only path by which a request may change
    /// something.
    ///
    /// Actions are addressed by id at the framework's own route, never
    /// by URL, so a mutation cannot be reached by a link, a prefetch or
    /// a crawler.
    pub fn action(mut self, id: &str, f: ActionFn) -> Self {
        self.actions.insert(id.to_string(), f);
        self
    }

    /// Register a LIVE source: every subscription whose source falls
    /// under `prefix` is rendered by `f`. A source falls under a prefix
    /// when it equals it, when the prefix ends in `:` or `/`, or when the
    /// source continues past it with one of those, so `room` covers
    /// `room:general` but not `roomba`.
    ///
    /// A prefix rather than an exact name, because a source carries its
    /// subject (`room:general`) and one renderer serves them all. A
    /// subscription matching no prefix is REFUSED — a client cannot
    /// name a stream the app never declared.
    pub fn live<F>(mut self, prefix: &str, f: F) -> Self
    where
        F: Fn(&str, &[u8]) -> Option<Html> + Send + Sync + 'static,
    {
        self.live.insert(prefix.to_string(), Arc::new(f));
        self
    }

    /// The stream-request queue handle name (default `streams`).
    pub fn streams_handle(mut self, name: impl Into<String>) -> Self {
        self.streams = name.into();
        self
    }

    /// The outbound frame queue handle name (default `frames`).
    pub fn frames_handle(mut self, name: impl Into<String>) -> Self {
        self.frames = name.into();
        self
    }

    /// The event log handle a live region tails (default `events`).
    pub fn events_handle(mut self, name: impl Into<String>) -> Self {
        self.events = name.into();
        self
    }

    /// Append a middleware (runs in registration order, before routing).
    pub fn middleware(mut self, f: MiddlewareFn) -> Self {
        self.middleware.push(f);
        self
    }

    /// Scope every action invocation to the caller `f` resolves.
    ///
    /// `f` answers with a STABLE identity the application vouches for —
    /// typically the subject id of its own verified session — or `None`
    /// for an anonymous caller. The scope becomes part of the invocation's
    /// store keys, so a recorded reply is replayed only to the caller that
    /// owns it, whatever idempotency key another caller presents. Never
    /// return a session token or anything else that rotates: a retry after
    /// a rotation would miss its record and run the action again. See
    /// [`action::ActionScopeFn`].
    pub fn action_scope<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(RouteCtx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        self.action_scope = Some(Arc::new(move |ctx| Box::pin(f(ctx))));
        self
    }

    /// The not-found boundary page, with the layout chain it renders
    /// inside.
    ///
    /// A 404 is a PAGE of the application, not a bare error string: it
    /// carries the site's chrome so a reader can navigate out of it, and
    /// so the styles its own template declares have somewhere to apply.
    pub fn not_found(mut self, layouts: Vec<LayoutRef>, f: PageFn) -> Self {
        self.not_found = Some((layouts, f));
        self
    }

    /// The application's own ERROR boundary, with its layout chain.
    ///
    /// Rendered for a 500 — an internal abort, a panicked render, a
    /// handler that failed — so a reader meets the site rather than a
    /// bare framework page. It is given NO detail about the failure:
    /// the cause is server-side evidence, and a boundary that printed it
    /// would leak internals to whoever provoked it.
    pub fn error_page(mut self, layouts: Vec<LayoutRef>, f: PageFn) -> Self {
        self.error_page = Some((layouts, f));
        self
    }

    /// Worker-pool size (default 4, capped at 256).
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n.clamp(1, 256);
        self
    }

    /// The request-queue handle name (default `requests`).
    pub fn requests_handle(mut self, name: impl Into<String>) -> Self {
        self.requests = name.into();
        self
    }

    /// The app's aggregated stylesheet: every template's scoped `<style>`
    /// block, as the compiler collected it.
    ///
    /// Without this the scope classes would be on the markup and the
    /// rules themselves would reach nobody — so the generated route
    /// table always passes it, even when it is empty.
    pub fn stylesheet(mut self, css: &'static str) -> Self {
        self.stylesheet = Some(css);
        self
    }

    /// The files from `public/`, as the compiler embedded them.
    ///
    /// Served at the path each name implies (`public/logo.svg` at
    /// `/logo.svg`), before routing, so an asset cannot be shadowed by
    /// a catch-all page — and revalidated by ETag rather than claimed
    /// immutable, because the author chose the URL.
    pub fn public(mut self, files: &'static [super::public::Asset]) -> Self {
        self.public = files;
        self
    }

    /// The island modules, as the compiler embedded them.
    ///
    /// Each is served at a content-addressed URL and named in every
    /// document's boot state, so the client imports one exactly when a
    /// marker for it appears — not on every page that merely could
    /// have had one.
    pub fn islands(mut self, islands: &'static [super::islands::Island]) -> Self {
        self.islands = islands;
        self
    }

    /// Declare the site's public base URL.
    ///
    /// With one, the app serves `/robots.txt` and `/sitemap.xml`. The
    /// URL is DECLARED rather than derived from a request header,
    /// because a sitemap built from an attacker-supplied Host would
    /// advertise their domain as canonical.
    pub fn site(mut self, base_url: impl Into<String>) -> Self {
        self.site = Some(base_url.into());
        self
    }

    /// Override the ingress/response bounds.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Assemble; refuses malformed patterns, duplicate shapes, invalid
    /// method sets, and a page/handler pair that would both claim GET on
    /// one shape (ALY-ROUTE-001, ALY-HTTP-002).
    pub fn build(self) -> Result<RsxApp, String> {
        let floor = self.limits.envelope_floor();
        if self.limits.max_envelope_bytes < floor {
            return Err(format!(
                "max_envelope_bytes ({}) is below the floor ({floor}) implied by \
                 max_body_bytes ({}); an oversized body would be discarded silently \
                 instead of answering 413",
                self.limits.max_envelope_bytes, self.limits.max_body_bytes
            ));
        }
        let mut pages = Router::new();
        let mut page_shapes = BTreeSet::new();
        let mut static_paths: Vec<String> = Vec::new();
        // Metadata is registered by pattern; resolve it here so a
        // declaration for a page that does not exist is caught at
        // startup rather than silently ignored forever.
        let mut metadata: BTreeMap<String, MetaFn> = BTreeMap::new();
        for (pattern, f) in self.metadata {
            let shape = route_shape(&pattern)?;
            metadata.insert(shape, f);
        }
        // Guards resolve by shape too, and COMBINE rather than replace:
        // a layout's guard and a page's own both apply, and the
        // strongest wins.
        let mut guards: BTreeMap<String, Guard> = BTreeMap::new();
        for (pattern, guard) in self.guards {
            let shape = route_shape(&pattern)?;
            let combined = match guards.get(&shape) {
                Some(existing) => existing.strongest(guard),
                None => guard,
            };
            guards.insert(shape, combined);
        }
        for (pattern, layouts, page, cache) in self.pages {
            let shape = route_shape(&pattern)?;
            page_shapes.insert(shape.clone());
            // A dynamic pattern names a SHAPE, not a page: listing it in
            // a sitemap would advertise a URL that does not exist.
            if !pattern.contains('[') {
                static_paths.push(pattern.clone());
            }
            // One tag slot belongs to the framework: every cached render
            // is tagged with its own URL so it can be revalidated by
            // path. A profile that fills every slot would silently lose
            // that tag, leaving a page nothing could invalidate.
            if let Some(profile) = &cache {
                let author_limit = super::cache::MAX_TAGS - 1;
                if profile.tags.len() > author_limit {
                    return Err(format!(
                        "cached route '{pattern}' declares {} tags; at most {author_limit} are \
                         allowed because one slot is reserved for the framework's path tag",
                        profile.tags.len()
                    ));
                }
            }
            let id = format!("page:{pattern}");
            let entry_metadata = metadata.remove(&shape);
            let entry_guard = guards.remove(&shape);
            pages.add(
                &pattern,
                PageEntry {
                    id,
                    layouts,
                    page,
                    cache,
                    metadata: entry_metadata,
                    guard: entry_guard,
                },
            )?;
        }
        if let Some(orphan) = metadata.keys().next() {
            return Err(format!(
                "metadata is declared for '{orphan}', which registers no page"
            ));
        }
        if let Some(orphan) = guards.keys().next() {
            return Err(format!(
                "a guard is declared for '{orphan}', which registers no page — a guard that \
                 protects nothing reads as protection"
            ));
        }
        let mut handlers = Router::new();
        for (pattern, methods, f) in self.handlers {
            let methods = normalize_methods(&pattern, &methods)?;
            let shape = route_shape(&pattern)?;
            if page_shapes.contains(&shape) && methods.iter().any(|m| m == "GET") {
                return Err(format!(
                    "route '{pattern}' declares a GET handler and a page on the same shape; \
                     one of them must own GET"
                ));
            }
            handlers.add(&pattern, HandlerEntry { methods, f })?;
        }
        Ok(RsxApp {
            pages,
            handlers,
            actions: self.actions,
            live: self.live,
            middleware: self.middleware,
            not_found: self.not_found.map(|(layouts, page)| PageEntry {
                id: "page:not-found".to_string(),
                layouts,
                page,
                cache: None,
                metadata: None,
                guard: None,
            }),
            error_page: self.error_page.map(|(layouts, page)| PageEntry {
                id: "page:error".to_string(),
                layouts,
                page,
                cache: None,
                metadata: None,
                guard: None,
            }),
            workers: self.workers,
            requests: self.requests,
            streams: self.streams,
            frames: self.frames,
            events: self.events,
            limits: self.limits,
            site: self.site,
            static_paths,
            stylesheet: self.stylesheet,
            public: self.public,
            islands: self.islands,
            action_scope: self.action_scope,
        })
    }
}

fn normalize_methods(pattern: &str, methods: &[String]) -> Result<Vec<String>, String> {
    if methods.is_empty() {
        return Err(format!("route '{pattern}' declares no methods"));
    }
    let mut set = BTreeSet::new();
    for m in methods {
        let upper = m.to_ascii_uppercase();
        if !is_http_token(&upper) {
            return Err(format!("route '{pattern}' declares invalid method '{m}'"));
        }
        set.insert(upper);
    }
    Ok(set.into_iter().collect())
}

/// Split a target into its path and its query PRESENCE: `None` means no
/// `?` at all (keep the current query), `Some("")` means an explicit
/// empty query (clear it).
fn split_path_query(raw: &str) -> (String, Option<String>) {
    match raw.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw.to_string(), None),
    }
}

async fn supervise(id: usize, app: Arc<RsxApp>, ctx: AppContext) {
    let mut backoff = 200u64;
    loop {
        let worker_app = Arc::clone(&app);
        let worker_ctx = ctx.clone();
        let handle = rt::spawn(async move { worker(worker_app, worker_ctx).await });
        match handle.await {
            Ok(()) => tracing::error!(worker = id, "rsx worker exited; restarting"),
            Err(e) => tracing::error!(worker = id, error = %e, "rsx worker panicked; restarting"),
        }
        ferrite_app::sleep_ms(backoff).await;
        backoff = (backoff * 2).min(5_000);
    }
}

/// Supervise the live-subscription worker, exactly as the request pool
/// is supervised: a panic restarts it rather than silently ending every
/// reader's stream for the life of the process.
async fn supervise_live(app: Arc<RsxApp>, ctx: AppContext) {
    let mut backoff = 200u64;
    loop {
        let worker_app = Arc::clone(&app);
        let worker_ctx = ctx.clone();
        let handle = rt::spawn(async move { live_worker(worker_app, worker_ctx).await });
        match handle.await {
            Ok(()) => tracing::error!("rsx live worker exited; restarting"),
            Err(e) => tracing::error!(error = %e, "rsx live worker panicked; restarting"),
        }
        ferrite_app::sleep_ms(backoff).await;
        backoff = (backoff * 2).min(5_000);
    }
}

/// The tailers a live worker started.
///
/// Dropping a `JoinHandle` DETACHES its task rather than stopping it, so
/// this owns them and aborts every one when it goes out of scope —
/// including while a panic unwinds. Without that, a worker that died
/// would leave its tailers polling the log forever: invisible,
/// unstoppable (a later `STREAM_CLOSE` reaches the NEW worker's empty
/// map), and duplicated the moment a reader reconnected.
struct TailerSet {
    handles: std::sync::Mutex<BTreeMap<String, rt::JoinHandle<()>>>,
}

impl TailerSet {
    fn new() -> Self {
        Self {
            handles: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Track a tailer, replacing (and stopping) any tailer already
    /// running for that connection.
    fn insert(&self, correlation_id: String, handle: rt::JoinHandle<()>) {
        let previous = self
            .handles
            .lock()
            .unwrap()
            .insert(correlation_id, handle);
        if let Some(previous) = previous {
            previous.abort();
        }
    }

    /// Stop one connection's tailer.
    fn remove(&self, correlation_id: &str) -> bool {
        let handle = self.handles.lock().unwrap().remove(correlation_id);
        match handle {
            Some(handle) => {
                handle.abort();
                true
            }
            None => false,
        }
    }
}

impl Drop for TailerSet {
    fn drop(&mut self) {
        for handle in self.handles.lock().unwrap().values() {
            handle.abort();
        }
    }
}

/// Consume the stream-lifecycle queue: open a tailer per subscription,
/// and stop it when its connection ends.
async fn live_worker(app: Arc<RsxApp>, ctx: AppContext) {
    let mut streams = match ctx.queue(&app.streams) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!(error = %e, "rsx cannot open the stream-request queue");
            return;
        }
    };
    // Owned by this worker, so every tailer stops when it does.
    let tailers = TailerSet::new();
    loop {
        let lease = match streams.poll_wait(1_000).await {
            Ok(Some(lease)) => lease,
            Ok(None) => continue,
            Err(_) => {
                ferrite_app::sleep_ms(200).await;
                continue;
            }
        };
        if let Ok(req) = serde_json::from_slice::<IngressRequest>(&lease.payload) {
            match req.method.as_str() {
                "GET" => open_live(&app, &ctx, &tailers, &req).await,
                // The connection ended — including ungracefully, which
                // is exactly why this arm matters: without it, every
                // reader who closed a laptop would leave a tailer
                // polling the log forever.
                "STREAM_CLOSE" => {
                    if tailers.remove(&req.correlation_id) {
                        tracing::debug!(
                            correlation_id = %req.correlation_id,
                            "live subscription closed"
                        );
                    }
                }
                other => tracing::debug!(method = %other, "ignoring a stream lifecycle verb"),
            }
        }
        let _ = streams.ack(lease.token).await;
    }
}

/// Whether `value` falls under `prefix` on a subject boundary: it equals
/// the prefix, the prefix already ends in a delimiter (`room:`), or the
/// next character is one (`room:1` covers `room:1` and `room:1:pins`).
///
/// A plain `starts_with` made `room:1` cover `room:10` too, so a reader
/// could receive another subject's records by naming a shorter one.
fn has_delimited_prefix(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.is_empty()
        || prefix.is_empty()
        || prefix.ends_with(['/', ':'])
        || rest.starts_with(['/', ':'])
}

/// Whether a subscription `source` names one subject under `prefix`.
///
/// It must name a SUBJECT, not the family: the source is strictly longer
/// than the declared prefix and does not end in a delimiter. Otherwise
/// `source=room:` (or `room`, or `room:1:`) would be accepted and then, in
/// the tailer's hierarchical match, cover every subject in the log.
fn source_admitted(source: &str, prefix: &str) -> bool {
    has_delimited_prefix(source, prefix)
        && source.len() > prefix.len()
        && !source.ends_with(['/', ':'])
}

/// Open one subscription: admit it through the app's middleware,
/// validate its source against the DECLARED prefixes, then spawn its
/// tailer.
async fn open_live(
    app: &Arc<RsxApp>,
    ctx: &AppContext,
    tailers: &TailerSet,
    req: &IngressRequest,
) {
    let Some(query) = admit_live(app, ctx, req).await else {
        publish_live_refusal(app, ctx, &req.correlation_id, &req.reply_to, "unauthorized subscription").await;
        return;
    };
    let pairs = parse_query(&query);
    let Some((source, from)) = live::parse_subscription(&pairs) else {
        publish_live_refusal(app, ctx, &req.correlation_id, &req.reply_to, "a subscription needs a source").await;
        return;
    };
    // The renderer registry is also the AUTHORITY: a source no declared
    // prefix matches is refused, so a client cannot subscribe to a
    // stream the application never offered.
    let renderer = app
        .live
        .iter()
        .find(|(prefix, _)| source_admitted(&source, prefix))
        .map(|(_, f)| Arc::clone(f));
    let Some(render) = renderer else {
        publish_live_refusal(app, ctx, &req.correlation_id, &req.reply_to, "no such live source").await;
        return;
    };

    let worker_app = Arc::clone(app);
    let worker_ctx = ctx.clone();
    let correlation_id = req.correlation_id.clone();
    let key = correlation_id.clone();
    let reply_to = req.reply_to.clone();
    let handle = rt::spawn(async move {
        tail_live(worker_app, worker_ctx, correlation_id, reply_to, source, from, render).await;
    });
    // Inserting REPLACES any tailer already running for this
    // connection, so a redelivered open cannot double-publish.
    tailers.insert(key, handle);
}

/// Put a subscription OPEN through the same admission an ordinary
/// request meets in `dispatch`: the canonical path, the query bounds and
/// the whole middleware chain. Answers the final query, or `None` when
/// the subscription is refused.
///
/// A subscription arrives on the stream-lifecycle queue rather than the
/// request queue, so it never passes through `dispatch`. Without this an
/// app whose authentication lives in middleware would serve every
/// declared live source to anyone who opened `/_live/subscribe`.
async fn admit_live(app: &RsxApp, ctx: &AppContext, req: &IngressRequest) -> Option<String> {
    let limits = &app.limits;
    let (raw_path, raw_query) = split_path_query(&req.path);
    let mut query = raw_query.unwrap_or_default();
    if query_refusal(&query, limits).is_some() {
        return None;
    }
    let mut canon = CanonicalPath::parse(&raw_path, &limits.path).ok()?;
    let req = Arc::new(req.clone());
    let mut rc = RouteCtx::new(
        ctx.clone(),
        Arc::clone(&req),
        Params::empty(),
        canon.as_str().to_string(),
        query.clone(),
    );
    for mw in &app.middleware {
        match mw(rc.clone()).await {
            MwResult::Continue => {}
            MwResult::Rewrite(target) => {
                let (p, q) = split_path_query(&target);
                canon = CanonicalPath::parse(&p, &limits.path).ok()?;
                if let Some(new_query) = q {
                    if query_refusal(&new_query, limits).is_some() {
                        return None;
                    }
                    query = new_query;
                }
                rc = RouteCtx::new(
                    ctx.clone(),
                    Arc::clone(&req),
                    Params::empty(),
                    canon.as_str().to_string(),
                    query.clone(),
                );
            }
            // Whatever the middleware would have answered (a 401, a
            // redirect to sign in), a stream cannot carry it: the
            // subscription is refused and ends.
            MwResult::Respond(_) => return None,
        }
    }
    Some(query)
}

/// Tell a client its subscription will produce nothing, and end it.
///
/// Silence would be indistinguishable from a quiet stream, so a reader
/// would wait forever on a source that does not exist.
async fn publish_live_refusal(
    app: &RsxApp,
    ctx: &AppContext,
    correlation_id: &str,
    reply_to: &str,
    reason: &str,
) {
    let Ok(mut frames) = live_frames(ctx, &app.frames, reply_to).await else {
        return;
    };
    let frame = StreamFrame {
        correlation_id: correlation_id.to_string(),
        event: Some(live::LIVE_EVENT.to_string()),
        data: live::refusal_payload(reason),
        done: true,
    };
    let _ = frames.publish_frame(&frame).await;
}

/// Tail the event log for one subscription, publishing a frame per
/// matching record.
async fn tail_live(
    app: Arc<RsxApp>,
    ctx: AppContext,
    correlation_id: String,
    reply_to: String,
    source: String,
    from: u64,
    render: LiveFn,
) {
    let (Ok(mut log), Ok(mut frames)) = (
        ctx.log(&app.events),
        live_frames(&ctx, &app.frames, &reply_to).await,
    ) else {
        tracing::error!("rsx cannot tail: the event log or the frame queue is missing");
        return;
    };
    let mut offset = from;
    loop {
        match log.read_from(offset, live::TAIL_BATCH).await {
            Ok(records) => {
                let idle = records.is_empty();
                for record in records {
                    // The cursor advances past EVERY record, matched or
                    // not: a reconnect must not re-read what this
                    // subscription already decided to skip.
                    offset = record.offset.saturating_add(1);
                    let key = String::from_utf8_lossy(&record.key).into_owned();
                    if !has_delimited_prefix(&key, &source) {
                        continue;
                    }
                    let Some(html) = render(&key, &record.value) else {
                        continue;
                    };
                    let frame = StreamFrame {
                        correlation_id: correlation_id.clone(),
                        event: Some(live::LIVE_EVENT.to_string()),
                        data: live::frame_payload(record.offset, html.as_str()),
                        done: false,
                    };
                    if let Err(e) = frames.publish_frame(&frame).await {
                        // The frame plane is the only way to reach this
                        // reader. The SDK retains an uncertain frame for
                        // the next publication to resolve under its number.
                        tracing::warn!(
                            error = %e,
                            %correlation_id,
                            "could not publish a live frame"
                        );
                    }
                }
                if idle {
                    ferrite_app::sleep_ms(live::TAIL_IDLE_MS).await;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "a live tail read failed; retrying");
                ferrite_app::sleep_ms(live::TAIL_IDLE_MS).await;
            }
        }
    }
}

async fn worker(app: Arc<RsxApp>, ctx: AppContext) {
    let mut requests = match ctx.queue(&app.requests) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!(error = %e, "rsx worker cannot open the request queue");
            return;
        }
    };
    loop {
        let lease = match requests.poll_wait(1_000).await {
            Ok(Some(l)) => l,
            Ok(None) => continue,
            Err(_) => {
                ferrite_app::sleep_ms(200).await;
                continue;
            }
        };
        // Bound the RAW payload before handing it to the deserializer:
        // every other limit describes an already-decoded request, so this
        // is the only one that can protect the decode itself. An
        // over-limit envelope cannot be answered without parsing the very
        // bytes being refused, so it is settled as poison and logged.
        if lease.payload.len() > app.limits.max_envelope_bytes {
            tracing::error!(
                bytes = lease.payload.len(),
                max = app.limits.max_envelope_bytes,
                "rsx discarded an oversized ingress envelope without decoding it"
            );
            let _ = requests.ack(lease.token).await;
            continue;
        }
        // Syntactic poison: not an ingress envelope at all.
        let Ok(req) = serde_json::from_slice::<IngressRequest>(&lease.payload) else {
            let _ = requests.ack(lease.token).await;
            continue;
        };
        // Semantic poison: an envelope naming no reply channel can never
        // be answered by anyone, so redelivering it forever helps nobody.
        if req.reply_to.trim().is_empty() || req.correlation_id.trim().is_empty() {
            tracing::error!(
                correlation_id = %req.correlation_id,
                "rsx discarded an envelope with no reply channel or correlation id"
            );
            let _ = requests.ack(lease.token).await;
            continue;
        }

        let correlation_id = req.correlation_id.clone();
        let reply_to = req.reply_to.clone();
        let now = ctx.now_ms();
        let deadline = req.deadline_ms;
        let token_mode = csrf::Mode::of(&ctx);
        let held = csrf::held(&req.headers, token_mode);

        let reply = if deadline != 0 && deadline <= now {
            // Expired before we even started: run NO application code.
            tracing::warn!(%correlation_id, "rsx refused an expired request");
            Reply::text(504, "deadline exceeded before dispatch")
        } else {
            let budget = if deadline == 0 {
                app.limits.max_render_ms
            } else {
                deadline.saturating_sub(now).min(app.limits.max_render_ms)
            };
            let req = Arc::new(req);
            let req_for_boundary = Arc::clone(&req);
            let task = {
                let app = Arc::clone(&app);
                let ctx = ctx.clone();
                let req = Arc::clone(&req);
                // The timeout lives INSIDE the spawned task so that
                // expiry DROPS the dispatch future. Timing out the join
                // handle instead would detach the work and leak it.
                rt::spawn(async move {
                    match rt::time::timeout(
                        Duration::from_millis(budget),
                        dispatch(Arc::clone(&app), ctx, req),
                    )
                    .await
                    {
                        Ok(reply) => reply,
                        Err(_) => Reply::text(504, "deadline exceeded"),
                    }
                })
            };
            match task.await {
                Ok(reply) => reply,
                Err(_) => {
                    tracing::error!(%correlation_id, "rsx render panicked; answering 500");
                    // The application's own error boundary, rendered in
                    // ITS OWN task and under what is LEFT of this
                    // request's budget — never a second full one. A
                    // boundary that panics must not take the worker
                    // down; one that hangs must not push the request
                    // past the deadline it was already given; and with
                    // no time left there is nothing to do but answer.
                    let spent = ctx.now_ms().saturating_sub(now);
                    let remaining = budget.saturating_sub(spent);
                    if remaining == 0 {
                        tracing::warn!(
                            %correlation_id,
                            "no budget left for the error boundary; serving the framework page"
                        );
                        error_reply(500, internal_error_page(), app.stylesheet)
                    } else {
                        let boundary_app = Arc::clone(&app);
                        let boundary_ctx = ctx.clone();
                        let boundary_req = Arc::clone(&req_for_boundary);
                        let rendered = rt::spawn(async move {
                            let render = async {
                                let (path, query) = split_path_query(&boundary_req.path);
                                let path = CanonicalPath::parse(&path, &boundary_app.limits.path)
                                    .map(|c| c.as_str().to_string())
                                    .unwrap_or_else(|_| "/".to_string());
                                let rc = RouteCtx::new(
                                    boundary_ctx,
                                    boundary_req,
                                    Params::empty(),
                                    path,
                                    query.unwrap_or_default(),
                                );
                                internal_error_reply(&boundary_app, Some(rc)).await
                            };
                            match rt::time::timeout(Duration::from_millis(remaining), render).await
                            {
                                Ok(reply) => reply,
                                Err(_) => {
                                    tracing::error!(
                                        "the error boundary exceeded the remaining budget"
                                    );
                                    error_reply(500, internal_error_page(), boundary_app.stylesheet)
                                }
                            }
                        })
                        .await;
                        rendered.unwrap_or_else(|_| {
                            tracing::error!("the error boundary panicked as well");
                            error_reply(500, internal_error_page(), app.stylesheet)
                        })
                    }
                }
            }
        };

        let reply = seal_document(reply, &held, token_mode);

        // A response too large for the reply envelope is an app defect,
        // not something to discover at the queue front. The replacement
        // is itself checked, so a very small configured limit cannot be
        // exceeded by the error page that reports exceeding it.
        let reply = if reply.body_len() > app.limits.max_response_bytes {
            tracing::error!(
                %correlation_id,
                bytes = reply.body_len(),
                max = app.limits.max_response_bytes,
                "rsx refused an oversized response"
            );
            let page = error_reply(500, internal_error_page(), app.stylesheet);
            if page.body_len() > app.limits.max_response_bytes {
                Reply::status(500)
            } else {
                page
            }
        } else {
            reply
        };

        let wire = reply.into_ingress(&correlation_id);

        // Reply FIRST; ack ONLY on a successfully published reply, so a
        // transient reply failure redelivers. An envelope whose reply
        // channel is permanently unreachable is settled after a bounded
        // number of attempts rather than redelivering forever.
        let replied = match ctx.reply_to_queue(&reply_to).await {
            Ok(mut rq) => {
                let bytes = match serde_json::to_vec(&wire) {
                    Ok(bytes) => Some(bytes),
                    Err(e) => {
                        tracing::error!(%correlation_id, error = %e, "reply failed to encode; answering a minimal 500");
                        serde_json::to_vec(&Reply::status(500).into_ingress(&correlation_id)).ok()
                    }
                };
                match bytes {
                    Some(bytes) => rq.publish(&bytes).await.is_ok(),
                    None => false,
                }
            }
            Err(e) => {
                tracing::error!(%correlation_id, %reply_to, error = %e, "rsx cannot open the reply channel");
                false
            }
        };
        if replied || lease.attempt >= MAX_REPLY_ATTEMPTS {
            if !replied {
                tracing::error!(
                    %correlation_id,
                    %reply_to,
                    attempt = lease.attempt,
                    "rsx settled an unanswerable request after exhausting its reply attempts"
                );
            }
            let _ = requests.ack(lease.token).await;
        }
    }
}

/// A framework-owned document: a real page with a head, so injected
/// head content (the stylesheet link) has somewhere to land.
fn framework_document(heading: &str, message: &str) -> Html {
    el("html")
        .child(
            el("head")
                .child(Html::raw(format!("<title>{}</title>", escape(heading))))
                .build(),
        )
        .child(
            el("body")
                .child(el("h1").text(heading).build())
                .child(el("p").text(message).build())
                .build(),
        )
        .build()
}

fn internal_error_page() -> Html {
    framework_document(
        "Something went wrong",
        "The server hit an internal error handling this request.",
    )
}

fn default_not_found_page() -> Html {
    framework_document("Not found", "No route serves this path.")
}

/// Finalize a DOCUMENT reply: link the app's stylesheet, set the content
/// type.
///
/// Every framework-produced document goes through here — pages, the
/// not-found boundary, the error boundaries — so a boundary cannot ship
/// without the styles its template declared, and a future one cannot
/// forget to.
fn document_reply(status: u16, document: String, stylesheet: Option<&'static str>) -> Reply {
    let document = match stylesheet {
        Some(css) if !css.is_empty() => meta::inject_head(&document, &assets::link(css)),
        _ => document,
    };
    Reply::status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(document.into_bytes())
}

fn error_reply(status: u16, page: Html, stylesheet: Option<&'static str>) -> Reply {
    document_reply(status, page.into_string(), stylesheet)
}

async fn not_found_reply(app: &RsxApp, rc: RouteCtx) -> Reply {
    let document = match &app.not_found {
        // Rendered through the SAME path a page takes, so the boundary
        // sits inside the site's chrome instead of arriving as a
        // fragment with no navigation and no styles.
        Some(entry) => match render_page(entry, &rc).await {
            Ok(rendered) => nav::compose(&rendered.shells, &rendered.content),
            Err(_) => default_not_found_page().into_string(),
        },
        None => default_not_found_page().into_string(),
    };
    document_reply(404, document, app.stylesheet)
}

/// Serve a 500 through the application's own error boundary when it has
/// one.
///
/// The boundary is rendered exactly like a page — inside its layout,
/// with the stylesheet — and is given no detail about the failure. If
/// the boundary ITSELF fails, the framework's plain document is served:
/// an error page that can fail into its own error page would be a loop.
async fn internal_error_reply(app: &RsxApp, rc: Option<RouteCtx>) -> Reply {
    if let (Some(entry), Some(rc)) = (&app.error_page, rc) {
        if let Ok(rendered) = render_page(entry, &rc).await {
            return document_reply(
                500,
                nav::compose(&rendered.shells, &rendered.content),
                app.stylesheet,
            );
        }
        tracing::error!("the application's error boundary failed; serving the framework page");
    }
    error_reply(500, internal_error_page(), app.stylesheet)
}

async fn abort_reply(app: &RsxApp, rc: RouteCtx, abort: Abort) -> Reply {
    match abort {
        Abort::NotFound => not_found_reply(app, rc).await,
        Abort::Redirect { location, status } => {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                tracing::error!(status, "rsx refused a non-redirect redirect status");
                return internal_error_reply(app, Some(rc)).await;
            }
            match Reply::status(status).try_header("location", location) {
                Ok(reply) => reply,
                Err(reason) => {
                    tracing::error!(%reason, "rsx refused an invalid redirect location");
                    internal_error_reply(app, Some(rc)).await
                }
            }
        }
        Abort::Unauthorized => error_reply(
            401,
            framework_document("Unauthorized", "This page needs you to sign in."),
            app.stylesheet,
        ),
        Abort::Forbidden => error_reply(
            403,
            framework_document("Forbidden", "This account cannot see this page."),
            app.stylesheet,
        ),
        Abort::Internal(detail) => {
            // The detail is server-side evidence only — never in the body.
            tracing::error!(%detail, "rsx page aborted internally");
            internal_error_reply(app, Some(rc)).await
        }
    }
}

fn path_error_reply(e: &PathError) -> Reply {
    Reply::text(e.status(), e.code())
}

/// The query bounds, applied identically to the original target and to
/// every middleware rewrite.
fn query_refusal(query: &str, limits: &Limits) -> Option<Reply> {
    if query.len() > limits.max_query_bytes {
        return Some(Reply::text(414, "query string too long"));
    }
    if parse_query(query).len() > limits.max_query_pairs {
        return Some(Reply::text(414, "too many query parameters"));
    }
    None
}

/// One rendered page, as the SEGMENT CHAIN a client patches.
///
/// Each layout is rendered once with a [`nav::HOLE`] where its children
/// go, so its hash describes its own chrome and not the page inside it.
/// It is serializable because a cached route stores exactly this — the
/// chain, not the finished document, so a cached render still answers
/// both a document request and a soft navigation.
#[derive(ferrite_app::serde::Serialize, ferrite_app::serde::Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct RenderedPage {
    /// Layout shells, root → leaf: `(segment id, html containing HOLE)`.
    shells: Vec<(String, String)>,
    /// The page's own segment id.
    page_id: String,
    /// The page's own html.
    content: String,
}

async fn render_page(entry: &PageEntry, pc: &RouteCtx) -> Result<RenderedPage, Abort> {
    let content = (entry.page)(pc.clone()).await?;
    let mut shells = Vec::with_capacity(entry.layouts.len());
    for l in &entry.layouts {
        let shell = (l.render)(pc.clone(), Html::raw(nav::HOLE)).await?;
        shells.push((l.id.clone(), shell.into_string()));
    }
    Ok(RenderedPage {
        shells,
        page_id: entry.id.clone(),
        content: content.into_string(),
    })
}

/// Render a page, through the cache when the route declares one.
///
/// An ABORT is never cached: a 404 or a redirect is a property of this
/// request, and storing one would serve it to everyone until the entry
/// expired. The abort is carried out of the closure and re-raised.
async fn render_page_cached(
    entry: &PageEntry,
    pc: &RouteCtx,
) -> Result<(RenderedPage, Freshness), Abort> {
    let Some(profile) = &entry.cache else {
        return render_page(entry, pc).await.map(|r| (r, Freshness::Miss));
    };
    if !pc.is_shared() {
        return render_page(entry, pc).await.map(|r| (r, Freshness::Miss));
    }
    let mut cache = pc
        .cache()
        .map_err(|e| Abort::Internal(format!("cache binding: {e}")))?;
    // Every render also carries a tag for its own URL, so one page can
    // be revalidated by path without knowing what it read — and without
    // taking its siblings with it. Room for it is RESERVED at build
    // time ([`RsxAppBuilder::build`] refuses a profile that leaves
    // none), so this can never silently drop the tag and leave a page
    // that `revalidate_path` cannot reach.
    let mut profile = profile.clone();
    let path_tag = Cache::path_tag(pc.path());
    if !profile.tags.contains(&path_tag) {
        profile.tags.push(path_tag);
    }
    let profile = &profile;
    // The key is NAMESPACED, carries the route's identity, AND names the
    // SLOT MODE. Without the mode, a soft navigation's shell (holes and
    // fallbacks) could be served later as a document — or a document's
    // fully resolved render could be served as a shell, defeating the
    // deferral. They are different renders and must be different
    // entries. The query is part of it too, since two URLs that render
    // differently must not share one.
    let mode = match pc.slot_mode() {
        SlotMode::Inline => "inline",
        SlotMode::Shell => "shell",
        SlotMode::Only(_) => "only",
    };
    let key = if pc.query_string().is_empty() {
        format!("render:{}:{mode}:{}", entry.id, pc.path())
    } else {
        format!(
            "render:{}:{mode}:{}?{}",
            entry.id,
            pc.path(),
            pc.query_string()
        )
    };
    let aborted: Arc<std::sync::Mutex<Option<Abort>>> = Arc::new(std::sync::Mutex::new(None));
    let sink = Arc::clone(&aborted);
    let outcome = cache
        .get_or_compute(&key, profile, || async {
            match render_page(entry, pc).await {
                Ok(rendered) => serde_json::to_vec(&rendered)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
                Err(abort) => {
                    *sink.lock().unwrap() = Some(abort);
                    Err(io::Error::other("render aborted"))
                }
            }
        })
        .await;
    match outcome {
        Ok(cached) => {
            let rendered: RenderedPage = serde_json::from_slice(&cached.value)
                .map_err(|e| Abort::Internal(format!("cached render: {e}")))?;
            Ok((rendered, cached.freshness))
        }
        Err(e) => match aborted.lock().unwrap().take() {
            Some(abort) => Err(abort),
            None => Err(Abort::Internal(e.to_string())),
        },
    }
}

/// Build the soft-navigation payload for a rendered page.
///
/// Shared by the page route and by an ACTION's inline refresh, so a
/// mutation's answer and a navigation's answer can never disagree about
/// the shape they produce.
fn build_payload(
    r: &RenderedPage,
    pc: &RouteCtx,
    metadata: Option<&Metadata>,
) -> nav::PagePayload {
    let layout_chain: Vec<(String, String)> = r
        .shells
        .iter()
        .map(|(id, html)| (id.clone(), nav::segment_hash(html)))
        .collect();
    let page_hash = nav::segment_hash(&r.content);
    let mut segments: Vec<nav::SegmentPayload> = layout_chain
        .iter()
        .map(|(id, hash)| nav::SegmentPayload {
            id: id.clone(),
            hash: hash.clone(),
        })
        .collect();
    segments.push(nav::SegmentPayload {
        id: r.page_id.clone(),
        hash: page_hash.clone(),
    });

    let layout_title = r
        .shells
        .iter()
        .find_map(|(_, html)| nav::document_title(html))
        .or_else(|| nav::document_title(&r.content));

    let have = nav::parse_have(pc.header(nav::HAVE_HEADER).unwrap_or(""));
    let shared = nav::shared_prefix(&layout_chain, &have);
    let mut payload = nav::PagePayload::new(pc.path(), segments);
    payload.head = match metadata {
        Some(m) if !m.is_empty() => {
            let mut head = m.payload_head();
            if head.title.is_none() {
                head.title = layout_title;
            }
            head
        }
        _ => nav::Head {
            title: layout_title,
            ..nav::Head::default()
        },
    };
    if shared > 0 {
        payload.patch_at = Some(layout_chain[shared - 1].0.clone());
        let page_unchanged = shared == layout_chain.len()
            && have
                .iter()
                .any(|(id, hash)| id == &r.page_id && hash == &page_hash);
        payload.html = if page_unchanged {
            None
        } else {
            Some(nav::compose(&r.shells[shared..], &r.content))
        };
    }
    payload
}

/// Serve a rendered page: a document, or a soft-navigation payload.
fn page_reply(
    r: RenderedPage,
    pc: &RouteCtx,
    metadata: Option<Metadata>,
    stylesheet: Option<&'static str>,
    islands: &'static [super::islands::Island],
) -> Reply {
    if pc.header(nav::NAV_HEADER).is_none() {
        let segments: Vec<nav::SegmentPayload> = r
            .shells
            .iter()
            .map(|(id, html)| nav::SegmentPayload {
                id: id.clone(),
                hash: nav::segment_hash(html),
            })
            .chain(std::iter::once(nav::SegmentPayload {
                id: r.page_id.clone(),
                hash: nav::segment_hash(&r.content),
            }))
            .collect();
        let document = nav::compose(&r.shells, &r.content);
        let document = match &metadata {
            Some(m) if !m.is_empty() => meta::inject_head(&document, m.head().as_str()),
            _ => document,
        };
        // The stylesheet link goes in the head of every DOCUMENT. A soft
        // navigation needs none: the document it patches already has it,
        // and the sheet covers every template rather than one page.
        let document = match stylesheet {
            Some(css) if !css.is_empty() => meta::inject_head(&document, &assets::link(css)),
            _ => document,
        };
        let state = serde_json::json!({
            "v": 1,
            "segments": segments,
            "islands": super::islands::manifest(islands),
        })
        .to_string();
        return Reply::status(200)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-rsx-stale", "0")
            .body(client::inject(&document, &state).into_bytes());
    }

    let payload = build_payload(&r, pc, metadata.as_ref());
    let body = match serde_json::to_vec(&payload) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "rsx could not serialize a page payload");
            return error_reply(500, internal_error_page(), stylesheet);
        }
    };
    let etag = nav::payload_etag(&body);
    if pc.header("if-none-match").map(str::trim) == Some(etag.as_str()) {
        return Reply::status(304)
            .header("etag", etag)
            .header("cache-control", "private, no-cache");
    }
    Reply::status(200)
        .header("content-type", "application/json")
        .header("etag", etag)
        .header("x-rsx-stale", "0")
        .header("cache-control", "private, no-cache")
        .body(body)
}

/// Re-render the page the client is LOOKING AT, for an action's inline
/// refresh.
///
/// A mutation changes what a page shows, so the client needs the new
/// render. Sending it WITH the action's answer makes that one round
/// trip instead of two — the discipline React Server Actions established
/// — and it cannot serve a stale render, because the action's cache
/// invalidation has already been applied by the time this runs.
///
/// The target is CALLER-SUPPLIED, so it takes the same admission a
/// navigation to that page would: a synthetic GET is put through the
/// whole middleware chain, and a guard that refuses it means no refresh
/// rather than a render the reader may not see. Anything else would
/// make an action a hole in every authorization middleware in the app.
async fn refresh_payload(
    app: &RsxApp,
    rc: &RouteCtx,
    ctx: &AppContext,
) -> Option<serde_json::Value> {
    let target = rc.header(nav::PATH_HEADER)?.to_string();
    let (path, raw_query) = split_path_query(&target);
    let mut canon = CanonicalPath::parse(&path, &app.limits.path).ok()?;
    let mut query = raw_query.unwrap_or_default();
    if query_refusal(&query, &app.limits).is_some() {
        return None;
    }

    // What a GET of that page would look like: same headers (so the
    // auth context and `x-rsx-have` travel), no body, GET method —
    // because middleware may legitimately branch on the method.
    let mut synthetic = (*rc.inner.req).clone();
    synthetic.method = "GET".to_string();
    synthetic.path = target;
    synthetic.body = Vec::new();
    let synthetic = Arc::new(synthetic);

    let mut pc = RouteCtx::new(
        ctx.clone(),
        Arc::clone(&synthetic),
        Params::empty(),
        canon.as_str().to_string(),
        query.clone(),
    );
    for mw in &app.middleware {
        match mw(pc.clone()).await {
            MwResult::Continue => {}
            MwResult::Rewrite(rewritten) => {
                let (p, q) = split_path_query(&rewritten);
                canon = CanonicalPath::parse(&p, &app.limits.path).ok()?;
                if let Some(new_query) = q {
                    if query_refusal(&new_query, &app.limits).is_some() {
                        return None;
                    }
                    query = new_query;
                }
                pc = RouteCtx::new(
                    ctx.clone(),
                    Arc::clone(&synthetic),
                    Params::empty(),
                    canon.as_str().to_string(),
                    query.clone(),
                );
            }
            // Refused. The mutation still happened — it was authorized
            // on its own terms — but its answer carries no render, and
            // the client falls back to fetching the page itself, where
            // it meets the same refusal properly.
            MwResult::Respond(_) => return None,
        }
    }

    let m = app.pages.match_segments(canon.segments())?;
    let pc = pc
        .with_params(m.params.clone())
        .with_slot_mode(SlotMode::Shell);
    // The page's own guard, on the SYNTHETIC GET: an action must not be
    // able to hand back a render its reader could not have fetched.
    if let Some(guard) = m.value.guard {
        guard.check(&pc).ok()?;
    }
    let metadata = m.value.metadata.as_ref().map(|f| f());
    let rendered = render_page_cached(m.value, &pc).await.ok()?.0;
    serde_json::to_value(build_payload(&rendered, &pc, metadata.as_ref())).ok()
}

/// Serve one action call.
///
/// Two entry shapes reach the same handler: the client runtime's JSON
/// fetch, and an ordinary browser `<form>` POST. The form path answers
/// a 303 redirect so a no-JavaScript client lands on a real page —
/// progressive enhancement, not a fallback nobody tests.
async fn action_reply(
    app: &RsxApp,
    ctx: &AppContext,
    id: &str,
    rc: &RouteCtx,
) -> Reply {
    if rc.method() != "POST" {
        return Reply::status(405).header("allow", "POST");
    }
    let Some(handler) = app.actions.get(id) else {
        return Reply::status(404)
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&ActionEnvelope::from(ActionError::new(
                    "not_found",
                    format!("no action named '{id}'"),
                )))
                .unwrap_or_default(),
            );
    };

    let content_type = rc.header("content-type").unwrap_or("").to_ascii_lowercase();
    let is_form = content_type.starts_with("application/x-www-form-urlencoded");
    let mut args = if is_form {
        action::parse_form(rc.body())
    } else if rc.body().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_slice(rc.body()) {
            Ok(value) => value,
            Err(e) => {
                return Reply::status(400)
                    .header("content-type", "application/json")
                    .body(
                        serde_json::to_vec(&ActionEnvelope::from(ActionError::new(
                            "invalid",
                            format!("the request body is not JSON: {e}"),
                        )))
                        .unwrap_or_default(),
                    )
            }
        }
    };

    // The action token, before anything runs or is recorded (see
    // `csrf`): a cross-site post is refused here, and a refusal is not
    // recorded under the idempotency key, so the reader's own retry with
    // the token is still admitted.
    let field = csrf::take_field(&mut args);
    let presented = if is_form { csrf::form_field(rc.body()) } else { field };
    if let Err(refusal) = csrf::check(&rc.request().headers, presented.as_deref(), csrf::Mode::of(rc.app())) {
        tracing::warn!(action = id, ?refusal, "rsx refused an action post");
        let envelope = ActionEnvelope::from(ActionError::new("csrf", refusal.message()));
        if is_form {
            return form_reply(&envelope, rc.header("referer"), "refused", app.stylesheet);
        }
        return Reply::status(envelope.http_status)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&envelope).unwrap_or_default());
    }

    // The caller the application says this invocation belongs to, if it
    // scopes invocations at all (see `RsxAppBuilder::action_scope`).
    let scope = match &app.action_scope {
        Some(resolve) => resolve(rc.clone()).await,
        None => None,
    };
    let (envelope, admission) =
        match action::run_action_scoped(handler, rc, id, args, scope.as_deref()).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(action = id, error = %e, "rsx could not run an action");
            (
                ActionEnvelope::from(ActionError::new("internal", "the action could not run")),
                action::Admission::Admitted,
            )
        }
    };

    // The tags the action expired are dropped from the SERVER cache
    // too, not just reported to the client: a mutation that only told
    // the browser would leave every other reader on stale data.
    //
    // This runs for REPLAYS as well as admissions, on purpose. Bumping
    // a tag twice invalidates what bumping it once does, and re-running
    // it here repairs the case where the admitted delivery committed
    // and then died before the cache heard about it.
    if !envelope.expired_tags.is_empty() {
        if let Ok(mut cache) = rc.cache() {
            let _ = cache.update_tags(&envelope.expired_tags).await;
        }
    }

    let admitted = match admission {
        action::Admission::Admitted => "admitted",
        action::Admission::Replayed => "replayed",
    };

    // The re-render happens AFTER the tag invalidation above, so it can
    // never serve the state the mutation just replaced.
    let mut envelope = envelope;
    if !is_form && !envelope.is_error() {
        envelope.refresh = refresh_payload(app, rc, ctx).await;
    }
    // The redirect target must be a LOCAL path on BOTH branches. The client
    // runtime assigns a JSON `redirect` to `location.href`, so an absolute
    // URL there is an open redirect and a `javascript:` one executes script.
    envelope.redirect = envelope.redirect.take().filter(|target| is_local_path(target));
    let envelope = envelope;

    if is_form {
        return form_reply(&envelope, rc.header("referer"), admitted, app.stylesheet);
    }

    // The HTTP status is the envelope's recorded one, for admitted and
    // replayed alike: a validation failure answered 200 would be a
    // success to every proxy, log and client that does not parse the
    // body.
    match serde_json::to_vec(&envelope) {
        Ok(body) => Reply::status(envelope.http_status)
            .header("content-type", "application/json")
            .header("x-rsx-admission", admitted)
            .body(body),
        Err(e) => {
            tracing::error!(action = id, error = %e, "an action envelope would not serialize");
            Reply::status(500)
        }
    }
}

/// `GET /_rsx/csrf`: the reader's action token as JSON, issuing one in the
/// token cookie when the reader holds none.
///
/// A cross-site page cannot read this reply (it is not CORS-readable), so
/// answering the token to whoever asks gives an attacker nothing it can use
/// against another reader: the token only counts beside the cookie this
/// reader's browser holds.
fn token_reply(req: &IngressRequest, mode: csrf::Mode) -> Reply {
    if req.method != "GET" {
        return Reply::status(405).header("allow", "GET");
    }
    let (token, issue) = match csrf::held(&req.headers, mode) {
        csrf::Held::One(token) => (token, false),
        _ => (csrf::mint(), true),
    };
    let body = serde_json::json!({ "v": 1, "token": token }).to_string();
    let reply = Reply::status(200)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    let reply = if issue {
        reply.header("set-cookie", csrf::set_cookie(&token, mode))
    } else {
        reply
    };
    reply.body(body.into_bytes())
}

/// Give an HTML reply the reader's action token: issue it in the token
/// cookie when the reader holds none, and write it into every action form
/// (see [`csrf::inject_forms`]).
///
/// Applied to every reply on its way out, after any render cache, so a
/// cached document is shared token-free and each reader's copy carries that
/// reader's token. A reply that already sets a cookie is not given a second
/// one (the gateway relays one `set-cookie` per reply), and then its forms
/// carry a token only if the reader already held one; the client runtime
/// asks `/_rsx/csrf` for one before it posts. `mode` names the cookie.
fn seal_document(mut reply: Reply, held: &csrf::Held, mode: csrf::Mode) -> Reply {
    let is_html = reply.headers.iter().any(|(n, v)| {
        n == "content-type" && v.trim_start().to_ascii_lowercase().starts_with("text/html")
    });
    if reply.refusal.is_some() || !is_html || reply.body.is_empty() {
        return reply;
    }
    let sets_cookie = reply.headers.iter().any(|(n, _)| n == "set-cookie");
    let (token, mut personal) = match held {
        csrf::Held::One(token) => (token.clone(), false),
        _ if sets_cookie => return reply,
        _ => {
            let token = csrf::mint();
            reply.headers.push(("set-cookie".to_string(), csrf::set_cookie(&token, mode)));
            (token, true)
        }
    };
    if let Ok(html) = std::str::from_utf8(&reply.body) {
        if let Some(sealed) = csrf::inject_forms(html, &token) {
            reply.body = sealed.into_bytes();
            personal = true;
        }
    }
    // The document now carries one reader's token: no shared cache may
    // keep it.
    if personal && !reply.headers.iter().any(|(n, _)| n == "cache-control") {
        reply.headers.push(("cache-control".to_string(), "private".to_string()));
    }
    reply
}

/// The answer to an ordinary browser `<form>` POST, which has no client
/// runtime to read an envelope.
///
/// A successful action sends the browser somewhere real with a 303: the
/// action's own redirect when it set one, otherwise back to the page that
/// posted. A refused action answers the envelope's status with a document
/// that shows the message, every field message and a link back, because a
/// 303 would drop the error and leave a browser without JavaScript with
/// no idea why nothing was stored.
fn form_reply(
    envelope: &ActionEnvelope,
    referer: Option<&str>,
    admitted: &str,
    stylesheet: Option<&'static str>,
) -> Reply {
    let back = referer
        .and_then(referer_return_path)
        .unwrap_or_else(|| "/".to_string());
    if envelope.is_error() {
        let (message, fields) = match &envelope.error {
            Some(error) => (error.message.as_str(), &error.fields),
            None => ("The action was refused.", &BTreeMap::new()),
        };
        let mut body = el("body")
            .child(el("h1").text("That did not go through").build())
            .child(el("p").text(message).build());
        if !fields.is_empty() {
            let mut list = el("ul");
            for (field, problem) in fields {
                list = list.child(el("li").text(format!("{field}: {problem}")).build());
            }
            body = body.child(list.build());
        }
        body = body.child(
            el("p")
                .child(el("a").attr("href", &back).text("Go back and try again").build())
                .build(),
        );
        let page = el("html")
            .child(
                el("head")
                    .child(Html::raw("<title>That did not go through</title>"))
                    .build(),
            )
            .child(body.build())
            .build();
        let status = if (400..=599).contains(&envelope.http_status) {
            envelope.http_status
        } else {
            422
        };
        return document_reply(status, page.into_string(), stylesheet)
            .header("x-rsx-admission", admitted);
    }
    // The target must be a LOCAL path: reflecting a caller-controlled
    // referer into `location` as it stands is an open redirect.
    let location = envelope
        .redirect
        .clone()
        .filter(|target| is_local_path(target))
        .unwrap_or(back);
    Reply::status(303)
        .header("location", location)
        .header("x-rsx-admission", admitted)
}

/// The local path a no-JavaScript form post returns to, from its referer.
///
/// Browsers send the referer as an absolute URL, which `is_local_path`
/// rightly refuses, so a post always landed on `/`. Only the path and
/// query are taken (the fragment never reaches a server's `location`),
/// and only when they form a local path: whatever host the referer names,
/// the browser is sent to a path on THIS origin, so no referer can make
/// the reply an open redirect.
fn referer_return_path(referer: &str) -> Option<String> {
    let path = if referer.starts_with('/') {
        referer
    } else {
        let rest = referer
            .strip_prefix("https://")
            .or_else(|| referer.strip_prefix("http://"))?;
        &rest[rest.find('/')?..]
    };
    let path = path.split('#').next().unwrap_or("");
    is_local_path(path).then(|| path.to_string())
}

/// Whether a redirect target stays inside this application.
///
/// A same-origin PATH only: `//evil.example` is a protocol-relative URL
/// the browser reads as another origin, and `\\` is treated as `//` by
/// several parsers.
fn is_local_path(target: &str) -> bool {
    // Any control character is refused, not only CR and LF: a URL parser
    // strips tabs and newlines, so `/\t/evil.example` reaches the browser
    // as `//evil.example`.
    target.starts_with('/')
        && !target.starts_with("//")
        && !target.starts_with("/\\")
        && !target.chars().any(|c| c.is_ascii_control())
}

async fn dispatch(app: Arc<RsxApp>, ctx: AppContext, req: Arc<IngressRequest>) -> Reply {
    let limits = &app.limits;

    if req.body.len() > limits.max_body_bytes {
        return Reply::text(413, "request body too large");
    }

    let (raw_path, raw_query) = split_path_query(&req.path);
    let mut query = raw_query.unwrap_or_default();
    if let Some(refusal) = query_refusal(&query, limits) {
        return refusal;
    }
    let mut canon = match CanonicalPath::parse(&raw_path, &limits.path) {
        Ok(c) => c,
        Err(e) => return path_error_reply(&e),
    };

    // The client runtime is framework-owned and served before middleware:
    // an application's auth guard must not be able to withhold the script
    // that makes its own pages navigable.
    if client::is_client_asset(canon.as_str()) {
        return client::client_reply(canon.as_str());
    }
    // The stylesheet, for the same reason: a page served without its
    // styles looks broken, and a guard has no business gating it.
    if let Some(css) = app.stylesheet {
        if !css.is_empty() && assets::is_stylesheet(canon.as_str()) {
            return assets::stylesheet_reply(css, canon.as_str());
        }
    }
    // Island modules, for the same reason and in the same position: a
    // page whose interactive parts are gated behind an auth check would
    // render and then never hydrate.
    if !app.islands.is_empty() {
        if let Some(reply) = super::islands::serve(app.islands, &req.method, canon.as_str()) {
            return reply;
        }
    }
    // Files the author put in `public/`. Before routing, so a catch-all
    // page cannot shadow an image, and before middleware for the same
    // reason the stylesheet is: a logo is not a protected resource, and
    // a guard that hid it would only break the page it guards.
    if !app.public.is_empty() {
        if let Some(reply) = super::public::serve(
            app.public,
            &req.method,
            canon.as_str(),
            req.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("if-none-match"))
                .map(|(_, v)| v.as_str()),
        ) {
            return reply;
        }
    }

    // The reader's action token, for a client runtime that has no cookie
    // to read it from. Framework-owned and served before middleware, like
    // the client runtime it exists for.
    if canon.as_str() == csrf::TOKEN_PATH {
        return token_reply(&req, csrf::Mode::of(&ctx));
    }

    let mut rc = RouteCtx::new(
        ctx.clone(),
        Arc::clone(&req),
        Params::empty(),
        canon.as_str().to_string(),
        query.clone(),
    );

    // Middleware chain (pre-routing; registration order). Every rewrite
    // is re-canonicalized, so a rewrite cannot smuggle a path the
    // canonicalizer would have refused.
    for mw in &app.middleware {
        match mw(rc.clone()).await {
            MwResult::Continue => {}
            MwResult::Rewrite(target) => {
                let (p, q) = split_path_query(&target);
                canon = match CanonicalPath::parse(&p, &limits.path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(target = %target, code = e.code(), "rsx refused a middleware rewrite");
                        return path_error_reply(&e);
                    }
                };
                if let Some(new_query) = q {
                    // A rewritten query is caller-influenced too: it takes
                    // the SAME bounds, pair count included.
                    if let Some(refusal) = query_refusal(&new_query, limits) {
                        return refusal;
                    }
                    query = new_query;
                }
                rc = RouteCtx::new(
                    ctx.clone(),
                    Arc::clone(&req),
                    Params::empty(),
                    canon.as_str().to_string(),
                    query.clone(),
                );
            }
            MwResult::Respond(reply) => return reply,
        }
    }

    // A slot request: re-render the page resolving exactly one
    // boundary. Stateless by construction — nothing is held between the
    // shell and the hole, so a slot can be fetched minutes later, by a
    // different instance, after a restart.
    if let Some(slot_id) = canon.as_str().strip_prefix("/_rsx/slot/") {
        let slot_id = slot_id.to_string();
        if req.method != "GET" {
            return Reply::status(405).header("allow", "GET");
        }
        let raw_target = rc.query_param("path").unwrap_or_else(|| "/".to_string());
        let (target_path, raw_target_query) = split_path_query(&raw_target);
        let mut target = match CanonicalPath::parse(&target_path, &limits.path) {
            Ok(c) => c,
            Err(e) => return path_error_reply(&e),
        };
        let mut target_query = raw_target_query.unwrap_or_default();
        if let Some(refusal) = query_refusal(&target_query, limits) {
            return refusal;
        }

        let mut synthetic = (*req).clone();
        synthetic.method = "GET".to_string();
        synthetic.path = raw_target;
        synthetic.body = Vec::new();
        let synthetic = Arc::new(synthetic);

        let mut sc = RouteCtx::new(
            ctx.clone(),
            Arc::clone(&synthetic),
            Params::empty(),
            target.as_str().to_string(),
            target_query.clone(),
        );
        for mw in &app.middleware {
            match mw(sc.clone()).await {
                MwResult::Continue => {}
                MwResult::Rewrite(rewritten) => {
                    let (p, q) = split_path_query(&rewritten);
                    target = match CanonicalPath::parse(&p, &limits.path) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!(target = %rewritten, code = e.code(), "rsx refused a slot middleware rewrite");
                            return path_error_reply(&e);
                        }
                    };
                    if let Some(new_query) = q {
                        if let Some(refusal) = query_refusal(&new_query, limits) {
                            return refusal;
                        }
                        target_query = new_query;
                    }
                    sc = RouteCtx::new(
                        ctx.clone(),
                        Arc::clone(&synthetic),
                        Params::empty(),
                        target.as_str().to_string(),
                        target_query.clone(),
                    );
                }
                MwResult::Respond(reply) => return reply,
            }
        }

        let Some(m) = app.pages.match_segments(target.segments()) else {
            return Reply::status(404).header("content-type", "application/json");
        };
        let sc = sc
            .with_params(m.params.clone())
            .with_slot_mode(SlotMode::Only(slot_id.clone()));
        // A region of a guarded page is guarded: resolving a slot is
        // rendering that page.
        if let Some(guard) = m.value.guard {
            if let Err(abort) = guard.check(&sc) {
                return abort_reply(&app, sc, abort).await;
            }
        }
        return match render_page(m.value, &sc).await {
            Ok(_) => match sc.take_slot() {
                Some(html) => Reply::status(200)
                    .header("content-type", "application/json")
                    .header("cache-control", "private, no-cache")
                    .body(
                        serde_json::to_vec(&serde_json::json!({ "v": 1, "html": html }))
                            .unwrap_or_default(),
                    ),
                // The page rendered but has no such boundary: 410, the
                // client falls back to a full payload refetch.
                None => Reply::status(410).header("content-type", "application/json"),
            },
            Err(abort) => abort_reply(&app, sc, abort).await,
        };
    }

    // The two resources a crawler asks for before anything else. They
    // are served only when the app DECLARED its base URL, because both
    // of them state where the site lives.
    if let Some(site) = &app.site {
        match canon.as_str() {
            "/robots.txt" if req.method == "GET" => {
                let sitemap = format!("{}/sitemap.xml", site.trim_end_matches('/'));
                return Reply::status(200)
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(meta::robots_txt(Some(&sitemap), &[]).into_bytes());
            }
            "/sitemap.xml" if req.method == "GET" => {
                return Reply::status(200)
                    .header("content-type", "application/xml; charset=utf-8")
                    .body(meta::sitemap_xml(site, &app.static_paths).into_bytes());
            }
            _ => {}
        }
    }

    // Actions are addressed by id at the framework's own route. They are
    // resolved from the FINAL canonical path — after every middleware
    // rewrite — so a rewrite away from an action does not still run it,
    // and a rewrite INTO one does. They sit outside the page/handler
    // routers because an action is not a URL: it must not be reachable
    // by navigating, prefetching or crawling.
    if let Some(id) = canon.as_str().strip_prefix(action::ACTION_PREFIX) {
        let id = id.to_string();
        return action_reply(&app, &ctx, &id, &rc).await;
    }

    // Route resolution is GLOBAL: the most specific shape across BOTH
    // tables owns the path, and only then does the method choose between
    // a handler and a page at that shape. Checking handlers first would
    // let a catch-all handler shadow a static page (ALY-ROUTE-001).
    let segments = canon.segments();
    let handler_hit = app.handlers.match_segments(segments);
    let page_hit = app.pages.match_segments(segments);

    let best = match (&handler_hit, &page_hit) {
        (Some(h), Some(p)) => Some(h.spec.clone().min(p.spec.clone())),
        (Some(h), None) => Some(h.spec.clone()),
        (None, Some(p)) => Some(p.spec.clone()),
        (None, None) => None,
    };
    let Some(best) = best else {
        return not_found_reply(&app, rc).await;
    };

    let handler_at_best = handler_hit.as_ref().filter(|h| h.spec == best);
    let page_at_best = page_hit.as_ref().filter(|p| p.spec == best);

    if let Some(m) = handler_at_best {
        if m.value.methods.iter().any(|allowed| allowed == &req.method) {
            let hc = rc.with_params(m.params.clone());
            let hc_for_error = hc.clone();
            return match (m.value.f)(hc).await {
                Ok(reply) => reply,
                Err(e) => {
                    tracing::error!(error = %e, path = %canon.as_str(), "rsx handler failed");
                    internal_error_reply(&app, Some(hc_for_error)).await
                }
            };
        }
    }

    if let Some(m) = page_at_best {
        if req.method == "GET" {
            // A document resolves every boundary; a soft navigation
            // sends the shell and lets the client fill it.
            let mode = if rc.header(nav::NAV_HEADER).is_some() {
                SlotMode::Shell
            } else {
                SlotMode::Inline
            };
            let pc = rc.with_params(m.params.clone()).with_slot_mode(mode);
            let entry = m.value;
            // The guard is checked HERE — before the render cache is
            // consulted. Inside the render it would be skipped on a
            // cache hit, so an entry stored while the route was open
            // could still be served after it was closed.
            if let Some(guard) = entry.guard {
                if let Err(abort) = guard.check(&pc) {
                    return abort_reply(&app, pc, abort).await;
                }
            }
            // Metadata is a pure declaration, so it is computed outside
            // the render cache: caching it would gain nothing and could
            // serve one page's head with another's body.
            let metadata = entry.metadata.as_ref().map(|f| f());
            return match render_page_cached(entry, &pc).await {
                Ok((rendered, freshness)) => {
                    page_reply(rendered, &pc, metadata, app.stylesheet, app.islands)
                        .header("x-rsx-cache", freshness.header())
                }
                Err(abort) => abort_reply(&app, pc, abort).await,
            };
        }
    }

    // The winning shape exists but serves no such method: 405 with the
    // allow set of THAT shape.
    if handler_at_best.is_some() || page_at_best.is_some() {
        let mut allow: BTreeSet<String> = handler_at_best
            .map(|m| m.value.methods.iter().cloned().collect())
            .unwrap_or_default();
        if page_at_best.is_some() {
            allow.insert("GET".to_string());
        }
        let allow: Vec<String> = allow.into_iter().collect();
        return Reply::status(405).header("allow", allow.join(", "));
    }

    not_found_reply(&app, rc).await
}

#[cfg(test)]
mod redirect_tests {
    use super::is_local_path;

    /// F190: the one rule both action branches apply to `redirect`.
    #[test]
    fn only_a_path_inside_the_application_is_a_redirect_target() {
        for ok in ["/", "/orders/42", "/search?q=a%20b#top"] {
            assert!(is_local_path(ok), "{ok}");
        }
        for bad in [
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            "/\t/evil.example/",
            "/\n/evil.example/",
            "/\r/evil.example/",
            "javascript:alert(1)",
            "data:text/html,x",
            "orders/42",
            "",
        ] {
            assert!(!is_local_path(bad), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    const T: &str = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
    const FORM: &str = "<form method=\"post\" action=\"/_rsx/action/save\"></form>";

    fn page() -> Reply {
        Reply::status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(FORM.as_bytes().to_vec())
    }

    fn cookies(reply: &Reply) -> Vec<&str> {
        reply
            .headers
            .iter()
            .filter(|(n, _)| n == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect()
    }

    #[test]
    fn a_reader_without_a_token_is_issued_one_and_the_form_carries_it() {
        let sealed = seal_document(page(), &csrf::Held::None, csrf::Mode::Deployed);
        let issued = cookies(&sealed);
        assert_eq!(issued.len(), 1);
        let token = &issued[0]["__Host-rsx_csrf=".len().."__Host-rsx_csrf=".len() + 64];
        let html = String::from_utf8(sealed.body.clone()).unwrap();
        assert!(html.contains(&format!("value=\"{token}\"")), "{html}");
        assert!(sealed.headers.iter().any(|(n, v)| n == "cache-control" && v == "private"));
    }

    #[test]
    fn a_local_dev_document_issues_the_cookie_a_browser_keeps_over_http() {
        let sealed = seal_document(page(), &csrf::Held::None, csrf::Mode::LocalDev);
        let issued = cookies(&sealed);
        assert_eq!(issued.len(), 1);
        let token = &issued[0]["rsx_csrf_dev=".len().."rsx_csrf_dev=".len() + 64];
        assert_eq!(issued[0], csrf::set_cookie(token, csrf::Mode::LocalDev));
        assert!(String::from_utf8(sealed.body.clone()).unwrap().contains(&format!("value=\"{token}\"")));
    }

    #[test]
    fn a_held_token_is_written_in_and_not_reissued() {
        let sealed = seal_document(page(), &csrf::Held::One(T.to_string()), csrf::Mode::Deployed);
        assert!(cookies(&sealed).is_empty());
        assert!(String::from_utf8(sealed.body).unwrap().contains(T));
    }

    #[test]
    fn a_reply_that_sets_its_own_cookie_is_not_given_a_second() {
        let own = page().header("set-cookie", "session=abc; Path=/");
        let sealed = seal_document(own, &csrf::Held::None, csrf::Mode::Deployed);
        assert_eq!(cookies(&sealed), vec!["session=abc; Path=/"], "one set-cookie per reply");
        assert_eq!(sealed.body, FORM.as_bytes(), "and no token it could not issue");
    }

    #[test]
    fn a_reply_that_is_not_a_document_is_left_alone() {
        let json = Reply::status(200)
            .header("content-type", "application/json")
            .body(FORM.as_bytes().to_vec());
        let sealed = seal_document(json, &csrf::Held::None, csrf::Mode::Deployed);
        assert!(cookies(&sealed).is_empty());
        assert_eq!(sealed.body, FORM.as_bytes());
    }
}

#[cfg(test)]
mod form_reply_tests {
    use super::*;

    fn header<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
        reply
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn succeeded(redirect: Option<&str>) -> ActionEnvelope {
        ActionEnvelope {
            v: 1,
            status: "ok".to_string(),
            result: serde_json::Value::Null,
            error: None,
            saga_id: None,
            http_status: 200,
            expired_tags: Vec::new(),
            redirect: redirect.map(str::to_string),
            refresh: None,
        }
    }

    /// Browsers send the referer as an absolute URL. A native post from
    /// an album page must come back to that album, not to `/`.
    #[test]
    fn a_native_post_returns_to_the_page_that_posted_it() {
        let reply = form_reply(
            &succeeded(None),
            Some("https://beats.example/albums/7?sort=new#top"),
            "admitted",
            None,
        );
        assert_eq!(reply.status, 303);
        assert_eq!(header(&reply, "location"), Some("/albums/7?sort=new"));
        assert_eq!(header(&reply, "x-rsx-admission"), Some("admitted"));
    }

    /// Only the referer's path is reused, and only when it is a local
    /// path: whatever host it names, the browser stays on this origin.
    #[test]
    fn a_referer_never_sends_the_browser_off_this_origin() {
        for hostile in [
            "https://evil.example//evil.example/",
            "https://evil.example/\\evil.example/",
            "javascript:alert(1)",
            "//evil.example/",
            "https://evil.example",
            "not a url",
        ] {
            let reply = form_reply(&succeeded(None), Some(hostile), "admitted", None);
            assert_eq!(header(&reply, "location"), Some("/"), "{hostile:?}");
        }
        let reply = form_reply(
            &succeeded(None),
            Some("https://evil.example/rooms/3"),
            "admitted",
            None,
        );
        assert_eq!(header(&reply, "location"), Some("/rooms/3"));
    }

    #[test]
    fn an_action_redirect_wins_over_the_referer() {
        let reply = form_reply(
            &succeeded(Some("/rooms/9")),
            Some("https://huddle.example/rooms/3"),
            "replayed",
            None,
        );
        assert_eq!(header(&reply, "location"), Some("/rooms/9"));
        assert_eq!(header(&reply, "x-rsx-admission"), Some("replayed"));
    }

    /// A refused native post used to answer 303 to `/` and drop the
    /// error, so a browser without JavaScript never learned why nothing
    /// was stored. It now answers the envelope's status with a page
    /// that shows the message, every field message, and a way back.
    #[test]
    fn a_refused_native_post_shows_its_error_instead_of_redirecting() {
        let envelope = ActionEnvelope::from(
            ActionError::new("invalid", "Check the <form>")
                .field("title", "required"),
        );
        let reply = form_reply(
            &envelope,
            Some("https://flow.example/week/2026-10-19"),
            "admitted",
            None,
        );
        assert_eq!(reply.status, envelope.http_status);
        assert!(reply.status >= 400, "{}", reply.status);
        assert_eq!(header(&reply, "location"), None);
        assert_eq!(
            header(&reply, "content-type"),
            Some("text/html; charset=utf-8")
        );
        let body = String::from_utf8(reply.body.clone()).expect("utf-8");
        assert!(body.contains("Check the &lt;form&gt;"), "{body}");
        assert!(!body.contains("<form>"), "{body}");
        assert!(body.contains("title"), "{body}");
        assert!(body.contains("required"), "{body}");
        assert!(body.contains("href=\"/week/2026-10-19\""), "{body}");
    }
}

#[cfg(test)]
mod live_prefix_tests {
    use super::{has_delimited_prefix, source_admitted};

    /// PR #609: a source covers its own subject and what lies under it,
    /// never a longer subject that merely shares its spelling.
    #[test]
    fn a_prefix_matches_only_on_a_subject_boundary() {
        for (value, prefix) in [
            ("room:general", "room:"),
            ("room:general", "room"),
            ("room:general", "room:general"),
            ("room:general:pins", "room:general"),
            ("feed/a/b", "feed/a"),
            ("feed/a/b", "feed/"),
        ] {
            assert!(has_delimited_prefix(value, prefix), "{value} under {prefix}");
        }
        for (value, prefix) in [
            ("room:general", "room:gen"),
            ("room:10", "room:1"),
            ("roomba:x", "room"),
            ("feed/ab", "feed/a"),
            ("room", "room:"),
        ] {
            assert!(!has_delimited_prefix(value, prefix), "{value} under {prefix}");
        }
    }

    #[test]
    fn a_subscription_must_name_a_subject_not_the_family() {
        // finding_0735440cb862c422
        for (source, prefix) in [("room:", "room:"), ("room", "room"), ("room:1:", "room:"), ("feed/", "feed/")] {
            assert!(!source_admitted(source, prefix), "{source} under {prefix}");
        }
        for (source, prefix) in [("room:general", "room:"), ("room:1", "room"), ("room:1:pins", "room:")] {
            assert!(source_admitted(source, prefix), "{source} under {prefix}");
        }
    }
}

#[cfg(test)]
mod slot_middleware_tests {
    use super::*;

    #[tokio::test]
    async fn slot_endpoint_enforces_path_scoped_middleware_on_target_path() {
        let env = ferrite_app_test::TestHarness::new().build().await;
        let ctx = ferrite_app::AppContext::new(env.payload().clone());
        let app = Arc::new(
            RsxApp::builder()
                .middleware(middleware(|rc| async move {
                    if rc.path().starts_with("/admin") {
                        MwResult::Respond(Reply::status(403).body(b"denied".to_vec()))
                    } else if rc.path() == "/legacy" {
                        MwResult::Rewrite("/public".to_string())
                    } else {
                        MwResult::Continue
                    }
                }))
                .page(
                    "/admin/secret",
                    Vec::new(),
                    page(|rc| async move {
                        if matches!(rc.slot_mode(), SlotMode::Only(id) if id == "s1") {
                            rc.record_slot("<p>CLASSIFIED_SLOT</p>");
                        }
                        Ok(Html::raw("<div>admin</div>"))
                    }),
                )
                .page(
                    "/public",
                    Vec::new(),
                    page(|rc| async move {
                        if matches!(rc.slot_mode(), SlotMode::Only(id) if id == "s1") {
                            rc.record_slot("<p>PUBLIC_SLOT</p>");
                        }
                        Ok(Html::raw("<div>public</div>"))
                    }),
                )
                .build()
                .expect("valid app"),
        );

        let bypass = Arc::new(IngressRequest::new(
            "GET",
            "/_rsx/slot/s1?path=/admin/secret",
            Vec::new(),
        ));
        let reply = dispatch(Arc::clone(&app), ctx.clone(), bypass).await;
        assert_eq!(
            reply.status, 403,
            "/_rsx/slot/s1?path=/admin/secret must not bypass /admin middleware"
        );
        assert!(
            !String::from_utf8_lossy(&reply.body).contains("CLASSIFIED_SLOT"),
            "protected slot markup leaked: {}",
            String::from_utf8_lossy(&reply.body)
        );

        let rewritten = Arc::new(IngressRequest::new(
            "GET",
            "/_rsx/slot/s1?path=/legacy",
            Vec::new(),
        ));
        let ok = dispatch(Arc::clone(&app), ctx, rewritten).await;
        assert_eq!(ok.status, 200);
        assert!(String::from_utf8_lossy(&ok.body).contains("PUBLIC_SLOT"));
        assert!(ok
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cache-control") && v == "private, no-cache"));
    }
}
