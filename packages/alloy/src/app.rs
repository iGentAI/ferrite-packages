//! **The runtime shell**: the loop, the reserved faces, and the ordering
//! rules every Alloy application was writing for itself.
//!
//! Why the reply is published before the lease is acked is a property of the
//! platform's queue contract, not of any application, so it lives here once.
//!
//! # What the shell owns
//!
//! - the competing-consumer loop over the request queue;
//! - decoding the ingress envelope, and settling a frame that is not one;
//! - **publishing the reply before acking the lease**;
//! - interleaving the outbox drain without starving the request loop;
//! - rendering a [`AlloyError`] as an RFC 9457 problem document;
//! - assembling a document from the prerendered shell.
//!
//! # What the application owns
//!
//! One `answer` function from a request to a reply. Everything above is
//! machinery; that function is the app.
//!
//! # Why the ordering is the shell's business
//!
//! Acking a lease before the reply is published turns a transient
//! reply-plane failure into a LOST REQUEST: the gateway waits out its
//! deadline while redelivery — the one mechanism that could still answer —
//! has already been suppressed. An application author has no reason to
//! derive that, and every reason to get it wrong.

use ferrite_app::client::QueueClusterClient;
use ferrite_app::tracing;
use ferrite_app::{serde_json, AppContext, IngressReply, IngressRequest};

use crate::alloy::document::{
    LoaderPayload, Metadata, Shell, BODY_MARKER, DATA_SCRIPT_EMPTY, HEAD_MARKER,
};
use crate::alloy::error::{AlloyError, Result};
use crate::alloy::outbox::OutboxDrain;
use crate::alloy::router::{ParamValue, Params, RenderMode, Route};

/// How long the loop may go without draining the outbox.
///
/// An idle loop drains for free, but an app under sustained load never
/// idles, and an effect must not wait for a lull that may never come.
pub const DRAIN_INTERVAL_MS: u64 = 1_000;

/// How many handled requests may pass before the outbox is drained.
///
/// The interval floor depends on the clock advancing between iterations.
/// Counting requests is a second, entirely clock-independent trigger: under
/// a frozen or coarse clock — a simulated run, a harness, a suspended
/// instance — this is the one that fires.
pub const DRAIN_EVERY_N_REQUESTS: u32 = 8;

/// How many budget-truncated drain passes may run back to back.
///
/// A truncated pass means work is still waiting, so coming straight back is
/// right — but only up to a point. Chaining without a ceiling would let a
/// large backlog run a full budget of effects for every ONE request polled,
/// which is the same starvation the per-pass budget was meant to prevent.
pub const MAX_CHAINED_PASSES: u32 = 2;

/// One Alloy application.
///
/// The associated constants, optional build hooks and the single `answer`
/// function are the whole surface: an application that implements this gets
/// the loop, the ordering and the drain without writing any of them.
pub trait AlloyApp: Send + Sync + 'static {
    /// The build id carried in every payload, so a client holding a stale
    /// bundle can detect skew.
    const BUILD: &'static str;

    /// The prerendered shell this app substitutes into.
    const SHELL: &'static str;

    /// The build-time HTML body for one route, when that route was
    /// prerendered.
    ///
    /// The shell must carry exactly one [`BODY_MARKER`] between its head and
    /// data markers. Returning `None` preserves the shell byte-for-byte, so
    /// existing applications and Hybrid/Spa routes need no migration. The
    /// returned HTML is trusted build output, not request data; the runtime
    /// still refuses any body that reproduces one of its reserved markers so
    /// a generated page cannot capture metadata or loader-data substitution.
    fn prerendered_body(_route_id: &str) -> Option<&'static str> {
        None
    }

    /// Whether a browser navigation that misses gets this app's document.
    ///
    /// When `answer` returns [`AlloyError::NotFound`] for a `GET`/`HEAD` whose
    /// `Accept` names `text/html`, outside the reserved `/__*` faces, the
    /// runtime renders the shell for route id `not_found` (with
    /// `{ "path": <path> }` as its data, [`Self::prerendered_body`] applied)
    /// and answers 404. Every other caller — an agent asking for JSON, the
    /// loader and action faces, a POST — still receives the RFC 9457 problem.
    ///
    /// Off by default, because it is only correct for an app whose client
    /// renders a not-found screen for an unknown route. A client-routed app
    /// that does (Flow's `NotFoundScreen`, for one) otherwise shows a visitor
    /// who mistypes a URL a raw JSON document.
    const NOT_FOUND_DOCUMENT: bool = false;

    /// The APE handle holding the tag epochs, markers and outbox.
    const TAGS: &'static str = "tags";

    /// The store handle the drain takes its shard leases in.
    const LEASES: &'static str = "cache";

    /// The queue handle carrying ingress requests.
    const REQUESTS: &'static str = "requests";

    /// Optional owned HTTP budget admission, before replay, assets and handlers.
    /// Returning a reply refuses dispatch through the normal publish/ack path.
    /// Applications without a declared owned budget retain the default behavior.
    fn request_budget(
        _ctx: &AppContext,
        _req: &IngressRequest,
    ) -> impl std::future::Future<Output = Option<IngressReply>> + Send {
        async { None }
    }

    /// The blob handle the gateway's content routes read (the site plane).
    const SITE: &'static str = "site";

    /// The public path prefix the app's frontend assets are served under, the
    /// same prefix the manifest's content route declares.
    ///
    /// The gateway consults a content route only when no api route matched,
    /// so an app whose api route is `/` receives `GET /assets/*` itself, and
    /// the shell answers those requests BEFORE [`Self::answer`] runs: from the
    /// packed archive when the app ships one, otherwise from the [`Self::SITE`]
    /// blob. They are answered without a session, because a script tag cannot
    /// present one and these files are the same for every visitor. Nothing
    /// outside this prefix is served this way. Empty switches it off.
    const ASSET_PREFIX: &'static str = "/assets/";

    /// The blob key prefix the manifest's content route declares
    /// (`key_prefix`), applied when an asset is read from the site blob.
    const ASSET_KEY_PREFIX: &'static str = "";

    /// The packed frontend `alloy-gen --pack-assets` emitted into
    /// `src/generated/assets.rs`, as base64 chunks of the LZSS archive.
    /// Empty means the app ships no packed assets and boot seeds nothing —
    /// the default, so an API-only app declares nothing.
    const ASSETS_B64: &'static [&'static str] = &[];

    /// The packed archive's raw (decompressed) byte length.
    const ASSETS_LEN: usize = 0;

    /// Whether a [`RenderMode::Static`] route may be offered to SHARED
    /// caches.
    ///
    /// Off by default, deliberately: `public` on a document that turns out
    /// to be per-viewer is one user's page served to another, which is the
    /// worst defect the document path can have. An app opts in only when it
    /// knows its static routes are viewer-independent, and even then only
    /// routes that also declare a [`Route::with_cache_life`] are offered.
    const PUBLIC_STATIC: bool = false;

    /// Origins other than the request's own host that may invoke actions.
    ///
    /// Empty by default: an action face that answered any origin would let
    /// any page on the web POST a mutation with the victim's cookies. Each
    /// entry is a full origin (`https://admin.example.com`) or a bare host
    /// (`admin.example.com`); requests carrying no `Origin` header pass
    /// regardless, because a non-browser client sends none and gains
    /// nothing by forging one.
    const ALLOWED_ACTION_ORIGINS: &'static [&'static str] = &[];

    /// Answer one request.
    fn answer(
        ctx: &AppContext,
        req: &IngressRequest,
    ) -> impl core::future::Future<Output = Result<IngressReply>> + Send;

    /// Seed the application's data set, idempotently.
    fn seed(ctx: &AppContext) -> impl core::future::Future<Output = Result<()>> + Send;

    /// Admit a request holding the authority its mount declared.
    ///
    /// The shell cannot perform the checks itself: authentication lives in
    /// `alloy-auth`, which is a SEPARATE package an application may or may
    /// not mount, and a runtime that hard-coded it would make the auth
    /// package mandatory for a demonstration feed that wants none.
    ///
    /// So the shell decides WHEN admission happens — before the handler,
    /// before its input is parsed, for every mounted action — and the
    /// application supplies HOW. That split is what removes the per-app
    /// `run_action` without forcing every app to authenticate.
    ///
    /// The default refuses anything but [`Authority::Public`], so an app
    /// that mounts a guarded action without implementing this fails closed
    /// rather than serving it unguarded.
    ///
    /// A refusal that is already a complete reply travels as
    /// [`AlloyError::Reply`] and reaches the client unchanged. An app that
    /// signs people in with the `auth` package admits with its gate, whose
    /// 303 to sign-in, 401 and 403 (which names the failed CSRF condition)
    /// then pass through as the gate wrote them:
    ///
    /// ```ignore
    /// async fn admit(ctx: &AppContext, req: &IngressRequest, authority: Authority) -> Result<()> {
    ///     if authority == Authority::Public {
    ///         return Ok(());
    ///     }
    ///     let mut auth = open_auth(ctx)?;                      // the app's own constructor
    ///     auth.gate(req, ctx.now_ms()).await.map(drop).map_err(AlloyError::reply)
    /// }
    /// ```
    fn admit(
        _ctx: &AppContext,
        _req: &IngressRequest,
        authority: Authority,
    ) -> impl core::future::Future<Output = Result<()>> + Send {
        async move {
            match authority {
                Authority::Public => Ok(()),
                // Fail CLOSED. An application that mounts a writer action
                // and forgets to implement `admit` would otherwise serve it
                // to anyone, which is precisely the defect the registry
                // exists to make unrepresentable.
                Authority::Writer | Authority::Admin => Err(AlloyError::internal(
                    "this action declares an authority, but the application implements no \
                     `admit`; mount `auth` or `alloy-auth` and implement it, or declare the \
                     action public",
                )),
            }
        }
    }
}

/// The authority an action requires, declared where it is MOUNTED.
///
/// The three checks a new action must not forget are authenticate, verify
/// CSRF and refuse a read-only role. If they hold only because actions route
/// through one helper, an action added anywhere else compiles unguarded.
///
/// Declaring the requirement at the mount point moves that from a
/// convention to a value the dispatcher reads. A reviewer asking "should
/// this have been guarded?" looks at one table rather than auditing each
/// handler's opening lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// No session at all. Stated rather than implied: a demonstration feed
    /// with an unauthenticated action is legitimate, and forcing it to
    /// invent a session would be worse than saying so here.
    Public,
    /// A verified session whose role may write.
    Writer,
    /// A verified session holding the admin role.
    Admin,
}

/// One mounted action: its wire name and the authority it demands.
pub struct ActionRoute<A: AlloyApp + ?Sized> {
    name: &'static str,
    authority: Authority,
    handler: ActionHandler,
    _app: core::marker::PhantomData<fn() -> A>,
}

/// The future a mounted action handler returns.
pub type ActionFuture<'a> =
    core::pin::Pin<Box<dyn core::future::Future<Output = Result<IngressReply>> + Send + 'a>>;

type ActionHandler =
    Box<dyn for<'a> Fn(&'a AppContext, &'a IngressRequest) -> ActionFuture<'a> + Send + Sync>;

impl<A: AlloyApp + ?Sized> ActionRoute<A> {
    /// The action's wire name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The authority this action demands.
    pub fn authority(&self) -> Authority {
        self.authority
    }
}

/// The action table an application declares.
///
/// Registration is by VERB — [`public`](Self::public), [`writer`](Self::writer),
/// [`admin`](Self::admin) — so the authority is visible at the mount point
/// rather than buried in the handler body.
pub struct Actions<A: AlloyApp + ?Sized> {
    routes: Vec<ActionRoute<A>>,
}

impl<A: AlloyApp + ?Sized> Default for Actions<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: AlloyApp + ?Sized> Actions<A> {
    /// An empty table.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Mount an action that needs no session.
    pub fn public<F>(&mut self, name: &'static str, handler: F) -> &mut Self
    where
        F: for<'a> Fn(&'a AppContext, &'a IngressRequest) -> ActionFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.push(name, Authority::Public, handler)
    }

    /// Mount an action requiring a verified writer session.
    pub fn writer<F>(&mut self, name: &'static str, handler: F) -> &mut Self
    where
        F: for<'a> Fn(&'a AppContext, &'a IngressRequest) -> ActionFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.push(name, Authority::Writer, handler)
    }

    /// Mount an action requiring the admin role.
    pub fn admin<F>(&mut self, name: &'static str, handler: F) -> &mut Self
    where
        F: for<'a> Fn(&'a AppContext, &'a IngressRequest) -> ActionFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.push(name, Authority::Admin, handler)
    }

    fn push<F>(&mut self, name: &'static str, authority: Authority, handler: F) -> &mut Self
    where
        F: for<'a> Fn(&'a AppContext, &'a IngressRequest) -> ActionFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.routes.push(ActionRoute {
            name,
            authority,
            handler: Box::new(handler),
            _app: core::marker::PhantomData,
        });
        self
    }

    /// Every mounted action.
    pub fn routes(&self) -> &[ActionRoute<A>] {
        &self.routes
    }

    /// Look one up by wire name.
    pub fn find(&self, name: &str) -> Option<&ActionRoute<A>> {
        self.routes.iter().find(|r| r.name == name)
    }

    /// Whether a name is mounted twice.
    ///
    /// Two mounts of one name would make the winner an ordering accident,
    /// and the loser's authority silently unreachable — so the shell
    /// refuses rather than picking one.
    pub fn duplicate(&self) -> Option<&'static str> {
        for (i, r) in self.routes.iter().enumerate() {
            if self.routes.iter().skip(i + 1).any(|o| o.name == r.name) {
                return Some(r.name);
            }
        }
        None
    }
}

/// Dispatch `POST /__alloy/action/{name}` through a declared table.
///
/// The method check, the authority check and the unknown-name refusal all
/// live here, so an application's action module contains handlers and
/// nothing else. This is what removes the per-app `run_action`: the three
/// checks are performed by the dispatcher for every mounted action, and a
/// handler cannot be reached without them.
pub async fn dispatch_action<A: AlloyApp + ?Sized>(
    actions: &Actions<A>,
    ctx: &AppContext,
    req: &IngressRequest,
    name: &str,
) -> Result<IngressReply> {
    if let Some(dup) = actions.duplicate() {
        return Err(AlloyError::internal(format!(
            "action '{dup}' is mounted twice; which authority applies would be an \
             ordering accident"
        )));
    }
    // Matched case-INSENSITIVELY, exactly as `RouteTable::resolve` does.
    // A gateway that normalises the method differently must not turn a
    // legal POST into a 405 on the action face while the very same request
    // would have been admitted on a page route.
    if !req.method.eq_ignore_ascii_case("POST") {
        return Ok(method_refusal(
            req,
            "POST, OPTIONS".to_string(),
            "an action is invoked with POST",
        ));
    }
    let route = admissible_route(actions, req, name)?;
    // The authority the MOUNT declared, enforced before the handler runs and
    // before its input is parsed. A handler therefore cannot forget a check
    // it never performs.
    A::admit(ctx, req, route.authority).await?;
    (route.handler)(ctx, req).await
}

/// The route a POST may go on to, or the refusal it gets instead.
///
/// The origin gate runs BEFORE admit, because CSRF is exactly the case
/// admission cannot catch: the victim's browser attaches the victim's real
/// credentials, so an authenticated check passes while the REQUEST was
/// authored by another site. What identifies that case is the `Origin` header
/// the browser stamps on every cross-origin POST and a page cannot forge.
///
/// It also runs before the NAME is looked up. In the other order a
/// cross-origin caller got 400 "no action named …" for a name that is not
/// mounted and 403 for one that is, and could list an app's actions from
/// another site by the difference. Now every
/// cross-origin POST gets the same 403, whatever it names.
fn admissible_route<'a, A: AlloyApp + ?Sized>(
    actions: &'a Actions<A>,
    req: &IngressRequest,
    name: &str,
) -> Result<&'a ActionRoute<A>> {
    check_action_origin::<A>(req)?;
    actions.find(name).ok_or_else(|| {
        AlloyError::bad_request(format!("no action named '{name}' is declared"))
    })
}

/// The same origin gate for a state-changing request that is NOT an action.
///
/// An application that also serves a plain-HTTP or MCP face authenticated by
/// the browser's session cookie has the action route's exposure on that face:
/// a cross-site form can POST a JSON body as `text/plain`, and the browser
/// attaches the victim's cookie. Call this before dispatching any such request
/// (the dispatcher already does for actions). Safe methods pass untouched, and
/// so does a request with no `Origin` (an agent, a webhook, `curl`), exactly
/// as for actions. It only works where the manifest forwards `origin` on the
/// route; the route configuration and origin check must remain aligned.
pub fn check_unsafe_request_origin<A: AlloyApp + ?Sized>(req: &IngressRequest) -> Result<()> {
    if matches!(
        req.method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    ) {
        return Ok(());
    }
    check_action_origin::<A>(req)
}

/// Refuse a cross-origin action, unless the app allowlisted the origin.
///
/// A request WITHOUT an `Origin` header passes: browsers send the header on
/// every cross-origin POST, so its absence means a non-browser client — and
/// a non-browser client is not confusable into attaching someone else's
/// cookies, which is the only attack this gate exists for. `Origin: null`
/// (a sandboxed iframe, a data: URL) is NOT absence: it is a browser saying
/// the context is untrustworthy, so it must fail the comparison rather than
/// slip through as "no header".
fn check_action_origin<A: AlloyApp + ?Sized>(req: &IngressRequest) -> Result<()> {
    // `Sec-Fetch-Site` is the browser's own verdict and page script cannot
    // forge it. A browser that marks the request anything but same-origin
    // (or user-initiated, `none`) outranks a missing `Origin` and a host
    // comparison that cannot see the scheme.
    let browser_cross = header(req, "sec-fetch-site").is_some_and(|site| {
        !site.eq_ignore_ascii_case("same-origin") && !site.eq_ignore_ascii_case("none")
    });
    let Some(origin) = header(req, "origin") else {
        if browser_cross {
            return Err(AlloyError::forbidden("a cross-site action carried no origin"));
        }
        return Ok(());
    };
    // The platform states no routed host: the request envelope carries none,
    // and `host` is a gateway-owned header no route is allowed to forward
    // (ledger 10, row R4), so on the fleet this header is absent for every
    // request, browser or not. It is still consulted, so a harness or a
    // gateway that does forward one gets its origin judged rather than
    // refused. It is NOT replaced by `x-forwarded-host`: the gateway relays
    // that header exactly as the client sent it, and a comparison against a
    // value the attacker's page cannot set but the attacker's server can is
    // not a comparison. Where there is no host, the browser's own verdict
    // below is the signal.
    let host = header(req, "host");
    if let Some(host) = host {
        if !browser_cross
            && origin_host(origin).is_some_and(|origin_host| host_matches(origin_host, host))
        {
            return Ok(());
        }
    } else if header(req, "sec-fetch-site").is_some_and(|site| site.eq_ignore_ascii_case("same-origin")) {
        // With no authority to compare against, the browser's own verdict is
        // the one remaining sound signal. `Sec-Fetch-Site` is a forbidden
        // header name: page script cannot set or alter it, so a cross-site
        // form or fetch arrives as `cross-site` or `same-site` whatever the
        // attacker writes. A non-browser client can send anything, and is not
        // the threat here, because it carries no victim's cookies. It only
        // works where the route forwards `sec-fetch-site`; where it does not,
        // the request falls through to the allowlist and is refused.
        return Ok(());
    }
    // The allowlist compares the FULL origin or its host part, so an app
    // can pin a scheme (`https://admin.example.com`) or accept any
    // (`admin.example.com`) — but a substring can never match.
    let allowed = A::ALLOWED_ACTION_ORIGINS.iter().any(|entry| {
        origin.eq_ignore_ascii_case(entry)
            || origin_host(origin).is_some_and(|h| host_matches(h, entry))
    });
    if allowed {
        return Ok(());
    }
    if host.is_none() {
        // An origin with no authority to compare against cannot be verified
        // same-origin, and unverifiable is refused, not assumed. On the fleet
        // this is every browser request whose route does not forward
        // `sec-fetch-site` and whose origin the application has not
        // allowlisted.
        return Err(AlloyError::forbidden(
            "an action carried an origin but the request names no host; forward `sec-fetch-site` on the route or declare the origin in ALLOWED_ACTION_ORIGINS",
        ));
    }
    Err(AlloyError::forbidden("cross-origin action"))
}

/// The first value of `name` among the forwarded request headers.
fn header<'a>(req: &'a IngressRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The host part of an `Origin` header value.
///
/// An origin is `scheme://host[:port]`, one per request. Anything that is
/// not that shape — `null`, an empty value, a bare word — has no host and
/// returns `None`, which the caller treats as a mismatch: an origin that
/// cannot be parsed cannot be verified, and unverifiable must not pass.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.split_once("://").map(|(_, rest)| rest)?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Whether two host[:port] values name the same authority.
///
/// The comparison is on the WHOLE value, case-insensitively, after folding
/// a default port away is deliberately NOT attempted: the gateway forwards
/// `host` exactly as the client sent it and a browser writes `Origin` from
/// the same URL, so the two agree byte-for-byte in every legitimate case,
/// and every clever normalisation is one more shape a forger can aim for.
fn host_matches(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Run a Alloy application: the loop, the ordering, and the drain.
///
/// This is the body an application's `FerriteApp::run` delegates to.
pub async fn serve<A: AlloyApp>(ctx: AppContext) -> std::io::Result<()> {
    // Decode the packed frontend FIRST: the api face answers /assets/ from it
    // (see `answer_asset`), and the site blob is seeded with the built files
    // for anything that reads them back from there. Warn-and-serve on
    // failure, like data seeding below: an already-seeded deployment keeps
    // serving its stored assets from the blob.
    let mut packed = crate::alloy::assets::PublicAssets::default();
    if !A::ASSETS_B64.is_empty() {
        match crate::alloy::assets::decode_assets(A::ASSETS_B64, A::ASSETS_LEN) {
            Ok(files) => {
                match ctx.blob(A::SITE) {
                    Ok(mut blob) => match crate::alloy::assets::seed_site_under(&mut blob, A::ASSET_KEY_PREFIX, &files).await {
                        Ok(written) => tracing::info!(
                            target: "alloy::app",
                            decoded = files.len(),
                            written,
                            "site assets seeded path-keyed"
                        ),
                        Err(e) => tracing::warn!(
                            target: "alloy::app",
                            error = %e,
                            "asset seeding failed; serving whatever the site blob already holds"
                        ),
                    },
                    Err(e) => tracing::warn!(
                        target: "alloy::app",
                        error = %e,
                        "no site blob binding; packed assets cannot be seeded"
                    ),
                }
                // Held for the life of the process: the api face answers
                // `ASSET_PREFIX` from these bytes, which costs no plane read
                // and works even where the blob could not be seeded.
                packed = crate::alloy::assets::PublicAssets::from_files(files);
                // The shell links the stable `/assets/entry.js` and
                // `/assets/entry.css`; a hashed build's document names the
                // hashed files instead, so a browser may keep them a year.
                if let Some(shell) = packed.rewrite_shell(A::SHELL, A::ASSET_PREFIX) {
                    register_shell::<A>(shell);
                }
            }
            Err(e) => tracing::warn!(
                target: "alloy::app",
                error = %e,
                "the packed assets did not decode; serving whatever the site blob already holds"
            ),
        }
    }

    // Seed before serving: a fresh deployment otherwise answers every
    // request with an empty view, which looks like a broken app rather than
    // an empty one. Seeding is idempotent, so a restart or a sibling
    // instance is a no-op.
    if let Err(e) = A::seed(&ctx).await {
        tracing::warn!(
            target: "alloy::app",
            error = %e,
            "seeding failed; serving what is already stored"
        );
    }

    let mut requests = ctx.queue(A::REQUESTS)?;

    // The drain runs in THIS loop rather than a second task: a Alloy app is a
    // pool of competing consumers, so every instance drains, and the shard
    // leases are what keep them from performing an effect twice between them.
    let mut drain = match OutboxDrain::from_context(&ctx, A::TAGS, A::LEASES) {
        Ok(drain) => Some(drain),
        Err(e) => {
            // An app whose planes cannot be bound still serves reads; it
            // simply performs no cross-plane effects, and says so once.
            tracing::error!(
                target: "alloy::app",
                error = %e,
                "the outbox drain could not bind its planes; committed intents will not be performed"
            );
            None
        }
    };
    let mut pump = DrainPump::default();
    let mut answered = HedgeMemory::default();

    loop {
        // Drain BEFORE taking a lease. A pass performs external effects and
        // can be slow; running it while holding a request lease would add
        // that latency to a request already in flight, and could burn the
        // lease's own deadline while the gateway waited.
        let now = ctx.now_ms();
        if let Some(drain) = drain.as_mut() {
            if pump.due(now) {
                pump.mark(now);
                match drain.drain_once(&ctx, now).await {
                    Ok(report) => pump.settle(report.budget_exhausted),
                    Err(e) => {
                        pump.settle(false);
                        tracing::warn!(
                            target: "alloy::app",
                            error = %e,
                            "an outbox drain pass failed; the intents stay pending"
                        );
                    }
                }
            }
        }

        let Some(lease) = requests.poll_wait(1_000).await? else {
            // An empty poll is the cheapest possible moment to perform
            // effects: nothing is in flight and no lease is held.
            pump.idle();
            continue;
        };
        // A frame that is not an ingress envelope can never be answered, so
        // it is settled rather than left to redeliver forever.
        let Ok(req) = serde_json::from_slice::<IngressRequest>(&lease.payload) else {
            let _ = requests.ack(lease.token).await?;
            continue;
        };
        // An envelope with nowhere to reply can never be answered: settle it before
        // the handler runs, or it redelivers and re-runs side effects forever.
        if req.reply_to.trim().is_empty() {
            tracing::warn!("settling a request envelope with no reply_to");
            let _ = requests.ack(lease.token).await?;
            continue;
        }

        // The gateway can hedge a GET while it waits in the queue or while its
        // reply is being published, even when the handler itself is fast. A
        // later copy on this instance reuses the reply, but still meets the
        // budget hook: admission applies to every delivered envelope.
        let started = ctx.now_ms();
        let budget_reply = A::request_budget(&ctx, &req).await;
        let admitted_at = ctx.now_ms();
        let budget_admitted = budget_reply.is_none();
        let hedge_key = if budget_admitted {
            HedgeMemory::key_for(&req)
        } else {
            None
        };
        let cached = hedge_key
            .as_deref()
            .and_then(|key| answered.recall(key, started));
        if let Some((reply, status)) = cached {
            let handled_at = ctx.now_ms();
            let delivered = match ctx.reply_to_queue(&req.reply_to).await {
                Ok(mut replies) => replies.publish(&reply).await.is_ok(),
                Err(_) => false,
            };
            let trace = RequestTrace { status, cache_hit: true, started, admitted_at, handled_at };
            settle_lease(&ctx, &mut requests, &req, lease.token, delivered, trace).await?;
            pump.handled();
            continue;
        }

        let reply = match budget_reply {
            Some(reply) => reply,
            None => match answer_asset::<A>(&ctx, &req, &packed).await {
                Some(reply) => reply,
                None => match A::answer(&ctx, &req).await {
                    Ok(reply) => reply,
                    Err(err) => error_reply::<A>(&req, err),
                },
            },
        };
        // HEAD is answered like GET with the body withheld, and that is a
        // property of the METHOD rather than of any one handler. Doing it
        // only in `document` would leave every route handler and loader
        // reply shipping a full payload to a caller that asked for none of
        // it — and no author writing a handler would think to check.
        let reply = withhold_head_body(&req, reply);
        let finished = ctx.now_ms();
        if let Some(key) = hedge_key.as_deref() {
            if HedgeMemory::is_cacheable_reply(&reply)
                && (req.method.eq_ignore_ascii_case("GET")
                    || finished.saturating_sub(started) >= HedgeMemory::SLOW_MS)
            {
                if let Some(encoded) = HedgeMemory::encode(key, &reply) {
                    answered.remember(key, encoded, reply.status, finished);
                }
            }
        }
        let handled_at = ctx.now_ms();

        // The lease is settled ONLY once the reply is actually published.
        let delivered = match ctx.reply_to_queue(&req.reply_to).await {
            Ok(mut replies) => match serde_json::to_vec(&reply) {
                Ok(encoded) => replies.publish(&encoded).await.is_ok(),
                Err(e) => {
                    // A reply that cannot be encoded will never encode, so
                    // redelivering it is pointless. But ACKING WITHOUT
                    // PUBLISHING is worse than pointless: the caller then
                    // waits out the gateway's full deadline for an answer
                    // that is never coming, and redelivery — the one
                    // mechanism that could still produce one — has already
                    // been suppressed.
                    //
                    // So the caller is told. A 500 problem document is
                    // built from the SAME typed error surface every other
                    // failure uses, and it encodes because it carries no
                    // application payload. Only if even that fails is the
                    // frame settled unanswered.
                    tracing::error!(
                        target: "alloy::app",
                        error = %e,
                        "reply could not be encoded; answering with a problem document"
                    );
                    let fallback = problem(
                        &req,
                        AlloyError::internal(format!("reply encoding failed: {e}")),
                    );
                    match serde_json::to_vec(&fallback) {
                        Ok(encoded) => replies.publish(&encoded).await.is_ok(),
                        Err(inner) => {
                            tracing::error!(
                                target: "alloy::app",
                                error = %inner,
                                "the problem document itself could not be encoded; settling"
                            );
                            true
                        }
                    }
                }
            },
            Err(e) => {
                tracing::warn!(
                    target: "alloy::app",
                    error = %e,
                    reply_to = %req.reply_to,
                    "reply queue unreachable; leaving the lease to redeliver"
                );
                false
            }
        };
        let trace = RequestTrace {
            status: reply.status,
            cache_hit: false,
            started,
            admitted_at,
            handled_at,
        };
        settle_lease(&ctx, &mut requests, &req, lease.token, delivered, trace).await?;
        pump.handled();
    }
}

/// Answer a `GET`/`HEAD` under [`AlloyApp::ASSET_PREFIX`], or `None` when the
/// request is not one.
///
/// The gateway resolves api routes before content routes, whatever their
/// prefix lengths, so an app with an api route at `/` is handed its own asset
/// requests; an Alloy app's `ferrite.json` says so explicitly with an api
/// route at `/assets/` that forwards `accept-encoding` and `if-none-match`
/// (and no cookie). Left to [`AlloyApp::answer`] these requests would meet the
/// app's session gate or its router and answer 401 or 404, and the page would
/// load with no script.
///
/// The packed archive is read first: the representation is negotiated from
/// the stored br/gzip encodings, cached for a year when the pack step found a
/// content hash in the name and revalidated otherwise, and answered 304 when
/// the caller's ETag names it. An app that seeds its blob another way is
/// answered from the [`AlloyApp::SITE`] blob under the key the content route
/// would have used, identity only.
pub async fn answer_asset<A: AlloyApp>(
    ctx: &AppContext,
    req: &IngressRequest,
    packed: &crate::alloy::assets::PublicAssets,
) -> Option<IngressReply> {
    use crate::alloy::assets::{asset_key, AssetReply};

    if !is_read(req) {
        return None;
    }
    let path = req.path.split(['?', '#']).next().unwrap_or("");
    if A::ASSET_PREFIX.is_empty() || !path.starts_with(A::ASSET_PREFIX) {
        return None;
    }
    let key = asset_key(A::ASSET_PREFIX, &req.path);
    // The reply's type and caching come from the DECODED name the bytes were
    // looked up under, so `/assets/entry%2Ejs` is served as the script it
    // is rather than as `application/octet-stream` a shared cache could
    // then pin for `/assets/entry.js`.
    let name = key.as_deref().unwrap_or(path);
    let if_none_match = header(req, "if-none-match");
    let Some(key) = &key else {
        return Some(asset_reply(req, AssetReply::Missing));
    };
    // The packed archive first: it carries the stored br/gzip encodings and
    // the pack step's cache decision, and costs no plane read.
    if let Some(asset) = packed.asset(key) {
        return Some(asset_reply(
            req,
            AssetReply::negotiate(name, Some(asset), header(req, "accept-encoding"), if_none_match),
        ));
    }
    // `/assets/entry.js` or `/assets/entry.css` from a document cached before
    // the shell was rewritten, or an old link: the hashed entry, revalidated
    // because the bytes behind the stable name change on every deploy.
    if let Some(asset) = packed.alias(key) {
        return Some(asset_reply(
            req,
            AssetReply::negotiate_cached(
                name,
                Some(asset),
                header(req, "accept-encoding"),
                if_none_match,
                Some(crate::alloy::assets::CACHE_REVALIDATE),
            ),
        ));
    }
    let bytes = match ctx.blob(A::SITE) {
        Ok(mut blob) => {
            let blob_key = format!("{}{key}", A::ASSET_KEY_PREFIX);
            match blob.get(blob_key.as_bytes()).await {
                Ok(found) => found,
                Err(e) => return Some(problem(req, AlloyError::from(e))),
            }
        }
        Err(_) => None,
    };
    Some(asset_reply(req, AssetReply::of(name, bytes, if_none_match)))
}

/// Render an [`crate::alloy::assets::AssetReply`] onto the wire.
pub fn asset_reply(req: &IngressRequest, asset: crate::alloy::assets::AssetReply) -> IngressReply {
    use crate::alloy::assets::AssetReply;

    let id = req.correlation_id.clone();
    match asset {
        AssetReply::Found {
            bytes,
            content_type,
            cache_control,
            etag,
            content_encoding,
            vary,
        } => {
            let mut reply = IngressReply::new(id, 200, bytes);
            reply.headers.extend([
                ("content-type".to_string(), content_type.to_string()),
                ("cache-control".to_string(), cache_control.to_string()),
                ("etag".to_string(), etag),
                ("x-content-type-options".to_string(), "nosniff".to_string()),
            ]);
            if let Some(coding) = content_encoding {
                reply.headers.push(("content-encoding".to_string(), coding.to_string()));
            }
            if vary {
                reply.headers.push(("vary".to_string(), "accept-encoding".to_string()));
            }
            reply
        }
        AssetReply::NotModified { etag, cache_control, vary } => {
            let mut reply = IngressReply::new(id, 304, Vec::new());
            reply.headers.extend([
                ("cache-control".to_string(), cache_control.to_string()),
                ("etag".to_string(), etag),
            ]);
            if vary {
                reply.headers.push(("vary".to_string(), "accept-encoding".to_string()));
            }
            reply
        }
        refusal => {
            let status = if refusal == AssetReply::Missing { 404 } else { 500 };
            if let AssetReply::TooLarge { size } = &refusal {
                tracing::error!(
                    target: "alloy::app",
                    path = %req.path,
                    size,
                    limit = crate::alloy::assets::MAX_ASSET_REPLY_BYTES,
                    "an asset is too large for one api reply and was refused"
                );
            }
            let body = refusal
                .problem_json()
                .map(|doc| doc.to_string().into_bytes())
                .unwrap_or_default();
            let mut reply = IngressReply::new(id, status, body);
            reply.headers.extend([
                ("content-type".to_string(), "application/problem+json".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ]);
            reply
        }
    }
}

async fn settle_lease(
    ctx: &AppContext,
    requests: &mut QueueClusterClient,
    req: &IngressRequest,
    token: u64,
    delivered: bool,
    trace: RequestTrace,
) -> std::io::Result<()> {
    let published_at = ctx.now_ms();
    let ack = if delivered {
        requests.ack(token).await.map(|_| ())
    } else {
        Ok(())
    };
    let failed_phase = if ack.is_err() {
        Some("ack")
    } else if !delivered {
        Some("publish")
    } else {
        None
    };
    trace_slow_request(req, trace, published_at, ctx.now_ms(), failed_phase);
    ack
}

fn is_read(req: &IngressRequest) -> bool {
    req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD")
}

/// Withhold the body of a reply to a HEAD request, keeping its headers.
///
/// RFC 9110 is explicit that a HEAD response carries the header fields a
/// GET would have sent and no content — which is the entire reason a client
/// chooses HEAD: to learn a resource's type, size or existence without
/// paying for it. A framework that returned the body anyway would make the
/// method pointless while still looking correct in every status assertion.
///
/// The reply never carries `content-length`: the gateway owns framing and
/// refuses any application reply that names it (502 "application response
/// headers refused"), so the header would take the whole property down.
fn withhold_head_body(req: &IngressRequest, reply: IngressReply) -> IngressReply {
    if !req.method.eq_ignore_ascii_case("HEAD") {
        return reply;
    }
    let mut out = IngressReply::new(reply.correlation_id.clone(), reply.status, Vec::new());
    out.headers = reply.headers.clone();
    out
}

/// Recent GET replies and slow replies from other methods, by correlation id.
/// GET hedges can arrive because of time outside the measured handler interval,
/// so their replies are retained regardless of local duration. Other methods
/// keep their existing slow-reply redelivery protection. Bytes, count and age bound
/// this instance's memory; another replica may still handle the same request.
#[derive(Default)]
struct HedgeMemory {
    entries: std::collections::VecDeque<(String, Vec<u8>, u16, u64)>,
    retained_bytes: usize,
}

impl HedgeMemory {
    /// Retain slow replies from other methods as well as every admitted GET.
    const SLOW_MS: u64 = 500;
    /// Longer than the gateway's reply deadline, after which no copy can still be waiting.
    const KEEP_MS: u64 = 60_000;
    const CAPACITY: usize = 32;
    const MAX_BYTES: usize = 8 * 1024 * 1024;

    fn key_for(req: &IngressRequest) -> Option<String> {
        if req.correlation_id.trim().is_empty()
            || req.reply_to.trim().is_empty()
            || req.stream_open
        {
            return None;
        }
        let method = req.method.to_ascii_uppercase();
        if matches!(
            method.as_str(),
            "WS_OPEN" | "WS_MESSAGE" | "WS_CLOSE" | "STREAM_CLOSE"
        ) {
            return None;
        }
        let mut hasher = crate::crypto::Sha256::new();
        let feed = |h: &mut crate::crypto::Sha256, bytes: &[u8]| {
            h.update(&(bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        };
        feed(&mut hasher, b"alloy/hedge-memory/v2");
        feed(&mut hasher, req.correlation_id.as_bytes());
        feed(&mut hasher, req.idempotency_key.as_bytes());
        feed(&mut hasher, req.reply_to.as_bytes());
        feed(&mut hasher, method.as_bytes());
        feed(&mut hasher, req.path.as_bytes());
        feed(&mut hasher, &req.body);
        let mut headers: Vec<(String, &str)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
            .collect();
        headers.sort_unstable();
        hasher.update(&(headers.len() as u64).to_be_bytes());
        for (k, v) in headers {
            feed(&mut hasher, k.as_bytes());
            feed(&mut hasher, v.as_bytes());
        }
        Some(crate::crypto::hex_encode(&hasher.finalize()))
    }

    fn is_cacheable_reply(reply: &IngressReply) -> bool {
        if reply.status >= 500
            || matches!(reply.status, 408 | 409 | 429)
            || reply
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        {
            return false;
        }
        true
    }

    fn encode(correlation_id: &str, reply: &IngressReply) -> Option<Vec<u8>> {
        let limit = Self::MAX_BYTES.checked_sub(correlation_id.len())?;
        // Encoding borrows the original reply and stops at the limit. In
        // particular, do not first allocate a full JSON copy of a large asset.
        if reply.body.len() > limit {
            return None;
        }
        let mut writer = BoundedReply {
            bytes: Vec::new(),
            limit,
        };
        serde_json::to_writer(&mut writer, reply).ok()?;
        Some(writer.bytes)
    }

    fn remember(&mut self, correlation_id: &str, encoded: Vec<u8>, status: u16, now_ms: u64) {
        self.prune(now_ms);
        let Some(bytes) = encoded.capacity().checked_add(correlation_id.len()) else {
            return;
        };
        if bytes > Self::MAX_BYTES {
            return;
        }
        while self.entries.len() == Self::CAPACITY || self.retained_bytes + bytes > Self::MAX_BYTES
        {
            self.remove_oldest();
        }
        self.retained_bytes += bytes;
        self.entries
            .push_back((correlation_id.to_string(), encoded, status, now_ms));
    }

    fn recall(&mut self, correlation_id: &str, now_ms: u64) -> Option<(Vec<u8>, u16)> {
        self.prune(now_ms);
        self.entries
            .iter()
            .find(|(id, _, _, _)| id == correlation_id)
            .map(|(_, encoded, status, _)| (encoded.clone(), *status))
    }

    fn prune(&mut self, now_ms: u64) {
        while let Some((_, _, _, at)) = self.entries.front() {
            if now_ms.saturating_sub(*at) <= Self::KEEP_MS {
                break;
            }
            self.remove_oldest();
        }
    }

    fn remove_oldest(&mut self) {
        if let Some((id, encoded, _, _)) = self.entries.pop_front() {
            self.retained_bytes -= id.len() + encoded.capacity();
        }
    }
}

struct BoundedReply {
    bytes: Vec<u8>,
    limit: usize,
}

impl std::io::Write for BoundedReply {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= self.limit)
            .ok_or_else(|| std::io::Error::other("reply exceeds hedge cache byte limit"))?;
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().max(1024) * 2)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RequestTrace {
    status: u16,
    cache_hit: bool,
    started: u64,
    admitted_at: u64,
    handled_at: u64,
}

fn trace_slow_request(
    req: &IngressRequest,
    t: RequestTrace,
    published_at: u64,
    finished: u64,
    failed_phase: Option<&str>,
) {
    let total_local_ms = finished.saturating_sub(t.started);
    if total_local_ms > HedgeMemory::SLOW_MS {
        tracing::warn!(
            target: "alloy::app",
            cid = %req.correlation_id,
            method = %req.method,
            status = t.status,
            cache_hit = t.cache_hit,
            admission_ms = t.admitted_at.saturating_sub(t.started),
            handler_ms = t.handled_at.saturating_sub(t.admitted_at),
            publish_ms = published_at.saturating_sub(t.handled_at),
            ack_ms = finished.saturating_sub(published_at),
            total_local_ms,
            failed_phase,
            "slow local request"
        );
    }
}

/// When the loop should drain, tracked without consulting the clock alone.
///
/// Three independent triggers, because each covers a case the others miss.
/// IDLE is the common one and costs nothing. The REQUEST COUNT bounds
/// staleness under sustained load without consulting the clock — an interval
/// floor alone would never fire again if the clock did not advance, and the
/// drain would silently stop after its first pass. The INTERVAL bounds it in
/// wall-clock terms for a trickle too slow to reach the count.
#[derive(Debug, Default)]
pub struct DrainPump {
    last_ms: u64,
    chained: u32,
    since: u32,
    idle: bool,
    /// Whether a pass has ever run.
    ///
    /// An instance that restarts inherits whatever the previous one left
    /// pending, and that backlog is durable: it is already committed and
    /// already discoverable. Waiting out a full interval before looking at
    /// it would delay every effect a crash left behind, for no benefit —
    /// so the very first pass is always due.
    started: bool,
}

impl DrainPump {
    /// Whether a pass is due at `now_ms`.
    pub fn due(&self, now_ms: u64) -> bool {
        !self.started
            || self.idle
            || self.chained > 0
            || now_ms.saturating_sub(self.last_ms) >= DRAIN_INTERVAL_MS
            || self.since >= DRAIN_EVERY_N_REQUESTS
    }

    /// Record that a pass is starting.
    pub fn mark(&mut self, now_ms: u64) {
        self.last_ms = now_ms;
        self.since = 0;
        self.idle = false;
        self.started = true;
    }

    /// Record a pass's outcome: a truncated pass may come straight back,
    /// but only `MAX_CHAINED_PASSES` times before the backlog waits.
    pub fn settle(&mut self, budget_exhausted: bool) {
        self.chained = if budget_exhausted && self.chained < MAX_CHAINED_PASSES {
            self.chained + 1
        } else {
            0
        };
    }

    /// Record that a poll came back empty.
    pub fn idle(&mut self) {
        self.idle = true;
    }

    /// Record that a request was handled.
    pub fn handled(&mut self) {
        self.since = self.since.saturating_add(1);
    }
}

/// The reply for an error `answer` returned.
///
/// A problem document, except for the one case [`AlloyApp::NOT_FOUND_DOCUMENT`]
/// opts into: a browser navigation that misses renders the app's document
/// with status 404. If that document cannot render, the problem document is
/// still sent, so an opt-in can never turn a 404 into a 500.
pub fn error_reply<A: AlloyApp>(req: &IngressRequest, err: AlloyError) -> IngressReply {
    if A::NOT_FOUND_DOCUMENT && matches!(err, AlloyError::NotFound) && is_html_navigation(req) {
        let path = req.path.split(['?', '#']).next().unwrap_or("/");
        match document_status::<A>(
            req,
            "not_found",
            &Params::new(),
            serde_json::json!({ "path": path }),
            &Metadata::new()
                .title("Page not found")
                .robots("noindex, nofollow"),
            404,
        ) {
            Ok(reply) => return reply,
            Err(e) => tracing::warn!(
                target: "alloy::app",
                error = %e,
                "the not-found document did not render; answering with a problem document"
            ),
        }
    }
    problem(req, err)
}

/// A `GET`/`HEAD` that asks for HTML, outside the reserved `/__*` faces.
fn is_html_navigation(req: &IngressRequest) -> bool {
    is_read(req)
        && !req.path.starts_with("/__")
        && header(req, "accept").is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"))
}

/// Render a typed error as an RFC 9457 problem document.
///
/// This is also what makes a Alloy app score on the agent-readiness
/// checklist without the author writing an error handler.
pub fn problem(req: &IngressRequest, err: AlloyError) -> IngressReply {
    // A prepared reply is not a problem to render: it is the answer, built by
    // whoever refused the request (see `AlloyError::Reply`).
    if let AlloyError::Reply { reply } = err {
        let mut reply = *reply;
        reply.correlation_id = req.correlation_id.clone();
        return reply;
    }
    let body = err.problem_json().to_string().into_bytes();
    let mut reply = IngressReply::new(req.correlation_id.clone(), err.status(), body);
    reply.headers.push(("content-type".into(), "application/problem+json".into()));
    if let AlloyError::Redirect { location, .. } = &err {
        reply.headers.push(("location".into(), location.clone()));
    }
    reply
}

/// A JSON reply.
pub fn json_reply(req: &IngressRequest, status: u16, body: &serde_json::Value) -> IngressReply {
    let mut reply = IngressReply::new(
        req.correlation_id.clone(),
        status,
        body.to_string().into_bytes(),
    );
    reply.headers.push(("content-type".into(), "application/json".into()));
    reply
}

/// The `/__alloy/contract` face: every declared route, as JSON.
pub fn contract_reply(req: &IngressRequest, routes: &[Route]) -> IngressReply {
    let routes: Vec<serde_json::Value> = routes
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "path": r.pattern,
                "render": format!("{:?}", r.render).to_lowercase(),
                "loader": r.loader,
                "actions": r.actions,
            })
        })
        .collect();
    json_reply(req, 200, &serde_json::json!({ "routes": routes }))
}

/// Run a mounted action on behalf of a tool call. The request's own cookie
/// and CSRF headers ride along, so authority and replay safety are decided by
/// [`dispatch_action`] exactly as for a client post. `Ok` carries the reply
/// body of a status under 400, `Err` the body of any other reply or the
/// problem document of a refusal.
pub async fn call_action_as_tool<A: AlloyApp + ?Sized>(
    actions: &Actions<A>,
    ctx: &AppContext,
    req: &IngressRequest,
    name: &str,
    args: serde_json::Value,
) -> std::result::Result<serde_json::Value, serde_json::Value> {
    let synthetic = IngressRequest {
        stream_open: false,
        path: format!("/__alloy/action/{name}"),
        method: "POST".into(),
        body: serde_json::to_vec(&args).unwrap_or_default(),
        ..req.clone()
    };
    match dispatch_action(actions, ctx, &synthetic, name).await {
        Ok(reply) => {
            let value = serde_json::from_slice(&reply.body).unwrap_or(serde_json::Value::Null);
            if reply.status < 400 {
                Ok(value)
            } else {
                Err(value)
            }
        }
        Err(e) => Err(e.problem_json()),
    }
}

/// `value` as a canonical origin: `http` or `https`, a DNS host and an
/// optional port, in lower case with no path, query or trailing slash. A
/// value that is not one answers `None`, so a mistyped secret keeps the
/// default rather than publishing a broken URL.
pub fn canonical_origin(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value.strip_suffix('/').unwrap_or(value).to_ascii_lowercase();
    let (scheme, authority) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let host = match authority.split_once(':') {
        Some((host, port)) => {
            port.parse::<u16>().ok().filter(|p| *p != 0 && p.to_string() == port)?;
            host
        }
        None => authority,
    };
    let label = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    host.split('.').all(label).then_some(value)
}

/// Answer a method the matched route does not accept.
///
/// An `OPTIONS` is a PREFLIGHT, not a mistake. `RouteTable::resolve` derives
/// `OPTIONS` into every `Allow` set it reports, so refusing it with a 405
/// would contradict the header carried in that very reply: the response
/// would say "OPTIONS is allowed" and simultaneously refuse it. A caller
/// discovering the surface would be told to use a method that does not
/// work, which is worse than not advertising it at all.
///
/// Everything else is a genuine mismatch and answers 405 with the same set,
/// so a client can correct itself from one round trip.
pub fn method_not_allowed(req: &IngressRequest, allowed: &[String]) -> IngressReply {
    method_refusal(req, allowed.join(", "), "method not allowed")
}

fn method_refusal(req: &IngressRequest, allow: String, detail: &str) -> IngressReply {
    if req.method.eq_ignore_ascii_case("OPTIONS") {
        let mut reply = IngressReply::new(req.correlation_id.clone(), 204, Vec::new());
        reply.headers.push(("allow".into(), allow));
        return reply;
    }
    let body = method_problem(detail);
    let mut reply = IngressReply::new(req.correlation_id.clone(), 405, body);
    reply.headers.extend([
        ("content-type".to_string(), "application/problem+json".to_string()),
        ("allow".to_string(), allow),
    ]);
    reply
}

/// The RFC 9457 document a 405 carries.
///
/// Built from `bad_request` for its `detail`, then corrected. Sent as it was,
/// the reply said `405` on the status line and `"status": 400, "title": "Bad
/// Request"` in the body, and a client reading the document — which is what
/// a problem document is for — was told the opposite of the transport.
fn method_problem(detail: &str) -> Vec<u8> {
    let mut doc = AlloyError::bad_request(detail).problem_json();
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("type".into(), serde_json::Value::String("urn:ferrite:problem:method-not-allowed".into()));
        obj.insert("title".into(), serde_json::Value::String("Method Not Allowed".into()));
        obj.insert("status".into(), serde_json::Value::from(405u16));
    }
    doc.to_string().into_bytes()
}

/// The non-blank string argument `name` of a tool or API call.
pub fn required_str<'a>(args: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AlloyError::bad_request(format!("{name} is required")))
}

/// Route parameters as the JSON a loader payload carries.
pub fn params_json(params: &Params) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (name, value) in params {
        let v = match value {
            ParamValue::One(s) => serde_json::Value::String(s.clone()),
            ParamValue::Many(list) => serde_json::Value::Array(
                list.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        };
        map.insert(name.clone(), v);
    }
    serde_json::Value::Object(map)
}

/// Assemble a document: the shell, with metadata and the loader payload
/// substituted in by Rust.
///
/// `cache-control: private, no-cache` because the payload is per-viewer:
/// a shared cache holding one user's document and serving it to another is
/// the worst defect this function could have.
pub fn document<A: AlloyApp>(
    req: &IngressRequest,
    route_id: &str,
    params: &Params,
    data: serde_json::Value,
    metadata: &Metadata,
) -> Result<IngressReply> {
    document_reply::<A>(req, route_id, params, data, metadata, None, None, 200)
}

/// [`document`], with an explicit HTTP status.
///
/// This is the route-table-independent form intended for designed error
/// documents: a direct miss can render the app's `not_found` body and still
/// answer 404 instead of falling back to an RFC 9457 JSON problem. It keeps
/// the conservative private cache policy of [`document`].
pub fn document_status<A: AlloyApp>(
    req: &IngressRequest,
    route_id: &str,
    params: &Params,
    data: serde_json::Value,
    metadata: &Metadata,
    status: u16,
) -> Result<IngressReply> {
    document_reply::<A>(req, route_id, params, data, metadata, None, None, status)
}

/// [`document`], for a RESOLVED route and an optional CSP nonce.
///
/// This is the variant the route table's declarations reach the reply
/// through: the route's `headers:` map is applied, a
/// [`RenderMode::Static`] route with a declared cache life is offered to
/// shared caches when the app opted in, and a nonce — when the caller made
/// one — is stamped into the shell and advertised in a
/// `content-security-policy` header.
pub fn document_for<A: AlloyApp>(
    req: &IngressRequest,
    route: &Route,
    params: &Params,
    data: serde_json::Value,
    metadata: &Metadata,
    nonce: Option<&str>,
) -> Result<IngressReply> {
    document_reply::<A>(
        req,
        &route.id,
        params,
        data,
        metadata,
        Some(route),
        nonce,
        200,
    )
}

/// [`document_for`], with an explicit HTTP status.
///
/// Route headers, CSP nonce handling, HEAD semantics and the route's cache
/// declaration are preserved; only the status line differs. Use
/// [`document_status`] for a designed miss that has no resolved route.
pub fn document_for_status<A: AlloyApp>(
    req: &IngressRequest,
    route: &Route,
    params: &Params,
    data: serde_json::Value,
    metadata: &Metadata,
    nonce: Option<&str>,
    status: u16,
) -> Result<IngressReply> {
    document_reply::<A>(
        req,
        &route.id,
        params,
        data,
        metadata,
        Some(route),
        nonce,
        status,
    )
}

/// The shells rewritten at boot, by app type: few entries, read on every
/// document, written once per process.
static SHELLS: std::sync::OnceLock<std::sync::RwLock<Vec<(std::any::TypeId, &'static str)>>> =
    std::sync::OnceLock::new();

/// Record `A`'s boot-time shell. The string lives for the process (one
/// allocation per app type; a second call for the same type replaces it).
fn register_shell<A: AlloyApp>(shell: String) {
    register_static_shell::<A>(Box::leak(shell.into_boxed_str()));
}

fn register_static_shell<A: AlloyApp>(shell: &'static str) {
    let id = std::any::TypeId::of::<A>();
    let table = SHELLS.get_or_init(|| std::sync::RwLock::new(Vec::new()));
    if let Ok(mut table) = table.write() {
        table.retain(|(t, _)| *t != id);
        table.push((id, shell));
    }
}

/// The shell `A`'s documents render from: the boot-time rewrite that names
/// the hashed entry script and stylesheet when the packed build has them,
/// otherwise [`AlloyApp::SHELL`] as written. An app that renders its shell
/// outside the router (a bespoke page) should start from this, not from
/// its own constant, so that page links the hashed files too.
///
/// [`serve`] registers the rewrite at boot. A caller that never ran it (a
/// test driving the router directly) gets the same answer: the first call
/// decodes the packed archive once and registers the result, or registers
/// [`AlloyApp::SHELL`] itself when there is nothing to rewrite.
pub fn shell<A: AlloyApp>() -> &'static str {
    let id = std::any::TypeId::of::<A>();
    let registered = SHELLS
        .get()
        .and_then(|table| table.read().ok().and_then(|t| t.iter().find(|(t, _)| *t == id).map(|(_, s)| *s)));
    if let Some(shell) = registered {
        return shell;
    }
    let rewritten = if A::ASSETS_B64.is_empty() {
        None
    } else {
        crate::alloy::assets::decode_assets(A::ASSETS_B64, A::ASSETS_LEN)
            .ok()
            .and_then(|files| {
                crate::alloy::assets::PublicAssets::from_files(files).rewrite_shell(A::SHELL, A::ASSET_PREFIX)
            })
    };
    let chosen: &'static str = match rewritten {
        Some(shell) => Box::leak(shell.into_boxed_str()),
        None => A::SHELL,
    };
    register_static_shell::<A>(chosen);
    chosen
}

fn document_reply<A: AlloyApp>(
    req: &IngressRequest,
    route_id: &str,
    params: &Params,
    data: serde_json::Value,
    metadata: &Metadata,
    route: Option<&Route>,
    nonce: Option<&str>,
    status: u16,
) -> Result<IngressReply> {
    let payload = loader_payload::<A>(route_id, params, data);
    let prerendered;
    let shell_html = match A::prerendered_body(route_id) {
        Some(body) => {
            prerendered = substitute_prerendered_body(shell::<A>(), body)?;
            prerendered.as_str()
        }
        None => shell::<A>(),
    };
    let shell = Shell::parse(shell_html, "shell-1")?;
    let html = match nonce {
        Some(nonce) => shell.render_with_nonce(metadata, &payload, nonce)?,
        None => shell.render(metadata, &payload)?,
    };
    let bytes = html.into_bytes();
    // A HEAD answers with the headers a GET would carry and NO body. The
    // router admits HEAD on every page, so without this the whole document
    // goes out on a request whose entire purpose is to avoid transferring
    // it — and a crawler or a health check paying for the full payload is a
    // bandwidth defect nothing in the reply would reveal.
    //
    // No `content-length`: the gateway owns reply framing and refuses any
    // application reply that names it.
    let body = if req.method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else {
        bytes
    };
    let mut reply = IngressReply::new(req.correlation_id.clone(), status, body);
    reply.headers.extend([
        ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
        ("cache-control".to_string(), document_cache_control::<A>(route)),
    ]);
    if let Some(nonce) = nonce {
        reply.headers.push((
            "content-security-policy".into(),
            format!("script-src 'self' 'nonce-{nonce}'"),
        ));
    }
    if let Some(route) = route {
        apply_route_headers(&mut reply, route);
    }
    Ok(reply)
}

/// Substitute trusted build output into the one optional body marker.
///
/// The ordering and uniqueness checks are deliberately here rather than in
/// a generator alone: packages may be mounted into hand-written apps, and a
/// malformed shell must fail visibly instead of serving a body in `<head>`
/// or replacing only the first of two ambiguous mount points.
fn substitute_prerendered_body(shell: &str, body: &str) -> Result<String> {
    if body.contains(HEAD_MARKER) || body.contains(BODY_MARKER) || body.contains(DATA_SCRIPT_EMPTY)
    {
        return Err(AlloyError::internal(
            "a prerendered body carries an Alloy-reserved marker",
        ));
    }

    let head_at = shell.find(HEAD_MARKER).ok_or_else(|| {
        AlloyError::internal(format!(
            "the prerendered shell carries no {HEAD_MARKER} marker"
        ))
    })?;
    let body_at = shell.find(BODY_MARKER).ok_or_else(|| {
        AlloyError::internal(format!(
            "the application supplied a prerendered body, but its shell carries no {BODY_MARKER} marker"
        ))
    })?;
    let data_at = shell.find(DATA_SCRIPT_EMPTY).ok_or_else(|| {
        AlloyError::internal("the prerendered shell carries no empty __alloy_data script element")
    })?;
    if shell[body_at + BODY_MARKER.len()..].contains(BODY_MARKER) {
        return Err(AlloyError::internal(format!(
            "the prerendered shell carries more than one {BODY_MARKER} marker"
        )));
    }
    if !(head_at < body_at && body_at < data_at) {
        return Err(AlloyError::internal(format!(
            "the {BODY_MARKER} marker must follow {HEAD_MARKER} and precede the __alloy_data script"
        )));
    }

    let mut out = String::with_capacity(shell.len() - BODY_MARKER.len() + body.len());
    out.push_str(&shell[..body_at]);
    out.push_str(body);
    out.push_str(&shell[body_at + BODY_MARKER.len()..]);
    Ok(out)
}

/// The `cache-control` a document reply carries.
///
/// `public` needs THREE simultaneous declarations — the route is Static,
/// the route names a cache life, and the app set `PUBLIC_STATIC` — because
/// each one alone is not a statement that the document is viewer-
/// independent, and a shared cache serving one user's page to another is
/// the defect this default exists to prevent. Everything else keeps
/// today's `private, no-cache`.
///
/// The window math maps the cache life onto HTTP's two shared-cache knobs:
/// `s-maxage` is the revalidate window (how long a cache may serve without
/// asking), and `stale-while-revalidate` is the remainder to expiry (how
/// long it may keep serving while it refetches) — the same fresh/stale
/// split the server-side envelope enforces, spoken in the cache's language.
fn document_cache_control<A: AlloyApp>(route: Option<&Route>) -> String {
    const PRIVATE: &str = "private, no-cache";
    let life = route
        .filter(|route| A::PUBLIC_STATIC && route.render == RenderMode::Static)
        .and_then(Route::cache_life);
    let Some(life) = life else {
        return PRIVATE.to_string();
    };
    let (_stale_ms, revalidate_ms, expire_ms) = life.windows();
    let s_maxage = revalidate_ms / 1_000;
    let swr = expire_ms.saturating_sub(revalidate_ms) / 1_000;
    format!("public, s-maxage={s_maxage}, stale-while-revalidate={swr}")
}

/// Apply a route's declared headers to a reply, LAST and replacing.
///
/// Replacement is what makes the declaration authoritative: a route that
/// names `content-security-policy` overrides the nonce-derived one, and a
/// route that names `cache-control` overrides the derived caching policy.
/// Appending instead would ship two values under one name and leave the
/// winner to whatever the reader does with duplicates.
fn apply_route_headers(reply: &mut IngressReply, route: &Route) {
    for (name, value) in route.headers() {
        reply
            .headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        reply.headers.push((name.clone(), value.clone()));
    }
}

fn loader_payload<A: AlloyApp>(
    route_id: &str,
    params: &Params,
    data: serde_json::Value,
) -> LoaderPayload {
    LoaderPayload {
        route: route_id.to_string(),
        params: params_json(params),
        data,
        build: A::BUILD.to_string(),
        epochs: Vec::new(),
    }
}

/// The loader payload a client navigation receives as JSON.
pub fn loader_reply<A: AlloyApp>(
    req: &IngressRequest,
    route_id: &str,
    params: &Params,
    data: serde_json::Value,
) -> IngressReply {
    let payload = loader_payload::<A>(route_id, params, data);
    json_reply(
        req,
        200,
        &serde_json::to_value(&payload).unwrap_or_default(),
    )
}

/// [`loader_reply`], for a RESOLVED route: the route's declared headers
/// ride the JSON payload too.
///
/// The declaration is per-ROUTE, not per-representation: a route that
/// demands `x-frame-options: DENY` demands it however its data leaves the
/// server, and a loader reply that dropped the headers would make the
/// protection depend on which navigation style the client happened to use.
pub fn loader_reply_for<A: AlloyApp>(
    req: &IngressRequest,
    route: &Route,
    params: &Params,
    data: serde_json::Value,
) -> IngressReply {
    let mut reply = loader_reply::<A>(req, &route.id, params, data);
    apply_route_headers(&mut reply, route);
    reply
}

/// The idempotency key for one delivery, bound to who sent it and what it
/// asked for.
///
/// The gateway hedges, so a duplicate delivery is a real pattern rather
/// than a hypothetical one. The caller's `idempotency-key` is always
/// present (the gateway falls back to the correlation id when the caller
/// sends none), but the caller CHOOSES it, so on its own it is not an
/// identity: a second person reusing it would be answered with the first
/// person's admitted result and have their own action dropped, and the same
/// person reusing it for a different input would be told an action ran that
/// never did. The key is therefore digested together with the session
/// credential the request presents (its `authorization` header and the
/// session cookies in [`SESSION_COOKIES`], never any other cookie) and the
/// exact method, path and body. A hedged copy or a client retry repeats all
/// of them and replays; anything else is a new action. Only the digest
/// leaves this function, never a credential.
///
/// An app that has already resolved the signed-in principal should prefer
/// [`idempotency_as`], which survives a session being refreshed between a
/// first attempt and its retry.
pub fn idempotency(req: &IngressRequest) -> String {
    let mut parts: Vec<(&str, &str)> = Vec::new();
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("authorization") {
            parts.push(("authorization", value.as_str()));
        } else if name.eq_ignore_ascii_case("cookie") {
            for pair in value.split(';') {
                let Some((cookie, session)) = pair.trim().split_once('=') else {
                    continue;
                };
                let cookie = cookie.trim();
                if let Some(known) = SESSION_COOKIES.iter().find(|known| **known == cookie) {
                    parts.push((known, session.trim()));
                }
            }
        }
    }
    parts.sort_by(|a, b| a.0.cmp(b.0));
    let mut credential = Vec::new();
    for (name, value) in parts {
        push_part(&mut credential, name.as_bytes());
        push_part(&mut credential, value.as_bytes());
    }
    bound_key(req, b"credential", &ferrite_app::crypto::sha256(&credential))
}

/// [`idempotency`], bound to a principal the application resolved itself
/// (a verified session's user id) instead of the presented credential.
pub fn idempotency_as(req: &IngressRequest, principal: &str) -> String {
    bound_key(req, b"principal", principal.as_bytes())
}

/// The session cookies the Ferrite sign-in packages set: `ferrite-sso`'s app
/// and docs sessions, `alloy-auth`'s session (and its `__Host-` form), and
/// `auth`'s production and development cookies.
pub const SESSION_COOKIES: &[&str] = &[
    "__Host-ferrite_app_session",
    "__Host-ferrite_docs_session",
    "alloy_session",
    "__Host-alloy_session",
    "__Host-ferrite_auth",
    "ferrite_auth_dev",
];

fn bound_key(req: &IngressRequest, kind: &[u8], who: &[u8]) -> String {
    let key = if req.idempotency_key.is_empty() {
        &req.correlation_id
    } else {
        &req.idempotency_key
    };
    let mut material = Vec::new();
    for part in [
        b"alloy-idempotency-v1".as_slice(),
        kind,
        who,
        key.as_bytes(),
        req.method.as_bytes(),
        req.path.as_bytes(),
        &req.body,
    ] {
        push_part(&mut material, part);
    }
    ferrite_app::crypto::hex(&ferrite_app::crypto::sha256(&material))
}

pub(crate) fn push_part(material: &mut Vec<u8>, part: &[u8]) {
    material.extend_from_slice(&(part.len() as u64).to_be_bytes());
    material.extend_from_slice(part);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_loop_drains_and_a_busy_one_still_does() {
        let mut pump = DrainPump::default();
        // A fresh pump is due immediately: an app that starts with a backlog
        // must not wait an interval before touching it.
        assert!(pump.due(0));
        pump.mark(0);
        pump.settle(false);
        assert!(!pump.due(1), "a settled pump must not spin");

        // Idle is the cheapest trigger.
        pump.idle();
        assert!(pump.due(1));
    }

    #[test]
    fn the_request_count_drives_the_drain_when_the_clock_does_not() {
        // THE case a wall-clock floor misses: a frozen or coarse clock. A
        // harness, a simulated run and a suspended instance all look like
        // this, and an interval-only pump would drain once and never again.
        let mut pump = DrainPump::default();
        pump.mark(0);
        pump.settle(false);
        for _ in 0..DRAIN_EVERY_N_REQUESTS {
            assert!(!pump.due(0), "drained before the count was reached");
            pump.handled();
        }
        assert!(pump.due(0), "the request count never triggered a drain");
    }

    #[test]
    fn the_interval_drives_the_drain_for_a_trickle_too_slow_to_count() {
        let mut pump = DrainPump::default();
        pump.mark(1_000);
        pump.settle(false);
        assert!(!pump.due(1_000 + DRAIN_INTERVAL_MS - 1));
        assert!(pump.due(1_000 + DRAIN_INTERVAL_MS));
    }

    #[test]
    fn a_truncated_pass_comes_back_but_not_forever() {
        // Chaining without a ceiling would run a full budget of effects for
        // every one request polled — the same starvation the per-pass budget
        // exists to prevent, merely spread across iterations.
        let mut pump = DrainPump::default();
        pump.mark(0);
        for _ in 0..MAX_CHAINED_PASSES {
            pump.settle(true);
            assert!(pump.due(0), "a truncated pass must come straight back");
            pump.mark(0);
        }
        // The ceiling is reached: the backlog now waits out an interval, so
        // the request loop gets an uncontended poll.
        pump.settle(true);
        assert!(!pump.due(0), "chained passes were not bounded");
    }

    #[test]
    fn a_pass_that_clears_its_work_resets_the_chain() {
        let mut pump = DrainPump::default();
        pump.mark(0);
        pump.settle(true);
        assert!(pump.due(0));
        pump.mark(0);
        pump.settle(false);
        assert!(!pump.due(0), "a cleared backlog must not keep chaining");
    }

    #[test]
    fn a_redirect_carries_its_location_header() {
        // A redirect is a VALUE in this framework, not a thrown exception,
        // so the shell is what turns it back into HTTP.
        let req = request();
        let reply = problem(&req, AlloyError::redirect("/after"));
        assert_eq!(reply.status, 307);
        assert!(reply
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("location") && v == "/after"));
    }

    #[test]
    fn a_prepared_reply_reaches_the_client_as_it_was_written() {
        // An admit that refuses with a gate's own reply (a 303 to sign-in,
        // a 403 naming the failed CSRF condition) must not be flattened
        // into a problem document on its way out.
        let req = request();
        let mut gate = IngressReply::new("the-gate-did-not-know", 303, Vec::new());
        gate.headers.extend([
            ("location".to_string(), "/auth/sign-in?return_to=%2Faccount".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
        ]);
        let reply = error_reply::<TestApp>(&req, AlloyError::reply(gate.clone()));
        assert_eq!(reply.status, 303);
        assert_eq!(reply.correlation_id, req.correlation_id, "re-stamped for this request");
        assert_eq!(reply.headers, gate.headers);
        assert!(reply.body.is_empty());

        let refusal = IngressReply::new("x", 403, b"csrf: no token".to_vec());
        let reply = problem(&req, AlloyError::reply(refusal));
        assert_eq!(reply.status, 403);
        assert_eq!(reply.body, b"csrf: no token");
    }

    #[test]
    fn a_problem_document_is_rfc9457_and_says_so_in_its_content_type() {
        let req = request();
        let reply = problem(&req, AlloyError::NotFound);
        assert_eq!(reply.status, 404);
        let ct = reply
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert_eq!(ct, "application/problem+json");
        let doc: serde_json::Value = serde_json::from_slice(&reply.body).expect("JSON");
        assert_eq!(doc["status"], 404);
        assert_eq!(doc["title"], "Not Found");
    }

    #[tokio::test]
    async fn an_action_method_is_matched_case_insensitively() {
        // `RouteTable::resolve` upper-cases before comparing, so a page
        // route admits `get`. The action face compared raw bytes, so the
        // same gateway normalisation that a page tolerated turned a legal
        // POST into a 405 here — one request, two verdicts, depending only
        // on which surface it reached.
        let mut actions: Actions<TestApp> = Actions::new();
        actions.public("noop", |_ctx, req| {
            Box::pin(async move { Ok(json_reply(req, 200, &serde_json::json!({ "ok": true }))) })
        });
        let env = ferrite_app_test::TestHarness::new().build().await;
        let ctx = env.context();
        let with_method = |method: &str| {
            let mut req = ferrite_app_test::ingress::post("/__alloy/action/noop", b"{}");
            req.method = method.into();
            req
        };

        for spelling in ["POST", "post", "Post", "pOsT"] {
            let reply = dispatch_action(&actions, &ctx, &with_method(spelling), "noop")
                .await
                .expect("the action runs");
            assert_eq!(reply.status, 200, "'{spelling}' did not reach the action");
        }
        let preflight = dispatch_action(&actions, &ctx, &with_method("options"), "noop")
            .await
            .expect("a preflight is answered");
        assert_eq!(preflight.status, 204);
        assert_eq!(header(&preflight, "allow"), "POST, OPTIONS");
        let refused = dispatch_action(&actions, &ctx, &with_method("get"), "noop")
            .await
            .expect("a wrong method is a reply");
        assert_eq!(refused.status, 405);
        assert_eq!(header(&refused, "allow"), "POST, OPTIONS");
    }

    #[test]
    fn a_cross_origin_caller_cannot_tell_a_mounted_action_from_an_unknown_one() {
        // The name used to be looked up first, so another site got
        // 400 for a name that is not mounted and 403 for one that is.
        let mut actions: Actions<TestApp> = Actions::new();
        actions.public("noop", |_ctx, req| {
            Box::pin(async move { Ok(json_reply(req, 200, &serde_json::json!({ "ok": true }))) })
        });
        let foreign = with_headers(&[("origin", "https://evil.example"), ("host", "app.example")]);
        let verdict = |name: &str| match admissible_route(&actions, &foreign, name) {
            Ok(_) => panic!("a cross-origin action must be refused"),
            Err(error) => (error.status(), error.to_string()),
        };
        assert_eq!(verdict("noop").0, 403);
        assert_eq!(verdict("noop"), verdict("no_such_action"));

        // Same-origin callers still learn that a name is wrong, and reach
        // the one that is right.
        let own = with_headers(&[("origin", "https://app.example"), ("host", "app.example")]);
        assert!(admissible_route(&actions, &own, "noop").is_ok());
        let unknown = admissible_route(&actions, &own, "no_such_action")
            .err()
            .expect("an unknown name is refused");
        assert_eq!(unknown.status(), 400);
    }

    #[test]
    fn a_405_names_the_methods_that_would_have_worked() {
        // A bare 405 tells a caller it was wrong; the Allow header tells it
        // what to do instead, which is the difference between a usable API
        // and a guessing game.
        let req = request();
        let reply = method_not_allowed(&req, &["GET".to_string(), "POST".to_string()]);
        assert_eq!(reply.status, 405);
        let allow = reply
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("allow"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert_eq!(allow, "GET, POST");
        // The document must agree with the status line it travels under.
        let doc: serde_json::Value = serde_json::from_slice(&reply.body).expect("a problem document");
        assert_eq!(doc["status"], 405);
        assert_eq!(doc["title"], "Method Not Allowed");
        assert_eq!(doc["type"], "urn:ferrite:problem:method-not-allowed");
        assert_eq!(doc["detail"], "method not allowed");
    }

    /// A minimal application, so the shell's own document assembly can be
    /// driven without standing up one of the five real apps.
    struct TestApp;

    struct BudgetHookApp;

    impl AlloyApp for BudgetHookApp {
        const BUILD: &'static str = "budget-hook";
        const SHELL: &'static str = "";

        async fn request_budget(ctx: &AppContext, req: &IngressRequest) -> Option<IngressReply> {
            let mut state = ctx.store("data").unwrap();
            state.add(b"budget_calls", 1).await.unwrap();
            if state.get(b"deny").await.unwrap().is_some() {
                // A slow refusal must not replace the remembered successful reply.
                ferrite_app::sleep_ms(550).await;
                Some(IngressReply::to(req, 429, b"budget refused".to_vec()))
            } else {
                None
            }
        }

        async fn answer(ctx: &AppContext, req: &IngressRequest) -> Result<IngressReply> {
            ctx.store("data").unwrap().add(b"handler_calls", 1).await.unwrap();
            ferrite_app::sleep_ms(550).await;
            Ok(IngressReply::to(req, 200, b"handled".to_vec()))
        }

        async fn seed(_ctx: &AppContext) -> Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn budget_hook_precedes_assets_replay_and_handler_effects() {
        let env = ferrite_app_test::TestHarness::new()
            .with_queue("requests").with_queue("replies")
            .with_store("cache").with_store("data").with_ape("tags")
            .with_blob("site").build().await;
        env.context().blob("site").unwrap().put(b"entry.js", b"asset").await.unwrap();
        env.run_app(|ctx| serve::<BudgetHookApp>(ctx));

        let asset = ferrite_app_test::ingress::get("/assets/entry.js");
        assert_eq!(env.handle(asset.clone()).await.unwrap().body, b"asset");
        let mut work = ferrite_app_test::ingress::get("/work");
        work.correlation_id = "budget-hook-replay".into();
        assert_eq!(env.handle(work.clone()).await.unwrap().status, 200);

        let mut state = env.store("data");
        state.put(b"deny", b"yes").await.unwrap();
        assert_eq!(env.handle(work.clone()).await.unwrap().status, 429);
        assert_eq!(env.handle(asset).await.unwrap().status, 429);
        state.delete(b"deny").await.unwrap();
        assert_eq!(env.handle(work).await.unwrap().body, b"handled");
        // Read atomically without changing the value. The permitted replay did
        // not repeat the handler, but every delivery met the budget hook.
        assert_eq!(state.add(b"handler_calls", 0).await.unwrap().0, 1);
        assert_eq!(state.add(b"budget_calls", 0).await.unwrap().0, 5);
    }

    impl AlloyApp for TestApp {
        const BUILD: &'static str = "test-1";
        const SHELL: &'static str = concat!(
            "<!doctype html><html><head><!--__alloy_head--></head><body>",
            "<div id=\"root\"></div>",
            "<script id=\"__alloy_data\" type=\"application/json\"></script>",
            "</body></html>"
        );

        async fn answer(_ctx: &AppContext, _req: &IngressRequest) -> Result<IngressReply> {
            Err(AlloyError::NotFound)
        }

        async fn seed(_ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    /// An app with two complete build-time bodies sharing one document
    /// shell, as generated static routes do.
    struct PrerenderedApp;

    impl AlloyApp for PrerenderedApp {
        const BUILD: &'static str = "static-1";
        const SHELL: &'static str = concat!(
            "<!doctype html><html><head><!--__alloy_head--></head><body>",
            "<div id=\"root\"><!--__alloy_body--></div>",
            "<script id=\"__alloy_data\" type=\"application/json\"></script>",
            "</body></html>"
        );

        fn prerendered_body(route_id: &str) -> Option<&'static str> {
            match route_id {
                "home" => Some("<main><h1>Home from the build</h1></main>"),
                "not_found" => Some("<main><h1>Page not found</h1></main>"),
                _ => None,
            }
        }

        async fn answer(_ctx: &AppContext, _req: &IngressRequest) -> Result<IngressReply> {
            Err(AlloyError::NotFound)
        }

        async fn seed(_ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    fn header(reply: &IngressReply, name: &str) -> String {
        reply
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    #[test]
    fn an_asset_reply_carries_a_static_servers_headers_and_a_refusal_says_why() {
        use crate::alloy::assets::{AssetReply, MAX_ASSET_REPLY_BYTES};

        let req = ferrite_app_test::ingress::get("/assets/entry.js");
        let served = asset_reply(&req, AssetReply::of("/assets/entry.js", Some(b"x()".to_vec()), None));
        assert_eq!(served.status, 200);
        assert_eq!(served.body.to_vec(), b"x()".to_vec());
        assert_eq!(header(&served, "content-type"), "text/javascript; charset=utf-8");
        assert_eq!(header(&served, "cache-control"), "public, max-age=300");
        assert!(header(&served, "vary").is_empty(), "no encodings, nothing to vary on");
        assert_eq!(header(&served, "x-content-type-options"), "nosniff");
        assert!(header(&served, "set-cookie").is_empty());

        // HEAD keeps the headers and drops the bytes, like every other reply.
        let mut head = req.clone();
        head.method = "HEAD".to_string();
        let withheld = withhold_head_body(&head, served.clone());
        assert!(withheld.body.is_empty());
        assert_eq!(header(&withheld, "etag"), header(&served, "etag"));

        let etag = header(&served, "etag");
        let revalidated = asset_reply(
            &req,
            AssetReply::of("/assets/entry.js", Some(b"x()".to_vec()), Some(&etag)),
        );
        assert_eq!(revalidated.status, 304);
        assert!(revalidated.body.is_empty());

        let missing = asset_reply(&req, AssetReply::Missing);
        assert_eq!(missing.status, 404);
        assert_eq!(header(&missing, "content-type"), "application/problem+json");

        let refused = asset_reply(&req, AssetReply::TooLarge { size: MAX_ASSET_REPLY_BYTES + 1 });
        assert_eq!(refused.status, 500);
        let doc: serde_json::Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(doc["type"], "urn:ferrite:problem:asset-too-large");
    }

    #[test]
    fn a_head_request_carries_the_get_headers_and_no_body() {
        // The router admits HEAD on every page, so a document request that
        // ignored the method would ship the whole payload to a caller that
        // asked for none of it. The headers must still describe the GET.
        let mut req = request();
        let get = document::<TestApp>(
            &req,
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("a GET renders");
        assert_eq!(get.status, 200);
        assert!(!get.body.is_empty());

        req.method = "HEAD".into();
        let head = document::<TestApp>(
            &req,
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("a HEAD answers");
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty(), "a HEAD must not carry a body");
        // …and it never names `content-length`: the gateway owns framing
        // and refuses any application reply that carries it.
        assert!(
            !head
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length")),
            "a reply must not carry content-length",
        );
        assert_eq!(header(&head, "content-type"), header(&get, "content-type"));
        assert_eq!(
            header(&head, "cache-control"),
            header(&get, "cache-control")
        );
    }

    #[test]
    fn a_route_gets_its_own_prerendered_body_and_old_shells_still_render() {
        let home = document::<PrerenderedApp>(
            &request(),
            "home",
            &Params::new(),
            serde_json::json!({ "page": "home" }),
            &Metadata::new().title("Home"),
        )
        .expect("the route-specific body renders");
        let html = String::from_utf8(home.body).expect("UTF-8");
        assert!(html.contains("<h1>Home from the build</h1>"));
        assert!(!html.contains(BODY_MARKER));
        assert!(html.contains("\"page\":\"home\""));

        // TestApp predates BODY_MARKER and uses the default hook. Its shell
        // remains byte-compatible rather than being forced through a new
        // marker requirement.
        let legacy = document::<TestApp>(
            &request(),
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("a legacy shell still renders");
        assert!(String::from_utf8(legacy.body)
            .expect("UTF-8")
            .contains("<div id=\"root\"></div>"));
    }

    struct NotFoundDocumentApp;

    impl AlloyApp for NotFoundDocumentApp {
        const BUILD: &'static str = PrerenderedApp::BUILD;
        const SHELL: &'static str = PrerenderedApp::SHELL;
        const NOT_FOUND_DOCUMENT: bool = true;

        fn prerendered_body(route_id: &str) -> Option<&'static str> {
            PrerenderedApp::prerendered_body(route_id)
        }

        async fn answer(_ctx: &AppContext, _req: &IngressRequest) -> Result<IngressReply> {
            Err(AlloyError::NotFound)
        }

        async fn seed(_ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    fn navigation(method: &str, path: &str, accept: &str) -> IngressRequest {
        let mut req = request();
        req.method = method.into();
        req.path = path.into();
        req.headers = vec![("accept".into(), accept.into())];
        req
    }

    #[test]
    fn an_opted_in_browser_navigation_that_misses_gets_the_document_with_404() {
        // R01 saw Flow answer a mistyped URL with a JSON problem although its
        // client renders a not-found screen for any unknown path.
        let browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        let reply = error_reply::<NotFoundDocumentApp>(&navigation("GET", "/nope?x=1", browser), AlloyError::NotFound);
        assert_eq!(reply.status, 404);
        assert_eq!(header(&reply, "content-type"), "text/html; charset=utf-8");
        let html = String::from_utf8(reply.body).expect("UTF-8");
        assert!(html.contains("<h1>Page not found</h1>"), "{html}");
        assert!(html.contains("\"route\":\"not_found\""), "{html}");
        assert!(html.contains("\"path\":\"/nope\""), "the query is not echoed as the path: {html}");
        assert!(html.contains("noindex, nofollow"));

        let head = error_reply::<NotFoundDocumentApp>(&navigation("HEAD", "/nope", browser), AlloyError::NotFound);
        assert_eq!(head.status, 404);
        assert!(head.body.is_empty());
    }

    #[test]
    fn everyone_else_still_gets_the_problem_document() {
        let browser = "text/html";
        let is_problem = |reply: &IngressReply| {
            reply.status == 404 && header(reply, "content-type") == "application/problem+json"
        };
        // Not opted in: unchanged behaviour for every existing app.
        assert!(is_problem(&error_reply::<PrerenderedApp>(&navigation("GET", "/nope", browser), AlloyError::NotFound)));
        // An agent or fetch asking for JSON.
        assert!(is_problem(&error_reply::<NotFoundDocumentApp>(&navigation("GET", "/nope", "application/json"), AlloyError::NotFound)));
        // No Accept header at all.
        let mut bare = request();
        bare.path = "/nope".into();
        bare.headers.clear();
        assert!(is_problem(&error_reply::<NotFoundDocumentApp>(&bare, AlloyError::NotFound)));
        // The reserved faces.
        assert!(is_problem(&error_reply::<NotFoundDocumentApp>(&navigation("GET", "/__alloy/loader?path=/x", browser), AlloyError::NotFound)));
        // A write.
        assert!(is_problem(&error_reply::<NotFoundDocumentApp>(&navigation("POST", "/nope", browser), AlloyError::NotFound)));
        // Other errors are never documents.
        let forbidden = error_reply::<NotFoundDocumentApp>(&navigation("GET", "/nope", browser), AlloyError::Forbidden);
        assert_eq!(forbidden.status, 403);
        assert_eq!(header(&forbidden, "content-type"), "application/problem+json");
    }

    #[test]
    fn a_designed_not_found_document_carries_404_and_head_semantics() {
        let reply = document_status::<PrerenderedApp>(
            &request(),
            "not_found",
            &Params::new(),
            serde_json::json!({ "path": "/missing" }),
            &Metadata::new()
                .title("Page not found")
                .robots("noindex, nofollow"),
            404,
        )
        .expect("the designed 404 renders");
        assert_eq!(reply.status, 404);
        assert_eq!(header(&reply, "content-type"), "text/html; charset=utf-8");
        let html = String::from_utf8(reply.body).expect("UTF-8");
        assert!(html.contains("<h1>Page not found</h1>"));
        assert!(html.contains("<meta name=\"robots\" content=\"noindex, nofollow\">"));

        let mut head = request();
        head.method = "HEAD".into();
        let reply = document_status::<PrerenderedApp>(
            &head,
            "not_found",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            404,
        )
        .expect("the designed 404 HEAD answers");
        assert_eq!(reply.status, 404);
        assert!(reply.body.is_empty());
    }

    #[test]
    fn prerendered_body_substitution_refuses_ambiguous_or_reserved_markers() {
        let no_body_marker = TestApp::SHELL;
        assert!(substitute_prerendered_body(no_body_marker, "<main>Hi</main>").is_err());

        let duplicate = PrerenderedApp::SHELL.replace("</div>", "<!--__alloy_body--></div>");
        assert!(substitute_prerendered_body(&duplicate, "<main>Hi</main>").is_err());

        assert!(substitute_prerendered_body(PrerenderedApp::SHELL, HEAD_MARKER).is_err());
        assert!(substitute_prerendered_body(PrerenderedApp::SHELL, DATA_SCRIPT_EMPTY).is_err());
    }

    #[test]
    fn a_document_is_never_offered_to_a_shared_cache() {
        // The payload is per-viewer: one user's document served to another
        // from a shared cache is the worst defect this function could have.
        let reply = document::<TestApp>(
            &request(),
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("renders");
        assert_eq!(header(&reply, "cache-control"), "private, no-cache");
    }

    #[test]
    fn no_reply_shape_names_a_gateway_owned_header() {
        // The gateway owns reply framing and connection state: an
        // application reply naming any of these headers is refused whole
        // (502 "application response headers refused"), so one stray
        // header takes the property down. Mirror the gateway's
        // is_forbidden_reply_header list and hold every reply shape this
        // package produces against it.
        const FORBIDDEN: &[&str] = &[
            "content-length",
            "connection",
            "transfer-encoding",
            "keep-alive",
            "upgrade",
            "proxy-connection",
            "te",
            "trailer",
            "x-correlation-id",
            "access-control-allow-origin",
        ];
        fn admissible(label: &str, reply: &IngressReply) {
            for (name, _) in &reply.headers {
                assert!(
                    !FORBIDDEN.iter().any(|f| name.eq_ignore_ascii_case(f)),
                    "{label} names the gateway-owned header {name}",
                );
            }
        }

        let mut req = request();
        let get = document::<TestApp>(
            &req,
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("a GET renders");
        admissible("the document reply", &get);
        req.method = "HEAD".into();
        let head = document::<TestApp>(
            &req,
            "home",
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
        )
        .expect("a HEAD answers");
        admissible("the HEAD reply", &head);
        req.method = "GET".into();
        admissible("the problem reply", &problem(&req, AlloyError::NotFound));
        admissible(
            "the json reply",
            &json_reply(&req, 200, &serde_json::json!({"ok": true})),
        );
        admissible(
            "the method refusal",
            &method_not_allowed(&req, &["GET".to_string(), "HEAD".to_string()]),
        );
    }

    #[test]
    fn an_options_preflight_is_answered_rather_than_refused() {
        // `resolve` derives OPTIONS into every Allow set it reports, so a
        // 405 here would contradict the header in its own reply: the
        // response would advertise OPTIONS and refuse it in one breath.
        let mut req = request();
        req.method = "OPTIONS".into();
        let allowed = vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()];
        let reply = method_not_allowed(&req, &allowed);
        assert_eq!(reply.status, 204);
        assert!(reply.body.is_empty());
        assert_eq!(header(&reply, "allow"), "GET, HEAD, OPTIONS");

        // Every other mismatch is still a genuine refusal.
        req.method = "DELETE".into();
        let refused = method_not_allowed(&req, &allowed);
        assert_eq!(refused.status, 405);
        assert_eq!(header(&refused, "allow"), "GET, HEAD, OPTIONS");
    }

    #[test]
    fn params_render_both_single_and_catch_all_shapes() {
        let mut params = Params::new();
        params.insert("id".into(), ParamValue::One("42".into()));
        params.insert(
            "slug".into(),
            ParamValue::Many(vec!["a".into(), "b".into()]),
        );
        let json = params_json(&params);
        assert_eq!(json["id"], "42");
        assert_eq!(json["slug"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn a_hedged_copy_of_a_slow_request_is_recalled_and_old_ones_are_forgotten() {
        let mut memory = HedgeMemory::default();
        memory.remember("c-1", b"reply".to_vec(), 200, 1_000);
        assert_eq!(memory.recall("c-1", 2_000), Some((b"reply".to_vec(), 200)));
        assert_eq!(memory.recall("c-2", 2_000), None);
        assert_eq!(memory.recall("c-1", 1_000 + HedgeMemory::KEEP_MS + 1), None);
        for n in 0..(HedgeMemory::CAPACITY + 5) {
            memory.remember(&format!("k-{n}"), Vec::new(), 200, 5_000);
        }
        assert_eq!(memory.entries.len(), HedgeMemory::CAPACITY);
        assert_eq!(memory.recall("k-0", 5_000), None);
        memory.prune(5_000 + HedgeMemory::KEEP_MS + 1);
        assert_eq!(memory.retained_bytes, 0);
    }

    #[test]
    fn hedge_memory_evicts_to_fit_bytes_and_skips_oversized_replies() {
        let mut memory = HedgeMemory::default();
        let mib = 1024 * 1024;
        memory.remember("a", vec![1; 3 * mib], 200, 1_000);
        memory.remember("b", vec![2; 2 * mib], 201, 1_000);
        memory.remember("c", vec![3; 4 * mib], 202, 1_000);
        assert_eq!(memory.recall("a", 1_000), None);
        assert_eq!(memory.recall("b", 1_000).unwrap().1, 201);
        assert_eq!(memory.retained_bytes, 6 * mib + 2);
        memory.remember("too-large", vec![0; HedgeMemory::MAX_BYTES], 200, 1_000);
        assert_eq!(memory.retained_bytes, 6 * mib + 2);
        assert_eq!(memory.recall("too-large", 1_000), None);
        let mut spare_capacity = Vec::with_capacity(HedgeMemory::MAX_BYTES);
        spare_capacity.push(1);
        memory.remember("allocated-too-large", spare_capacity, 200, 1_000);
        assert_eq!(memory.retained_bytes, 6 * mib + 2, "allocation capacity is charged");
        memory.prune(1_000 + HedgeMemory::KEEP_MS + 1);
        assert_eq!(memory.retained_bytes, 0);
        assert!(memory.entries.is_empty());
    }

    #[test]
    fn hedge_cache_encoding_is_bounded_before_retention() {
        let reply = IngressReply::new("small", 200, b"reply".to_vec());
        let encoded = HedgeMemory::encode("small", &reply).unwrap();
        assert_eq!(encoded, serde_json::to_vec(&reply).unwrap());
        assert!(encoded.capacity() + "small".len() <= HedgeMemory::MAX_BYTES);
        let oversized = IngressReply::new("large", 200, vec![0; HedgeMemory::MAX_BYTES]);
        assert!(HedgeMemory::encode("large", &oversized).is_none());
        // A Vec<u8> body expands into a JSON array; raw body length alone
        // cannot bound the encoded allocation.
        let expanding = IngressReply::new("expand", 200, vec![255; 3 * 1024 * 1024]);
        assert!(HedgeMemory::encode("expand", &expanding).is_none());
    }

    #[test]
    fn an_absent_idempotency_key_falls_back_to_the_correlation_id() {
        // The gateway hedges up to three times, so an action with no key at
        // all would be applied more than once. The fallback is what makes
        // every delivery recognisable.
        let mut keyless = request();
        keyless.correlation_id = "c-1".into();
        let mut keyed = keyless.clone();
        keyed.idempotency_key = "c-1".into();
        assert_eq!(idempotency(&keyless), idempotency(&keyed));
        let mut other = keyless.clone();
        other.correlation_id = "c-2".into();
        assert_ne!(idempotency(&keyless), idempotency(&other));
    }

    #[test]
    fn a_resolved_principal_binds_the_key_whatever_credential_carried_it() {
        let ana = keyed_delivery("c-1", "dark", "ana-session", "{}");
        let refreshed = keyed_delivery("c-2", "dark", "ana-refreshed-session", "{}");
        assert_eq!(idempotency_as(&ana, "ana"), idempotency_as(&refreshed, "ana"));
        assert_ne!(idempotency_as(&ana, "ana"), idempotency_as(&ana, "raj"));
        let changed = keyed_delivery("c-1", "dark", "ana-session", r#"{"n":1}"#);
        assert_ne!(idempotency_as(&ana, "ana"), idempotency_as(&changed, "ana"));
        let digest = idempotency_as(&ana, "ana");
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains("shared-key") && !idempotency(&ana).contains("ana-session"));
    }

    #[test]
    fn the_same_session_cookies_in_another_order_bind_the_same_key() {
        let mut first = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        first.headers.push(("cookie".into(), "theme=dark; alloy_session=s1; __Host-ferrite_app_session=p1".into()));
        let mut reordered = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        reordered.headers.push(("cookie".into(), "__Host-ferrite_app_session=p1".into()));
        reordered.headers.push(("cookie".into(), "alloy_session=s1; theme=light".into()));
        assert_eq!(idempotency(&first), idempotency(&reordered));
        let mut other = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        other.headers.push(("cookie".into(), "alloy_session=s2; __Host-ferrite_app_session=p1".into()));
        assert_ne!(idempotency(&first), idempotency(&other));
    }

    #[test]
    fn reversed_duplicate_session_cookies_do_not_share_a_key() {
        let mut ana_first = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        ana_first.headers.push(("cookie".into(), "alloy_session=ana; alloy_session=raj".into()));
        let mut raj_first = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        raj_first.headers.push(("cookie".into(), "alloy_session=raj; alloy_session=ana".into()));
        assert_ne!(idempotency(&ana_first), idempotency(&raj_first));
        let mut bearer_first = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        bearer_first.headers.push(("authorization".into(), "Bearer a".into()));
        bearer_first.headers.push(("authorization".into(), "Bearer b".into()));
        let mut bearer_reversed = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "k", "{}");
        bearer_reversed.headers.push(("authorization".into(), "Bearer b".into()));
        bearer_reversed.headers.push(("authorization".into(), "Bearer a".into()));
        assert_ne!(idempotency(&bearer_first), idempotency(&bearer_reversed));
    }

    fn keyed_delivery(correlation: &str, theme: &str, session: &str, body: &str) -> IngressRequest {
        let mut req = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "shared-key", body);
        req.correlation_id = correlation.into();
        req.headers.push(("cookie".into(), format!("theme={theme}; alloy_session={session}")));
        req
    }

    #[tokio::test]
    async fn a_reused_idempotency_key_replays_only_the_same_callers_same_input() {
        let env = ferrite_app_test::TestHarness::new().with_ape("tags").build().await;
        let ctx = env.context();
        let mut runner = crate::alloy::actions::ActionRunner::new(ctx.ape("tags").expect("the tag plane binds"));
        let none = crate::alloy::actions::Effects::new();

        let ana = keyed_delivery("c-1", "dark", "ana-session", r#"{"body":"from ana"}"#);
        let first = runner
            .commit("comment", &idempotency(&ana), &none, serde_json::json!({ "author": "ana" }), 1)
            .await
            .expect("ana's comment commits");
        assert!(first.first_admission);

        let retry_after_theme_change = keyed_delivery("c-2", "light", "ana-session", r#"{"body":"from ana"}"#);
        let replayed = runner
            .recorded("comment", &idempotency(&retry_after_theme_change))
            .await
            .expect("the marker reads")
            .expect("a retry of the same caller's same input replays");
        assert_eq!(replayed.result, serde_json::json!({ "author": "ana" }));

        let raj = keyed_delivery("c-3", "dark", "raj-session", r#"{"body":"from ana"}"#);
        assert!(
            runner.recorded("comment", &idempotency(&raj)).await.expect("the marker reads").is_none(),
            "another person's reuse of the key was answered with ana's result"
        );
        let by_raj = runner
            .commit("comment", &idempotency(&raj), &none, serde_json::json!({ "author": "raj" }), 2)
            .await
            .expect("raj's comment commits");
        assert!(by_raj.first_admission, "raj's own action was dropped");
        assert_eq!(by_raj.result, serde_json::json!({ "author": "raj" }));

        let changed = keyed_delivery("c-4", "dark", "ana-session", r#"{"body":"second from ana"}"#);
        assert!(
            runner.recorded("comment", &idempotency(&changed)).await.expect("the marker reads").is_none(),
            "the same key with a different input replayed the first input's result"
        );

        let mut bearer = ferrite_app_test::ingress::post_keyed("/__alloy/action/comment", "shared-key", r#"{"body":"from ana"}"#);
        bearer.headers.push(("authorization".into(), "Bearer other-token".into()));
        assert!(
            runner.recorded("comment", &idempotency(&bearer)).await.expect("the marker reads").is_none(),
            "a bearer caller's reuse of the key was answered with ana's result"
        );
    }

    /// A GET request for `path`, built by the harness rather than by hand.
    ///
    /// NOT a field-by-field literal, deliberately. Two crates are named
    /// `ferrite-app`: the local-dev twin and the platform SDK an attested
    /// build redirects to. The real SDK's `IngressRequest` carries a
    /// `native_caller` the twin does not, so a literal naming every field
    /// compiles against exactly ONE of them and the application stops being
    /// portable across the redirect. `Default` is not implemented on either.
    /// Both ship `ingress::get`, so that is the portable spelling.
    fn request() -> IngressRequest {
        ferrite_app_test::ingress::get("/")
    }

    /// The same app with the public-static opt-in set, so the derivation
    /// can be observed both off (the default) and on.
    struct PublicApp;

    impl AlloyApp for PublicApp {
        const BUILD: &'static str = TestApp::BUILD;
        const SHELL: &'static str = TestApp::SHELL;
        const PUBLIC_STATIC: bool = true;

        async fn answer(_ctx: &AppContext, _req: &IngressRequest) -> Result<IngressReply> {
            Err(AlloyError::NotFound)
        }

        async fn seed(_ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    fn static_route(life: Option<crate::alloy::cache::CacheLife>) -> crate::alloy::router::Route {
        let route = crate::alloy::router::Route::page("home", "/")
            .expect("the pattern parses")
            .with_render(crate::alloy::router::RenderMode::Static);
        match life {
            Some(life) => route.with_cache_life(life),
            None => route,
        }
    }

    #[test]
    fn route_headers_ride_the_document_and_the_loader_reply() {
        // The declaration is per-route, not per-representation: dropping
        // the headers on the JSON path would make `x-frame-options` depend
        // on which navigation style the client happened to use.
        let route = crate::alloy::router::Route::page("home", "/")
            .unwrap()
            .with_headers(&[
                ("x-frame-options", "DENY"),
                ("referrer-policy", "same-origin"),
            ]);
        let req = request();

        let doc = document_for::<TestApp>(
            &req,
            &route,
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            None,
        )
        .expect("renders");
        assert_eq!(header(&doc, "x-frame-options"), "DENY");
        assert_eq!(header(&doc, "referrer-policy"), "same-origin");

        let status_doc = document_for_status::<TestApp>(
            &req,
            &route,
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            None,
            404,
        )
        .expect("a status document renders");
        assert_eq!(status_doc.status, 404);
        assert_eq!(header(&status_doc, "x-frame-options"), "DENY");

        let loader =
            loader_reply_for::<TestApp>(&req, &route, &Params::new(), serde_json::json!({}));
        assert_eq!(header(&loader, "x-frame-options"), "DENY");
    }

    #[test]
    fn a_route_header_wins_over_a_shell_derived_one() {
        // Replacement, not appending: two values under one name leave the
        // winner to whatever the reader does with duplicates.
        let route = crate::alloy::router::Route::page("home", "/")
            .unwrap()
            .with_headers(&[("cache-control", "private, max-age=30")]);
        let reply = document_for::<TestApp>(
            &request(),
            &route,
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            None,
        )
        .expect("renders");
        assert_eq!(header(&reply, "cache-control"), "private, max-age=30");
        assert_eq!(
            reply
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
                .count(),
            1
        );
    }

    #[test]
    fn public_caching_needs_the_opt_in_the_render_mode_and_a_declared_life() {
        // All three declarations, or private: each alone is not a statement
        // that the document is viewer-independent.
        let life = crate::alloy::cache::CacheLife::Custom {
            stale_ms: 0,
            revalidate_ms: 60_000,
            expire_ms: 360_000,
        };
        let req = request();
        let render = |route| {
            document_for::<PublicApp>(
                &req,
                &route,
                &Params::new(),
                serde_json::json!({}),
                &Metadata::new(),
                None,
            )
            .expect("renders")
        };

        // Opted in + Static + a life: public, with the derived windows.
        // s-maxage is the revalidate window; stale-while-revalidate is the
        // remainder to expiry.
        let public = render(static_route(Some(life)));
        assert_eq!(
            header(&public, "cache-control"),
            "public, s-maxage=60, stale-while-revalidate=300"
        );

        // Static but no declared life: private.
        let no_life = render(static_route(None));
        assert_eq!(header(&no_life, "cache-control"), "private, no-cache");

        // A life on a HYBRID route: private — the payload is per-request.
        let hybrid = crate::alloy::router::Route::page("home", "/")
            .unwrap()
            .with_cache_life(life);
        assert_eq!(
            header(&render(hybrid), "cache-control"),
            "private, no-cache"
        );

        // And the same static+life route WITHOUT the app opt-in: private.
        let opted_out = document_for::<TestApp>(
            &req,
            &static_route(Some(life)),
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            None,
        )
        .expect("renders");
        assert_eq!(header(&opted_out, "cache-control"), "private, no-cache");
    }

    #[test]
    fn a_nonce_reaches_the_scripts_and_the_csp_header_together() {
        // The stamp and the header are one feature: a header without the
        // stamp blocks the app's own scripts; a stamp without the header
        // protects nothing.
        let route = crate::alloy::router::Route::page("home", "/").unwrap();
        let reply = document_for::<TestApp>(
            &request(),
            &route,
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            Some("r4nd0m"),
        )
        .expect("renders");
        assert_eq!(
            header(&reply, "content-security-policy"),
            "script-src 'self' 'nonce-r4nd0m'"
        );
        let html = String::from_utf8(reply.body).expect("UTF-8");
        assert!(html.contains("<script nonce=\"r4nd0m\" id=\"__alloy_data\""));

        // A route declaring its own CSP wins over the derived one.
        let pinned = route.with_headers(&[("content-security-policy", "default-src 'none'")]);
        let reply = document_for::<TestApp>(
            &request(),
            &pinned,
            &Params::new(),
            serde_json::json!({}),
            &Metadata::new(),
            Some("r4nd0m"),
        )
        .expect("renders");
        assert_eq!(
            header(&reply, "content-security-policy"),
            "default-src 'none'"
        );
    }

    fn with_headers(headers: &[(&str, &str)]) -> IngressRequest {
        let mut req = ferrite_app_test::ingress::post("/__alloy/action/x", b"{}");
        for (k, v) in headers {
            req.headers.push((k.to_string(), v.to_string()));
        }
        req
    }

    /// What upstream's gateway publishes for a browser POST on a route that
    /// forwards `origin` and `sec-fetch-site`: no host of any kind.
    fn from_gateway(origin: &str, fetch_site: &str) -> IngressRequest {
        with_headers(&[("origin", origin), ("sec-fetch-site", fetch_site)])
    }

    #[test]
    fn the_browsers_cross_site_verdict_outranks_a_missing_origin_or_a_host_match() {
        // finding_7597ca11540f3cff
        let refused = check_action_origin::<TestApp>(&with_headers(&[("sec-fetch-site", "cross-site")]));
        assert!(refused.is_err(), "a cross-site POST without Origin passed");
        let refused = check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "http://app.example"),
            ("host", "app.example"),
            ("sec-fetch-site", "cross-site"),
        ]));
        assert!(refused.is_err(), "a scheme-blind host match outranked the browser");
        assert!(check_action_origin::<TestApp>(&with_headers(&[("sec-fetch-site", "none")])).is_ok());
        assert!(check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "https://app.example"),
            ("host", "app.example"),
            ("sec-fetch-site", "same-origin"),
        ]))
        .is_ok());
    }

    #[test]
    fn a_cross_origin_action_is_refused_before_it_is_admitted() {
        // The victim's browser attaches the victim's real cookies, so
        // admission passes; the Origin header is what identifies the forged
        // request, and mismatch is a 403.
        let refused = check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "https://evil.example"),
            ("host", "app.example"),
        ]))
        .expect_err("a mismatched origin must be refused");
        assert_eq!(refused.status(), 403);
        assert_eq!(refused, AlloyError::Forbidden);
    }

    #[test]
    fn an_absent_origin_passes_and_a_matching_one_does_too() {
        // No Origin header means a non-browser client, which cannot be
        // confused into attaching someone else's cookies — the only attack
        // this gate exists for.
        assert!(check_action_origin::<TestApp>(&with_headers(&[("host", "app.example")])).is_ok());
        assert!(check_action_origin::<TestApp>(&request()).is_ok());

        // Same host (with and without an explicit port) passes.
        assert!(check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "https://app.example"),
            ("host", "app.example"),
        ]))
        .is_ok());
        assert!(check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "http://localhost:3000"),
            ("host", "localhost:3000"),
        ]))
        .is_ok());
    }

    #[test]
    fn origin_spoofing_shapes_do_not_pass_the_gate() {
        // Each of these is a spelling an attacker controls; none may read
        // as same-origin with `app.example`.
        for hostile in [
            "null",                         // a sandboxed iframe
            "",                             // empty
            "https://app.example.evil.com", // suffix-extended host
            "https://evil.com/app.example", // host in the path
            "https://app.example@evil.com", // userinfo trick (host is evil.com…
            "app.example",                  // …and a bare host is not an origin)
        ] {
            let verdict = check_action_origin::<TestApp>(&with_headers(&[
                ("origin", hostile),
                ("host", "app.example"),
            ]));
            assert!(verdict.is_err(), "'{hostile}' passed the origin gate");
        }
        // An origin with no authority at all to compare against — no
        // attached host, no forwarded header — is unverifiable, and
        // unverifiable is refused.
        assert!(check_action_origin::<TestApp>(&with_headers(&[(
            "origin",
            "https://app.example"
        )]))
        .is_err());
    }

    /// Upstream Ferrite Core states no host at all. The browser's own
    /// `sec-fetch-site` verdict is then the one sound signal, and only its
    /// `same-origin` value passes: anything else, or nothing, is refused.
    #[test]
    fn with_no_host_at_all_only_the_browsers_same_origin_verdict_passes() {
        let judged = |site: Option<&str>| {
            let mut headers = vec![("origin", "https://app.example")];
            if let Some(site) = site {
                headers.push(("sec-fetch-site", site));
            }
            check_action_origin::<TestApp>(&with_headers(&headers))
        };
        assert!(judged(Some("same-origin")).is_ok());
        assert!(judged(Some("Same-Origin")).is_ok());
        for refused in [Some("cross-site"), Some("same-site"), Some("none"), Some(""), None] {
            assert!(judged(refused).is_err(), "{refused:?} passed with no host to compare");
        }
        // Where a host IS stated, the comparison decides and the header cannot
        // overrule it: a foreign origin stays refused whatever it claims.
        assert!(check_action_origin::<TestApp>(&with_headers(&[
            ("origin", "https://evil.example"),
            ("host", "app.example"),
            ("sec-fetch-site", "same-origin"),
        ]))
        .is_err());
    }

    #[test]
    fn the_allowlist_still_widens_a_gateway_attached_request() {
        // The allowlist is consulted AFTER the same-origin comparison, which
        // is why the old early return made it unreachable for exactly the
        // requests it existed to rescue.
        let check =
            |origin: &str| check_action_origin::<WidenedApp>(&from_gateway(origin, "cross-site"));
        assert!(check("https://admin.example").is_ok());
        assert!(check("https://tools.example").is_ok());
        assert!(check("https://evil.example").is_err());
    }

    /// An app that allowlists a second origin for its actions.
    struct WidenedApp;

    impl AlloyApp for WidenedApp {
        const BUILD: &'static str = TestApp::BUILD;
        const SHELL: &'static str = TestApp::SHELL;
        const ALLOWED_ACTION_ORIGINS: &'static [&'static str] =
            &["https://admin.example", "tools.example"];

        async fn answer(_ctx: &AppContext, _req: &IngressRequest) -> Result<IngressReply> {
            Err(AlloyError::NotFound)
        }

        async fn seed(_ctx: &AppContext) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_allowlisted_origin_passes_and_only_that_origin() {
        // A full-origin entry pins the scheme; a bare-host entry accepts
        // any scheme; a substring of either is still refused.
        let check = |origin: &str| {
            check_action_origin::<WidenedApp>(&with_headers(&[
                ("origin", origin),
                ("host", "app.example"),
            ]))
        };
        assert!(check("https://admin.example").is_ok());
        assert!(check("https://tools.example").is_ok());
        assert!(
            check("http://tools.example").is_ok(),
            "a bare-host entry accepts any scheme"
        );
        assert!(
            check("http://admin.example").is_err(),
            "a full-origin entry pins the scheme"
        );
        assert!(check("https://admin.example.evil.com").is_err());
        assert!(check("https://evil.example").is_err());
    }
}
