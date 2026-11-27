//! The readiness router: ONE call before the app's own routing answers every
//! agent-readiness path from the declared [`Surface`].
//!
//! ```ignore
//! if let Some((status, ctype, body)) = well_known::handle(&surface, &req.method, &req.path, &req.headers, &req.body, &pages, &exec).await {
//!     return reply(status, ctype, body);
//! }
//! // ... the app's own routes ...
//! ```
//!
//! Markdown negotiation: three mechanisms serve the same clean-markdown twin
//! of a content page —
//! - the **`.md` path twin** (`/docs/pricing.md`, `/index.md`);
//! - the **`?format=md` query** on the canonical URL;
//! - an **`Accept` header that prefers `text/markdown`** (parsed per
//!   RFC 9110 §12.5.1: comma list, q-values, `text/*` and `*/*` wildcards),
//!   answering at the SAME canonical URL. The header reaches the app when
//!   the route declares `"forward_headers": ["accept"]` in `ferrite.json`.
//!
//! Precedence: an explicit ask always wins — a `.md` path or `?format=md`
//! query serves markdown regardless of `Accept`; the header is consulted
//! only when neither is present. A tie (e.g. `*/*`, or naming both
//! `text/markdown` and `text/html` at equal quality) keeps the canonical
//! HTML answer.
//!
//! Vary delta: the canonical URL's representation varies on `Accept`, and
//! honest HTTP advertises that with a `Vary: Accept` response header. The
//! widened [`handle_h`] returns the extra headers a host must emit; the
//! legacy [`handle`] shape drops them for hosts that cannot carry headers.

use ferrite_app::serde_json;

use crate::agent_ready::a2a_face;
use crate::agent_ready::artefacts::{self, paths};
use crate::agent_ready::catalog;
use crate::agent_ready::mcp_face::{self, ToolOutcome};
use crate::agent_ready::problem;
use crate::agent_ready::query;
use crate::agent_ready::score;
use crate::agent_ready::surface::Surface;
use crate::agent_ready::telemetry::{self, AgentEvent};

/// A served readiness answer: HTTP status, content type, body.
pub type Answer = (u16, &'static str, Vec<u8>);

/// [`Answer`] plus response headers the host must add (e.g. `Vary: Accept`
/// on a negotiated representation, so caches keep the twins separate).
pub type AnswerH = (u16, &'static str, Vec<u8>, Vec<(&'static str, String)>);

/// Look up a content page's markdown body by path. The host supplies this —
/// pages may live in code, in the blob store, or be rendered on demand.
pub trait PageSource {
    /// Async tools backed by the host's durable, authenticated Tasks store.
    fn task_tools(&self) -> Vec<String> {
        Vec::new()
    }
    /// Set only when the native host replaces successful subscriptions/listen
    /// dispatch with a real SSE stream driven by task_stream::TaskSubscription.
    fn task_streaming(&self) -> bool {
        false
    }
    fn task_call(
        &self,
        _method: String,
        _params: serde_json::Value,
    ) -> impl std::future::Future<Output = Result<serde_json::Value, crate::agent_ready::tasks::TaskError>>
    {
        async { Err(crate::agent_ready::tasks::TaskError::unavailable()) }
    }
    /// Caller-appropriate event declarations; empty means no Events capability.
    fn events(&self) -> Vec<crate::agent_ready::events::EventType> {
        Vec::new()
    }
    /// Recheck authorization and validate event-specific arguments on EVERY poll.
    /// Return a bounded proposal-shaped response, e.g. through `poll_snapshot`.
    fn poll_event(
        &self,
        _request: crate::agent_ready::events::PollRequest,
    ) -> impl std::future::Future<
        Output = Result<serde_json::Value, crate::agent_ready::events::EventError>,
    > {
        async { Err(crate::agent_ready::events::EventError::forbidden()) }
    }

    /// Delivery modes mounted by the host. Ordinary body-only hosts keep polling.
    fn event_delivery(&self) -> Vec<&'static str> {
        vec!["poll"]
    }
    /// Override for webhook registry dispatch; streaming hosts handle their stream
    /// response before the body-only router. Never return a fake finite push response.
    fn event_call(
        &self,
        method: String,
        params: serde_json::Value,
    ) -> impl std::future::Future<
        Output = Result<serde_json::Value, crate::agent_ready::events::EventError>,
    > {
        async move {
            if method == "events/poll" {
                self.poll_event(crate::agent_ready::events::PollRequest::parse(&params)?)
                    .await
            } else {
                Err(
                    crate::agent_ready::events::EventError::unsupported_delivery(
                        if method == "events/stream" {
                            "push"
                        } else {
                            "webhook"
                        },
                    ),
                )
            }
        }
    }

    /// Authored, caller-appropriate workflows served over MCP. Empty by default.
    fn skills(&self) -> Vec<crate::agent_ready::skills::Skill> {
        Vec::new()
    }
    /// Optional MCP Apps UI resources (`ui://...`, `text/html;profile=mcp-app`)
    /// and their linked tool names (`_meta.ui.resourceUri`).
    fn mcp_ui_resources(&self) -> Vec<mcp_face::UiResource> {
        Vec::new()
    }
    /// Optional plain MCP resources served through `resources/list` and `resources/read`.
    fn mcp_resources(&self) -> Vec<mcp_face::ResourceEntry> {
        Vec::new()
    }
    /// Optional MCP prompt templates served through `prompts/list`.
    fn mcp_prompts(&self) -> Vec<mcp_face::PromptEntry> {
        Vec::new()
    }
    /// Resolve a declared MCP prompt template for `prompts/get`.
    fn mcp_prompt_get(
        &self,
        _name: String,
        _arguments: serde_json::Value,
    ) -> impl std::future::Future<Output = Option<serde_json::Value>> {
        async { None }
    }
    /// Opt-in MCP File Uploads & Downloads capability (`io.modelcontextprotocol/files`).
    fn mcp_files_config(&self) -> crate::agent_ready::files::FilesConfig {
        crate::agent_ready::files::FilesConfig::default()
    }
    /// Opt-in standalone MRTR hook for `tools/call` on MCP 2026-07-28: return
    /// `Some(Ok(result))` to answer `input_required` (Elicitation),
    /// `upload_required` (File Uploads), or a `complete` result with `_meta`
    /// downloads; return `Some(Err(e))` for `-32021`/`-32602`; return `None`
    /// to fall through to the ordinary `exec` handler.
    fn mcp_tool_call_mrtr(
        &self,
        _name: String,
        _params: serde_json::Value,
    ) -> impl std::future::Future<
        Output = Option<Result<serde_json::Value, crate::agent_ready::elicitation::ElicitationError>>,
    > {
        async { None }
    }
    /// Opt-in HTTP handler for out-of-band MCP file transfer paths under `/mcp/files/*`
    /// (`PUT`/`POST` staged uploads and `GET` downloads with `Range` support).
    fn mcp_file_http(
        &self,
        _method: &str,
        _subpath: &str,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> impl std::future::Future<Output = Option<AnswerH>> {
        async { None }
    }
    /// Personal Agent Protocol (Poppy 1.0) configuration. `None` by default so
    /// apps opt in explicitly with their exposure, auth, and extension policy.
    fn poppy(&self) -> Option<crate::agent_ready::poppy::PoppyConfig> {
        None
    }
    /// Optional handler for `POST /poppy/feedback` (§9.3). Returning `Some(alt)`
    /// responds `200` with that `Alternative`; returning `None` responds `202`
    /// with an empty body.
    fn poppy_feedback(
        &self,
        _report: &crate::agent_ready::poppy::FeedbackReport,
    ) -> Option<crate::agent_ready::poppy::Alternative> {
        None
    }
    /// The app's own password-change page, served at
    /// `/.well-known/change-password` as a 303. The default is `None`: an app
    /// that has no such page advertises nothing and discovery answers 404.
    /// This is discovery metadata, not a public content page: do not add the
    /// account page to the sitemap or expose its authenticated content as Markdown.
    fn change_password_url(&self) -> Option<&str> {
        None
    }

    /// The markdown body for `path`, if the page exists.
    fn markdown(&self, path: &str) -> Option<String>;
    /// The HTML body for `path`, if the page exists.
    fn html(&self, path: &str) -> Option<String>;
}

/// Answer a readiness path, or `None` when the path belongs to the app.
///
/// `headers` is the request's forwarded header list (`IngressRequest.
/// headers`: allowlisted, lowercase names); this router reads `accept` for
/// markdown negotiation and `mcp-protocol-version`, `mcp-method` and
/// `mcp-name` for the MCP face.
/// `exec` runs MCP tool calls (the host's own operation handler).
pub async fn handle<P, F, Fut>(
    surface: &Surface,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    pages: &P,
    exec: F,
) -> Option<Answer>
where
    P: PageSource + Sync,
    F: Fn(String, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    // Compatibility shape: hosts that cannot carry extra headers drop them.
    handle_h(surface, method, path, headers, body, pages, exec)
        .await
        .map(|(status, ctype, bytes, _)| {
            // Without Location, a 303 is unusable. The discovery response body
            // contains the W3C-permitted refresh fallback for legacy GET hosts.
            if status == 303 && method == "GET" {
                (200, ctype, bytes)
            } else if status == 303 {
                // A body-only HEAD response cannot carry either redirect form.
                (501, ctype, Vec::new())
            } else {
                (status, ctype, bytes)
            }
        })
}

/// Answer a readiness path, or `None` when the path belongs to the app —
/// the full form, carrying the response headers the host must emit.
///
/// `headers` is the request's forwarded header list (`IngressRequest.
/// headers`: allowlisted, lowercase names); this router reads `accept` for
/// markdown negotiation and `mcp-protocol-version`, `mcp-method` and
/// `mcp-name` for the MCP face.
/// `exec` runs MCP tool calls (the host's own operation handler).
///
/// The A2A face answers statelessly here (messages, no tasks). A host with a
/// caller-bound [`a2a_face::TaskStore`] calls [`handle_ht`] instead.
pub async fn handle_h<P, F, Fut>(
    surface: &Surface,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    pages: &P,
    exec: F,
) -> Option<AnswerH>
where
    P: PageSource + Sync,
    F: Fn(String, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    handle_ht(
        surface,
        method,
        path,
        headers,
        body,
        pages,
        &a2a_face::NoTasks,
        exec,
    )
    .await
}

/// [`handle_h`] with durable A2A tasks: `tasks` is the task store bound to
/// the authenticated caller (see [`a2a_face::TaskStore`]).
#[allow(clippy::too_many_arguments)]
pub async fn handle_ht<P, S, F, Fut>(
    surface: &Surface,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    pages: &P,
    tasks: &S,
    exec: F,
) -> Option<AnswerH>
where
    // `Sync` because `llms_full_txt` renders pages through a shared borrow
    // of the source.
    P: PageSource + Sync,
    S: a2a_face::TaskStore,
    F: Fn(String, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    if let Some(mut answer) =
        crate::http_change_password::handle(method, path, pages.change_password_url())
    {
        let ok = answer.status < 400;
        let mut evt = AgentEvent::discovery("/.well-known/change-password").with_ok(ok);
        if !ok {
            evt = evt.with_err(&answer.status.to_string());
        }
        answer.headers.push(evt.to_static_header());
        return Some((
            answer.status,
            "text/html; charset=utf-8",
            answer.body,
            answer.headers,
        ));
    }
    // Strip a `?format=md` (or any query) for matching; remember the ask.
    // The split and the read both go through the canonical decoder, so a
    // client that percent-encodes the parameter gets the same answer as one
    // that does not.
    let (bare, raw_query) = query::split_query(path);
    let wants_md = query::param(raw_query, "format").as_deref() == Some("md");
    let discovery_ans = |path: &str, a: Answer, mut hdrs: Vec<(&'static str, String)>| {
        let mut evt = AgentEvent::discovery(path);
        if a.0 >= 400 {
            evt = evt.with_ok(false).with_err(&a.0.to_string());
        }
        hdrs.push(evt.to_static_header());
        (a.0, a.1, a.2, hdrs)
    };
    let discovery_plain = |path: &str, a: Answer| discovery_ans(path, a, Vec::new());

    match (method, bare) {
        ("GET", p) if p == paths::ROBOTS => Some(discovery_plain(
            p,
            (
                200,
                "text/plain; charset=utf-8",
                artefacts::robots_txt(surface).into_bytes(),
            ),
        )),
        ("GET", p) if p == paths::SITEMAP => Some(discovery_plain(
            p,
            (
                200,
                "application/xml",
                artefacts::sitemap_xml(surface).into_bytes(),
            ),
        )),
        ("GET", p) if p == paths::LLMS => Some(discovery_plain(
            p,
            (
                200,
                "text/markdown; charset=utf-8",
                artefacts::llms_txt(surface).into_bytes(),
            ),
        )),
        ("GET", p) if p == paths::LLMS_FULL => Some(discovery_plain(
            p,
            (
                200,
                "text/markdown; charset=utf-8",
                artefacts::llms_full_txt(surface, &|path| pages.markdown(path)).into_bytes(),
            ),
        )),
        ("GET", p) if p == paths::OPENAPI || p == "/openapi.json" => Some(match catalog::openapi(surface) {
            Ok(document) => discovery_plain(
                p,
                (200, "application/json", serde_json::to_vec_pretty(&document).ok()?),
            ),
            Err(_) => (
                500,
                problem::CONTENT_TYPE,
                problem::problem_bytes(
                    500,
                    "ARDY_HTTP_DUP",
                    "Ambiguous HTTP catalogue",
                    "Two declared operations share an HTTP method and path; the catalogue cannot be served.",
                ),
                vec![AgentEvent::discovery(p)
                    .with_ok(false)
                    .with_err("ARDY_HTTP_DUP")
                    .to_static_header()],
            ),
        }),
        ("GET", p) if p == paths::AGENT_CARD => Some(discovery_plain(
            p,
            (
                200,
                "application/json",
                serde_json::to_vec_pretty(&catalog::agent_card(surface)).ok()?,
            ),
        )),
        // MCP discovery: the registry manifest and its well-known twin.
        ("GET", p) if p == paths::MCP_MANIFEST || p == paths::MCP_SERVER_CARD => Some(discovery_plain(
            p,
            (
                200,
                "application/json",
                serde_json::to_vec_pretty(&catalog::mcp_manifest(surface)).ok()?,
            ),
        )),
        // Agent Skills: the index and the one projected skill body.
        ("GET", p) if p == paths::SKILLS_INDEX => Some(discovery_plain(
            p,
            (
                200,
                "application/json",
                serde_json::to_vec_pretty(&{
                    let authored = pages.skills();
                    if authored.is_empty() {
                        catalog::skills_index(surface)
                    } else {
                        serde_json::json!({"$schema":"https://schemas.agentskills.io/index/v1.json", "skills": authored.iter().map(|skill| serde_json::json!({
                            "id": skill.uri, "name": skill.frontmatter["name"], "description": skill.frontmatter["description"],
                            "url": format!("/.well-known/agent-skills/{}", skill.uri.strip_prefix("skill://").unwrap_or(&skill.uri)),
                            "version": surface.version
                        })).collect::<Vec<_>>()})
                    }
                })
                .ok()?,
            ),
        )),
        ("GET", p) if p.starts_with("/.well-known/agent-skills/") && p != artefacts::SKILL_PATH => {
            let rel = p.strip_prefix("/.well-known/agent-skills/")?;
            let uri = format!("skill://{rel}");
            let skills = pages.skills();
            let file = skills.iter().flat_map(|skill| &skill.files).find(|file| file.uri == uri)?;
            let content_type: &'static str = match file.mime_type.as_str() {
                "text/markdown" => "text/markdown; charset=utf-8",
                "application/json" => "application/json",
                "text/plain" => "text/plain; charset=utf-8",
                "text/x-rust" => "text/x-rust; charset=utf-8",
                "application/toml" => "application/toml; charset=utf-8",
                "image/png" => "image/png",
                "application/pdf" => "application/pdf",
                _ => "application/octet-stream",
            };
            Some(discovery_plain(p, (200, content_type, file.bytes.clone())))
        }
        ("GET", p) if p == artefacts::SKILL_PATH => Some(discovery_plain(
            p,
            (
                200,
                "text/markdown; charset=utf-8",
                artefacts::skill_md(surface).into_bytes(),
            ),
        )),
        // Machine-readable pricing.
        ("GET", p) if p == paths::PRICING => Some(discovery_plain(
            p,
            (
                200,
                "text/markdown; charset=utf-8",
                artefacts::pricing_md(surface).into_bytes(),
            ),
        )),
        ("GET", p) if p == paths::READINESS => Some(discovery_plain(
            p,
            (
                200,
                "application/json",
                serde_json::to_vec_pretty(&score::readiness_json_with_poppy(
                    surface,
                    pages.poppy().as_ref(),
                ))
                .ok()?,
            ),
        )),
        // Personal Agent Protocol (Poppy 1.0) discovery, PRM, exposure-filtered OpenAPI,
        // tasks/skills (`0.2.0`), and feedback endpoints.
        ("GET", p) if p == crate::agent_ready::poppy::paths::DISCOVERY => {
            let cfg = pages.poppy()?;
            Some(discovery_ans(
                p,
                (
                    200,
                    "application/json",
                    serde_json::to_vec_pretty(&crate::agent_ready::poppy::poppy_json(surface, &cfg))
                        .ok()?,
                ),
                vec![("cache-control", "public, max-age=300".into())],
            ))
        }
        ("GET", p) if p == crate::agent_ready::poppy::paths::OAUTH_PRM_DOMAIN => {
            let cfg = pages.poppy()?;
            let doc = crate::agent_ready::poppy::domain_protected_resource_metadata(surface, &cfg)?;
            Some(discovery_ans(
                p,
                (200, "application/json", serde_json::to_vec_pretty(&doc).ok()?),
                vec![("cache-control", "public, max-age=300".into())],
            ))
        }
        ("GET", p) if p == crate::agent_ready::poppy::paths::OAUTH_PRM_MCP => {
            let cfg = pages.poppy()?;
            let doc = crate::agent_ready::poppy::mcp_protected_resource_metadata(surface, &cfg)?;
            Some(discovery_ans(
                p,
                (200, "application/json", serde_json::to_vec_pretty(&doc).ok()?),
                vec![("cache-control", "public, max-age=300".into())],
            ))
        }
        ("GET", p) if p == crate::agent_ready::poppy::paths::POPPY_OPENAPI => {
            let cfg = pages.poppy()?;
            Some(match crate::agent_ready::poppy::poppy_openapi(surface, &cfg) {
                Ok(document) => discovery_plain(
                    p,
                    (
                        200,
                        "application/json",
                        serde_json::to_vec_pretty(&document).ok()?,
                    ),
                ),
                Err(_) => (
                    500,
                    problem::CONTENT_TYPE,
                    problem::problem_bytes(
                        500,
                        "ARDY_HTTP_DUP",
                        "Ambiguous HTTP catalogue",
                        "Two declared operations share an HTTP method and path; the catalogue cannot be served.",
                    ),
                    vec![AgentEvent::discovery(p)
                        .with_ok(false)
                        .with_err("ARDY_HTTP_DUP")
                        .to_static_header()],
                ),
            })
        }
        ("GET", p) if p == crate::agent_ready::poppy::paths::TASKS => {
            let cfg = pages.poppy()?;
            if !cfg.enable_tasks {
                return None;
            }
            let doc = crate::agent_ready::poppy::tasks_json(surface, &cfg, &pages.skills());
            Some(discovery_ans(
                p,
                (200, "application/json", serde_json::to_vec_pretty(&doc).ok()?),
                vec![("cache-control", "public, max-age=300".into())],
            ))
        }
        ("POST", p) if p == crate::agent_ready::poppy::paths::FEEDBACK => {
            let cfg = pages.poppy()?;
            if !cfg.enable_tasks || !cfg.enable_feedback {
                return None;
            }
            match crate::agent_ready::poppy::parse_feedback_report(body) {
                Err(err) => {
                    let mut hdrs = err.headers.clone();
                    hdrs.push(
                        AgentEvent::discovery(p)
                            .with_ok(false)
                            .with_err(&err.error)
                            .to_static_header(),
                    );
                    Some((err.status, "application/json", err.to_json_bytes(), hdrs))
                }
                Ok(report) => match pages.poppy_feedback(&report) {
                    Some(alt) => Some(discovery_ans(
                        p,
                        (
                            200,
                            "application/json",
                            serde_json::to_vec(&alt).unwrap_or_default(),
                        ),
                        vec![("cache-control", "no-store".into())],
                    )),
                    None => Some(discovery_ans(
                        p,
                        (202, "application/json", Vec::new()),
                        vec![("cache-control", "no-store".into())],
                    )),
                },
            }
        }
        ("POST", p) if p == paths::MCP => {
            if let Some(refusal) = mcp_face::origin_refusal(surface, header(headers, "origin")) {
                let (status, resp_body) = mcp_face::with_request_id(refusal, body);
                let evt = mcp_face::telemetry_event(headers, body, status, &resp_body);
                return Some((
                    status,
                    "application/json",
                    resp_body,
                    vec![evt.to_static_header()],
                ));
            }
            // When a Poppy Personal Agent calls /mcp (carrying Poppy-Session) and the
            // host declared Poppy exposure policies, filter InternalOnly operations out
            // of the MCP surface so Personal Agents never see or invoke internal tools.
            let is_poppy_caller = header(headers, crate::agent_ready::poppy::headers::SESSION).is_some();
            let filtered_surface = if is_poppy_caller {
                pages.poppy().map(|cfg| {
                    let mut fs = surface.clone();
                    for r in &mut fs.routes {
                        r.operations.retain(|o| cfg.is_exposed(&o.name));
                    }
                    fs
                })
            } else {
                None
            };
            let active_surface = filtered_surface.as_ref().unwrap_or(surface);
            // The face reads the protocol-version header and SEP-2243's
            // mirrored `mcp-method` / `mcp-name`; a host that does not
            // forward the latter still gets a correct server (see the
            // mcp_face module notes).
            let files_cfg = pages.mcp_files_config();
            let extra_caps = mcp_face::ExtraCapabilities {
                ui_resources: pages.mcp_ui_resources(),
                resources: pages.mcp_resources(),
                prompts: pages.mcp_prompts(),
            };
            let (status, resp_body) = mcp_face::handle_h_complete(
                active_surface,
                mcp_face::RequestHeaders::from_list(headers),
                body,
                &pages.skills(),
                &pages.events(),
                &pages.event_delivery(),
                |method, params| pages.event_call(method, params),
                &pages.task_tools(),
                pages.task_streaming(),
                |method, params| pages.task_call(method, params),
                &files_cfg,
                &extra_caps,
                |name, args| pages.mcp_prompt_get(name, args),
                |name, params| pages.mcp_tool_call_mrtr(name, params),
                exec,
            )
            .await;
            let evt = mcp_face::telemetry_event(headers, body, status, &resp_body);
            Some((
                status,
                "application/json",
                resp_body,
                vec![
                    ("cache-control", "private, no-store".into()),
                    evt.to_static_header(),
                ],
            ))
        }
        (m, p) if p.starts_with("/mcp/files/") => {
            if let Some(refusal) = mcp_face::origin_refusal(surface, header(headers, "origin")) {
                let (status, resp_body) = mcp_face::with_request_id(refusal, &[]);
                let caller = mcp_face::caller_agent_from_headers(headers);
                let evt = AgentEvent::mcp(
                    mcp_face::PROTOCOL_VERSION,
                    "files",
                    None,
                    false,
                    Some(mcp_face::INVALID_REQUEST),
                    None,
                    caller.as_deref(),
                );
                return Some((
                    status,
                    "application/json",
                    resp_body,
                    vec![evt.to_static_header()],
                ));
            }
            let sub_path = p.strip_prefix("/mcp/files/").unwrap_or("");
            pages.mcp_file_http(m, sub_path, headers, body).await.map(|(st, ct, b, mut hdrs)| {
                if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case(telemetry::AGENT_EVENT_HEADER)) {
                    let caller = mcp_face::caller_agent_from_headers(headers);
                    let evt = AgentEvent::mcp(
                        mcp_face::PROTOCOL_VERSION,
                        "files",
                        None,
                        st < 400,
                        None,
                        None,
                        caller.as_deref(),
                    );
                    hdrs.push(evt.to_static_header());
                }
                (st, ct, b, hdrs)
            })
        }
        // The stateless MCP face serves POST only: no server-initiated SSE
        // stream (GET) and no session to terminate (DELETE). RFC 9110 requires
        // a 405 to say what IS allowed.
        (m, p) if p == paths::MCP => {
            let (status, resp_body) = problem::method_not_allowed(m, paths::MCP);
            let evt = AgentEvent::mcp("", m, None, false, None, None, None)
                .with_err("method_not_allowed");
            Some((
                status,
                problem::CONTENT_TYPE,
                resp_body,
                vec![("allow", "POST".into()), evt.to_static_header()],
            ))
        }
        ("POST", p) if p == paths::A2A => {
            // The same DNS-rebinding and cross-site defence as the MCP face:
            // a browser page on a foreign origin must not drive the agent
            // with the visitor's session.
            if let Some(refusal) = mcp_face::origin_refusal(surface, header(headers, "origin")) {
                let (status, resp_body) = mcp_face::with_request_id(refusal, body);
                let evt = a2a_face::telemetry_event(body, status, &resp_body);
                return Some((
                    status,
                    "application/json",
                    resp_body,
                    vec![evt.to_static_header()],
                ));
            }
            let (status, resp_body) = a2a_face::handle_with(surface, body, tasks, exec).await;
            let evt = a2a_face::telemetry_event(body, status, &resp_body);
            // Caller-scoped like the MCP face: never cached.
            Some((
                status,
                "application/json",
                resp_body,
                vec![
                    ("cache-control", "private, no-store".into()),
                    evt.to_static_header(),
                ],
            ))
        }
        (m, p) if p == paths::A2A => {
            let (status, resp_body) = problem::method_not_allowed(m, paths::A2A);
            let evt = AgentEvent::a2a(m, None, None, false, Some("method_not_allowed"));
            Some((
                status,
                problem::CONTENT_TYPE,
                resp_body,
                vec![("allow", "POST".into()), evt.to_static_header()],
            ))
        }
        // Markdown page twins: `/page.md`, `/page?format=md`, and `/index.md`.
        ("GET", p) if p.ends_with(".md") => {
            let source = p.trim_end_matches(".md");
            let source = if source.is_empty() || source == "/index" {
                "/"
            } else {
                source
            };
            page_markdown(surface, pages, source).map(|(status, ctype, bytes)| {
                let mut evt = AgentEvent::markdown(source, false);
                if status >= 400 {
                    evt = evt.with_ok(false).with_err(&status.to_string());
                }
                (status, ctype, bytes, vec![evt.to_static_header()])
            })
        }
        ("GET", p) if wants_md => page_markdown(surface, pages, p).map(|(status, ctype, bytes)| {
            let mut evt = AgentEvent::markdown(p, false);
            if status >= 400 {
                evt = evt.with_ok(false).with_err(&status.to_string());
            }
            (status, ctype, bytes, vec![evt.to_static_header()])
        }),
        // Accept negotiation: the SAME canonical URL answers in markdown
        // when the caller's Accept prefers it. The explicit asks above
        // (`.md` twin, `?format=md`) matched first, so they win. The
        // canonical URL's representation varies on Accept, and HONEST HTTP
        // says so — the host must emit this Vary so shared caches keep the
        // markdown and HTML twins separate.
        ("GET", p) if prefers_markdown(header(headers, "accept")) => {
            page_markdown(surface, pages, p).map(|(status, ctype, bytes)| {
                let mut evt = AgentEvent::markdown(p, true);
                if status >= 400 {
                    evt = evt.with_ok(false).with_err(&status.to_string());
                }
                (
                    status,
                    ctype,
                    bytes,
                    vec![("vary", "accept".into()), evt.to_static_header()],
                )
            })
        }
        _ => None,
    }
}

/// The first header value for `name`. The gateway forwards names lowercase;
/// matching stays case-insensitive for non-gateway callers (tests, bench).
fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// A media range's standing for one concrete type: quality in thousandths
/// (RFC 9110 q-values carry at most three decimals — integer compare, no
/// floats) and a specificity rank (2 = exact `type/subtype`, 1 = `type/*`,
/// 0 = `*/*`).
type Rank = (u16, u8);

/// The rank `accept` assigns to `mtype/msub`: the q-value of the MOST
/// SPECIFIC matching range (exact beats `type/*` beats `*/*`, per
/// RFC 9110 §12.5.1), or `None` when no range matches. Malformed list
/// members are skipped; a malformed q-value reads as 0 (never preferred).
fn accept_rank(accept: &str, mtype: &str, msub: &str) -> Option<Rank> {
    let mut best: Option<Rank> = None;
    for member in accept.split(',') {
        let mut params = member.split(';');
        let range = params.next().unwrap_or("").trim();
        let Some((t, s)) = range.split_once('/') else {
            continue;
        };
        let (t, s) = (t.trim(), s.trim());
        let spec: u8 = if t == "*" && s == "*" {
            0
        } else if t.eq_ignore_ascii_case(mtype) && s == "*" {
            1
        } else if t.eq_ignore_ascii_case(mtype) && s.eq_ignore_ascii_case(msub) {
            2
        } else {
            continue;
        };
        let q = params
            .filter_map(|p| {
                let p = p.trim();
                let (name, value) = p.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| q_thousandths(value))
            })
            .next()
            .unwrap_or(1000);
        // The most specific range wins; among equally specific ones, the highest q.
        if best.is_none_or(|(bq, bs)| (spec, q) > (bs, bq)) {
            best = Some((q, spec));
        }
    }
    best
}

/// Parse an RFC 9110 q-value (`1`, `0.5`, `0.05`, `1.000`) into thousandths;
/// anything malformed or out of range reads as 0.
fn q_thousandths(v: &str) -> u16 {
    let v = v.trim();
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    match int {
        "1" => {
            if frac.bytes().all(|b| b == b'0') {
                1000
            } else {
                0
            }
        }
        "0" => frac
            .bytes()
            .enumerate()
            .map(|(i, b)| u16::from(b - b'0') * 10u16.pow(2 - i as u32))
            .sum(),
        _ => 0,
    }
}

/// True when `accept` prefers `text/markdown` over `text/html`: markdown's
/// (quality, specificity) rank strictly exceeds HTML's. A tie — `*/*`,
/// `text/*`, or both types named at equal quality — keeps the canonical
/// HTML answer, so only a caller that actually asks for markdown gets it.
fn prefers_markdown(accept: Option<&str>) -> bool {
    let Some(accept) = accept else { return false };
    let Some(md) = accept_rank(accept, "text", "markdown") else {
        return false;
    };
    if md.0 == 0 {
        return false;
    }
    match accept_rank(accept, "text", "html") {
        Some(html) => md > html,
        None => true,
    }
}

fn page_markdown<P: PageSource>(surface: &Surface, pages: &P, path: &str) -> Option<Answer> {
    let known = surface.pages.iter().any(|pg| pg.path == path);
    let md = pages.markdown(path).or_else(|| {
        pages
            .html(path)
            .map(|h| crate::agent_ready::markdown::to_markdown(&h))
    });
    match md {
        Some(md) => Some((200, "text/markdown; charset=utf-8", md.into_bytes())),
        None if known => {
            let (status, body) = problem::not_found(path, &surface.origin);
            Some((status, problem::CONTENT_TYPE, body))
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Page, Route, RouteKind};
    use ferrite_app::serde_json::{self, Value};

    struct Pages;
    impl PageSource for Pages {
        fn markdown(&self, path: &str) -> Option<String> {
            (path == "/").then(|| "# Home\n\nHello.".to_string())
        }
        fn html(&self, path: &str) -> Option<String> {
            (path == "/about").then(|| "<h1>About</h1><p>Us.</p>".to_string())
        }
    }

    fn surface() -> Surface {
        Surface {
            name: "notes".into(),
            owner: "labs".into(),
            origin: "https://notes.example".into(),
            description: "A note-keeping API.".into(),
            version: "1.0.0".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "notes API".into(),
                operations: vec![Operation {
                    name: "list_notes".into(),
                    method: "GET".into(),
                    path: "/api/notes".into(),
                    description: "List notes.".into(),
                    input_schema: None,
                    output_schema: None,
                    read_only: true,
                    idempotent: true,
                    price_micros: 0,
                }],
            }],
            pages: vec![
                Page {
                    path: "/".into(),
                    title: "Home".into(),
                    summary: "home".into(),
                    updated_ms: 0,
                    core: true,
                },
                Page {
                    path: "/about".into(),
                    title: "About".into(),
                    summary: "about".into(),
                    updated_ms: 0,
                    core: true,
                },
                Page {
                    path: "/gone".into(),
                    title: "Gone".into(),
                    summary: "gone".into(),
                    updated_ms: 0,
                    core: false,
                },
            ],
        }
    }

    async fn run(method: &str, path: &str, body: &[u8]) -> Option<Answer> {
        run_h(method, path, &[], body).await
    }

    async fn run_h(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Option<Answer> {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        handle(
            &surface(),
            method,
            path,
            &headers,
            body,
            &Pages,
            |name, _args| async move { ToolOutcome::ok(serde_json::json!({ "tool": name })) },
        )
        .await
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        // The tests run under the harness's tokio-less test runner; a
        // hand-rolled block_on over an immediately-ready future is enough
        // because nothing here awaits a real resource.
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended in a ready-only test"),
        }
    }

    #[test]
    fn colliding_operations_refuse_the_catalogue_instead_of_losing_a_read() {
        let mut surface = surface();
        let mut duplicate = surface.routes[0].operations[0].clone();
        duplicate.name = "read_other_notes".into();
        duplicate.method = "get".into();
        surface.routes[0].operations.push(duplicate);
        assert!(surface
            .validate()
            .iter()
            .any(|error| error.starts_with("ARDY_HTTP_DUP:")));
        assert!(
            catalog::openapi(&surface).is_err(),
            "direct generation must refuse collisions too"
        );
        for path in [paths::OPENAPI, "/openapi.json"] {
            let answer = block(handle(
                &surface,
                "GET",
                path,
                &[],
                &[],
                &Pages,
                |_, _| async {
                    panic!("catalogue discovery must not execute an operation");
                    #[allow(unreachable_code)]
                    ToolOutcome::ok(serde_json::json!({}))
                },
            ))
            .unwrap();
            assert_eq!(answer.0, 500);
            assert_eq!(answer.1, problem::CONTENT_TYPE);
            let body: Value = serde_json::from_slice(&answer.2).unwrap();
            assert_eq!(body["code"], "ARDY_HTTP_DUP");
            assert!(body.get("paths").is_none());
        }
        surface.routes[0].operations[1].method = "POST".into();
        assert!(
            surface.http_collisions().is_empty(),
            "different methods may share a path"
        );
        let catalog = catalog::openapi(&surface).unwrap();
        assert_eq!(
            catalog["paths"]["/api/notes"]["get"]["operationId"],
            "list_notes"
        );
        assert_eq!(
            catalog["paths"]["/api/notes"]["post"]["operationId"],
            "read_other_notes"
        );
    }

    #[test]
    fn serves_all_wellknown_paths() {
        for (m, p, ct) in [
            ("GET", "/robots.txt", "text/plain; charset=utf-8"),
            ("GET", "/sitemap.xml", "application/xml"),
            ("GET", "/llms.txt", "text/markdown; charset=utf-8"),
            ("GET", "/llms-full.txt", "text/markdown; charset=utf-8"),
            ("GET", "/.well-known/api-catalog", "application/json"),
            ("GET", "/openapi.json", "application/json"),
            ("GET", "/.well-known/agent-card.json", "application/json"),
            ("GET", "/.well-known/agent-readiness", "application/json"),
        ] {
            let (status, ctype, body) =
                block(run(m, p, b"")).unwrap_or_else(|| panic!("no answer for {p}"));
            assert_eq!(status, 200, "{p}");
            assert_eq!(ctype, ct, "{p}");
            assert!(!body.is_empty(), "{p}");
        }
    }

    struct AccountPages(Option<&'static str>);

    impl PageSource for AccountPages {
        fn change_password_url(&self) -> Option<&str> {
            self.0
        }

        fn markdown(&self, _: &str) -> Option<String> {
            panic!("password discovery must not render account content")
        }

        fn html(&self, _: &str) -> Option<String> {
            panic!("password discovery must not render account content")
        }
    }

    #[test]
    fn password_discovery_precedes_markdown_and_does_not_dispatch_tools() {
        let surface = surface();
        let pages = AccountPages(Some("/account/password"));
        let headers = vec![("accept".into(), "text/markdown".into())];
        for method in ["GET", "HEAD", "POST"] {
            let answer = block(handle_h(
                &surface,
                method,
                "/.well-known/change-password?format=md&next=//evil.example",
                &headers,
                b"untrusted request body",
                &pages,
                |_, _| async { panic!("discovery must not dispatch tools") },
            ))
            .unwrap();
            assert_eq!(answer.0, if method == "POST" { 405 } else { 303 });
            if method != "POST" {
                assert!(answer.3.contains(&("location", "/account/password".into())));
            }
            if method == "HEAD" {
                assert!(answer.2.is_empty());
            }
        }
        let answer = block(handle_h(
            &surface,
            "GET",
            "/.well-known/change-password?format=md",
            &headers,
            b"",
            &AccountPages(None),
            |_, _| async { panic!("disabled discovery must not dispatch tools") },
        ))
        .unwrap();
        assert_eq!(answer.0, 404);
        assert!(answer.2.is_empty());
    }

    #[test]
    fn legacy_password_discovery_uses_a_refresh_document_instead_of_a_headerless_redirect() {
        let surface = surface();
        let pages = AccountPages(Some("/account/password"));
        let answer = block(handle(
            &surface,
            "GET",
            "/.well-known/change-password",
            &[],
            b"",
            &pages,
            |_, _| async { panic!("discovery must not dispatch tools") },
        ))
        .unwrap();
        assert_eq!(answer.0, 200);
        assert!(String::from_utf8(answer.2)
            .unwrap()
            .contains("http-equiv=\"refresh\""));
        let head = block(handle(
            &surface,
            "HEAD",
            "/.well-known/change-password",
            &[],
            b"",
            &pages,
            |_, _| async { panic!("discovery must not dispatch tools") },
        ))
        .unwrap();
        assert_eq!(head.0, 501);
    }

    #[test]
    fn mcp_round_trip() {
        let init = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let (status, _, body) =
            block(run("POST", "/mcp", &serde_json::to_vec(&init).unwrap())).unwrap();
        assert_eq!(status, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["result"]["serverInfo"]["name"], "notes");

        let call = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_notes","arguments":{}}});
        let (status, _, body) =
            block(run("POST", "/mcp", &serde_json::to_vec(&call).unwrap())).unwrap();
        assert_eq!(status, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["result"]["structuredContent"]["tool"], "list_notes");
        assert_eq!(v["result"]["isError"], false);
    }

    #[test]
    fn markdown_twins() {
        // Direct markdown source.
        let (s, ct, b) = block(run("GET", "/index.md", b"")).unwrap();
        assert_eq!((s, ct), (200, "text/markdown; charset=utf-8"));
        assert!(String::from_utf8(b).unwrap().contains("# Home"));
        // HTML converted.
        let (s, _, b) = block(run("GET", "/about.md", b"")).unwrap();
        assert_eq!(s, 200);
        let md = String::from_utf8(b).unwrap();
        assert!(md.contains("# About"), "{md}");
        // format=md query.
        let (s, _, _) = block(run("GET", "/about?format=md", b"")).unwrap();
        assert_eq!(s, 200);
        // Declared page with no source ⇒ problem+json 404, not silence.
        let (s, ct, _) = block(run("GET", "/gone.md", b"")).unwrap();
        assert_eq!(s, 404);
        assert_eq!(ct, "application/problem+json");
        // Unknown path ⇒ None (belongs to the app).
        assert!(block(run("GET", "/nope", b"")).is_none());
        assert!(block(run("GET", "/nope.md", b"")).is_none());
    }

    #[test]
    fn accept_rank_parses_q_values_wildcards_and_junk() {
        // Exact match, default quality.
        assert_eq!(
            accept_rank("text/markdown", "text", "markdown"),
            Some((1000, 2))
        );
        // Wildcards match at their specificity.
        assert_eq!(
            accept_rank("text/*;q=0.5", "text", "markdown"),
            Some((500, 1))
        );
        assert_eq!(accept_rank("*/*;q=0.05", "text", "markdown"), Some((50, 0)));
        // Unknown types do not match.
        assert_eq!(accept_rank("application/json", "text", "markdown"), None);
        // The MOST SPECIFIC matching range's q wins, even when lower.
        assert_eq!(
            accept_rank("*/*, text/markdown;q=0.2", "text", "markdown"),
            Some((200, 2))
        );
        // q parses case-insensitively and with surrounding space.
        assert_eq!(
            accept_rank("text/markdown ; Q=0.3", "text", "markdown"),
            Some((300, 2))
        );
        // finding_058c07ca351ee594: equal specificity keeps the higher q.
        assert_eq!(
            accept_rank("text/markdown;v=2;q=0, text/markdown;q=0.9", "text", "markdown"),
            Some((900, 2))
        );
        // Malformed q reads as 0; malformed members are skipped.
        assert_eq!(
            accept_rank("text/markdown;q=nope", "text", "markdown"),
            Some((0, 2))
        );
        assert_eq!(
            accept_rank("garbage, text/markdown", "text", "markdown"),
            Some((1000, 2))
        );
        // q-value grammar: at most three decimals, max 1.
        assert_eq!(q_thousandths("1"), 1000);
        assert_eq!(q_thousandths("1.000"), 1000);
        assert_eq!(q_thousandths("0.9"), 900);
        assert_eq!(q_thousandths("0.05"), 50);
        assert_eq!(q_thousandths("0.0501"), 0);
        assert_eq!(q_thousandths("1.5"), 0);
        assert_eq!(q_thousandths("2"), 0);
    }

    #[test]
    fn accept_preference_requires_markdown_to_win() {
        // Markdown named and unopposed, or opposed at lower quality.
        assert!(prefers_markdown(Some("text/markdown")));
        assert!(prefers_markdown(Some(
            "text/markdown;q=0.9, text/html;q=0.1"
        )));
        assert!(prefers_markdown(Some("text/markdown, */*;q=0.8")));
        // Naming markdown exactly beats HTML reached only via a wildcard.
        assert!(prefers_markdown(Some("text/markdown, */*")));
        // Ties keep the canonical HTML answer.
        assert!(!prefers_markdown(Some("*/*")));
        assert!(!prefers_markdown(Some("text/*")));
        assert!(!prefers_markdown(Some("text/markdown, text/html")));
        // HTML preferred, markdown refused, unknown-only, or no header.
        assert!(!prefers_markdown(Some("text/html")));
        assert!(!prefers_markdown(Some("text/markdown;q=0")));
        assert!(!prefers_markdown(Some("application/json")));
        assert!(!prefers_markdown(None));
    }

    #[test]
    fn accept_negotiation_and_precedence() {
        // Accept alone serves the markdown twin at the canonical URL.
        let (s, ct, b) = block(run_h("GET", "/", &[("accept", "text/markdown")], b"")).unwrap();
        assert_eq!((s, ct), (200, "text/markdown; charset=utf-8"));
        assert!(String::from_utf8(b).unwrap().contains("# Home"));
        // Header-name matching is case-insensitive.
        assert!(block(run_h("GET", "/", &[("Accept", "text/markdown")], b"")).is_some());
        // An HTML-preferring Accept leaves the canonical URL to the app.
        assert!(block(run_h("GET", "/about", &[("accept", "text/html")], b"")).is_none());
        // Explicit asks beat Accept: the `.md` twin and `?format=md` serve
        // markdown even when the header prefers HTML.
        let (s, ct, _) = block(run_h("GET", "/about.md", &[("accept", "text/html")], b"")).unwrap();
        assert_eq!((s, ct), (200, "text/markdown; charset=utf-8"));
        let (s, ct, _) = block(run_h(
            "GET",
            "/about?format=md",
            &[("accept", "text/html")],
            b"",
        ))
        .unwrap();
        assert_eq!((s, ct), (200, "text/markdown; charset=utf-8"));
        // A non-page path stays the app's even under a markdown Accept.
        assert!(block(run_h("GET", "/nope", &[("accept", "text/markdown")], b"")).is_none());
    }

    #[test]
    fn mcp_protocol_version_header_flows_through() {
        let ping = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"});
        let body = serde_json::to_vec(&ping).unwrap();
        // The released wire's version and a missing header both serve.
        let hdr = [("mcp-protocol-version", mcp_face::LEGACY_PROTOCOL_VERSION)];
        let (s, _, _) = block(run_h("POST", "/mcp", &hdr, &body)).unwrap();
        assert_eq!(s, 200);
        let (s, _, _) = block(run("POST", "/mcp", &body)).unwrap();
        assert_eq!(s, 200);
        // An unsupported version is refused before dispatch.
        let hdr = [("mcp-protocol-version", "1999-01-01")];
        let (s, ct, b) = block(run_h("POST", "/mcp", &hdr, &body)).unwrap();
        assert_eq!((s, ct), (400, "application/json"));
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v["error"]["data"]["supported"][0],
            mcp_face::PROTOCOL_VERSION
        );
    }

    #[test]
    fn mcp_mirrored_headers_reach_the_face_through_the_router() {
        // A 2026-07-28 request with its envelope, its version header and
        // SEP-2243's mirrored method header.
        let list = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": mcp_face::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            } }
        });
        let body = serde_json::to_vec(&list).unwrap();
        let agree = [
            ("mcp-protocol-version", mcp_face::PROTOCOL_VERSION),
            ("mcp-method", "tools/list"),
        ];
        let (s, _, b) = block(run_h("POST", "/mcp", &agree, &body)).unwrap();
        assert_eq!(s, 200);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["result"]["resultType"], "complete");
        // The router hands the mirrored header on: a disagreement is refused.
        let disagree = [
            ("mcp-protocol-version", mcp_face::PROTOCOL_VERSION),
            ("mcp-method", "tools/call"),
        ];
        let (s, _, b) = block(run_h("POST", "/mcp", &disagree, &body)).unwrap();
        assert_eq!(s, 400);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"]["code"], mcp_face::HEADER_MISMATCH);
    }
    #[test]
    fn events_route_replays_changes_and_rechecks_authorization() {
        use crate::agent_ready::events::{
            poll_snapshot, EventError, EventRecord, EventType, PollRequest,
        };
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        };
        struct EventPages {
            allowed: AtomicBool,
            rows: Mutex<Vec<EventRecord>>,
        }
        impl PageSource for EventPages {
            fn markdown(&self, _: &str) -> Option<String> {
                None
            }
            fn html(&self, _: &str) -> Option<String> {
                None
            }
            fn events(&self) -> Vec<EventType> {
                vec![EventType {
                    name: "notes.changed".into(),
                    description: "A note changed".into(),
                    input_schema: serde_json::json!({"type":"object","additionalProperties":false}),
                    payload_schema: serde_json::json!({"type":"object"}),
                }]
            }
            async fn poll_event(&self, request: PollRequest) -> Result<Value, EventError> {
                if !self.allowed.load(Ordering::SeqCst) {
                    return Err(EventError::forbidden());
                }
                if !request.arguments.as_object().unwrap().is_empty() {
                    return Err(EventError::invalid());
                }
                poll_snapshot("alice", &self.rows.lock().unwrap(), 1, 100, &request)
            }
        }
        let pages = EventPages {
            allowed: AtomicBool::new(true),
            rows: Mutex::new(vec![]),
        };
        for modern in [false, true] {
            let invoke = |method: &str, mut params: Value| {
                if modern {
                    params["_meta"] = serde_json::json!({
                        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities":{}
                    });
                }
                let body = serde_json::to_vec(
                    &serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
                )
                .unwrap();
                let (status, _, bytes, headers) = block(handle_h(
                    &surface(),
                    "POST",
                    "/mcp",
                    &[],
                    &body,
                    &pages,
                    |_, _| async { ToolOutcome::ok(Value::Null) },
                ))
                .unwrap();
                assert_eq!(
                    headers
                        .iter()
                        .find(|(k, _)| *k == "cache-control")
                        .unwrap()
                        .1,
                    "private, no-store"
                );
                (status, serde_json::from_slice::<Value>(&bytes).unwrap())
            };
            let discovery = invoke(
                if modern {
                    "server/discover"
                } else {
                    "initialize"
                },
                serde_json::json!({}),
            )
            .1;
            let caps = &discovery["result"]["capabilities"];
            assert_eq!(
                if modern {
                    &caps["extensions"]["io.modelcontextprotocol/events"]["listChanged"]
                } else {
                    &caps["events"]["listChanged"]
                },
                false
            );
            let list = invoke("events/list", serde_json::json!({})).1;
            assert_eq!(
                list["result"]["events"][0]["delivery"],
                serde_json::json!(["poll"])
            );
            let boot = invoke(
                "events/poll",
                serde_json::json!({"name":"notes.changed","cursor":null}),
            )
            .1;
            assert_eq!(boot["result"]["events"], serde_json::json!([]));
            pages.rows.lock().unwrap().push(EventRecord {
                id: format!("change-{modern}"),
                at_ms: 2,
                data: serde_json::json!({"note":"new"}),
            });
            let params =
                serde_json::json!({"name":"notes.changed","cursor":boot["result"]["cursor"]});
            let delivered = invoke("events/poll", params.clone()).1;
            assert_eq!(delivered["result"]["events"].as_array().unwrap().len(), 1);
            assert_eq!(delivered["result"].get("resultType").is_some(), modern);
            assert_eq!(delivered, invoke("events/poll", params.clone()).1);
            pages.allowed.store(false, Ordering::SeqCst);
            assert_eq!(invoke("events/poll", params).1["error"]["code"], -32024);
            pages.allowed.store(true, Ordering::SeqCst);
            assert_eq!(
                invoke("events/poll", serde_json::json!({"name":"unknown"})).1["error"]["code"],
                -32023
            );
            assert_eq!(
                invoke("events/subscribe", serde_json::json!({})).1["error"]["code"],
                -32026
            );
        }
        let plain = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let (_, _, body) =
            block(run("POST", "/mcp", &serde_json::to_vec(&plain).unwrap())).unwrap();
        assert!(
            serde_json::from_slice::<Value>(&body).unwrap()["result"]["capabilities"]
                .get("events")
                .is_none()
        );
    }

    #[test]
    fn mcp_files_route_enforces_origin_refusal_and_well_known_skills_preserve_mime_types() {
        struct FilesAndSkillsPages;
        impl PageSource for FilesAndSkillsPages {
            fn markdown(&self, _path: &str) -> Option<String> {
                None
            }
            fn html(&self, _path: &str) -> Option<String> {
                None
            }
            fn skills(&self) -> Vec<crate::agent_ready::skills::Skill> {
                vec![crate::agent_ready::skills::Skill {
                    uri: "skill://demo/kit/SKILL.md".into(),
                    frontmatter: serde_json::json!({"name": "kit", "description": "Kit."}),
                    files: vec![
                        crate::agent_ready::skills::SkillFile {
                            uri: "skill://demo/kit/SKILL.md".into(),
                            mime_type: "text/markdown".into(),
                            bytes: b"# Kit\n".to_vec(),
                        },
                        crate::agent_ready::skills::SkillFile {
                            uri: "skill://demo/kit/config.json".into(),
                            mime_type: "application/json".into(),
                            bytes: b"{}\n".to_vec(),
                        },
                    ],
                }]
            }
            fn mcp_file_http(
                &self,
                _method: &str,
                sub_path: &str,
                _headers: &[(String, String)],
                _body: &[u8],
            ) -> impl std::future::Future<Output = Option<AnswerH>> + Send {
                let sub = sub_path.to_string();
                async move { Some((200, "text/plain", sub.into_bytes(), vec![])) }
            }
        }
        let pages = FilesAndSkillsPages;
        // Cross-origin request to /mcp/files/* is refused before reaching mcp_file_http.
        let (status, _, _, _) = block(handle_h(
            &surface(),
            "PUT",
            "/mcp/files/upload/slot1",
            &[("origin".to_string(), "https://evil.example".to_string())],
            b"abc",
            &pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(status, 403);

        // Same-origin (or non-browser) request reaches mcp_file_http with single stripped prefix.
        let (status, _, body, _) = block(handle_h(
            &surface(),
            "GET",
            "/mcp/files/download/tok1",
            &[],
            b"",
            &pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"download/tok1");

        // /.well-known/agent-skills/* serves application/json for .json files, not text/markdown.
        let (status, ct, body, hdrs) = block(handle_h(
            &surface(),
            "GET",
            "/.well-known/agent-skills/demo/kit/config.json",
            &[],
            b"",
            &pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        assert_eq!(body, b"{}\n");
        assert!(hdrs.iter().any(|(k, v)| *k == telemetry::AGENT_EVENT_HEADER
            && v == "s=discovery;op=/.well-known/agent-skills/demo/kit/config.json;ok=1"));
    }

    #[test]
    fn emits_agent_event_telemetry_across_discovery_markdown_mcp_and_a2a() {
        let event_of = |hdrs: &[(&'static str, String)]| -> String {
            hdrs.iter()
                .find(|(k, _)| *k == telemetry::AGENT_EVENT_HEADER)
                .map(|(_, v)| v.clone())
                .expect("missing x-ferrite-agent-event header")
        };

        // Discovery
        let (_, _, _, hdrs) = block(handle_h(
            &surface(),
            "GET",
            "/llms.txt",
            &[],
            b"",
            &Pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(event_of(&hdrs), "s=discovery;op=/llms.txt;ok=1");

        // Markdown twin (.md) vs Accept-negotiated
        let (_, _, _, hdrs) = block(handle_h(
            &surface(),
            "GET",
            "/about.md",
            &[],
            b"",
            &Pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(
            event_of(&hdrs),
            "s=markdown;op=/about;ok=1;verdict=twin"
        );
        let (_, _, _, hdrs) = block(handle_h(
            &surface(),
            "GET",
            "/about",
            &[("accept".into(), "text/markdown".into())],
            b"",
            &Pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(
            event_of(&hdrs),
            "s=markdown;op=/about;ok=1;verdict=negotiated"
        );

        // MCP 2025-11-25 tools/call ok
        let call_legacy = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "list_notes", "arguments": {} }
        });
        let (st, _, _, hdrs) = block(handle_h(
            &surface(),
            "POST",
            "/mcp",
            &[("x-poppy-client-id".into(), "https://muse.ai/poppy/agent.json".into())],
            &serde_json::to_vec(&call_legacy).unwrap(),
            &Pages,
            |name, _| async move { ToolOutcome::ok(serde_json::json!({ "tool": name })) },
        ))
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(
            event_of(&hdrs),
            "s=mcp;m=tools/call;op=list_notes;rev=2025-11-25;ok=1;ag=muse.ai"
        );

        // MCP 2025-11-25 JSON-RPC error on HTTP 200 -> ok=0;err=-32602
        let bad_tool = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "missing_tool", "arguments": {} }
        });
        let (st, _, _, hdrs) = block(handle_h(
            &surface(),
            "POST",
            "/mcp",
            &[],
            &serde_json::to_vec(&bad_tool).unwrap(),
            &Pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(
            event_of(&hdrs),
            "s=mcp;m=tools/call;op=missing_tool;rev=2025-11-25;ok=0;err=-32602"
        );

        // MCP 2026-07-28 MRTR input_required verdict
        struct MrtrPages;
        impl PageSource for MrtrPages {
            fn markdown(&self, _: &str) -> Option<String> {
                None
            }
            fn html(&self, _: &str) -> Option<String> {
                None
            }
            async fn mcp_tool_call_mrtr(
                &self,
                _name: String,
                _params: Value,
            ) -> Option<Result<Value, crate::agent_ready::elicitation::ElicitationError>>
            {
                Some(Ok(serde_json::json!({
                    "resultType": "input_required",
                    "elicitationId": "el_1",
                    "message": "confirm?"
                })))
            }
        }
        let call_2026 = serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "list_notes",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": mcp_face::PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let (st, _, _, hdrs) = block(handle_h(
            &surface(),
            "POST",
            "/mcp",
            &[("mcp-protocol-version".into(), mcp_face::PROTOCOL_VERSION.into())],
            &serde_json::to_vec(&call_2026).unwrap(),
            &MrtrPages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(
            event_of(&hdrs),
            "s=mcp;m=tools/call;op=list_notes;rev=2026-07-28;ok=1;verdict=input_required"
        );

        // A2A message/send with skill + JSON-RPC error on HTTP 200
        let a2a_ok = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": {
                "message": {
                    "kind": "message",
                    "messageId": "m1",
                    "role": "user",
                    "parts": [{ "kind": "data", "data": { "skill": "list_notes", "arguments": {} } }]
                }
            }
        });
        let (st, _, _, hdrs) = block(handle_h(
            &surface(),
            "POST",
            "/a2a",
            &[],
            &serde_json::to_vec(&a2a_ok).unwrap(),
            &Pages,
            |name, _| async move { ToolOutcome::ok(serde_json::json!({ "tool": name })) },
        ))
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(
            event_of(&hdrs),
            "s=a2a;m=message/send;op=list_notes;ok=1"
        );

        let a2a_err = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tasks/get",
            "params": { "id": "missing-task" }
        });
        let (st, _, _, hdrs) = block(handle_h(
            &surface(),
            "POST",
            "/a2a",
            &[],
            &serde_json::to_vec(&a2a_err).unwrap(),
            &Pages,
            |_, _| async { ToolOutcome::ok(Value::Null) },
        ))
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(event_of(&hdrs), "s=a2a;m=tasks/get;ok=0;err=-32001");
    }
}
