//! Session persistence (snapshot and restore) and the navigation pipeline.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use super::super::dom::NodeId;
use super::super::extract;
use super::super::html;
use super::super::js::runtime::Realm;
use super::super::js::runtime::RunLimits;
use super::super::js::runtime::run_page_scripts_in_realm;
use super::{CdpBrowser, CdpCommand, CdpError, CdpEvent, CdpHost, ConsoleTap, Cookie, DEFAULT_CONTEXT, JsonValue, NetRecord, RealmSeed, RedirectChain, Session, cookie_matches, eval_in_realm, exception_event, navigation_origin, resolve_url, seed_realm_globals, strip_redirect_credentials};

impl CdpBrowser {
    /// Snapshot one session's durable state as JSON. Carries
    /// what survives an instance hop: the target id, current URL, the
    /// serialized DOM, navigation history, cookie jar, extra headers,
    /// UA/locale/timezone/media/touch emulation, new-document scripts,
    /// created stylesheets and the JS/viewport settings. The live JS realm
    /// is deliberately NOT serialized — restoring resets globals exactly
    /// like a navigation does (documented session semantics); page effects
    /// already applied to the DOM survive in the serialized HTML.
    pub fn snapshot_session(&self, session_id: &str) -> Option<JsonValue> {
        let s = self.sessions.get(session_id)?;
        let doc = s.doc.borrow();
        let html = extract::serialize_html(&doc, NodeId::DOCUMENT);
        let cookies = JsonValue::Arr(
            s.cookies
                .iter()
                .map(|c| {
                    JsonValue::obj(vec![
                        ("name", JsonValue::str(c.name.clone())),
                        ("value", JsonValue::str(c.value.clone())),
                        ("domain", JsonValue::str(c.domain.clone())),
                        ("path", JsonValue::str(c.path.clone())),
                        ("secure", JsonValue::Bool(c.secure)),
                        ("httpOnly", JsonValue::Bool(c.http_only)),
                        ("expires", JsonValue::Num(c.expires)),
                    ])
                })
                .collect(),
        );
        let headers = JsonValue::Arr(
            s.extra_headers
                .iter()
                .map(|(k, v)| {
                    JsonValue::Arr(vec![
                        JsonValue::str(k.clone()),
                        JsonValue::str(v.clone()),
                    ])
                })
                .collect(),
        );
        let history = JsonValue::Arr(s.history.iter().map(|u| JsonValue::str(u.clone())).collect());
        let scripts = JsonValue::Arr(
            s.new_doc_scripts
                .iter()
                .map(|(id, src)| {
                    JsonValue::Arr(vec![JsonValue::str(id.clone()), JsonValue::str(src.clone())])
                })
                .collect(),
        );
        let sheets = JsonValue::Arr(
            s.stylesheets
                .iter()
                .map(|c| JsonValue::str(c.clone()))
                .collect(),
        );
        let created = JsonValue::Arr(
            s.created_sheets
                .iter()
                .map(|(id, css)| {
                    JsonValue::Arr(vec![JsonValue::str(id.clone()), JsonValue::str(css.clone())])
                })
                .collect(),
        );
        Some(JsonValue::obj(vec![
            ("version", JsonValue::Num(1.0)),
            ("sessionId", JsonValue::str(session_id)),
            ("targetId", JsonValue::str(s.target_id.clone())),
            ("url", JsonValue::str(s.url.clone())),
            ("html", JsonValue::str(html)),
            ("history", history),
            ("historyIndex", JsonValue::Num(s.history_index as f64)),
            ("cookies", cookies),
            ("extraHeaders", headers),
            (
                "userAgent",
                s.user_agent
                    .clone()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "locale",
                s.locale.clone().map(JsonValue::str).unwrap_or(JsonValue::Null),
            ),
            (
                "timezone",
                s.timezone
                    .clone()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "emulatedMedia",
                s.emulated_media
                    .clone()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            ("touchEnabled", JsonValue::Bool(s.touch_enabled)),
            ("jsEnabled", JsonValue::Bool(s.js_enabled)),
            ("viewportWidth", JsonValue::Num(f64::from(s.viewport_width))),
            ("viewportHeight", JsonValue::Num(f64::from(s.viewport_height))),
            ("newDocScripts", scripts),
            ("stylesheets", sheets),
            ("createdSheets", created),
        ]))
    }

    /// Rebuild a session from a [`snapshot_session`] JSON value under its
    /// original session and target ids. The DOM is re-parsed from the
    /// snapshot HTML **without running scripts** (no double network
    /// effects); history, cookies, headers and emulation state are
    /// restored; the JS realm starts fresh (navigation-reset semantics).
    /// Returns the restored session id, or an error string for a malformed
    /// snapshot.
    pub fn restore_session(&mut self, snapshot: &JsonValue) -> Result<String, String> {
        let sid = snapshot
            .get("sessionId")
            .and_then(JsonValue::as_str)
            .ok_or("snapshot missing sessionId")?
            .to_string();
        let tid = snapshot
            .get("targetId")
            .and_then(JsonValue::as_str)
            .ok_or("snapshot missing targetId")?
            .to_string();
        let url = snapshot
            .get("url")
            .and_then(JsonValue::as_str)
            .unwrap_or("about:blank")
            .to_string();
        let html_src = snapshot
            .get("html")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        // Re-parse WITHOUT running scripts: effects the page's scripts had
        // already applied are baked into the serialized DOM.
        let doc = html::parse_with_scripting(&html_src, false);
        self.targets.insert(tid.clone(), url.clone());
        self.target_contexts
            .entry(tid.clone())
            .or_insert_with(|| DEFAULT_CONTEXT.to_string());
        // Attach a fresh session shell under the SAME id, then restore the
        // snapshot fields over it.
        let mut s = Session::fresh(&tid, &url);
        s.doc = Rc::new(RefCell::new(doc));
        if let Some(JsonValue::Arr(items)) = snapshot.get("history") {
            s.history = items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if s.history.is_empty() {
                s.history = vec![url.clone()];
            }
        }
        s.history_index = snapshot
            .get("historyIndex")
            .and_then(JsonValue::as_f64)
            .map(|v| v.max(0.0) as usize)
            .unwrap_or(0)
            .min(s.history.len().saturating_sub(1));
        if let Some(JsonValue::Arr(items)) = snapshot.get("cookies") {
            for c in items {
                s.cookies.push(Cookie {
                    name: c
                        .get("name")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    value: c
                        .get("value")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    domain: c
                        .get("domain")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    path: c
                        .get("path")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("/")
                        .to_string(),
                    secure: c.get("secure").and_then(JsonValue::as_bool).unwrap_or(false),
                    http_only: c
                        .get("httpOnly")
                        .and_then(JsonValue::as_bool)
                        .unwrap_or(false),
                    same_site: None,
                    expires: c.get("expires").and_then(JsonValue::as_f64).unwrap_or(-1.0),
                });
            }
        }
        if let Some(JsonValue::Arr(items)) = snapshot.get("extraHeaders") {
            for kv in items {
                if let JsonValue::Arr(pair) = kv {
                    if let (Some(k), Some(v)) = (
                        pair.first().and_then(JsonValue::as_str),
                        pair.get(1).and_then(JsonValue::as_str),
                    ) {
                        s.extra_headers.push((k.to_string(), v.to_string()));
                    }
                }
            }
        }
        s.user_agent = snapshot
            .get("userAgent")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        s.locale = snapshot
            .get("locale")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        s.timezone = snapshot
            .get("timezone")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        s.emulated_media = snapshot
            .get("emulatedMedia")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        s.touch_enabled = snapshot
            .get("touchEnabled")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        s.js_enabled = snapshot
            .get("jsEnabled")
            .and_then(JsonValue::as_bool)
            .unwrap_or(true);
        s.viewport_width = snapshot
            .get("viewportWidth")
            .and_then(JsonValue::as_f64)
            .map(|v| v as f32)
            .unwrap_or(1280.0);
        s.viewport_height = snapshot
            .get("viewportHeight")
            .and_then(JsonValue::as_f64)
            .map(|v| v as f32)
            .unwrap_or(720.0);
        if let Some(JsonValue::Arr(items)) = snapshot.get("newDocScripts") {
            for kv in items {
                if let JsonValue::Arr(pair) = kv {
                    if let (Some(id), Some(src)) = (
                        pair.first().and_then(JsonValue::as_str),
                        pair.get(1).and_then(JsonValue::as_str),
                    ) {
                        s.new_doc_scripts.push((id.to_string(), src.to_string()));
                    }
                }
            }
        }
        if let Some(JsonValue::Arr(items)) = snapshot.get("stylesheets") {
            s.stylesheets = items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
        }
        if let Some(JsonValue::Arr(items)) = snapshot.get("createdSheets") {
            for kv in items {
                if let JsonValue::Arr(pair) = kv {
                    if let (Some(id), Some(css)) = (
                        pair.first().and_then(JsonValue::as_str),
                        pair.get(1).and_then(JsonValue::as_str),
                    ) {
                        s.created_sheets.push((id.to_string(), css.to_string()));
                    }
                }
            }
        }
        self.sessions.insert(sid.clone(), s);
        Ok(sid)
    }

    /// The ids of every live session (used by hosts that persist sessions).
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Load `url` (or the supplied `preloaded` HTML) into the session: fetch
    /// the document and its external resources through the host, rebuild the
    /// realm, run the Page.addScriptToEvaluateOnNewDocument sources, run the
    /// page's own scripts, and raise the navigation lifecycle events. The
    /// page's console lines and script errors surface as
    /// Runtime.consoleAPICalled / Runtime.exceptionThrown events.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn navigate_session(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
        url: String,
        preloaded: Option<String>,
        method: &str,
        body: Option<String>,
        push_history: bool,
        emit_events: bool,
    ) -> Result<JsonValue, CdpError> {
        let (js_enabled, new_doc_scripts, seed, request_headers, net_on, security_on, rid) = {
            let session = self.session_for(cmd)?;
            // Every navigation fetch carries the session's cookie jar, the
            // client's extra headers and its user-agent override, the way
            // a browser's network stack would.
            let mut hdrs: Vec<(String, String)> = session.extra_headers.clone();
            let jar = cookie_header(&session.cookies, &url);
            if !jar.is_empty() {
                hdrs.push(("cookie".to_string(), jar));
            }
            if let Some(ua) = &session.user_agent {
                hdrs.push(("user-agent".to_string(), ua.clone()));
            }
            let rid = format!("req-{}", session.next_request_id);
            session.next_request_id = session.next_request_id.wrapping_add(1);
            (
                session.js_enabled,
                session.new_doc_scripts.clone(),
                RealmSeed::of(session),
                hdrs,
                session.network_enabled,
                session.security_enabled,
                rid,
            )
        };
        let sid = cmd.session_id.clone();
        let is_fetch = preloaded.is_none() && url != "about:blank";
        if net_on && is_fetch {
            self.events.push(CdpEvent {
                method: "Network.requestWillBeSent".to_string(),
                params: JsonValue::obj(vec![
                    ("requestId", JsonValue::str(rid.clone())),
                    ("loaderId", JsonValue::str("loader-1")),
                    ("documentURL", JsonValue::str(url.clone())),
                    (
                        "request",
                        JsonValue::obj(vec![
                            ("url", JsonValue::str(url.clone())),
                            ("method", JsonValue::str(method.to_ascii_uppercase())),
                            (
                                "headers",
                                JsonValue::Obj(
                                    request_headers
                                        .iter()
                                        .map(|(k, v)| (k.clone(), JsonValue::str(v.clone())))
                                        .collect(),
                                ),
                            ),
                        ]),
                    ),
                    ("timestamp", JsonValue::Num(0.0)),
                    ("wallTime", JsonValue::Num(0.0)),
                    ("type", JsonValue::str("Document")),
                ]),
                session_id: sid.clone(),
            });
        }
        let mut fetched_status: u16 = 200;
        let mut url = url;
        let html_src = match preloaded {
            Some(html) => html,
            None if url == "about:blank" => String::new(),
            None => {
                // A GET navigation is a document fetch on the host's
                // navigation seam; a form POST rides the script network hook
                // (the only seam that carries a body). 3xx answers are
                // followed like a browser's network stack would: bounded
                // hops, `Location` resolved against the redirecting URL,
                // 303 (and the historical 301/302-on-POST) demoting to GET,
                // 307/308 preserving the method and body. Every hop is
                // re-authorized by the host's own egress allowlist — a
                // denied hop fails the navigation with the host's error.
                let mut chain = RedirectChain::new(&url).map_err(|message| CdpError { code: -32000, message })?;
                let mut crossed_origin = false;
                let mut cur_method = method.to_string();
                let mut cur_body = body.clone();
                let fetched = loop {
                    let session = self.session_for(cmd)?;
                    let mut hop_headers = session.extra_headers.clone();
                    if crossed_origin { strip_redirect_credentials(&mut hop_headers); }
                    let jar = cookie_header(&session.cookies, &url);
                    if !jar.is_empty() { hop_headers.push(("cookie".to_string(), jar)); }
                    if let Some(ua) = &session.user_agent { hop_headers.push(("user-agent".to_string(), ua.clone())); }
                    let raw = if cur_method.eq_ignore_ascii_case("POST") {
                        let mut hdrs = hop_headers;
                        hdrs.push((
                            "content-type".to_string(),
                            "application/x-www-form-urlencoded".to_string(),
                        ));
                        host.hooks()
                            .fetch(&url, "POST", &hdrs, cur_body.as_deref().map(str::as_bytes))
                    } else {
                        host.fetch_document_with(&url, &hop_headers)
                    };
                    match raw {
                        Ok((status, headers, b)) => {
                            if let Err(error) = chain.record_response(b.len()) { break Err(error); }
                            let location = headers.iter().find_map(|(k, v)| {
                                k.eq_ignore_ascii_case("location").then(|| v.clone())
                            });
                            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                                let Some(loc) = location else {
                                    break Err(format!(
                                        "origin returned {status} with no Location"
                                    ));
                                };
                                let next = match chain.follow(&url, &loc) { Ok(next) => next, Err(error) => break Err(error) };
                                crossed_origin |= navigation_origin(&url) != navigation_origin(&next);
                                if net_on {
                                    self.events.push(CdpEvent {
                                        method: "Network.requestWillBeSent".to_string(),
                                        params: JsonValue::obj(vec![
                                            ("requestId", JsonValue::str(rid.clone())),
                                            ("loaderId", JsonValue::str("loader-1")),
                                            ("documentURL", JsonValue::str(next.clone())),
                                            (
                                                "redirectResponse",
                                                JsonValue::obj(vec![
                                                    ("url", JsonValue::str(url.clone())),
                                                    (
                                                        "status",
                                                        JsonValue::Num(f64::from(status)),
                                                    ),
                                                ]),
                                            ),
                                        ]),
                                        session_id: sid.clone(),
                                    });
                                }
                                // 303 always demotes to GET; so do 301/302
                                // for a POST (the behaviour every browser
                                // ships). 307/308 keep method and body.
                                if status == 303
                                    || (matches!(status, 301 | 302)
                                        && cur_method.eq_ignore_ascii_case("POST"))
                                {
                                    cur_method = "GET".to_string();
                                    cur_body = None;
                                }
                                url = next;
                                continue;
                            }
                            fetched_status = status;
                            if status >= 400 {
                                break Err(format!("origin returned {status}"));
                            }
                            break Ok(String::from_utf8_lossy(&b).into_owned());
                        }
                        Err(e) => break Err(e),
                    }
                };
                match fetched {
                    Ok(text) => text,
                    Err(e) => {
                        if net_on {
                            self.events.push(CdpEvent {
                                method: "Network.loadingFailed".to_string(),
                                params: JsonValue::obj(vec![
                                    ("requestId", JsonValue::str(rid.clone())),
                                    ("timestamp", JsonValue::Num(0.0)),
                                    ("type", JsonValue::str("Document")),
                                    ("errorText", JsonValue::str(e.clone())),
                                    ("canceled", JsonValue::Bool(false)),
                                ]),
                                session_id: sid.clone(),
                            });
                        }
                        return Err(CdpError {
                            code: -32000,
                            message: format!("navigation failed: {e}"),
                        });
                    }
                }
            }
        };
        if is_fetch {
            let session = self.session_for(cmd)?;
            session.requests.clear();
            session.requests.push(NetRecord {
                id: rid.clone(),
                post_data: body.clone(),
                body: html_src.clone().into_bytes(),
            });
        }
        if net_on && is_fetch {
            self.events.push(CdpEvent {
                method: "Network.responseReceived".to_string(),
                params: JsonValue::obj(vec![
                    ("requestId", JsonValue::str(rid.clone())),
                    ("loaderId", JsonValue::str("loader-1")),
                    ("timestamp", JsonValue::Num(0.0)),
                    ("type", JsonValue::str("Document")),
                    (
                        "response",
                        JsonValue::obj(vec![
                            ("url", JsonValue::str(url.clone())),
                            ("status", JsonValue::Num(fetched_status as f64)),
                            ("statusText", JsonValue::str("")),
                            ("headers", JsonValue::Obj(vec![])),
                            ("mimeType", JsonValue::str("text/html")),
                            (
                                "encodedDataLength",
                                JsonValue::Num(html_src.len() as f64),
                            ),
                        ]),
                    ),
                ]),
                session_id: sid.clone(),
            });
            self.events.push(CdpEvent {
                method: "Network.loadingFinished".to_string(),
                params: JsonValue::obj(vec![
                    ("requestId", JsonValue::str(rid.clone())),
                    ("timestamp", JsonValue::Num(0.0)),
                    ("encodedDataLength", JsonValue::Num(html_src.len() as f64)),
                ]),
                session_id: sid.clone(),
            });
        }
        // Fetch the page's external resources through the host, the same
        // complete path the /render action takes: stylesheets and, when JS
        // is on, external classic scripts, URL-resolved against the page
        // URL. The caps bound fetch attempts, so failing URLs cannot
        // multiply the requests one navigation makes.
        let mut stylesheets: Vec<String> = Vec::new();
        let mut external: HashMap<String, String> = HashMap::new();
        if !html_src.is_empty() {
            let sheet_urls = html::stylesheet_links(&html_src)
                .into_iter()
                .filter_map(|href| resolve_url(&url, &href))
                .take(5);
            for abs in sheet_urls {
                if let Ok(css) = host.fetch_document(&abs) {
                    stylesheets.push(css);
                }
            }
            if js_enabled {
                let script_urls = super::super::js::runtime::external_script_srcs(&html_src)
                    .into_iter()
                    .filter_map(|src| resolve_url(&url, &src).map(|abs| (src, abs)))
                    .take(10);
                for (src, abs) in script_urls {
                    if let Ok(text) = host.fetch_document(&abs) {
                        external.insert(src, text);
                    }
                }
            }
        }
        // `<noscript>` follows the session's scripting flag
        // (Emulation.setScriptExecutionDisabled), as in Chrome.
        let doc = Rc::new(RefCell::new(html::parse_with_scripting(&html_src, js_enabled)));
        // A navigation tears down the JS realm (fresh page, fresh globals),
        // exactly like a real browser. The CDP-owned globals (bindings,
        // dialog policy, navigator overrides) are installed into the fresh
        // realm first, so the page's own scripts observe them.
        let mut realm = Realm::default();
        let mut console_lines: Vec<(String, String)> = Vec::new();
        if js_enabled {
            let mut tap = ConsoleTap {
                inner: host.hooks(),
                lines: Vec::new(),
            };
            seed_realm_globals(doc.clone(), &mut realm, &mut tap, &seed);
            for (_, source) in &new_doc_scripts {
                if let Err(e) = eval_in_realm(doc.clone(), &mut realm, source, &mut tap) {
                    tap.lines.push(("error".to_string(), e));
                }
            }
            console_lines.append(&mut tap.lines);
        }
        let report = if js_enabled && !html_src.is_empty() {
            // The page URL travels with the run: `location` reports it and
            // a dynamically inserted `<script src="/chunk.js">` resolves
            // against it before reaching the host's `fetch`.
            let limits = RunLimits {
                page_url: Some(url.clone()),
                monotonic: host.monotonic_ms(),
                ..RunLimits::default()
            };
            Some(run_page_scripts_in_realm(
                doc.clone(),
                &external,
                host.hooks(),
                limits,
                &mut realm,
            ))
        } else {
            None
        };
        let (page_console, page_errors) = report
            .as_ref()
            .map(|r| (r.console.clone(), r.errors.clone()))
            .unwrap_or_default();
        let ran_scripts = report.as_ref().map(|r| r.scripts_found > 0).unwrap_or(false);
        let tid = {
            let session = self.session_for(cmd)?;
            session.url = url.clone();
            session.doc = doc;
            session.stylesheets = stylesheets;
            session.realm = realm;
            session.remote_objects.clear();
            session.next_object_id = 1;
            session.navigations = session.navigations.wrapping_add(1);
            if ran_scripts {
                session.script_runs = session.script_runs.wrapping_add(1);
            }
            // Remote ids minted for the old page's stylesheet searches are
            // gone with the document.
            session.searches.clear();
            // The old document's pending press must not complete a click on
            // whichever node of the new document reuses its arena id.
            session.pressed = None;
            session.last_report = report;
            if push_history {
                session
                    .history
                    .truncate(session.history_index.saturating_add(1));
                if session.history.last() != Some(&url) {
                    session.history.push(url.clone());
                }
                session.history_index = session.history.len().saturating_sub(1);
            }
            session.target_id.clone()
        };
        self.targets.insert(tid.clone(), url.clone());
        for (level, text) in console_lines.iter().chain(page_console.iter()) {
            self.emit_console(cmd, level, text);
        }
        for (_, err) in &page_errors {
            self.events.push(exception_event(err, sid.clone()));
        }
        if security_on && is_fetch {
            // The host owns TLS; the state reported is what the scheme says.
            let secure = url.starts_with("https://");
            self.events.push(CdpEvent {
                method: "Security.securityStateChanged".to_string(),
                params: JsonValue::obj(vec![
                    (
                        "securityState",
                        JsonValue::str(if secure { "secure" } else { "insecure" }),
                    ),
                    ("schemeIsCryptographic", JsonValue::Bool(secure)),
                    ("explanations", JsonValue::Arr(vec![])),
                    ("summary", JsonValue::str("")),
                ]),
                session_id: sid.clone(),
            });
        }
        if emit_events {
            self.events.push(CdpEvent {
                method: "Page.frameNavigated".to_string(),
                params: JsonValue::obj(vec![(
                    "frame",
                    JsonValue::obj(vec![
                        ("id", JsonValue::str(tid.clone())),
                        ("url", JsonValue::str(url.clone())),
                        ("loaderId", JsonValue::str("loader-1")),
                        ("mimeType", JsonValue::str("text/html")),
                    ]),
                )]),
                session_id: sid.clone(),
            });
            self.events.push(CdpEvent {
                method: "Page.loadEventFired".to_string(),
                params: JsonValue::obj(vec![("timestamp", JsonValue::Num(0.0))]),
                session_id: sid,
            });
        }
        Ok(JsonValue::obj(vec![
            ("frameId", JsonValue::str(tid)),
            ("loaderId", JsonValue::str("loader-1")),
        ]))
    }
}

/// The `cookie` request header value for `url` (empty when nothing applies).
fn cookie_header(cookies: &[Cookie], url: &str) -> String {
    cookies
        .iter()
        .filter(|c| cookie_matches(c, url))
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ")
}
