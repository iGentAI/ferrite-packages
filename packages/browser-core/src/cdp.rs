//! cdp — a Chrome DevTools Protocol facade over the browser engine, in the
//! shape obscura's cdp crate models: JSON-RPC commands dispatched by domain
//! (Target / Page / Runtime / DOM), session-scoped, transport-agnostic.
//!
//! The consumer app owns the transport (agent-browser exposes POST /browser/cdp
//! over queue ingress: one command in, one result + drained events out).
//! Sessions are in-memory per CdpBrowser; each session holds one loaded page
//! (DOM + JS realm state persisted across commands until navigation).
//!
//! Supported surface (what a Puppeteer / Playwright / chromiumoxide style
//! client drives):
//!   Browser.getVersion, Schema.getDomains
//!   Target.getTargets / createTarget / attachToTarget / detachFromTarget /
//!     closeTarget / getTargetInfo / setDiscoverTargets / setAutoAttach
//!   Page.enable / navigate / reload / setDocumentContent /
//!     getNavigationHistory / navigateToHistoryEntry /
//!     addScriptToEvaluateOnNewDocument / removeScriptToEvaluateOnNewDocument /
//!     getLayoutMetrics / getFrameTree / captureScreenshot
//!   Runtime.enable / evaluate / callFunctionOn / getProperties /
//!     releaseObject (remote objects live in the session until navigation)
//!   DOM.getDocument / describeNode / querySelector / querySelectorAll /
//!     getOuterHTML / setOuterHTML / getAttributes / setAttributeValue /
//!     setNodeValue / removeNode / resolveNode / requestNode / getBoxModel /
//!     getNodeForLocation / focus
//!   Input.dispatchMouseEvent / dispatchKeyEvent / insertText
//!   CSS.getComputedStyleForNode / getMatchedStylesForNode
//!   Accessibility.getFullAXTree
//!   Emulation.setDeviceMetricsOverride / clearDeviceMetricsOverride /
//!     setScriptExecutionDisabled
//!   Network.getCookies (empty by design) and the no-op toggles
//!
//! Events raised by a command travel in its reply: Target.attachedToTarget,
//! Page.frameNavigated, Page.loadEventFired, Runtime.consoleAPICalled and
//! Runtime.exceptionThrown. Page-script and listener exceptions become
//! events, never command failures (Chrome semantics).
//!
//! Everything else answers a well-formed CDP error (-32601 method not found)
//! so clients can feature-detect. Panic-free like the rest of the engine.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::api::{Page, PageOptions};
use super::dom::{Document, NodeId};
use super::html;
use super::js::dom_bindings;
use super::js::interp::{HostHooks, Interp};
use super::js::parser;
use super::js::runtime::{Realm, ScriptRunReport};
use super::js::value::{JsObject, JsValue as JsVal, ObjKind};

mod accessibility;
mod browser;
mod css;
mod diagnostics;
mod dom;
mod emulation;
mod input;
mod network;
mod page;
mod runtime;
mod session;

/// The browser context every target belongs to unless
/// `Target.createBrowserContext` minted another.
const DEFAULT_CONTEXT: &str = "context-default";

/// The user agent the browser reports when no override is set.
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (compatible; agent-browser/0.1)";

/// Resolve `href` against `base` (absolute, protocol-relative, root- and
/// path-relative forms). Returns None for unsupported schemes/fragments.
/// Shared by package consumers so navigation, stylesheets, scripts, images,
/// and links all use one bounded resolver.
pub fn resolve_url(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    if let Some(rest) = href.strip_prefix("//") {
        let scheme = base.split("://").next().unwrap_or("https");
        return Some(format!("{scheme}://{rest}"));
    }
    if href.starts_with('#') || href.contains("://") {
        return None;
    }
    let scheme_end = base.find("://")?.checked_add(3)?;
    let host_end = base
        .get(scheme_end..)?
        .find('/')
        .and_then(|i| scheme_end.checked_add(i))
        .unwrap_or(base.len());
    if let Some(rooted) = href.strip_prefix('/') {
        return Some(format!("{}/{}", base.get(..host_end)?, rooted));
    }
    // Path-relative: replace everything after the last '/' of the base path.
    let dir_end = base
        .rfind('/')
        .filter(|&i| i >= host_end)
        .and_then(|i| i.checked_add(1));
    match dir_end {
        Some(end) => Some(format!("{}{}", base.get(..end)?, href)),
        None => Some(format!("{}/{}", base.get(..host_end)?, href)),
    }
}

/// Navigation shares one response-byte budget across every redirect and the
/// final document. Redirect bodies count even though they are not rendered.
/// This bounds accepted buffered bodies, not bytes already received by the SDK.
pub const MAX_NAVIGATION_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REDIRECT_HOPS: usize = 5;

/// HTTP URL identity used for redirect cycles and origin comparisons. Rejects
/// credentials and ambiguous authorities; normalizes case, default ports,
/// percent-encoded unreserved path bytes, dot segments, and fragments.
pub fn canonical_navigation_url(url: &str) -> Option<String> {
    let url = url.trim().split('#').next()?;
    if url
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
    {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = authority.get(..=close)?;
        host.get(1..host.len().checked_sub(1)?)?
            .parse::<core::net::Ipv6Addr>()
            .ok()?;
        let suffix = authority.get(close + 1..)?;
        (
            host,
            if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(':')?)
            },
        )
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
    {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let port = port.map(|p| p.parse::<u16>()).transpose().ok()?;
    let authority = match port {
        Some(0) => return None,
        Some(80) if scheme == "http" => host,
        Some(443) if scheme == "https" => host,
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let tail = rest.get(end..)?;
    let (path, query) = tail
        .split_once('?')
        .map_or((tail, None), |(p, q)| (p, Some(q)));
    let mut decoded = String::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = path.get(i + 1..i + 3)?;
            let byte = u8::from_str_radix(pair, 16).ok()?;
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                decoded.push(char::from(byte));
            } else {
                decoded.push_str(&format!("%{byte:02X}"));
            }
            i += 3;
        } else {
            let ch = path.get(i..)?.chars().next()?;
            decoded.push(ch);
            i += ch.len_utf8();
        }
    }
    let mut segments = Vec::new();
    for part in decoded.split('/').skip(1) {
        match part {
            "." => (),
            ".." => {
                segments.pop();
            }
            _ => segments.push(part),
        }
    }
    let mut path = format!("/{}", segments.join("/"));
    if (decoded.ends_with("/.") || decoded.ends_with("/..")) && !path.ends_with('/') {
        path.push('/');
    }
    let query = query.map(|q| format!("?{q}")).unwrap_or_default();
    Some(format!("{scheme}://{authority}{path}{query}"))
}

pub fn navigation_origin(url: &str) -> Option<String> {
    let canonical = canonical_navigation_url(url)?;
    let start = canonical.find("://")? + 3;
    let end = start + canonical.get(start..)?.find('/')?;
    Some(canonical.get(..end)?.to_string())
}

pub fn strip_redirect_credentials(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !["authorization", "proxy-authorization", "cookie"]
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
    });
}

/// Per-navigation state. A cycle is refused before sending the repeated URL.
pub struct RedirectChain {
    visited: std::collections::HashSet<String>,
    bytes: usize,
    hops: usize,
}
impl RedirectChain {
    pub fn new(url: &str) -> Result<Self, String> {
        let canonical =
            canonical_navigation_url(url).ok_or_else(|| "invalid navigation URL".to_string())?;
        Ok(Self {
            visited: std::iter::once(canonical).collect(),
            bytes: 0,
            hops: 0,
        })
    }
    pub fn record_response(&mut self, bytes: usize) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= MAX_NAVIGATION_RESPONSE_BYTES)
            .ok_or_else(|| "navigation response bytes exceed 1 MiB".to_string())?;
        Ok(())
    }
    pub fn follow(&mut self, current: &str, location: &str) -> Result<String, String> {
        if self.hops >= MAX_REDIRECT_HOPS {
            return Err(format!("redirect chain exceeded {MAX_REDIRECT_HOPS} hops"));
        }
        let base = canonical_navigation_url(current)
            .ok_or_else(|| "invalid navigation URL".to_string())?;
        let loc = location.trim();
        let raw = if loc.is_empty() || loc.starts_with('#') {
            base.clone()
        } else if loc.starts_with('?') {
            format!("{}{}", base.split('?').next().unwrap_or(&base), loc)
        } else if loc.contains("://") {
            loc.to_string()
        } else {
            resolve_url(base.split('?').next().unwrap_or(&base), loc)
                .ok_or_else(|| "unresolvable redirect Location".to_string())?
        };
        let next = canonical_navigation_url(&raw)
            .ok_or_else(|| "invalid redirect Location".to_string())?;
        if !self.visited.insert(next.clone()) {
            return Err("redirect loop detected".to_string());
        }
        self.hops += 1;
        Ok(next)
    }
}

/// A decoded incoming CDP command.
#[derive(Debug, Clone)]
pub struct CdpCommand {
    pub id: u64,
    pub method: String,
    /// Raw JSON params (already parsed by the embedder).
    pub params: JsonValue,
    pub session_id: Option<String>,
}

/// Minimal JSON value model (std-only; the engine cannot depend on serde).
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<JsonValue>),
    Obj(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn str(s: impl Into<String>) -> JsonValue {
        JsonValue::Str(s.into())
    }
    pub fn obj(entries: Vec<(&str, JsonValue)>) -> JsonValue {
        JsonValue::Obj(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }
}

/// Serialize a JsonValue to a JSON string (std-only).
pub fn to_json(v: &JsonValue) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Num(n) => {
            if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                out.push_str(&format!("{}", *n as i64));
            } else if n.is_finite() {
                out.push_str(&format!("{n}"));
            } else {
                out.push_str("null");
            }
        }
        JsonValue::Str(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        JsonValue::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        JsonValue::Obj(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&JsonValue::Str(k.clone()), out);
                out.push(':');
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

/// One CDP reply: the result (or error) plus any events the command produced.
#[derive(Debug, Clone)]
pub struct CdpReply {
    pub id: u64,
    pub result: Result<JsonValue, CdpError>,
    pub events: Vec<CdpEvent>,
}

#[derive(Debug, Clone)]
pub struct CdpError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct CdpEvent {
    pub method: String,
    pub params: JsonValue,
    pub session_id: Option<String>,
}

/// The embedder supplies navigation fetches + script network + image decode.
pub trait CdpHost {
    /// Fetch a document (navigation). Returns the body text.
    fn fetch_document(&mut self, url: &str) -> Result<String, String>;
    /// Fetch raw bytes (images).
    fn fetch_bytes(&mut self, url: &str) -> Result<Vec<u8>, String>;
    /// HostHooks for script fetch/XHR + console during JS execution.
    fn hooks(&mut self) -> &mut dyn HostHooks;
    /// Fetch a document for navigation with the session's request headers
    /// (cookie jar, `Network.setExtraHTTPHeaders`, a user-agent override).
    /// Returns the status, the response headers (lowercase names; used for
    /// `Location` on a redirect) and the body. The default drops the headers
    /// and uses [`CdpHost::fetch_document`]; hosts whose transport can carry
    /// headers override it.
    fn fetch_document_with(
        &mut self,
        url: &str,
        _headers: &[(String, String)],
    ) -> Result<super::js::interp::FetchResponse, String> {
        self.fetch_document(url)
            .map(|s| (200, Vec::new(), s.into_bytes()))
    }
    /// The screenshot cost budget in bytes (projected canvas + PNG encode
    /// cost). `Page.captureScreenshot` refuses with a typed error instead of
    /// allocating past it — the same poison-pill defence as the host's
    /// render action. Hosts running under a hard process memory cap
    /// override this with their real budget.
    fn screenshot_cost_budget(&self) -> usize {
        192 * 1024 * 1024
    }
    /// The embedder's monotonic-milliseconds clock for script wall budgets
    /// (see [`super::js::interp::MonotonicMs`]). Constrained hosts hand the
    /// platform's injected clock seam through; the default (no clock)
    /// leaves wall budgets unenforced — the step and virtual-clock budgets
    /// still bound every run.
    fn monotonic_ms(&self) -> Option<super::js::interp::MonotonicMs> {
        None
    }
}

/// One attached page session.
struct Session {
    target_id: String,
    url: String,
    doc: Rc<RefCell<Document>>,
    /// The last script run report (populated by navigate).
    last_report: Option<ScriptRunReport>,
    viewport_width: f32,
    /// Node id map: CDP backend node ids are arena indices + 1 (0 reserved).
    js_enabled: bool,
    /// The session's persistent JS realm: global scope, global object,
    /// listeners and focus — created by navigation or the first
    /// `Runtime.evaluate` and reused by every later command, so `var x = 1`
    /// in one command is visible to the next (standard CDP session
    /// semantics). Navigation replaces it with a fresh realm.
    realm: Realm,
    /// External stylesheets fetched at navigation (used by captureScreenshot
    /// so the rendered page carries the same styling as a full render).
    stylesheets: Vec<String>,
    /// Viewport height for layout metrics (layout itself is width-driven).
    viewport_height: f32,
    /// Remote object table: objectId → live JS value (Runtime.getProperties
    /// / callFunctionOn / releaseObject). Cleared on navigation.
    remote_objects: HashMap<String, JsVal>,
    next_object_id: u64,
    /// Navigation history (URLs) and the current position in it.
    history: Vec<String>,
    history_index: usize,
    /// Page.addScriptToEvaluateOnNewDocument sources, run in the fresh
    /// realm before the page's own scripts on every navigation.
    new_doc_scripts: Vec<(String, String)>,
    next_script_id: u64,
    /// The node under the last left-button `mousePressed`, so a click only
    /// fires when the matching `mouseReleased` lands on the same element
    /// (a release elsewhere, or a release with no press, activates nothing).
    pressed: Option<NodeId>,
    /// The per-session cookie jar (`Network.setCookie` / `getCookies` /
    /// `deleteCookies`). Cookies ride navigation fetches as a `cookie`
    /// request header through the host hooks; nothing persists past the
    /// session.
    cookies: Vec<Cookie>,
    /// `Network.setExtraHTTPHeaders`: sent with every navigation fetch.
    extra_headers: Vec<(String, String)>,
    /// `Emulation.setUserAgentOverride` / `Network.setUserAgentOverride`:
    /// what `navigator.userAgent` and `Browser.getVersion` report.
    user_agent: Option<String>,
    /// `Emulation.setEmulatedMedia`: the media type layout evaluates
    /// (`screen` by default) and the forced `prefers-*` features.
    emulated_media: Option<String>,
    /// `Log` / `Console` domain enablement and the retained entries.
    log_enabled: bool,
    console_enabled: bool,
    log_entries: Vec<(String, String)>,
    /// `Runtime.addBinding` names: callable globals that raise
    /// `Runtime.bindingCalled` events.
    bindings: Vec<String>,
    /// Whether `Page.handleJavaScriptDialog` auto-accepts: the engine has
    /// no modal UI, so `alert`/`confirm`/`prompt` resolve synchronously
    /// and the recorded choice is what `confirm` returns.
    dialog_accept: bool,
    /// Browser context this target belongs to (`Target.createTarget`'s
    /// `browserContextId`).
    browser_context: String,
    /// Page-scope metrics counters for `Performance.getMetrics`.
    navigations: u64,
    script_runs: u64,
    /// `Network.enable` raises requestWillBeSent / responseReceived /
    /// loadingFinished for every navigation fetch; the bodies stay
    /// retrievable through `Network.getResponseBody` until the next
    /// navigation replaces them.
    network_enabled: bool,
    requests: Vec<NetRecord>,
    next_request_id: u64,
    /// `Runtime.compileScript` sources by scriptId (`Runtime.runScript`).
    compiled: Vec<(String, String)>,
    next_compiled_id: u64,
    /// `CSS.forcePseudoState`: forced pseudo-classes per node index.
    forced_pseudo: Vec<(usize, Vec<String>)>,
    /// `CSS.startRuleUsageTracking` is active.
    rule_tracking: bool,
    /// `Emulation.setGeolocationOverride`: (latitude, longitude, accuracy)
    /// answered by `navigator.geolocation.getCurrentPosition`.
    geolocation: Option<(f64, f64, f64)>,
    /// `Emulation.setTimezoneOverride`: reported by
    /// `Intl.DateTimeFormat().resolvedOptions().timeZone`.
    timezone: Option<String>,
    /// `Emulation.setTouchEmulationEnabled`: `navigator.maxTouchPoints`.
    touch_enabled: bool,
    /// `Input.setIgnoreInputEvents`: Input commands succeed without
    /// dispatching anything.
    ignore_input: bool,
    /// `Security.setIgnoreCertificateErrors` (recorded; the host owns TLS).
    ignore_cert_errors: bool,
    /// `Page.handleJavaScriptDialog`'s `promptText`: what `prompt()` returns
    /// when dialogs are accepted.
    dialog_prompt: Option<String>,
    /// `Emulation.setDefaultBackgroundColorOverride`: the canvas backdrop
    /// a screenshot paints when the page sets none.
    background_override: Option<(u8, u8, u8, u8)>,
    /// `Page.setBypassCSP` / `Page.setInterceptFileChooserDialog`.
    bypass_csp: bool,
    intercept_file_chooser: bool,
    /// `Emulation.setCPUThrottlingRate` scales the script step budget.
    cpu_throttle: f64,
    /// `Security.enable` raises `Security.securityStateChanged` on
    /// navigation.
    security_enabled: bool,
    /// `DOM.performSearch` result sets by search id.
    searches: Vec<(String, Vec<NodeId>)>,
    next_search_id: u64,
    /// `Emulation.setLocaleOverride`: `navigator.language`.
    locale: Option<String>,
    /// `CSS.createStyleSheet` sheets by id: author CSS the client injects,
    /// cascading after the document's own sheets and the fetched ones.
    created_sheets: Vec<(String, String)>,
    next_sheet_id: u64,
}

impl Session {
    /// A fresh session shell attached to `target_id` at `url`: the state
    /// `Target.attachToTarget` creates, factored out so snapshot restore
    /// builds the identical baseline before overlaying persisted fields.
    fn fresh(target_id: &str, url: &str) -> Session {
        Session {
            target_id: target_id.to_string(),
            url: url.to_string(),
            doc: Rc::new(RefCell::new(html::parse(""))),
            last_report: None,
            viewport_width: 1280.0,
            js_enabled: true,
            realm: Realm::default(),
            stylesheets: Vec::new(),
            viewport_height: 720.0,
            remote_objects: HashMap::new(),
            next_object_id: 1,
            history: vec![url.to_string()],
            history_index: 0,
            new_doc_scripts: Vec::new(),
            next_script_id: 1,
            pressed: None,
            cookies: Vec::new(),
            extra_headers: Vec::new(),
            user_agent: None,
            emulated_media: None,
            log_enabled: false,
            console_enabled: false,
            log_entries: Vec::new(),
            bindings: Vec::new(),
            dialog_accept: true,
            browser_context: DEFAULT_CONTEXT.to_string(),
            navigations: 0,
            script_runs: 0,
            network_enabled: false,
            requests: Vec::new(),
            next_request_id: 1,
            compiled: Vec::new(),
            next_compiled_id: 1,
            forced_pseudo: Vec::new(),
            rule_tracking: false,
            geolocation: None,
            timezone: None,
            touch_enabled: false,
            ignore_input: false,
            ignore_cert_errors: false,
            dialog_prompt: None,
            background_override: None,
            bypass_csp: false,
            intercept_file_chooser: false,
            cpu_throttle: 1.0,
            security_enabled: false,
            searches: Vec::new(),
            next_search_id: 1,
            locale: None,
            created_sheets: Vec::new(),
            next_sheet_id: 1,
        }
    }
}

/// One navigation fetch recorded for the Network domain.
#[derive(Debug, Clone)]
struct NetRecord {
    id: String,
    post_data: Option<String>,
    body: Vec<u8>,
}

/// One cookie in the per-session jar.
#[derive(Debug, Clone)]
struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    expires: f64,
}

/// The browser: targets + sessions, dispatching CDP commands.
pub struct CdpBrowser {
    sessions: HashMap<String, Session>,
    targets: HashMap<String, String>, // target_id -> current url
    /// target_id -> browser context id (the default context is
    /// `context-default`; `Target.createBrowserContext` mints more).
    target_contexts: HashMap<String, String>,
    browser_contexts: Vec<String>,
    next_id: u64,
    events: Vec<CdpEvent>,
    /// `Browser.close` was called: every later command fails with -32000.
    closed: bool,
}

impl Default for CdpBrowser {
    fn default() -> Self {
        Self::new()
    }
}
impl CdpBrowser {
    pub fn new() -> CdpBrowser {
        CdpBrowser {
            sessions: HashMap::new(),
            targets: HashMap::new(),
            target_contexts: HashMap::new(),
            browser_contexts: vec![DEFAULT_CONTEXT.to_string()],
            next_id: 1,
            events: Vec::new(),
            closed: false,
        }
    }

    fn fresh_id(&mut self, prefix: &str) -> String {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        format!("{prefix}-{id:04}")
    }

    /// Dispatch one command against the browser, producing a reply and
    /// draining any events it raised.
    pub fn dispatch(&mut self, cmd: &CdpCommand, host: &mut dyn CdpHost) -> CdpReply {
        let result = if self.closed {
            Err(CdpError {
                code: -32000,
                message: "browser is closed (Browser.close)".to_string(),
            })
        } else {
            self.dispatch_inner(cmd, host)
        };
        CdpReply {
            id: cmd.id,
            result,
            events: core::mem::take(&mut self.events),
        }
    }

    fn session_for(&mut self, cmd: &CdpCommand) -> Result<&mut Session, CdpError> {
        let sid = cmd.session_id.clone().unwrap_or_default();
        // Fall back to the sole session for sessionless clients. Resolve the
        // key FIRST so only one mutable borrow of the map ever exists.
        let key: Option<String> = if sid.is_empty() {
            if self.sessions.len() == 1 {
                self.sessions.keys().next().cloned()
            } else {
                None
            }
        } else {
            Some(sid)
        };
        key.and_then(|k| self.sessions.get_mut(&k)).ok_or(CdpError {
            code: -32001,
            message: "no session; Target.attachToTarget first".to_string(),
        })
    }

    fn dispatch_inner(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        let domain = cmd.method.split_once('.').map_or("", |(domain, _)| domain);
        match domain {
            "Browser" | "Schema" => self.browser_command(cmd),
            "Target" => self.target_command(cmd),
            "Page" => self.page_command(cmd, host),
            "Runtime" => self.runtime_command(cmd, host),
            "DOM" => self.dom_command(cmd, host),
            "Emulation" => self.emulation_command(cmd, host),
            "Input" => self.input_command(cmd, host),
            "CSS" => self.css_command(cmd),
            "Accessibility" => self.accessibility_command(cmd),
            "Network" => self.network_command(cmd, host),
            "Log" | "Console" | "Performance" | "Security" => self.diagnostics_command(cmd),
            _ => Err(method_not_found(&cmd.method)),
        }
    }
}

impl CdpBrowser {
    /// Build a laid-out [`Page`] from the session's CURRENT document and the
    /// stylesheets fetched at navigation (no network: images are omitted, so
    /// geometry queries stay cheap and deterministic).
    fn page_for(&mut self, cmd: &CdpCommand) -> Result<Page, CdpError> {
        let session = self.session_for(cmd)?;
        let doc = session.doc.borrow().clone();
        let sheets = all_sheets(session);
        let width = session.viewport_width;
        let height = session.viewport_height;
        let sheet_refs: Vec<&str> = sheets.iter().map(String::as_str).collect();
        Ok(Page::from_document(
            doc,
            PageOptions {
                viewport_width: width,
                viewport_height: height,
                ..PageOptions::default()
            },
            &sheet_refs,
            &HashMap::new(),
        ))
    }

    /// Run `f` with a realm-adopted interpreter over the session document,
    /// then capture the realm back and surface console lines / exceptions as
    /// CDP events. The inner result is the command's to interpret.
    fn with_session_interp<T>(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
        f: impl FnOnce(&mut Interp<'_>) -> Result<T, JsVal>,
    ) -> Result<Result<T, String>, CdpError> {
        let (doc, mut realm) = {
            let session = self.session_for(cmd)?;
            (session.doc.clone(), core::mem::take(&mut session.realm))
        };
        let mut tap = ConsoleTap {
            inner: host.hooks(),
            lines: Vec::new(),
        };
        let out = {
            let mut interp = Interp::new(&mut tap);
            if realm.is_live() {
                realm.adopt_into(&mut interp);
            }
            interp.dom = Some(doc);
            dom_bindings::install_document(&mut interp);
            let r = f(&mut interp).map_err(|e| super::js::interp::to_display(&e));
            let drained = interp
                .drain_microtasks()
                .map_err(|e| super::js::interp::to_display(&e));
            realm = Realm::capture_from(&interp);
            match (r, drained) {
                (Err(e), _) => Err(e),
                (Ok(_), Err(e)) => Err(e),
                (Ok(v), Ok(())) => Ok(v),
            }
        };
        let lines = tap.lines;
        for (level, text) in &lines {
            self.emit_console(cmd, level, text);
        }
        if let Err(e) = &out {
            self.events.push(exception_event(e, cmd.session_id.clone()));
        }
        let session = self.session_for(cmd)?;
        session.realm = realm;
        Ok(out)
    }
}

impl CdpBrowser {
    /// Raise the CDP events one captured console line stands for: a plain
    /// line is `Runtime.consoleAPICalled` (mirrored into the Log and Console
    /// domains when they are enabled); the engine-internal `__cdp_binding`
    /// and `__cdp_dialog` levels carry `Runtime.bindingCalled` and the
    /// `Page.javascriptDialog*` pair instead.
    fn emit_console(&mut self, cmd: &CdpCommand, level: &str, text: &str) {
        let sid = cmd.session_id.clone();
        match level {
            "__cdp_binding" => {
                let (name, payload) = text.split_once('\u{0}').unwrap_or((text, ""));
                self.events.push(CdpEvent {
                    method: "Runtime.bindingCalled".to_string(),
                    params: JsonValue::obj(vec![
                        ("name", JsonValue::str(name)),
                        ("payload", JsonValue::str(payload)),
                        ("executionContextId", JsonValue::Num(1.0)),
                    ]),
                    session_id: sid,
                });
            }
            "__cdp_dialog" => {
                let (kind, message) = text.split_once('\u{0}').unwrap_or(("alert", text));
                let (url, accept, prompt_text) = match self.session_for(cmd) {
                    Ok(s) => (s.url.clone(), s.dialog_accept, s.dialog_prompt.clone()),
                    Err(_) => (String::new(), true, None),
                };
                self.events.push(CdpEvent {
                    method: "Page.javascriptDialogOpening".to_string(),
                    params: JsonValue::obj(vec![
                        ("url", JsonValue::str(url)),
                        ("message", JsonValue::str(message)),
                        ("type", JsonValue::str(kind)),
                        ("hasBrowserHandler", JsonValue::Bool(true)),
                    ]),
                    session_id: sid.clone(),
                });
                self.events.push(CdpEvent {
                    method: "Page.javascriptDialogClosed".to_string(),
                    params: JsonValue::obj(vec![
                        ("result", JsonValue::Bool(accept)),
                        ("userInput", JsonValue::str(prompt_text.unwrap_or_default())),
                    ]),
                    session_id: sid,
                });
            }
            _ => {
                self.events.push(console_event(level, text, sid.clone()));
                let (log_on, console_on) = match self.session_for(cmd) {
                    Ok(s) => {
                        s.log_entries.push((level.to_string(), text.to_string()));
                        (s.log_enabled, s.console_enabled)
                    }
                    Err(_) => (false, false),
                };
                if log_on {
                    self.events.push(log_entry_event(level, text, sid.clone()));
                }
                if console_on {
                    self.events.push(console_message_event(level, text, sid));
                }
            }
        }
    }

    /// Re-install the session's CDP-owned globals into its live realm after
    /// a setting changed (`Runtime.addBinding`, an Emulation override, a
    /// dialog policy). Navigation seeds the fresh realm itself.
    fn seed_realm(&mut self, cmd: &CdpCommand, host: &mut dyn CdpHost) -> Result<(), CdpError> {
        let (doc, mut realm, seed) = {
            let s = self.session_for(cmd)?;
            (s.doc.clone(), core::mem::take(&mut s.realm), RealmSeed::of(s))
        };
        seed_realm_globals(doc, &mut realm, host.hooks(), &seed);
        let s = self.session_for(cmd)?;
        s.realm = realm;
        Ok(())
    }
}

/// The CDP-controlled state a realm's globals are built from.
struct RealmSeed {
    bindings: Vec<String>,
    user_agent: Option<String>,
    locale: Option<String>,
    touch: bool,
    dialog_accept: bool,
    dialog_prompt: Option<String>,
    geolocation: Option<(f64, f64, f64)>,
    timezone: Option<String>,
}

impl RealmSeed {
    fn of(s: &Session) -> RealmSeed {
        RealmSeed {
            bindings: s.bindings.clone(),
            user_agent: s.user_agent.clone(),
            locale: s.locale.clone(),
            touch: s.touch_enabled,
            dialog_accept: s.dialog_accept,
            dialog_prompt: s.dialog_prompt.clone(),
            geolocation: s.geolocation,
            timezone: s.timezone.clone(),
        }
    }
}

/// Install the binding functions, emulated `navigator` fields, geolocation
/// and the `alert` / `confirm` / `prompt` dialog functions into `realm`
/// (creating it when it is not live yet). Dialog outcomes follow
/// `Page.handleJavaScriptDialog`; the engine has no modal UI, so they
/// resolve synchronously and surface as `Page.javascriptDialog*` events.
fn seed_realm_globals(
    doc: Rc<RefCell<Document>>,
    realm: &mut Realm,
    hooks: &mut dyn HostHooks,
    seed: &RealmSeed,
) {
    use super::js::value::NativeFn;
    let mut interp = Interp::new(hooks);
    if realm.is_live() {
        realm.adopt_into(&mut interp);
    }
    interp.dom = Some(doc);
    dom_bindings::install_document(&mut interp);
    let nav = interp.global_object.borrow().get_prop("navigator");
    if let Some(JsVal::Object(nav)) = nav {
        let mut b = nav.borrow_mut();
        if let Some(ua) = &seed.user_agent {
            b.set_prop("userAgent", JsVal::str(ua.clone()), true);
        }
        b.set_prop(
            "language",
            JsVal::str(seed.locale.clone().unwrap_or_else(|| "en-US".to_string())),
            true,
        );
        b.set_prop(
            "maxTouchPoints",
            JsVal::Num(if seed.touch { 5.0 } else { 0.0 }),
            true,
        );
        if let Some(tz) = &seed.timezone {
            b.set_prop("__timeZone", JsVal::str(tz.clone()), false);
        }
        let geo = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        let fix = seed.geolocation;
        let get_pos: NativeFn = Rc::new(move |interp, _this, args| {
            match fix {
                Some((lat, lon, acc)) => {
                    let coords = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                    coords.borrow_mut().set_prop("latitude", JsVal::Num(lat), true);
                    coords.borrow_mut().set_prop("longitude", JsVal::Num(lon), true);
                    coords.borrow_mut().set_prop("accuracy", JsVal::Num(acc), true);
                    let pos = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                    pos.borrow_mut().set_prop("coords", JsVal::Object(coords), true);
                    pos.borrow_mut().set_prop("timestamp", JsVal::Num(interp.now_ms), true);
                    if let Some(cb) = args.first().cloned() {
                        interp.call(cb, JsVal::Undefined, &[JsVal::Object(pos)])?;
                    }
                }
                None => {
                    if let Some(cb) = args.get(1).cloned() {
                        let err = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                        err.borrow_mut().set_prop("code", JsVal::Num(1.0), true);
                        err.borrow_mut().set_prop(
                            "message",
                            JsVal::str("geolocation unavailable"),
                            true,
                        );
                        interp.call(cb, JsVal::Undefined, &[JsVal::Object(err)])?;
                    }
                }
            }
            Ok(JsVal::Undefined)
        });
        let f = JsVal::Object(JsObject::new(
            ObjKind::Native(get_pos),
            Some(interp.function_proto.clone()),
        ));
        geo.borrow_mut().set_prop("getCurrentPosition", f, false);
        b.set_prop("geolocation", JsVal::Object(geo), true);
    }
    for name in &seed.bindings {
        let n = name.clone();
        let f: NativeFn = Rc::new(move |interp, _this, args| {
            let payload = args.first().map(|a| a.to_js_string()).unwrap_or_default();
            interp
                .hooks
                .console("__cdp_binding", &format!("{n}\u{0}{payload}"));
            Ok(JsVal::Undefined)
        });
        let fv = JsVal::Object(JsObject::new(
            ObjKind::Native(f),
            Some(interp.function_proto.clone()),
        ));
        set_realm_global(&mut interp, name, fv);
    }
    let alert: NativeFn = Rc::new(|interp, _this, args| {
        let m = args.first().map(|a| a.to_js_string()).unwrap_or_default();
        interp
            .hooks
            .console("__cdp_dialog", &format!("alert\u{0}{m}"));
        Ok(JsVal::Undefined)
    });
    let accept = seed.dialog_accept;
    let confirm: NativeFn = Rc::new(move |interp, _this, args| {
        let m = args.first().map(|a| a.to_js_string()).unwrap_or_default();
        interp
            .hooks
            .console("__cdp_dialog", &format!("confirm\u{0}{m}"));
        Ok(JsVal::Bool(accept))
    });
    let prompt_text = seed.dialog_prompt.clone();
    let prompt: NativeFn = Rc::new(move |interp, _this, args| {
        let m = args.first().map(|a| a.to_js_string()).unwrap_or_default();
        interp
            .hooks
            .console("__cdp_dialog", &format!("prompt\u{0}{m}"));
        if !accept {
            return Ok(JsVal::Null);
        }
        let answer = prompt_text
            .clone()
            .or_else(|| args.get(1).map(|d| d.to_js_string()))
            .unwrap_or_default();
        Ok(JsVal::str(answer))
    });
    for (name, f) in [("alert", alert), ("confirm", confirm), ("prompt", prompt)] {
        let fv = JsVal::Object(JsObject::new(
            ObjKind::Native(f),
            Some(interp.function_proto.clone()),
        ));
        set_realm_global(&mut interp, name, fv);
    }
    *realm = Realm::capture_from(&interp);
}

/// Every author stylesheet beyond the document's own `<style>` blocks:
/// the `<link rel=stylesheet>` sheets fetched at navigation, then the
/// sheets a client created through `CSS.createStyleSheet`, in that order.
fn all_sheets(session: &Session) -> Vec<String> {
    let mut sheets = session.stylesheets.clone();
    sheets.extend(session.created_sheets.iter().map(|(_, css)| css.clone()));
    sheets
}

/// Declare `name` on the global object and in the global scope.
fn set_realm_global(interp: &mut Interp<'_>, name: &str, v: JsVal) {
    interp
        .global_object
        .borrow_mut()
        .set_prop(name, v.clone(), false);
    super::js::interp::Scope::declare(&interp.global_scope.clone(), name, v, false);
}

/// The host of an http(s) URL: lower-cased, without port or credentials,
/// and with an IPv6 literal kept in its brackets. Empty for a URL that
/// [`canonical_navigation_url`] refuses, so no cookie matches it.
fn url_host(url: &str) -> String {
    let Some(origin) = navigation_origin(url) else {
        return String::new();
    };
    let authority = origin.split_once("://").map_or("", |(_, a)| a);
    let host = match authority.find(']') {
        Some(close) if authority.starts_with('[') => authority.get(..=close),
        _ => authority.split(':').next(),
    };
    host.unwrap_or("").to_string()
}

/// The path of an http(s) URL (`/` when absent), ending before any query
/// or fragment.
fn url_path(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    match rest.find('/') {
        Some(i) => rest.get(i..).unwrap_or("/").to_string(),
        None => "/".to_string(),
    }
}

/// Whether `c` is sent with a request to `url`: a domain cookie (stored
/// with a leading `.`) matches its domain and subdomains of a named host,
/// a host-only cookie matches its host exactly; then the path prefix and
/// secure-only over https.
fn cookie_matches(c: &Cookie, url: &str) -> bool {
    let host = url_host(url);
    let domain_ok = match c.domain.strip_prefix('.') {
        Some(d) => {
            !d.is_empty()
                && (host == d || (!is_address(&host) && host.ends_with(&format!(".{d}"))))
        }
        None => !host.is_empty() && host == c.domain,
    };
    domain_ok && url_path(url).starts_with(&c.path) && (!c.secure || url.starts_with("https://"))
}

/// An IPv4 literal or bracketed IPv6 literal host.
fn is_address(host: &str) -> bool {
    host.starts_with('[') || host.parse::<core::net::Ipv4Addr>().is_ok()
}

/// A `Log.entryAdded` event for one console line.
fn log_entry_event(level: &str, text: &str, session_id: Option<String>) -> CdpEvent {
    let level = match level {
        "warn" => "warning",
        "error" => "error",
        "debug" => "verbose",
        _ => "info",
    };
    CdpEvent {
        method: "Log.entryAdded".to_string(),
        params: JsonValue::obj(vec![(
            "entry",
            JsonValue::obj(vec![
                ("source", JsonValue::str("javascript")),
                ("level", JsonValue::str(level)),
                ("text", JsonValue::str(text)),
                ("timestamp", JsonValue::Num(0.0)),
            ]),
        )]),
        session_id,
    }
}

/// A `Console.messageAdded` event for one console line.
fn console_message_event(level: &str, text: &str, session_id: Option<String>) -> CdpEvent {
    let level = match level {
        "warn" => "warning",
        "error" => "error",
        "debug" => "debug",
        "info" => "info",
        _ => "log",
    };
    CdpEvent {
        method: "Console.messageAdded".to_string(),
        params: JsonValue::obj(vec![(
            "message",
            JsonValue::obj(vec![
                ("source", JsonValue::str("console-api")),
                ("level", JsonValue::str(level)),
                ("text", JsonValue::str(text)),
            ]),
        )]),
        session_id,
    }
}

/// Topmost visible layout box containing (x, y), by paint order.
fn hit_test(page: &Page, x: f32, y: f32) -> Option<NodeId> {
    let mut best: Option<NodeId> = None;
    for b in &page.layout.boxes {
        if !b.visible {
            continue;
        }
        let r = &b.rect;
        if x >= r.x && x <= r.x + r.width && y >= r.y && y <= r.y + r.height {
            if let Some(n) = b.node {
                best = Some(n);
            }
        }
    }
    best
}

/// Console hook wrapper: forwards to the embedder's hooks while capturing
/// the lines so the dispatcher can raise Runtime.consoleAPICalled events.
struct ConsoleTap<'a> {
    inner: &'a mut dyn HostHooks,
    lines: Vec<(String, String)>,
}

impl HostHooks for ConsoleTap<'_> {
    fn fetch(
        &mut self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        self.inner.fetch(url, method, headers, body)
    }
    fn console(&mut self, level: &str, message: &str) {
        self.lines.push((level.to_string(), message.to_string()));
        self.inner.console(level, message);
    }
    fn random_fill(&mut self, dest: &mut [u8]) -> Result<(), String> {
        self.inner.random_fill(dest)
    }
}

/// Evaluate an expression inside the session realm, capturing the realm
/// back so later commands observe the bindings, listeners and focus this
/// evaluation created. Errors come back as display strings.
fn eval_in_realm(
    doc: Rc<RefCell<Document>>,
    realm: &mut Realm,
    expr: &str,
    hooks: &mut dyn HostHooks,
) -> Result<JsVal, String> {
    let prog = parser::parse(expr).map_err(|e| format!("SyntaxError: {}", e.message))?;
    let mut interp = Interp::new(hooks);
    if realm.is_live() {
        realm.adopt_into(&mut interp);
    }
    interp.dom = Some(doc);
    dom_bindings::install_document(&mut interp);
    let out = interp
        .run_program(&prog)
        .map_err(|e| super::js::interp::to_display(&e));
    // A rejected queued microtask is part of the evaluation's outcome: it
    // must surface through the command result / exceptionThrown path, not
    // vanish (review R17).
    let drained = interp
        .drain_microtasks()
        .map_err(|e| super::js::interp::to_display(&e));
    *realm = Realm::capture_from(&interp);
    match (out, drained) {
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(v), Ok(())) => Ok(v),
    }
}

/// A Runtime.consoleAPICalled event for one captured console line.
fn console_event(level: &str, text: &str, session_id: Option<String>) -> CdpEvent {
    CdpEvent {
        method: "Runtime.consoleAPICalled".to_string(),
        params: JsonValue::obj(vec![
            ("type", JsonValue::str(level)),
            (
                "args",
                JsonValue::Arr(vec![JsonValue::obj(vec![
                    ("type", JsonValue::str("string")),
                    ("value", JsonValue::str(text)),
                ])]),
            ),
            ("executionContextId", JsonValue::Num(1.0)),
            ("timestamp", JsonValue::Num(0.0)),
        ]),
        session_id,
    }
}

/// A Runtime.exceptionThrown event for one script error.
fn exception_event(text: &str, session_id: Option<String>) -> CdpEvent {
    CdpEvent {
        method: "Runtime.exceptionThrown".to_string(),
        params: JsonValue::obj(vec![
            ("timestamp", JsonValue::Num(0.0)),
            (
                "exceptionDetails",
                JsonValue::obj(vec![
                    ("text", JsonValue::str(text)),
                    ("exceptionId", JsonValue::Num(1.0)),
                    ("lineNumber", JsonValue::Num(0.0)),
                    ("columnNumber", JsonValue::Num(0.0)),
                ]),
            ),
        ]),
        session_id,
    }
}

/// Describe a JS value as a CDP RemoteObject, allocating an objectId for
/// objects so Runtime.getProperties / callFunctionOn / releaseObject can
/// address them later. Primitives carry `value` inline (no id needed).
fn remote_object(session: &mut Session, v: &JsVal) -> JsonValue {
    match v {
        JsVal::Undefined => JsonValue::obj(vec![("type", JsonValue::str("undefined"))]),
        JsVal::Null => JsonValue::obj(vec![
            ("type", JsonValue::str("object")),
            ("subtype", JsonValue::str("null")),
            ("value", JsonValue::Null),
        ]),
        JsVal::Bool(b) => JsonValue::obj(vec![
            ("type", JsonValue::str("boolean")),
            ("value", JsonValue::Bool(*b)),
            ("description", JsonValue::str(v.to_js_string())),
        ]),
        JsVal::Num(n) => JsonValue::obj(vec![
            ("type", JsonValue::str("number")),
            ("value", JsonValue::Num(*n)),
            ("description", JsonValue::str(v.to_js_string())),
        ]),
        JsVal::Str(_) => JsonValue::obj(vec![
            ("type", JsonValue::str("string")),
            ("value", JsonValue::Str(v.to_js_string())),
            ("description", JsonValue::str(v.to_js_string())),
        ]),
        JsVal::Symbol(_) => JsonValue::obj(vec![
            ("type", JsonValue::str("symbol")),
            ("description", JsonValue::str(v.to_js_string())),
        ]),
        JsVal::Object(o) => {
            let (type_name, subtype, class_name, description) = {
                let b = o.borrow();
                match &b.kind {
                    ObjKind::Array => (
                        "object",
                        Some("array"),
                        "Array",
                        format!("Array({})", b.array_length()),
                    ),
                    ObjKind::Function { .. } | ObjKind::Native(_) | ObjKind::Bound { .. } => {
                        ("function", None, "Function", "function".to_string())
                    }
                    ObjKind::DomNode(_) => ("object", Some("node"), "Node", "node".to_string()),
                    ObjKind::Promise(_) => ("object", None, "Promise", "Promise".to_string()),
                    ObjKind::Date(_) => (
                        "object",
                        Some("date"),
                        "Date",
                        v.to_js_string(),
                    ),
                    ObjKind::RegExp { .. } => (
                        "object",
                        Some("regexp"),
                        "RegExp",
                        v.to_js_string(),
                    ),
                    ObjKind::Error => ("object", Some("error"), "Error", v.to_js_string()),
                    _ => ("object", None, b.class_name, "Object".to_string()),
                }
            };
            let id = format!("obj-{}", session.next_object_id);
            session.next_object_id = session.next_object_id.wrapping_add(1);
            session.remote_objects.insert(id.clone(), v.clone());
            let mut entries = vec![
                ("type", JsonValue::str(type_name)),
                ("className", JsonValue::str(class_name)),
                ("description", JsonValue::str(description)),
                ("objectId", JsonValue::str(id)),
            ];
            if let Some(st) = subtype {
                entries.insert(1, ("subtype", JsonValue::str(st)));
            }
            // Arrays and plain objects also carry a bounded value preview so
            // simple clients need no getProperties round-trip.
            let plain = matches!(
                &o.borrow().kind,
                ObjKind::Array | ObjKind::Plain
            );
            if plain {
                entries.push(("value", js_to_json(v, 0)));
            }
            JsonValue::obj(entries)
        }
    }
}

/// Convert a JsValue to JsonValue (depth-bounded, functions elided).
fn js_to_json(v: &super::js::value::JsValue, depth: usize) -> JsonValue {
    use super::js::value::{JsValue, ObjKind, Prop};
    if depth > 6 {
        return JsonValue::Null;
    }
    match v {
        JsValue::Undefined | JsValue::Null | JsValue::Symbol(_) => JsonValue::Null,
        JsValue::Bool(b) => JsonValue::Bool(*b),
        JsValue::Num(n) => JsonValue::Num(*n),
        JsValue::Str(s) => JsonValue::Str(s.as_ref().clone()),
        JsValue::Object(o) => {
            let b = o.borrow();
            match &b.kind {
                ObjKind::Array => {
                    JsonValue::Arr(b.array_values().iter().map(|e| js_to_json(e, depth + 1)).collect())
                }
                ObjKind::Function { .. } | ObjKind::Native(_) | ObjKind::Bound { .. } => {
                    JsonValue::Str("function".to_string())
                }
                _ => {
                    let mut entries = Vec::new();
                    for (k, p) in &b.props {
                        if let Prop::Value {
                            value,
                            enumerable: true,
                        } = p
                        {
                            entries.push((k.clone(), js_to_json(value, depth + 1)));
                        }
                    }
                    JsonValue::Obj(entries)
                }
            }
        }
    }
}

fn invalid(msg: &str) -> CdpError {
    CdpError {
        code: -32602,
        message: msg.to_string(),
    }
}

/// CDP node ids are arena indices + 1 (CDP reserves 0 as "none").
fn node_to_cdp(n: NodeId) -> f64 {
    (n.index() as f64) + 1.0
}

fn cdp_to_node(id: f64) -> NodeId {
    let idx = if id >= 1.0 {
        (id as usize).saturating_sub(1)
    } else {
        0
    };
    NodeId(idx as u32)
}

/// Minimal base64 for screenshot data.
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let idx = |shift: u32| {
            T.get(((n >> shift) & 0x3f) as usize)
                .copied()
                .unwrap_or(b'A') as char
        };
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

fn method_not_found(method: &str) -> CdpError {
    CdpError {
        code: -32601,
        message: format!("'{method}' wasn't found"),
    }
}
