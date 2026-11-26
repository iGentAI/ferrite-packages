//! Route patterns, matching, and the route table.
//!
//! A Alloy route is declared once, in Rust, and `alloy-gen` emits both the Rust
//! registry and the TypeScript route table from that single declaration — so
//! a route cannot exist on one side of the contract only. This module is the
//! runtime half: it parses the pattern syntax, extracts typed parameters, and
//! ranks overlapping routes deterministically.
//!
//! The pattern syntax matches the Next.js App Router's, because it is the
//! syntax every author and every coding agent already knows:
//!
//! | Pattern | Meaning | Parameter |
//! |---|---|---|
//! | `/drops` | a literal segment | — |
//! | `/drops/[id]` | one dynamic segment | `id` → one value |
//! | `/docs/[...slug]` | one or more segments | `slug` → many |
//! | `/shop/[[...path]]` | zero or more segments | `path` → many, possibly empty |
//! | `/(marketing)/about` | a route GROUP: organizes files, not URLs | — |

use std::collections::BTreeMap;

use ferrite_app::serde::{Deserialize, Serialize};
// The attested build's macro gate admits `tracing::warn!` (the reviewed
// path form), not the fully-qualified `tracing::warn!`.
use ferrite_app::tracing;

use crate::alloy::cache::CacheLife;

/// One parsed segment of a route pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// A literal path segment.
    Static(String),
    /// `[name]` — exactly one segment.
    Param(String),
    /// `[...name]` — one or more trailing segments.
    CatchAll(String),
    /// `[[...name]]` — zero or more trailing segments.
    OptionalCatchAll(String),
}

/// A matched parameter value: one segment, or the tail of a catch-all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", untagged)]
pub enum ParamValue {
    /// A single segment (`[id]`).
    One(String),
    /// A segment list (`[...slug]`, `[[...slug]]`).
    Many(Vec<String>),
}

impl ParamValue {
    /// The single value, when this is a `[name]` parameter.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ParamValue::One(s) => Some(s.as_str()),
            ParamValue::Many(_) => None,
        }
    }

    /// The segment list, when this is a catch-all parameter.
    pub fn as_slice(&self) -> Option<&[String]> {
        match self {
            ParamValue::Many(v) => Some(v.as_slice()),
            ParamValue::One(_) => None,
        }
    }
}

/// The parameters extracted from a matched path.
pub type Params = BTreeMap<String, ParamValue>;

/// How a page route reaches the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum RenderMode {
    /// Fully prerendered at build time; the served HTML is complete.
    Static,
    /// A build-time shell, with per-request metadata and loader data
    /// substituted by Rust. The default.
    Hybrid,
    /// A bare mount point: no prerender, for authenticated interiors.
    Spa,
}

impl Default for RenderMode {
    fn default() -> Self {
        Self::Hybrid
    }
}

/// What a route serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum RouteKind {
    /// A page: a document request serves a shell; a client navigation serves
    /// the loader payload as JSON.
    Page,
    /// A route handler: typed HTTP methods, JSON in and out.
    Handler,
}

/// One route in the generated registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The stable route id (also the generated symbol name).
    pub id: String,
    /// The declared pattern.
    pub pattern: String,
    /// The parsed pattern.
    pub segments: Vec<Segment>,
    /// Page or handler.
    pub kind: RouteKind,
    /// The render mode (pages only).
    pub render: RenderMode,
    /// The loader function id, when the route declares one.
    pub loader: Option<String>,
    /// The action ids reachable from this route.
    pub actions: Vec<String>,
    /// The HTTP methods a handler route answers.
    pub methods: Vec<String>,
    /// Response headers this route stamps on every reply it produces.
    headers: Vec<(String, String)>,
    /// The freshness profile a publicly cacheable render is derived from.
    cache_life: Option<CacheLife>,
}

impl Route {
    /// A page route with the default render mode.
    pub fn page(id: impl Into<String>, pattern: &str) -> core::result::Result<Self, String> {
        Ok(Self {
            id: id.into(),
            pattern: pattern.to_string(),
            segments: parse_pattern(pattern)?,
            kind: RouteKind::Page,
            render: RenderMode::Hybrid,
            loader: None,
            actions: Vec::new(),
            methods: vec!["GET".into()],
            headers: Vec::new(),
            cache_life: None,
        })
    }

    /// A route handler answering `methods`.
    pub fn handler(
        id: impl Into<String>,
        pattern: &str,
        methods: &[&str],
    ) -> core::result::Result<Self, String> {
        Ok(Self {
            id: id.into(),
            pattern: pattern.to_string(),
            segments: parse_pattern(pattern)?,
            kind: RouteKind::Handler,
            render: RenderMode::Spa,
            loader: None,
            actions: Vec::new(),
            methods: methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
            headers: Vec::new(),
            cache_life: None,
        })
    }

    /// Set the render mode.
    pub fn with_render(mut self, render: RenderMode) -> Self {
        self.render = render;
        self
    }

    /// Set the loader id.
    pub fn with_loader(mut self, loader: impl Into<String>) -> Self {
        self.loader = Some(loader.into());
        self
    }

    /// Declare the actions reachable from this route.
    pub fn with_actions(mut self, actions: &[&str]) -> Self {
        self.actions = actions.iter().map(|a| a.to_string()).collect();
        self
    }

    /// Declare response headers the shell stamps on this route's replies.
    ///
    /// Two classes of header are dropped here rather than carried into a
    /// reply, because both fail in a way the author cannot see:
    ///
    /// - **A gateway-owned header** ([`REFUSED_HEADERS`]). The gateway owns
    ///   reply framing and refuses an application reply that names one —
    ///   WHOLE, with a 502 — so a single stray `content-length` on one route
    ///   takes that route's every response down rather than merely being
    ///   ignored.
    /// - **A name or value carrying a control character.** A value holding
    ///   CR or LF is the classic response-splitting payload: it ends the
    ///   header and begins whatever the attacker wrote next. The generator
    ///   validates the charset at build time, but a route table is ordinary
    ///   Rust an application may also write by hand, and this is the one
    ///   place every route passes through.
    ///
    /// Dropping rather than refusing keeps the builder infallible, which is
    /// what lets generated code chain it; the drop is logged so it is not
    /// silent.
    pub fn with_headers(mut self, headers: &[(&str, &str)]) -> Self {
        for (name, value) in headers {
            if !is_admissible_header(name, value) {
                tracing::warn!(
                    target: "alloy::router",
                    route = %self.id,
                    header = %name,
                    "a route header was dropped: it is gateway-owned or carries an \
                     illegal character"
                );
                continue;
            }
            let lowered = name.to_ascii_lowercase();
            // A repeated name is a LAST-wins replacement rather than two
            // headers: `x-frame-options` twice with different values is a
            // header browsers resolve by ignoring both.
            self.headers.retain(|(existing, _)| existing != &lowered);
            self.headers.push((lowered, value.to_string()));
        }
        self
    }

    /// The response headers this route declares.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Declare the freshness profile a publicly cacheable render derives its
    /// `cache-control` from.
    pub fn with_cache_life(mut self, life: CacheLife) -> Self {
        self.cache_life = Some(life);
        self
    }

    /// The declared cache life, when the route named one.
    pub fn cache_life(&self) -> Option<CacheLife> {
        self.cache_life
    }

    /// Match a path (without its query string) against this route.
    ///
    /// A path carrying a malformed percent sequence matches NOTHING, because
    /// such a path has no single meaning — see [`try_split_path`].
    pub fn match_path(&self, path: &str) -> Option<Params> {
        let parts = try_split_path(path)?;
        match_segments(&self.segments, &parts)
    }

    /// The ranking key: lower sorts first, so the most specific route wins.
    ///
    /// Specificity is compared **segment by segment, left to right**, which
    /// is what "a longer literal prefix wins" actually means. At each
    /// position a static segment beats a parameter, a parameter beats a
    /// catch-all, and a required catch-all beats an optional one; the first
    /// position where two patterns differ decides between them.
    ///
    /// Aggregate counting cannot express this. For `/a/[x]/c` against
    /// `/a/b/[y]`, both patterns hold two static and one dynamic segment, so
    /// a count-based key ties and falls through to lexical order — which
    /// picks `/a/[x]/c` even though `/a/b/[y]` matches `/a/b/c` with the
    /// longer literal prefix. Comparing left to right, position 1 is static
    /// in `/a/b/[y]` and dynamic in `/a/[x]/c`, so `/a/b/[y]` wins.
    ///
    /// The ordering is total (the pattern breaks any remaining tie) and
    /// depends only on the pattern, so a route table is deterministic
    /// regardless of declaration order.
    pub fn specificity(&self) -> (Vec<u8>, usize, String) {
        let ranks: Vec<u8> = self
            .segments
            .iter()
            .map(|seg| match seg {
                Segment::Static(_) => 0u8,
                Segment::Param(_) => 1,
                Segment::CatchAll(_) => 2,
                Segment::OptionalCatchAll(_) => 3,
            })
            .collect();
        (ranks, self.segments.len(), self.pattern.clone())
    }
}

/// Parse a route pattern into segments.
///
/// Route groups (`(name)`) organize the source tree and never appear in a
/// URL, so they are dropped here. A catch-all must be the final segment, and
/// parameter names must be unique — both are build errors in the generator
/// and hard errors here, so a hand-written table cannot smuggle in a pattern
/// the generator would have refused.
pub fn parse_pattern(pattern: &str) -> core::result::Result<Vec<Segment>, String> {
    if !pattern.starts_with('/') {
        return Err(format!("route pattern '{pattern}' must start with '/'"));
    }
    let mut segments = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    let pieces: Vec<&str> = pattern.split('/').filter(|p| !p.is_empty()).collect();
    for (i, piece) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        if piece.starts_with('(') && piece.ends_with(')') {
            continue; // a route group: source organization, not a URL segment
        }
        let (inner, segment): (&str, fn(String) -> Segment) = if let Some(inner) = piece
            .strip_prefix("[[...")
            .and_then(|s| s.strip_suffix("]]"))
        {
            if !last {
                return Err(format!(
                    "optional catch-all '[[...{inner}]]' must be the last segment of '{pattern}'"
                ));
            }
            (inner, Segment::OptionalCatchAll)
        } else if let Some(inner) = piece.strip_prefix("[...").and_then(|s| s.strip_suffix(']')) {
            if !last {
                return Err(format!(
                    "catch-all '[...{inner}]' must be the last segment of '{pattern}'"
                ));
            }
            (inner, Segment::CatchAll)
        } else if let Some(inner) = piece.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            (inner, Segment::Param)
        } else {
            if piece.contains('[') || piece.contains(']') {
                return Err(format!(
                    "malformed dynamic segment '{piece}' in '{pattern}'"
                ));
            }
            segments.push(Segment::Static(piece.to_string()));
            continue;
        };
        check_param_name(inner, piece, pattern)?;
        if seen.contains(&inner) {
            return Err(format!(
                "parameter '{inner}' is declared twice in '{pattern}'"
            ));
        }
        seen.push(inner);
        segments.push(segment(inner.to_string()));
    }
    Ok(segments)
}

/// Refuse a parameter name that is not a plain identifier.
///
/// The bracket-stripping above is a PREFIX/SUFFIX match, so it happily
/// leaves whatever is between the brackets untouched — including more
/// brackets and more dots. Without this check `[...id]]` parses to a
/// parameter literally named `id]`, and `[....id]` to one named `.id`.
///
/// Both are silent: the route matches, the parameter binds, and the name
/// travels into the generated TypeScript as an object key and into the
/// loader payload as JSON. The author sees a parameter that is *almost*
/// the one they wrote, and the mismatch surfaces far from its cause.
///
/// Next.js refuses exactly these two shapes at build time, with the same
/// reasoning: a segment name may not start or end with extra brackets, and
/// may not start with erroneous periods.
fn check_param_name(name: &str, piece: &str, pattern: &str) -> core::result::Result<(), String> {
    if name.is_empty() {
        return Err(format!("empty parameter name in '{pattern}'"));
    }
    if name.starts_with('.') {
        return Err(format!(
            "segment '{piece}' in '{pattern}' names a parameter starting with a period; \
             a catch-all is spelled '[...name]' with exactly three dots"
        ));
    }
    if name.contains('[') || name.contains(']') {
        return Err(format!(
            "segment '{piece}' in '{pattern}' leaves a bracket inside the parameter \
             name '{name}'; the name must be a plain identifier"
        ));
    }
    // A name reaches the generated TypeScript as an object key and the Rust
    // registry as a map key, so anything outside an identifier charset is a
    // build error here rather than a puzzle two toolchains later.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return Err(format!(
            "parameter name '{name}' in '{pattern}' must be alphanumeric, '_' or '$'"
        ));
    }
    Ok(())
}

/// Whether a request target is a RELATIVE path rather than an absolute or
/// protocol-relative URL.
///
/// Next refuses `http://example.com/abc` and treats `//host` as a hostile
/// shape for the same reason this does: a target that names another origin
/// is not a path, and matching it against a route table is how a redirect
/// or a navigation ends up pointing somewhere the application never owned.
///
/// The two shapes are distinct and both matter:
///
/// - **`scheme://host/path`** would split into `["scheme:", "host", …]`, so
///   a catch-all route would happily match it and bind `scheme:` as an
///   ordinary parameter.
/// - **`//host/path`** carries no scheme at all, and a browser resolves it
///   against the CURRENT one — which is exactly what makes it the classic
///   open-redirect payload. Splitting drops the empty leading segments, so
///   without this check it is indistinguishable from `/host/path`.
///
/// A target holding any control character is refused too: a browser strips
/// tab and newline from a URL, so `/\t/evil.com` and `/\n/evil.com` become
/// `//evil.com` after this check has looked at them.
pub fn is_relative_target(target: &str) -> bool {
    if target.chars().any(char::is_control) {
        return false;
    }
    let bare = target.split(['?', '#']).next().unwrap_or("");
    // A path is empty or absolute. Anything else — `drops/42`, or a leading
    // space a browser strips before reading `https:` or `\\host` — is not
    // one of this application's paths.
    if !(bare.is_empty() || bare.starts_with('/')) || target.starts_with(char::is_whitespace) {
        return false;
    }
    if bare.starts_with("//") {
        return false;
    }
    // A scheme is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`, and it
    // can only appear before the first `/` — `\` is included because
    // browsers normalise a backslash to a forward slash in a URL, so
    // `/\evil.com` is protocol-relative in practice even though it does
    // not look it.
    if bare.starts_with('\\') || bare.starts_with("/\\") {
        return false;
    }
    match bare.find(':') {
        Some(colon) => {
            let scheme = &bare[..colon];
            let looks_like_scheme = !scheme.is_empty()
                && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
            // A colon INSIDE a later segment is legal in a path
            // (`/drops/a:b`), so only a scheme-shaped prefix before any
            // slash disqualifies the target.
            let before_slash = bare[..colon].find('/').is_none();
            !(looks_like_scheme && before_slash)
        }
        None => true,
    }
}

/// Split a path into percent-decoded segments, replacing invalid bytes.
///
/// This is the LOSSY form, kept for callers that are describing a path
/// rather than resolving one. Routing uses [`try_split_path`], because
/// replacement makes distinct URLs identical — see there for why that
/// matters.
pub fn split_path(path: &str) -> Vec<String> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.split('/')
        .filter(|p| !p.is_empty())
        .map(percent_decode)
        .collect()
}

/// Split a path into percent-decoded segments, refusing a malformed one.
///
/// # Why a bad escape is a 404 and not a replacement character
///
/// `String::from_utf8_lossy` maps every invalid byte to U+FFFD, so `%ff`,
/// `%fe` and a LEGITIMATE `%ef%bf%bd` all decode to the same string. Three
/// different URLs then name one resource: they match the same route, bind
/// the same parameter, and produce the same cache key — so a response
/// computed for one is served for the others, and an audit record cannot
/// say which was requested.
///
/// Next.js refuses the same input rather than repairing it, and refusing is
/// the safe direction: a client that sent a malformed path gets a 404 it
/// can act on, instead of another request's answer.
pub fn try_split_path(path: &str) -> Option<Vec<String>> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    // An INTERIOR empty segment is refused. Upstream builds a per-segment
    // matcher of `[^/]+?`, which requires at least one character, so
    // `/drops//42` matches nothing there — and it must not here either,
    // or `/drops/42`, `/drops//42` and `/drops///42` would be one
    // resource under three URLs, sharing a cache key and an audit record.
    //
    // A LEADING empty segment is the protocol-relative case, already
    // refused above; a TRAILING one is the ordinary `/drops/42/`
    // spelling that clients really send, and is folded rather than
    // refused. That asymmetry is deliberate: only the interior form has
    // no legitimate sender.
    if !(path.is_empty() || path.starts_with('/')) {
        return None;
    }
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let mut out: Vec<String> = Vec::new();
    for (i, raw) in trimmed.split('/').enumerate() {
        if raw.is_empty() {
            // index 0 is the empty piece before the leading '/'.
            if i == 0 {
                continue;
            }
            return None;
        }
        out.push(try_percent_decode(raw)?);
    }
    Some(out)
}

/// Match parsed segments against decoded path parts.
pub fn match_segments(segments: &[Segment], parts: &[String]) -> Option<Params> {
    let mut params = Params::new();
    let mut i = 0usize;
    for (idx, seg) in segments.iter().enumerate() {
        match seg {
            Segment::Static(s) => {
                if parts.get(i)? != s {
                    return None;
                }
                i += 1;
            }
            Segment::Param(name) => {
                let v = parts.get(i)?;
                params.insert(name.clone(), ParamValue::One(v.clone()));
                i += 1;
            }
            Segment::CatchAll(name) => {
                if idx + 1 != segments.len() || i >= parts.len() {
                    return None;
                }
                params.insert(name.clone(), ParamValue::Many(parts[i..].to_vec()));
                i = parts.len();
            }
            Segment::OptionalCatchAll(name) => {
                if idx + 1 != segments.len() {
                    return None;
                }
                params.insert(name.clone(), ParamValue::Many(parts[i..].to_vec()));
                i = parts.len();
            }
        }
    }
    if i == parts.len() {
        Some(params)
    } else {
        None
    }
}

/// Percent-decode one path segment.
///
/// `+` is left alone: it is a space only in `application/x-www-form-urlencoded`
/// query strings, never in a path segment, and decoding it here would corrupt
/// identifiers that legitimately contain it.
pub fn percent_decode(input: &str) -> String {
    // Invalid UTF-8 in a URL is a client error, not a panic: replace rather
    // than reject, so a malformed path 404s instead of killing the worker.
    String::from_utf8_lossy(&percent_decode_bytes(input)).into_owned()
}

/// A stray `%` that is not a complete escape is kept literally: that is a
/// spelling question, not an encoding one.
fn percent_decode_bytes(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Percent-decode one path segment, or refuse a malformed one.
///
/// Differs from [`percent_decode`] in exactly one place: the final UTF-8
/// conversion. Where that one REPLACES an invalid byte, this returns
/// `None`, so a path whose bytes are not text names no route rather than
/// silently becoming its neighbour: a sequence that is not UTF-8 has no text
/// meaning, so it is refused rather than folded onto U+FFFD alongside every
/// other bad sequence.
pub fn try_percent_decode(input: &str) -> Option<String> {
    String::from_utf8(percent_decode_bytes(input)).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse the query string of a full request target into decoded pairs.
///
/// In a query string `+` DOES mean space, so it is decoded here — the
/// opposite of [`percent_decode`]'s path rule, and deliberately so.
///
/// # A repeated key keeps its FIRST value
///
/// `?project=WEB&project=API` is one key with two values, and something has
/// to choose. The choice is not free here, because this function is only
/// half of a contract: `alloy-gen` emits a TypeScript `loaderKey` that reads
/// the same query string with `URLSearchParams.get`, and the web platform
/// specifies that `get` returns the FIRST occurrence.
///
/// A last-wins map would therefore make the two halves disagree about the
/// identity of one request — the browser would seed its cache under the
/// first value while the server keyed its answer on the last. Each side is
/// internally consistent, every test passes, and a user following a link
/// with a duplicated parameter is served another filter's rows. Matching
/// the platform is what keeps one URL meaning one thing on both sides.
pub fn query_params(target: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    // The FRAGMENT is stripped first, because a '#' ends the query wherever
    // it appears — including BEFORE the first '?'. Splitting on '?' first
    // would read `/p#frag?a=1` as carrying `a=1`, inventing a parameter out
    // of fragment text that the server never receives (a browser does not
    // send the fragment at all) and that the generated `loaderKey` would
    // then fold into a cache key.
    let target = target.split('#').next().unwrap_or("");
    let Some((_, query)) = target.split_once('?') else {
        return out;
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.entry(percent_decode(&k.replace('+', " ")))
            .or_insert_with(|| percent_decode(&v.replace('+', " ")));
    }
    out
}

/// One declared redirect, exactly as the generator emits it.
///
/// `from` uses the route pattern grammar (`[param]`, `[...rest]`), and `to`
/// may reference the same parameters. Both are plain strings here because
/// this is the WIRE shape of `redirects()` in generated code; the table
/// compiles them once at [`RouteTable::with_redirects`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// The pattern a request path is matched against.
    pub from: String,
    /// The target, with path `[param]` references substituted from the match.
    /// A query string and fragment are preserved as URL syntax.
    pub to: String,
    /// 308 when true, 307 otherwise.
    pub permanent: bool,
}

/// A redirect compiled against the pattern grammar, so a request costs a
/// match rather than a parse.
#[derive(Debug, Clone)]
struct CompiledRedirect {
    from: Vec<Segment>,
    to_path: Vec<Segment>,
    /// The declared query and/or fragment, kept outside the path grammar.
    /// Encoding it as a path segment would turn `#section` into `%23section`
    /// and change the location's meaning.
    to_suffix: String,
    permanent: bool,
}

/// Build a redirect location from a `to` pattern and the matched parameters.
///
/// Every substituted value is RE-percent-encoded per segment. The matched
/// parameters are decoded text — `try_split_path` decoded them — so pasting
/// them in raw would let a request for `/old/a%2F..%2Fadmin` redirect to
/// `/new/a/../admin`: the one-segment value the pattern matched becomes
/// three segments in the location, and the traversal the split-then-decode
/// order closed reopens one hop later.
///
/// `None` when `to` names a parameter `from` never bound; the caller treats
/// that declaration as unusable rather than emitting a location with a hole.
fn substitute_target(to: &[Segment], suffix: &str, params: &Params) -> Option<String> {
    let mut out = String::new();
    for seg in to {
        match seg {
            Segment::Static(s) => {
                out.push('/');
                out.push_str(&encode_segment(s));
            }
            Segment::Param(name) => {
                let value = params.get(name)?.as_str()?;
                out.push('/');
                out.push_str(&encode_segment(value));
            }
            Segment::CatchAll(name) | Segment::OptionalCatchAll(name) => {
                let values = params.get(name)?.as_slice()?;
                for value in values {
                    out.push('/');
                    out.push_str(&encode_segment(value));
                }
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out.push_str(suffix);
    Some(out)
}

/// Split a redirect target into the path the route grammar compiles and the
/// query/fragment suffix a `Location` header must preserve verbatim.
///
/// A hand-written table is allowed alongside generated declarations, so the
/// suffix is checked here too: carrying CR, LF or NUL into `Location` would
/// let one redirect declaration inject another response header.
fn redirect_target_parts(target: &str) -> Option<(&str, &str)> {
    let suffix_at = target.find(['?', '#']).unwrap_or(target.len());
    let (path, suffix) = target.split_at(suffix_at);
    (is_header_safe(suffix) && !path.is_empty()).then_some((path, suffix))
}

/// Percent-encode one path segment of a redirect location.
///
/// Everything outside the RFC 3986 unreserved set is encoded — including
/// `/` (it would split the segment), `%` (it would double-decode), and `?`
/// and `#` (they would end the path early). Encoding conservatively cannot
/// change the segment's meaning, because a decoder maps both spellings to
/// the same text.
fn encode_segment(s: &str) -> String {
    // A whole segment of `.` or `..` is a dot-segment a client resolves, so a
    // decoded `%2e%2e` parameter must be re-encoded rather than emitted as
    // `/../` traversal in a `Location`.
    if s == "." {
        return "%2E".to_string();
    }
    if s == ".." {
        return "%2E%2E".to_string();
    }
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The reply headers the gateway owns and refuses from an application.
///
/// This mirrors the gateway's own `is_forbidden_reply_header` list: a reply
/// naming any of them is refused WHOLE with a 502, so a route header table
/// must not be able to carry one into every response of a route.
const REFUSED_HEADERS: &[&str] = &[
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

/// Whether a declared route header may reach a reply.
///
/// The name must be a token (no separators, no controls) and the value must
/// carry no CR, LF or NUL — a value holding a line break is the classic
/// response-splitting payload, ending this header and starting the
/// attacker's.
fn is_admissible_header(name: &str, value: &str) -> bool {
    if name.is_empty() || REFUSED_HEADERS.iter().any(|f| name.eq_ignore_ascii_case(f)) {
        return false;
    }
    let token = name.bytes().all(|b| {
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
    });
    token && is_header_safe(value)
}

/// Whether a value may reach a header: no CR, LF or NUL, which would end this
/// header and begin whatever the attacker wrote next.
/// The gateway's own reply-header rule: any control byte (below 0x20, or DEL)
/// fails the whole reply with a 502, so none may reach it.
fn is_header_safe(value: &str) -> bool {
    value.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|existing| existing == value) {
        list.push(value.to_string());
    }
}

/// The generated route registry.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<Route>,
    redirects: Vec<CompiledRedirect>,
}

impl RouteTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a table from routes, ordering them by specificity.
    pub fn from_routes(mut routes: Vec<Route>) -> Self {
        routes.sort_by_key(|r| r.specificity());
        Self {
            routes,
            redirects: Vec::new(),
        }
    }

    /// Declare the table's redirects, compiled once.
    ///
    /// A redirect whose `from` or target PATH does not parse under the
    /// pattern grammar is DROPPED with a log line rather than kept inert or
    /// made a panic. A target's query and fragment are not path segments and
    /// are retained separately, so `/new#section` stays a fragment redirect
    /// instead of becoming `/new%23section`.
    pub fn with_redirects(mut self, redirects: Vec<Redirect>) -> Self {
        for r in redirects {
            let Some((to_path, to_suffix)) = redirect_target_parts(&r.to) else {
                tracing::warn!(
                    target: "alloy::router",
                    from = %r.from,
                    to = %r.to,
                    "a redirect was dropped: its target is empty or carries an illegal header character"
                );
                continue;
            };
            let (Ok(from), Ok(to_path)) = (parse_pattern(&r.from), parse_pattern(to_path)) else {
                tracing::warn!(
                    target: "alloy::router",
                    from = %r.from,
                    to = %r.to,
                    "a redirect was dropped: its pattern does not parse"
                );
                continue;
            };
            self.redirects.push(CompiledRedirect {
                from,
                to_path,
                to_suffix: to_suffix.to_string(),
                permanent: r.permanent,
            });
        }
        self
    }

    /// Add a route, preserving the specificity ordering.
    pub fn push(&mut self, route: Route) {
        self.routes.push(route);
        self.routes.sort_by_key(|r| r.specificity());
    }

    /// Every route, most specific first.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Look up a route by id.
    pub fn by_id(&self, id: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.id == id)
    }

    /// Resolve a full request target (path plus optional query) and method to
    /// the most specific matching route.
    ///
    /// A path that matches a route's pattern but not its methods yields
    /// [`Resolution::MethodNotAllowed`] carrying the allowed set, so the
    /// caller answers 405 with a correct `Allow` header rather than 404.
    pub fn resolve(&self, target: &str, method: &str) -> Resolution<'_> {
        // A target naming another origin is not a path. Matching it would
        // let `//evil.com/x` bind against a catch-all and be echoed back as
        // though the application owned it.
        if !is_relative_target(target) {
            return Resolution::NotFound;
        }
        // A malformed percent sequence has no single meaning, so it names
        // no resource rather than aliasing onto one.
        let Some(parts) = try_split_path(target) else {
            return Resolution::NotFound;
        };
        // Redirects are consulted BEFORE route matching, so a redirect may
        // deliberately shadow a route (alloy-check flags the accidental
        // case). The answer is ONE hop by construction: the substituted
        // location is returned without being resolved again, so a chain —
        // or a cycle — declared in the table costs the client a round trip
        // per hop instead of costing this loop its termination.
        for redirect in &self.redirects {
            let Some(params) = match_segments(&redirect.from, &parts) else {
                continue;
            };
            let Some(location) = substitute_target(&redirect.to_path, &redirect.to_suffix, &params)
            else {
                // A `to` naming a parameter the `from` never bound cannot
                // build a meaningful location. The generator refuses the
                // declaration; a hand-written one falls through to route
                // matching rather than emitting a redirect to nowhere.
                continue;
            };
            return Resolution::Redirect {
                location,
                permanent: redirect.permanent,
            };
        }
        let method = method.to_ascii_uppercase();
        let mut allowed: Vec<String> = Vec::new();
        for route in &self.routes {
            let Some(params) = match_segments(&route.segments, &parts) else {
                continue;
            };
            let ok = match route.kind {
                RouteKind::Page => method == "GET" || method == "HEAD",
                // A handler that answers GET also answers HEAD. HTTP makes
                // HEAD derived rather than declared, so refusing it with a
                // 405 tells a client probing for existence or size that the
                // resource does not accept a method every GET resource
                // must — and no author would think to declare it.
                RouteKind::Handler => {
                    route.methods.contains(&method)
                        || (method == "HEAD" && route.methods.iter().any(|m| m == "GET"))
                }
            };
            if ok {
                return Resolution::Matched { route, params };
            }
            match route.kind {
                RouteKind::Page => {
                    push_unique(&mut allowed, "GET");
                    push_unique(&mut allowed, "HEAD");
                }
                RouteKind::Handler => {
                    for m in &route.methods {
                        push_unique(&mut allowed, m);
                    }
                    // HEAD is derived from GET, so the advertised set has
                    // to name it: an `Allow` that omitted a method the
                    // route actually accepts would send a client away from
                    // a request that works.
                    if route.methods.iter().any(|m| m == "GET") {
                        push_unique(&mut allowed, "HEAD");
                    }
                }
            }
        }
        if allowed.is_empty() {
            Resolution::NotFound
        } else {
            // OPTIONS is derived, never declared.
            if !allowed.iter().any(|a| a == "OPTIONS") {
                allowed.push("OPTIONS".to_string());
            }
            allowed.sort();
            Resolution::MethodNotAllowed { allowed }
        }
    }
}

/// The verdict of [`RouteTable::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// A route matched, with its extracted parameters.
    Matched {
        /// The matched route.
        route: &'a Route,
        /// Its parameters.
        params: Params,
    },
    /// A declared redirect matched, before any route was consulted.
    Redirect {
        /// The substituted target, percent-encoded and ready for a
        /// `location` header.
        location: String,
        /// 308 when true, 307 otherwise.
        permanent: bool,
    },
    /// The path matched a route whose methods exclude this one.
    MethodNotAllowed {
        /// The methods that would be accepted.
        allowed: Vec<String>,
    },
    /// Nothing matched.
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(p: &Params, k: &str) -> String {
        p.get(k).and_then(|v| v.as_str()).unwrap_or_default().into()
    }

    fn many(p: &Params, k: &str) -> Vec<String> {
        p.get(k)
            .and_then(|v| v.as_slice())
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }

    #[test]
    fn static_and_dynamic_segments_match() {
        let r = Route::page("drop", "/drops/[id]").unwrap();
        let p = r.match_path("/drops/42").expect("matches");
        assert_eq!(one(&p, "id"), "42");
        assert!(r.match_path("/drops").is_none());
        assert!(r.match_path("/drops/42/replies").is_none());
    }

    #[test]
    fn the_root_route_matches_only_the_root() {
        let r = Route::page("home", "/").unwrap();
        assert!(r.match_path("/").is_some());
        assert!(r.match_path("").is_some());
        assert!(r.match_path("/drops").is_none());
    }

    #[test]
    fn catch_all_requires_at_least_one_segment() {
        let r = Route::page("docs", "/docs/[...slug]").unwrap();
        assert!(r.match_path("/docs").is_none());
        assert_eq!(many(&r.match_path("/docs/a").unwrap(), "slug"), vec!["a"]);
        assert_eq!(
            many(&r.match_path("/docs/a/b/c").unwrap(), "slug"),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn optional_catch_all_matches_the_bare_prefix() {
        let r = Route::page("shop", "/shop/[[...path]]").unwrap();
        assert_eq!(many(&r.match_path("/shop").unwrap(), "path").len(), 0);
        assert_eq!(
            many(&r.match_path("/shop/a/b").unwrap(), "path"),
            vec!["a", "b"]
        );
    }

    #[test]
    fn route_groups_do_not_appear_in_the_url() {
        let r = Route::page("about", "/(marketing)/about").unwrap();
        assert!(r.match_path("/about").is_some());
        assert!(r.match_path("/marketing/about").is_none());
    }

    #[test]
    fn a_catch_all_must_be_last() {
        assert!(parse_pattern("/docs/[...slug]/edit").is_err());
        assert!(parse_pattern("/docs/[[...slug]]/edit").is_err());
    }

    #[test]
    fn duplicate_parameter_names_are_refused() {
        assert!(parse_pattern("/a/[id]/b/[id]").is_err());
    }

    #[test]
    fn a_pattern_must_be_absolute() {
        assert!(parse_pattern("drops/[id]").is_err());
    }

    #[test]
    fn malformed_dynamic_segments_are_refused() {
        assert!(parse_pattern("/a/[id").is_err());
        assert!(parse_pattern("/a/id]").is_err());
        assert!(parse_pattern("/a/[]").is_err());
    }

    #[test]
    fn a_bracket_tail_cannot_smuggle_itself_into_a_parameter_name() {
        // Stripping is a prefix/suffix match, so `[...id]]` would otherwise
        // parse to a parameter literally named `id]`. Nothing downstream
        // rejects that: the route matches, the parameter binds, and `id]`
        // travels into the generated TypeScript as an object key. The author
        // sees a parameter almost like the one they wrote, and the mismatch
        // surfaces far from its cause.
        for hostile in [
            "/blog/[...id]]",
            "/blog/[[...id]]]",
            "/blog/[id]]",
            "/blog/[[id]]",
        ] {
            assert!(parse_pattern(hostile).is_err(), "'{hostile}' was accepted");
        }
        // …and the well-formed spellings still parse.
        assert!(parse_pattern("/blog/[id]").is_ok());
        assert!(parse_pattern("/blog/[...id]").is_ok());
        assert!(parse_pattern("/blog/[[...id]]").is_ok());
    }

    #[test]
    fn extra_periods_do_not_become_part_of_a_parameter_name() {
        // A catch-all is exactly three dots. `[....id]` would otherwise
        // parse to a parameter named `.id`, which is a typo the author
        // cannot see in the rendered route table.
        assert!(parse_pattern("/blog/[....id]").is_err());
        assert!(parse_pattern("/blog/[..id]").is_err());
        assert!(parse_pattern("/blog/[.id]").is_err());
        assert!(parse_pattern("/blog/[...id]").is_ok());
    }

    #[test]
    fn a_parameter_name_must_survive_both_sides_of_the_contract() {
        // The name becomes a TypeScript object key and a Rust map key, so a
        // character that is legal in neither is a build error here rather
        // than a puzzle in an emitted file two toolchains later.
        for hostile in [
            "/a/[id-x]",
            "/a/[id x]",
            "/a/[id.x]",
            "/a/[id\"x]",
            "/a/[…x]",
        ] {
            assert!(parse_pattern(hostile).is_err(), "'{hostile}' was accepted");
        }
        assert!(parse_pattern("/a/[id_x]").is_ok());
        assert!(parse_pattern("/a/[id2]").is_ok());
    }

    #[test]
    fn static_routes_outrank_dynamic_ones() {
        let table = RouteTable::from_routes(vec![
            Route::page("drop", "/drops/[id]").unwrap(),
            Route::page("new", "/drops/new").unwrap(),
            Route::page("any", "/[...rest]").unwrap(),
        ]);
        match table.resolve("/drops/new", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "new"),
            other => panic!("expected the static route, got {other:?}"),
        }
        match table.resolve("/drops/42", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "drop"),
            other => panic!("expected the dynamic route, got {other:?}"),
        }
        match table.resolve("/anything/else", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "any"),
            other => panic!("expected the catch-all, got {other:?}"),
        }
    }

    #[test]
    fn a_longer_literal_prefix_wins_over_an_earlier_parameter() {
        // Both patterns hold two static and one dynamic segment, so any
        // aggregate count ties; only a left-to-right comparison gets this
        // right. '/a/b/c' must resolve to the route whose literal prefix
        // reaches further.
        let table = RouteTable::from_routes(vec![
            Route::page("early_param", "/a/[x]/c").unwrap(),
            Route::page("late_param", "/a/b/[y]").unwrap(),
        ]);
        match table.resolve("/a/b/c", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "late_param"),
            other => panic!("expected the longer literal prefix to win, got {other:?}"),
        }
        // …and each still owns the paths only it can match.
        match table.resolve("/a/z/c", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "early_param"),
            other => panic!("expected the early-parameter route, got {other:?}"),
        }
    }

    #[test]
    fn specificity_is_decided_at_the_first_differing_segment() {
        // '/a/[y]' beats '/[x]/b' for '/a/b': position 0 decides, and no
        // amount of later staticness rescues a leading parameter.
        let table = RouteTable::from_routes(vec![
            Route::page("leading_param", "/[x]/b").unwrap(),
            Route::page("leading_static", "/a/[y]").unwrap(),
        ]);
        match table.resolve("/a/b", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "leading_static"),
            other => panic!("expected the leading static segment to win, got {other:?}"),
        }
    }

    #[test]
    fn a_required_catch_all_outranks_an_optional_one() {
        let table = RouteTable::from_routes(vec![
            Route::page("optional", "/docs/[[...rest]]").unwrap(),
            Route::page("required", "/docs/[...slug]").unwrap(),
        ]);
        match table.resolve("/docs/a/b", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "required"),
            other => panic!("expected the required catch-all, got {other:?}"),
        }
        // Only the optional form matches the bare prefix.
        match table.resolve("/docs", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "optional"),
            other => panic!("expected the optional catch-all, got {other:?}"),
        }
    }

    #[test]
    fn ordering_does_not_depend_on_declaration_order() {
        let a = RouteTable::from_routes(vec![
            Route::page("new", "/drops/new").unwrap(),
            Route::page("drop", "/drops/[id]").unwrap(),
        ]);
        let b = RouteTable::from_routes(vec![
            Route::page("drop", "/drops/[id]").unwrap(),
            Route::page("new", "/drops/new").unwrap(),
        ]);
        let ids_a: Vec<&str> = a.routes().iter().map(|r| r.id.as_str()).collect();
        let ids_b: Vec<&str> = b.routes().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids_a, ids_b);
    }

    #[test]
    fn a_wrong_method_is_405_with_an_allow_set_not_404() {
        let table = RouteTable::from_routes(vec![Route::handler(
            "api_drops",
            "/api/drops",
            &["GET", "POST"],
        )
        .unwrap()]);
        match table.resolve("/api/drops", "DELETE") {
            Resolution::MethodNotAllowed { allowed } => {
                // HEAD rides with GET: the set names every method that
                // really works, including the two HTTP derives rather than
                // asks an author to declare.
                assert_eq!(allowed, vec!["GET", "HEAD", "OPTIONS", "POST"]);
            }
            other => panic!("expected 405, got {other:?}"),
        }
        assert_eq!(table.resolve("/api/nothing", "GET"), Resolution::NotFound);
    }

    #[test]
    fn a_page_answers_get_and_head() {
        let table = RouteTable::from_routes(vec![Route::page("home", "/").unwrap()]);
        assert!(matches!(
            table.resolve("/", "HEAD"),
            Resolution::Matched { .. }
        ));
        assert!(matches!(
            table.resolve("/", "POST"),
            Resolution::MethodNotAllowed { .. }
        ));
    }

    #[test]
    fn a_handler_declaring_get_also_answers_head() {
        // HTTP derives HEAD from GET rather than declaring it, so an author
        // writing `&["GET"]` has not opted out of HEAD — and a client
        // probing with HEAD must not be told the method is unsupported.
        let table = RouteTable::from_routes(vec![
            Route::handler("api_drops", "/api/drops", &["GET", "POST"]).unwrap(),
            Route::handler("api_submit", "/api/submit", &["POST"]).unwrap(),
        ]);
        assert!(matches!(
            table.resolve("/api/drops", "HEAD"),
            Resolution::Matched { .. }
        ));
        // …but a handler with no GET has nothing to derive a HEAD from, and
        // the refusal names what would work.
        match table.resolve("/api/submit", "HEAD") {
            Resolution::MethodNotAllowed { allowed } => {
                assert_eq!(allowed, vec!["OPTIONS", "POST"]);
            }
            other => panic!("expected 405, got {other:?}"),
        }
    }

    #[test]
    fn route_matching_is_case_sensitive() {
        // A path is bytes, not a case-folded name: matching `/Drops` to
        // `/drops` would make two URLs one resource, and every cache key,
        // canonical link and audit record would then disagree about which
        // one was served.
        let table = RouteTable::from_routes(vec![Route::page("drops", "/drops").unwrap()]);
        assert!(matches!(
            table.resolve("/drops", "GET"),
            Resolution::Matched { .. }
        ));
        assert_eq!(table.resolve("/Drops", "GET"), Resolution::NotFound);
        assert_eq!(table.resolve("/DROPS", "GET"), Resolution::NotFound);
    }

    #[test]
    fn a_method_is_matched_case_insensitively() {
        // HTTP methods are case-SENSITIVE on the wire, but a gateway that
        // normalises them differently must not turn a legal GET into a 405.
        // `resolve` upper-cases before comparing, so both spellings work.
        let table = RouteTable::from_routes(vec![Route::page("home", "/").unwrap()]);
        assert!(matches!(
            table.resolve("/", "get"),
            Resolution::Matched { .. }
        ));
    }

    #[test]
    fn percent_escapes_decode_in_path_segments() {
        let r = Route::page("drop", "/drops/[id]").unwrap();
        let p = r.match_path("/drops/a%20b%2Fc").expect("matches");
        // %2F decodes AFTER splitting, so it stays inside one segment.
        assert_eq!(one(&p, "id"), "a b/c");
    }

    #[test]
    fn a_plus_is_literal_in_a_path_and_a_space_in_a_query() {
        let r = Route::page("drop", "/drops/[id]").unwrap();
        assert_eq!(one(&r.match_path("/drops/a+b").unwrap(), "id"), "a+b");
        let q = query_params("/search?q=a+b&tag=x%20y");
        assert_eq!(q.get("q").map(String::as_str), Some("a b"));
        assert_eq!(q.get("tag").map(String::as_str), Some("x y"));
    }

    #[test]
    fn a_repeated_query_key_keeps_its_first_value() {
        // This function is half of a contract: the generated TypeScript
        // `loaderKey` reads the same query string with
        // `URLSearchParams.get`, which the web platform defines as the
        // FIRST occurrence. A last-wins map here would make the browser
        // seed its cache under one value while the server keyed its answer
        // on another — one URL, two identities, and a user following a link
        // with a duplicated parameter served another filter's rows.
        let q = query_params("/?project=WEB&project=API");
        assert_eq!(q.get("project").map(String::as_str), Some("WEB"));

        // The rule holds however many times the key repeats, and does not
        // disturb the other keys around it.
        let q = query_params("/?a=1&b=x&a=2&a=3&c=y");
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert_eq!(q.get("b").map(String::as_str), Some("x"));
        assert_eq!(q.get("c").map(String::as_str), Some("y"));
    }

    #[test]
    fn a_key_is_deduplicated_after_decoding_just_as_the_browser_does() {
        // `URLSearchParams` decodes a key BEFORE comparing it, so `%61`
        // and `a` are one key and `get` answers with the first value. If
        // this side deduplicated on the RAW spelling instead, a caller
        // writing `?a=1&%61=2` would be two keys here and one there — the
        // same divergence the first-wins rule exists to close, reached by
        // a different route.
        let q = query_params("/?a=1&%61=2");
        assert_eq!(q.len(), 1);
        assert_eq!(q.get("a").map(String::as_str), Some("1"));

        // …and the reverse spelling resolves identically, so which form
        // the caller wrote first cannot change the answer.
        let q = query_params("/?%61=1&a=2");
        assert_eq!(q.get("a").map(String::as_str), Some("1"));

        // A key whose two spellings differ only in how a SPACE was encoded
        // is likewise one key: `+` and `%20` both decode to a space.
        let q = query_params("/?a+b=1&a%20b=2");
        assert_eq!(q.get("a b").map(String::as_str), Some("1"));

        // Case is NOT folded, on either side: `a` and `A` stay distinct.
        let q = query_params("/?a=1&A=2");
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert_eq!(q.get("A").map(String::as_str), Some("2"));
    }

    #[test]
    fn an_encoded_separator_cannot_forge_a_path_segment() {
        // Splitting happens BEFORE decoding, so `%2F` stays inside the
        // segment it was written in. Were it decoded first, a caller could
        // write `/drops/a%2F..%2Fadmin` and have it matched as three
        // segments — traversing into a route they were never granted.
        let r = Route::page("drop", "/drops/[id]").unwrap();
        let p = r.match_path("/drops/a%2F..%2Fadmin").expect("one segment");
        assert_eq!(one(&p, "id"), "a/../admin");

        // Double encoding decodes exactly ONCE: `%252F` is the literal text
        // `%2F`, not a separator. A second pass would re-open the hole the
        // first one closed.
        let p = r.match_path("/drops/a%252Fb").expect("one segment");
        assert_eq!(one(&p, "id"), "a%2Fb");

        // A pattern expecting one segment still refuses a real separator.
        assert!(r.match_path("/drops/a/b").is_none());
    }

    #[test]
    fn query_pairs_survive_their_degenerate_spellings() {
        // Real query strings are written by hand, by templates and by
        // clients that disagree about the shape. None of these may panic or
        // silently swallow a neighbouring pair.
        let q = query_params("/?flag&empty=&=novalue&x=1");
        // A bare key is present with an empty value, which is how a caller
        // spells a boolean flag.
        assert_eq!(q.get("flag").map(String::as_str), Some(""));
        assert_eq!(q.get("empty").map(String::as_str), Some(""));
        // A pair whose value contains '=' keeps everything after the FIRST
        // one: base64 and signed tokens are full of trailing '='.
        let q = query_params("/?token=YWJj==&next=/a?b=c");
        assert_eq!(q.get("token").map(String::as_str), Some("YWJj=="));
        assert_eq!(q.get("next").map(String::as_str), Some("/a?b=c"));
        // A target with no query at all is empty rather than an error.
        assert!(query_params("/drops/42").is_empty());
        assert!(query_params("/drops/42?").is_empty());
        // A fragment is not part of the query.
        let q = query_params("/?a=1#frag=2");
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert!(q.get("frag").is_none());
    }

    #[test]
    fn an_absolute_or_protocol_relative_target_is_not_a_path() {
        // Ported from Next's `parse-relative-url`, which throws on
        // `http://example.com/abc`. Alloy's splitter would otherwise turn it
        // into `["http:", "example.com", "abc"]` and let a catch-all bind
        // `http:` as an ordinary segment.
        let table = RouteTable::from_routes(vec![
            Route::page("home", "/").unwrap(),
            Route::page("any", "/[...rest]").unwrap(),
        ]);
        for hostile in [
            "http://evil.com/x",
            "https://evil.com/x",
            "//evil.com/x",
            "javascript:alert(1)",
            "\\\\evil.com/x",
            "/\\\\evil.com/x",
        ] {
            assert_eq!(
                table.resolve(hostile, "GET"),
                Resolution::NotFound,
                "'{hostile}' was matched as a path"
            );
        }

        // …and an ordinary path with a colon in a LATER segment is still a
        // path: `/drops/a:b` is legal and must not be caught by the rule.
        assert!(is_relative_target("/drops/a:b"));
        assert!(is_relative_target("/"));
        assert!(is_relative_target("/albums/x?from=http://a.test"));
        assert!(matches!(
            table.resolve("/drops/a:b", "GET"),
            Resolution::Matched { .. }
        ));
    }

    #[test]
    fn a_relative_or_space_prefixed_target_is_not_a_path() {
        // finding_52d84d6800f3803b
        for hostile in [" https:\\\\evil.com/x", " \\\\evil.com/x", " javascript:alert(1)", "drops/42", " /x"] {
            assert!(!is_relative_target(hostile), "{hostile:?} was taken as a path");
            assert!(try_split_path(hostile).is_none() || !is_relative_target(hostile));
        }
        assert!(try_split_path("drops/42").is_none());
        assert!(try_split_path("/drops/42").is_some());
        assert!(is_relative_target(""));
    }

    #[test]
    fn a_dot_segment_parameter_is_encoded_in_a_redirect() {
        // finding_a282c7646fa11888
        assert_eq!(encode_segment(".."), "%2E%2E");
        assert_eq!(encode_segment("."), "%2E");
        assert_eq!(encode_segment("a.b"), "a.b");
    }

    #[test]
    fn a_target_holding_a_control_character_is_not_a_path() {
        for hostile in [
            "/\t/evil.com/x",
            "/\n/evil.com/x",
            "/\r\n/evil.com",
            "\t//evil.com",
            "/a\u{0}b",
            "/albums/x?next=\n//evil.com",
            "/albums/x#\t//evil.com",
            "/albums/\u{7f}",
        ] {
            assert!(!is_relative_target(hostile), "{hostile:?} was taken as a path");
        }
        for ordinary in ["/", "/albums/x", "/albums/x?q=a%09b", "/drops/a:b#top"] {
            assert!(is_relative_target(ordinary), "{ordinary:?} was refused");
        }
    }

    #[test]
    fn a_fragment_ends_the_query_even_before_the_first_question_mark() {
        // A '#' ends the query wherever it appears. Splitting on '?' first
        // reads `/p#frag?a=1` as carrying `a=1` — a parameter invented from
        // fragment text the server never receives, since a browser does not
        // transmit the fragment. The generated `loaderKey` folds declared
        // query values into a cache key, so this would let a fragment vary
        // the identity of a request that is byte-identical on the wire.
        assert!(query_params("/p#frag?a=1").is_empty());
        assert!(query_params("/p#/other?token=secret").is_empty());

        // …and a real query still parses, fragment or not.
        let q = query_params("/p?a=1#b=2");
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert!(q.get("b").is_none());
        assert_eq!(
            query_params("/p?a=1").get("a").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn a_query_string_never_participates_in_matching() {
        let table = RouteTable::from_routes(vec![Route::page("drop", "/drops/[id]").unwrap()]);
        match table.resolve("/drops/42?from=home#top", "GET") {
            Resolution::Matched { params, .. } => assert_eq!(one(&params, "id"), "42"),
            other => panic!("expected a match, got {other:?}"),
        }
    }

    #[test]
    fn an_interior_double_slash_is_refused_but_a_trailing_one_is_folded() {
        // Upstream matches each segment with `[^/]+?`, which requires at
        // least one character, so `/drops//42` matches nothing. Folding it
        // instead would make `/drops/42`, `/drops//42` and `/drops///42`
        // one resource under three URLs — the same aliasing the percent
        // rule above exists to prevent, reached by a different route.
        let table = RouteTable::from_routes(vec![Route::page("drop", "/drops/[id]").unwrap()]);
        for hostile in ["/drops//42", "/drops///42", "//drops/42", "/drops//"] {
            assert_eq!(
                table.resolve(hostile, "GET"),
                Resolution::NotFound,
                "'{hostile}' resolved instead of being refused"
            );
        }

        // A TRAILING slash is the ordinary spelling clients really send,
        // so it is folded rather than refused: there is no ambiguity about
        // what it names, and no second sender to disagree with.
        for ok in ["/drops/42", "/drops/42/"] {
            match table.resolve(ok, "GET") {
                Resolution::Matched { params, .. } => assert_eq!(one(&params, "id"), "42"),
                other => panic!("'{ok}' was refused: {other:?}"),
            }
        }

        // The root keeps working in both spellings.
        let root = RouteTable::from_routes(vec![Route::page("home", "/").unwrap()]);
        assert!(matches!(
            root.resolve("/", "GET"),
            Resolution::Matched { .. }
        ));
        assert!(matches!(
            root.resolve("", "GET"),
            Resolution::Matched { .. }
        ));

        // …and a catch-all cannot be handed an empty interior segment.
        let deep = RouteTable::from_routes(vec![Route::page("docs", "/docs/[...slug]").unwrap()]);
        assert_eq!(deep.resolve("/docs/a//b", "GET"), Resolution::NotFound);
        match deep.resolve("/docs/a/b/", "GET") {
            Resolution::Matched { params, .. } => {
                assert_eq!(many(&params, "slug"), vec!["a", "b"]);
            }
            other => panic!("a trailing slash on a catch-all was refused: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_percent_sequence_names_no_route_at_all() {
        // `from_utf8_lossy` maps EVERY invalid byte to U+FFFD, so `%ff`,
        // `%fe` and a legitimate `%ef%bf%bd` decode to the same string.
        // Three different URLs would then be one resource: same route, same
        // parameter, same cache key — so a response computed for one is
        // served for the others, and no audit record can say which arrived.
        let table = RouteTable::from_routes(vec![Route::page("drop", "/drops/[id]").unwrap()]);

        // The aliasing, demonstrated on the lossy decoder that is still
        // exported for callers who are describing a path rather than
        // resolving one.
        assert_eq!(percent_decode("%ff"), percent_decode("%fe"));
        assert_eq!(percent_decode("%ff"), percent_decode("%ef%bf%bd"));

        // …and the refusal on the routing path.
        for hostile in ["/drops/%ff", "/drops/%fe", "/drops/%c3%28"] {
            assert_eq!(
                table.resolve(hostile, "GET"),
                Resolution::NotFound,
                "'{hostile}' resolved instead of being refused"
            );
        }

        // A LEGITIMATE U+FFFD is still a perfectly good parameter: the rule
        // refuses malformed BYTES, not the replacement character itself.
        match table.resolve("/drops/%ef%bf%bd", "GET") {
            Resolution::Matched { params, .. } => {
                assert_eq!(one(&params, "id"), "\u{fffd}");
            }
            other => panic!("a valid U+FFFD must still match, got {other:?}"),
        }

        // Ordinary non-ASCII text is untouched.
        match table.resolve("/drops/caf%c3%a9", "GET") {
            Resolution::Matched { params, .. } => assert_eq!(one(&params, "id"), "café"),
            other => panic!("expected a match, got {other:?}"),
        }
    }

    #[test]
    fn a_stray_percent_is_a_spelling_question_not_an_encoding_one() {
        // `%zz` is not an escape, but the bytes are still text, so the
        // segment keeps it literally rather than 404ing. Refusing here
        // would break identifiers that legitimately contain '%'.
        let table = RouteTable::from_routes(vec![Route::page("drop", "/drops/[id]").unwrap()]);
        for (path, expected) in [("/drops/a%", "a%"), ("/drops/a%zz", "a%zz")] {
            match table.resolve(path, "GET") {
                Resolution::Matched { params, .. } => assert_eq!(one(&params, "id"), expected),
                other => panic!("'{path}' was refused: {other:?}"),
            }
        }
    }

    #[test]
    fn the_strict_decoder_agrees_with_the_lossy_one_on_valid_input() {
        // The two must not drift: wherever the input IS text, the strict
        // decoder returns exactly what the lossy one does.
        for good in [
            "",
            "a",
            "a%20b",
            "caf%c3%a9",
            "a%2Fb",
            "a+b",
            "%ef%bf%bd",
            "a%",
            "a%zz",
        ] {
            assert_eq!(
                try_percent_decode(good).as_deref(),
                Some(percent_decode(good).as_str()),
                "decoders disagree on '{good}'"
            );
        }
        // …and only where it is NOT text do they part company.
        for bad in ["%ff", "%fe", "%c3%28"] {
            assert!(try_percent_decode(bad).is_none(), "'{bad}' was accepted");
        }
    }

    #[test]
    fn malformed_percent_escapes_do_not_panic() {
        assert_eq!(percent_decode("a%"), "a%");
        assert_eq!(percent_decode("a%zz"), "a%zz");
        assert_eq!(percent_decode("%e2%28"), "\u{fffd}(");
    }

    #[test]
    fn deeply_nested_paths_match_without_recursion() {
        let r = Route::page("docs", "/docs/[...slug]").unwrap();
        let deep = format!("/docs{}", "/a".repeat(5_000));
        assert_eq!(many(&r.match_path(&deep).unwrap(), "slug").len(), 5_000);
    }

    #[test]
    fn a_declared_redirect_answers_before_any_route_is_consulted() {
        // A redirect deliberately outranks a route: shadowing a route by
        // accident is a config error alloy-check flags, so the runtime's
        // job is only to be deterministic about the order.
        let table = RouteTable::from_routes(vec![
            Route::page("old", "/old-path").unwrap(),
            Route::page("new", "/new-path").unwrap(),
        ])
        .with_redirects(vec![Redirect {
            from: "/old-path".into(),
            to: "/new-path".into(),
            permanent: true,
        }]);
        match table.resolve("/old-path", "GET") {
            Resolution::Redirect {
                location,
                permanent,
            } => {
                assert_eq!(location, "/new-path");
                assert!(permanent);
            }
            other => panic!("expected the redirect, got {other:?}"),
        }
        // …and the target route still serves normally.
        assert!(matches!(
            table.resolve("/new-path", "GET"),
            Resolution::Matched { .. }
        ));
    }

    #[test]
    fn a_redirect_substitutes_its_parameters_into_the_target() {
        let table = RouteTable::new().with_redirects(vec![
            Redirect {
                from: "/drops/[id]/old".into(),
                to: "/drops/[id]".into(),
                permanent: false,
            },
            Redirect {
                from: "/docs/[...slug]".into(),
                to: "/manual/[...slug]".into(),
                permanent: false,
            },
        ]);
        match table.resolve("/drops/42/old", "GET") {
            Resolution::Redirect {
                location,
                permanent,
            } => {
                assert_eq!(location, "/drops/42");
                assert!(!permanent, "permanent defaults to false");
            }
            other => panic!("expected a substituted redirect, got {other:?}"),
        }
        match table.resolve("/docs/a/b/c", "GET") {
            Resolution::Redirect { location, .. } => assert_eq!(location, "/manual/a/b/c"),
            other => panic!("expected the catch-all redirect, got {other:?}"),
        }
    }

    #[test]
    fn a_redirect_preserves_its_query_and_fragment_outside_the_path() {
        let table = RouteTable::new().with_redirects(vec![
            Redirect {
                from: "/old/[id]".into(),
                to: "/new/[id]?via=legacy#details".into(),
                permanent: true,
            },
            Redirect {
                from: "/for/commerce".into(),
                to: "/examples#supply".into(),
                permanent: true,
            },
        ]);

        match table.resolve("/old/a%2Fb", "GET") {
            Resolution::Redirect { location, .. } => {
                // The matched parameter is still encoded as ONE safe path
                // segment; only the declared suffix stays URL syntax.
                assert_eq!(location, "/new/a%2Fb?via=legacy#details");
            }
            other => panic!("expected a redirect with a suffix, got {other:?}"),
        }
        match table.resolve("/for/commerce", "GET") {
            Resolution::Redirect { location, .. } => {
                assert_eq!(location, "/examples#supply");
                assert!(!location.contains("%23"));
            }
            other => panic!("expected a fragment redirect, got {other:?}"),
        }
    }

    #[test]
    fn a_redirect_suffix_cannot_inject_a_response_header() {
        let table = RouteTable::from_routes(vec![Route::page("old", "/old").unwrap()])
            .with_redirects(vec![Redirect {
                from: "/old".into(),
                to: "/new?ok=1\r\nx-forged: yes".into(),
                permanent: false,
            }]);
        match table.resolve("/old", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "old"),
            other => panic!("the unsafe redirect should have been dropped, got {other:?}"),
        }
    }

    #[test]
    fn a_redirect_is_one_hop_even_when_its_target_matches_another_redirect() {
        // A chain is a config error alloy-check flags; the runtime's part of
        // the contract is that the answer for one request is exactly one
        // hop. This also holds for a CYCLE (a → b → a): each request costs
        // the client one round trip, and resolve itself always terminates.
        let table = RouteTable::new().with_redirects(vec![
            Redirect {
                from: "/a".into(),
                to: "/b".into(),
                permanent: false,
            },
            Redirect {
                from: "/b".into(),
                to: "/a".into(),
                permanent: false,
            },
        ]);
        match table.resolve("/a", "GET") {
            Resolution::Redirect { location, .. } => assert_eq!(location, "/b"),
            other => panic!("expected one hop, got {other:?}"),
        }
        match table.resolve("/b", "GET") {
            Resolution::Redirect { location, .. } => assert_eq!(location, "/a"),
            other => panic!("expected one hop, got {other:?}"),
        }
    }

    #[test]
    fn a_substituted_parameter_cannot_forge_extra_path_segments() {
        // The matched value is DECODED text, so `/old/a%2F..%2Fadmin` binds
        // `a/../admin` as one segment. Pasting it into the location raw
        // would emit `/new/a/../admin` — three segments and a traversal —
        // so the substitution re-encodes per segment.
        let table = RouteTable::new().with_redirects(vec![Redirect {
            from: "/old/[id]".into(),
            to: "/new/[id]".into(),
            permanent: false,
        }]);
        match table.resolve("/old/a%2F..%2Fadmin", "GET") {
            Resolution::Redirect { location, .. } => {
                assert_eq!(location, "/new/a%2F..%2Fadmin");
                assert!(!location.contains("/../"), "a traversal was forged");
            }
            other => panic!("expected a redirect, got {other:?}"),
        }
        // A malformed percent sequence still names nothing, redirects
        // included.
        assert_eq!(table.resolve("/old/%ff", "GET"), Resolution::NotFound);
        // …and an absolute target is refused before redirects are consulted.
        assert_eq!(
            table.resolve("//evil.com/old/x", "GET"),
            Resolution::NotFound
        );
    }

    #[test]
    fn a_redirect_naming_an_unbound_parameter_is_unusable_rather_than_a_hole() {
        // The generator refuses `to`-params outside the `from` set; a
        // hand-written table falls through to route matching instead of
        // emitting a location with a missing piece.
        let table = RouteTable::from_routes(vec![Route::page("old", "/old/[id]").unwrap()])
            .with_redirects(vec![Redirect {
                from: "/old/[id]".into(),
                to: "/new/[other]".into(),
                permanent: false,
            }]);
        match table.resolve("/old/42", "GET") {
            Resolution::Matched { route, .. } => assert_eq!(route.id, "old"),
            other => panic!("expected the route, got {other:?}"),
        }
        // A malformed pattern is dropped at construction, not kept inert.
        let dropped = RouteTable::new().with_redirects(vec![Redirect {
            from: "not-absolute".into(),
            to: "/x".into(),
            permanent: false,
        }]);
        assert_eq!(
            dropped.resolve("/not-absolute", "GET"),
            Resolution::NotFound
        );
    }

    #[test]
    fn route_headers_are_stored_lowercased_and_last_wins() {
        let r = Route::page("home", "/").unwrap().with_headers(&[
            ("X-Frame-Options", "SAMEORIGIN"),
            ("referrer-policy", "same-origin"),
            ("x-frame-options", "DENY"),
        ]);
        assert_eq!(
            r.headers(),
            &[
                ("referrer-policy".to_string(), "same-origin".to_string()),
                ("x-frame-options".to_string(), "DENY".to_string()),
            ]
        );
    }

    #[test]
    fn a_hostile_route_header_never_reaches_the_reply_table() {
        // A value carrying CR/LF is the response-splitting payload; a
        // gateway-owned name takes the whole reply down with a 502. Both
        // are dropped at declaration, the one place every route passes.
        let r = Route::page("home", "/").unwrap().with_headers(&[
            ("x-safe", "ok"),
            ("x-split", "a\r\nset-cookie: session=forged"),
            ("content-length", "0"),
            ("transfer-encoding", "chunked"),
            ("bad name", "v"),
            ("", "v"),
        ]);
        assert_eq!(r.headers(), &[("x-safe".to_string(), "ok".to_string())]);
    }
}
