//! The action token: what stops another site's page from posting to an
//! action with the reader's cookies.
//!
//! An action is reachable by an ordinary cross-site `<form method="post">`,
//! and a browser attaches this application's cookies to that post. An
//! application that signs readers in with a cookie would therefore run the
//! action with the reader's authority on a page the reader never saw. The
//! defence is the one Alloy uses: a token the application issues to each
//! browser session and requires on every action POST, carried in the request
//! BODY so it works whether or not a route forwards `Origin`.
//!
//! * The token is 32 random bytes, hex encoded, issued in the script-readable
//!   `__Host-rsx_csrf` session cookie. `__Host-` makes the browser refuse the
//!   cookie unless it is `Secure`, host-only and `Path=/`, so a sibling
//!   subdomain cannot plant one.
//! * Every action POST carries the same value in the `_rsx_csrf` body field:
//!   a hidden input the framework writes into each action form of a document
//!   it serves, or a JSON field the client runtime adds from the cookie. The
//!   two must agree, compared in constant time.
//! * A cross-site page can make the browser SEND the cookie but cannot READ it
//!   or the page that carries the token, so it cannot write the matching
//!   field. The protection comes from the same-origin policy, exactly as for
//!   Alloy's body-field token, and not from where the token is stored.
//! * An `Origin` that is present and foreign is refused as well, judged
//!   against the request's `host` when one is forwarded and otherwise by the
//!   browser's own `Sec-Fetch-Site` verdict. Where a route forwards neither,
//!   the origin cannot be judged and the token alone decides.
//!
//! The cookie is the only state: nothing is stored server side, so the check
//! costs no plane read. A route must forward `cookie` for the token to be
//! seen; the compiler's synthesized spec does.
//!
//! Under `ferrite dev` the page is served over plain HTTP, and a browser that
//! keeps `Secure` cookies only for HTTPS origins (Safari, on
//! `http://localhost`) never stores a `__Host-` cookie there, so every action
//! would be refused. `ferrite dev` says it is the server ([`LOCAL_DEV_SECRET`]),
//! and only then is the token issued and read in [`DEV_COOKIE`], which has
//! neither the prefix nor `Secure` and is host-only like any cookie without a
//! `Domain`. A deployed application cannot be told it is a local serve, and
//! never issues or reads that name.

use ferrite_app::crypto;
use ferrite_app::AppContext;

/// The cookie the token is issued in by a deployed application, as the
/// browser names it.
pub const COOKIE: &str = "__Host-rsx_csrf";

/// The cookie the token is issued in under `ferrite dev` (see [`Mode`]).
pub const DEV_COOKIE: &str = "rsx_csrf_dev";

/// The injected secret by which `ferrite dev` tells an application that it
/// is a local serve over plain HTTP, and [`LOCAL_DEV_VALUE`] its value.
///
/// The name carries a `:`. The platform admits a secret name only from
/// `[A-Za-z0-9_.-]`, refusing any other on write and dropping it again when
/// it builds an application's context, so no deployed application can hold
/// this secret, whatever its owner sets.
pub const LOCAL_DEV_SECRET: &str = "ferrite:local-dev";

/// The value `ferrite dev` gives [`LOCAL_DEV_SECRET`].
pub const LOCAL_DEV_VALUE: &str = "http";

/// Which cookie carries the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// [`COOKIE`]: `__Host-` prefixed and `Secure`. Every application that
    /// is not a `ferrite dev` serve.
    Deployed,
    /// [`DEV_COOKIE`], without the prefix or `Secure`, so a browser keeps it
    /// on a plain-HTTP origin. Only when the context carries
    /// [`LOCAL_DEV_SECRET`] with [`LOCAL_DEV_VALUE`].
    LocalDev,
}

impl Mode {
    /// The mode `ctx` was started in.
    pub fn of(ctx: &AppContext) -> Self {
        if ctx.secret(LOCAL_DEV_SECRET).as_deref() == Some(LOCAL_DEV_VALUE) {
            Mode::LocalDev
        } else {
            Mode::Deployed
        }
    }

    /// The token cookie's name in this mode. The other name is never read.
    pub fn cookie(self) -> &'static str {
        match self {
            Mode::Deployed => COOKIE,
            Mode::LocalDev => DEV_COOKIE,
        }
    }
}

/// The body field (form or JSON) an action POST carries the token in.
pub const FIELD: &str = "_rsx_csrf";

/// The framework route that answers a reader's token as JSON, issuing one
/// when the reader has none. The client runtime asks it only when the cookie
/// is missing.
pub const TOKEN_PATH: &str = "/_rsx/csrf";

/// A token's length in hex characters (32 bytes).
const TOKEN_HEX_LEN: usize = 64;

/// Why an action POST was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The request carried an `Origin` that is not this application's.
    ForeignOrigin,
    /// The request carried no token, or two, or one that does not match the
    /// cookie.
    Token,
}

impl Refusal {
    /// The client-facing message for this refusal.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::ForeignOrigin => "this action was posted from another site",
            Refusal::Token => {
                "this action did not carry this page's token; reload the page and try again"
            }
        }
    }
}

/// Mint a new token.
///
/// The SDK exports no random function and the code gate refuses every other
/// source, so the bytes come from the one route the SDK has to the operating
/// system's generator: a freshly generated signing key, keyed into an HMAC of
/// a fixed label and dropped (the `sha256-hmac` package's construction).
pub fn mint() -> String {
    const LABEL: &[u8] = b"ferrite/rsx/csrf/v1";
    let document = crypto::Ed25519SigningKey::generate_pkcs8();
    crypto::hex(&crypto::hmac_sha256(&document, LABEL))
}

/// Whether `value` has a token's shape: 64 lower-case hex characters.
pub fn is_token(value: &str) -> bool {
    value.len() == TOKEN_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The `Set-Cookie` value that issues `token` for this browser session.
///
/// Script-readable on purpose: the client runtime copies it into the JSON
/// body of an action call. `SameSite=Lax` keeps it off cross-site POSTs in
/// the browsers that honour it, and still sends it on a top-level navigation
/// from another site, so arriving from a link does not re-issue it. Only a
/// [`Mode::LocalDev`] cookie lacks `Secure`.
pub fn set_cookie(token: &str, mode: Mode) -> String {
    match mode {
        Mode::Deployed => format!("{COOKIE}={token}; Path=/; Secure; SameSite=Lax"),
        Mode::LocalDev => format!("{DEV_COOKIE}={token}; Path=/; SameSite=Lax"),
    }
}

/// What the request's cookies say about the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// No token cookie.
    None,
    /// Exactly one well-formed token cookie.
    One(String),
    /// Two token cookies, or one that is not a token. Never compared:
    /// whoever gets to choose which of two values counts gets to bypass the
    /// check.
    Ambiguous,
}

impl Held {
    /// The token, when there is exactly one well-formed one.
    pub fn token(&self) -> Option<&str> {
        match self {
            Held::One(token) => Some(token),
            _ => None,
        }
    }
}

/// Read the token cookie of `mode` from forwarded request headers.
pub fn held(headers: &[(String, String)], mode: Mode) -> Held {
    let cookie = mode.cookie();
    let mut found: Option<&str> = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.split(';') {
            let Some((key, val)) = pair.trim().split_once('=') else {
                continue;
            };
            if key.trim() != cookie {
                continue;
            }
            if found.is_some() {
                return Held::Ambiguous;
            }
            found = Some(val.trim());
        }
    }
    match found {
        None => Held::None,
        Some(token) if is_token(token) => Held::One(token.to_string()),
        Some(_) => Held::Ambiguous,
    }
}

/// Whether every cookie in a `cookie` header value is the framework's own
/// token cookie in `mode`.
///
/// The token is the same for every page a reader loads and never reaches a
/// render (it is written into a document after the render, see
/// [`inject_forms`]), so a request that carries only it is no more personal
/// than one with no cookie at all, and may share the render cache.
pub fn only_token_cookies(value: &str, mode: Mode) -> bool {
    value
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .all(|pair| pair.split_once('=').is_some_and(|(key, _)| key.trim() == mode.cookie()))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The `host[:port]` of an `Origin` value, or `None` when it is not an
/// `http(s)://authority` origin (`null`, a path, a value with userinfo).
fn origin_authority(origin: &str) -> Option<&str> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) || rest.contains(char::is_whitespace) {
        return None;
    }
    Some(rest)
}

/// Refuse a request whose `Origin` is present and foreign.
///
/// No `Origin` passes: a browser sends one on every cross-origin POST, so its
/// absence means a client that carries no reader's cookies. `Origin: null` (a
/// sandboxed frame, a `data:` URL) and any value that is not an origin are
/// foreign. A present origin is compared with the forwarded `host` when there
/// is one; the platform treats `host` as its own header and forwards it to no
/// route, so on a fleet the browser's `Sec-Fetch-Site` verdict decides
/// instead: `same-site` and `cross-site` are foreign, because an action is
/// never posted from a sibling site. Where neither is forwarded the origin
/// cannot be judged here, and the token decides.
pub fn check_origin(headers: &[(String, String)]) -> Result<(), Refusal> {
    let Some(origin) = header(headers, "origin") else {
        return Ok(());
    };
    let Some(authority) = origin_authority(origin.trim()) else {
        return Err(Refusal::ForeignOrigin);
    };
    if let Some(host) = header(headers, "host") {
        return if authority.eq_ignore_ascii_case(host.trim()) {
            Ok(())
        } else {
            Err(Refusal::ForeignOrigin)
        };
    }
    match header(headers, "sec-fetch-site").map(str::trim) {
        Some(site) if site.eq_ignore_ascii_case("same-site") || site.eq_ignore_ascii_case("cross-site") => {
            Err(Refusal::ForeignOrigin)
        }
        _ => Ok(()),
    }
}

/// Check an action POST: its origin, then its token against its cookie in
/// `mode`.
///
/// `presented` is the body field's value (`None` when absent or given more
/// than once).
pub fn check(headers: &[(String, String)], presented: Option<&str>, mode: Mode) -> Result<(), Refusal> {
    check_origin(headers)?;
    let Held::One(expected) = held(headers, mode) else {
        return Err(Refusal::Token);
    };
    match presented {
        Some(token) if is_token(token) && crypto::ct_eq(token.as_bytes(), expected.as_bytes()) => {
            Ok(())
        }
        _ => Err(Refusal::Token),
    }
}

/// Take the token field out of an action's arguments.
///
/// The handler never sees it: it is the framework's, not the action's. A
/// JSON body that is not an object cannot carry one.
pub fn take_field(args: &mut ferrite_app::serde_json::Value) -> Option<String> {
    args.as_object_mut()
        .and_then(|map| map.remove(FIELD))
        .and_then(|value| value.as_str().map(str::to_string))
}

/// The token field of a form body, or `None` when it is absent or appears
/// more than once.
pub fn form_field(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let mut found = None;
    for (name, value) in super::router::parse_query(&text) {
        if name == FIELD {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// Write the token into every action form of a document: a hidden input
/// immediately after the start tag of each `<form>` whose `action` begins
/// with the action prefix.
///
/// Returns `None` when the document has no action form. Comments and the
/// contents of `script`, `style`, `textarea` and `title` are skipped, so a
/// `<form` that is text rather than markup is never rewritten. A form whose
/// action names this application some other way (an absolute URL, an
/// encoded slash) is not recognised and carries no token, so it is refused:
/// the failure is a refused post, never a token sent somewhere else.
pub fn inject_forms(html: &str, token: &str) -> Option<String> {
    let bytes = html.as_bytes();
    let input = format!("<input type=\"hidden\" name=\"{FIELD}\" value=\"{token}\">");
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut at = 0;
    while let Some(offset) = html[at..].find('<') {
        let start = at + offset;
        let rest = &html[start..];
        if rest.starts_with("<!--") {
            at = match rest.find("-->") {
                Some(end) => start + end + 3,
                None => break,
            };
            continue;
        }
        let name_end = rest[1..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .map_or(rest.len(), |i| i + 1);
        let name = rest[1..name_end].to_ascii_lowercase();
        if name.is_empty() && !rest[1..].starts_with(['/', '!', '?']) {
            // `<` followed by anything but a letter, `/`, `!` or `?` is text,
            // not a tag: skipping to the next `>` would skip a real form.
            at = start + 1;
            continue;
        }
        let Some(tag_end) = tag_end(bytes, start + name_end) else {
            break;
        };
        if matches!(name.as_str(), "script" | "style" | "textarea" | "title") {
            // Raw text: find the matching end tag, case-insensitively.
            let close = format!("</{name}");
            let lower = html[tag_end..].to_ascii_lowercase();
            at = match lower.find(&close) {
                Some(end) => tag_end + end,
                None => break,
            };
            continue;
        }
        if name == "form" && is_action_form(&html[start + name_end..tag_end - 1]) {
            let doc = out.get_or_insert_with(|| String::with_capacity(html.len() + input.len()));
            doc.push_str(&html[copied..tag_end]);
            doc.push_str(&input);
            copied = tag_end;
        }
        at = tag_end;
    }
    let mut doc = out?;
    doc.push_str(&html[copied..]);
    Some(doc)
}

/// The index just past the `>` that ends the tag whose attributes start at
/// `from`, honouring quoted attribute values.
fn tag_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate().skip(from) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i + 1),
            None => {}
        }
    }
    None
}

/// Whether a form start tag's attribute text names an action target.
fn is_action_form(attrs: &str) -> bool {
    attr_value(attrs, "action").is_some_and(|action| action.starts_with(super::action::ACTION_PREFIX))
}

/// One attribute's raw value from a start tag's attribute text.
fn attr_value<'a>(attrs: &'a str, wanted: &str) -> Option<&'a str> {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let name = &attrs[name_start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = "";
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                let value_start = i + 1;
                let end = attrs[value_start..].find(q as char).map_or(attrs.len(), |e| value_start + e);
                value = &attrs[value_start..end];
                i = (end + 1).min(attrs.len());
            } else {
                let value_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                value = &attrs[value_start..i];
            }
        }
        if name.is_empty() {
            // A nameless `=value` already consumed its bytes above; stepping
            // again would skip the next attribute's first byte, or land
            // inside a multi-byte character and panic on the next slice.
            if i == name_start {
                i += 1;
            }
            continue;
        }
        if name.eq_ignore_ascii_case(wanted) {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_nameless_attribute_neither_panics_nor_eats_the_next_name() {
        // finding_83b9357000c622aa
        assert_eq!(attr_value(r#"="" action="/_rsx/action/save""#, "action"), Some("/_rsx/action/save"));
        assert_eq!(attr_value(r#"=""action="/_rsx/action/save""#, "action"), Some("/_rsx/action/save"));
        assert_eq!(
            attr_value(r#"=""xaction="/_rsx/action/save" action="https://example.com""#, "action"),
            Some("https://example.com")
        );
        assert_eq!(attr_value("=\"\"\u{e9} action=\"/x\"", "action"), Some("/x"));
    }

    #[test]
    fn a_minted_token_is_well_formed_and_fresh() {
        let a = mint();
        let b = mint();
        assert!(is_token(&a), "{a}");
        assert_ne!(a, b);
        assert!(!is_token(&a.to_ascii_uppercase()));
        assert!(!is_token(&a[1..]));
    }

    #[test]
    fn the_cookie_is_host_only_secure_and_script_readable() {
        let cookie = set_cookie(T, Mode::Deployed);
        assert!(cookie.starts_with(&format!("__Host-rsx_csrf={T};")));
        assert!(cookie.contains("; Path=/") && cookie.contains("; Secure") && cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain"), "a __Host- cookie is host-only");
        assert!(!cookie.contains("HttpOnly"), "the client runtime reads it");
    }

    #[test]
    fn exactly_one_well_formed_cookie_is_a_held_token() {
        assert_eq!(held(&headers(&[]), Mode::Deployed), Held::None);
        assert_eq!(held(&headers(&[("cookie", "theme=dark")]), Mode::Deployed), Held::None);
        assert_eq!(held(&headers(&[("cookie", &format!("theme=dark; {COOKIE}={T}"))]), Mode::Deployed), Held::One(T.into()));
        assert_eq!(
            held(&headers(&[("cookie", &format!("{COOKIE}={T}")), ("cookie", &format!("{COOKIE}={T}"))]), Mode::Deployed),
            Held::Ambiguous,
            "two cookies are never resolved"
        );
        assert_eq!(held(&headers(&[("cookie", &format!("{COOKIE}=short"))]), Mode::Deployed), Held::Ambiguous);
    }

    #[test]
    fn only_the_framework_cookie_keeps_a_request_shareable() {
        assert!(only_token_cookies(&format!("{COOKIE}={T}"), Mode::Deployed));
        assert!(only_token_cookies(&format!(" {COOKIE}={T} ; "), Mode::Deployed));
        assert!(!only_token_cookies(&format!("{COOKIE}={T}; session=abc"), Mode::Deployed));
        assert!(!only_token_cookies("session=abc", Mode::Deployed));
        assert!(!only_token_cookies("rsx_csrf=abc", Mode::Deployed), "only the prefixed name is the framework's");
    }

    #[test]
    fn a_matching_token_passes_and_anything_else_is_refused() {
        let cookie = format!("{COOKIE}={T}");
        let h = headers(&[("cookie", &cookie)]);
        assert_eq!(check(&h, Some(T), Mode::Deployed), Ok(()));
        let other = T.replace('0', "1");
        assert_eq!(check(&h, Some(&other), Mode::Deployed), Err(Refusal::Token));
        assert_eq!(check(&h, None, Mode::Deployed), Err(Refusal::Token));
        assert_eq!(check(&h, Some(""), Mode::Deployed), Err(Refusal::Token));
        assert_eq!(check(&headers(&[]), Some(T), Mode::Deployed), Err(Refusal::Token), "a field without its cookie");
    }

    #[test]
    fn a_present_foreign_origin_is_refused() {
        let cookie = format!("{COOKIE}={T}");
        let with = |extra: &[(&str, &str)]| {
            let mut h = headers(&[("cookie", &cookie)]);
            h.extend(headers(extra));
            check(&h, Some(T), Mode::Deployed)
        };
        assert_eq!(with(&[]), Ok(()), "no origin: the token decides");
        assert_eq!(with(&[("origin", "https://app.example"), ("host", "app.example")]), Ok(()));
        assert_eq!(with(&[("origin", "https://evil.example"), ("host", "app.example")]), Err(Refusal::ForeignOrigin));
        assert_eq!(with(&[("origin", "null")]), Err(Refusal::ForeignOrigin));
        assert_eq!(with(&[("origin", "https://user@app.example")]), Err(Refusal::ForeignOrigin));
        assert_eq!(with(&[("origin", "https://evil.example"), ("sec-fetch-site", "cross-site")]), Err(Refusal::ForeignOrigin));
        assert_eq!(with(&[("origin", "https://other.app.example"), ("sec-fetch-site", "same-site")]), Err(Refusal::ForeignOrigin));
        assert_eq!(with(&[("origin", "https://app.example"), ("sec-fetch-site", "same-origin")]), Ok(()));
        assert_eq!(
            with(&[("origin", "https://evil.example")]),
            Ok(()),
            "an origin with nothing to judge it against leaves the decision to the token"
        );
    }

    #[test]
    fn the_field_is_taken_out_of_the_arguments() {
        let mut args = ferrite_app::serde_json::json!({ "title": "x", FIELD: T });
        assert_eq!(take_field(&mut args).as_deref(), Some(T));
        assert_eq!(args, ferrite_app::serde_json::json!({ "title": "x" }));
        let mut array = ferrite_app::serde_json::json!([T]);
        assert_eq!(take_field(&mut array), None);
        assert_eq!(form_field(format!("a=1&{FIELD}={T}").as_bytes()).as_deref(), Some(T));
        assert_eq!(form_field(format!("{FIELD}={T}&{FIELD}={T}").as_bytes()), None, "twice is refused");
        assert_eq!(form_field(b"a=1"), None);
    }

    #[test]
    fn a_local_dev_serve_issues_and_reads_only_the_unprefixed_cookie() {
        // A browser keeps this cookie on http://localhost: no `__Host-`
        // prefix, no `Secure`, and host-only (no `Domain`).
        let cookie = set_cookie(T, Mode::LocalDev);
        assert_eq!(cookie, format!("{DEV_COOKIE}={T}; Path=/; SameSite=Lax"));
        assert!(!cookie.contains("__Host-") && !cookie.contains("Secure") && !cookie.contains("Domain"));

        let dev = headers(&[("cookie", &format!("{DEV_COOKIE}={T}"))]);
        let deployed = headers(&[("cookie", &format!("{COOKIE}={T}"))]);
        assert_eq!(held(&dev, Mode::LocalDev), Held::One(T.into()));
        assert_eq!(check(&dev, Some(T), Mode::LocalDev), Ok(()));
        assert!(only_token_cookies(&format!("{DEV_COOKIE}={T}"), Mode::LocalDev));
        // Each mode reads its own name and never the other's: a deployed
        // application ignores the unprefixed cookie a sibling host could
        // plant, and a local serve ignores a stale prefixed one.
        assert_eq!(held(&dev, Mode::Deployed), Held::None);
        assert_eq!(check(&dev, Some(T), Mode::Deployed), Err(Refusal::Token));
        assert!(!only_token_cookies(&format!("{DEV_COOKIE}={T}"), Mode::Deployed));
        assert_eq!(held(&deployed, Mode::LocalDev), Held::None);
        assert_eq!(check(&deployed, Some(T), Mode::LocalDev), Err(Refusal::Token));
    }

    #[test]
    fn only_the_local_dev_marker_selects_the_local_dev_cookie() {
        let ctx = |secrets: &[(&str, &str)]| {
            AppContext::new(ferrite_app::InjectionPayload {
                zone: None,
                instance: None,
                conductor_addrs: Vec::new(),
                services: Default::default(),
                edge_roots: Vec::new(),
                depends: Default::default(),
                native_replies: Default::default(),
                secrets: secrets.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            })
        };
        assert_eq!(Mode::of(&ctx(&[])), Mode::Deployed);
        assert_eq!(Mode::of(&ctx(&[(LOCAL_DEV_SECRET, LOCAL_DEV_VALUE)])), Mode::LocalDev);
        assert_eq!(Mode::of(&ctx(&[(LOCAL_DEV_SECRET, "https")])), Mode::Deployed);
        // A name an owner can set on the platform selects nothing.
        assert_eq!(Mode::of(&ctx(&[("ferrite_local_dev", LOCAL_DEV_VALUE), ("local-dev", LOCAL_DEV_VALUE)])), Mode::Deployed);
        // The platform admits secret names from [A-Za-z0-9_.-] only, so it
        // can never deliver the marker to a deployed application.
        assert!(LOCAL_DEV_SECRET
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))));
    }

    #[test]
    fn every_action_form_and_only_an_action_form_gets_the_token() {
        let html = concat!(
            "<html><head><title><form action=\"/_rsx/action/t\"></title></head><body>",
            "<form method=\"post\" action=\"/_rsx/action/save\" data-rsx-action=\"save\"><button>Save</button></form>",
            "<!-- <form action=\"/_rsx/action/c\"> -->",
            "<FORM action='/_rsx/action/remove' method=post><input name=id value=1></FORM>",
            "<form action=\"/search\"><input name=q></form>",
            "<form data-x=\"a>b\" action=/_rsx/action/bare>x</form>",
            "<script>var s = '<form action=\"/_rsx/action/s\">';</script>",
            "<p>1 < 2</p><form action=\"/_rsx/action/after-text\"></form>",
            "</body></html>"
        );
        let out = inject_forms(html, T).expect("there are action forms");
        let input = format!("<input type=\"hidden\" name=\"{FIELD}\" value=\"{T}\">");
        assert_eq!(out.matches(&input).count(), 4, "{out}");
        assert!(out.contains(&format!("after-text\">{input}</form>")), "a stray `<` in text hides no form");
        assert!(out.contains(&format!("data-rsx-action=\"save\">{input}<button>")));
        assert!(out.contains(&format!("method=post>{input}<input name=id")));
        assert!(out.contains(&format!("action=/_rsx/action/bare>{input}x")));
        assert!(out.contains("<form action=\"/search\"><input name=q>"), "an ordinary form is untouched");
        assert!(out.contains("<title><form action=\"/_rsx/action/t\"></title>"));
        assert!(out.contains("'<form action=\"/_rsx/action/s\">';</script>"));
        assert_eq!(inject_forms("<p>no forms</p><form action=\"/x\"></form>", T), None);
    }
}
