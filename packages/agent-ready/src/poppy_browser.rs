//! Poppy 1.0 Browser Join (§6) and Browser Control v1 extension helpers.
//!
//! Implements the 3-step CSRF-safe Browser Join handshake:
//! 1. `GET /poppy/browser-session` — returns an uncacheable, unframeable HTML form
//!    with a single-use hidden `code` bound to a short-lived `HttpOnly; SameSite=Strict`
//!    cookie (`__Host-poppy_session=j.<nonce>`).
//! 2. `POST /poppy/browser-session/authorize` — Personal Agent authorizes `code`
//!    with its verified `Poppy-Session` header and optional OAuth access token
//!    (requiring `poppy:browser-sign-in` when signed in).
//! 3. `POST /poppy/browser-session` — browser submits the form with its cookie;
//!    `code` is consumed on the first submission regardless of outcome, the cookie
//!    is replaced in-place with `s.<browser_sid>` (compatible with gateways that
//!    relay a single `Set-Cookie` header), and the browser redirects `303 See Other`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ferrite_app::crypto::{base64url_encode, ct_eq, hmac_sha256, sha256, Ed25519SigningKey};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Value};

use crate::agent_ready::poppy::{PoppyError, SCOPE_BROWSER_SIGN_IN};
use crate::agent_ready::poppy_verify::VerifiedSession;
use crate::agent_ready::query;

/// HTML attribute name for the `browser-control` v1 extension.
pub const DATA_POPPY_USER_STEP: &str = "data-poppy-user-step";
/// Attribute value: User must interact with and submit this control/form (`browser-control` §4).
pub const STEP_INTERACTION: &str = "interaction";
/// Attribute value: Agent may fill fields, but User must submit the form (`browser-control` §4).
pub const STEP_SUBMISSION: &str = "submission";

/// Default Browser Join cookie name (`__Host-` prefix prevents subdomain injection, §6).
pub const COOKIE_NAME_PROD: &str = "__Host-poppy_session";
/// Local HTTP development cookie name (when running on plain-HTTP loopback/test only).
pub const COOKIE_NAME_DEV: &str = "poppy_session_dev";

/// Browser join code lifetime (Poppy Guides: 60 seconds).
pub const JOIN_CODE_TTL_SECS: u64 = 60;

/// Stored one-time browser-join transaction (§6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct JoinCodeRecord {
    pub code: String,
    pub cookie_nonce_sha256: String,
    pub expires_at_ms: u64,
    pub authorized: Option<AuthorizedJoin>,
    pub submitted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AuthorizedJoin {
    pub client_id: String,
    pub sid: String,
    pub sub: String,
    pub account_id: Option<String>,
    pub scopes: Vec<String>,
    pub extensions: BTreeMap<String, String>,
}

/// Active browser session record created in Step 3 (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct BrowserSessionRecord {
    pub browser_sid: String,
    pub client_id: String,
    pub sid: String,
    pub sub: String,
    /// `Some(acct)` when joined with an access token; `None` when joined signed out.
    pub account_id: Option<String>,
    pub scopes: Vec<String>,
    pub extensions: BTreeMap<String, String>,
    /// True when this browser session was joined signed in — per §6 truth table,
    /// a signed-in join permanently supersedes any prior browser login cookie even
    /// after the Poppy session later ends or signs out.
    pub supersedes_browser_login: bool,
    pub active: bool,
    pub expires_at_ms: u64,
}

/// Effective browser authentication resolution per Poppy §6 truth table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAuthResolution {
    /// Browser is NOT joined to a Poppy Session; use ordinary browser login cookie if any.
    NotJoined,
    /// Joined signed out: keep any existing browser login cookie untouched (§6 row 1 & 3).
    JoinedSignedOut { session: BrowserSessionRecord },
    /// Joined signed in to `account_id` with `scopes`: overrides any prior browser login (§6 row 2 & 4).
    JoinedSignedIn { session: BrowserSessionRecord },
    /// Previously joined signed in, now ended/revoked: browser MUST act signed out
    /// (earlier login does NOT come back, §6 row 2 & 4).
    SignedInEnded,
}

/// Persistence contract for Browser Join codes and active browser sessions.
pub trait BrowserJoinStore {
    fn put_code(&self, rec: JoinCodeRecord);
    fn get_code(&self, code: &str) -> Option<JoinCodeRecord>;
    /// Atomically authorize an unauthorized, unsubmitted, unexpired code.
    fn authorize_code(&self, code: &str, auth: AuthorizedJoin, now_ms: u64) -> bool;
    /// Atomically mark a code submitted on the FIRST submission regardless of outcome (§6 step 3).
    /// Returns the record as it existed immediately before marking `submitted = true`,
    /// or `None` if unknown or already submitted.
    fn consume_code(&self, code: &str) -> Option<JoinCodeRecord>;
    fn put_browser_session(&self, sess: BrowserSessionRecord);
    fn get_browser_session(&self, browser_sid: &str) -> Option<BrowserSessionRecord>;
    fn end_browser_sessions_for_account(&self, client_id: &str, account_id: &str);
}

#[derive(Default)]
pub struct MemoryBrowserJoinStore {
    inner: Mutex<MemoryBrowserState>,
}

#[derive(Default)]
struct MemoryBrowserState {
    codes: BTreeMap<String, JoinCodeRecord>,
    sessions: BTreeMap<String, BrowserSessionRecord>,
}

impl BrowserJoinStore for MemoryBrowserJoinStore {
    fn put_code(&self, rec: JoinCodeRecord) {
        if let Ok(mut g) = self.inner.lock() {
            g.codes.insert(rec.code.clone(), rec);
        }
    }

    fn get_code(&self, code: &str) -> Option<JoinCodeRecord> {
        self.inner.lock().ok()?.codes.get(code).cloned()
    }

    fn authorize_code(&self, code: &str, auth: AuthorizedJoin, now_ms: u64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(rec) = g.codes.get_mut(code) else {
            return false;
        };
        if rec.submitted || rec.authorized.is_some() || now_ms >= rec.expires_at_ms {
            return false;
        }
        rec.authorized = Some(auth);
        true
    }

    fn consume_code(&self, code: &str) -> Option<JoinCodeRecord> {
        let mut g = self.inner.lock().ok()?;
        let rec = g.codes.get_mut(code)?;
        if rec.submitted {
            return None;
        }
        rec.submitted = true;
        Some(rec.clone())
    }

    fn put_browser_session(&self, sess: BrowserSessionRecord) {
        if let Ok(mut g) = self.inner.lock() {
            g.sessions.insert(sess.browser_sid.clone(), sess);
        }
    }

    fn get_browser_session(&self, browser_sid: &str) -> Option<BrowserSessionRecord> {
        self.inner.lock().ok()?.sessions.get(browser_sid).cloned()
    }

    fn end_browser_sessions_for_account(&self, client_id: &str, account_id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            for s in g.sessions.values_mut() {
                if s.client_id == client_id && s.account_id.as_deref() == Some(account_id) {
                    s.active = false;
                }
            }
        }
    }
}

/// HTTP reply produced by Browser Join handlers.
#[derive(Debug, Clone)]
pub struct BrowserJoinReply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

/// Build an active telemetry event (`X-Ferrite-Agent-Event`) for a Poppy Browser event.
pub fn telemetry_event(
    event: &str,
    agent: Option<&str>,
) -> crate::agent_ready::telemetry::AgentEvent {
    crate::agent_ready::telemetry::AgentEvent::poppy_browser(event, agent)
}

/// Convenience helper returning `(AGENT_EVENT_HEADER, value)` for host apps.
pub fn telemetry_header(event: &str, agent: Option<&str>) -> (String, String) {
    telemetry_event(event, agent).to_header()
}

/// Step 1 (`GET /poppy/browser-session`): mint a single-use code + join cookie (§6 step 1).
pub fn handle_get_page<S: BrowserJoinStore>(
    endpoint_path: &str,
    secure_cookie: bool,
    store: &S,
    now_ms: u64,
) -> BrowserJoinReply {
    let code_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-agent-ready/poppy-browser-code/v1")
    };
    let nonce_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-agent-ready/poppy-browser-nonce/v1")
    };
    let code = format!("bc_{}", base64url_encode(&code_bytes[..24]));
    let nonce = base64url_encode(&nonce_bytes[..24]);
    let nonce_hash = base64url_encode(&sha256(nonce.as_bytes()));

    store.put_code(JoinCodeRecord {
        code: code.clone(),
        cookie_nonce_sha256: nonce_hash,
        expires_at_ms: now_ms.saturating_add(JOIN_CODE_TTL_SECS * 1000),
        authorized: None,
        submitted: false,
    });

    let cookie_name = if secure_cookie {
        COOKIE_NAME_PROD
    } else {
        COOKIE_NAME_DEV
    };
    let secure_attr = if secure_cookie { "; Secure" } else { "" };
    let set_cookie = format!(
        "{cookie_name}=j.{nonce}; Path=/; Max-Age={JOIN_CODE_TTL_SECS}{secure_attr}; HttpOnly; SameSite=Strict"
    );

    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Connecting</title></head>\
        <body><form method=\"post\" action=\"{endpoint_path}\">\
        <input type=\"hidden\" name=\"code\" value=\"{code}\">\
        <button type=\"submit\">Continue</button>\
        </form></body></html>\n"
    );

    BrowserJoinReply {
        status: 200,
        content_type: "text/html; charset=utf-8",
        body: html.into_bytes(),
        headers: vec![
            ("cache-control", "no-store".into()),
            ("content-security-policy", "frame-ancestors 'none'".into()),
            ("cross-origin-opener-policy", "same-origin".into()),
            ("set-cookie", set_cookie),
            telemetry_event("join_page", None).to_static_header(),
        ],
    }
}

/// Step 2 (`POST /poppy/browser-session/authorize`): Personal Agent authorizes the code (§6 step 2).
pub fn handle_authorize<S: BrowserJoinStore>(
    session: &VerifiedSession,
    body: &[u8],
    store: &S,
    now_ms: u64,
) -> Result<BrowserJoinReply, PoppyError> {
    // §6: Signed-in join MUST hold `poppy:browser-sign-in` scope.
    if session.is_signed_in() && !session.has_scope(SCOPE_BROWSER_SIGN_IN) {
        return Err(PoppyError::insufficient_scope(
            &[SCOPE_BROWSER_SIGN_IN.to_string()],
            None,
        ));
    }

    let doc: Value = serde_json::from_slice(body)
        .map_err(|_| PoppyError::invalid_request("authorize body must be JSON"))?;
    let code = doc
        .get("code")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| PoppyError::invalid_request("missing or invalid code"))?;

    let auth = AuthorizedJoin {
        client_id: session.client_id.clone(),
        sid: session.sid.clone(),
        sub: session.sub.clone(),
        account_id: session.account_id.clone(),
        scopes: session.scopes.clone(),
        extensions: session.extensions.clone(),
    };
    if !store.authorize_code(code, auth, now_ms) {
        return Err(PoppyError::invalid_request(
            "code is unknown, expired, or already authorized",
        ));
    }

    Ok(BrowserJoinReply {
        status: 204,
        content_type: "application/json",
        body: Vec::new(),
        headers: vec![
            ("cache-control", "no-store".into()),
            telemetry_event("authorize", Some(&session.client_id)).to_static_header(),
        ],
    })
}

/// Step 3 (`POST /poppy/browser-session`): Browser submits the form and receives the Session cookie (§6 step 3).
pub fn handle_submit_form<S: BrowserJoinStore>(
    cookie_header: Option<&str>,
    body: &[u8],
    secure_cookie: bool,
    session_ttl_secs: u64,
    landing_path: &str,
    store: &S,
    now_ms: u64,
) -> BrowserJoinReply {
    let err_reply = |msg: &str| BrowserJoinReply {
        status: 400,
        content_type: "text/html; charset=utf-8",
        body: format!(
            "<!doctype html><title>Session join failed</title><p>{msg}</p>"
        )
        .into_bytes(),
        headers: vec![
            ("cache-control", "no-store".into()),
            telemetry_event("join_failed", None)
                .with_ok(false)
                .to_static_header(),
        ],
    };

    let raw_form = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return err_reply("Invalid form body."),
    };
    let Some(code) = query::param(raw_form, "code").filter(|c| !c.is_empty()) else {
        return err_reply("Missing browser-session code.");
    };

    // §6 step 3: "A code is used by the first request that submits it, whatever the result."
    let Some(rec) = store.consume_code(&code) else {
        return err_reply("Browser-session code is unknown or already used.");
    };
    if now_ms >= rec.expires_at_ms {
        return err_reply("Browser-session code expired.");
    }

    // Check cookie pairing.
    let cookie_name = if secure_cookie {
        COOKIE_NAME_PROD
    } else {
        COOKIE_NAME_DEV
    };
    let Some(cookie_val) = extract_cookie(cookie_header, cookie_name) else {
        return err_reply("Missing browser-session join cookie.");
    };
    let Some(nonce) = cookie_val.strip_prefix("j.") else {
        return err_reply("Invalid browser-session join cookie.");
    };
    let presented_hash = base64url_encode(&sha256(nonce.as_bytes()));
    if !ct_eq(presented_hash.as_bytes(), rec.cookie_nonce_sha256.as_bytes()) {
        return err_reply("Join cookie does not match code.");
    }

    let Some(auth) = rec.authorized else {
        return err_reply("Code has not been authorized by the Personal Agent.");
    };

    let sid_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-agent-ready/poppy-browser-sid/v1")
    };
    let browser_sid = base64url_encode(&sid_bytes[..24]);
    let is_signed_in = auth.account_id.is_some();
    let client_id = auth.client_id.clone();
    store.put_browser_session(BrowserSessionRecord {
        browser_sid: browser_sid.clone(),
        client_id: auth.client_id,
        sid: auth.sid,
        sub: auth.sub,
        account_id: auth.account_id,
        scopes: auth.scopes,
        extensions: auth.extensions,
        supersedes_browser_login: is_signed_in,
        active: true,
        expires_at_ms: now_ms.saturating_add(session_ttl_secs.max(300) * 1000),
    });

    let secure_attr = if secure_cookie { "; Secure" } else { "" };
    // Overwrites the join cookie in place using ONE Set-Cookie header!
    let set_cookie = format!(
        "{cookie_name}=s.{browser_sid}; Path=/; Max-Age={session_ttl_secs}{secure_attr}; HttpOnly; SameSite=Lax"
    );

    BrowserJoinReply {
        status: 303,
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
        headers: vec![
            ("cache-control", "no-store".into()),
            ("location", landing_path.to_string()),
            ("set-cookie", set_cookie),
            telemetry_event("join_complete", Some(&client_id)).to_static_header(),
        ],
    }
}

/// Resolve an incoming browser request's Poppy Session cookie per the §6 truth table.
pub fn resolve_browser_session<S: BrowserJoinStore>(
    cookie_header: Option<&str>,
    secure_cookie: bool,
    store: &S,
    now_ms: u64,
) -> BrowserAuthResolution {
    let cookie_name = if secure_cookie {
        COOKIE_NAME_PROD
    } else {
        COOKIE_NAME_DEV
    };
    let Some(val) = extract_cookie(cookie_header, cookie_name) else {
        return BrowserAuthResolution::NotJoined;
    };
    let Some(browser_sid) = val.strip_prefix("s.") else {
        return BrowserAuthResolution::NotJoined;
    };
    let Some(rec) = store.get_browser_session(browser_sid) else {
        return BrowserAuthResolution::NotJoined;
    };
    if !rec.active || now_ms >= rec.expires_at_ms {
        return if rec.supersedes_browser_login {
            BrowserAuthResolution::SignedInEnded
        } else {
            BrowserAuthResolution::NotJoined
        };
    }
    if rec.account_id.is_some() {
        BrowserAuthResolution::JoinedSignedIn { session: rec }
    } else {
        BrowserAuthResolution::JoinedSignedOut { session: rec }
    }
}

fn extract_cookie<'a>(cookie_header: Option<&'a str>, name: &str) -> Option<&'a str> {
    let raw = cookie_header?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(account: Option<&str>, scopes: &[&str]) -> VerifiedSession {
        VerifiedSession {
            protocol_version: "1.0".into(),
            extensions: BTreeMap::new(),
            client_id: "https://agent.example/agent.json".into(),
            sid: "sid_browser".into(),
            sub: "usr_browser".into(),
            agent_id: None,
            delegated_kid: "kid_b".into(),
            ath: None,
            account_id: account.map(str::to_string),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn extract_code(html: &str) -> String {
        let marker = "name=\"code\" value=\"";
        let start = html.find(marker).unwrap() + marker.len();
        let end = html[start..].find('"').unwrap();
        html[start..start + end].to_string()
    }

    #[test]
    fn three_step_browser_join_and_csrf_protections() {
        let store = MemoryBrowserJoinStore::default();
        let now = 1_790_900_000_000u64;

        // Step 1: GET page
        let page = handle_get_page("/poppy/browser-session", true, &store, now);
        assert_eq!(page.status, 200);
        assert!(page
            .headers
            .iter()
            .any(|(k, v)| *k == "content-security-policy" && v.contains("frame-ancestors 'none'")));
        assert!(page
            .headers
            .iter()
            .any(|(k, v)| *k == "cross-origin-opener-policy" && v == "same-origin"));
        let cookie_pair = page
            .headers
            .iter()
            .find(|(k, _)| *k == "set-cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(cookie_pair.starts_with("__Host-poppy_session=j."));
        let code = extract_code(std::str::from_utf8(&page.body).unwrap());

        // Step 2: Signed-in without `poppy:browser-sign-in` -> 403 insufficient_scope
        let missing_scope = sess(Some("acct_1"), &["orders:read"]);
        let err = handle_authorize(
            &missing_scope,
            format!("{{\"code\":\"{code}\"}}").as_bytes(),
            &store,
            now + 1000,
        )
        .unwrap_err();
        assert_eq!(err.status, 403);
        assert_eq!(err.error, "insufficient_scope");

        // Step 2: Signed-in WITH `poppy:browser-sign-in` -> 204
        let ok_sess = sess(Some("acct_1"), &["orders:read", SCOPE_BROWSER_SIGN_IN]);
        let auth_res = handle_authorize(
            &ok_sess,
            format!("{{\"code\":\"{code}\"}}").as_bytes(),
            &store,
            now + 2000,
        )
        .unwrap();
        assert_eq!(auth_res.status, 204);

        // Re-authorizing the same code -> 400 invalid_request
        assert_eq!(
            handle_authorize(
                &ok_sess,
                format!("{{\"code\":\"{code}\"}}").as_bytes(),
                &store,
                now + 3000,
            )
            .unwrap_err()
            .error,
            "invalid_request"
        );

        // Step 3: Submit with right cookie -> 303 and session cookie!
        let form_body = format!("code={code}");
        let joined = handle_submit_form(
            Some(&cookie_pair),
            form_body.as_bytes(),
            true,
            3600,
            "/",
            &store,
            now + 4000,
        );
        assert_eq!(joined.status, 303);
        let sess_cookie = joined
            .headers
            .iter()
            .find(|(k, _)| *k == "set-cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(sess_cookie.starts_with("__Host-poppy_session=s."));

        // Replaying the submitted code MUST fail (§6 step 3).
        let replay = handle_submit_form(
            Some(&cookie_pair),
            form_body.as_bytes(),
            true,
            3600,
            "/",
            &store,
            now + 5000,
        );
        assert_eq!(replay.status, 400);

        // Resolve active signed-in session, then end it -> SignedInEnded (prior login never returns).
        assert!(matches!(
            resolve_browser_session(Some(&sess_cookie), true, &store, now + 6000),
            BrowserAuthResolution::JoinedSignedIn { .. }
        ));
        store.end_browser_sessions_for_account("https://agent.example/agent.json", "acct_1");
        assert_eq!(
            resolve_browser_session(Some(&sess_cookie), true, &store, now + 7000),
            BrowserAuthResolution::SignedInEnded
        );
    }
}
