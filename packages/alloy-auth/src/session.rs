//! Opaque store-backed sessions and their browser cookies.

use ferrite_app::client::StoreClusterClient;
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};
use crate::alloy_auth::user::{Actor, UserStore};
use crate::http_cookies;

/// The entropy in a session token. 32 bytes is 256 bits: unguessable by
/// any offline or online search.
pub const SESSION_BYTES: usize = 32;

/// How long a session lives before storage makes it absent.
pub const SESSION_TTL_MS: u64 = 12 * 60 * 60 * 1_000;

/// The session cookie's name suffix. The rendered cookie is
/// `__Host-alloy_session`, which a browser refuses to accept unless it is
/// `Secure` and host-only — so the prefix enforces the property rather
/// than merely describing it.
pub const SESSION_COOKIE: &str = "alloy_session";

/// The script-readable CSRF cookie's name suffix.
pub const CSRF_COOKIE: &str = "alloy_csrf";

/// The full session cookie name as the browser sees it.
pub fn session_cookie_name() -> String {
    format!("{}{SESSION_COOKIE}", http_cookies::HOST_PREFIX)
}

/// The full CSRF cookie name as the browser sees it.
///
/// This is for DISPLAY and for a client that inspects `document.cookie`. Do
/// not pass it to [`http_cookies::host_cookie_value`], which takes the bare
/// SUFFIX and adds the prefix itself: handing it this value looks for
/// `__Host-__Host-alloy_csrf`, finds nothing, and returns `None` — which
/// surfaces later as an unexplained `Forbidden` rather than as an error
/// here. Pass [`CSRF_COOKIE`] to that function instead.
pub fn csrf_cookie_name() -> String {
    format!("{}{CSRF_COOKIE}", http_cookies::HOST_PREFIX)
}

/// The key a session lives under: the token's DIGEST, never the token.
///
/// Storing the token itself would mean a store dump is a list of live
/// credentials. Storing the digest means a dump is worthless: an attacker
/// would have to invert SHA-256 to produce a cookie that validates.
pub fn session_key(token: &str) -> String {
    let digest = ferrite_app::crypto::sha256(token.as_bytes());
    format!("sess/{}", crate::crypto::hex_encode(&digest))
}

/// One session, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct SessionRecord {
    /// The authenticated user id.
    pub user_id: String,
    /// The CSRF token bound to this session.
    pub csrf: String,
    /// When the session was created (epoch ms).
    pub created_at_ms: u64,
    /// When it expires (epoch ms), which is also the store TTL.
    pub expires_at_ms: u64,
    /// The [`crate::alloy_auth::user::UserRecord::epoch`] of the account
    /// instance this session was opened for. A later account created under
    /// the same id has another epoch, so the session does not resolve to it.
    #[serde(default)]
    pub user_epoch: String,
}

/// A live session and the actor it authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The authenticated actor.
    pub actor: Actor,
    /// The CSRF token this session's writes must present.
    pub csrf: String,
}

/// Sessions over an injected store handle.
pub struct SessionStore {
    store: StoreClusterClient,
}

impl SessionStore {
    /// Wrap an injected store client.
    pub fn new(store: StoreClusterClient) -> Self {
        Self { store }
    }

    /// Verify a credential and open a session.
    ///
    /// Returns the token and the CSRF value; the caller renders them as
    /// cookies with [`login_cookies`]. The credential is checked within the
    /// per-account attempt limit ([`UserStore::verify_sign_in`]), so an
    /// account whose attempts are spent is refused with
    /// [`AlloyError::TooManyRequests`] whatever password is offered.
    pub async fn login(
        &mut self,
        users: &mut UserStore,
        id: &str,
        password: &str,
        now_ms: u64,
    ) -> Result<(String, Session)> {
        let user = users.verify_sign_in_record(id, password, now_ms).await?;
        let user_epoch = user.epoch.clone();
        let actor: Actor = user.into();
        let token = crate::crypto::random_token(SESSION_BYTES)
            .map_err(|e| AlloyError::internal(e.to_string()))?;
        let csrf = crate::crypto::random_token(16)
            .map_err(|e| AlloyError::internal(e.to_string()))?;
        let expires_at_ms = now_ms.saturating_add(SESSION_TTL_MS);
        let record = SessionRecord {
            user_id: actor.id.clone(),
            csrf: csrf.clone(),
            created_at_ms: now_ms,
            expires_at_ms,
            user_epoch,
        };
        let encoded =
            serde_json::to_vec(&record).map_err(|e| AlloyError::internal(e.to_string()))?;
        // The TTL is the store's own: an expired session is ABSENT on every
        // read surface, so expiry cannot be missed by a reader and needs no
        // sweeper to enforce.
        self.store
            .put_expiring(session_key(&token).as_bytes(), &encoded, expires_at_ms)
            .await?;
        Ok((token, Session { actor, csrf }))
    }

    /// Resolve the session a request's cookies carry, if any.
    ///
    /// Answers `None` rather than an error for an absent or expired
    /// session, so a caller can distinguish "anonymous" from "broken".
    pub async fn resolve(
        &mut self,
        users: &mut UserStore,
        headers: &[(String, String)],
        now_ms: u64,
    ) -> Result<Option<Session>> {
        let Some(token) = unique_session_cookie(headers) else {
            return Ok(None);
        };
        let Some(raw) = self.store.get(session_key(token).as_bytes()).await? else {
            return Ok(None);
        };
        let Ok(record) = serde_json::from_slice::<SessionRecord>(&raw) else {
            return Ok(None);
        };
        // Storage enforces the TTL, but a clock check costs nothing and
        // closes the window between expiry and reclamation.
        if now_ms >= record.expires_at_ms {
            return Ok(None);
        }
        let Some(user) = users.get(&record.user_id).await? else {
            // The user was removed while the session lived. The session is
            // dead with it, or a deleted account keeps acting.
            return Ok(None);
        };
        if user.epoch != record.user_epoch {
            // A session opened for an earlier account under this id, which
            // was deleted and created again: it never acts as the new one.
            return Ok(None);
        }
        Ok(Some(Session {
            actor: user.into(),
            csrf: record.csrf,
        }))
    }

    /// Revoke a session, idempotently.
    pub async fn logout(&mut self, headers: &[(String, String)]) -> Result<()> {
        if let Some(token) = unique_session_cookie(headers) {
            self.store.delete(session_key(token).as_bytes()).await?;
        }
        Ok(())
    }
}

/// Extract the `__Host-alloy_session` cookie value, refusing requests that
/// present more than one occurrence of the session cookie across `cookie`
/// headers so `resolve` and `check_csrf` enforce the same non-ambiguity rule.
fn unique_session_cookie(headers: &[(String, String)]) -> Option<&str> {
    let full = session_cookie_name();
    let mut found: Option<&str> = None;
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in v.split(';') {
            let Some((name, val)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == full {
                let val = val.trim();
                if val.is_empty() || found.is_some() {
                    return None;
                }
                found = Some(val);
            }
        }
    }
    found
}

/// The JSON field a login reply and an identity (`/__auth/me`) reply carry the
/// session's CSRF token in.
pub const CSRF_BODY_FIELD: &str = "csrf";

/// The `Set-Cookie` values a successful login emits: exactly one, the session.
///
/// The gateway relays ONE `set-cookie` per reply (the first of a repeated
/// name is kept), so a login that set a session cookie and a CSRF cookie
/// together delivered the session and lost the CSRF token, and every write
/// afterwards answered 403. The session cookie is therefore the only cookie a
/// login sets, and the CSRF token travels in the reply BODY ([`with_csrf`]):
/// the login reply carries it, and so does every identity reply, which is how
/// a page that was reloaded recovers it.
///
/// The cookie is a `__Host-` cookie from `packages/http-cookies`, which
/// composes the prefix, `Path=/`, `Secure` and the absence of `Domain` in one
/// constructor and re-checks them on the rendered header. It is `HttpOnly`,
/// so script cannot read the session even if the page is compromised.
///
/// # Why a body is as sound a channel as a script-readable cookie
///
/// The token's protection never came from where it was stored: it comes from
/// the same-origin policy. A cross-site page can make the victim's browser
/// SEND a request with the victim's cookies, but it cannot READ the reply to
/// a credentialed same-origin `fetch`, exactly as it could not read the
/// victim's cookie jar. [`check_csrf`] compares the echoed header with the
/// token held in the session RECORD, so nothing about the check changes.
/// An identity reply that carries the token must not be cacheable by a shared
/// cache; [`with_csrf`]'s callers send `cache-control: no-store`.
///
/// # The header the client must echo, and the two places it can be lost
///
/// [`check_csrf`] compares the session's token against the **`x-alloy-csrf`**
/// request header, not `x-csrf-token`, and not a JSON body field. A caller
/// that sends the right token under the wrong name is refused with
/// `Forbidden`, which reads exactly like a permissions problem and is not one.
///
/// The header also has to REACH the app. A Ferrite app receives only the
/// headers its manifest forwards, so every route that accepts a mutation
/// needs `x-alloy-csrf` in its `forward_headers` beside `cookie`. Omitting
/// it produces the same `Forbidden`, from a correctly-behaving client, with
/// nothing in the app to point at.
pub fn login_cookies(token: &str) -> Result<Vec<String>> {
    let session = http_cookies::render(
        &http_cookies::host_session(SESSION_COOKIE, token)
            .map_err(AlloyError::internal)?
            .max_age_secs(SESSION_TTL_MS / 1_000),
    )
    .map_err(AlloyError::internal)?;
    Ok(vec![session])
}

/// Put the session's CSRF token into a JSON reply body, under
/// [`CSRF_BODY_FIELD`].
///
/// Call it on the login reply and on the identity reply of a signed-in caller;
/// the client keeps the value in memory and echoes it as `x-alloy-csrf`. A
/// body that is not a JSON object is returned unchanged, because there is no
/// field to add to it.
pub fn with_csrf(mut body: serde_json::Value, session: &Session) -> serde_json::Value {
    if let Some(object) = body.as_object_mut() {
        object.insert(
            CSRF_BODY_FIELD.to_string(),
            serde_json::Value::String(session.csrf.clone()),
        );
    }
    body
}

/// The script-readable CSRF cookie, for an IDENTITY reply to set on its own.
///
/// One reply carries one cookie, so this can never ride the login reply
/// beside the session. An identity reply sets no other cookie, and a client
/// generated before the body channel existed reads its token from
/// `document.cookie`; setting this there keeps such a client writing. A new
/// client should read [`CSRF_BODY_FIELD`] from the body and ignore the cookie.
pub fn csrf_cookie(csrf: &str) -> Result<String> {
    http_cookies::render(
        &http_cookies::host_session(CSRF_COOKIE, csrf)
            .map_err(AlloyError::internal)?
            .max_age_secs(SESSION_TTL_MS / 1_000)
            .script_readable(),
    )
    .map_err(AlloyError::internal)
}

/// The `Set-Cookie` values that clear a session: exactly one, the session.
///
/// A CSRF cookie left behind by [`csrf_cookie`] is inert once the session
/// record is gone, because [`check_csrf`] compares against the record and
/// never against the cookie; it expires with the lifetime it was given.
pub fn clear_cookies() -> Result<Vec<String>> {
    Ok(vec![
        http_cookies::clear_host_session(SESSION_COOKIE).map_err(AlloyError::internal)?,
    ])
}

/// Check a request's CSRF token against the session it claims, reading the
/// `x-alloy-csrf` header only.
///
/// `SameSite=Strict` already blocks the common cross-site form post, but it
/// is one browser control: this is the server-side half, and it is the one
/// that holds when a browser is old, a proxy rewrites the cookie, or the
/// request arrives from a non-browser client.
///
/// **A plain HTML form cannot set a header.** An app whose UI is a
/// server-rendered `<form>` — which is what `ferrite new alloy` scaffolds —
/// must use [`check_csrf_with_body`] instead, or every signed-in visitor is
/// refused with `Forbidden` by the app's own primary control.
pub fn check_csrf(session: &Session, headers: &[(String, String)]) -> Result<()> {
    // A DUPLICATED header is refused rather than resolved.
    //
    // `cookie_value` in the same SDK already refuses a duplicated cookie
    // name, and this has to agree with it: the two halves of the
    // double-submit check must not disagree about which value is "the"
    // value. Picking the first would mean an attacker who can append a
    // header — through a proxy that merges rather than replaces, or a
    // caller that sends two — gets to choose which one is compared, and
    // the browser's own cookie would be the one ignored.
    //
    // There is no legitimate reason to send this header twice, so the
    // ambiguity itself is the signal.
    let mut presented = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-alloy-csrf"))
        .map(|(_, v)| v.as_str());
    let Some(token) = presented.next() else {
        return Err(AlloyError::Forbidden);
    };
    if presented.next().is_some() {
        return Err(AlloyError::Forbidden);
    }
    require_session_token(session, token)
}

fn require_session_token(session: &Session, token: &str) -> Result<()> {
    if token.is_empty()
        || !crate::crypto::constant_time_eq(token.as_bytes(), session.csrf.as_bytes())
    {
        return Err(AlloyError::Forbidden);
    }
    Ok(())
}

/// The form field a server-rendered page carries its CSRF token in.
pub const CSRF_FIELD: &str = "alloy_csrf";

/// Check the CSRF token from the `x-alloy-csrf` header OR, failing that,
/// from an `alloy_csrf` field in a form-encoded body.
///
/// # Why a body field is as safe as a header
///
/// The double-submit defence rests on one property: a cross-site attacker
/// can cause a request to be SENT with the victim's cookies, but cannot READ
/// those cookies to learn what to echo. That property is about reading the
/// cookie, not about which part of the request carries the echo. A hidden
/// field the page filled in from the script-readable CSRF cookie is exactly
/// as unforgeable from another origin as a header is — which is why the
/// mainstream server frameworks accept a form field.
///
/// It exists because a header alone makes the package unusable by the very
/// UI the Alloy scaffold generates: `<form method="post">` cannot set a
/// header, so a signed-in visitor pressing the app's only button is refused.
///
/// The header is still checked first, so an existing `fetch` caller is
/// unaffected, and a duplicated field is refused for the same reason a
/// duplicated header is: whoever gets to pick which of two values is
/// compared gets to bypass the check.
pub fn check_csrf_with_body(
    session: &Session,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    if check_csrf(session, headers).is_ok() {
        return Ok(());
    }
    let Ok(text) = core::str::from_utf8(body) else {
        return Err(AlloyError::Forbidden);
    };
    let mut found: Option<String> = None;
    for pair in text.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if form_decode(key) != CSRF_FIELD {
            continue;
        }
        if found.is_some() {
            return Err(AlloyError::Forbidden);
        }
        found = Some(form_decode(value));
    }
    let Some(token) = found else {
        return Err(AlloyError::Forbidden);
    };
    require_session_token(session, &token)
}

/// Percent-decode one `application/x-www-form-urlencoded` component. `+`
/// means space in this encoding and only in it, so it is replaced first.
fn form_decode(raw: &str) -> String {
    let swapped = raw.replace('+', " ");
    let bytes = swapped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = core::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with(csrf: &str) -> Session {
        Session {
            actor: Actor {
                id: "ana".into(),
                name: "Ana".into(),
                role: "member".into(),
            },
            csrf: csrf.to_string(),
        }
    }

    #[test]
    fn a_session_key_is_the_digest_and_never_the_token() {
        let key = session_key("super-secret-token");
        assert!(key.starts_with("sess/"));
        assert!(!key.contains("super-secret-token"));
        // 5 for the prefix + 64 hex characters.
        assert_eq!(key.len(), "sess/".len() + 64);
        // Deterministic, or a returning cookie would never find its session.
        assert_eq!(key, session_key("super-secret-token"));
        assert_ne!(key, session_key("super-secret-tokeo"));
    }

    #[test]
    fn the_session_cookie_is_host_only_httponly_and_strict() {
        let cookies = login_cookies("tok").unwrap();
        let session = &cookies[0];
        assert!(session.starts_with("__Host-alloy_session=tok"));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("Secure"));
        assert!(session.contains("SameSite=Strict"));
        assert!(session.contains("Path=/"));
        // No Domain attribute: a host-only cookie cannot be widened to
        // sibling subdomains by anything downstream.
        assert!(!session.contains("Domain"));
    }

    #[test]
    fn a_login_and_a_logout_each_set_exactly_one_cookie() {
        // The gateway relays one `set-cookie` per reply. A second cookie on
        // either reply would be dropped silently, so neither may depend on one.
        assert_eq!(login_cookies("tok").unwrap().len(), 1);
        let cleared = clear_cookies().unwrap();
        assert_eq!(cleared.len(), 1);
        assert!(cleared[0].starts_with("__Host-alloy_session="), "{}", cleared[0]);
        assert!(cleared[0].contains("Max-Age=0"), "{}", cleared[0]);
    }

    #[test]
    fn the_csrf_token_reaches_the_client_in_the_reply_body() {
        let session = session_with("csrf-value");
        let body = with_csrf(serde_json::json!({ "id": "ana", "role": "member" }), &session);
        assert_eq!(body[CSRF_BODY_FIELD], "csrf-value");
        assert_eq!(body["id"], "ana", "the identity fields are kept");

        // The value the body carries is the value the check accepts.
        let echoed = vec![(
            "x-alloy-csrf".to_string(),
            body[CSRF_BODY_FIELD].as_str().unwrap().to_string(),
        )];
        assert!(check_csrf(&session, &echoed).is_ok());

        // Nothing to add a field to: returned as it came, never a panic.
        assert_eq!(with_csrf(serde_json::json!(null), &session), serde_json::json!(null));
    }

    #[test]
    fn the_csrf_cookie_is_readable_because_an_older_client_must_echo_it() {
        let csrf = csrf_cookie("csrf-value").unwrap();
        assert!(csrf.starts_with("__Host-alloy_csrf=csrf-value"));
        assert!(!csrf.contains("HttpOnly"));
        // Still Secure and host-only: readable is not the same as loose.
        assert!(csrf.contains("Secure"));
        assert!(csrf.contains("SameSite=Strict"));
    }

    #[test]
    fn a_write_without_the_matching_csrf_token_is_refused() {
        let session = session_with("the-real-token");
        let good = vec![("x-alloy-csrf".to_string(), "the-real-token".to_string())];
        assert!(check_csrf(&session, &good).is_ok());

        // Absent, empty, wrong, and prefix-of-correct must all fail. The
        // last matters: a comparison that stopped at the shorter length
        // would accept any prefix of the real token.
        assert!(check_csrf(&session, &[]).is_err());
        for hostile in ["", "the-real", "the-real-token-extra", "THE-REAL-TOKEN"] {
            let headers = vec![("x-alloy-csrf".to_string(), hostile.to_string())];
            assert!(
                check_csrf(&session, &headers).is_err(),
                "accepted '{hostile}'"
            );
        }
    }

    #[test]
    fn a_duplicated_csrf_header_is_refused_rather_than_resolved() {
        // The double-submit check compares a header against a cookie, and
        // both halves must agree about which value is "the" value.
        // `cookie_value` already refuses a duplicated cookie name, so a
        // first-wins rule here would let an attacker who can APPEND a
        // header choose which one is compared — and the browser's own
        // cookie would be the one ignored.
        let session = session_with("the-real-token");

        // Both correct: still refused, because the ambiguity is the signal
        // and there is no legitimate reason to send this header twice.
        let doubled = vec![
            ("x-alloy-csrf".to_string(), "the-real-token".to_string()),
            ("x-alloy-csrf".to_string(), "the-real-token".to_string()),
        ];
        assert!(check_csrf(&session, &doubled).is_err());

        // The attack shape: a real token followed by an injected one, and
        // the reverse. Neither ordering may be admitted.
        let smuggled = vec![
            ("x-alloy-csrf".to_string(), "the-real-token".to_string()),
            ("x-alloy-csrf".to_string(), "attacker-chosen".to_string()),
        ];
        assert!(check_csrf(&session, &smuggled).is_err());
        let reversed = vec![
            ("x-alloy-csrf".to_string(), "attacker-chosen".to_string()),
            ("x-alloy-csrf".to_string(), "the-real-token".to_string()),
        ];
        assert!(check_csrf(&session, &reversed).is_err());

        // Differing CASE is still the same header name to HTTP, so it is
        // still a duplicate rather than a way around the rule.
        let cased = vec![
            ("x-alloy-csrf".to_string(), "the-real-token".to_string()),
            ("X-Alloy-CSRF".to_string(), "attacker-chosen".to_string()),
        ];
        assert!(check_csrf(&session, &cased).is_err());

        // …and exactly one still works, so the rule costs a real client
        // nothing.
        let single = vec![("x-alloy-csrf".to_string(), "the-real-token".to_string())];
        assert!(check_csrf(&session, &single).is_ok());
    }

    #[test]
    fn the_csrf_header_name_is_matched_case_insensitively() {
        // HTTP header names are case-insensitive and the gateway normalizes
        // to lowercase, but a client sending the canonical casing must work.
        let session = session_with("t");
        let headers = vec![("X-Alloy-CSRF".to_string(), "t".to_string())];
        assert!(check_csrf(&session, &headers).is_ok());
    }

    #[test]
    fn the_session_lifetime_is_bounded() {
        // An unbounded session is a permanent credential. These are const
        // assertions, so a change that violated the bound would fail the
        // BUILD rather than wait for anyone to run this test.
        const _: () = assert!(SESSION_TTL_MS > 0);
        const _: () = assert!(SESSION_TTL_MS <= 24 * 60 * 60 * 1_000);
        const _: () = assert!(SESSION_BYTES >= 16);
    }

    #[test]
    fn duplicate_session_cookies_are_refused() {
        let single = vec![(
            "cookie".to_string(),
            "__Host-alloy_session=tok1; theme=dark".to_string(),
        )];
        assert_eq!(unique_session_cookie(&single), Some("tok1"));

        let same_header_dup = vec![(
            "cookie".to_string(),
            "__Host-alloy_session=tok1; __Host-alloy_session=tok2".to_string(),
        )];
        assert_eq!(unique_session_cookie(&same_header_dup), None);

        let multi_header_dup = vec![
            ("cookie".to_string(), "__Host-alloy_session=tok1".to_string()),
            ("Cookie".to_string(), "__Host-alloy_session=tok2".to_string()),
        ];
        assert_eq!(unique_session_cookie(&multi_header_dup), None);
    }

    /// Finding H1 of the launch review: twelve wrong passwords in a row were
    /// twelve 401s, and the right one straight afterwards opened a session,
    /// so guessing was bounded only by the route's request rate. Sign-in is
    /// now limited per account, the right password included once the
    /// attempts are spent, and the account opens again when the window ends.
    #[tokio::test]
    async fn sign_in_attempts_are_bounded_per_account_and_reopen_with_the_window() {
        use crate::alloy_auth::user::{MAX_SIGN_IN_ATTEMPTS, SIGN_IN_WINDOW_MS};
        let start = 4_000_000_000_000u64;
        let env = ferrite_app_test::TestHarness::new()
            .manual_clock(start)
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        let mut users = UserStore::new(ctx.store("data").unwrap());
        let mut sessions = SessionStore::new(ctx.store("data").unwrap());
        assert!(users.create_if_absent("ana", "Ana", "admin", "the-right-password").await.unwrap());
        assert!(users.create_if_absent("raj", "Raj", "member", "raj-own-password").await.unwrap());

        for n in 0..MAX_SIGN_IN_ATTEMPTS {
            let wrong = sessions.login(&mut users, "ana", "a-wrong-guess", env.now_ms()).await;
            assert_eq!(wrong.err(), Some(AlloyError::Unauthorized), "attempt {n}");
        }
        let over = sessions.login(&mut users, "ana", "a-wrong-guess", env.now_ms()).await;
        assert!(matches!(over, Err(AlloyError::TooManyRequests { .. })), "{over:?}");
        // The right password is refused too: otherwise the limit only slows
        // the guesses it refuses, and the next right one still gets through.
        match sessions.login(&mut users, "ana", "the-right-password", env.now_ms()).await {
            Err(AlloyError::TooManyRequests { retry_after_secs }) => {
                assert!((1..=SIGN_IN_WINDOW_MS / 1_000).contains(&retry_after_secs), "{retry_after_secs}");
            }
            other => panic!("a spent account signed in: {other:?}"),
        }
        // Another account is unaffected.
        assert!(sessions.login(&mut users, "raj", "raj-own-password", env.now_ms()).await.is_ok());

        env.advance(SIGN_IN_WINDOW_MS);
        let (_, session) = sessions
            .login(&mut users, "ana", "the-right-password", env.now_ms())
            .await
            .expect("the account opens again when the window ends");
        assert_eq!(session.actor.id, "ana");
    }

    /// A success clears the count, and an unknown id is counted exactly like
    /// a known one, so the limit is no account-enumeration oracle.
    #[tokio::test]
    async fn a_success_clears_the_count_and_an_unknown_id_is_limited_alike() {
        use crate::alloy_auth::user::MAX_SIGN_IN_ATTEMPTS;
        let env = ferrite_app_test::TestHarness::new()
            .manual_clock(4_000_000_000_000)
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        let mut users = UserStore::new(ctx.store("data").unwrap());
        let mut sessions = SessionStore::new(ctx.store("data").unwrap());
        assert!(users.create_if_absent("ana", "Ana", "admin", "the-right-password").await.unwrap());

        for _ in 1..MAX_SIGN_IN_ATTEMPTS {
            assert!(sessions.login(&mut users, "ana", "a-wrong-guess", env.now_ms()).await.is_err());
        }
        assert!(sessions.login(&mut users, "ana", "the-right-password", env.now_ms()).await.is_ok());
        for n in 0..MAX_SIGN_IN_ATTEMPTS {
            let wrong = sessions.login(&mut users, "ana", "a-wrong-guess", env.now_ms()).await;
            assert_eq!(wrong.err(), Some(AlloyError::Unauthorized), "attempt {n} after a success");
        }

        for _ in 0..MAX_SIGN_IN_ATTEMPTS {
            let wrong = sessions.login(&mut users, "nobody", "a-wrong-guess", env.now_ms()).await;
            assert_eq!(wrong.err(), Some(AlloyError::Unauthorized));
        }
        let over = sessions.login(&mut users, "nobody", "a-wrong-guess", env.now_ms()).await;
        assert!(matches!(over, Err(AlloyError::TooManyRequests { .. })), "an unknown id was not limited: {over:?}");
    }

    /// A session ends with its account and never acts as a later account
    /// created under the same id (audit finding
    /// `packages/alloy-auth/src/session.rs:resolve:session-survives-account-deletion-and-recreation`).
    /// The session record carried only the id, so once the id was taken
    /// again inside the session's lifetime the old token resolved to the new
    /// account.
    #[tokio::test]
    async fn a_session_does_not_survive_its_account_being_deleted_and_created_again() {
        let env = ferrite_app_test::TestHarness::new()
            .manual_clock(4_000_000_000_000)
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        let mut users = UserStore::new(ctx.store("data").unwrap());
        let mut sessions = SessionStore::new(ctx.store("data").unwrap());
        let mut store = ctx.store("data").unwrap();
        assert!(users.create_if_absent("acme:v@x.test", "First", "member", "first-holder-pass").await.unwrap());
        let (token, _) = sessions.login(&mut users, "acme:v@x.test", "first-holder-pass", env.now_ms()).await.unwrap();
        let cookie = vec![("cookie".to_string(), format!("{}={token}", session_cookie_name()))];
        assert!(sessions.resolve(&mut users, &cookie, env.now_ms()).await.unwrap().is_some());

        store.delete(crate::alloy_auth::user::user_key("acme:v@x.test").as_bytes()).await.unwrap();
        assert!(sessions.resolve(&mut users, &cookie, env.now_ms()).await.unwrap().is_none());
        assert!(users.create_if_absent("acme:v@x.test", "Second", "member", "second-holder-pass").await.unwrap());
        env.advance(60_000);
        assert!(
            sessions.resolve(&mut users, &cookie, env.now_ms()).await.unwrap().is_none(),
            "a session of the deleted account resolved to the account created after it"
        );
        let (fresh, _) = sessions.login(&mut users, "acme:v@x.test", "second-holder-pass", env.now_ms()).await.unwrap();
        let cookie = vec![("cookie".to_string(), format!("{}={fresh}", session_cookie_name()))];
        let session = sessions.resolve(&mut users, &cookie, env.now_ms()).await.unwrap().expect("the new account's own session");
        assert_eq!(session.actor.name, "Second");
    }

    /// Records written before account epochs existed carry none on either
    /// side, and still resolve, so the change signs nobody out.
    #[tokio::test]
    async fn a_session_written_before_epochs_still_resolves_its_unchanged_account() {
        let env = ferrite_app_test::TestHarness::new()
            .manual_clock(4_000_000_000_000)
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        let mut users = UserStore::new(ctx.store("data").unwrap());
        let mut sessions = SessionStore::new(ctx.store("data").unwrap());
        let mut store = ctx.store("data").unwrap();
        let legacy_user = br#"{"id":"ana","name":"Ana","role":"member","password":"x"}"#;
        store.put(crate::alloy_auth::user::user_key("ana").as_bytes(), legacy_user).await.unwrap();
        let legacy_session = format!(
            r#"{{"user_id":"ana","csrf":"c","created_at_ms":1,"expires_at_ms":{}}}"#,
            env.now_ms() + 60_000
        );
        store.put(session_key("legacy-token").as_bytes(), legacy_session.as_bytes()).await.unwrap();
        let cookie = vec![("cookie".to_string(), format!("{}=legacy-token", session_cookie_name()))];
        assert!(sessions.resolve(&mut users, &cookie, env.now_ms()).await.unwrap().is_some());
    }
}
