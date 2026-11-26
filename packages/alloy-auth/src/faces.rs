//! The password sign-in routes of an app whose users live in its `data` store
//! and that may carry [published demo accounts](crate::alloy_auth::demo):
//! `POST /__auth/login`, `POST /__auth/logout` and `GET /__auth/me`.

use ferrite_app::{serde_json, AppContext, IngressReply, IngressRequest};

use crate::alloy::app::{check_unsafe_request_origin, json_reply, AlloyApp};
use crate::alloy::error::{AlloyError, Result};
use crate::alloy_auth::demo::{
    demo_accounts_enabled, is_published_demo_credential, still_published_demo_account, DemoAccount,
};
use crate::alloy_auth::session::{
    check_csrf, clear_cookies, csrf_cookie, login_cookies, with_csrf, Session, SessionStore,
};
use crate::alloy_auth::user::UserStore;

/// The session a request's cookies carry, if any. A session of a demo account
/// that should have been retired is no session (see
/// [`still_published_demo_account`]).
pub async fn resolve_session(
    ctx: &AppContext,
    req: &IngressRequest,
    accounts: &[DemoAccount],
) -> Result<Option<Session>> {
    let mut sessions = SessionStore::new(ctx.store("data")?);
    let mut users = UserStore::new(ctx.store("data")?);
    let Some(session) = sessions.resolve(&mut users, &req.headers, ctx.now_ms()).await? else {
        return Ok(None);
    };
    if still_published_demo_account(ctx, accounts, &session.actor.id).await? {
        return Ok(None);
    }
    Ok(Some(session))
}

/// `POST /__auth/login`: refuse a cross-origin request and a body that declares
/// itself as anything but JSON, then [`open_session`].
pub async fn login<A: AlloyApp + ?Sized>(
    ctx: &AppContext,
    req: &IngressRequest,
    accounts: &[DemoAccount],
) -> Result<IngressReply> {
    require_post(req, "log in with POST")?;
    check_unsafe_request_origin::<A>(req)?;
    let content_type = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    if let Some(content_type) = content_type {
        let media = content_type.split(';').next().unwrap_or("").trim();
        if !media.eq_ignore_ascii_case("application/json") {
            return Err(AlloyError::bad_request(
                "a login body is JSON: send content-type: application/json",
            ));
        }
    }
    open_session(ctx, req, accounts).await
}

/// Parse `{id, password}`, verify it, and answer with the session cookie and,
/// in the body, the session's CSRF token.
pub async fn open_session(
    ctx: &AppContext,
    req: &IngressRequest,
    accounts: &[DemoAccount],
) -> Result<IngressReply> {
    #[derive(ferrite_app::serde::Deserialize)]
    #[serde(crate = "ferrite_app::serde")]
    struct Credentials {
        id: String,
        password: String,
    }
    let creds: Credentials = serde_json::from_slice(&req.body)
        .map_err(|_| AlloyError::bad_request("a login needs an id and a password"))?;
    // While the demo accounts are off, a published credential never opens a
    // session, even if the boot-time cleanup could not remove its account:
    // the shell logs a failed seed and keeps serving.
    if !demo_accounts_enabled(ctx) && is_published_demo_credential(accounts, &creds.id, &creds.password) {
        return Err(AlloyError::Unauthorized);
    }

    let mut sessions = SessionStore::new(ctx.store("data")?);
    let mut users = UserStore::new(ctx.store("data")?);
    let (token, session) = sessions
        .login(&mut users, &creds.id, &creds.password, ctx.now_ms())
        .await?;

    let mut reply = json_reply(
        req,
        200,
        // The CSRF token travels in the body: the gateway relays one
        // `set-cookie` per reply, and that one is the session.
        &with_csrf(
            serde_json::json!({
                "id": session.actor.id,
                "name": session.actor.name,
                "role": session.actor.role,
            }),
            &session,
        ),
    );
    reply.headers.push(("cache-control".into(), "no-store".into()));
    for cookie in login_cookies(&token)? {
        reply.headers.push(("set-cookie".into(), cookie));
    }
    Ok(reply)
}

/// `POST /__auth/logout`. Logging someone out is a state change, so it carries
/// the same origin check and CSRF proof every other mutation does.
pub async fn logout<A: AlloyApp + ?Sized>(
    ctx: &AppContext,
    req: &IngressRequest,
    accounts: &[DemoAccount],
) -> Result<IngressReply> {
    require_post(req, "log out with POST")?;
    check_unsafe_request_origin::<A>(req)?;
    let session = resolve_session(ctx, req, accounts).await?.ok_or(AlloyError::Unauthorized)?;
    check_csrf(&session, &req.headers)?;
    close_session(ctx, req).await
}

/// Delete the request's session and answer with its cookies cleared. The
/// caller has already checked the origin and the CSRF proof.
pub async fn close_session(ctx: &AppContext, req: &IngressRequest) -> Result<IngressReply> {
    let mut sessions = SessionStore::new(ctx.store("data")?);
    sessions.logout(&req.headers).await?;
    let mut reply = json_reply(req, 200, &serde_json::json!({ "ok": true }));
    for cookie in clear_cookies()? {
        reply.headers.push(("set-cookie".into(), cookie));
    }
    Ok(reply)
}

/// `GET /__auth/me`. Anonymous is a normal state for a page load, so an ABSENT
/// session is reported as `id: null`. A store failure is NOT anonymity:
/// reporting it as "logged out" would make a data-plane outage look like an
/// expired session, and the client would show a login form for a backend that
/// is simply down. Only the absent case is flattened.
pub async fn whoami(
    ctx: &AppContext,
    req: &IngressRequest,
    accounts: &[DemoAccount],
) -> Result<IngressReply> {
    match resolve_session(ctx, req, accounts).await? {
        // A reloaded page recovers its CSRF token here. The body carries it;
        // the cookie keeps a client generated before the body field working,
        // and this reply sets no other cookie for it to displace.
        Some(session) => {
            let mut reply = json_reply(
                req,
                200,
                &with_csrf(
                    serde_json::json!({
                        "id": session.actor.id,
                        "name": session.actor.name,
                        "role": session.actor.role,
                        "can_write": session.actor.require_writer().is_ok(),
                    }),
                    &session,
                ),
            );
            reply.headers.extend([
                ("cache-control".into(), "no-store".into()),
                ("set-cookie".into(), csrf_cookie(&session.csrf)?),
            ]);
            Ok(reply)
        }
        None => {
            // Signed out is still a per-browser answer: no cache may keep it.
            let mut reply = json_reply(
                req,
                200,
                &serde_json::json!({ "id": null, "demo_accounts": demo_accounts_enabled(ctx) }),
            );
            reply.headers.push(("cache-control".into(), "no-store".into()));
            Ok(reply)
        }
    }
}

/// Refuse any method but POST with `message`.
pub fn require_post(req: &IngressRequest, message: &str) -> Result<()> {
    if req.method != "POST" {
        return Err(AlloyError::bad_request(message));
    }
    Ok(())
}
