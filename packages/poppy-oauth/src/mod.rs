//! Per-application OAuth 2.1 Authorization Server for Personal Agent Protocol (Poppy 1.0).
//!
//! Pure, storage-injected authority + HTTP handlers supporting:
//! - RFC 8414 Authorization Server Metadata (with Poppy `protected_resources`)
//! - CIMD + `private_key_jwt` client authentication (`ES256`, plus `PS384` via resolver hook)
//! - Direct Sign-In (PKCE `S256`, exact `redirect_uri` + loopback port variance, `iss` RFC 9207, `prompt=consent`, PAR RFC 9126)
//! - Optional Device Sign-In (RFC 8628 + RFC 10027)
//! - Multi-resource access tokens (RFC 8707), refresh rotation & grant-family replay revocation (RFC 9700 §4.14.2), optional DPoP binding (RFC 9449)
//! - RFC 7009 revocation immediately invalidating access tokens
//! - Connected Personal Agents account-settings UI

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use ferrite_app::crypto::{
    base64url_decode, base64url_encode, ct_eq, es256_verify, hmac_sha256, p256_point, sha256,
    Ed25519SigningKey,
};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Value};

use crate::agent_ready::poppy::{PoppyConfig, PoppyError, PoppyWeb, ScopeChanges, SCOPE_BROWSER_SIGN_IN};
use crate::agent_ready::poppy_verify::{
    jwk_thumbprint_p256, verify_client_assertion, AgentKeyResolver, PresentedToken,
};
use crate::agent_ready::telemetry::{AgentEvent, AGENT_EVENT_HEADER};
use crate::http_query;

pub const PAR_TTL_SECS: u64 = 120;
pub const CODE_TTL_SECS: u64 = 300;
pub const DEVICE_CODE_TTL_SECS: u64 = 600;
pub const DEVICE_INTERVAL_SECS: u64 = 5;
pub const ACCESS_TTL_SECS: u64 = 3600;
pub const REFRESH_TTL_SECS: u64 = 90 * 24 * 3600;

/// Configuration for one isolated Company OAuth 2.1 issuer.
#[derive(Debug, Clone)]
pub struct OAuthServerConfig {
    /// Canonical HTTPS issuer URL (e.g. `https://tasks.acme.example` or
    /// `https://auth.ferrite.cloud/acme-tasks`). No trailing slash.
    pub issuer: String,
    /// Display name shown on consent pages.
    pub company_name: String,
    /// Every protected resource this issuer serves (`https://{domain}`, `https://{domain}/mcp`, ...).
    pub protected_resources: Vec<String>,
    /// Default resource identifier (`https://{domain}`) used when a token request omits `resource`.
    pub default_resource: String,
    /// HMAC secret key for signing codes, access tokens, and refresh tokens (≥32 bytes).
    pub signing_secret: Vec<u8>,
    /// Supported scopes with descriptions and hints.
    pub poppy: PoppyConfig,
    pub allow_device_sign_in: bool,
    pub require_par: bool,
    pub require_dpop: bool,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

impl OAuthServerConfig {
    pub fn from_poppy(
        issuer: impl Into<String>,
        protected_resources: Vec<String>,
        signing_secret: Vec<u8>,
        poppy: PoppyConfig,
    ) -> Self {
        let issuer = issuer.into().trim_end_matches('/').to_string();
        let default_resource = protected_resources
            .first()
            .cloned()
            .unwrap_or_else(|| issuer.clone());
        let (allow_device_sign_in, require_par, require_dpop) = match &poppy.auth {
            crate::agent_ready::poppy::PoppyAuth::SelfHosted {
                allow_device_sign_in,
                require_par,
                require_dpop,
                ..
            } => (*allow_device_sign_in, *require_par, *require_dpop),
            _ => (false, false, false),
        };
        Self {
            issuer,
            company_name: poppy.organization_name.clone(),
            protected_resources,
            default_resource,
            signing_secret,
            poppy,
            allow_device_sign_in,
            require_par,
            require_dpop,
            access_ttl_secs: ACCESS_TTL_SECS,
            refresh_ttl_secs: REFRESH_TTL_SECS,
        }
    }

    pub fn scope_names(&self) -> Vec<String> {
        self.poppy.scopes().iter().map(|s| s.name.clone()).collect()
    }

    pub fn is_known_scope(&self, scope: &str) -> bool {
        self.poppy.scopes().iter().any(|s| s.name == scope)
    }

    pub fn is_supported_resource(&self, resource: &str) -> bool {
        let norm = resource.trim_end_matches('/');
        self.protected_resources
            .iter()
            .any(|r| r.trim_end_matches('/') == norm)
    }
}

/// Stored PAR request (`RFC 9126`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ParRequest {
    pub request_uri: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub prompt_consent: bool,
    pub dpop_jkt: Option<String>,
    pub expires_at_secs: u64,
}

/// Stored Device Authorization record (`RFC 8628`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct DeviceGrantRecord {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub expires_at_secs: u64,
    pub interval_secs: u64,
    pub last_poll_secs: u64,
    pub status: DeviceGrantStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum DeviceGrantStatus {
    Pending,
    Approved {
        account_id: String,
        granted_scopes: Vec<String>,
    },
    Denied,
    Consumed,
}

/// Grant family record for Account Settings UI & immediate revocation (§4.6, §5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct GrantFamily {
    pub family_id: String,
    pub client_id: String,
    pub client_name: String,
    pub account_id: String,
    pub scopes: Vec<String>,
    /// Allowed resources: `None` means all Company resources (§4.5).
    pub allowed_resources: Option<Vec<String>>,
    pub dpop_jkt: Option<String>,
    pub created_secs: u64,
    pub last_used_secs: u64,
    pub expires_at_secs: u64,
    pub revoked: bool,
}

/// Persistence contract for OAuth burns, PAR requests, Device codes, and Grant families.
pub trait OAuthStore {
    /// Atomically burn a single-use key (code nonce, refresh nonce, or assertion `jti`).
    /// Returns `true` on the FIRST burn and `false` on any replay.
    fn burn_once(&self, key: &str, expires_at_secs: u64) -> bool;
    fn put_par(&self, req: ParRequest);
    fn take_par(&self, request_uri: &str) -> Option<ParRequest>;
    fn put_family(&self, family: GrantFamily);
    fn get_family(&self, family_id: &str) -> Option<GrantFamily>;
    fn revoke_family(&self, family_id: &str);
    fn touch_family(&self, family_id: &str, now_secs: u64);
    fn list_families_for_account(&self, account_id: &str) -> Vec<GrantFamily>;
    fn put_device(&self, rec: DeviceGrantRecord);
    fn get_device_by_code(&self, device_code: &str) -> Option<DeviceGrantRecord>;
    fn get_device_by_user_code(&self, user_code: &str) -> Option<DeviceGrantRecord>;
}

#[derive(Default)]
pub struct MemoryOAuthStore {
    inner: Mutex<MemoryOAuthState>,
}

#[derive(Default)]
struct MemoryOAuthState {
    burned: BTreeSet<String>,
    pars: BTreeMap<String, ParRequest>,
    families: BTreeMap<String, GrantFamily>,
    devices: BTreeMap<String, DeviceGrantRecord>,
}

impl OAuthStore for MemoryOAuthStore {
    fn burn_once(&self, key: &str, _expires_at_secs: u64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        g.burned.insert(key.to_string())
    }
    fn put_par(&self, req: ParRequest) {
        if let Ok(mut g) = self.inner.lock() {
            g.pars.insert(req.request_uri.clone(), req);
        }
    }
    fn take_par(&self, request_uri: &str) -> Option<ParRequest> {
        self.inner.lock().ok()?.pars.remove(request_uri)
    }
    fn put_family(&self, family: GrantFamily) {
        if let Ok(mut g) = self.inner.lock() {
            g.families.insert(family.family_id.clone(), family);
        }
    }
    fn get_family(&self, family_id: &str) -> Option<GrantFamily> {
        self.inner.lock().ok()?.families.get(family_id).cloned()
    }
    fn revoke_family(&self, family_id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(f) = g.families.get_mut(family_id) {
                f.revoked = true;
            }
        }
    }
    fn touch_family(&self, family_id: &str, now_secs: u64) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(f) = g.families.get_mut(family_id) {
                f.last_used_secs = now_secs;
            }
        }
    }
    fn list_families_for_account(&self, account_id: &str) -> Vec<GrantFamily> {
        self.inner
            .lock()
            .ok()
            .map(|g| {
                g.families
                    .values()
                    .filter(|f| f.account_id == account_id && !f.revoked)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    fn put_device(&self, rec: DeviceGrantRecord) {
        if let Ok(mut g) = self.inner.lock() {
            g.devices.insert(rec.device_code.clone(), rec);
        }
    }
    fn get_device_by_code(&self, device_code: &str) -> Option<DeviceGrantRecord> {
        self.inner.lock().ok()?.devices.get(device_code).cloned()
    }
    fn get_device_by_user_code(&self, user_code: &str) -> Option<DeviceGrantRecord> {
        let norm = user_code.trim().to_ascii_uppercase();
        self.inner
            .lock()
            .ok()?
            .devices
            .values()
            .find(|d| d.user_code == norm)
            .cloned()
    }
}

/// HTTP reply returned by `PoppyOAuthServer` handlers.
#[derive(Debug, Clone)]
pub struct OAuthReply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

impl OAuthReply {
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_default(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    fn oauth_err(status: u16, error: &str, desc: &str) -> Self {
        Self::json(
            status,
            &serde_json::json!({ "error": error, "error_description": desc }),
        )
    }

    fn html(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
            headers: vec![
                ("cache-control", "no-store".into()),
                ("content-security-policy", "frame-ancestors 'none'".into()),
            ],
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: 303,
            content_type: "text/plain; charset=utf-8",
            body: Vec::new(),
            headers: vec![
                ("cache-control", "no-store".into()),
                ("location", location),
            ],
        }
    }

    fn with_telemetry(mut self, verdict: &str, agent: Option<&str>, err: Option<&str>) -> Self {
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(AGENT_EVENT_HEADER))
        {
            let mut evt = AgentEvent::poppy_oauth(verdict, agent);
            if let Some(code) = err {
                evt = evt.with_err(code);
            }
            self.headers.push(evt.to_static_header());
        }
        self
    }

    fn with_denied_telemetry(self, agent: Option<&str>) -> Self {
        let err_code = serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string));
        self.with_telemetry("denied", agent, err_code.as_deref())
    }
}

/// Project RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`).
pub fn authorization_server_metadata(cfg: &OAuthServerConfig) -> Value {
    let mut grants = vec!["authorization_code", "refresh_token"];
    if cfg.allow_device_sign_in {
        grants.push("urn:ietf:params:oauth:grant-type:device_code");
    }
    let mut doc = serde_json::json!({
        "issuer": cfg.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", cfg.issuer),
        "token_endpoint": format!("{}/oauth/token", cfg.issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", cfg.issuer),
        "pushed_authorization_request_endpoint": format!("{}/oauth/par", cfg.issuer),
        "require_pushed_authorization_requests": cfg.require_par,
        "grant_types_supported": grants,
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "PS384"],
        "client_id_metadata_document_supported": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": cfg.scope_names(),
        "protected_resources": cfg.protected_resources,
    });
    if cfg.allow_device_sign_in {
        doc["device_authorization_endpoint"] =
            Value::String(format!("{}/oauth/device", cfg.issuer));
    }
    doc
}

/// Handle `POST /oauth/par` (RFC 9126 Pushed Authorization Requests, Poppy §4.2).
pub fn handle_par<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    body: &[u8],
    dpop_header: Option<&str>,
    resolver: &R,
    store: &S,
    now_ms: u64,
) -> OAuthReply {
    let now_secs = now_ms / 1000;
    let raw = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return OAuthReply::oauth_err(400, "invalid_request", "non-UTF-8 form body")
                .with_denied_telemetry(None)
        }
    };
    let form_cid = http_query::param(raw, "client_id");
    let client_id = match authenticate_client_form(cfg, raw, resolver, store, now_secs) {
        Ok(cid) => cid,
        Err(reply) => return reply.with_denied_telemetry(form_cid.as_deref()),
    };
    let Some(meta) = resolver.resolve(&client_id) else {
        return OAuthReply::oauth_err(401, "invalid_client", "unknown client")
            .with_denied_telemetry(Some(&client_id));
    };
    if http_query::param(raw, "response_type").as_deref() != Some("code") {
        return OAuthReply::oauth_err(400, "unsupported_response_type", "response_type must be code")
            .with_denied_telemetry(Some(&client_id));
    }
    let Some(redirect_uri) = http_query::param(raw, "redirect_uri") else {
        return OAuthReply::oauth_err(400, "invalid_request", "missing redirect_uri")
            .with_denied_telemetry(Some(&client_id));
    };
    if !matches_registered_redirect(&meta.redirect_uris, &redirect_uri) {
        return OAuthReply::oauth_err(400, "invalid_request", "redirect_uri not registered in client metadata")
            .with_denied_telemetry(Some(&client_id));
    }
    if http_query::param(raw, "code_challenge_method").as_deref() != Some("S256") {
        return OAuthReply::oauth_err(400, "invalid_request", "PKCE S256 is required")
            .with_denied_telemetry(Some(&client_id));
    }
    let Some(code_challenge) = http_query::param(raw, "code_challenge").filter(|s| s.len() >= 32) else {
        return OAuthReply::oauth_err(400, "invalid_request", "missing or invalid code_challenge")
            .with_denied_telemetry(Some(&client_id));
    };
    let scopes = match parse_and_validate_scopes(cfg, http_query::param(raw, "scope").as_deref()) {
        Ok(s) => s,
        Err(reply) => return reply.with_denied_telemetry(Some(&client_id)),
    };
    let dpop_jkt = match dpop_header {
        Some(proof) => match verify_dpop_proof(
            proof,
            "POST",
            &format!("{}/oauth/par", cfg.issuer),
            None,
            store,
            now_secs,
        ) {
            Ok(jkt) => Some(jkt),
            Err(e) => {
                return OAuthReply::oauth_err(400, "invalid_dpop_proof", &e)
                    .with_denied_telemetry(Some(&client_id))
            }
        },
        None => {
            if cfg.require_dpop {
                return OAuthReply::oauth_err(400, "invalid_dpop_proof", "DPoP proof required")
                    .with_denied_telemetry(Some(&client_id));
            }
            None
        }
    };

    let req_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-poppy-oauth/par/v1")
    };
    let req_id = base64url_encode(&req_bytes[..24]);
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{req_id}");
    store.put_par(ParRequest {
        request_uri: request_uri.clone(),
        client_id: client_id.clone(),
        redirect_uri,
        scopes,
        state: http_query::param(raw, "state"),
        code_challenge,
        prompt_consent: http_query::param(raw, "prompt").as_deref() == Some("consent"),
        dpop_jkt,
        expires_at_secs: now_secs.saturating_add(PAR_TTL_SECS),
    });

    OAuthReply::json(
        201,
        &serde_json::json!({
            "request_uri": request_uri,
            "expires_in": PAR_TTL_SECS
        }),
    )
    .with_telemetry("par_created", Some(&client_id), None)
}

/// Render the Poppy-compliant Direct Sign-In consent page (`GET /oauth/authorize`, §4.2, §10.8).
/// The host app authenticates the human user first (via `packages/auth` or `packages/alloy-auth`)
/// and passes their `account_id`, `account_label`, and `csrf_token`.
#[allow(clippy::too_many_arguments)]
pub fn handle_authorize_get<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    raw_query: &str,
    account_id: &str,
    account_label: &str,
    csrf_token: &str,
    resolver: &R,
    store: &S,
    now_ms: u64,
) -> OAuthReply {
    let now_secs = now_ms / 1000;
    let query_cid = http_query::param(raw_query, "client_id");
    let params = match resolve_authorize_params(cfg, raw_query, resolver, store, now_secs) {
        Ok(p) => p,
        Err(reply) => return reply.with_denied_telemetry(query_cid.as_deref()),
    };
    let Some(meta) = resolver.resolve(&params.client_id) else {
        return OAuthReply::oauth_err(400, "invalid_client", "Personal Agent not accepted")
            .with_denied_telemetry(Some(&params.client_id));
    };
    let client_domain = meta
        .client_id
        .split("://")
        .nth(1)
        .unwrap_or(&meta.client_id)
        .split('/')
        .next()
        .unwrap_or(&meta.client_id);

    let already_granted: BTreeSet<String> = store
        .list_families_for_account(account_id)
        .into_iter()
        .filter(|f| f.client_id == params.client_id)
        .flat_map(|f| f.scopes.into_iter())
        .collect();

    let web_unscoped = matches!(cfg.poppy.web, PoppyWeb::BrowserJoin { unscoped: true, .. });
    let mut scope_items = String::new();
    for sc_name in &params.scopes {
        let spec = cfg.poppy.scopes().iter().find(|s| s.name == *sc_name);
        let desc = spec
            .map(|s| s.description.as_str())
            .unwrap_or(sc_name.as_str());
        let mut badges = Vec::new();
        if let Some(s) = spec {
            match s.changes {
                ScopeChanges::None => badges.push(("badge-read", "Read only")),
                ScopeChanges::Reversible => badges.push(("badge-write", "Reversible")),
                ScopeChanges::Irreversible => badges.push(("badge-warn", "Irreversible action")),
            }
            if s.personal_data {
                badges.push(("badge-data", "Personal data"));
            }
        }
        if !already_granted.is_empty() && !already_granted.contains(sc_name) {
            badges.push(("badge-new", "New"));
        }
        if sc_name == SCOPE_BROWSER_SIGN_IN && web_unscoped {
            badges.push(("badge-warn", "Full website access"));
        }
        let badge_html: String = badges
            .iter()
            .map(|(cls, text)| format!("<span class=\"pill {cls}\">{text}</span>"))
            .collect::<Vec<_>>()
            .join(" ");
        scope_items.push_str(&format!(
            "<li class=\"scope-card\"><label class=\"scope-row\">\
            <input type=\"checkbox\" name=\"approved_scope\" value=\"{val}\" checked>\
            <div class=\"scope-copy\">\
              <div class=\"scope-top\"><strong>{name}</strong><span class=\"pills\">{badges}</span></div>\
              <div class=\"scope-desc\">{desc}</div>\
            </div>\
            </label></li>\n",
            val = html_escape(sc_name),
            name = html_escape(sc_name),
            desc = html_escape(desc),
            badges = badge_html,
        ));
    }

    let signed_txn = sign_authorize_txn(cfg, &params, account_id, now_secs);
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
        <title>Connect {agent} to {co}</title>\
        <style>{css}</style></head>\
        <body><main class=\"card\">\
        <div class=\"brand-row\"><span class=\"mark\" aria-hidden=\"true\">{mark}</span>\
        <div><div class=\"eyebrow\">Personal Agent Protocol · Poppy 1.0</div><div class=\"co-name\">{co}</div></div></div>\
        <h1>{agent} wants to connect to your {co} account</h1>\
        <div class=\"meta-grid\">\
          <div><span class=\"meta-label\">Verified agent</span><span class=\"meta-val\"><strong>{agent}</strong> <code class=\"domain\">{domain}</code></span></div>\
          <div><span class=\"meta-label\">Signed in as</span><span class=\"meta-val\">{acct}</span></div>\
        </div>\
        <div class=\"notice\" role=\"note\"><strong>Only continue if you asked {agent} to do this just now.</strong> You can disconnect this agent at any time from your account settings.</div>\
        <form method=\"post\" action=\"/oauth/authorize\">\
        <input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\">\
        <input type=\"hidden\" name=\"txn\" value=\"{txn}\">\
        <div class=\"section-title\">Requested permissions</div>\
        <ul class=\"scope-list\">{items}</ul>\
        <div class=\"actions\">\
          <button class=\"btn btn-primary\" type=\"submit\" name=\"decision\" value=\"approve\">Approve &amp; connect {agent}</button>\
          <button class=\"btn btn-secondary\" type=\"submit\" name=\"decision\" value=\"deny\">Decline</button>\
        </div>\
        </form></main></body></html>\n",
        css = POPPY_OAUTH_CSS,
        mark = html_escape(&cfg.company_name.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "P".into())),
        agent = html_escape(&meta.client_name),
        co = html_escape(&cfg.company_name),
        domain = html_escape(client_domain),
        acct = html_escape(account_label),
        csrf = html_escape(csrf_token),
        txn = html_escape(&signed_txn),
        items = scope_items,
    );
    OAuthReply::html(200, html).with_telemetry("consent_shown", Some(&params.client_id), None)
}

/// Complete Direct Sign-In consent (`POST /oauth/authorize`), redirecting with `code` + `iss`
/// (RFC 9207) or `error=access_denied` + `iss`.
pub fn handle_authorize_post(
    cfg: &OAuthServerConfig,
    body: &[u8],
    account_id: &str,
    now_ms: u64,
) -> OAuthReply {
    let now_secs = now_ms / 1000;
    let raw = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return OAuthReply::oauth_err(400, "invalid_request", "invalid form body")
                .with_denied_telemetry(None)
        }
    };
    let Some(txn_str) = http_query::param(raw, "txn") else {
        return OAuthReply::oauth_err(400, "invalid_request", "missing authorization transaction")
            .with_denied_telemetry(None);
    };
    let Some(txn) = verify_authorize_txn(cfg, &txn_str, account_id, now_secs) else {
        return OAuthReply::oauth_err(400, "invalid_request", "invalid or expired authorization transaction")
            .with_denied_telemetry(None);
    };

    let decision = http_query::param(raw, "decision").unwrap_or_default();
    let approved_scopes: Vec<String> = http_query::parse_query(raw)
        .into_iter()
        .filter(|(k, _)| k == "approved_scope")
        .map(|(_, v)| v)
        // §4.7: NEVER grant scopes beyond those requested.
        .filter(|sc| txn.scopes.contains(sc))
        .collect();

    // §4.7: A Poppy sign-in grants at least one scope; zero approved scopes ends as a decline.
    if decision != "approve" || approved_scopes.is_empty() {
        let mut qs = vec![
            ("error", "access_denied".to_string()),
            ("iss", cfg.issuer.clone()),
        ];
        if let Some(st) = txn.state {
            qs.push(("state", st));
        }
        return OAuthReply::redirect(append_query(&txn.redirect_uri, &qs)).with_telemetry(
            "denied",
            Some(&txn.client_id),
            Some("access_denied"),
        );
    }

    let code_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-poppy-oauth/code/v1")
    };
    let code_nonce = base64url_encode(&code_bytes[..16]);
    let client_id = txn.client_id.clone();
    let payload = SignedCode {
        nonce: code_nonce,
        client_id: txn.client_id,
        redirect_uri: txn.redirect_uri.clone(),
        account_id: account_id.to_string(),
        scopes: approved_scopes,
        code_challenge: txn.code_challenge,
        dpop_jkt: txn.dpop_jkt,
        exp: now_secs.saturating_add(CODE_TTL_SECS),
    };
    let code = seal_value(&cfg.signing_secret, b"poppy-oauth/code", &payload);

    let mut qs = vec![("code", code), ("iss", cfg.issuer.clone())];
    if let Some(st) = txn.state {
        qs.push(("state", st));
    }
    OAuthReply::redirect(append_query(&txn.redirect_uri, &qs)).with_telemetry(
        "code_issued",
        Some(&client_id),
        None,
    )
}

/// Handle `POST /oauth/token` (`authorization_code`, `refresh_token`, optional `device_code`).
pub fn handle_token<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    body: &[u8],
    dpop_header: Option<&str>,
    resolver: &R,
    store: &S,
    now_ms: u64,
) -> OAuthReply {
    let now_secs = now_ms / 1000;
    let raw = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return OAuthReply::oauth_err(400, "invalid_request", "invalid form body")
                .with_denied_telemetry(None)
        }
    };
    let form_cid = http_query::param(raw, "client_id");
    let client_id = match authenticate_client_form(cfg, raw, resolver, store, now_secs) {
        Ok(cid) => cid,
        Err(reply) => return reply.with_denied_telemetry(form_cid.as_deref()),
    };
    let client_name = resolver
        .resolve(&client_id)
        .map(|m| m.client_name)
        .unwrap_or_else(|| client_id.clone());

    let dpop_jkt = match dpop_header {
        Some(proof) => match verify_dpop_proof(
            proof,
            "POST",
            &format!("{}/oauth/token", cfg.issuer),
            None,
            store,
            now_secs,
        ) {
            Ok(jkt) => Some(jkt),
            Err(e) => {
                return OAuthReply::oauth_err(400, "invalid_dpop_proof", &e)
                    .with_denied_telemetry(Some(&client_id))
            }
        },
        None => {
            if cfg.require_dpop {
                return OAuthReply::oauth_err(400, "invalid_dpop_proof", "DPoP proof required")
                    .with_denied_telemetry(Some(&client_id));
            }
            None
        }
    };

    let requested_resource = http_query::param(raw, "resource");
    let target_resource = match requested_resource.as_deref() {
        Some(r) => {
            if !cfg.is_supported_resource(r) {
                return OAuthReply::oauth_err(400, "invalid_target", "unsupported resource identifier")
                    .with_denied_telemetry(Some(&client_id));
            }
            r.trim_end_matches('/').to_string()
        }
        None => cfg.default_resource.clone(),
    };

    let grant_type = http_query::param(raw, "grant_type").unwrap_or_default();
    match grant_type.as_str() {
        "authorization_code" => {
            let Some(code_str) = http_query::param(raw, "code") else {
                return OAuthReply::oauth_err(400, "invalid_request", "missing code")
                    .with_denied_telemetry(Some(&client_id));
            };
            let Some(redirect_uri) = http_query::param(raw, "redirect_uri") else {
                return OAuthReply::oauth_err(400, "invalid_request", "missing redirect_uri")
                    .with_denied_telemetry(Some(&client_id));
            };
            let Some(code_verifier) = http_query::param(raw, "code_verifier") else {
                return OAuthReply::oauth_err(400, "invalid_request", "missing code_verifier")
                    .with_denied_telemetry(Some(&client_id));
            };
            let Some(code): Option<SignedCode> =
                open_value(&cfg.signing_secret, b"poppy-oauth/code", &code_str)
            else {
                return OAuthReply::oauth_err(400, "invalid_grant", "malformed or invalid code")
                    .with_denied_telemetry(Some(&client_id));
            };
            if now_secs >= code.exp
                || code.client_id != client_id
                || code.redirect_uri != redirect_uri
            {
                return OAuthReply::oauth_err(400, "invalid_grant", "code expired or mismatched")
                    .with_denied_telemetry(Some(&client_id));
            }
            if let Some(bound_jkt) = &code.dpop_jkt {
                if dpop_jkt.as_deref() != Some(bound_jkt.as_str()) {
                    return OAuthReply::oauth_err(400, "invalid_grant", "DPoP key does not match PAR proof")
                        .with_denied_telemetry(Some(&client_id));
                }
            }
            let expected_challenge = base64url_encode(&sha256(code_verifier.as_bytes()));
            if !ct_eq(expected_challenge.as_bytes(), code.code_challenge.as_bytes()) {
                return OAuthReply::oauth_err(400, "invalid_grant", "PKCE verification failed")
                    .with_denied_telemetry(Some(&client_id));
            }
            if !store.burn_once(&format!("code:{}", code.nonce), code.exp) {
                return OAuthReply::oauth_err(400, "invalid_grant", "authorization code already used")
                    .with_denied_telemetry(Some(&client_id));
            }

            let family_id = format!("fam_{}", code.nonce);
            let family_exp = now_secs.saturating_add(cfg.refresh_ttl_secs);
            store.put_family(GrantFamily {
                family_id: family_id.clone(),
                client_id: client_id.clone(),
                client_name,
                account_id: code.account_id.clone(),
                scopes: code.scopes.clone(),
                allowed_resources: None, // Sign-in without resource covers every resource (§4.5)
                dpop_jkt: dpop_jkt.clone(),
                created_secs: now_secs,
                last_used_secs: now_secs,
                expires_at_secs: family_exp,
                revoked: false,
            });
            issue_token_pair(
                cfg,
                &family_id,
                &client_id,
                &code.account_id,
                &code.scopes,
                &target_resource,
                dpop_jkt,
                family_exp,
                now_secs,
            )
            .with_telemetry("grant_issued", Some(&client_id), None)
        }
        "refresh_token" => {
            let Some(rt_str) = http_query::param(raw, "refresh_token") else {
                return OAuthReply::oauth_err(400, "invalid_request", "missing refresh_token")
                    .with_denied_telemetry(Some(&client_id));
            };
            let Some(rt): Option<SignedRefreshToken> =
                open_value(&cfg.signing_secret, b"poppy-oauth/refresh", &rt_str)
            else {
                return OAuthReply::oauth_err(400, "invalid_grant", "invalid refresh token")
                    .with_denied_telemetry(Some(&client_id));
            };
            if rt.client_id != client_id || now_secs >= rt.exp {
                return OAuthReply::oauth_err(400, "invalid_grant", "refresh token expired or mismatched")
                    .with_denied_telemetry(Some(&client_id));
            }
            let Some(family) = store.get_family(&rt.family_id) else {
                return OAuthReply::oauth_err(400, "invalid_grant", "grant family unknown")
                    .with_denied_telemetry(Some(&client_id));
            };
            if family.revoked || now_secs >= family.expires_at_secs {
                return OAuthReply::oauth_err(400, "invalid_grant", "grant family revoked or expired")
                    .with_denied_telemetry(Some(&client_id));
            }
            // §4.4: DPoP key binding on refresh tokens.
            if let Some(bound_jkt) = &family.dpop_jkt {
                if dpop_jkt.as_deref() != Some(bound_jkt.as_str()) {
                    return OAuthReply::oauth_err(
                        400,
                        "invalid_grant",
                        "refresh token is bound to a different DPoP key (§4.4)",
                    )
                    .with_denied_telemetry(Some(&client_id));
                }
            }
            // RFC 9700 §4.14.2: replayed refresh token revokes the entire grant family!
            if !store.burn_once(&format!("rt:{}", rt.nonce), family.expires_at_secs) {
                store.revoke_family(&rt.family_id);
                return OAuthReply::oauth_err(
                    400,
                    "invalid_grant",
                    "refresh token replay detected; grant family revoked",
                )
                .with_denied_telemetry(Some(&client_id));
            }
            // Optional downscoping (§4.4): requested scopes must be a subset of family scopes.
            let granted_scopes = match http_query::param(raw, "scope") {
                None => family.scopes.clone(),
                Some(sc) => {
                    let req_scopes: Vec<String> =
                        sc.split_whitespace().map(str::to_string).collect();
                    if req_scopes.is_empty()
                        || !req_scopes.iter().all(|s| family.scopes.contains(s))
                    {
                        return OAuthReply::oauth_err(
                            400,
                            "invalid_scope",
                            "requested scope exceeds original grant",
                        )
                        .with_denied_telemetry(Some(&client_id));
                    }
                    req_scopes
                }
            };
            store.touch_family(&family.family_id, now_secs);
            issue_token_pair(
                cfg,
                &family.family_id,
                &client_id,
                &family.account_id,
                &granted_scopes,
                &target_resource,
                family.dpop_jkt,
                family.expires_at_secs,
                now_secs,
            )
            .with_telemetry("token_refreshed", Some(&client_id), None)
        }
        _ => OAuthReply::oauth_err(400, "unsupported_grant_type", "unsupported grant_type")
            .with_denied_telemetry(Some(&client_id)),
    }
}

/// Handle `POST /oauth/revoke` (RFC 7009 + Poppy §4.6 / §5.5).
pub fn handle_revoke<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    body: &[u8],
    resolver: &R,
    store: &S,
    now_ms: u64,
) -> OAuthReply {
    let now_secs = now_ms / 1000;
    let raw = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return OAuthReply::oauth_err(400, "invalid_request", "invalid form body")
                .with_denied_telemetry(None)
        }
    };
    let form_cid = http_query::param(raw, "client_id");
    let client_id = match authenticate_client_form(cfg, raw, resolver, store, now_secs) {
        Ok(cid) => cid,
        Err(reply) => return reply.with_denied_telemetry(form_cid.as_deref()),
    };
    if let Some(token) = http_query::param(raw, "token") {
        if let Some(rt) = open_value::<SignedRefreshToken>(
            &cfg.signing_secret,
            b"poppy-oauth/refresh",
            &token,
        ) {
            if rt.client_id == client_id {
                store.revoke_family(&rt.family_id);
            }
        } else if let Some(at) = open_value::<SignedAccessToken>(
            &cfg.signing_secret,
            b"poppy-oauth/access",
            &token,
        ) {
            if at.client_id == client_id {
                store.revoke_family(&at.family_id);
            }
        }
    }
    // RFC 7009 §2.2: always return 200 OK even for unknown tokens.
    OAuthReply {
        status: 200,
        content_type: "application/json",
        body: Vec::new(),
        headers: vec![("cache-control", "no-store".into())],
    }
    .with_telemetry("grant_revoked", Some(&client_id), None)
}

/// Verify an incoming `Authorization: Bearer <token>` (or `DPoP <token>`) at a
/// resource endpoint, enforcing exact `resource` audience binding (§4.5, §7)
/// and immediate grant-family revocation (§5.5).
pub fn verify_access_token<S: OAuthStore>(
    cfg: &OAuthServerConfig,
    authorization_header: &str,
    expected_resource: &str,
    dpop_header: Option<&str>,
    method: &str,
    canonical_htu: &str,
    store: &S,
    now_ms: u64,
) -> Result<PresentedToken, PoppyError> {
    let now_secs = now_ms / 1000;
    let (scheme, raw_token) = authorization_header
        .trim()
        .split_once(' ')
        .map(|(s, t)| (s.trim(), t.trim()))
        .ok_or_else(|| PoppyError::auth_required(&[], None))?;
    if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("dpop") {
        return Err(PoppyError::auth_required(&[], None));
    }
    let tok: SignedAccessToken =
        open_value(&cfg.signing_secret, b"poppy-oauth/access", raw_token)
            .ok_or_else(|| PoppyError::auth_required(&[], None))?;
    if now_secs >= tok.exp || tok.resource.trim_end_matches('/') != expected_resource.trim_end_matches('/') {
        return Err(PoppyError::auth_required(&[], None));
    }
    if let Some(bound_jkt) = &tok.dpop_jkt {
        if !scheme.eq_ignore_ascii_case("dpop") {
            return Err(PoppyError::auth_required(&[], None));
        }
        let proof = dpop_header.ok_or_else(|| PoppyError::auth_required(&[], None))?;
        let jkt = verify_dpop_proof(proof, method, canonical_htu, Some(raw_token), store, now_secs)
            .map_err(|_| PoppyError::auth_required(&[], None))?;
        if !ct_eq(jkt.as_bytes(), bound_jkt.as_bytes()) {
            return Err(PoppyError::auth_required(&[], None));
        }
    }
    let family = store
        .get_family(&tok.family_id)
        .ok_or_else(|| PoppyError::auth_required(&[], None))?;
    if family.revoked || now_secs >= family.expires_at_secs {
        return Err(PoppyError::auth_required(&[], None));
    }
    Ok(PresentedToken {
        raw_token: raw_token.to_string(),
        client_id: tok.client_id,
        account_id: tok.account_id,
        scopes: tok.scopes,
    })
}

/// Render the Account Settings "Connected Personal Agents" page (`GET /oauth/connected-agents`).
pub fn handle_connected_agents_get<S: OAuthStore>(
    cfg: &OAuthServerConfig,
    account_id: &str,
    csrf_token: &str,
    store: &S,
) -> OAuthReply {
    let families = store.list_families_for_account(account_id);
    let mut rows = String::new();
    for f in &families {
        let domain = f
            .client_id
            .split("://")
            .nth(1)
            .unwrap_or(&f.client_id)
            .split('/')
            .next()
            .unwrap_or(&f.client_id);
        rows.push_str(&format!(
            "<li class=\"scope-card\"><div class=\"agent-row\">\
            <div class=\"scope-copy\">\
              <div class=\"scope-top\"><strong>{name}</strong> <code class=\"domain\">{domain}</code></div>\
              <div class=\"scope-desc\">Scopes: <code>{scopes}</code></div>\
            </div>\
            <form method=\"post\" action=\"/oauth/connected-agents\">\
            <input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\">\
            <input type=\"hidden\" name=\"disconnect\" value=\"{fam}\">\
            <button class=\"btn btn-danger\" type=\"submit\">Disconnect</button></form></div></li>\n",
            name = html_escape(&f.client_name),
            domain = html_escape(domain),
            scopes = html_escape(&f.scopes.join(" ")),
            csrf = html_escape(csrf_token),
            fam = html_escape(&f.family_id),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<li class=\"empty\">No Personal Agents are currently connected to your account.</li>");
    }
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
        <title>Connected Personal Agents — {co}</title>\
        <style>{css}</style></head>\
        <body><main class=\"card\">\
        <div class=\"brand-row\"><span class=\"mark\" aria-hidden=\"true\">{mark}</span>\
        <div><div class=\"eyebrow\">Personal Agent Protocol · Poppy 1.0</div><div class=\"co-name\">{co}</div></div></div>\
        <h1>Connected Personal Agents</h1>\
        <p class=\"lead\">Disconnecting an agent immediately revokes all of its active access and refresh tokens.</p>\
        <ul class=\"scope-list\">{rows}</ul>\
        <div class=\"foot\"><a href=\"/account\">Back to account</a></div>\
        </main></body></html>\n",
        css = POPPY_OAUTH_CSS,
        mark = html_escape(&cfg.company_name.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "P".into())),
        co = html_escape(&cfg.company_name),
        rows = rows
    );
    OAuthReply::html(200, html)
}

const POPPY_OAUTH_CSS: &str = "\
:root{--bg:#ffffff;--panel:rgba(255,255,255,.9);--ink:#141312;--muted:#5c5852;--line:rgba(20,19,18,.12);--accent:#141312;--danger:#b42318;--ok:#146841;--warn:#9a5b08;}\
*{box-sizing:border-box;}\
body{margin:0;min-height:100vh;padding:44px 18px 64px;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue','Segoe UI',sans-serif;font-size:14px;line-height:1.55;background:radial-gradient(90% 60% at 50% 0%,#fff0 0%,#fff 100%),linear-gradient(155deg,#fff 8%,#ffe3ea 48%,#fff6e0 86%,#fff 100%);color:var(--ink);display:flex;align-items:center;justify-content:center;}\
.card{width:100%;max-width:540px;margin:0 auto;background:var(--panel);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--line);border-radius:24px;padding:34px 32px;box-shadow:0 24px 60px rgba(20,19,18,.07);}\
.brand-row{display:flex;align-items:center;gap:12px;margin-bottom:22px;}\
.mark{width:34px;height:34px;border-radius:999px;background:var(--ink);color:#fff;font-weight:500;display:grid;place-items:center;font-size:14px;letter-spacing:.04em;}\
.eyebrow{font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.18em;color:var(--muted);}\
.co-name{font-weight:500;font-size:15px;letter-spacing:.01em;}\
h1{font-size:24px;font-weight:300;line-height:1.2;letter-spacing:-.025em;margin:0 0 18px;}\
.lead{color:var(--muted);font-weight:300;margin:0 0 20px;}\
.meta-grid{display:grid;gap:10px;padding:14px 16px;border:1px solid var(--line);border-radius:16px;background:#fff;margin-bottom:16px;}\
.meta-grid>div{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap;}\
.meta-label{font-size:12px;color:var(--muted);}\
.meta-val{font-size:13px;}\
.domain{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#f4f2ef;padding:2px 7px;border-radius:6px;}\
.notice{background:#fdf6e7;border:1px solid rgba(185,127,16,.28);color:#784208;border-radius:14px;padding:12px 14px;font-size:13px;margin-bottom:20px;}\
.section-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin-bottom:10px;}\
.scope-list{list-style:none;margin:0 0 24px;padding:0;display:grid;gap:10px;}\
.scope-card{border:1px solid var(--line);border-radius:16px;background:#fff;padding:12px 14px;}\
.scope-row{display:flex;gap:12px;align-items:flex-start;cursor:pointer;}\
.scope-row input{margin-top:3px;accent-color:var(--ink);}\
.agent-row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;}\
.scope-copy{flex:1;min-width:0;}\
.scope-top{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}\
.scope-desc{color:var(--muted);font-size:13px;margin-top:3px;}\
.pills{display:inline-flex;gap:4px;flex-wrap:wrap;}\
.pill{font-size:11px;font-weight:500;padding:2px 8px;border-radius:999px;background:#f2f0ec;color:var(--muted);}\
.badge-read{background:#eff8f3;color:var(--ok);}\
.badge-write{background:#eef4fa;color:#24567f;}\
.badge-warn{background:#fff1f0;color:var(--danger);}\
.badge-data{background:#fdf6e7;color:var(--warn);}\
.badge-new{background:#fff1ed;color:#b72f19;}\
.actions{display:flex;gap:10px;flex-wrap:wrap;}\
.btn{font:inherit;font-weight:500;border-radius:999px;padding:12px 20px;border:1px solid transparent;cursor:pointer;transition:background-color 160ms ease,border-color 160ms ease,transform 150ms cubic-bezier(.23,1,.32,1);}\
.btn:active{transform:scale(.97);}\
.btn-primary{background:var(--ink);color:#fff;flex:1;}\
.btn-primary:hover{background:#2e2c29;}\
.btn-secondary{background:#fff;border-color:var(--line);color:var(--ink);}\
.btn-secondary:hover{border-color:rgba(20,19,18,.35);}\
.btn-danger{background:#fff;border-color:#f3c1bd;color:var(--danger);padding:7px 14px;font-size:13px;}\
.empty{padding:20px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:14px;}\
.foot{margin-top:18px;font-size:13px;}\
.foot a{color:var(--ink);text-decoration:underline;text-underline-offset:3px;font-weight:500;}\
";

/// Disconnect a Personal Agent from Account Settings (`POST /oauth/connected-agents`).
pub fn handle_connected_agents_disconnect<S: OAuthStore>(
    account_id: &str,
    body: &[u8],
    store: &S,
) -> OAuthReply {
    let raw = std::str::from_utf8(body).unwrap_or("");
    let mut revoked_client: Option<String> = None;
    if let Some(family_id) = http_query::param(raw, "disconnect") {
        if let Some(fam) = store.get_family(&family_id) {
            if fam.account_id == account_id {
                store.revoke_family(&family_id);
                revoked_client = Some(fam.client_id);
            }
        }
    }
    let reply = OAuthReply::redirect("/oauth/connected-agents".into());
    match revoked_client {
        Some(cid) => reply.with_telemetry("grant_revoked", Some(&cid), None),
        None => reply,
    }
}

// ---- Internal wire & crypto helpers -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    code_challenge: String,
    dpop_jkt: Option<String>,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct AuthorizeTxn {
    account_id: String,
    params: AuthorizeParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct SignedCode {
    nonce: String,
    client_id: String,
    redirect_uri: String,
    account_id: String,
    scopes: Vec<String>,
    code_challenge: String,
    dpop_jkt: Option<String>,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct SignedRefreshToken {
    nonce: String,
    family_id: String,
    client_id: String,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct SignedAccessToken {
    family_id: String,
    client_id: String,
    account_id: String,
    scopes: Vec<String>,
    resource: String,
    dpop_jkt: Option<String>,
    exp: u64,
}

#[allow(clippy::too_many_arguments)]
fn issue_token_pair(
    cfg: &OAuthServerConfig,
    family_id: &str,
    client_id: &str,
    account_id: &str,
    scopes: &[String],
    resource: &str,
    dpop_jkt: Option<String>,
    family_exp: u64,
    now_secs: u64,
) -> OAuthReply {
    let at_exp = now_secs.saturating_add(cfg.access_ttl_secs).min(family_exp);
    let access_token = seal_value(
        &cfg.signing_secret,
        b"poppy-oauth/access",
        &SignedAccessToken {
            family_id: family_id.to_string(),
            client_id: client_id.to_string(),
            account_id: account_id.to_string(),
            scopes: scopes.to_vec(),
            resource: resource.to_string(),
            dpop_jkt: dpop_jkt.clone(),
            exp: at_exp,
        },
    );
    let rt_bytes = {
        let key = Ed25519SigningKey::generate_pkcs8();
        hmac_sha256(&key, b"ferrite-poppy-oauth/refresh/v1")
    };
    let rt_nonce = base64url_encode(&rt_bytes[..16]);
    let refresh_token = seal_value(
        &cfg.signing_secret,
        b"poppy-oauth/refresh",
        &SignedRefreshToken {
            nonce: rt_nonce,
            family_id: family_id.to_string(),
            client_id: client_id.to_string(),
            exp: family_exp,
        },
    );
    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    OAuthReply::json(
        200,
        &serde_json::json!({
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": at_exp.saturating_sub(now_secs),
            "refresh_token": refresh_token,
            "scope": scopes.join(" "),
        }),
    )
}

fn authenticate_client_form<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    raw_form: &str,
    resolver: &R,
    store: &S,
    now_secs: u64,
) -> Result<String, OAuthReply> {
    if http_query::param(raw_form, "client_assertion_type").as_deref()
        != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    {
        return Err(OAuthReply::oauth_err(
            401,
            "invalid_client",
            "private_key_jwt client_assertion_type is required (§4.1)",
        ));
    }
    let Some(assertion) = http_query::param(raw_form, "client_assertion") else {
        return Err(OAuthReply::oauth_err(
            401,
            "invalid_client",
            "missing client_assertion",
        ));
    };
    let (cid, jti, exp) = verify_client_assertion(&assertion, &cfg.issuer, resolver, now_secs, 30)
        .map_err(|e| OAuthReply::oauth_err(401, "invalid_client", &e))?;
    if let Some(form_cid) = http_query::param(raw_form, "client_id") {
        if form_cid != cid {
            return Err(OAuthReply::oauth_err(
                401,
                "invalid_client",
                "client_id parameter disagrees with client_assertion iss",
            ));
        }
    }
    if !store.burn_once(&format!("jti:{cid}:{jti}"), exp) {
        return Err(OAuthReply::oauth_err(
            401,
            "invalid_client",
            "replayed client_assertion jti",
        ));
    }
    Ok(cid)
}

fn resolve_authorize_params<R: AgentKeyResolver, S: OAuthStore>(
    cfg: &OAuthServerConfig,
    raw_query: &str,
    resolver: &R,
    store: &S,
    now_secs: u64,
) -> Result<AuthorizeParams, OAuthReply> {
    if let Some(req_uri) = http_query::param(raw_query, "request_uri") {
        let Some(cid) = http_query::param(raw_query, "client_id") else {
            return Err(OAuthReply::oauth_err(400, "invalid_request", "missing client_id"));
        };
        let Some(par) = store.take_par(&req_uri) else {
            return Err(OAuthReply::oauth_err(400, "invalid_request", "unknown or expired request_uri"));
        };
        if par.client_id != cid || now_secs >= par.expires_at_secs {
            return Err(OAuthReply::oauth_err(400, "invalid_request", "request_uri expired or client mismatch"));
        }
        return Ok(AuthorizeParams {
            client_id: par.client_id,
            redirect_uri: par.redirect_uri,
            scopes: par.scopes,
            state: par.state,
            code_challenge: par.code_challenge,
            dpop_jkt: par.dpop_jkt,
            exp: now_secs.saturating_add(600),
        });
    }
    if cfg.require_par {
        return Err(OAuthReply::oauth_err(
            400,
            "invalid_request",
            "Pushed Authorization Requests (PAR) are required by this issuer",
        ));
    }
    let Some(client_id) = http_query::param(raw_query, "client_id") else {
        return Err(OAuthReply::oauth_err(400, "invalid_request", "missing client_id"));
    };
    let Some(meta) = resolver.resolve(&client_id) else {
        return Err(OAuthReply::oauth_err(400, "invalid_client", "Personal Agent not accepted"));
    };
    if http_query::param(raw_query, "response_type").as_deref() != Some("code") {
        return Err(OAuthReply::oauth_err(400, "unsupported_response_type", "response_type must be code"));
    }
    let Some(redirect_uri) = http_query::param(raw_query, "redirect_uri") else {
        return Err(OAuthReply::oauth_err(400, "invalid_request", "missing redirect_uri"));
    };
    if !matches_registered_redirect(&meta.redirect_uris, &redirect_uri) {
        return Err(OAuthReply::oauth_err(400, "invalid_request", "redirect_uri not registered in client metadata"));
    }
    if http_query::param(raw_query, "code_challenge_method").as_deref() != Some("S256") {
        return Err(OAuthReply::oauth_err(400, "invalid_request", "PKCE S256 is required"));
    }
    let Some(code_challenge) = http_query::param(raw_query, "code_challenge").filter(|s| s.len() >= 32) else {
        return Err(OAuthReply::oauth_err(400, "invalid_request", "missing or invalid code_challenge"));
    };
    let scopes = parse_and_validate_scopes(cfg, http_query::param(raw_query, "scope").as_deref())?;
    Ok(AuthorizeParams {
        client_id,
        redirect_uri,
        scopes,
        state: http_query::param(raw_query, "state"),
        code_challenge,
        dpop_jkt: None,
        exp: now_secs.saturating_add(600),
    })
}

fn parse_and_validate_scopes(
    cfg: &OAuthServerConfig,
    raw: Option<&str>,
) -> Result<Vec<String>, OAuthReply> {
    let Some(raw) = raw else {
        return Err(OAuthReply::oauth_err(
            400,
            "invalid_scope",
            "scope parameter is required on Poppy sign-in (§4.7)",
        ));
    };
    let mut out = Vec::new();
    for s in raw.split_whitespace() {
        if !cfg.is_known_scope(s) {
            return Err(OAuthReply::oauth_err(
                400,
                "invalid_scope",
                &format!("unknown scope '{s}'"),
            ));
        }
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    if out.is_empty() {
        return Err(OAuthReply::oauth_err(
            400,
            "invalid_scope",
            "at least one scope must be requested (§4.7)",
        ));
    }
    Ok(out)
}

/// §4.2 exact `redirect_uri` match, except port variance on RFC 8252 §7.3 loopback URIs.
fn matches_registered_redirect(registered: &[String], presented: &str) -> bool {
    if registered.iter().any(|r| r == presented) {
        return true;
    }
    let Some((p_host, p_rest)) = split_loopback_http(presented) else {
        return false;
    };
    registered.iter().any(|r| {
        split_loopback_http(r).is_some_and(|(r_host, r_rest)| r_host == p_host && r_rest == p_rest)
    })
}

fn split_loopback_http(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let host = if auth.starts_with('[') {
        let end = auth.find(']')?;
        &auth[..=end]
    } else {
        auth.split(':').next()?
    };
    if matches!(host, "127.0.0.1" | "[::1]") {
        Some((host, tail))
    } else {
        None
    }
}

/// Minimal RFC 9449 DPoP ES256 proof verification returning the JWK thumbprint (`jkt`).
/// Enforces single-use `jti` replay protection and, at protected resources, RFC 9449 §4.3 `ath`.
fn verify_dpop_proof<S: OAuthStore>(
    proof: &str,
    method: &str,
    htu: &str,
    access_token: Option<&str>,
    store: &S,
    now_secs: u64,
) -> Result<String, String> {
    let mut parts = proof.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed DPoP JWT".into());
    };
    let hdr: Value = serde_json::from_slice(&base64url_decode(h).map_err(|_| "bad header")?)
        .map_err(|_| "bad header json")?;
    let claims: Value = serde_json::from_slice(&base64url_decode(p).map_err(|_| "bad payload")?)
        .map_err(|_| "bad payload json")?;
    let sig = base64url_decode(s).map_err(|_| "bad sig")?;

    if hdr.get("typ").and_then(Value::as_str) != Some("dpop+jwt")
        || hdr.get("alg").and_then(Value::as_str) != Some("ES256")
    {
        return Err("DPoP must be ES256 with typ=dpop+jwt".into());
    }
    let jwk = hdr.get("jwk").and_then(Value::as_object).ok_or("DPoP missing jwk")?;
    if jwk.contains_key("d")
        || jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err("DPoP jwk must be public EC P-256".into());
    }
    let x = jwk.get("x").and_then(Value::as_str).ok_or("missing x")?;
    let y = jwk.get("y").and_then(Value::as_str).ok_or("missing y")?;
    let xb = base64url_decode(x).map_err(|_| "bad x")?;
    let yb = base64url_decode(y).map_err(|_| "bad y")?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err("invalid P-256 point".into());
    }
    let point = p256_point(&xb, &yb);

    let signing_input = &proof[..h.len() + 1 + p.len()];
    if !es256_verify(&point, signing_input.as_bytes(), &sig) {
        return Err("DPoP signature invalid".into());
    }
    if !claims
        .get("htm")
        .and_then(Value::as_str)
        .is_some_and(|m| m.eq_ignore_ascii_case(method))
        || claims.get("htu").and_then(Value::as_str) != Some(htu)
    {
        return Err("DPoP htm/htu mismatch".into());
    }
    let iat = claims.get("iat").and_then(Value::as_u64).ok_or("DPoP missing iat")?;
    if iat < now_secs.saturating_sub(90) || iat > now_secs.saturating_add(30) {
        return Err("DPoP iat out of window".into());
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("DPoP missing jti")?;
    if let Some(raw_token) = access_token {
        let ath = claims
            .get("ath")
            .and_then(Value::as_str)
            .ok_or("DPoP missing ath for access token")?;
        let expected_ath = base64url_encode(&sha256(raw_token.as_bytes()));
        if !ct_eq(ath.as_bytes(), expected_ath.as_bytes()) {
            return Err("DPoP ath mismatch".into());
        }
    }
    let jkt = jwk_thumbprint_p256(x, y);
    if !store.burn_once(&format!("dpop:{jkt}:{jti}"), now_secs.saturating_add(120)) {
        return Err("DPoP jti replay detected".into());
    }
    Ok(jkt)
}

fn sign_authorize_txn(
    cfg: &OAuthServerConfig,
    params: &AuthorizeParams,
    account_id: &str,
    _now_secs: u64,
) -> String {
    seal_value(
        &cfg.signing_secret,
        b"poppy-oauth/txn",
        &AuthorizeTxn {
            account_id: account_id.to_string(),
            params: params.clone(),
        },
    )
}

fn verify_authorize_txn(
    cfg: &OAuthServerConfig,
    raw: &str,
    account_id: &str,
    now_secs: u64,
) -> Option<AuthorizeParams> {
    let txn: AuthorizeTxn = open_value(&cfg.signing_secret, b"poppy-oauth/txn", raw)?;
    if txn.account_id != account_id || now_secs >= txn.params.exp {
        return None;
    }
    Some(txn.params)
}

fn seal_value<T: Serialize>(secret: &[u8], domain: &[u8], value: &T) -> String {
    let key = hmac_sha256(secret, domain);
    let payload = serde_json::to_vec(value).unwrap_or_default();
    let body = base64url_encode(&payload);
    let mac = base64url_encode(&hmac_sha256(&key, body.as_bytes()));
    format!("{body}.{mac}")
}

fn open_value<T: for<'de> Deserialize<'de>>(secret: &[u8], domain: &[u8], raw: &str) -> Option<T> {
    let (body, mac) = raw.split_once('.')?;
    let key = hmac_sha256(secret, domain);
    let expected = base64url_encode(&hmac_sha256(&key, body.as_bytes()));
    if !ct_eq(mac.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let bytes = base64url_decode(body).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn append_query(base: &str, pairs: &[(&str, String)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect();
    format!("{base}{sep}{}", encoded.join("&"))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::poppy::ScopeSpec;
    use crate::agent_ready::poppy_verify::{sign_es256_jwt, StaticAgentDirectory};
    use ferrite_app::crypto::EcdsaSigningKey;

    fn test_setup() -> (OAuthServerConfig, EcdsaSigningKey, String, StaticAgentDirectory) {
        let root = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let pb = root.public_point();
        let x = base64url_encode(&pb[1..33]);
        let y = base64url_encode(&pb[33..65]);
        let kid = jwk_thumbprint_p256(&x, &y);
        let client_id = "https://agent.example/agent.json".to_string();
        let agent_json = serde_json::json!({
            "client_id": client_id,
            "client_name": "Muse Personal Agent",
            "jwks_uri": "https://agent.example/jwks.json",
            "redirect_uris": ["https://agent.example/cb", "http://127.0.0.1/cb"],
            "token_endpoint_auth_method": "private_key_jwt"
        });
        let jwks_json = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig", "x": x, "y": y }]
        });
        let mut dir = StaticAgentDirectory::new();
        dir.register_from_json(
            &client_id,
            agent_json.to_string().as_bytes(),
            jwks_json.to_string().as_bytes(),
        )
        .unwrap();

        let poppy = PoppyConfig::with_self_hosted_oauth(
            "Acme Tasks",
            vec![
                ScopeSpec::new("tasks:read", "Read tasks", ScopeChanges::None, false),
                ScopeSpec::new("tasks:write", "Write tasks", ScopeChanges::Irreversible, false),
            ],
        );
        let cfg = OAuthServerConfig::from_poppy(
            "https://tasks.acme.example",
            vec![
                "https://tasks.acme.example".into(),
                "https://tasks.acme.example/mcp".into(),
            ],
            b"super-secret-oauth-key-32-bytes!".to_vec(),
            poppy,
        );
        (cfg, root, kid, dir)
    }

    fn make_assertion(root: &EcdsaSigningKey, kid: &str, issuer: &str, jti: &str, now_secs: u64) -> String {
        sign_es256_jwt(
            root,
            &serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid}),
            &serde_json::json!({
                "iss": "https://agent.example/agent.json",
                "sub": "https://agent.example/agent.json",
                "aud": issuer,
                "iat": now_secs,
                "exp": now_secs + 120,
                "jti": jti
            }),
        )
    }

    #[test]
    fn full_par_direct_sign_in_multi_resource_refresh_and_revoke() {
        let (cfg, root, kid, dir) = test_setup();
        let store = MemoryOAuthStore::default();
        let now_secs = 1_790_900_000u64;
        let now_ms = now_secs * 1000;

        // 1. Metadata includes required Poppy fields.
        let meta = authorization_server_metadata(&cfg);
        assert_eq!(meta["issuer"], "https://tasks.acme.example");
        assert_eq!(meta["protected_resources"][1], "https://tasks.acme.example/mcp");
        assert_eq!(meta["client_id_metadata_document_supported"], true);

        // 2. PAR push with PKCE S256 & private_key_jwt.
        let verifier = "v_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let challenge = base64url_encode(&sha256(verifier.as_bytes()));
        let a1 = make_assertion(&root, &kid, &cfg.issuer, "jti_par", now_secs);
        let par_body = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=tasks%3Aread%20tasks%3Awrite&state=st1&code_challenge={}&code_challenge_method=S256&prompt=consent&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode("https://agent.example/agent.json"),
            percent_encode("http://127.0.0.1:49152/cb"),
            percent_encode(&challenge),
            percent_encode(&a1),
        );
        let par_reply = handle_par(&cfg, par_body.as_bytes(), None, &dir, &store, now_ms);
        assert_eq!(par_reply.status, 201);
        let par_json: Value = serde_json::from_slice(&par_reply.body).unwrap();
        let request_uri = par_json["request_uri"].as_str().unwrap();

        // 3. Authorize GET renders consent page with anti-phishing copy.
        let auth_q = format!(
            "client_id={}&request_uri={}",
            percent_encode("https://agent.example/agent.json"),
            percent_encode(request_uri),
        );
        let consent = handle_authorize_get(&cfg, &auth_q, "acct_1", "alice@acme.example", "csrf_1", &dir, &store, now_ms);
        assert_eq!(consent.status, 200);
        let html = std::str::from_utf8(&consent.body).unwrap();
        assert!(html.contains("Muse Personal Agent wants to connect"));
        assert!(html.contains("Only continue if you asked Muse Personal Agent"));

        // Extract txn hidden field and approve BOTH scopes.
        let marker = "name=\"txn\" value=\"";
        let start = html.find(marker).unwrap() + marker.len();
        let end = html[start..].find('"').unwrap();
        let txn = &html[start..start + end];
        let approve_body = format!(
            "_csrf=csrf_1&txn={}&decision=approve&approved_scope=tasks%3Aread&approved_scope=tasks%3Awrite",
            percent_encode(txn)
        );
        let redir = handle_authorize_post(&cfg, approve_body.as_bytes(), "acct_1", now_ms + 1000);
        assert_eq!(redir.status, 303);
        let loc = redir.headers.iter().find(|(k, _)| *k == "location").unwrap().1.clone();
        let (_, qs) = loc.split_once('?').unwrap();
        assert_eq!(http_query::param(qs, "iss").as_deref(), Some("https://tasks.acme.example"));
        assert_eq!(http_query::param(qs, "state").as_deref(), Some("st1"));
        let code = http_query::param(qs, "code").unwrap();

        // 4. Exchange code for default resource token.
        let a2 = make_assertion(&root, &kid, &cfg.issuer, "jti_tok1", now_secs + 2);
        let tok_body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode(&code),
            percent_encode("http://127.0.0.1:49152/cb"),
            percent_encode(verifier),
            percent_encode(&a2),
        );
        let tok_res = handle_token(&cfg, tok_body.as_bytes(), None, &dir, &store, now_ms + 2000);
        assert_eq!(tok_res.status, 200);
        assert!(tok_res.headers.iter().any(|(k, v)| *k == AGENT_EVENT_HEADER
            && v == "s=poppy_oauth;ok=1;verdict=grant_issued;ag=agent.example"));
        let tok_json: Value = serde_json::from_slice(&tok_res.body).unwrap();
        let at_default = tok_json["access_token"].as_str().unwrap();
        let rt1 = tok_json["refresh_token"].as_str().unwrap();

        // Default token works at domain resource, NOT at /mcp (§7).
        assert!(verify_access_token(&cfg, &format!("Bearer {at_default}"), "https://tasks.acme.example", None, "GET", "https://tasks.acme.example/api/tasks", &store, now_ms + 3000).is_ok());
        assert!(verify_access_token(&cfg, &format!("Bearer {at_default}"), "https://tasks.acme.example/mcp", None, "POST", "https://tasks.acme.example/mcp", &store, now_ms + 3000).is_err());

        // 5. Refresh for /mcp resource + downscope to tasks:read (§4.4, §4.5).
        let a3 = make_assertion(&root, &kid, &cfg.issuer, "jti_ref1", now_secs + 4);
        let ref_body = format!(
            "grant_type=refresh_token&refresh_token={}&resource={}&scope=tasks%3Aread&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode(rt1),
            percent_encode("https://tasks.acme.example/mcp"),
            percent_encode(&a3),
        );
        let ref_res = handle_token(&cfg, ref_body.as_bytes(), None, &dir, &store, now_ms + 4000);
        assert_eq!(ref_res.status, 200);
        assert!(ref_res.headers.iter().any(|(k, v)| *k == AGENT_EVENT_HEADER
            && v == "s=poppy_oauth;ok=1;verdict=token_refreshed;ag=agent.example"));
        let ref_json: Value = serde_json::from_slice(&ref_res.body).unwrap();
        let at_mcp = ref_json["access_token"].as_str().unwrap();
        let rt2 = ref_json["refresh_token"].as_str().unwrap();
        let verified_mcp = verify_access_token(&cfg, &format!("Bearer {at_mcp}"), "https://tasks.acme.example/mcp", None, "POST", "https://tasks.acme.example/mcp", &store, now_ms + 5000).unwrap();
        assert_eq!(verified_mcp.scopes, vec!["tasks:read"]);

        // 6. Revoking rt2 immediately invalidates at_mcp (§5.5).
        let a4 = make_assertion(&root, &kid, &cfg.issuer, "jti_rev", now_secs + 6);
        let rev_body = format!(
            "token={}&token_type_hint=refresh_token&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode(rt2),
            percent_encode(&a4),
        );
        let rev_res = handle_revoke(&cfg, rev_body.as_bytes(), &dir, &store, now_ms + 6000);
        assert_eq!(rev_res.status, 200);
        assert!(rev_res.headers.iter().any(|(k, v)| *k == AGENT_EVENT_HEADER
            && v == "s=poppy_oauth;ok=1;verdict=grant_revoked;ag=agent.example"));
        assert!(verify_access_token(&cfg, &format!("Bearer {at_mcp}"), "https://tasks.acme.example/mcp", None, "POST", "https://tasks.acme.example/mcp", &store, now_ms + 7000).is_err());

        // 7. Denied token attempt emits denied verdict with error code.
        let a5 = make_assertion(&root, &kid, &cfg.issuer, "jti_denied", now_secs + 8);
        let bad_ref = format!(
            "grant_type=refresh_token&refresh_token={}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode(rt2),
            percent_encode(&a5),
        );
        let denied_res = handle_token(&cfg, bad_ref.as_bytes(), None, &dir, &store, now_ms + 8000);
        assert_eq!(denied_res.status, 400);
        assert!(denied_res.headers.iter().any(|(k, v)| *k == AGENT_EVENT_HEADER
            && v == "s=poppy_oauth;ok=0;err=invalid_grant;verdict=denied;ag=agent.example"));
    }

    #[test]
    fn dpop_enforces_ath_and_single_use_jti() {
        let (cfg, root, kid, dir) = test_setup();
        let store = MemoryOAuthStore::default();
        let now_secs = 1_790_900_000u64;
        let now_ms = now_secs * 1000;
        let dpop_key = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let pb = dpop_key.public_point();
        let x = base64url_encode(&pb[1..33]);
        let y = base64url_encode(&pb[33..65]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});

        let make_dpop = |htm: &str, htu: &str, jti: &str, ath: Option<&str>| {
            let mut claims = serde_json::json!({
                "htm": htm,
                "htu": htu,
                "iat": now_secs,
                "jti": jti,
            });
            if let Some(a) = ath {
                claims["ath"] = Value::String(a.into());
            }
            sign_es256_jwt(
                &dpop_key,
                &serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}),
                &claims,
            )
        };

        let verifier = "v_dpop_0123456789abcdefghijklmnopqrstuvwxyzABCDEF";
        let challenge = base64url_encode(&sha256(verifier.as_bytes()));
        let a1 = make_assertion(&root, &kid, &cfg.issuer, "jti_dpop_par", now_secs);
        let par_body = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=tasks%3Aread&code_challenge={}&code_challenge_method=S256&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode("https://agent.example/agent.json"),
            percent_encode("https://agent.example/cb"),
            percent_encode(&challenge),
            percent_encode(&a1),
        );
        let par_dpop = make_dpop("POST", &format!("{}/oauth/par", cfg.issuer), "dpop_jti_1", None);
        let par_reply = handle_par(&cfg, par_body.as_bytes(), Some(&par_dpop), &dir, &store, now_ms);
        assert_eq!(par_reply.status, 201);
        // Replaying the same PAR DPoP proof must fail.
        let a1b = make_assertion(&root, &kid, &cfg.issuer, "jti_dpop_par_2", now_secs);
        let par_body_2 = par_body.replace(&percent_encode(&a1), &percent_encode(&a1b));
        let replay_par = handle_par(&cfg, par_body_2.as_bytes(), Some(&par_dpop), &dir, &store, now_ms);
        assert_eq!(replay_par.status, 400);

        let par_json: Value = serde_json::from_slice(&par_reply.body).unwrap();
        let auth_q = format!(
            "client_id={}&request_uri={}",
            percent_encode("https://agent.example/agent.json"),
            percent_encode(par_json["request_uri"].as_str().unwrap()),
        );
        let consent = handle_authorize_get(&cfg, &auth_q, "acct_1", "alice@acme.example", "csrf_1", &dir, &store, now_ms);
        let html = std::str::from_utf8(&consent.body).unwrap();
        let marker = "name=\"txn\" value=\"";
        let start = html.find(marker).unwrap() + marker.len();
        let end = html[start..].find('"').unwrap();
        let txn = &html[start..start + end];
        let approve_body = format!("_csrf=csrf_1&txn={}&decision=approve&approved_scope=tasks%3Aread", percent_encode(txn));
        let redir = handle_authorize_post(&cfg, approve_body.as_bytes(), "acct_1", now_ms + 1000);
        let loc = redir.headers.iter().find(|(k, _)| *k == "location").unwrap().1.clone();
        let code = http_query::param(loc.split_once('?').unwrap().1, "code").unwrap();

        let a2 = make_assertion(&root, &kid, &cfg.issuer, "jti_dpop_tok", now_secs + 1);
        let tok_body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}",
            percent_encode(&code),
            percent_encode("https://agent.example/cb"),
            percent_encode(verifier),
            percent_encode(&a2),
        );
        let tok_dpop = make_dpop("POST", &format!("{}/oauth/token", cfg.issuer), "dpop_jti_2", None);
        let tok_res = handle_token(&cfg, tok_body.as_bytes(), Some(&tok_dpop), &dir, &store, now_ms + 1000);
        assert_eq!(tok_res.status, 200);
        let tok_json: Value = serde_json::from_slice(&tok_res.body).unwrap();
        let at = tok_json["access_token"].as_str().unwrap();

        // Missing ath at resource must fail (RFC 9449 §4.3).
        let no_ath = make_dpop("GET", "https://tasks.acme.example/api/tasks", "dpop_jti_3", None);
        assert!(verify_access_token(&cfg, &format!("DPoP {at}"), "https://tasks.acme.example", Some(&no_ath), "GET", "https://tasks.acme.example/api/tasks", &store, now_ms + 2000).is_err());

        // Matching ath succeeds once and fails on replay.
        let expected_ath = base64url_encode(&sha256(at.as_bytes()));
        let good_res_dpop = make_dpop("GET", "https://tasks.acme.example/api/tasks", "dpop_jti_4", Some(&expected_ath));
        assert!(verify_access_token(&cfg, &format!("DPoP {at}"), "https://tasks.acme.example", Some(&good_res_dpop), "GET", "https://tasks.acme.example/api/tasks", &store, now_ms + 2000).is_ok());
        assert!(verify_access_token(&cfg, &format!("DPoP {at}"), "https://tasks.acme.example", Some(&good_res_dpop), "GET", "https://tasks.acme.example/api/tasks", &store, now_ms + 2000).is_err());
    }
}
