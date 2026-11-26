//! Poppy 1.0 cryptographic Session header (`Poppy-Session`), delegation
//! (`poppy_dlg`), and Session continuity verification (§5.2, §5.3, §5.5).
//!
//! Uses `ferrite_app::crypto` (`es256_verify`, `p256_point`, `base64url_decode`,
//! `base64url_encode`, `sha256`) with zero additional Cargo dependencies.
//!
//! Verification supports both:
//! - **In-app verification** via an [`AgentKeyResolver`] (allowlisted or fetched
//!   Personal Agent metadata/JWKS, verifying `ES256` directly and dispatching `PS384`
//!   through a custom verifier hook), and
//! - **Gateway-attested verification** ([`GatewayPoppyContext`]) when the
//!   platform gateway verifies `Poppy-Session` at the edge.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use ferrite_app::crypto::{
    base64url_decode, base64url_encode, ct_eq, es256_verify, p256_point, sha256,
};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Value};
use ferrite_app::{EgressHandle, EgressHeader, EgressHttpMethod, EgressOutcome};

use crate::agent_ready::poppy::{
    check_poppy_version, is_https_url, is_valid_poppy_id, parse_extensions_header, PoppyError,
    PoppyVersion,
};

/// Maximum permitted delegation lifetime (§5.2: 24 hours).
pub const MAX_DELEGATION_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// Default acceptance window for Session JWT `iat` (§5.3, Guides: ~1 minute).
pub const DEFAULT_IAT_WINDOW_SECS: u64 = 60;
/// Default clock skew leeway (Guides: 30 seconds).
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 30;
/// Default TTL for egress-fetched Personal Agent metadata & JWKS cache entries (15 minutes).
pub const DEFAULT_AGENT_CACHE_TTL_MS: u64 = 15 * 60 * 1000;
/// Maximum accepted size for a Personal Agent `agent.json` or `jwks.json` response (64 KiB).
pub const MAX_AGENT_DOC_BYTES: usize = 64 * 1024;
/// Canonical Poppy 1.0 `client_id` for Meta Muse.
pub const MUSE_CLIENT_ID: &str = "https://muse.ai/poppy/agent.json";

/// A published Personal Agent bundled as a built-in fallback snapshot.
///
/// Apps with an outbound `egress` handle still refresh the agent's live
/// `client_id` metadata and `jwks_uri` on schedule (and immediately upon seeing
/// an unknown `kid`); this snapshot ensures zero-config first contact even
/// before the first refresh or in offline test harnesses.
#[derive(Debug, Clone, Copy)]
pub struct WellKnownAgent {
    pub client_id: &'static str,
    pub client_name: &'static str,
    pub jwks_uri: &'static str,
    pub agent_json: &'static str,
    pub jwks_json: &'static str,
}

/// Published Poppy 1.0 Personal Agents accepted out of the box.
pub const WELL_KNOWN_AGENTS: &[WellKnownAgent] = &[WellKnownAgent {
    client_id: MUSE_CLIENT_ID,
    client_name: "Muse",
    jwks_uri: "https://muse.ai/poppy/jwks.json",
    agent_json: r#"{"client_id":"https://muse.ai/poppy/agent.json","client_name":"Muse","logo_uri":"https://muse.ai/images/pwa_icons/any/512.png","jwks_uri":"https://muse.ai/poppy/jwks.json","redirect_uris":["https://muse.ai/api/hatch/oauth/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"private_key_jwt","dpop_bound_access_tokens":true,"extensions":{"operations":{"version":"2"}}}"#,
    jwks_json: r#"{"keys":[{"kty":"EC","crv":"P-256","x":"u8nbvPbQgYupbbnM_BqIySGkImL8mXoJPYxzW6pkMnM","y":"vbmtouGrOhleHLuu2S_QrmAN8YYNy0_3A5dYd3BfHls","kid":"8zN-5pZghBM7l6SEEpomZofjLCC8WiJqdt8lg_kV3CQ","use":"sig","alg":"ES256"},{"kty":"EC","crv":"P-256","x":"Y8K7SMSpLh5eB5wrxPfsx0xOt7PnUAt9QL3tyTqGvEc","y":"0Bpprt_w9jrSlvJ5CrjsImHnInx6HIW_f1TyQHKur3I","kid":"Pf97d3A2xr4Af7K0d8OUdDCui5iC3pPkDcz2thJ8zbI","use":"sig","alg":"ES256"}]}"#,
}];

/// Return the table of built-in published Poppy 1.0 Personal Agents.
pub fn well_known_agents() -> &'static [WellKnownAgent] {
    WELL_KNOWN_AGENTS
}

/// Cached Personal Agent CIMD metadata + JWKS fetched from `client_id` / `jwks_uri`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct CachedAgentEntry {
    pub client_id: String,
    pub client_name: String,
    pub jwks_uri: String,
    pub agent_json: String,
    pub jwks_json: String,
    pub fetched_at_ms: u64,
    pub expires_at_ms: u64,
}

impl CachedAgentEntry {
    pub fn is_fresh(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }

    pub fn to_metadata(&self) -> Result<AgentMetadata, String> {
        parse_agent_metadata(
            &self.client_id,
            self.agent_json.as_bytes(),
            self.jwks_json.as_bytes(),
        )
    }
}

/// Minimal HTTP GET abstraction used by [`fetch_agent_metadata`] so both
/// Ferrite Cloud's audited [`EgressHandle`] and deterministic test doubles
/// share one implementation.
pub trait AgentHttpFetcher {
    fn fetch_json(
        &mut self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<(u16, Vec<u8>), String>> + Send;
}

impl AgentHttpFetcher for EgressHandle {
    async fn fetch_json(&mut self, url: &str) -> Result<(u16, Vec<u8>), String> {
        let headers = [EgressHeader {
            name: "accept".into(),
            value: "application/json".into(),
        }];
        match self
            .deliver_http(EgressHttpMethod::Get, url, &headers, &[])
            .await
        {
            Ok(EgressOutcome::Delivered { status, body }) => Ok((status, body)),
            Ok(EgressOutcome::Denied { reason }) => {
                Err(format!("egress denied fetching {url}: {reason}"))
            }
            Err(e) => Err(format!("egress transport error fetching {url}: {e}")),
        }
    }
}

/// Fetch, validate (§4.1: `client_id == fetched URL`, same-domain `jwks_uri`,
/// public keys only), and wrap a Personal Agent's metadata and JWKS for caching.
pub async fn fetch_agent_metadata<F: AgentHttpFetcher>(
    fetcher: &mut F,
    client_id: &str,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<CachedAgentEntry, String> {
    if !is_https_url(client_id) {
        return Err("client_id must be an https:// URL".into());
    }
    let (status, agent_bytes) = fetcher.fetch_json(client_id).await?;
    if status != 200 {
        return Err(format!("client_id metadata returned HTTP {status}"));
    }
    if agent_bytes.len() > MAX_AGENT_DOC_BYTES {
        return Err("agent.json exceeds maximum allowed size".into());
    }
    let agent_doc: Value =
        serde_json::from_slice(&agent_bytes).map_err(|_| "agent.json is not valid JSON")?;
    if agent_doc.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err("client_id inside agent.json does not match fetched URL (§4.1)".into());
    }
    let jwks_uri = agent_doc
        .get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|u| is_https_url(u))
        .ok_or("agent.json missing https jwks_uri")?
        .to_string();
    if !same_host(client_id, &jwks_uri) {
        return Err("jwks_uri must be on the same domain as client_id (§4.1)".into());
    }

    let (jstatus, jwks_bytes) = fetcher.fetch_json(&jwks_uri).await?;
    if jstatus != 200 {
        return Err(format!("jwks_uri returned HTTP {jstatus}"));
    }
    if jwks_bytes.len() > MAX_AGENT_DOC_BYTES {
        return Err("jwks.json exceeds maximum allowed size".into());
    }

    let parsed = parse_agent_metadata(client_id, &agent_bytes, &jwks_bytes)?;
    let agent_json =
        String::from_utf8(agent_bytes).map_err(|_| "agent.json is not valid UTF-8")?;
    let jwks_json =
        String::from_utf8(jwks_bytes).map_err(|_| "jwks.json is not valid UTF-8")?;
    Ok(CachedAgentEntry {
        client_id: parsed.client_id,
        client_name: parsed.client_name,
        jwks_uri: parsed.jwks_uri,
        agent_json,
        jwks_json,
        fetched_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(ttl_ms.max(60_000)),
    })
}

/// Peek the unverified `(iss, delegation_kid)` from a `Poppy-Session` JWT so a
/// host app can refresh cached JWKS before cryptographic verification runs.
pub fn extract_session_iss_and_delegation_kid(raw_jwt: &str) -> Option<(String, String)> {
    let (hdr, claims, _, _) = parse_jwt_parts(raw_jwt.trim()).ok()?;
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| is_https_url(s))?
        .to_string();
    let raw_dlg = hdr.get("poppy_dlg").and_then(Value::as_str)?;
    let (dlg_hdr, _, _, _) = parse_jwt_parts(raw_dlg).ok()?;
    let kid = dlg_hdr
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    Some((iss, kid))
}

/// Peek the unverified `(iss, kid)` from an OAuth `private_key_jwt` `client_assertion`.
pub fn extract_assertion_iss_and_kid(raw_assertion: &str) -> Option<(String, String)> {
    let (hdr, claims, _, _) = parse_jwt_parts(raw_assertion.trim()).ok()?;
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| is_https_url(s))?
        .to_string();
    let kid = hdr
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    Some((iss, kid))
}

/// Verified Poppy Session attached to an inbound request after passing all
/// §5.2 / §5.3 checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct VerifiedSession {
    pub protocol_version: String,
    pub extensions: BTreeMap<String, String>,
    /// Personal Agent `client_id` HTTPS URL (`iss`).
    pub client_id: String,
    /// Session ID (`sid`).
    pub sid: String,
    /// Pairwise pseudonymous User ID (`sub`).
    pub sub: String,
    /// Optional Agent ID (`agent_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Delegated P-256 key JWK thumbprint (`kid`).
    pub delegated_kid: String,
    /// SHA-256 base64url hash of the bound access token (`ath`), when signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Authenticated Company account ID (populated once the access token is verified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Granted OAuth scopes (populated from the verified access token).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl VerifiedSession {
    /// True when the Personal Agent declared `name` at exact major version `version`
    /// in `Poppy-Extensions` (§3.3, §3.4).
    pub fn has_extension(&self, name: &str, version: &str) -> bool {
        self.extensions.get(name).map(String::as_str) == Some(version)
    }

    pub fn is_signed_in(&self) -> bool {
        self.account_id.is_some()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn has_all_scopes(&self, required: &[String]) -> bool {
        required.iter().all(|s| self.has_scope(s))
    }
}

/// A parsed public JWK from a Personal Agent's `jwks_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPublicKey {
    /// Uncompressed 65-byte SEC1 P-256 point (`0x04 || x || y`) for `ES256`.
    Es256 { kid: String, point: Vec<u8> },
    /// RSA public key `(n, e)` for `PS384` (RFC 9474 blind-signed delegations / assertions).
    Ps384 { kid: String, n: Vec<u8>, e: Vec<u8> },
}

impl AgentPublicKey {
    pub fn kid(&self) -> &str {
        match self {
            AgentPublicKey::Es256 { kid, .. } | AgentPublicKey::Ps384 { kid, .. } => kid,
        }
    }
}

/// Verified Personal Agent CIMD metadata + public keys (§4.1).
#[derive(Debug, Clone)]
pub struct AgentMetadata {
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: Option<String>,
    pub jwks_uri: String,
    pub redirect_uris: Vec<String>,
    pub keys: Vec<AgentPublicKey>,
}

/// Pluggable Personal Agent metadata/key resolver (static allowlist, egress-backed
/// cache, or test double).
pub trait AgentKeyResolver {
    fn resolve(&self, client_id: &str) -> Option<AgentMetadata>;

    /// Optional PS384 verifier hook (until `ferrite_app::crypto::ps384_verify` lands
    /// via Core proposal C1). Defaults to returning `false` (fails closed).
    fn verify_ps384(&self, _n: &[u8], _e: &[u8], _signing_input: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// Static allowlist directory of Personal Agents (zero egress, works on today's Core
/// and in unit/staging tests).
#[derive(Debug, Default, Clone)]
pub struct StaticAgentDirectory {
    agents: BTreeMap<String, AgentMetadata>,
}

impl StaticAgentDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a directory pre-populated with all built-in published Poppy 1.0
    /// Personal Agents (such as Meta Muse at `https://muse.ai/poppy/agent.json`).
    /// Apps can then overlay live egress-fetched cache entries and manual pins
    /// on top via [`insert`](Self::insert) or [`register_from_json`](Self::register_from_json).
    pub fn with_well_known_agents() -> Self {
        let mut dir = Self::new();
        for a in WELL_KNOWN_AGENTS {
            let _ = dir.register_from_json(
                a.client_id,
                a.agent_json.as_bytes(),
                a.jwks_json.as_bytes(),
            );
        }
        dir
    }

    pub fn insert(&mut self, meta: AgentMetadata) {
        self.agents.insert(meta.client_id.clone(), meta);
    }

    /// True if `client_id` is present and holds a public key matching `kid`.
    pub fn has_key(&self, client_id: &str, kid: &str) -> bool {
        self.agents
            .get(client_id)
            .is_some_and(|m| m.keys.iter().any(|k| k.kid() == kid))
    }

    /// Parse a Personal Agent's `agent.json` and `jwks.json` and register it after
    /// enforcing every §4.1 domain and field rule.
    pub fn register_from_json(
        &mut self,
        expected_client_id: &str,
        agent_json: &[u8],
        jwks_json: &[u8],
    ) -> Result<(), String> {
        let meta = parse_agent_metadata(expected_client_id, agent_json, jwks_json)?;
        self.insert(meta);
        Ok(())
    }
}

impl AgentKeyResolver for StaticAgentDirectory {
    fn resolve(&self, client_id: &str) -> Option<AgentMetadata> {
        self.agents.get(client_id).cloned()
    }
}

/// Parse and validate a Personal Agent's CIMD document and JWKS (§4.1).
pub fn parse_agent_metadata(
    expected_client_id: &str,
    agent_json: &[u8],
    jwks_json: &[u8],
) -> Result<AgentMetadata, String> {
    if !is_https_url(expected_client_id) {
        return Err("client_id must be an https:// URL".into());
    }
    let doc: Value = serde_json::from_slice(agent_json).map_err(|_| "invalid agent.json")?;
    let cid = doc
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("missing client_id")?;
    if cid != expected_client_id {
        return Err("client_id in document does not match fetched URL".into());
    }
    let client_name = doc
        .get("client_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("missing client_name")?
        .to_string();
    let logo_uri = match doc.get("logo_uri") {
        None | Some(Value::Null) => None,
        Some(Value::String(u)) if is_https_url(u) => Some(u.clone()),
        _ => return Err("logo_uri must be an https:// URL".into()),
    };
    let jwks_uri = doc
        .get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|u| is_https_url(u))
        .ok_or("missing or non-https jwks_uri")?
        .to_string();
    if !same_host(expected_client_id, &jwks_uri) {
        return Err("jwks_uri must be on the same domain as client_id (§4.1)".into());
    }
    let mut redirect_uris = Vec::new();
    if let Some(arr) = doc.get("redirect_uris").and_then(Value::as_array) {
        for item in arr {
            let uri = item.as_str().ok_or("redirect_uri must be string")?;
            if !is_valid_redirect_uri(expected_client_id, uri) {
                return Err(format!("invalid redirect_uri '{uri}' (§4.1)"));
            }
            redirect_uris.push(uri.to_string());
        }
    }
    let keys = parse_agent_jwks(jwks_json)?;
    if keys.is_empty() {
        return Err("jwks_uri holds no usable ES256 or PS384 public key".into());
    }
    Ok(AgentMetadata {
        client_id: cid.to_string(),
        client_name,
        logo_uri,
        jwks_uri,
        redirect_uris,
        keys,
    })
}

/// Parse `jwks.json` into ES256 / PS384 public keys, refusing private key material.
pub fn parse_agent_jwks(jwks_json: &[u8]) -> Result<Vec<AgentPublicKey>, String> {
    let doc: Value = serde_json::from_slice(jwks_json).map_err(|_| "invalid jwks.json")?;
    let keys_arr = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("jwks missing keys array")?;
    let mut out = Vec::new();
    for k in keys_arr {
        let Some(obj) = k.as_object() else { continue };
        // Reject private key fields if present.
        if obj.contains_key("d") || obj.contains_key("p") || obj.contains_key("q") {
            return Err("public JWKS must not contain private key parameters".into());
        }
        if obj.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") {
            continue;
        }
        let Some(kid) = obj.get("kid").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            continue;
        };
        let kty = obj.get("kty").and_then(Value::as_str).unwrap_or("");
        let alg = obj.get("alg").and_then(Value::as_str);
        match kty {
            "EC" => {
                if obj.get("crv").and_then(Value::as_str) != Some("P-256") {
                    continue;
                }
                if alg.is_some_and(|a| a != "ES256") {
                    continue;
                }
                let (Some(x), Some(y)) = (
                    obj.get("x").and_then(Value::as_str),
                    obj.get("y").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if let (Ok(xb), Ok(yb)) = (base64url_decode(x), base64url_decode(y)) {
                    if xb.len() == 32 && yb.len() == 32 {
                        let point = p256_point(&xb, &yb);
                        out.push(AgentPublicKey::Es256 {
                            kid: kid.to_string(),
                            point,
                        });
                    }
                }
            }
            "RSA" => {
                if alg.is_some_and(|a| a != "PS384") {
                    continue;
                }
                let (Some(n), Some(e)) = (
                    obj.get("n").and_then(Value::as_str),
                    obj.get("e").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if let (Ok(nb), Ok(eb)) = (base64url_decode(n), base64url_decode(e)) {
                    // Poppy guides: accept RSA keys of 2048 to 4096 bits (256..=512 bytes).
                    if (256..=512).contains(&nb.len()) && !eb.is_empty() {
                        out.push(AgentPublicKey::Ps384 {
                            kid: kid.to_string(),
                            n: nb,
                            e: eb,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let auth = rest.split(['/', '?', '#']).next()?;
    let lower = auth.to_ascii_lowercase();
    Some(lower.strip_suffix(":443").unwrap_or(&lower).to_string())
}

fn same_host(a: &str, b: &str) -> bool {
    matches!((host_of(a), host_of(b)), (Some(ha), Some(hb)) if ha == hb)
}

/// §4.1: HTTPS URL on the same domain as `client_id`, or RFC 8252 §7.3 loopback URI.
pub fn is_valid_redirect_uri(client_id: &str, uri: &str) -> bool {
    if is_https_url(uri) && same_host(client_id, uri) {
        return true;
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = if authority.starts_with('[') {
            authority.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
        } else {
            authority.split(':').next().unwrap_or("").to_ascii_lowercase()
        };
        return matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost");
    }
    false
}

/// Compute the RFC 7638 SHA-256 JWK thumbprint for an EC P-256 public key.
/// Canonical member order: `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`.
pub fn jwk_thumbprint_p256(x_b64url: &str, y_b64url: &str) -> String {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        x_b64url, y_b64url
    );
    base64url_encode(&sha256(canonical.as_bytes()))
}

/// Compute `ath` (`base64url(SHA-256(access_token))`) per RFC 9449 §4.2 and Poppy §5.2.
pub fn access_token_hash(access_token: &str) -> String {
    base64url_encode(&sha256(access_token.as_bytes()))
}

/// Verified access-token metadata supplied by the app's OAuth token verifier
/// before Session binding checks run (§5.3 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedToken {
    pub raw_token: String,
    pub client_id: String,
    pub account_id: String,
    pub scopes: Vec<String>,
}

/// Stored continuity state for one Poppy Session (§5.3, §5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct SessionRecord {
    pub client_id: String,
    pub sid: String,
    pub sub: String,
    pub agent_id: Option<String>,
    pub bound_account: Option<String>,
    pub protocol_version: String,
    pub extensions: BTreeMap<String, String>,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

/// Session store contract for continuity, ended-session tombstones (`session_ended`),
/// and optional delegated-key-to-User-ID pinning (§5.2, §5.3, §5.5).
pub trait PoppySessionStore {
    fn get_session(&self, client_id: &str, sid: &str) -> Option<SessionRecord>;
    fn put_session(&self, record: SessionRecord);
    fn is_ended(&self, client_id: &str, sid: &str) -> bool;
    fn end_session(&self, client_id: &str, sid: &str);
    /// Record or verify that a delegated key thumbprint signs for only one `sub` (§5.2, §10.7).
    /// Returns `false` if this `kid` was already observed signing for a different `sub`.
    fn check_delegated_key_user(&self, client_id: &str, kid: &str, sub: &str) -> bool;
}

/// In-memory [`PoppySessionStore`] for tests and single-instance benches.
#[derive(Default)]
pub struct MemorySessionStore {
    inner: Mutex<MemorySessionState>,
}

#[derive(Default)]
struct MemorySessionState {
    sessions: BTreeMap<(String, String), SessionRecord>,
    ended: BTreeSet<(String, String)>,
    key_users: BTreeMap<(String, String), String>,
}

impl PoppySessionStore for MemorySessionStore {
    fn get_session(&self, client_id: &str, sid: &str) -> Option<SessionRecord> {
        let guard = self.inner.lock().ok()?;
        guard
            .sessions
            .get(&(client_id.to_string(), sid.to_string()))
            .cloned()
    }

    fn put_session(&self, record: SessionRecord) {
        if let Ok(mut guard) = self.inner.lock() {
            guard
                .sessions
                .insert((record.client_id.clone(), record.sid.clone()), record);
        }
    }

    fn is_ended(&self, client_id: &str, sid: &str) -> bool {
        self.inner
            .lock()
            .ok()
            .is_some_and(|g| g.ended.contains(&(client_id.to_string(), sid.to_string())))
    }

    fn end_session(&self, client_id: &str, sid: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let key = (client_id.to_string(), sid.to_string());
            guard.sessions.remove(&key);
            guard.ended.insert(key);
        }
    }

    fn check_delegated_key_user(&self, client_id: &str, kid: &str, sub: &str) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        let key = (client_id.to_string(), kid.to_string());
        match guard.key_users.get(&key) {
            Some(existing) => existing == sub,
            None => {
                guard.key_users.insert(key, sub.to_string());
                true
            }
        }
    }
}

/// Input parameters for verifying a request's Poppy headers (§5.2, §5.3).
pub struct VerifyRequest<'a> {
    pub method: &'a str,
    /// Full canonical public URL WITHOUT query or fragment (`https://example.com/poppy/tasks`).
    pub canonical_htu: &'a str,
    /// Company identifier (§3.2): issuer URL or `https://{domain}`.
    pub company_identifier: &'a str,
    pub poppy_session_header: Option<&'a str>,
    pub poppy_version_header: Option<&'a str>,
    pub poppy_extensions_header: Option<&'a str>,
    pub presented_token: Option<&'a PresentedToken>,
    pub now_ms: u64,
    pub iat_window_secs: u64,
    pub clock_skew_secs: u64,
}

/// Verify `Poppy-Version`, `Poppy-Extensions`, `Poppy-Session`, its embedded
/// `poppy_dlg` delegation, access-token `ath` binding, and Session continuity (§5.2–5.5).
pub fn verify_session_request<R: AgentKeyResolver, S: PoppySessionStore>(
    req: &VerifyRequest<'_>,
    resolver: &R,
    store: &S,
) -> Result<VerifiedSession, PoppyError> {
    // §3.4: An endpoint that verifies the Session header MUST check Poppy-Version.
    let version: PoppyVersion = check_poppy_version(req.poppy_version_header)?;
    let version_str = format!("{}.{}", version.major, version.minor);
    let extensions = parse_extensions_header(req.poppy_extensions_header);

    let raw_jwt = req
        .poppy_session_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_session("missing Poppy-Session header"))?;

    let (hdr, claims, signing_input, sig) = parse_jwt_parts(raw_jwt)
        .map_err(|e| PoppyError::invalid_session(format!("malformed Session JWT: {e}")))?;

    // §5.2 header checks.
    if hdr.get("typ").and_then(Value::as_str) != Some("poppy-session+jwt") {
        return Err(PoppyError::invalid_session(
            "Session JWT typ must be poppy-session+jwt",
        ));
    }
    if hdr.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(PoppyError::invalid_session(
            "Session JWT alg must be ES256",
        ));
    }
    let session_kid = hdr
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing kid"))?;
    let raw_dlg = hdr
        .get("poppy_dlg")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing poppy_dlg delegation"))?;

    // Required Session JWT claims.
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| is_https_url(s))
        .ok_or_else(|| PoppyError::invalid_session("Session JWT iss must be an https:// URL"))?;
    let aud = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("Session JWT aud must be a single string"))?;
    let sid = claims
        .get("sid")
        .and_then(Value::as_str)
        .filter(|s| is_valid_poppy_id(s))
        .ok_or_else(|| PoppyError::invalid_session("Session JWT sid is missing or invalid"))?;
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| PoppyError::invalid_session("Session JWT sub is missing"))?;
    let agent_id = match claims.get("agent_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(v)) if !v.is_empty() && v.len() <= 256 => Some(v.clone()),
        _ => return Err(PoppyError::invalid_session("Session JWT agent_id invalid")),
    };
    let htm = claims
        .get("htm")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing htm"))?;
    let htu = claims
        .get("htu")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing htu"))?;
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing numeric iat"))?;
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_session("Session JWT missing jti"))?;
    let _ = jti;

    // Step 1: Resolve Personal Agent metadata & keys (§5.3 step 1).
    let meta = resolver.resolve(iss).ok_or_else(|| {
        PoppyError::invalid_session(format!(
            "Personal Agent client_id '{iss}' is not accepted on this deployment. Published agents (such as {MUSE_CLIENT_ID}) and egress-allowed agent metadata URLs are verified automatically; custom or unlisted agents can be added via the app's Poppy settings or egress policy."
        ))
    })?;

    // Step 2: Verify delegation (`poppy_dlg`) BEFORE verifying Session JWT (§5.2).
    let now_secs = req.now_ms / 1000;
    let delegated = verify_delegation(raw_dlg, iss, &meta, resolver, now_secs, req.clock_skew_secs)?;

    // Step 3: Verify Session JWT signature with delegated key and check `kid` thumbprint.
    if !ct_eq(session_kid.as_bytes(), delegated.thumbprint.as_bytes()) {
        return Err(PoppyError::invalid_session(
            "Session JWT kid does not match delegated key JWK thumbprint",
        ));
    }
    if !es256_verify(&delegated.p256_point, signing_input.as_bytes(), &sig) {
        return Err(PoppyError::invalid_session(
            "Session JWT signature verification failed",
        ));
    }
    // §5.2: Personal Agent MUST NOT sign a Session JWT after its delegation's exp.
    if iat > delegated.exp {
        return Err(PoppyError::invalid_session(
            "Session JWT iat is after its delegation expiry",
        ));
    }

    // Step 4: Verify aud, htm, htu, and iat window (§5.3 step 2).
    if aud != req.company_identifier {
        return Err(PoppyError::invalid_session(
            "Session JWT aud does not match Company identifier",
        ));
    }
    if !htm.eq_ignore_ascii_case(req.method) {
        return Err(PoppyError::invalid_session(
            "Session JWT htm does not match HTTP method",
        ));
    }
    if htu != req.canonical_htu {
        return Err(PoppyError::invalid_session(
            "Session JWT htu does not match request URL",
        ));
    }
    let min_iat = now_secs.saturating_sub(req.iat_window_secs + req.clock_skew_secs);
    let max_iat = now_secs.saturating_add(req.clock_skew_secs);
    if iat < min_iat || iat > max_iat {
        return Err(PoppyError::invalid_session(
            "Session JWT iat is outside the acceptance window",
        ));
    }

    // Step 5: Verify `ath` and token client binding (§5.3 step 3).
    let presented_ath = claims.get("ath").and_then(Value::as_str);
    let (account_id, scopes, ath) = match req.presented_token {
        Some(tok) => {
            if tok.client_id != iss {
                return Err(PoppyError::invalid_session(
                    "access token client_id does not match Session JWT iss",
                ));
            }
            let expected_ath = access_token_hash(&tok.raw_token);
            let actual_ath = presented_ath.ok_or_else(|| {
                PoppyError::invalid_session("signed-in Session JWT must include ath")
            })?;
            if !ct_eq(actual_ath.as_bytes(), expected_ath.as_bytes()) {
                return Err(PoppyError::invalid_session(
                    "Session JWT ath does not match access token",
                ));
            }
            (
                Some(tok.account_id.clone()),
                tok.scopes.clone(),
                Some(actual_ath.to_string()),
            )
        }
        None => {
            if claims.get("ath").is_some() {
                return Err(PoppyError::invalid_session(
                    "signed-out Session JWT must not include ath",
                ));
            }
            (None, Vec::new(), None)
        }
    };

    // §5.2 / §10.7: reject a delegated key reused across different User IDs.
    if !store.check_delegated_key_user(iss, &delegated.thumbprint, sub) {
        return Err(PoppyError::invalid_session(
            "delegated key already signed for a different User ID",
        ));
    }

    // Step 6: Session continuity & ended-session checks (§5.3 step 4, §5.4, §5.5).
    if store.is_ended(iss, sid) {
        return Err(PoppyError::session_ended("Session has ended"));
    }
    if let Some(mut existing) = store.get_session(iss, sid) {
        if existing.sub != sub || existing.agent_id != agent_id {
            return Err(PoppyError::invalid_session(
                "Session sub or agent_id changed within an existing Session",
            ));
        }
        if existing.protocol_version != version_str || existing.extensions != extensions {
            return Err(PoppyError::invalid_session(
                "Poppy-Version or Poppy-Extensions cannot change within a Session (§3.4)",
            ));
        }
        if let (Some(prev_acct), Some(cur_acct)) = (&existing.bound_account, &account_id) {
            if prev_acct != cur_acct {
                return Err(PoppyError::session_ended(
                    "Session cannot switch to a different account (§5.4)",
                ));
            }
        }
        if existing.bound_account.is_none() && account_id.is_some() {
            existing.bound_account = account_id.clone();
        }
        existing.last_seen_ms = req.now_ms;
        store.put_session(existing);
    } else {
        store.put_session(SessionRecord {
            client_id: iss.to_string(),
            sid: sid.to_string(),
            sub: sub.to_string(),
            agent_id: agent_id.clone(),
            bound_account: account_id.clone(),
            protocol_version: version_str.clone(),
            extensions: extensions.clone(),
            created_ms: req.now_ms,
            last_seen_ms: req.now_ms,
        });
    }

    Ok(VerifiedSession {
        protocol_version: version_str,
        extensions,
        client_id: iss.to_string(),
        sid: sid.to_string(),
        sub: sub.to_string(),
        agent_id,
        delegated_kid: delegated.thumbprint,
        ath,
        account_id,
        scopes,
    })
}

struct VerifiedDelegation {
    p256_point: Vec<u8>,
    thumbprint: String,
    exp: u64,
}

fn verify_delegation<R: AgentKeyResolver>(
    raw_dlg: &str,
    expected_iss: &str,
    meta: &AgentMetadata,
    resolver: &R,
    now_secs: u64,
    clock_skew_secs: u64,
) -> Result<VerifiedDelegation, PoppyError> {
    let (hdr, claims, signing_input, sig) = parse_jwt_parts(raw_dlg)
        .map_err(|e| PoppyError::invalid_session(format!("malformed delegation JWT: {e}")))?;

    if hdr.get("typ").and_then(Value::as_str) != Some("poppy-delegation+jwt") {
        return Err(PoppyError::invalid_session(
            "delegation typ must be poppy-delegation+jwt",
        ));
    }
    let alg = hdr
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("delegation missing alg"))?;
    let kid = hdr
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_session("delegation missing kid"))?;

    let key = meta
        .keys
        .iter()
        .find(|k| k.kid() == kid)
        .ok_or_else(|| PoppyError::invalid_session("delegation kid not found in jwks_uri"))?;

    let sig_ok = match (alg, key) {
        ("ES256", AgentPublicKey::Es256 { point, .. }) => {
            es256_verify(point, signing_input.as_bytes(), &sig)
        }
        ("PS384", AgentPublicKey::Ps384 { n, e, .. }) => {
            resolver.verify_ps384(n, e, signing_input.as_bytes(), &sig)
        }
        _ => {
            return Err(PoppyError::invalid_session(
                "delegation alg must be ES256 or PS384 matching jwks_uri key",
            ));
        }
    };
    if !sig_ok {
        return Err(PoppyError::invalid_session(
            "delegation signature verification failed",
        ));
    }

    if claims.get("iss").and_then(Value::as_str) != Some(expected_iss) {
        return Err(PoppyError::invalid_session(
            "delegation iss does not match Session JWT iss",
        ));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| PoppyError::invalid_session("delegation missing iat"))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| PoppyError::invalid_session("delegation missing exp"))?;
    if exp <= iat || exp - iat > MAX_DELEGATION_LIFETIME_SECS {
        return Err(PoppyError::invalid_session(
            "delegation lifetime must be >0 and <= 24 hours (§5.2)",
        ));
    }
    if now_secs >= exp.saturating_add(clock_skew_secs) {
        return Err(PoppyError::invalid_session("delegation has expired"));
    }
    if claims
        .get("jti")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(PoppyError::invalid_session("delegation missing jti"));
    }

    // Extract and validate `cnf.jwk` (must be public EC P-256, no private members).
    let jwk = claims
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(Value::as_object)
        .ok_or_else(|| PoppyError::invalid_session("delegation missing cnf.jwk"))?;
    if jwk.contains_key("d") {
        return Err(PoppyError::invalid_session(
            "delegation cnf.jwk must not contain private key parameter d",
        ));
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(PoppyError::invalid_session(
            "delegation cnf.jwk must be an EC P-256 key",
        ));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("delegation cnf.jwk missing x"))?;
    let y = jwk
        .get("y")
        .and_then(Value::as_str)
        .ok_or_else(|| PoppyError::invalid_session("delegation cnf.jwk missing y"))?;
    let xb = base64url_decode(x)
        .map_err(|_| PoppyError::invalid_session("delegation cnf.jwk x not base64url"))?;
    let yb = base64url_decode(y)
        .map_err(|_| PoppyError::invalid_session("delegation cnf.jwk y not base64url"))?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err(PoppyError::invalid_session(
            "delegation cnf.jwk coordinates must be 32 bytes each",
        ));
    }
    let point = p256_point(&xb, &yb);
    let thumbprint = jwk_thumbprint_p256(x, y);

    Ok(VerifiedDelegation {
        p256_point: point,
        thumbprint,
        exp,
    })
}

/// Verify a `private_key_jwt` OAuth client assertion (§4.1, RFC 7523bis).
/// Returns `(client_id, jti, exp)` on success.
pub fn verify_client_assertion<R: AgentKeyResolver>(
    raw_assertion: &str,
    expected_issuer: &str,
    resolver: &R,
    now_secs: u64,
    clock_skew_secs: u64,
) -> Result<(String, String, u64), String> {
    let (hdr, claims, signing_input, sig) = parse_jwt_parts(raw_assertion)?;
    let alg = hdr
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("client assertion missing alg")?;
    let kid = hdr
        .get("kid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("client assertion missing kid")?;

    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| is_https_url(s))
        .ok_or("client assertion iss must be https:// URL")?;
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or("client assertion missing sub")?;
    if sub != iss {
        return Err("client assertion sub must equal iss".into());
    }
    // §4.1: aud MUST be the Company's issuer as a single string (RFC 7523bis).
    let aud = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or("client assertion aud must be a single string naming the issuer")?;
    if aud != expected_issuer {
        return Err("client assertion aud does not match issuer".into());
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or("client assertion missing iat")?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or("client assertion missing exp")?;
    if exp <= iat || exp - iat > 300 {
        return Err("client assertion lifetime must be >0 and <= 5 minutes (§4.1)".into());
    }
    if now_secs >= exp.saturating_add(clock_skew_secs) {
        return Err("client assertion expired".into());
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("client assertion missing jti")?;

    let meta = resolver.resolve(iss).ok_or_else(|| {
        format!(
            "Personal Agent client_id '{iss}' is not accepted on this deployment. Published agents (such as {MUSE_CLIENT_ID}) and egress-allowed agent metadata URLs are verified automatically; custom or unlisted agents can be added via the app's Poppy settings or egress policy."
        )
    })?;
    let key = meta
        .keys
        .iter()
        .find(|k| k.kid() == kid)
        .ok_or("client assertion kid not found in jwks_uri")?;
    let ok = match (alg, key) {
        ("ES256", AgentPublicKey::Es256 { point, .. }) => {
            es256_verify(point, signing_input.as_bytes(), &sig)
        }
        ("PS384", AgentPublicKey::Ps384 { n, e, .. }) => {
            resolver.verify_ps384(n, e, signing_input.as_bytes(), &sig)
        }
        _ => return Err("client assertion alg must be ES256 or PS384".into()),
    };
    if !ok {
        return Err("client assertion signature invalid".into());
    }
    Ok((iss.to_string(), jti.to_string(), exp))
}

fn parse_jwt_parts(token: &str) -> Result<(Value, Value, &str, Vec<u8>), &'static str> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("expected three dot-separated segments");
    };
    let h_bytes = base64url_decode(h).map_err(|_| "header not base64url")?;
    let p_bytes = base64url_decode(p).map_err(|_| "payload not base64url")?;
    let sig = base64url_decode(s).map_err(|_| "signature not base64url")?;
    let hdr: Value = serde_json::from_slice(&h_bytes).map_err(|_| "header not JSON")?;
    let claims: Value = serde_json::from_slice(&p_bytes).map_err(|_| "payload not JSON")?;
    if !hdr.is_object() || !claims.is_object() {
        return Err("header and payload must be JSON objects");
    }
    if hdr.get("crit").is_some() || hdr.get("b64").is_some() {
        return Err("unsupported critical header parameter");
    }
    Ok((hdr, claims, &token[..h.len() + 1 + p.len()], sig))
}

/// Sign a compact ES256 JWT with custom `header` and `claims` — used by tests
/// and by Ferrite apps acting as Poppy Personal Agents.
pub fn sign_es256_jwt(
    key: &ferrite_app::crypto::EcdsaSigningKey,
    header: &Value,
    claims: &Value,
) -> String {
    let h = base64url_encode(header.to_string().as_bytes());
    let p = base64url_encode(claims.to_string().as_bytes());
    let input = format!("{h}.{p}");
    let sig = key.sign_es256(input.as_bytes());
    format!("{input}.{}", base64url_encode(&sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::crypto::EcdsaSigningKey;

    fn jwk_for_es256(key: &EcdsaSigningKey) -> (String, String, Value) {
        let pub_bytes = key.public_point();
        assert_eq!(pub_bytes.len(), 65);
        let x = base64url_encode(&pub_bytes[1..33]);
        let y = base64url_encode(&pub_bytes[33..65]);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });
        (x, y, jwk)
    }

    fn make_agent() -> (EcdsaSigningKey, String, StaticAgentDirectory) {
        let root = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let (rx, ry, _) = jwk_for_es256(&root);
        let root_kid = jwk_thumbprint_p256(&rx, &ry);
        let client_id = "https://agent.example/agent.json".to_string();
        let agent_json = serde_json::json!({
            "client_id": client_id,
            "client_name": "Test Agent",
            "jwks_uri": "https://agent.example/jwks.json",
            "redirect_uris": ["https://agent.example/callback"],
            "token_endpoint_auth_method": "private_key_jwt"
        });
        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": root_kid,
                "alg": "ES256",
                "use": "sig",
                "x": rx,
                "y": ry
            }]
        });
        let mut dir = StaticAgentDirectory::new();
        dir.register_from_json(
            &client_id,
            agent_json.to_string().as_bytes(),
            jwks_json.to_string().as_bytes(),
        )
        .unwrap();
        (root, root_kid, dir)
    }

    fn make_session_jwt(
        root: &EcdsaSigningKey,
        root_kid: &str,
        delegated: &EcdsaSigningKey,
        iss: &str,
        aud: &str,
        sid: &str,
        sub: &str,
        htm: &str,
        htu: &str,
        now_secs: u64,
        ath: Option<&str>,
    ) -> String {
        let (dx, dy, djwk) = jwk_for_es256(delegated);
        let dkid = jwk_thumbprint_p256(&dx, &dy);
        let dlg = sign_es256_jwt(
            root,
            &serde_json::json!({
                "alg": "ES256",
                "typ": "poppy-delegation+jwt",
                "kid": root_kid,
            }),
            &serde_json::json!({
                "iss": iss,
                "cnf": { "jwk": djwk },
                "iat": now_secs - 60,
                "exp": now_secs + 3600,
                "jti": "dlg_jti_1"
            }),
        );
        let mut claims = serde_json::json!({
            "iss": iss,
            "aud": aud,
            "sid": sid,
            "sub": sub,
            "htm": htm,
            "htu": htu,
            "iat": now_secs,
            "jti": "sess_jti_1"
        });
        if let Some(a) = ath {
            claims["ath"] = Value::String(a.into());
        }
        sign_es256_jwt(
            delegated,
            &serde_json::json!({
                "typ": "poppy-session+jwt",
                "alg": "ES256",
                "kid": dkid,
                "poppy_dlg": dlg
            }),
            &claims,
        )
    }

    #[test]
    fn valid_signed_out_and_signed_in_session_verification() {
        let (root, root_kid, dir) = make_agent();
        let del = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let store = MemorySessionStore::default();
        let now_secs = 1_790_900_000u64;
        let iss = "https://agent.example/agent.json";
        let company = "https://shop.example";
        let htu = "https://shop.example/poppy/tasks";

        let jwt = make_session_jwt(
            &root, root_kid.as_str(), &del, iss, company, "sid_1", "usr_A", "GET", htu, now_secs,
            None,
        );
        let verified = verify_session_request(
            &VerifyRequest {
                method: "GET",
                canonical_htu: htu,
                company_identifier: company,
                poppy_session_header: Some(&jwt),
                poppy_version_header: Some("1.0"),
                poppy_extensions_header: Some(r#""operations";v="3""#),
                presented_token: None,
                now_ms: now_secs * 1000,
                iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            },
            &dir,
            &store,
        )
        .unwrap();
        assert_eq!(verified.sid, "sid_1");
        assert_eq!(verified.sub, "usr_A");
        assert!(verified.has_extension("operations", "3"));

        // Rotate delegated key on the SAME session: must succeed (§5.2).
        let del2 = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let tok = PresentedToken {
            raw_token: "tok_secret_123".into(),
            client_id: iss.into(),
            account_id: "acct_1".into(),
            scopes: vec!["orders:read".into()],
        };
        let ath = access_token_hash(&tok.raw_token);
        let jwt2 = make_session_jwt(
            &root,
            &root_kid,
            &del2,
            iss,
            company,
            "sid_1",
            "usr_A",
            "POST",
            "https://shop.example/api/orders",
            now_secs + 5,
            Some(&ath),
        );
        let verified2 = verify_session_request(
            &VerifyRequest {
                method: "POST",
                canonical_htu: "https://shop.example/api/orders",
                company_identifier: company,
                poppy_session_header: Some(&jwt2),
                poppy_version_header: Some("1.0"),
                poppy_extensions_header: Some(r#""operations";v="3""#),
                presented_token: Some(&tok),
                now_ms: (now_secs + 5) * 1000,
                iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            },
            &dir,
            &store,
        )
        .unwrap();
        assert_eq!(verified2.account_id.as_deref(), Some("acct_1"));

        // Reusing del for a DIFFERENT sub must fail (§5.2, §10.7).
        let bad_sub = make_session_jwt(
            &root, &root_kid, &del, iss, company, "sid_other", "usr_B", "GET", htu, now_secs + 6,
            None,
        );
        let err = verify_session_request(
            &VerifyRequest {
                method: "GET",
                canonical_htu: htu,
                company_identifier: company,
                poppy_session_header: Some(&bad_sub),
                poppy_version_header: Some("1.0"),
                poppy_extensions_header: None,
                presented_token: None,
                now_ms: (now_secs + 6) * 1000,
                iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            },
            &dir,
            &store,
        )
        .unwrap_err();
        assert_eq!(err.error, "invalid_session");

        // Ending sid_1 causes subsequent requests to get `session_ended` (§5.5).
        store.end_session(iss, "sid_1");
        let ended_err = verify_session_request(
            &VerifyRequest {
                method: "POST",
                canonical_htu: "https://shop.example/api/orders",
                company_identifier: company,
                poppy_session_header: Some(&jwt2),
                poppy_version_header: Some("1.0"),
                poppy_extensions_header: Some(r#""operations";v="3""#),
                presented_token: Some(&tok),
                now_ms: (now_secs + 10) * 1000,
                iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            },
            &dir,
            &store,
        )
        .unwrap_err();
        assert_eq!(ended_err.error, "session_ended");
    }

    #[test]
    fn client_assertion_enforces_aud_issuer_and_lifetime() {
        let (root, root_kid, dir) = make_agent();
        let now_secs = 1_790_900_000u64;
        let iss = "https://agent.example/agent.json";
        let assertion = sign_es256_jwt(
            &root,
            &serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": root_kid}),
            &serde_json::json!({
                "iss": iss,
                "sub": iss,
                "aud": "https://auth.shop.example",
                "iat": now_secs,
                "exp": now_secs + 120,
                "jti": "jti_ok"
            }),
        );
        let (cid, jti, _) =
            verify_client_assertion(&assertion, "https://auth.shop.example", &dir, now_secs, 30)
                .unwrap();
        assert_eq!(cid, iss);
        assert_eq!(jti, "jti_ok");

        // Token endpoint URL in aud MUST be rejected (§4.1, RFC 7523bis).
        assert!(verify_client_assertion(
            &assertion,
            "https://auth.shop.example/oauth/token",
            &dir,
            now_secs,
            30
        )
        .is_err());
    }

    #[test]
    fn well_known_agents_includes_meta_muse_with_live_p256_keys() {
        let dir = StaticAgentDirectory::with_well_known_agents();
        let muse = dir
            .resolve(MUSE_CLIENT_ID)
            .expect("Meta Muse must be seeded in well-known agents");
        assert_eq!(muse.client_name, "Muse");
        assert_eq!(muse.jwks_uri, "https://muse.ai/poppy/jwks.json");
        assert!(muse
            .redirect_uris
            .iter()
            .any(|u| u == "https://muse.ai/api/hatch/oauth/callback"));
        assert!(muse.keys.len() >= 2);
        assert!(dir.has_key(MUSE_CLIENT_ID, "8zN-5pZghBM7l6SEEpomZofjLCC8WiJqdt8lg_kV3CQ"));
        assert!(dir.has_key(MUSE_CLIENT_ID, "Pf97d3A2xr4Af7K0d8OUdDCui5iC3pPkDcz2thJ8zbI"));
    }

    #[test]
    fn unknown_agent_error_gives_actionable_guidance_and_extract_helpers_work() {
        let (root, root_kid, _) = make_agent();
        let del = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let now_secs = 1_790_900_000u64;
        let iss = "https://unlisted.example/agent.json";
        let jwt = make_session_jwt(
            &root,
            &root_kid,
            &del,
            iss,
            "https://yoga.ferrite.run",
            "sid_x",
            "usr_x",
            "POST",
            "https://yoga.ferrite.run/poppy/conversations",
            now_secs,
            None,
        );
        let (peek_iss, peek_kid) = extract_session_iss_and_delegation_kid(&jwt).unwrap();
        assert_eq!(peek_iss, iss);
        assert_eq!(peek_kid, root_kid);

        let dir = StaticAgentDirectory::with_well_known_agents();
        let store = MemorySessionStore::default();
        let err = verify_session_request(
            &VerifyRequest {
                method: "POST",
                canonical_htu: "https://yoga.ferrite.run/poppy/conversations",
                company_identifier: "https://yoga.ferrite.run",
                poppy_session_header: Some(&jwt),
                poppy_version_header: Some("1.0"),
                poppy_extensions_header: None,
                presented_token: None,
                now_ms: now_secs * 1000,
                iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
                clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            },
            &dir,
            &store,
        )
        .unwrap_err();
        assert_eq!(err.error, "invalid_session");
        let desc = err.description.unwrap_or_default();
        assert!(desc.contains(iss), "got {desc}");
        assert!(desc.contains(MUSE_CLIENT_ID), "got {desc}");
    }

    struct StubFetcher(BTreeMap<String, (u16, Vec<u8>)>);
    impl AgentHttpFetcher for StubFetcher {
        async fn fetch_json(&mut self, url: &str) -> Result<(u16, Vec<u8>), String> {
            self.0
                .get(url)
                .cloned()
                .ok_or_else(|| format!("404 for {url}"))
        }
    }

    #[test]
    fn fetch_agent_metadata_enforces_cimd_and_same_domain_jwks() {
        let root = EcdsaSigningKey::from_pkcs8(&EcdsaSigningKey::generate_pkcs8()).unwrap();
        let (rx, ry, _) = jwk_for_es256(&root);
        let kid = jwk_thumbprint_p256(&rx, &ry);
        let cid = "https://sierra.example/poppy/agent.json";
        let jwks_url = "https://sierra.example/poppy/jwks.json";
        let good_agent = serde_json::json!({
            "client_id": cid,
            "client_name": "Sierra Personal Agent",
            "jwks_uri": jwks_url,
            "redirect_uris": ["https://sierra.example/oauth/cb"],
            "token_endpoint_auth_method": "private_key_jwt"
        });
        let good_jwks = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig", "x": rx, "y": ry }]
        });
        let bad_cross_domain = serde_json::json!({
            "client_id": "https://evil.example/agent.json",
            "client_name": "Cross Domain",
            "jwks_uri": "https://other.example/jwks.json",
            "redirect_uris": ["https://evil.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt"
        });

        let mut map = BTreeMap::new();
        map.insert(cid.into(), (200, good_agent.to_string().into_bytes()));
        map.insert(jwks_url.into(), (200, good_jwks.to_string().into_bytes()));
        map.insert(
            "https://evil.example/agent.json".into(),
            (200, bad_cross_domain.to_string().into_bytes()),
        );
        let mut fetcher = StubFetcher(map);

        struct NoopWake;
        impl std::task::Wake for NoopWake {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        fn poll_ready<F: std::future::Future>(fut: F) -> F::Output {
            let mut fut = std::pin::pin!(fut);
            let waker = std::task::Waker::from(std::sync::Arc::new(NoopWake));
            let mut cx = std::task::Context::from_waker(&waker);
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(v) => v,
                std::task::Poll::Pending => panic!("stub fetcher must resolve immediately"),
            }
        }

        let entry = poll_ready(fetch_agent_metadata(
            &mut fetcher,
            cid,
            10_000,
            DEFAULT_AGENT_CACHE_TTL_MS,
        ))
        .expect("valid CIMD + JWKS fetch succeeds");
        assert_eq!(entry.client_name, "Sierra Personal Agent");
        assert!(entry.is_fresh(10_000));
        assert!(!entry.is_fresh(10_000 + DEFAULT_AGENT_CACHE_TTL_MS));
        let meta = entry.to_metadata().unwrap();
        assert_eq!(meta.keys.len(), 1);

        // Cross-domain jwks_uri MUST be rejected before fetching jwks.
        let err = poll_ready(fetch_agent_metadata(
            &mut fetcher,
            "https://evil.example/agent.json",
            10_000,
            DEFAULT_AGENT_CACHE_TTL_MS,
        ))
        .unwrap_err();
        assert!(err.contains("same domain"), "got {err}");
    }
}
