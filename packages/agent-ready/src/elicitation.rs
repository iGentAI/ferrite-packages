//! Standalone MCP 2026-07-28 Elicitation and SEP-2322 `InputRequiredResult`.
//!
//! Lets any constrained Ferrite application pause a `tools/call` mid-flight to
//! ask the user for structured confirmation (form mode) or an out-of-band
//! browser action (URL mode — required by MCP for secrets, credentials, or
//! payments), then resume statelessly via an HMAC-SHA256 sealed `requestState`.
//!
//! Security invariants:
//! - Never send an elicitation mode the client did not declare in
//!   `_meta["io.modelcontextprotocol/clientCapabilities"]["elicitation"]`.
//! - Never ask for passwords, API keys, tokens, or payment details in form mode;
//!   use URL mode for sensitive interactions.
//! - Bind `requestState` to `(tool, canonical arguments digest, principal, nonce,
//!   expires_ms)` so a state token from one call or caller cannot replay onto
//!   another.

use std::collections::BTreeMap;

use ferrite_app::crypto::{base64url_decode, base64url_encode, ct_eq};
use ferrite_app::serde_json::{self, Map, Value};

pub const RESULT_INPUT_REQUIRED: &str = "input_required";
pub const METHOD_ELICITATION_CREATE: &str = "elicitation/create";
pub const MAX_REQUEST_STATE_BYTES: usize = 16 * 1024;
pub const MAX_INPUT_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Form,
    Url,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::Url => "url",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElicitationError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl ElicitationError {
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: msg.into(),
            data: None,
        }
    }

    pub fn missing_capability(mode: Mode) -> Self {
        let req = match mode {
            Mode::Form => serde_json::json!({"elicitation": {"form": {}}}),
            Mode::Url => serde_json::json!({"elicitation": {"url": {}}}),
        };
        Self {
            code: -32021,
            message: "Missing required client capability".into(),
            data: Some(serde_json::json!({"requiredCapabilities": req})),
        }
    }
}

/// Read declared elicitation capabilities from a 2026-07-28 `params` object.
/// Per MCP 2026-07-28, an empty `elicitation: {}` object declares form mode only.
pub fn client_supports(params: &Value, mode: Mode) -> bool {
    let Some(elicit) = params
        .pointer("/_meta/io.modelcontextprotocol~1clientCapabilities/elicitation")
        .and_then(Value::as_object)
    else {
        return false;
    };
    match mode {
        Mode::Form => elicit.is_empty() || elicit.get("form").is_some_and(Value::is_object),
        Mode::Url => elicit.get("url").is_some_and(Value::is_object),
    }
}

pub fn require_mode(params: &Value, mode: Mode) -> Result<(), ElicitationError> {
    if client_supports(params, mode) {
        Ok(())
    } else {
        Err(ElicitationError::missing_capability(mode))
    }
}

/// Validate a form-mode `requestedSchema`: flat object with primitive properties
/// (or multi-select string enum arrays), per MCP 2026-07-28 Elicitation.
pub fn validate_form_schema(schema: &Value) -> Result<(), &'static str> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err("requestedSchema.type must be \"object\"");
    }
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Err("requestedSchema.properties must be an object");
    };
    for prop in props.values() {
        let Some(prop_obj) = prop.as_object() else {
            return Err("each form property must be an object schema");
        };
        match prop_obj.get("type").and_then(Value::as_str) {
            Some("string") => {
                if let Some(fmt) = prop_obj.get("format").and_then(Value::as_str) {
                    if !matches!(fmt, "email" | "uri" | "date" | "date-time") {
                        return Err("unsupported string format in form schema");
                    }
                }
            }
            Some("integer" | "number" | "boolean") => {}
            Some("array") => {
                let items = prop_obj.get("items").unwrap_or(&Value::Null);
                let ok_enum = items.get("type").and_then(Value::as_str) == Some("string")
                    && items
                        .get("enum")
                        .and_then(Value::as_array)
                        .is_some_and(|vals| vals.iter().all(Value::is_string));
                let ok_any_of = items
                    .get("anyOf")
                    .and_then(Value::as_array)
                    .is_some_and(|opts| {
                        opts.iter()
                            .all(|o| o["const"].is_string() && o["title"].is_string())
                    });
                if !ok_enum && !ok_any_of {
                    return Err("array form properties must be multi-select string enums");
                }
            }
            _ => return Err("form schema properties must be primitive or string-enum arrays"),
        }
    }
    if let Some(req) = schema.get("required") {
        let Some(arr) = req.as_array() else {
            return Err("requestedSchema.required must be an array of strings");
        };
        if !arr.iter().all(|v| v.as_str().is_some_and(|k| props.contains_key(k))) {
            return Err("requestedSchema.required must name declared properties");
        }
    }
    Ok(())
}

/// Build a validated form-mode `elicitation/create` input request.
pub fn form_request(message: &str, requested_schema: Value) -> Result<Value, &'static str> {
    if message.trim().is_empty() {
        return Err("elicitation message must not be empty");
    }
    validate_form_schema(&requested_schema)?;
    Ok(serde_json::json!({
        "method": METHOD_ELICITATION_CREATE,
        "params": {
            "mode": "form",
            "message": message,
            "requestedSchema": requested_schema,
        }
    }))
}

/// Build a validated URL-mode `elicitation/create` input request.
/// URL mode MUST be used for secrets, credentials, payments, and external sign-in.
pub fn url_request(
    message: &str,
    url: &str,
    elicitation_id: &str,
) -> Result<Value, &'static str> {
    if message.trim().is_empty() {
        return Err("elicitation message must not be empty");
    }
    if elicitation_id.trim().is_empty() || elicitation_id.len() > 128 {
        return Err("elicitationId must be 1..=128 characters");
    }
    if !url.starts_with("https://") || url.len() > 2048 || url.bytes().any(|b| b < 0x21 || b == 0x7f)
    {
        return Err("URL-mode elicitation requires a clean https:// URL");
    }
    Ok(serde_json::json!({
        "method": METHOD_ELICITATION_CREATE,
        "params": {
            "mode": "url",
            "message": message,
            "url": url,
            "elicitationId": elicitation_id,
        }
    }))
}

/// Build an `InputRequiredResult` (`resultType: "input_required"`).
pub fn input_required_result(
    input_requests: Map<String, Value>,
    request_state: String,
) -> Result<Value, &'static str> {
    if input_requests.is_empty() || input_requests.len() > MAX_INPUT_REQUESTS {
        return Err("inputRequests must contain 1..=16 entries");
    }
    if request_state.is_empty() || request_state.len() > MAX_REQUEST_STATE_BYTES {
        return Err("requestState must be 1..=16384 bytes");
    }
    Ok(serde_json::json!({
        "resultType": RESULT_INPUT_REQUIRED,
        "inputRequests": Value::Object(input_requests),
        "requestState": request_state,
    }))
}

/// Canonical JSON serialization for JSON Schema instance equality (keys sorted,
/// whole-number floats normalized to integers so `1` and `1.0` hash identically).
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
                    out.push_str(&(f as i64).to_string());
                } else {
                    out.push_str(&n.to_string());
                }
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()));
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
    }
}

pub fn args_digest(args: &Value) -> String {
    super::sha256::to_hex(&super::sha256::sha256(canonical_json(args).as_bytes()))
}

/// Verified payload sealed inside an opaque HMAC-SHA256 `requestState`.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedState {
    pub tool: String,
    pub args_sha256: String,
    pub principal: String,
    pub nonce: String,
    pub expires_ms: u64,
    pub context: Value,
}

const STATE_DOMAIN: &[u8] = b"ferrite/mcp-request-state/v1:";

/// Single-use nonce tracker for replay protection on sealed `requestState` tokens.
///
/// Stateless HMAC verification (`open_state`) binds a token to `(tool, args, principal,
/// expiry)` but cannot alone stop replay within `expires_ms`. Hosts handling destructive or
/// charged actions should verify via [`open_state_once`] backed by a durable or bounded
/// in-memory `NonceStore`.
pub trait NonceStore {
    /// Record `nonce` until `expires_ms`. Returns `true` if `nonce` was unused and is now
    /// consumed; returns `false` if it was already consumed.
    fn consume(&mut self, nonce: &str, expires_ms: u64, now_ms: u64) -> bool;
}

/// Bounded, TTL-pruned in-memory [`NonceStore`] for single-instance hosts and tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryNonceStore {
    seen: BTreeMap<String, u64>,
    max_entries: usize,
}

impl MemoryNonceStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            max_entries: max_entries.max(1),
        }
    }
}

impl NonceStore for MemoryNonceStore {
    fn consume(&mut self, nonce: &str, expires_ms: u64, now_ms: u64) -> bool {
        self.seen.retain(|_, exp| *exp > now_ms);
        if self.seen.contains_key(nonce) {
            return false;
        }
        while self.seen.len() >= self.max_entries {
            if let Some(oldest_key) = self
                .seen
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&oldest_key);
            } else {
                break;
            }
        }
        self.seen.insert(nonce.to_string(), expires_ms);
        true
    }
}

/// Seal a `SealedState` into an opaque `requestState` string (`<b64url>.<hmac>`)
/// bound to the Elicitation HMAC domain.
pub fn seal_state(secret: &[u8], state: &SealedState) -> Result<String, &'static str> {
    seal_state_with_domain(secret, STATE_DOMAIN, state)
}

pub(crate) fn seal_state_with_domain(
    secret: &[u8],
    domain: &[u8],
    state: &SealedState,
) -> Result<String, &'static str> {
    if secret.is_empty() {
        return Err("sealing secret must not be empty");
    }
    let payload = serde_json::json!({
        "v": 1,
        "t": state.tool,
        "a": state.args_sha256,
        "p": state.principal,
        "n": state.nonce,
        "e": state.expires_ms,
        "c": state.context,
    });
    let raw = serde_json::to_vec(&payload).map_err(|_| "failed to encode requestState")?;
    let body_b64 = base64url_encode(&raw);
    let mac = super::hmac::hmac_sha256_concat(secret, &[domain, body_b64.as_bytes()]);
    let token = format!("{body_b64}.{}", base64url_encode(&mac));
    if token.len() > MAX_REQUEST_STATE_BYTES {
        return Err("sealed requestState exceeds 16 KiB limit");
    }
    Ok(token)
}

/// Verify and unseal an Elicitation `requestState` string against the retried call's
/// tool, arguments, principal, and current clock.
///
/// Note: `open_state` verifies authenticity, binding, and expiry, but is stateless; call
/// [`open_state_once`] (or consume `state.nonce` durably) to prevent replay within `expires_ms`.
pub fn open_state(
    secret: &[u8],
    token: &str,
    expected_tool: &str,
    expected_args: &Value,
    expected_principal: &str,
    now_ms: u64,
) -> Result<SealedState, ElicitationError> {
    let state = open_state_with_domain(
        secret,
        STATE_DOMAIN,
        token,
        expected_tool,
        expected_args,
        expected_principal,
        now_ms,
    )?;
    if state.context.get("uploadIssued") == Some(&Value::Bool(true)) {
        return Err(ElicitationError::invalid_params(
            "requestState belongs to a file upload, not elicitation",
        ));
    }
    Ok(state)
}

/// Verify, unseal, and consume the single-use `nonce` of an Elicitation `requestState`.
pub fn open_state_once(
    secret: &[u8],
    token: &str,
    expected_tool: &str,
    expected_args: &Value,
    expected_principal: &str,
    now_ms: u64,
    nonces: &mut impl NonceStore,
) -> Result<SealedState, ElicitationError> {
    let state = open_state(
        secret,
        token,
        expected_tool,
        expected_args,
        expected_principal,
        now_ms,
    )?;
    if state.nonce.is_empty() || !nonces.consume(&state.nonce, state.expires_ms, now_ms) {
        return Err(ElicitationError::invalid_params(
            "requestState nonce has already been consumed",
        ));
    }
    Ok(state)
}

pub(crate) fn open_state_with_domain(
    secret: &[u8],
    domain: &[u8],
    token: &str,
    expected_tool: &str,
    expected_args: &Value,
    expected_principal: &str,
    now_ms: u64,
) -> Result<SealedState, ElicitationError> {
    if secret.is_empty() || token.is_empty() || token.len() > MAX_REQUEST_STATE_BYTES {
        return Err(ElicitationError::invalid_params("invalid requestState"));
    }
    let Some((body_b64, sig_b64)) = token.split_once('.') else {
        return Err(ElicitationError::invalid_params("malformed requestState"));
    };
    let expected_mac = super::hmac::hmac_sha256_concat(secret, &[domain, body_b64.as_bytes()]);
    let presented_mac = base64url_decode(sig_b64)
        .map_err(|_| ElicitationError::invalid_params("malformed requestState signature"))?;
    if presented_mac.len() != expected_mac.len() || !ct_eq(&presented_mac, &expected_mac) {
        return Err(ElicitationError::invalid_params(
            "requestState signature verification failed",
        ));
    }
    let raw = base64url_decode(body_b64)
        .map_err(|_| ElicitationError::invalid_params("malformed requestState payload"))?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|_| ElicitationError::invalid_params("invalid requestState JSON"))?;
    if v["v"].as_u64() != Some(1) {
        return Err(ElicitationError::invalid_params(
            "unsupported requestState version",
        ));
    }
    let tool = v["t"]
        .as_str()
        .ok_or_else(|| ElicitationError::invalid_params("requestState missing tool"))?
        .to_string();
    let args_sha256 = v["a"]
        .as_str()
        .ok_or_else(|| ElicitationError::invalid_params("requestState missing args digest"))?
        .to_string();
    let principal = v["p"]
        .as_str()
        .ok_or_else(|| ElicitationError::invalid_params("requestState missing principal"))?
        .to_string();
    let nonce = v["n"]
        .as_str()
        .ok_or_else(|| ElicitationError::invalid_params("requestState missing nonce"))?
        .to_string();
    let expires_ms = v["e"]
        .as_u64()
        .ok_or_else(|| ElicitationError::invalid_params("requestState missing expiry"))?;
    if now_ms >= expires_ms {
        return Err(ElicitationError::invalid_params("requestState expired"));
    }
    if tool != expected_tool {
        return Err(ElicitationError::invalid_params(
            "requestState tool mismatch",
        ));
    }
    if principal != expected_principal {
        return Err(ElicitationError::invalid_params(
            "requestState principal mismatch",
        ));
    }
    if args_sha256 != args_digest(expected_args) {
        return Err(ElicitationError::invalid_params(
            "requestState arguments mismatch",
        ));
    }
    Ok(SealedState {
        tool,
        args_sha256,
        principal,
        nonce,
        expires_ms,
        context: v["c"].clone(),
    })
}

/// Parsed answer to one `elicitation/create` input request.
#[derive(Clone, Debug, PartialEq)]
pub enum ElicitationAnswer {
    Accept(Map<String, Value>),
    Decline,
    Cancel,
}

/// Extract and validate the user's elicitation answer for `key` from `params["inputResponses"]`.
pub fn parse_answer(params: &Value, key: &str) -> Result<ElicitationAnswer, ElicitationError> {
    let Some(responses) = params.get("inputResponses").and_then(Value::as_object) else {
        return Err(ElicitationError::invalid_params(
            "inputResponses must be an object",
        ));
    };
    let Some(entry) = responses.get(key).and_then(Value::as_object) else {
        return Err(ElicitationError::invalid_params(format!(
            "missing elicitation answer for '{key}'"
        )));
    };
    if entry.contains_key("jsonrpc") {
        return Err(ElicitationError::invalid_params(
            "inputResponses entries must be result objects, not JSON-RPC envelopes",
        ));
    }
    match entry.get("action").and_then(Value::as_str) {
        Some("accept") => {
            let content = match entry.get("content") {
                None => Map::new(),
                Some(Value::Object(m)) => m.clone(),
                Some(_) => {
                    return Err(ElicitationError::invalid_params(
                        "elicitation accept content must be an object",
                    ));
                }
            };
            Ok(ElicitationAnswer::Accept(content))
        }
        Some("decline") => Ok(ElicitationAnswer::Decline),
        Some("cancel") => Ok(ElicitationAnswer::Cancel),
        _ => Err(ElicitationError::invalid_params(
            "elicitation action must be accept, decline, or cancel",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json::json;

    #[test]
    fn capability_detection_matches_2026_07_28_spec() {
        let empty_elicit = json!({
            "_meta": {"io.modelcontextprotocol/clientCapabilities": {"elicitation": {}}}
        });
        assert!(client_supports(&empty_elicit, Mode::Form));
        assert!(!client_supports(&empty_elicit, Mode::Url));

        let both = json!({
            "_meta": {"io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}, "url": {}}}}
        });
        assert!(client_supports(&both, Mode::Form));
        assert!(client_supports(&both, Mode::Url));

        let none = json!({"_meta": {"io.modelcontextprotocol/clientCapabilities": {}}});
        assert!(!client_supports(&none, Mode::Form));
        assert_eq!(require_mode(&none, Mode::Url).unwrap_err().code, -32021);
    }

    #[test]
    fn form_and_url_requests_enforce_spec_rules() {
        let form = form_request(
            "Confirm taking my-app offline",
            json!({
                "type": "object",
                "properties": {
                    "app": {"type": "string", "title": "App name"},
                    "confirm": {"type": "boolean"}
                },
                "required": ["app", "confirm"]
            }),
        )
        .unwrap();
        assert_eq!(form["method"], "elicitation/create");
        assert_eq!(form["params"]["mode"], "form");

        // Nested objects are forbidden by MCP flat-object form rule.
        assert!(form_request(
            "Nested",
            json!({"type": "object", "properties": {"x": {"type": "object"}}})
        )
        .is_err());

        let url = url_request(
            "Enter API key in Dashboard",
            "https://dashboard.ferrite.cloud/a/acct/apps/demo/settings",
            "elicit-1",
        )
        .unwrap();
        assert_eq!(url["params"]["mode"], "url");
        assert!(url_request("Bad", "http://insecure.example", "id").is_err());
    }

    #[test]
    fn sealed_state_binds_tool_canonical_args_principal_and_expiry() {
        let secret = b"test-secret-32-bytes-0123456789ab";
        let args1 = json!({"b": 1, "a": "x"});
        let args2 = json!({"a": "x", "b": 1.0});
        assert_eq!(args_digest(&args1), args_digest(&args2));

        let state = SealedState {
            tool: "withdraw".into(),
            args_sha256: args_digest(&args1),
            principal: "acct-1".into(),
            nonce: "nonce-123".into(),
            expires_ms: 10_000,
            context: json!({"step": "confirm"}),
        };
        let token = seal_state(secret, &state).unwrap();
        let opened = open_state(secret, &token, "withdraw", &args2, "acct-1", 5_000).unwrap();
        assert_eq!(opened, state);

        assert!(open_state(secret, &token, "other", &args2, "acct-1", 5_000).is_err());
        assert!(open_state(secret, &token, "withdraw", &args2, "acct-2", 5_000).is_err());
        assert!(open_state(secret, &token, "withdraw", &json!({"a": "y"}), "acct-1", 5_000).is_err());
        assert!(open_state(secret, &token, "withdraw", &args2, "acct-1", 10_000).is_err());
        assert!(open_state(b"wrong", &token, "withdraw", &args2, "acct-1", 5_000).is_err());

        // Single-use nonce consumption blocks 15-minute replay attacks.
        let mut nonces = MemoryNonceStore::new(16);
        assert!(open_state_once(secret, &token, "withdraw", &args2, "acct-1", 5_000, &mut nonces).is_ok());
        assert!(open_state_once(secret, &token, "withdraw", &args2, "acct-1", 5_001, &mut nonces).is_err());
    }

    #[test]
    fn parse_answer_distinguishes_accept_decline_cancel() {
        let p = json!({
            "inputResponses": {
                "confirm": {"action": "accept", "content": {"app": "demo"}}
            }
        });
        assert_eq!(
            parse_answer(&p, "confirm").unwrap(),
            ElicitationAnswer::Accept(
                json!({"app": "demo"}).as_object().unwrap().clone()
            )
        );
        assert_eq!(
            parse_answer(&json!({"inputResponses": {"c": {"action": "decline"}}}), "c").unwrap(),
            ElicitationAnswer::Decline
        );
        assert_eq!(
            parse_answer(&json!({"inputResponses": {"c": {"action": "cancel"}}}), "c").unwrap(),
            ElicitationAnswer::Cancel
        );
        assert!(parse_answer(
            &json!({"inputResponses": {"c": {"jsonrpc": "2.0", "result": {}}}}),
            "c"
        )
        .is_err());
    }
}
