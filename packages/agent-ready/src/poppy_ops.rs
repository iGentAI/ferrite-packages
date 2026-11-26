//! Poppy `operations` v3 extension: exact-terms confirmation and at-most-once
//! execution across REST APIs, MCP tools, Conversations, and Websites.
//!
//! Unapproved operations require zero storage: the `revision` is computed
//! deterministically as `{expires_unix}-{hmac}` over canonical terms, action
//! fingerprint, and who may approve it (Poppy Guides, "Operations"). Once
//! approved, [`OperationStore`] enforces at-most-once execution until `expires_at`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ferrite_app::crypto::{base64url_encode, ct_eq, hmac_sha256, Ed25519SigningKey};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Value};

use crate::agent_ready::artefacts::civil_date;
use crate::agent_ready::poppy::{
    format_operation_header, is_valid_poppy_id, Alternative, ApprovalPolicy, ApprovalSubmission,
    EXT_OPERATIONS, EXT_OPERATIONS_VERSION,
};
use crate::agent_ready::poppy_verify::VerifiedSession;

/// MCP `_meta` key for sending an `operations` v3 approval (`operations` §6).
pub const MCP_APPROVAL_META_KEY: &str = "personalagentprotocol.org/approval";

/// Operation object returned to Personal Agents (`operation.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct OperationOffer {
    pub operation_id: String,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub terms: Value,
    pub expires_at: String,
}

/// Action descriptor fed into stateless revision computation.
#[derive(Debug, Clone)]
pub struct ActionSpec<'a> {
    /// Interface channel: `"api"`, `"mcp"`, `"conversation"`, or `"web"`.
    /// Prevents approving a website operation at an API or vice versa (Operations §6).
    pub channel: &'a str,
    /// Stable action identifier (e.g. `"POST /api/orders/1/cancel"` or `"mcp:delete_task"`).
    pub action: &'a str,
    /// Structured JSON object terms shown to the User (`terms` MUST be a JSON object).
    pub terms: Value,
    /// Optional plain-language summary (Basic CommonMark only, no links/HTML).
    pub summary: Option<String>,
    /// Canonical request parameters affecting the action (included in HMAC even if omitted from terms).
    pub fingerprint: Value,
}

/// Who may approve and consume an operation (Operations §3: "Who can approve it").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct OperationOwner {
    pub client_id: String,
    pub sub: String,
    /// `None` for signed-out operations; `Some(account_id)` for signed-in operations.
    pub account_id: Option<String>,
}

impl OperationOwner {
    pub fn from_session(session: &VerifiedSession) -> Self {
        Self {
            client_id: session.client_id.clone(),
            sub: session.sub.clone(),
            account_id: session.account_id.clone(),
        }
    }
}

/// Lifecycle state of an approved or performed operation (`OperationStore`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum OperationState {
    /// Recorded approval waiting for browser re-submission (Websites §6).
    Approved {
        owner: OperationOwner,
        revision: String,
        channel: String,
        expires_at_secs: u64,
        approval: ApprovalSubmission,
    },
    /// Currently executing (or uncertain downstream outcome): retries MUST return 503 + Retry-After.
    Performing {
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
    },
    /// Executed once: retries with this operation's approval return the first result verbatim.
    Performed {
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
        status: u16,
        body: Value,
        approval: ApprovalSubmission,
    },
}

/// Store contract for at-most-once execution and website approval recording (Operations §6–7).
pub trait OperationStore {
    fn get(&self, operation_id: &str) -> Option<OperationState>;
    /// Atomically insert `Performing` if absent (or transition `Approved` -> `Performing`).
    /// Returns `Ok(())` when this caller won the right to execute, or `Err(existing)` otherwise.
    fn try_begin_perform(
        &self,
        operation_id: &str,
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
    ) -> Result<(), OperationState>;
    fn mark_performed(
        &self,
        operation_id: &str,
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
        status: u16,
        body: Value,
        approval: ApprovalSubmission,
    );
    /// Release an in-flight `Performing` lock when execution fails definitively before committing
    /// side effects, so retries are not stranded in `503 operation_in_progress`.
    fn abort_perform(&self, _operation_id: &str, _owner: &OperationOwner, _revision: &str) {}

    fn record_website_approval(&self, operation_id: &str, state: OperationState) -> Result<(), OperationState>;
}

/// In-memory [`OperationStore`] for tests and single-instance deployments.
#[derive(Default)]
pub struct MemoryOperationStore {
    inner: Mutex<BTreeMap<String, OperationState>>,
}

impl OperationStore for MemoryOperationStore {
    fn get(&self, operation_id: &str) -> Option<OperationState> {
        self.inner.lock().ok()?.get(operation_id).cloned()
    }

    fn try_begin_perform(
        &self,
        operation_id: &str,
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
    ) -> Result<(), OperationState> {
        let mut guard = self.inner.lock().expect("operation store lock");
        match guard.get(operation_id) {
            None => {
                guard.insert(
                    operation_id.to_string(),
                    OperationState::Performing {
                        owner,
                        revision,
                        expires_at_secs,
                    },
                );
                Ok(())
            }
            Some(OperationState::Approved {
                owner: a_owner,
                revision: a_rev,
                ..
            }) if a_owner == &owner && a_rev == &revision => {
                guard.insert(
                    operation_id.to_string(),
                    OperationState::Performing {
                        owner,
                        revision,
                        expires_at_secs,
                    },
                );
                Ok(())
            }
            Some(existing) => Err(existing.clone()),
        }
    }

    fn mark_performed(
        &self,
        operation_id: &str,
        owner: OperationOwner,
        revision: String,
        expires_at_secs: u64,
        status: u16,
        body: Value,
        approval: ApprovalSubmission,
    ) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(
                operation_id.to_string(),
                OperationState::Performed {
                    owner,
                    revision,
                    expires_at_secs,
                    status,
                    body,
                    approval,
                },
            );
        }
    }

    fn abort_perform(&self, operation_id: &str, owner: &OperationOwner, revision: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let matches_performing = matches!(
                guard.get(operation_id),
                Some(OperationState::Performing {
                    owner: existing_owner,
                    revision: existing_rev,
                    ..
                }) if existing_owner == owner && existing_rev == revision
            );
            if matches_performing {
                guard.remove(operation_id);
            }
        }
    }

    fn record_website_approval(
        &self,
        operation_id: &str,
        state: OperationState,
    ) -> Result<(), OperationState> {
        let mut guard = self.inner.lock().expect("operation store lock");
        if let Some(existing) = guard.get(operation_id) {
            return Err(existing.clone());
        }
        guard.insert(operation_id.to_string(), state);
        Ok(())
    }
}

/// Outcome of evaluating an `operations` v3 gate before executing an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationGateOutcome {
    /// Approval is valid and this caller holds the exclusive `Performing` lock;
    /// execute the action and call [`OperationStore::mark_performed`].
    Execute {
        operation_id: String,
        revision: String,
        expires_at_secs: u64,
        approval: ApprovalSubmission,
    },
    /// Operation was already performed; return the cached original result (at-most-once).
    ReplayPerformed { status: u16, body: Value },
    /// Operation is currently executing; answer 503 + `Retry-After`.
    InProgress { retry_after_secs: u64 },
    /// No valid approval (missing, expired, or terms changed); refuse with `approval_required`.
    ApprovalRequired(OperationOffer),
    /// Approval was declined by policy (e.g. `approver="agent"` when `require_user_approver=true`).
    Declined {
        operation_id: String,
        revision: String,
        reason: Option<String>,
        alternative: Option<Alternative>,
    },
    /// Caller did not declare `"operations";v="3"` in `Poppy-Extensions` (Operations §2).
    ExtensionRequired,
}

/// Evaluate an `operations` v3 gate for an API, MCP tool, or Conversation action.
///
/// Follows the exact check order required by Operations §6 ("What the Company checks"):
/// 1. Check Session declared `"operations";v="3"`.
/// 2. Check ownership (if an approval was presented).
/// 3. Check whether already `Performing` or `Performed` (at-most-once §7).
/// 4. Recompute revision HMAC for current terms and check expiry; on mismatch, return
///    a fresh revision keeping the same `operation_id` (and never returning the revision
///    the caller just sent).
/// 5. Check policy (`require_user_approver`), declining with `approval_declined` if refused.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_gate<S: OperationStore>(
    secret: &[u8],
    policy: ApprovalPolicy,
    session: &VerifiedSession,
    spec: &ActionSpec<'_>,
    presented: Option<&ApprovalSubmission>,
    store: &S,
    now_ms: u64,
) -> OperationGateOutcome {
    let ApprovalPolicy::Required {
        ttl_secs,
        require_user_approver,
    } = policy
    else {
        return OperationGateOutcome::Declined {
            operation_id: String::new(),
            revision: String::new(),
            reason: Some("Approval policy is not configured for this operation.".into()),
            alternative: None,
        };
    };

    if !session.has_extension(EXT_OPERATIONS, EXT_OPERATIONS_VERSION) {
        return OperationGateOutcome::ExtensionRequired;
    }

    let now_secs = now_ms / 1000;
    let owner = OperationOwner::from_session(session);

    if let Some(apr) = presented {
        if is_valid_poppy_id(&apr.operation_id)
            && is_valid_poppy_id(&apr.revision)
            && matches!(apr.approver.as_str(), "user" | "agent")
        {
            // Check 2 (at-most-once) & Check 1 (ownership) for any stored record.
            if let Some(existing) = store.get(&apr.operation_id) {
                match existing {
                    OperationState::Performed {
                        owner: ref o,
                        status,
                        body,
                        ..
                    } if o == &owner => {
                        return OperationGateOutcome::ReplayPerformed { status, body };
                    }
                    OperationState::Performing { owner: ref o, .. } if o == &owner => {
                        return OperationGateOutcome::InProgress { retry_after_secs: 2 };
                    }
                    OperationState::Performed { .. } | OperationState::Performing { .. } => {
                        // Different owner: treat as if request had no approval (Operations §6 check 1).
                        let offer = mint_offer(secret, &owner, spec, None, now_secs, ttl_secs);
                        return OperationGateOutcome::ApprovalRequired(offer);
                    }
                    OperationState::Approved { .. } => {}
                }
            }

            // Check 3: verify revision HMAC and expiry against current terms.
            if let Some(expires_at_secs) =
                verify_revision(secret, &owner, spec, &apr.operation_id, &apr.revision, now_secs)
            {
                // Policy check: decline agent approval when user approval is required.
                if require_user_approver && apr.approver != "user" {
                    return OperationGateOutcome::Declined {
                        operation_id: apr.operation_id.clone(),
                        revision: apr.revision.clone(),
                        reason: Some(
                            "This action requires direct confirmation from the user.".into(),
                        ),
                        alternative: None,
                    };
                }

                // Atomically claim execution right.
                match store.try_begin_perform(
                    &apr.operation_id,
                    owner.clone(),
                    apr.revision.clone(),
                    expires_at_secs,
                ) {
                    Ok(()) => {
                        return OperationGateOutcome::Execute {
                            operation_id: apr.operation_id.clone(),
                            revision: apr.revision.clone(),
                            expires_at_secs,
                            approval: apr.clone(),
                        };
                    }
                    Err(OperationState::Performed {
                        owner: ref o,
                        status,
                        body,
                        ..
                    }) if o == &owner => {
                        return OperationGateOutcome::ReplayPerformed { status, body };
                    }
                    Err(OperationState::Performing { owner: ref o, .. }) if o == &owner => {
                        return OperationGateOutcome::InProgress { retry_after_secs: 2 };
                    }
                    Err(_) => {
                        let offer = mint_offer(secret, &owner, spec, None, now_secs, ttl_secs);
                        return OperationGateOutcome::ApprovalRequired(offer);
                    }
                }
            }

            // Check 3 failed (terms changed or expired): issue a NEW revision for the SAME operation_id,
            // guaranteeing the returned revision differs from `apr.revision`.
            let mut offer = mint_offer(
                secret,
                &owner,
                spec,
                Some(apr.operation_id.clone()),
                now_secs,
                ttl_secs,
            );
            if offer.revision == apr.revision {
                offer = mint_offer(
                    secret,
                    &owner,
                    spec,
                    Some(apr.operation_id.clone()),
                    now_secs.saturating_add(1),
                    ttl_secs,
                );
            }
            return OperationGateOutcome::ApprovalRequired(offer);
        }
    }

    let offer = mint_offer(secret, &owner, spec, None, now_secs, ttl_secs);
    OperationGateOutcome::ApprovalRequired(offer)
}

/// Compute a fresh [`OperationOffer`] with a stateless HMAC-SHA256 revision.
pub fn mint_offer(
    secret: &[u8],
    owner: &OperationOwner,
    spec: &ActionSpec<'_>,
    existing_operation_id: Option<String>,
    now_secs: u64,
    ttl_secs: u64,
) -> OperationOffer {
    let operation_id = existing_operation_id.unwrap_or_else(new_operation_id);
    let expires_at_secs = now_secs.saturating_add(ttl_secs.max(60));
    let revision = compute_revision(secret, owner, spec, &operation_id, expires_at_secs);
    OperationOffer {
        operation_id,
        revision,
        summary: spec.summary.clone(),
        terms: spec.terms.clone(),
        expires_at: format_rfc3339_utc(expires_at_secs),
    }
}

/// Compare two operation fingerprints using canonical JSON serialization so
/// responders can recognize duplicate pending operations regardless of key order.
pub fn same_operation_fingerprint(a: &Value, b: &Value) -> bool {
    canonical_json(a) == canonical_json(b)
}

/// Reconstruct an `OperationOffer` from a stored pending operation without
/// minting a duplicate `operation_id`.
pub fn offer_from_parts(
    operation_id: impl Into<String>,
    revision: impl Into<String>,
    summary: Option<String>,
    terms: Value,
    expires_at_secs: u64,
) -> OperationOffer {
    OperationOffer {
        operation_id: operation_id.into(),
        revision: revision.into(),
        summary,
        terms,
        expires_at: format_rfc3339_utc(expires_at_secs),
    }
}

/// Compute `{expires_unix}-{hmac_b64url}` over canonical terms, owner, and action fingerprint.
pub fn compute_revision(
    secret: &[u8],
    owner: &OperationOwner,
    spec: &ActionSpec<'_>,
    operation_id: &str,
    expires_at_secs: u64,
) -> String {
    let key = hmac_sha256(secret, b"ferrite-poppy/v1/operation-revision");
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        operation_id,
        expires_at_secs,
        spec.channel,
        spec.action,
        owner.client_id,
        owner.sub,
        owner.account_id.as_deref().unwrap_or(""),
        canonical_json(&spec.terms),
        canonical_json(&spec.fingerprint),
    );
    let mac = hmac_sha256(&key, canonical.as_bytes());
    let tag = base64url_encode(&mac[..18]); // 144-bit MAC tag, compact & URL-safe
    format!("{expires_at_secs}-{tag}")
}

/// Verify a presented `revision` against current terms and `now_secs`.
/// Returns `Some(expires_at_secs)` when authentic and unexpired.
pub fn verify_revision(
    secret: &[u8],
    owner: &OperationOwner,
    spec: &ActionSpec<'_>,
    operation_id: &str,
    presented_revision: &str,
    now_secs: u64,
) -> Option<u64> {
    let (exp_str, _) = presented_revision.split_once('-')?;
    let expires_at_secs: u64 = exp_str.parse().ok()?;
    if now_secs >= expires_at_secs {
        return None;
    }
    let expected = compute_revision(secret, owner, spec, operation_id, expires_at_secs);
    ct_eq(presented_revision.as_bytes(), expected.as_bytes()).then_some(expires_at_secs)
}

/// Build an API `403 approval_required` JSON body (`operations` §4 APIs).
pub fn api_approval_required_body(offer: &OperationOffer) -> Value {
    serde_json::json!({
        "error": "approval_required",
        "operation": offer,
    })
}

/// Build an API `403 approval_declined` JSON body (`operations` §6 Declining).
pub fn api_approval_declined_body(
    operation_id: &str,
    revision: &str,
    reason: Option<&str>,
    alternative: Option<&Alternative>,
) -> Value {
    let mut obj = serde_json::json!({
        "error": "approval_declined",
        "operation_id": operation_id,
        "revision": revision,
    });
    if let Some(r) = reason {
        obj["reason"] = Value::String(r.to_string());
    }
    if let Some(a) = alternative {
        if let Ok(av) = serde_json::to_value(a) {
            obj["alternative"] = av;
        }
    }
    obj
}

/// Build an MCP `isError: true` tool outcome body for `approval_required` (`operations` §4 MCP).
pub fn mcp_approval_required_result(offer: &OperationOffer) -> Value {
    let text = match &offer.summary {
        Some(s) => format!("Not done yet. This needs approval: {s}"),
        None => format!(
            "Not done yet. This action ({}) needs approval before it can be performed.",
            offer.operation_id
        ),
    };
    serde_json::json!({
        "isError": true,
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "operation": offer }
    })
}

/// Build an MCP `isError: true` tool outcome body for `approval_declined` (`operations` §6 MCP).
pub fn mcp_approval_declined_result(
    operation_id: &str,
    revision: &str,
    reason: Option<&str>,
    alternative: Option<&Alternative>,
) -> Value {
    let text = reason.unwrap_or("Approval declined; the action was not performed.");
    let structured = api_approval_declined_body(operation_id, revision, reason, alternative);
    serde_json::json!({
        "isError": true,
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured
    })
}

/// Extract an [`ApprovalSubmission`] from MCP `tools/call` `params._meta` (`operations` §6 MCP).
pub fn extract_mcp_approval(params: &Value) -> Option<ApprovalSubmission> {
    let raw = params.get("_meta")?.get(MCP_APPROVAL_META_KEY)?;
    parse_approval_json(raw)
}

/// Extract an [`ApprovalSubmission`] from a §8 Conversation message's
/// `extensions.operations.approval` (`operations` v3 §6 Conversations).
pub fn extract_conversation_approval(message: &Value) -> Option<ApprovalSubmission> {
    let raw = message.pointer("/extensions/operations/approval")?;
    parse_approval_json(raw)
}

fn parse_approval_json(raw: &Value) -> Option<ApprovalSubmission> {
    let mut apr: ApprovalSubmission = serde_json::from_value(raw.clone()).ok()?;
    if !matches!(apr.approver.as_str(), "user" | "agent") {
        return None;
    }
    if apr.approver == "agent" {
        apr.input_type = None;
    }
    Some(apr)
}

/// Build the `extensions.operations` payload proposing an operation in a Conversation
/// (`operations` v3 §4 Conversations: `{"operation": ...}`).
pub fn conversation_operation_content(offer: &OperationOffer) -> Value {
    serde_json::json!({ "operation": offer })
}

/// Build the `extensions.operations` payload declining an approval in a Conversation
/// (`operations` v3 §6 Declining: `{"declined": ...}`, intentionally without `"error"`).
pub fn conversation_declined_content(
    operation_id: &str,
    revision: &str,
    reason: Option<&str>,
    alternative: Option<&Alternative>,
) -> Value {
    let mut declined = serde_json::json!({
        "operation_id": operation_id,
        "revision": revision,
    });
    if let Some(r) = reason {
        declined["reason"] = Value::String(r.to_string());
    }
    if let Some(a) = alternative {
        if let Ok(av) = serde_json::to_value(a) {
            declined["alternative"] = av;
        }
    }
    serde_json::json!({ "declined": declined })
}

/// Build the `Poppy-Operation` header value for a website 403 response (`operations` §4 Websites).
pub fn website_operation_header(sid: &str, sealed_ref: &str) -> String {
    format_operation_header(sid, sealed_ref)
}

/// Deterministic canonical JSON string (sorted object keys, no extraneous whitespace)
/// so equivalent JSON payloads hash identically regardless of member order.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => v.to_string(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let pairs: Vec<String> = sorted
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(val)
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Format UTC epoch seconds as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_rfc3339_utc(epoch_secs: u64) -> String {
    let (y, m, d) = civil_date(epoch_secs.saturating_mul(1000));
    let rem = epoch_secs % 86_400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn new_operation_id() -> String {
    let key = Ed25519SigningKey::generate_pkcs8();
    let bytes = hmac_sha256(&key, b"ferrite-agent-ready/poppy-op/v1");
    format!("op_{}", base64url_encode(&bytes[..12]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(with_ops_ext: bool, account: Option<&str>) -> VerifiedSession {
        let mut extensions = BTreeMap::new();
        if with_ops_ext {
            extensions.insert(EXT_OPERATIONS.into(), EXT_OPERATIONS_VERSION.into());
        }
        VerifiedSession {
            protocol_version: "1.0".into(),
            extensions,
            client_id: "https://agent.example/agent.json".into(),
            sid: "sid_1".into(),
            sub: "usr_1".into(),
            agent_id: None,
            delegated_kid: "kid_1".into(),
            ath: None,
            account_id: account.map(str::to_string),
            scopes: vec!["orders:write".into()],
        }
    }

    #[test]
    fn full_approval_lifecycle_and_at_most_once_replay() {
        let secret = b"test-operation-secret-32-bytes!!";
        let store = MemoryOperationStore::default();
        let sess = session(true, Some("acct_42"));
        let policy = ApprovalPolicy::Required {
            ttl_secs: 900,
            require_user_approver: true,
        };
        let spec = ActionSpec {
            channel: "api",
            action: "POST /api/orders/1042/cancel",
            terms: serde_json::json!({"order_id": "1042", "refund_usd": "70.00"}),
            summary: Some("Cancel order **1042** for a **$70.00** refund.".into()),
            fingerprint: serde_json::json!({"order_id": "1042"}),
        };
        let now_ms = 1_790_900_000_000u64;

        // 1. Without operations extension -> ExtensionRequired.
        let no_ext = session(false, Some("acct_42"));
        assert_eq!(
            evaluate_gate(secret, policy, &no_ext, &spec, None, &store, now_ms),
            OperationGateOutcome::ExtensionRequired
        );

        // 2. Without approval -> ApprovalRequired with offer.
        let offer = match evaluate_gate(secret, policy, &sess, &spec, None, &store, now_ms) {
            OperationGateOutcome::ApprovalRequired(o) => o,
            other => panic!("expected ApprovalRequired, got {other:?}"),
        };

        // 3. Agent approval when user approval required -> Declined.
        let agent_apr = ApprovalSubmission {
            operation_id: offer.operation_id.clone(),
            revision: offer.revision.clone(),
            approver: "agent".into(),
            approved_at: Some(1_790_900_010),
            input_type: None,
            reference: Some("apr_1".into()),
        };
        assert!(matches!(
            evaluate_gate(secret, policy, &sess, &spec, Some(&agent_apr), &store, now_ms + 10_000),
            OperationGateOutcome::Declined { .. }
        ));

        // 4. Price changes before user approves -> fresh revision with SAME operation_id.
        let changed_spec = ActionSpec {
            terms: serde_json::json!({"order_id": "1042", "refund_usd": "65.00"}),
            ..spec.clone()
        };
        let user_apr_old = ApprovalSubmission {
            approver: "user".into(),
            input_type: Some("tap".into()),
            ..agent_apr.clone()
        };
        let offer2 = match evaluate_gate(
            secret,
            policy,
            &sess,
            &changed_spec,
            Some(&user_apr_old),
            &store,
            now_ms + 15_000,
        ) {
            OperationGateOutcome::ApprovalRequired(o) => o,
            other => panic!("expected refreshed ApprovalRequired, got {other:?}"),
        };
        assert_eq!(offer2.operation_id, offer.operation_id);
        assert_ne!(offer2.revision, offer.revision);

        // 5. User approves current revision -> Execute!
        let user_apr_new = ApprovalSubmission {
            revision: offer2.revision.clone(),
            ..user_apr_old
        };
        let (op_id, rev, exp) = match evaluate_gate(
            secret,
            policy,
            &sess,
            &changed_spec,
            Some(&user_apr_new),
            &store,
            now_ms + 20_000,
        ) {
            OperationGateOutcome::Execute {
                operation_id,
                revision,
                expires_at_secs,
                ..
            } => (operation_id, revision, expires_at_secs),
            other => panic!("expected Execute, got {other:?}"),
        };

        // Concurrent retry while performing -> InProgress (503 + Retry-After).
        assert!(matches!(
            evaluate_gate(
                secret,
                policy,
                &sess,
                &changed_spec,
                Some(&user_apr_new),
                &store,
                now_ms + 21_000,
            ),
            OperationGateOutcome::InProgress { .. }
        ));

        // Mark performed -> replay returns cached first result (at-most-once).
        store.mark_performed(
            &op_id,
            OperationOwner::from_session(&sess),
            rev,
            exp,
            200,
            serde_json::json!({"cancelled": true, "refund_usd": "65.00"}),
            user_apr_new.clone(),
        );
        assert_eq!(
            evaluate_gate(
                secret,
                policy,
                &sess,
                &changed_spec,
                Some(&user_apr_new),
                &store,
                now_ms + 25_000,
            ),
            OperationGateOutcome::ReplayPerformed {
                status: 200,
                body: serde_json::json!({"cancelled": true, "refund_usd": "65.00"}),
            }
        );
    }

    #[test]
    fn conversation_helpers_and_abort_perform() {
        let secret = b"test-operation-secret-32-bytes!!";
        let store = MemoryOperationStore::default();
        let sess = session(true, None);
        let policy = ApprovalPolicy::Required {
            ttl_secs: 900,
            require_user_approver: false,
        };
        let spec = ActionSpec {
            channel: "conversation",
            action: "conv:create_booking",
            terms: serde_json::json!({"class": "Beginners' Yoga", "drop_in_price": null}),
            summary: Some("Book Beginners' Yoga".into()),
            fingerprint: serde_json::json!({"event_type_id": "beginners-yoga", "start_ms": 1234}),
        };
        let now_ms = 1_790_900_000_000u64;

        let offer = match evaluate_gate(secret, policy, &sess, &spec, None, &store, now_ms) {
            OperationGateOutcome::ApprovalRequired(o) => o,
            other => panic!("expected offer, got {other:?}"),
        };
        let offer_ext = conversation_operation_content(&offer);
        assert_eq!(offer_ext["operation"]["operation_id"], offer.operation_id);

        let declined_ext = conversation_declined_content(
            &offer.operation_id,
            &offer.revision,
            Some("Direct user confirmation required."),
            None,
        );
        assert_eq!(declined_ext["declined"]["operation_id"], offer.operation_id);
        assert!(declined_ext.get("error").is_none());
        assert!(declined_ext["declined"].get("error").is_none());

        let msg = serde_json::json!({
            "author": { "type": "agent" },
            "extensions": {
                "operations": {
                    "approval": {
                        "operation_id": offer.operation_id,
                        "revision": offer.revision,
                        "approver": "agent",
                        "input_type": "tap"
                    }
                }
            }
        });
        let extracted = extract_conversation_approval(&msg).expect("approval extracted");
        assert_eq!(extracted.approver, "agent");
        assert_eq!(extracted.input_type, None, "agent approver strips input_type");

        // Invalid approver value is rejected.
        let bad_msg = serde_json::json!({
            "extensions": {
                "operations": {
                    "approval": {
                        "operation_id": offer.operation_id,
                        "revision": offer.revision,
                        "approver": "bot"
                    }
                }
            }
        });
        assert!(extract_conversation_approval(&bad_msg).is_none());

        // Claim execution, then abort_perform releases the Performing lock cleanly.
        let (op_id, rev) = match evaluate_gate(
            secret,
            policy,
            &sess,
            &spec,
            Some(&extracted),
            &store,
            now_ms + 5_000,
        ) {
            OperationGateOutcome::Execute {
                operation_id,
                revision,
                ..
            } => (operation_id, revision),
            other => panic!("expected Execute, got {other:?}"),
        };
        assert!(matches!(
            evaluate_gate(secret, policy, &sess, &spec, Some(&extracted), &store, now_ms + 6_000),
            OperationGateOutcome::InProgress { .. }
        ));
        store.abort_perform(&op_id, &OperationOwner::from_session(&sess), &rev);
        assert!(matches!(
            evaluate_gate(secret, policy, &sess, &spec, Some(&extracted), &store, now_ms + 7_000),
            OperationGateOutcome::Execute { .. }
        ));

        // Canonical fingerprint comparison ignores JSON key ordering.
        assert!(same_operation_fingerprint(
            &serde_json::json!({"b": 2, "a": 1}),
            &serde_json::json!({"a": 1, "b": 2})
        ));
        assert!(!same_operation_fingerprint(
            &serde_json::json!({"a": 1}),
            &serde_json::json!({"a": 2})
        ));
        let reused = offer_from_parts("op_dup", "123-abc", Some("Book".into()), serde_json::json!({}), 1_700_000_900);
        assert_eq!(reused.operation_id, "op_dup");
        assert_eq!(reused.revision, "123-abc");
    }
}
