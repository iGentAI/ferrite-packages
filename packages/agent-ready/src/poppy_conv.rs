//! Poppy 1.0 Company Agent Conversations (§8) + `links` v1, `disclosures` v1, and `operations` v3.
//!
//! Implements the complete Section 8 HTTP conversation protocol plus lifecycle helpers:
//! - `GET {endpoint}` — list the caller's open and recent conversations
//! - `POST {endpoint}` — start a conversation or a Direct Conversation (§8.3, §8.10),
//!   with optional `close_existing` / `resume_existing` lifecycle controls
//! - `POST {endpoint}/{id}/messages` — send a message (§8.3, §8.4)
//! - `GET {endpoint}/{id}/events?cursor=&wait=` — read ordered events & state (§8.5, §8.7)
//! - `POST {endpoint}/{id}/handoff` & `/handoff/cancel` — human handoff (§8.9)
//! - `POST {endpoint}/{id}/close` — close conversation (§8.12)
//! - `POST {endpoint}/{id}/resume` — reopen a closed/timed-out conversation or refresh activity
//!
//! Enforces per-User request-ID idempotency (`request_id_conflict` 409),
//! strict ownership isolation (`conversation_not_found` 404 vs `401` challenge),
//! Direct Conversation parent locking (`direct_conversation_open` 409),
//! documented inactivity timeouts (auto-closing while retaining events),
//! and extension gating (`links`, `disclosures`, `operations` emitted only when
//! declared in `Poppy-Extensions`).

use std::collections::BTreeMap;
use std::sync::Mutex;

use ferrite_app::crypto::{base64url_encode, hmac_sha256, Ed25519SigningKey};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::poppy::{
    is_valid_poppy_id, PoppyError, EXT_DISCLOSURES, EXT_DISCLOSURES_VERSION, EXT_LINKS,
    EXT_LINKS_VERSION, EXT_OPERATIONS, EXT_OPERATIONS_VERSION,
};
use crate::agent_ready::poppy_ops::format_rfc3339_utc;
use crate::agent_ready::poppy_verify::VerifiedSession;

/// Default conversation inactivity timeout: 24 hours.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 86_400;
/// Default retention window for closed conversation events: 7 days.
pub const DEFAULT_RETENTION_SECS: u64 = 604_800;

/// Lifecycle policy governing conversation inactivity timeout, retention, and concurrency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversationPolicy {
    /// Seconds of inactivity before an open conversation auto-closes (0 = never auto-close).
    pub idle_timeout_secs: u64,
    /// Documented retention window in seconds after a conversation closes.
    pub retention_secs: u64,
    /// Optional cap on concurrent open top-level conversations per `(client_id, sub)`.
    /// When exceeded (and neither `close_existing` nor `resume_existing` is set),
    /// `POST {endpoint}` returns `409 already_open` with the open `conversation_id` and recovery links.
    pub max_open_per_user: Option<usize>,
}

impl Default for ConversationPolicy {
    fn default() -> Self {
        Self {
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            retention_secs: DEFAULT_RETENTION_SECS,
            max_open_per_user: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum HandoffState {
    None,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum ResponderType {
    Agent,
    Human,
}

/// Structured link for the `links` v1 extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PoppyLink {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Structured disclosure notice for the `disclosures` v1 extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PoppyDisclosure {
    pub text: String,
}

/// A Company Agent reply returned by a host [`ConversationResponder`].
#[derive(Debug, Clone, Default)]
pub struct AgentReply {
    pub text: Option<String>,
    pub data: Option<Value>,
    pub author_id: Option<String>,
    pub author_name: Option<String>,
    pub links: Vec<PoppyLink>,
    pub disclosures: Vec<PoppyDisclosure>,
    /// Optional `operations` v3 content (`{"operation": ...}` or `{"declined": ...}`).
    pub operation_content: Option<Value>,
    /// Optional mid-conversation authorization request (§8.11).
    pub require_scopes: Option<Vec<String>>,
    /// Optional invitation for the User to join a Direct Conversation (§8.10).
    pub request_user_reason: Option<String>,
}

/// Stored conversation event (§8.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ConversationEvent {
    pub id: String,
    pub body: Value,
}

/// Stored idempotent request receipt keyed by `(client_id, sub, request_id)` (§8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct RequestReceipt {
    pub path: String,
    pub body_canonical: String,
    pub status: u16,
    pub conversation_id: String,
}

/// Persistent state for one Poppy Conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ConversationRecord {
    pub id: String,
    pub client_id: String,
    pub sub: String,
    pub bound_account: Option<String>,
    pub protocol_version: String,
    pub parent_conversation_id: Option<String>,
    pub active_direct_id: Option<String>,
    pub working: bool,
    pub handoff: HandoffState,
    pub responder: ResponderType,
    pub closed: bool,
    pub events: Vec<ConversationEvent>,
    /// Maps `(parent_id, user_requested_event_id)` -> direct conversation id (§8.10).
    pub direct_by_invite: BTreeMap<String, String>,
    /// Creation timestamp (epoch ms). Defaults to 0 for legacy records persisted before 1.15.0.
    #[serde(default)]
    pub created_at_ms: u64,
    /// Last activity timestamp (epoch ms) used for inactivity expiry and pruning order.
    #[serde(default)]
    pub last_activity_ms: u64,
    /// Configured inactivity timeout for this conversation (seconds; 0 falls back to policy).
    #[serde(default)]
    pub idle_timeout_secs: u64,
}

/// Persistence contract for Poppy Conversations.
pub trait ConversationStore {
    fn get(&self, id: &str) -> Option<ConversationRecord>;
    fn put(&self, rec: ConversationRecord);
    fn get_receipt(&self, client_id: &str, sub: &str, req_id: &str) -> Option<RequestReceipt>;
    fn put_receipt(&self, client_id: &str, sub: &str, req_id: &str, receipt: RequestReceipt);
    /// List conversations belonging to `(client_id, sub)` so agents can inspect, resume,
    /// or close open threads (`GET {endpoint}` and `close_existing` / `resume_existing`).
    fn list_for_owner(&self, _client_id: &str, _sub: &str) -> Vec<ConversationRecord> {
        Vec::new()
    }
}

/// Strip `<script>`/`<style>` blocks, any `<...>` HTML/XML tags, stray angle brackets,
/// and control characters from untrusted conversational input while preserving valid
/// Unicode letters, accents, emoji, apostrophes, and hyphens.
pub fn strip_markup_and_controls(raw: &str) -> String {
    // 1. Remove `<script ...>...</script>` and `<style ...>...</style>` blocks (including unclosed).
    let mut stage1 = String::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        let next_script = lower.find("<script");
        let next_style = lower.find("<style");
        let block = match (next_script, next_style) {
            (Some(a), Some(b)) => {
                if a <= b {
                    Some((a, "</script>"))
                } else {
                    Some((b, "</style>"))
                }
            }
            (Some(a), None) => Some((a, "</script>")),
            (None, Some(b)) => Some((b, "</style>")),
            (None, None) => None,
        };
        let Some((pos, close_tag)) = block else {
            stage1.push_str(rest);
            break;
        };
        // Find matching char boundary in `rest` (ASCII `<script`/`<style` start aligns with char boundary,
        // guard against any non-ASCII case folding length shift by stepping on char indices).
        let byte_pos = rest
            .char_indices()
            .find(|(idx, _)| rest[*idx..].to_ascii_lowercase().starts_with(if close_tag == "</script>" { "<script" } else { "<style" }))
            .map(|(idx, _)| idx)
            .unwrap_or(pos.min(rest.len()));
        stage1.push_str(&rest[..byte_pos]);
        stage1.push(' ');
        let after_open = &rest[byte_pos..];
        let close_pos = after_open
            .char_indices()
            .find(|(idx, _)| after_open[*idx..].to_ascii_lowercase().starts_with(close_tag))
            .map(|(idx, _)| idx + close_tag.len());
        match close_pos {
            Some(end) => rest = &after_open[end..],
            None => break, // Unclosed script/style tag — drop the rest safely.
        }
    }

    // 2. Strip any remaining `<...>` tags and stray angle brackets / control chars.
    let mut stage2 = String::with_capacity(stage1.len());
    let mut in_tag = false;
    for ch in stage1.chars() {
        if ch == '<' {
            in_tag = true;
            stage2.push(' ');
            continue;
        }
        if ch == '>' {
            in_tag = false;
            stage2.push(' ');
            continue;
        }
        if in_tag {
            continue;
        }
        if ch.is_control() {
            stage2.push(' ');
        } else {
            stage2.push(ch);
        }
    }

    stage2.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Tokenize conversational text into lowercased words while also expanding hyphenated
/// compounds into their constituent parts (e.g. `"yin-lessen"` -> `["yin-lessen", "yin", "lessen"]`)
/// so multilingual compound terms match reliably without breaking ISO dates or slugs.
pub fn normalized_words_and_parts(raw: &str) -> Vec<String> {
    let clean = strip_markup_and_controls(raw);
    let mut out = Vec::new();
    for tok in clean
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != ':')
        .filter(|t| !t.is_empty())
    {
        let lower = tok.to_lowercase();
        let has_hyphen = lower.contains('-');
        out.push(lower.clone());
        if has_hyphen {
            for part in lower.split('-').filter(|p| !p.is_empty()) {
                out.push(part.to_string());
            }
        }
    }
    out
}

#[derive(Default)]
pub struct MemoryConversationStore {
    inner: Mutex<MemoryConvState>,
}

#[derive(Default)]
struct MemoryConvState {
    convs: BTreeMap<String, ConversationRecord>,
    receipts: BTreeMap<(String, String, String), RequestReceipt>,
}

impl ConversationStore for MemoryConversationStore {
    fn get(&self, id: &str) -> Option<ConversationRecord> {
        self.inner.lock().ok()?.convs.get(id).cloned()
    }
    fn put(&self, rec: ConversationRecord) {
        if let Ok(mut g) = self.inner.lock() {
            g.convs.insert(rec.id.clone(), rec);
        }
    }
    fn get_receipt(&self, client_id: &str, sub: &str, req_id: &str) -> Option<RequestReceipt> {
        self.inner
            .lock()
            .ok()?
            .receipts
            .get(&(client_id.to_string(), sub.to_string(), req_id.to_string()))
            .cloned()
    }
    fn put_receipt(&self, client_id: &str, sub: &str, req_id: &str, receipt: RequestReceipt) {
        if let Ok(mut g) = self.inner.lock() {
            g.receipts.insert(
                (client_id.to_string(), sub.to_string(), req_id.to_string()),
                receipt,
            );
        }
    }
    fn list_for_owner(&self, client_id: &str, sub: &str) -> Vec<ConversationRecord> {
        self.inner
            .lock()
            .ok()
            .map(|g| {
                g.convs
                    .values()
                    .filter(|c| c.client_id == client_id && c.sub == sub)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Callback implemented by the host app (e.g. bridging to `packages/agent-sdk`)
/// to answer incoming Poppy conversation messages.
pub trait ConversationResponder {
    fn reply(
        &self,
        session: &VerifiedSession,
        conversation_id: &str,
        user_message: Option<&Value>,
    ) -> impl std::future::Future<Output = AgentReply>;
}

/// HTTP reply returned by [`handle_conversation`].
#[derive(Debug, Clone)]
pub struct ConvHttpReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

/// Build an active telemetry event (`X-Ferrite-Agent-Event`) for a Poppy Conversation event.
pub fn telemetry_event(
    event: &str,
    agent: Option<&str>,
) -> crate::agent_ready::telemetry::AgentEvent {
    crate::agent_ready::telemetry::AgentEvent::poppy_conv(event, agent)
}

/// Convenience helper returning `(AGENT_EVENT_HEADER, value)` for host apps.
pub fn telemetry_header(event: &str, agent: Option<&str>) -> (String, String) {
    telemetry_event(event, agent).to_header()
}

/// Route a request under `{base_path}` (e.g. `/poppy/conversations`) using [`ConversationPolicy::default`].
/// Caller MUST have already verified `Poppy-Session` and `Poppy-Version` into `session`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_conversation<S: ConversationStore, R: ConversationResponder>(
    base_path: &str,
    method: &str,
    bare_path: &str,
    raw_query: &str,
    body: &[u8],
    session: &VerifiedSession,
    store: &S,
    responder: &R,
    now_ms: u64,
) -> Option<ConvHttpReply> {
    handle_conversation_with_policy(
        base_path,
        method,
        bare_path,
        raw_query,
        body,
        session,
        store,
        responder,
        ConversationPolicy::default(),
        now_ms,
    )
    .await
}

/// Route a request under `{base_path}` with an explicit [`ConversationPolicy`].
#[allow(clippy::too_many_arguments)]
pub async fn handle_conversation_with_policy<S: ConversationStore, R: ConversationResponder>(
    base_path: &str,
    method: &str,
    bare_path: &str,
    raw_query: &str,
    body: &[u8],
    session: &VerifiedSession,
    store: &S,
    responder: &R,
    policy: ConversationPolicy,
    now_ms: u64,
) -> Option<ConvHttpReply> {
    let tail = bare_path.strip_prefix(base_path)?;
    let mut reply = handle_conversation_inner(
        base_path,
        tail,
        method,
        bare_path,
        raw_query,
        body,
        session,
        store,
        responder,
        policy,
        now_ms,
    )
    .await?;
    let event_name = match (method, tail) {
        ("GET", "" | "/") => "list",
        ("POST", "" | "/") => {
            let doc = serde_json::from_slice::<Value>(body).ok();
            if doc
                .as_ref()
                .and_then(|d| d.get("parent_conversation_id"))
                .and_then(Value::as_str)
                .is_some()
            {
                "direct_start"
            } else if reply.status == 200
                && doc
                    .as_ref()
                    .and_then(|d| d.get("resume_existing"))
                    .and_then(Value::as_bool)
                    == Some(true)
            {
                "resume_existing"
            } else {
                "start"
            }
        }
        _ => match tail
            .strip_prefix('/')
            .and_then(|t| t.split_once('/'))
            .map(|(_, r)| r)
        {
            Some("events") => "events",
            Some("messages") => "message",
            Some("handoff") => "handoff",
            Some("handoff/cancel") => "handoff_cancel",
            Some("close") => "close",
            Some("resume") => "resume",
            _ => "conv",
        },
    };
    let mut evt = telemetry_event(event_name, Some(&session.client_id));
    if reply.status >= 400 {
        evt = evt.with_ok(false);
        if let Ok(v) = serde_json::from_slice::<Value>(&reply.body) {
            if let Some(code) = v.get("error").and_then(Value::as_str) {
                evt = evt.with_err(code);
            }
        }
    }
    reply.headers.push(evt.to_static_header());
    Some(reply)
}

#[allow(clippy::too_many_arguments)]
async fn handle_conversation_inner<S: ConversationStore, R: ConversationResponder>(
    base_path: &str,
    tail: &str,
    method: &str,
    bare_path: &str,
    raw_query: &str,
    body: &[u8],
    session: &VerifiedSession,
    store: &S,
    responder: &R,
    policy: ConversationPolicy,
    now_ms: u64,
) -> Option<ConvHttpReply> {
    let now_rfc3339 = format_rfc3339_utc(now_ms / 1000);
    let cursor_param = crate::agent_ready::query::param(raw_query, "cursor");
    let wait_param = crate::agent_ready::query::param(raw_query, "wait");
    if let Some(w) = &wait_param {
        if w.is_empty() || !w.bytes().all(|b| b.is_ascii_digit()) {
            return Some(err_reply(PoppyError::invalid_request(
                "wait must be a whole number of seconds",
            )));
        }
    }

    match (method, tail) {
        // GET {endpoint} -> List caller's open and recent conversations for discovery & recovery.
        ("GET", "" | "/") => {
            let status_filter = crate::agent_ready::query::param(raw_query, "status");
            let mut owned = collect_visible_conversations(store, session, policy, now_ms, &now_rfc3339);
            owned.sort_by(|a, b| {
                b.last_activity_ms
                    .cmp(&a.last_activity_ms)
                    .then_with(|| b.id.cmp(&a.id))
            });
            let active_id = owned
                .iter()
                .find(|c| !c.closed && c.parent_conversation_id.is_none())
                .map(|c| c.id.clone());
            let open_count = owned.iter().filter(|c| !c.closed).count();
            let filtered: Vec<Value> = owned
                .iter()
                .filter(|c| match status_filter.as_deref() {
                    Some("open") => !c.closed,
                    Some("closed") => c.closed,
                    _ => true,
                })
                .map(|c| conversation_summary_json(base_path, c, policy))
                .collect();
            let payload = serde_json::json!({
                "conversations": filtered,
                "active_conversation_id": active_id,
                "open_count": open_count,
                "idle_timeout_secs": policy.idle_timeout_secs,
                "retention_secs": policy.retention_secs,
            });
            Some(ConvHttpReply {
                status: 200,
                body: serde_json::to_vec(&payload).unwrap_or_default(),
                headers: vec![("cache-control", "no-store".into())],
            })
        }

        // POST {endpoint} -> Start conversation or Direct Conversation (§8.3, §8.10).
        ("POST", "" | "/") => {
            let doc: Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => return Some(err_reply(PoppyError::invalid_request("invalid JSON body"))),
            };
            let req_id = match doc.get("id").and_then(Value::as_str) {
                Some(id) if is_valid_poppy_id(id) => id.to_string(),
                _ => {
                    return Some(err_reply(PoppyError::invalid_request(
                        "missing or invalid request id",
                    )))
                }
            };
            let canonical_body = crate::agent_ready::poppy_ops::canonical_json(&doc);
            if let Some(prev) = store.get_receipt(&session.client_id, &session.sub, &req_id) {
                if prev.path != bare_path || prev.body_canonical != canonical_body {
                    return Some(json_err(409, "request_id_conflict", None));
                }
                let conv = match store.get(&prev.conversation_id) {
                    Some(c) => c,
                    None => return Some(json_err(404, "conversation_not_found", None)),
                };
                if let Err(e) = check_ownership(&conv, session) {
                    return Some(e);
                }
                return Some(post_response(
                    prev.status,
                    &conv,
                    cursor_param.as_deref(),
                    wait_param.is_some(),
                    policy,
                ));
            }

            let parent_id = doc
                .get("parent_conversation_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let invite_evt_id = doc
                .get("user_requested_event_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let close_existing = doc
                .get("close_existing")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let resume_existing = doc
                .get("resume_existing")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let msg = doc.get("message");

            if msg.is_none() && !(parent_id.is_some() && invite_evt_id.is_some()) {
                return Some(err_reply(PoppyError::invalid_request(
                    "message is required unless accepting user_requested_event_id",
                )));
            }
            if let Some(m) = msg {
                if let Err(e) = validate_incoming_message(m) {
                    return Some(err_reply(e));
                }
            }

            // Validate parent conversation if starting a Direct Conversation (§8.10).
            if let Some(pid) = &parent_id {
                let mut parent = match store.get(pid) {
                    Some(p) => p,
                    None => return Some(json_err(404, "conversation_not_found", None)),
                };
                if let Err(e) = check_ownership(&parent, session) {
                    return Some(e);
                }
                if apply_idle_expiry(&mut parent, policy, now_ms, &now_rfc3339) {
                    store.put(parent.clone());
                }
                if parent.parent_conversation_id.is_some() {
                    return Some(err_reply(PoppyError::invalid_request(
                        "parent cannot itself be a Direct Conversation",
                    )));
                }
                if let Some(inv) = &invite_evt_id {
                    // Repeating the same parent + invite event returns the same Direct Conversation.
                    if let Some(existing_direct) = parent.direct_by_invite.get(inv) {
                        if let Some(dc) = store.get(existing_direct) {
                            if let Err(e) = check_ownership(&dc, session) {
                                return Some(e);
                            }
                            return Some(post_response(
                                201,
                                &dc,
                                cursor_param.as_deref(),
                                wait_param.is_some(),
                                policy,
                            ));
                        }
                    }
                    let valid_invite = parent.events.iter().any(|e| {
                        e.id == *inv && e.body.get("type").and_then(Value::as_str) == Some("user_requested")
                    });
                    if !valid_invite {
                        return Some(err_reply(PoppyError::invalid_request(
                            "user_requested_event_id does not name a user_requested event in parent",
                        )));
                    }
                }
                if parent.closed {
                    return Some(conversation_closed_err(base_path, &parent, policy));
                }
                if let Some(open_id) = &parent.active_direct_id {
                    return Some(direct_open_err(base_path, open_id));
                }

                let conv_id = new_conv_id();
                parent.active_direct_id = Some(conv_id.clone());
                touch_activity(&mut parent, policy, now_ms);
                if let Some(inv) = invite_evt_id {
                    parent.direct_by_invite.insert(inv, conv_id.clone());
                }
                let opened_id = new_evt_id();
                parent.events.push(ConversationEvent {
                    id: opened_id.clone(),
                    body: serde_json::json!({
                        "id": opened_id,
                        "type": "direct_opened",
                        "created_at": now_rfc3339,
                        "conversation_id": conv_id
                    }),
                });
                store.put(parent);

                let conv = create_and_answer(
                    conv_id,
                    Some(pid.clone()),
                    &req_id,
                    msg,
                    session,
                    store,
                    responder,
                    policy,
                    now_ms,
                    &now_rfc3339,
                )
                .await;
                store.put_receipt(
                    &session.client_id,
                    &session.sub,
                    &req_id,
                    RequestReceipt {
                        path: bare_path.to_string(),
                        body_canonical: canonical_body,
                        status: 201,
                        conversation_id: conv.id.clone(),
                    },
                );
                return Some(post_response(
                    201,
                    &conv,
                    cursor_param.as_deref(),
                    wait_param.is_some(),
                    policy,
                ));
            }

            // Top-level conversation lifecycle controls: close_existing, resume_existing, and max_open_per_user.
            let mut open_top_level: Vec<ConversationRecord> =
                collect_visible_conversations(store, session, policy, now_ms, &now_rfc3339)
                    .into_iter()
                    .filter(|c| !c.closed && c.parent_conversation_id.is_none())
                    .collect();
            open_top_level.sort_by(|a, b| {
                b.last_activity_ms
                    .cmp(&a.last_activity_ms)
                    .then_with(|| b.id.cmp(&a.id))
            });

            if close_existing && !open_top_level.is_empty() {
                for mut existing in open_top_level.drain(..) {
                    close_conversation_record(&mut existing, store, policy, now_ms, &now_rfc3339);
                }
            } else if resume_existing {
                if let Some(mut existing) = open_top_level
                    .into_iter()
                    .find(|c| c.active_direct_id.is_none())
                {
                    if existing.bound_account.is_none() && session.account_id.is_some() {
                        existing.bound_account = session.account_id.clone();
                    }
                    touch_activity(&mut existing, policy, now_ms);
                    if let Some(m) = msg {
                        record_user_message(&mut existing, &req_id, m, &now_rfc3339);
                        if existing.responder == ResponderType::Agent {
                            let reply = responder.reply(session, &existing.id, Some(m)).await;
                            record_agent_reply(
                                &mut existing,
                                Some(&req_id),
                                session,
                                reply,
                                &now_rfc3339,
                            );
                        }
                    }
                    store.put(existing.clone());
                    store.put_receipt(
                        &session.client_id,
                        &session.sub,
                        &req_id,
                        RequestReceipt {
                            path: bare_path.to_string(),
                            body_canonical: canonical_body,
                            status: 200,
                            conversation_id: existing.id.clone(),
                        },
                    );
                    return Some(post_response(
                        200,
                        &existing,
                        cursor_param.as_deref(),
                        wait_param.is_some(),
                        policy,
                    ));
                }
            } else if let Some(limit) = policy.max_open_per_user {
                if open_top_level.len() >= limit {
                    return Some(already_open_err(base_path, &open_top_level, policy));
                }
            }

            let conv_id = new_conv_id();
            let conv = create_and_answer(
                conv_id,
                None,
                &req_id,
                msg,
                session,
                store,
                responder,
                policy,
                now_ms,
                &now_rfc3339,
            )
            .await;
            store.put_receipt(
                &session.client_id,
                &session.sub,
                &req_id,
                RequestReceipt {
                    path: bare_path.to_string(),
                    body_canonical: canonical_body,
                    status: 201,
                    conversation_id: conv.id.clone(),
                },
            );
            Some(post_response(
                201,
                &conv,
                cursor_param.as_deref(),
                wait_param.is_some(),
                policy,
            ))
        }

        // Sub-routes: /{id}/events, /{id}/messages, /{id}/handoff, /{id}/handoff/cancel, /{id}/close, /{id}/resume
        _ => {
            let trimmed = tail.strip_prefix('/')?;
            let (conv_id, rest) = trimmed.split_once('/')?;
            if !is_valid_poppy_id(conv_id) {
                return Some(err_reply(PoppyError::invalid_request(
                    "invalid conversation id",
                )));
            }
            let mut conv = match store.get(conv_id) {
                Some(c) => c,
                None => return Some(json_err(404, "conversation_not_found", None)),
            };
            if let Err(e) = check_ownership(&conv, session) {
                return Some(e);
            }
            let mut dirty = false;
            // Bind account if this request is signed in and conversation was signed out (§8.2).
            if conv.bound_account.is_none() && session.account_id.is_some() {
                conv.bound_account = session.account_id.clone();
                dirty = true;
            }
            if apply_idle_expiry(&mut conv, policy, now_ms, &now_rfc3339) {
                dirty = true;
            }

            match (method, rest) {
                ("GET", "events") => {
                    if dirty {
                        store.put(conv.clone());
                    }
                    Some(events_response(200, &conv, cursor_param.as_deref(), policy))
                }
                ("POST", "messages") => {
                    let doc: Value = match serde_json::from_slice(body) {
                        Ok(v) => v,
                        Err(_) => {
                            return Some(err_reply(PoppyError::invalid_request("invalid JSON body")))
                        }
                    };
                    let req_id = match doc.get("id").and_then(Value::as_str) {
                        Some(id) if is_valid_poppy_id(id) => id.to_string(),
                        _ => {
                            return Some(err_reply(PoppyError::invalid_request(
                                "missing or invalid request id",
                            )))
                        }
                    };
                    let canonical_body = crate::agent_ready::poppy_ops::canonical_json(&doc);
                    if let Some(prev) =
                        store.get_receipt(&session.client_id, &session.sub, &req_id)
                    {
                        if prev.path != bare_path || prev.body_canonical != canonical_body {
                            return Some(json_err(409, "request_id_conflict", None));
                        }
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(post_response(
                            202,
                            &conv,
                            cursor_param.as_deref(),
                            wait_param.is_some(),
                            policy,
                        ));
                    }
                    if conv.closed {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(conversation_closed_err(base_path, &conv, policy));
                    }
                    if let Some(open_id) = &conv.active_direct_id {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(direct_open_err(base_path, open_id));
                    }
                    let msg = match doc.get("message") {
                        Some(m) => {
                            if let Err(e) = validate_incoming_message(m) {
                                return Some(err_reply(e));
                            }
                            m
                        }
                        None => {
                            return Some(err_reply(PoppyError::invalid_request(
                                "message is required",
                            )))
                        }
                    };
                    touch_activity(&mut conv, policy, now_ms);
                    record_user_message(&mut conv, &req_id, msg, &now_rfc3339);
                    if conv.responder == ResponderType::Agent {
                        let reply = responder.reply(session, &conv.id, Some(msg)).await;
                        record_agent_reply(&mut conv, Some(&req_id), session, reply, &now_rfc3339);
                    }
                    store.put(conv.clone());
                    store.put_receipt(
                        &session.client_id,
                        &session.sub,
                        &req_id,
                        RequestReceipt {
                            path: bare_path.to_string(),
                            body_canonical: canonical_body,
                            status: 202,
                            conversation_id: conv.id.clone(),
                        },
                    );
                    Some(post_response(
                        202,
                        &conv,
                        cursor_param.as_deref(),
                        wait_param.is_some(),
                        policy,
                    ))
                }
                ("POST", "handoff") => {
                    let (req_id, canonical_body) = match parse_action_doc(body) {
                        Ok(v) => v,
                        Err(e) => return Some(err_reply(e)),
                    };
                    if let Some(prev) =
                        store.get_receipt(&session.client_id, &session.sub, &req_id)
                    {
                        if prev.path != bare_path || prev.body_canonical != canonical_body {
                            return Some(json_err(409, "request_id_conflict", None));
                        }
                        return Some(post_response(
                            202,
                            &conv,
                            cursor_param.as_deref(),
                            wait_param.is_some(),
                            policy,
                        ));
                    }
                    if conv.closed {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(conversation_closed_err(base_path, &conv, policy));
                    }
                    if let Some(open_id) = &conv.active_direct_id {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(direct_open_err(base_path, open_id));
                    }
                    touch_activity(&mut conv, policy, now_ms);
                    if conv.handoff == HandoffState::None && conv.responder == ResponderType::Agent {
                        conv.handoff = HandoffState::Pending;
                        push_state_event(&mut conv, &now_rfc3339, None);
                    }
                    store.put(conv.clone());
                    store.put_receipt(
                        &session.client_id,
                        &session.sub,
                        &req_id,
                        RequestReceipt {
                            path: bare_path.to_string(),
                            body_canonical: canonical_body,
                            status: 202,
                            conversation_id: conv.id.clone(),
                        },
                    );
                    Some(post_response(
                        202,
                        &conv,
                        cursor_param.as_deref(),
                        wait_param.is_some(),
                        policy,
                    ))
                }
                ("POST", "handoff/cancel") => {
                    let (req_id, canonical_body) = match parse_action_doc(body) {
                        Ok(v) => v,
                        Err(e) => return Some(err_reply(e)),
                    };
                    if let Some(prev) =
                        store.get_receipt(&session.client_id, &session.sub, &req_id)
                    {
                        if prev.path != bare_path || prev.body_canonical != canonical_body {
                            return Some(json_err(409, "request_id_conflict", None));
                        }
                        return Some(post_response(
                            202,
                            &conv,
                            cursor_param.as_deref(),
                            wait_param.is_some(),
                            policy,
                        ));
                    }
                    if conv.closed {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(conversation_closed_err(base_path, &conv, policy));
                    }
                    if let Some(open_id) = &conv.active_direct_id {
                        if dirty {
                            store.put(conv.clone());
                        }
                        return Some(direct_open_err(base_path, open_id));
                    }
                    touch_activity(&mut conv, policy, now_ms);
                    if conv.handoff == HandoffState::Pending {
                        conv.handoff = HandoffState::None;
                        push_state_event(&mut conv, &now_rfc3339, None);
                    }
                    store.put(conv.clone());
                    store.put_receipt(
                        &session.client_id,
                        &session.sub,
                        &req_id,
                        RequestReceipt {
                            path: bare_path.to_string(),
                            body_canonical: canonical_body,
                            status: 202,
                            conversation_id: conv.id.clone(),
                        },
                    );
                    Some(post_response(
                        202,
                        &conv,
                        cursor_param.as_deref(),
                        wait_param.is_some(),
                        policy,
                    ))
                }
                ("POST", "close") => {
                    let (req_id, canonical_body) = match parse_action_doc(body) {
                        Ok(v) => v,
                        Err(e) => return Some(err_reply(e)),
                    };
                    if let Some(prev) =
                        store.get_receipt(&session.client_id, &session.sub, &req_id)
                    {
                        if prev.path != bare_path || prev.body_canonical != canonical_body {
                            return Some(json_err(409, "request_id_conflict", None));
                        }
                        return Some(post_response(
                            202,
                            &conv,
                            cursor_param.as_deref(),
                            wait_param.is_some(),
                            policy,
                        ));
                    }
                    close_conversation_record(&mut conv, store, policy, now_ms, &now_rfc3339);
                    store.put_receipt(
                        &session.client_id,
                        &session.sub,
                        &req_id,
                        RequestReceipt {
                            path: bare_path.to_string(),
                            body_canonical: canonical_body,
                            status: 202,
                            conversation_id: conv.id.clone(),
                        },
                    );
                    Some(post_response(
                        202,
                        &conv,
                        cursor_param.as_deref(),
                        wait_param.is_some(),
                        policy,
                    ))
                }
                ("POST", "resume") => {
                    let doc: Value = if body.is_empty() {
                        serde_json::json!({})
                    } else {
                        match serde_json::from_slice(body) {
                            Ok(v) => v,
                            Err(_) => {
                                return Some(err_reply(PoppyError::invalid_request(
                                    "invalid JSON body",
                                )))
                            }
                        }
                    };
                    let req_id = match doc.get("id") {
                        None | Some(Value::Null) => None,
                        Some(Value::String(id)) if is_valid_poppy_id(id) => Some(id.clone()),
                        _ => {
                            return Some(err_reply(PoppyError::invalid_request(
                                "invalid request id",
                            )))
                        }
                    };
                    let canonical_body = crate::agent_ready::poppy_ops::canonical_json(&doc);
                    if let Some(ref rid) = req_id {
                        if let Some(prev) =
                            store.get_receipt(&session.client_id, &session.sub, rid)
                        {
                            if prev.path != bare_path || prev.body_canonical != canonical_body {
                                return Some(json_err(409, "request_id_conflict", None));
                            }
                            return Some(post_response(
                                200,
                                &conv,
                                cursor_param.as_deref(),
                                wait_param.is_some(),
                                policy,
                            ));
                        }
                    }
                    let msg = doc.get("message");
                    if let Some(m) = msg {
                        if let Err(e) = validate_incoming_message(m) {
                            return Some(err_reply(e));
                        }
                    }
                    if let Some(pid) = &conv.parent_conversation_id {
                        if let Some(mut parent) = store.get(pid) {
                            if parent.closed {
                                return Some(conversation_closed_err(base_path, &parent, policy));
                            }
                            if let Some(open_id) = &parent.active_direct_id {
                                if open_id != &conv.id {
                                    return Some(direct_open_err(base_path, open_id));
                                }
                            } else {
                                parent.active_direct_id = Some(conv.id.clone());
                                touch_activity(&mut parent, policy, now_ms);
                                store.put(parent);
                            }
                        }
                    }
                    if conv.closed {
                        conv.closed = false;
                        conv.working = false;
                        conv.handoff = HandoffState::None;
                        push_state_event(&mut conv, &now_rfc3339, Some("resumed"));
                    }
                    conv.idle_timeout_secs = policy.idle_timeout_secs;
                    touch_activity(&mut conv, policy, now_ms);
                    if let Some(m) = msg {
                        let msg_req_id = req_id.clone().unwrap_or_else(new_msg_id);
                        record_user_message(&mut conv, &msg_req_id, m, &now_rfc3339);
                        if conv.responder == ResponderType::Agent {
                            let reply = responder.reply(session, &conv.id, Some(m)).await;
                            record_agent_reply(
                                &mut conv,
                                Some(&msg_req_id),
                                session,
                                reply,
                                &now_rfc3339,
                            );
                        }
                    }
                    store.put(conv.clone());
                    if let Some(rid) = req_id {
                        store.put_receipt(
                            &session.client_id,
                            &session.sub,
                            &rid,
                            RequestReceipt {
                                path: bare_path.to_string(),
                                body_canonical: canonical_body,
                                status: 200,
                                conversation_id: conv.id.clone(),
                            },
                        );
                    }
                    if wait_param.is_some() {
                        Some(events_response(200, &conv, cursor_param.as_deref(), policy))
                    } else {
                        Some(ConvHttpReply {
                            status: 200,
                            body: serde_json::to_vec(&conversation_summary_json(
                                base_path, &conv, policy,
                            ))
                            .unwrap_or_default(),
                            headers: vec![("cache-control", "no-store".into())],
                        })
                    }
                }
                _ => None,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_and_answer<S: ConversationStore, R: ConversationResponder>(
    conv_id: String,
    parent_id: Option<String>,
    req_id: &str,
    msg: Option<&Value>,
    session: &VerifiedSession,
    store: &S,
    responder: &R,
    policy: ConversationPolicy,
    now_ms: u64,
    now_rfc3339: &str,
) -> ConversationRecord {
    let mut conv = ConversationRecord {
        id: conv_id,
        client_id: session.client_id.clone(),
        sub: session.sub.clone(),
        bound_account: session.account_id.clone(),
        protocol_version: session.protocol_version.clone(),
        parent_conversation_id: parent_id,
        active_direct_id: None,
        working: false,
        handoff: HandoffState::None,
        responder: ResponderType::Agent,
        closed: false,
        events: Vec::new(),
        direct_by_invite: BTreeMap::new(),
        created_at_ms: now_ms,
        last_activity_ms: now_ms,
        idle_timeout_secs: policy.idle_timeout_secs,
    };
    if let Some(m) = msg {
        record_user_message(&mut conv, req_id, m, now_rfc3339);
    }
    let reply = responder.reply(session, &conv.id, msg).await;
    record_agent_reply(
        &mut conv,
        msg.map(|_| req_id),
        session,
        reply,
        now_rfc3339,
    );
    store.put(conv.clone());
    conv
}

fn effective_idle_timeout_secs(conv: &ConversationRecord, policy: ConversationPolicy) -> u64 {
    if conv.idle_timeout_secs > 0 {
        conv.idle_timeout_secs
    } else {
        policy.idle_timeout_secs
    }
}

fn touch_activity(conv: &mut ConversationRecord, policy: ConversationPolicy, now_ms: u64) {
    if conv.created_at_ms == 0 {
        conv.created_at_ms = now_ms;
    }
    conv.last_activity_ms = now_ms;
    if conv.idle_timeout_secs == 0 {
        conv.idle_timeout_secs = policy.idle_timeout_secs;
    }
}

fn apply_idle_expiry(
    conv: &mut ConversationRecord,
    policy: ConversationPolicy,
    now_ms: u64,
    now_rfc3339: &str,
) -> bool {
    if conv.closed || conv.last_activity_ms == 0 {
        return false;
    }
    let timeout = effective_idle_timeout_secs(conv, policy);
    if timeout == 0 {
        return false;
    }
    let expires_ms = conv.last_activity_ms.saturating_add(timeout.saturating_mul(1000));
    if now_ms >= expires_ms {
        conv.closed = true;
        conv.working = false;
        conv.handoff = HandoffState::None;
        push_state_event(conv, now_rfc3339, Some("inactivity_timeout"));
        true
    } else {
        false
    }
}

fn close_conversation_record<S: ConversationStore>(
    conv: &mut ConversationRecord,
    store: &S,
    policy: ConversationPolicy,
    now_ms: u64,
    now_rfc3339: &str,
) {
    if !conv.closed {
        conv.closed = true;
        conv.working = false;
        conv.handoff = HandoffState::None;
        touch_activity(conv, policy, now_ms);
        push_state_event(conv, now_rfc3339, None);
        // Closing a Direct Conversation notifies and unlocks parent (§8.10).
        if let Some(pid) = &conv.parent_conversation_id {
            if let Some(mut parent) = store.get(pid) {
                if parent.active_direct_id.as_deref() == Some(conv.id.as_str()) {
                    parent.active_direct_id = None;
                    let cid = new_evt_id();
                    parent.events.push(ConversationEvent {
                        id: cid.clone(),
                        body: serde_json::json!({
                            "id": cid,
                            "type": "direct_closed",
                            "created_at": now_rfc3339,
                            "conversation_id": conv.id
                        }),
                    });
                    store.put(parent);
                }
            }
        }
        // Closing a parent also closes its open Direct Conversation (§8.10).
        if let Some(did) = conv.active_direct_id.take() {
            if let Some(mut child) = store.get(&did) {
                if !child.closed {
                    child.closed = true;
                    child.working = false;
                    child.handoff = HandoffState::None;
                    touch_activity(&mut child, policy, now_ms);
                    push_state_event(&mut child, now_rfc3339, None);
                    store.put(child);
                }
            }
        }
        store.put(conv.clone());
    }
}

fn collect_visible_conversations<S: ConversationStore>(
    store: &S,
    session: &VerifiedSession,
    policy: ConversationPolicy,
    now_ms: u64,
    now_rfc3339: &str,
) -> Vec<ConversationRecord> {
    let mut out = Vec::new();
    for mut conv in store.list_for_owner(&session.client_id, &session.sub) {
        if check_ownership(&conv, session).is_err() {
            continue;
        }
        if apply_idle_expiry(&mut conv, policy, now_ms, now_rfc3339) {
            store.put(conv.clone());
        }
        out.push(conv);
    }
    out
}

fn conversation_summary_json(
    base_path: &str,
    conv: &ConversationRecord,
    policy: ConversationPolicy,
) -> Value {
    let timeout = effective_idle_timeout_secs(conv, policy);
    let mut obj = serde_json::json!({
        "conversation_id": conv.id,
        "closed": conv.closed,
        "working": conv.working,
        "handoff": conv.handoff,
        "responder": conv.responder,
        "parent_conversation_id": conv.parent_conversation_id,
        "active_direct_id": conv.active_direct_id,
        "event_count": conv.events.len(),
        "idle_timeout_secs": timeout,
        "retention_secs": policy.retention_secs,
        "events_endpoint": format!("{base_path}/{}/events", conv.id),
        "messages_endpoint": format!("{base_path}/{}/messages", conv.id),
        "close_endpoint": format!("{base_path}/{}/close", conv.id),
        "resume_endpoint": format!("{base_path}/{}/resume", conv.id),
    });
    if conv.created_at_ms > 0 {
        obj["created_at"] = Value::String(format_rfc3339_utc(conv.created_at_ms / 1000));
    }
    if conv.last_activity_ms > 0 {
        obj["last_activity_at"] = Value::String(format_rfc3339_utc(conv.last_activity_ms / 1000));
        if !conv.closed && timeout > 0 {
            let exp_secs = (conv.last_activity_ms / 1000).saturating_add(timeout);
            obj["expires_at"] = Value::String(format_rfc3339_utc(exp_secs));
        }
    }
    obj
}

fn check_ownership(conv: &ConversationRecord, session: &VerifiedSession) -> Result<(), ConvHttpReply> {
    if conv.client_id != session.client_id || conv.sub != session.sub {
        return Err(json_err(404, "conversation_not_found", None));
    }
    if let Some(bound) = &conv.bound_account {
        match &session.account_id {
            None => return Err(err_reply(PoppyError::auth_required(&[], None))),
            Some(acct) if acct != bound => {
                return Err(json_err(404, "conversation_not_found", None));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_incoming_message(msg: &Value) -> Result<(), PoppyError> {
    let obj = msg
        .as_object()
        .ok_or_else(|| PoppyError::invalid_request("message must be a JSON object"))?;
    let author = obj
        .get("author")
        .and_then(Value::as_object)
        .ok_or_else(|| PoppyError::invalid_request("message requires author object"))?;
    let author_type = author
        .get("type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PoppyError::invalid_request("message author requires type"))?;
    if author_type == "human" && obj.get("as_of_cursor").is_some() {
        return Err(PoppyError::invalid_request(
            "human messages must not include as_of_cursor (§8.4)",
        ));
    }
    let has_content = obj.get("text").is_some()
        || obj.get("data").is_some()
        || obj.get("context").is_some()
        || obj.get("extensions").is_some();
    if !has_content {
        return Err(PoppyError::invalid_request(
            "message must include at least one of text, data, context, or extensions (§8.4)",
        ));
    }
    Ok(())
}

fn record_user_message(conv: &mut ConversationRecord, req_id: &str, msg: &Value, now_rfc3339: &str) {
    let mut stored = Map::new();
    stored.insert("id".into(), Value::String(req_id.to_string()));
    stored.insert("role".into(), Value::String("user".into()));
    if let Some(obj) = msg.as_object() {
        // Only keep author.type on incoming messages (§8.4).
        let author_type = obj
            .get("author")
            .and_then(|a| a.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("agent");
        stored.insert("author".into(), serde_json::json!({ "type": author_type }));
        for field in ["text", "data", "context", "extensions", "as_of_cursor"] {
            if let Some(v) = obj.get(field) {
                stored.insert(field.into(), v.clone());
            }
        }
    }
    let evt_id = new_evt_id();
    conv.events.push(ConversationEvent {
        id: evt_id.clone(),
        body: serde_json::json!({
            "id": evt_id,
            "type": "message",
            "created_at": now_rfc3339,
            "message": Value::Object(stored)
        }),
    });
}

fn record_agent_reply(
    conv: &mut ConversationRecord,
    as_of_request: Option<&str>,
    session: &VerifiedSession,
    reply: AgentReply,
    now_rfc3339: &str,
) {
    let mut exts = Map::new();
    let mut fallback_notes = Vec::new();
    if !reply.links.is_empty() && session.has_extension(EXT_LINKS, EXT_LINKS_VERSION) {
        exts.insert(
            EXT_LINKS.into(),
            serde_json::json!({ "items": reply.links }),
        );
    }
    if !reply.disclosures.is_empty() {
        if session.has_extension(EXT_DISCLOSURES, EXT_DISCLOSURES_VERSION) {
            exts.insert(
                EXT_DISCLOSURES.into(),
                serde_json::json!({ "items": reply.disclosures }),
            );
        } else {
            // Disclosures §2: if Personal Agent didn't declare the extension, put notice in text.
            for d in &reply.disclosures {
                fallback_notes.push(d.text.clone());
            }
        }
    }
    if let Some(op_val) = reply.operation_content {
        if session.has_extension(EXT_OPERATIONS, EXT_OPERATIONS_VERSION) {
            exts.insert(EXT_OPERATIONS.into(), op_val);
        }
    }

    let text = match (reply.text, fallback_notes.is_empty()) {
        (Some(mut t), false) => {
            t.push_str("\n\n");
            t.push_str(&fallback_notes.join("\n"));
            Some(t)
        }
        (t, true) => t,
        (None, false) => Some(fallback_notes.join("\n")),
    };

    if text.is_some() || reply.data.is_some() || !exts.is_empty() {
        let mut author = Map::new();
        author.insert("type".into(), Value::String("agent".into()));
        if let Some(id) = reply.author_id {
            author.insert("id".into(), Value::String(id));
        }
        if let Some(name) = reply.author_name {
            author.insert("name".into(), Value::String(name));
        }
        let mut m = Map::new();
        m.insert("id".into(), Value::String(new_msg_id()));
        m.insert("role".into(), Value::String("company".into()));
        m.insert("author".into(), Value::Object(author));
        if let Some(req_id) = as_of_request {
            m.insert("as_of_request".into(), Value::String(req_id.to_string()));
        }
        if let Some(t) = text {
            m.insert("text".into(), Value::String(t));
        }
        if let Some(d) = reply.data {
            m.insert("data".into(), d);
        }
        if !exts.is_empty() {
            m.insert("extensions".into(), Value::Object(exts));
        }
        let evt_id = new_evt_id();
        conv.events.push(ConversationEvent {
            id: evt_id.clone(),
            body: serde_json::json!({
                "id": evt_id,
                "type": "message",
                "created_at": now_rfc3339,
                "message": Value::Object(m)
            }),
        });
    }

    if let Some(scopes) = reply.require_scopes {
        let evt_id = new_evt_id();
        conv.events.push(ConversationEvent {
            id: evt_id.clone(),
            body: serde_json::json!({
                "id": evt_id,
                "type": "authorization",
                "created_at": now_rfc3339,
                "error": "insufficient_scope",
                "scope": scopes.join(" ")
            }),
        });
    }

    if let Some(reason) = reply.request_user_reason {
        let evt_id = new_evt_id();
        conv.events.push(ConversationEvent {
            id: evt_id.clone(),
            body: serde_json::json!({
                "id": evt_id,
                "type": "user_requested",
                "created_at": now_rfc3339,
                "reason": reason
            }),
        });
    }
}

fn push_state_event(conv: &mut ConversationRecord, now_rfc3339: &str, reason: Option<&str>) {
    let evt_id = new_evt_id();
    let mut body = serde_json::json!({
        "id": evt_id,
        "type": "state",
        "created_at": now_rfc3339,
        "handoff": conv.handoff,
        "responder": conv.responder,
        "closed": conv.closed
    });
    if let Some(r) = reason {
        body["reason"] = Value::String(r.to_string());
    }
    conv.events.push(ConversationEvent { id: evt_id, body });
}

fn post_response(
    status: u16,
    conv: &ConversationRecord,
    cursor: Option<&str>,
    include_events: bool,
    policy: ConversationPolicy,
) -> ConvHttpReply {
    if include_events {
        events_response(status, conv, cursor, policy)
    } else {
        ConvHttpReply {
            status,
            body: serde_json::to_vec(&serde_json::json!({ "conversation_id": conv.id }))
                .unwrap_or_default(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }
}

fn events_response(
    status: u16,
    conv: &ConversationRecord,
    cursor: Option<&str>,
    policy: ConversationPolicy,
) -> ConvHttpReply {
    let start_idx = match cursor {
        None => 0,
        Some(c) => match conv.events.iter().position(|e| e.id == c) {
            Some(pos) => pos + 1,
            None => return json_err(400, "invalid_cursor", Some("unknown cursor for conversation")),
        },
    };
    let slice: Vec<&Value> = conv.events[start_idx..].iter().map(|e| &e.body).collect();
    let out_cursor = conv.events[start_idx..]
        .last()
        .map(|e| Value::String(e.id.clone()))
        .or_else(|| cursor.map(|c| Value::String(c.to_string())))
        .unwrap_or(Value::Null);

    let timeout = effective_idle_timeout_secs(conv, policy);
    let mut payload = serde_json::json!({
        "conversation_id": conv.id,
        "events": slice,
        "cursor": out_cursor,
        "has_more": false,
        "working": conv.working,
        "handoff": conv.handoff,
        "responder": conv.responder,
        "closed": conv.closed,
        "idle_timeout_secs": timeout,
        "retention_secs": policy.retention_secs,
    });
    if conv.last_activity_ms > 0 {
        payload["last_activity_at"] =
            Value::String(format_rfc3339_utc(conv.last_activity_ms / 1000));
        if !conv.closed && timeout > 0 {
            let exp_secs = (conv.last_activity_ms / 1000).saturating_add(timeout);
            payload["expires_at"] = Value::String(format_rfc3339_utc(exp_secs));
        }
    }
    ConvHttpReply {
        status,
        body: serde_json::to_vec(&payload).unwrap_or_default(),
        headers: vec![("cache-control", "no-store".into())],
    }
}

fn parse_action_doc(body: &[u8]) -> Result<(String, String), PoppyError> {
    let doc: Value = serde_json::from_slice(body)
        .map_err(|_| PoppyError::invalid_request("invalid JSON body"))?;
    let id = doc
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_valid_poppy_id(id))
        .map(str::to_string)
        .ok_or_else(|| PoppyError::invalid_request("missing or invalid request id"))?;
    let canonical = crate::agent_ready::poppy_ops::canonical_json(&doc);
    Ok((id, canonical))
}

fn err_reply(err: PoppyError) -> ConvHttpReply {
    ConvHttpReply {
        status: err.status,
        body: err.to_json_bytes(),
        headers: err.headers,
    }
}

fn json_err(status: u16, code: &'static str, desc: Option<&str>) -> ConvHttpReply {
    let mut obj = serde_json::json!({ "error": code });
    if let Some(d) = desc {
        obj["error_description"] = Value::String(d.to_string());
    }
    ConvHttpReply {
        status,
        body: serde_json::to_vec(&obj).unwrap_or_default(),
        headers: vec![("cache-control", "no-store".into())],
    }
}

fn conversation_closed_err(
    base_path: &str,
    conv: &ConversationRecord,
    policy: ConversationPolicy,
) -> ConvHttpReply {
    let timeout = effective_idle_timeout_secs(conv, policy);
    ConvHttpReply {
        status: 409,
        body: serde_json::to_vec(&serde_json::json!({
            "error": "conversation_closed",
            "error_description": format!(
                "Conversation {} is closed. Reopen it with POST {base_path}/{}/resume or open a new conversation with POST {base_path}.",
                conv.id, conv.id
            ),
            "conversation_id": conv.id,
            "events_endpoint": format!("{base_path}/{}/events", conv.id),
            "resume_endpoint": format!("{base_path}/{}/resume", conv.id),
            "new_conversation_endpoint": base_path,
            "idle_timeout_secs": timeout,
            "retention_secs": policy.retention_secs,
        }))
        .unwrap_or_default(),
        headers: vec![("cache-control", "no-store".into())],
    }
}

fn already_open_err(
    base_path: &str,
    open_convs: &[ConversationRecord],
    policy: ConversationPolicy,
) -> ConvHttpReply {
    let primary = &open_convs[0];
    let ids: Vec<&str> = open_convs.iter().map(|c| c.id.as_str()).collect();
    ConvHttpReply {
        status: 409,
        body: serde_json::to_vec(&serde_json::json!({
            "error": "already_open",
            "error_description": format!(
                "An active conversation ({}) is already open for this caller. Continue messaging it at POST {base_path}/{}/messages, close it at POST {base_path}/{}/close, or retry POST {base_path} with close_existing: true or resume_existing: true.",
                primary.id, primary.id, primary.id
            ),
            "conversation_id": primary.id,
            "open_conversation_ids": ids,
            "events_endpoint": format!("{base_path}/{}/events", primary.id),
            "messages_endpoint": format!("{base_path}/{}/messages", primary.id),
            "close_endpoint": format!("{base_path}/{}/close", primary.id),
            "resume_endpoint": format!("{base_path}/{}/resume", primary.id),
            "list_endpoint": base_path,
            "idle_timeout_secs": policy.idle_timeout_secs,
        }))
        .unwrap_or_default(),
        headers: vec![("cache-control", "no-store".into())],
    }
}

fn direct_open_err(base_path: &str, open_id: &str) -> ConvHttpReply {
    ConvHttpReply {
        status: 409,
        body: serde_json::to_vec(&serde_json::json!({
            "error": "direct_conversation_open",
            "error_description": format!(
                "Direct Conversation {open_id} is open on this parent conversation. Message or close it before posting to the parent."
            ),
            "conversation_id": open_id,
            "events_endpoint": format!("{base_path}/{open_id}/events"),
            "messages_endpoint": format!("{base_path}/{open_id}/messages"),
            "close_endpoint": format!("{base_path}/{open_id}/close"),
        }))
        .unwrap_or_default(),
        headers: vec![("cache-control", "no-store".into())],
    }
}

fn random_id(prefix: &str, label: &[u8]) -> String {
    let key = Ed25519SigningKey::generate_pkcs8();
    let bytes = hmac_sha256(&key, label);
    format!("{prefix}_{}", base64url_encode(&bytes[..12]))
}

fn new_conv_id() -> String {
    random_id("cnv", b"ferrite-agent-ready/poppy-conv/v1")
}

fn new_evt_id() -> String {
    random_id("evt", b"ferrite-agent-ready/poppy-evt/v1")
}

fn new_msg_id() -> String {
    random_id("msg", b"ferrite-agent-ready/poppy-msg/v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoResponder;
    impl ConversationResponder for EchoResponder {
        async fn reply(
            &self,
            _session: &VerifiedSession,
            _conversation_id: &str,
            user_message: Option<&Value>,
        ) -> AgentReply {
            let text = user_message
                .and_then(|m| m.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("Hello!");
            AgentReply {
                text: Some(format!("Echo: {text}")),
                links: vec![PoppyLink {
                    url: "https://shop.example/help".into(),
                    title: Some("Help".into()),
                }],
                disclosures: vec![PoppyDisclosure {
                    text: "Contains peanuts.".into(),
                }],
                ..Default::default()
            }
        }
    }

    fn sess(sub: &str, with_exts: bool) -> VerifiedSession {
        let mut extensions = BTreeMap::new();
        if with_exts {
            extensions.insert(EXT_LINKS.into(), EXT_LINKS_VERSION.into());
            extensions.insert(EXT_DISCLOSURES.into(), EXT_DISCLOSURES_VERSION.into());
        }
        VerifiedSession {
            protocol_version: "1.0".into(),
            extensions,
            client_id: "https://agent.example/agent.json".into(),
            sid: "sid_c".into(),
            sub: sub.into(),
            agent_id: None,
            delegated_kid: "kid_c".into(),
            ath: None,
            account_id: None,
            scopes: vec![],
        }
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended in a ready-only test"),
        }
    }

    #[test]
    fn conversation_lifecycle_idempotency_and_extensions() {
        block(async {
        let store = MemoryConversationStore::default();
        let responder = EchoResponder;
        let s = sess("usr_1", true);
        let now = 1_790_900_000_000u64;

        let start_body = serde_json::json!({
            "id": "req_start_1",
            "message": { "author": { "type": "agent" }, "text": "Need return info" }
        })
        .to_string();

        let r1 = handle_conversation(
            "/poppy/conversations",
            "POST",
            "/poppy/conversations",
            "wait=5",
            start_body.as_bytes(),
            &s,
            &store,
            &responder,
            now,
        )
        .await
        .unwrap();
        assert_eq!(r1.status, 201);
        let v1: Value = serde_json::from_slice(&r1.body).unwrap();
        let cid = v1["conversation_id"].as_str().unwrap().to_string();
        assert_eq!(v1["events"].as_array().unwrap().len(), 2);
        assert_eq!(
            v1["events"][1]["message"]["extensions"]["links"]["items"][0]["url"],
            "https://shop.example/help"
        );
        assert_eq!(
            v1["events"][1]["message"]["extensions"]["disclosures"]["items"][0]["text"],
            "Contains peanuts."
        );

        // Retrying same request ID with different body -> 409 request_id_conflict.
        let conflict_body = serde_json::json!({
            "id": "req_start_1",
            "message": { "author": { "type": "agent" }, "text": "Different text" }
        })
        .to_string();
        let r_conf = handle_conversation(
            "/poppy/conversations",
            "POST",
            "/poppy/conversations",
            "",
            conflict_body.as_bytes(),
            &s,
            &store,
            &responder,
            now + 1000,
        )
        .await
        .unwrap();
        assert_eq!(r_conf.status, 409);

        // Another user reading this conversation -> 404 conversation_not_found.
        let other = sess("usr_2", false);
        let r_other = handle_conversation(
            "/poppy/conversations",
            "GET",
            &format!("/poppy/conversations/{cid}/events"),
            "",
            b"",
            &other,
            &store,
            &responder,
            now + 2000,
        )
        .await
        .unwrap();
        assert_eq!(r_other.status, 404);

        // Handoff -> pending, then close -> closed=true.
        let r_hnd = handle_conversation(
            "/poppy/conversations",
            "POST",
            &format!("/poppy/conversations/{cid}/handoff"),
            "wait=0",
            br#"{"id":"hnd_1"}"#,
            &s,
            &store,
            &responder,
            now + 3000,
        )
        .await
        .unwrap();
        assert_eq!(r_hnd.status, 202);
        let vh: Value = serde_json::from_slice(&r_hnd.body).unwrap();
        assert_eq!(vh["handoff"], "pending");

        let r_close = handle_conversation(
            "/poppy/conversations",
            "POST",
            &format!("/poppy/conversations/{cid}/close"),
            "wait=0",
            br#"{"id":"cls_1"}"#,
            &s,
            &store,
            &responder,
            now + 4000,
        )
        .await
        .unwrap();
        assert_eq!(r_close.status, 202);
        let vc: Value = serde_json::from_slice(&r_close.body).unwrap();
        assert_eq!(vc["closed"], true);
        assert_eq!(vc["handoff"], "none");
        });
    }

    #[test]
    fn conversation_list_idle_expiry_resume_already_open_and_human_responder() {
        block(async {
        let store = MemoryConversationStore::default();
        let responder = EchoResponder;
        let s = sess("usr_life", true);
        let policy = ConversationPolicy {
            idle_timeout_secs: 600,
            retention_secs: 86_400,
            max_open_per_user: Some(1),
        };
        let t0 = 1_790_900_000_000u64;

        // 1. Open first conversation.
        let r1 = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            "/poppy/conversations",
            "wait=0",
            br#"{"id":"req_1","message":{"author":{"type":"agent"},"text":"Hi"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t0,
        )
        .await
        .unwrap();
        assert_eq!(r1.status, 201);
        let v1: Value = serde_json::from_slice(&r1.body).unwrap();
        let cid1 = v1["conversation_id"].as_str().unwrap().to_string();
        assert_eq!(v1["idle_timeout_secs"], 600);
        assert_eq!(v1["retention_secs"], 86_400);
        assert!(v1["expires_at"].as_str().is_some());

        // 2. GET /poppy/conversations lists it as active.
        let r_list = handle_conversation_with_policy(
            "/poppy/conversations",
            "GET",
            "/poppy/conversations",
            "status=open",
            b"",
            &s,
            &store,
            &responder,
            policy,
            t0 + 10_000,
        )
        .await
        .unwrap();
        assert_eq!(r_list.status, 200);
        let vl: Value = serde_json::from_slice(&r_list.body).unwrap();
        assert_eq!(vl["active_conversation_id"], cid1);
        assert_eq!(vl["open_count"], 1);

        // 3. Opening a second while first is open -> 409 already_open with recovery fields.
        let r_dup = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            "/poppy/conversations",
            "",
            br#"{"id":"req_2","message":{"author":{"type":"agent"},"text":"Second"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t0 + 20_000,
        )
        .await
        .unwrap();
        assert_eq!(r_dup.status, 409);
        let vdup: Value = serde_json::from_slice(&r_dup.body).unwrap();
        assert_eq!(vdup["error"], "already_open");
        assert_eq!(vdup["conversation_id"], cid1);
        assert!(vdup["close_endpoint"].as_str().unwrap().contains(&cid1));

        // 4. Advance past idle_timeout_secs -> auto-closes on message with recovery links, events stay readable.
        let t_exp = t0 + 700_000;
        let r_after_exp = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            &format!("/poppy/conversations/{cid1}/messages"),
            "",
            br#"{"id":"req_3","message":{"author":{"type":"agent"},"text":"Still there?"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t_exp,
        )
        .await
        .unwrap();
        assert_eq!(r_after_exp.status, 409);
        let vexp: Value = serde_json::from_slice(&r_after_exp.body).unwrap();
        assert_eq!(vexp["error"], "conversation_closed");
        assert_eq!(vexp["conversation_id"], cid1);
        assert!(vexp["resume_endpoint"].as_str().unwrap().ends_with("/resume"));

        // Events remain readable with inactivity_timeout state event.
        let r_ev = handle_conversation_with_policy(
            "/poppy/conversations",
            "GET",
            &format!("/poppy/conversations/{cid1}/events"),
            "",
            b"",
            &s,
            &store,
            &responder,
            policy,
            t_exp + 1_000,
        )
        .await
        .unwrap();
        assert_eq!(r_ev.status, 200);
        let vev: Value = serde_json::from_slice(&r_ev.body).unwrap();
        assert_eq!(vev["closed"], true);
        assert_eq!(
            vev["events"].as_array().unwrap().last().unwrap()["reason"],
            "inactivity_timeout"
        );

        // 5. Resume closed conversation + send a follow-up message in one step.
        let r_res = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            &format!("/poppy/conversations/{cid1}/resume"),
            "wait=0",
            br#"{"id":"req_res_1","message":{"author":{"type":"agent"},"text":"Back again"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t_exp + 2_000,
        )
        .await
        .unwrap();
        assert_eq!(r_res.status, 200);
        let vres: Value = serde_json::from_slice(&r_res.body).unwrap();
        assert_eq!(vres["closed"], false);
        assert!(vres["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e.pointer("/message/text").and_then(Value::as_str) == Some("Echo: Back again")));

        // 6. close_existing: true closes cid1 and opens cid2 cleanly.
        let r_replace = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            "/poppy/conversations",
            "wait=0",
            br#"{"id":"req_rep_1","close_existing":true,"message":{"author":{"type":"agent"},"text":"Fresh thread"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t_exp + 5_000,
        )
        .await
        .unwrap();
        assert_eq!(r_replace.status, 201);
        let vrep: Value = serde_json::from_slice(&r_replace.body).unwrap();
        let cid2 = vrep["conversation_id"].as_str().unwrap().to_string();
        assert_ne!(cid2, cid1);
        assert!(store.get(&cid1).unwrap().closed);

        // 7. When human staff takes over (responder == Human), incoming user messages do NOT trigger AI reply.
        let mut rec = store.get(&cid2).unwrap();
        rec.responder = ResponderType::Human;
        let ev_before = rec.events.len();
        store.put(rec);
        let r_human = handle_conversation_with_policy(
            "/poppy/conversations",
            "POST",
            &format!("/poppy/conversations/{cid2}/messages"),
            "wait=0",
            br#"{"id":"req_hum_1","message":{"author":{"type":"agent"},"text":"Hi staff"}}"#,
            &s,
            &store,
            &responder,
            policy,
            t_exp + 10_000,
        )
        .await
        .unwrap();
        assert_eq!(r_human.status, 202);
        let vhum: Value = serde_json::from_slice(&r_human.body).unwrap();
        assert_eq!(
            vhum["events"].as_array().unwrap().len(),
            ev_before + 1,
            "human responder should record user message without auto AI reply"
        );
        });
    }

    #[test]
    fn strip_markup_preserves_unicode_and_emoji_while_removing_scripts_and_tags() {
        assert_eq!(
            strip_markup_and_controls("Zoë 🚀 O'Neil-Smith <script>alert(1)</script>"),
            "Zoë 🚀 O'Neil-Smith"
        );
        assert_eq!(
            strip_markup_and_controls("<b>Ada</b> <img src=x onerror=alert(1)> Lovelace"),
            "Ada Lovelace"
        );
        assert_eq!(
            strip_markup_and_controls("Sam\u{0007}\n<SCRIPT>evil()"),
            "Sam"
        );
        let parts = normalized_words_and_parts("Welke yin-lessen zijn er op 2026-11-28?");
        assert!(parts.iter().any(|t| t == "yin-lessen"));
        assert!(parts.iter().any(|t| t == "yin"));
        assert!(parts.iter().any(|t| t == "lessen"));
        assert!(parts.iter().any(|t| t == "2026-11-28"));
    }
}
