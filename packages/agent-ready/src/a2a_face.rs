//! The A2A face — the agent card's `url` answers A2A JSON-RPC.
//!
//! A2A v0.3.0 defines an agent by its card and the JSON-RPC methods served at
//! the card's `url` under `preferredTransport: "JSONRPC"`. Every declared
//! operation is a skill. A message invokes one with a data part:
//!
//! ```json
//! { "kind": "data", "data": { "skill": "get_quote", "arguments": { "tag": "systems" } } }
//! ```
//!
//! Tool execution is the host's own handler, exactly as for the MCP face —
//! the same operation, the same authorization, the same effects.
//!
//! # Two modes
//!
//! **With a [`TaskStore`]** ([`handle_with`]) every `message/send` creates or
//! continues a `Task` the caller can read back with `tasks/get` and cancel
//! with `tasks/cancel`:
//!
//! - a message without a skill part leaves the task `input-required`, its
//!   status message listing the skills and the invocation shape;
//! - a skill invocation completes the task (`completed`, or `failed` when the
//!   operation reports an error) with the result as an artifact;
//! - a message naming a `taskId` continues that task; a terminal task cannot
//!   be continued or canceled.
//!
//! The store is supplied by the host already bound to the caller, so one
//! caller can never read, continue or cancel another's task: a foreign id is
//! simply `TaskNotFoundError`. Saves are compare-and-set on the version the
//! request loaded, so a cancel racing a completion cannot silently overwrite.
//!
//! **Without one** ([`handle`], [`NoTasks`]) the face is stateless: a message
//! is answered with an agent `Message` (A2A lets `message/send` return a
//! `Message` rather than a `Task`) and every task method answers
//! `TaskNotFoundError`.
//!
//! Streaming and push notifications are not offered and answer the typed A2A
//! errors the card's capabilities predict. JSON-RPC errors travel with HTTP
//! 200 (a body that cannot be parsed answers 400 with `-32700`). A request
//! without `id` is still answered, with `id: null`: A2A defines no client
//! notifications.

use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::mcp_face::ToolOutcome;
use crate::agent_ready::surface::Surface;

/// The A2A protocol version this face implements.
pub const PROTOCOL_VERSION: &str = "0.3.0";

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// A2A `TaskNotFoundError`.
pub const TASK_NOT_FOUND: i64 = -32001;
/// A2A `TaskNotCancelableError`.
pub const TASK_NOT_CANCELABLE: i64 = -32002;
/// A2A `PushNotificationNotSupportedError`.
pub const PUSH_NOT_SUPPORTED: i64 = -32003;
/// A2A `UnsupportedOperationError`.
pub const UNSUPPORTED_OPERATION: i64 = -32004;
/// A2A `AuthenticatedExtendedCardNotConfiguredError`.
pub const EXTENDED_CARD_NOT_CONFIGURED: i64 = -32007;

/// The most history entries a task keeps (oldest dropped first).
pub const HISTORY_LIMIT: usize = 50;

/// The largest request body this face accepts, in bytes. A message is
/// stored in the task history and echoed back, so an unbounded one would
/// make every later `tasks/get` pay for it.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Durable, caller-scoped task storage supplied by the host.
///
/// Implementations must bind every key to the authenticated caller before
/// this face sees it. `load` returns the stored task and an opaque version;
/// `save` writes only when the stored version still equals `expected`
/// (`None` = create only if absent) and returns `Ok(false)` on a mismatch.
pub trait TaskStore {
    /// Whether this store persists tasks. [`NoTasks`] answers false.
    fn persists(&self) -> bool {
        true
    }
    /// A fresh, unguessable task id.
    fn new_id(&self) -> Result<String, String>;
    /// The host clock, epoch milliseconds. `0` (the default) disables lease
    /// expiry, so a host that wants interrupted claims reconciled supplies it.
    fn now_ms(&self) -> u64 {
        0
    }
    /// How long a skill claim may stay `working` before a reader treats the
    /// execution as interrupted.
    fn lease_ms(&self) -> u64 {
        DEFAULT_LEASE_MS
    }
    /// Read a task.
    async fn load(&self, id: &str) -> Result<Option<(Value, u64)>, String>;
    /// Compare-and-set a task.
    async fn save(&self, id: &str, task: &Value, expected: Option<u64>) -> Result<bool, String>;
}

/// The default claim lease: a skill is one request/reply operation on the
/// host, so a claim older than this was abandoned by a process that stopped.
pub const DEFAULT_LEASE_MS: u64 = 60_000;

/// Load a task, reconciling an expired claim first.
///
/// A task is `working` only while a process holds its claim. If that process
/// stopped (after the claim was saved, or after the skill ran but before the
/// result was saved) the lease runs out and the first reader moves the task to
/// `failed`, saying the effect is unknown. A replay of the same message then
/// reads that answer instead of running the skill a second time; a caller who
/// decides to retry sends a new message.
async fn load_reconciled<S: TaskStore>(tasks: &S, task_id: &str) -> Result<Option<(Value, u64)>, String> {
    for _ in 0..3 {
        let Some((mut task, version)) = tasks.load(task_id).await? else {
            return Ok(None);
        };
        let now = tasks.now_ms();
        let lease_until = task.pointer("/metadata/ferriteClaim/leaseUntilMs").and_then(Value::as_u64);
        let expired = task_state(&task) == "working" && now > 0 && lease_until.is_some_and(|until| now > until);
        if !expired {
            return Ok(Some((task, version)));
        }
        let claimed_message = task
            .pointer("/metadata/ferriteClaim/messageId")
            .cloned()
            .unwrap_or(Value::Null);
        let context = task["contextId"].clone();
        let reply = serde_json::json!({
            "kind": "message",
            "role": "agent",
            "messageId": format!("{}:interrupted", claimed_message.as_str().unwrap_or("")),
            "taskId": task_id,
            "contextId": context,
            "parts": [ { "kind": "text", "text": "This task was interrupted before its result was recorded. Whether the skill's effect happened is unknown; check before retrying, and retry with a new message." } ],
            "metadata": { "interrupted": true, "effectUnknown": true, "messageId": claimed_message }
        });
        task["status"] = serde_json::json!({ "state": "failed", "message": reply.clone() });
        if let Some(meta) = task["metadata"].as_object_mut() {
            meta.remove("ferriteClaim");
        }
        push_history(&mut task, reply);
        if tasks.save(task_id, &task, Some(version)).await? {
            return Ok(tasks.load(task_id).await?);
        }
        // Someone else changed it (the claimant finished, or another reader
        // reconciled): read again.
    }
    tasks.load(task_id).await
}

/// The stateless mode: nothing is stored, every task is not found.
pub struct NoTasks;

impl TaskStore for NoTasks {
    fn persists(&self) -> bool {
        false
    }
    fn new_id(&self) -> Result<String, String> {
        Err("this agent does not create tasks".into())
    }
    async fn load(&self, _id: &str) -> Result<Option<(Value, u64)>, String> {
        Ok(None)
    }
    async fn save(&self, _id: &str, _task: &Value, _expected: Option<u64>) -> Result<bool, String> {
        Ok(false)
    }
}

fn rpc_result(id: &Value, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn answer(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap_or_default())
}

/// Validate a `Message` object per A2A v0.3.0 §6.4, returning it and its parts.
fn message_parts(params: &Value) -> Result<(&Map<String, Value>, &Vec<Value>), String> {
    let params = params
        .as_object()
        .ok_or_else(|| "params must be an object".to_string())?;
    let message = params
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| "params.message must be a Message object".to_string())?;
    if message.get("kind").and_then(Value::as_str) != Some("message") {
        return Err("message.kind must be \"message\"".into());
    }
    if !message.get("messageId").is_some_and(Value::is_string) {
        return Err("message.messageId must be a string".into());
    }
    if message.get("role").and_then(Value::as_str) != Some("user") {
        return Err("message.role must be \"user\"".into());
    }
    for key in ["taskId", "contextId"] {
        if message.get(key).is_some_and(|v| !v.is_string()) {
            return Err(format!("message.{key} must be a string"));
        }
    }
    let parts = message
        .get("parts")
        .and_then(Value::as_array)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "message.parts must be a non-empty array".to_string())?;
    for part in parts {
        match part.get("kind").and_then(Value::as_str) {
            Some("text") if part.get("text").is_some_and(Value::is_string) => {}
            Some("data") if part.get("data").is_some_and(Value::is_object) => {}
            Some("file") if part.get("file").is_some_and(Value::is_object) => {}
            _ => return Err("every part must be a valid text, data or file part".into()),
        }
    }
    Ok((message, parts))
}

fn agent_message(request: &Map<String, Value>, parts: Vec<Value>, metadata: Option<Value>) -> Value {
    let request_id = request.get("messageId").and_then(Value::as_str).unwrap_or("");
    let mut m = serde_json::json!({
        "kind": "message",
        "role": "agent",
        "messageId": format!("{request_id}:reply"),
        "parts": parts,
    });
    for key in ["contextId", "taskId"] {
        if let Some(v) = request.get(key).filter(|v| v.is_string()) {
            m[key] = v.clone();
        }
    }
    if let Some(meta) = metadata {
        m["metadata"] = meta;
    }
    m
}

/// The guidance a conversational message receives: the skills and how to
/// invoke one.
fn guidance(surface: &Surface) -> String {
    let mut out = format!(
        "{} serves these skills over A2A. Invoke one with a data part {{\"skill\": \"<id>\", \"arguments\": {{...}}}}.\n",
        surface.name
    );
    for o in surface.operations() {
        out.push_str(&format!("- {}: {}\n", o.name, o.description));
    }
    out
}

fn is_terminal(state: &str) -> bool {
    matches!(state, "completed" | "canceled" | "failed" | "rejected")
}

fn task_state(task: &Value) -> &str {
    task.pointer("/status/state").and_then(Value::as_str).unwrap_or("unknown")
}

fn push_history(task: &mut Value, message: Value) {
    if !task["history"].is_array() {
        task["history"] = Value::Array(Vec::new());
    }
    if let Some(h) = task["history"].as_array_mut() {
        h.push(message);
        if h.len() > HISTORY_LIMIT {
            let excess = h.len() - HISTORY_LIMIT;
            h.drain(..excess);
        }
    }
}

/// Answer one A2A JSON-RPC POST body without task storage. See [`handle_with`].
pub async fn handle<F, Fut>(surface: &Surface, body: &[u8], exec: F) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    handle_with(surface, body, &NoTasks, exec).await
}

/// Answer one A2A JSON-RPC POST body. `tasks` is the caller-bound store;
/// `exec` runs a named operation with its arguments (the host's own handler).
/// Returns `(http_status, body)`.
pub async fn handle_with<S, F, Fut>(surface: &Surface, body: &[u8], tasks: &S, exec: F) -> (u16, Vec<u8>)
where
    S: TaskStore,
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    if body.len() > MAX_BODY_BYTES {
        let r = rpc_error(
            &Value::Null,
            INVALID_REQUEST,
            &format!("request body exceeds {MAX_BODY_BYTES} bytes"),
        );
        return (413, serde_json::to_vec(&r).unwrap_or_default());
    }
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            let r = rpc_error(&Value::Null, PARSE_ERROR, &format!("parse error: {e}"));
            return (400, serde_json::to_vec(&r).unwrap_or_default());
        }
    };
    let Some(obj) = v.as_object() else {
        return answer(rpc_error(&Value::Null, INVALID_REQUEST, "request must be a JSON object"));
    };
    let id = obj.get("id").cloned().unwrap_or(Value::Null);
    if !(id.is_null() || id.is_string() || id.is_i64() || id.is_u64()) {
        return answer(rpc_error(&Value::Null, INVALID_REQUEST, "id must be a string, an integer or null"));
    }
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return answer(rpc_error(&id, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
    }
    let method = match obj.get("method") {
        Some(Value::String(m)) => m.as_str(),
        _ => return answer(rpc_error(&id, INVALID_REQUEST, "method must be a string")),
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let resp = match method {
        "message/send" => match message_parts(&params) {
            Err(msg) => rpc_error(&id, INVALID_PARAMS, &msg),
            Ok((message, parts)) => send(surface, tasks, &exec, &id, message, parts).await,
        },
        "tasks/get" => match params.get("id").and_then(Value::as_str) {
            None => rpc_error(&id, INVALID_PARAMS, "params.id must be a task id string"),
            Some(task_id) => {
                let history_length = match params.get("historyLength") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_u64() {
                        Some(n) => Some(n as usize),
                        None => return answer(rpc_error(&id, INVALID_PARAMS, "historyLength must be a non-negative integer")),
                    },
                };
                match load_reconciled(tasks, task_id).await {
                    Err(e) => rpc_error(&id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
                    Ok(None) => rpc_error(&id, TASK_NOT_FOUND, &format!("task '{task_id}' not found")),
                    Ok(Some((mut task, _))) => {
                        if let Some(n) = history_length {
                            if let Some(h) = task["history"].as_array_mut() {
                                let keep = h.len().saturating_sub(n);
                                h.drain(..keep);
                            } else {
                                task["history"] = Value::Array(Vec::new());
                            }
                        }
                        rpc_result(&id, task)
                    }
                }
            }
        },
        "tasks/cancel" => match params.get("id").and_then(Value::as_str) {
            None => rpc_error(&id, INVALID_PARAMS, "params.id must be a task id string"),
            Some(task_id) => match load_reconciled(tasks, task_id).await {
                Err(e) => rpc_error(&id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
                Ok(None) => rpc_error(&id, TASK_NOT_FOUND, &format!("task '{task_id}' not found")),
                Ok(Some((mut task, version))) => {
                    let state = task_state(&task).to_string();
                    if is_terminal(&state) {
                        rpc_error(&id, TASK_NOT_CANCELABLE, &format!("task '{task_id}' is already {state}"))
                    } else {
                        task["status"] = serde_json::json!({ "state": "canceled" });
                        // The claim is internal to an execution; a canceled task does not carry it.
                        if let Some(meta) = task["metadata"].as_object_mut() {
                            meta.remove("ferriteClaim");
                            if meta.is_empty() {
                                task.as_object_mut().map(|t| t.remove("metadata"));
                            }
                        }
                        match tasks.save(task_id, &task, Some(version)).await {
                            Err(e) => rpc_error(&id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
                            Ok(false) => rpc_error(&id, INTERNAL_ERROR, "the task changed concurrently; read it and retry"),
                            Ok(true) => rpc_result(&id, task),
                        }
                    }
                }
            },
        },
        "message/stream" | "tasks/resubscribe" => {
            rpc_error(&id, UNSUPPORTED_OPERATION, "streaming is not offered (capabilities.streaming is false)")
        }
        m if m.starts_with("tasks/pushNotificationConfig/") => {
            rpc_error(&id, PUSH_NOT_SUPPORTED, "push notifications are not offered (capabilities.pushNotifications is false)")
        }
        "agent/getAuthenticatedExtendedCard" => {
            rpc_error(&id, EXTENDED_CARD_NOT_CONFIGURED, "no authenticated extended card is configured")
        }
        other => rpc_error(&id, METHOD_NOT_FOUND, &format!("method '{other}' not supported")),
    };
    answer(resp)
}

/// Build an [`crate::agent_ready::telemetry::AgentEvent`] describing one `/a2a`
/// JSON-RPC exchange: method, skill name on `message/send`, task state, and ok/err.
pub fn telemetry_event(
    req_body: &[u8],
    status: u16,
    resp_body: &[u8],
) -> crate::agent_ready::telemetry::AgentEvent {
    let req_val = serde_json::from_slice::<Value>(req_body).ok();
    let resp_val = if resp_body.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(resp_body).ok()
    };

    let method = req_val
        .as_ref()
        .and_then(|v| v.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("invalid");

    let skill_opt = if method == "message/send" {
        req_val
            .as_ref()
            .and_then(|v| v.pointer("/params/message/parts"))
            .and_then(Value::as_array)
            .and_then(|parts| {
                parts.iter().find_map(|p| {
                    p.get("data")
                        .and_then(|d| d.get("skill"))
                        .and_then(Value::as_str)
                })
            })
    } else {
        None
    };

    if let Some(err_obj) = resp_val.as_ref().and_then(|r| r.get("error")) {
        let code_str = err_obj
            .get("code")
            .and_then(Value::as_i64)
            .map(|c| c.to_string());
        return crate::agent_ready::telemetry::AgentEvent::a2a(
            method,
            skill_opt,
            None,
            false,
            code_str.as_deref(),
        );
    }

    if let Some(res_obj) = resp_val.as_ref().and_then(|r| r.get("result")) {
        let task_state = res_obj
            .pointer("/status/state")
            .and_then(Value::as_str);
        let is_skill_err = res_obj
            .pointer("/metadata/isError")
            .and_then(Value::as_bool)
            == Some(true)
            || matches!(task_state, Some("failed" | "rejected"));
        let ok = status < 400 && !is_skill_err;
        let err_opt = if is_skill_err {
            Some("skill_error")
        } else {
            None
        };
        return crate::agent_ready::telemetry::AgentEvent::a2a(
            method,
            skill_opt,
            task_state,
            ok,
            err_opt,
        );
    }

    crate::agent_ready::telemetry::AgentEvent::a2a(
        method,
        skill_opt,
        None,
        status < 400,
        None,
    )
}

async fn send<S, F, Fut>(
    surface: &Surface,
    tasks: &S,
    exec: &F,
    id: &Value,
    message: &Map<String, Value>,
    parts: &[Value],
) -> Value
where
    S: TaskStore,
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    let invocation = parts.iter().find_map(|p| {
        let data = p.get("data")?;
        let skill = data.get("skill")?.as_str()?;
        Some((skill.to_string(), data.get("arguments").cloned()))
    });
    if let Some((skill, args)) = &invocation {
        if surface.operation(skill).is_none() {
            return rpc_error(id, INVALID_PARAMS, &format!("unknown skill '{skill}'"));
        }
        if args.as_ref().is_some_and(|a| !a.is_object()) {
            return rpc_error(id, INVALID_PARAMS, "data.arguments must be an object");
        }
    }

    // The existing task this message continues, if it names one.
    let continued = match message.get("taskId").and_then(Value::as_str) {
        None => None,
        Some(task_id) if tasks.persists() => match load_reconciled(tasks, task_id).await {
            Err(e) => return rpc_error(id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
            Ok(None) => return rpc_error(id, TASK_NOT_FOUND, &format!("task '{task_id}' not found")),
            Ok(Some((task, version))) => {
                // A replayed message is answered with the task as it stands:
                // the skill it named has already run (or is running) once.
                if has_message(&task, message) {
                    return rpc_result(id, task);
                }
                let state = task_state(&task).to_string();
                if is_terminal(&state) {
                    return rpc_error(id, INVALID_PARAMS, &format!("task '{task_id}' is {state} and cannot be continued"));
                }
                // One skill at a time per task: a continuation that arrived
                // while another message's skill runs would otherwise overwrite
                // that result when both save.
                if state == "working" {
                    return rpc_error(id, INVALID_PARAMS, &format!("task '{task_id}' is working; read it with tasks/get and continue once it settles"));
                }
                Some((task_id.to_string(), task, version))
            }
        },
        Some(task_id) => return rpc_error(id, TASK_NOT_FOUND, &format!("task '{task_id}' not found")),
    };

    if !tasks.persists() {
        let outcome = match invocation {
            None => None,
            Some((skill, args)) => {
                let result = exec(skill.clone(), args.unwrap_or_else(|| serde_json::json!({}))).await;
                Some((skill, result))
            }
        };
        return match outcome {
            None => rpc_result(id, agent_message(message, vec![serde_json::json!({ "kind": "text", "text": guidance(surface) })], None)),
            Some((skill, result)) => {
                let meta = serde_json::json!({ "skill": skill, "isError": result.is_error });
                rpc_result(id, agent_message(message, vec![serde_json::json!({ "kind": "data", "data": result.value })], Some(meta)))
            }
        };
    }

    // Claim before execute. The user message enters the task history and the
    // task is saved `working` under compare-and-set BEFORE the skill runs, so a
    // replay or a concurrent duplicate of the same `messageId` loses the claim
    // and reads the task back instead of running the skill a second time.
    let (task_id, mut task, mut version) = match continued {
        Some((task_id, task, version)) => (task_id, task, Some(version)),
        None => {
            let task_id = task_id_for(message);
            let context = message
                .get("contextId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("ctx-{task_id}"));
            let task = serde_json::json!({
                "kind": "task",
                "id": task_id,
                "contextId": context,
                "status": { "state": "submitted" },
                "history": [],
                "artifacts": [],
            });
            (task_id, task, None)
        }
    };
    let mut user = Value::Object(message.clone());
    user["taskId"] = Value::String(task_id.clone());
    user["contextId"] = task["contextId"].clone();
    push_history(&mut task, user);

    if invocation.is_some() {
        task["status"] = serde_json::json!({ "state": "working" });
        let lease_until = match tasks.now_ms() {
            0 => Value::Null,
            now => Value::from(now.saturating_add(tasks.lease_ms())),
        };
        if !task["metadata"].is_object() {
            task["metadata"] = Value::Object(Map::new());
        }
        task["metadata"]["ferriteClaim"] = serde_json::json!({
            "messageId": message.get("messageId").cloned().unwrap_or(Value::Null),
            "leaseUntilMs": lease_until,
        });
        match tasks.save(&task_id, &task, version).await {
            Err(e) => return rpc_error(id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
            Ok(true) => {}
            Ok(false) => return replayed(tasks, id, &task_id, message).await,
        }
        version = match tasks.load(&task_id).await {
            // Still our claim: run the skill under this version.
            Ok(Some((current, v))) if task_state(&current) == "working" && has_message(&current, message) => Some(v),
            // Changed between the claim and now (for example canceled): answer
            // with what is stored rather than running the skill.
            Ok(Some((current, _))) => return rpc_result(id, current),
            Ok(None) => return rpc_error(id, INTERNAL_ERROR, "the claimed task disappeared"),
            Err(e) => return rpc_error(id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
        };
    }

    let outcome = match invocation {
        None => None,
        Some((skill, args)) => {
            let result = exec(skill.clone(), args.unwrap_or_else(|| serde_json::json!({}))).await;
            Some((skill, result))
        }
    };

    let reply = match outcome {
        None => {
            let mut m = agent_message(message, vec![serde_json::json!({ "kind": "text", "text": guidance(surface) })], None);
            m["taskId"] = Value::String(task_id.clone());
            m["contextId"] = task["contextId"].clone();
            task["status"] = serde_json::json!({ "state": "input-required", "message": m.clone() });
            m
        }
        Some((skill, result)) => {
            let meta = serde_json::json!({ "skill": skill, "isError": result.is_error });
            let mut m = agent_message(message, vec![serde_json::json!({ "kind": "data", "data": result.value.clone() })], Some(meta));
            m["taskId"] = Value::String(task_id.clone());
            m["contextId"] = task["contextId"].clone();
            let n = task["artifacts"].as_array().map_or(0, Vec::len);
            if !task["artifacts"].is_array() {
                task["artifacts"] = Value::Array(Vec::new());
            }
            if let Some(a) = task["artifacts"].as_array_mut() {
                a.push(serde_json::json!({
                    "artifactId": format!("{task_id}-{}", n + 1),
                    "name": skill,
                    "parts": [ { "kind": "data", "data": result.value } ],
                }));
            }
            let state = if result.is_error { "failed" } else { "completed" };
            task["status"] = serde_json::json!({ "state": state, "message": m.clone() });
            m
        }
    };
    push_history(&mut task, reply);
    if let Some(meta) = task["metadata"].as_object_mut() {
        meta.remove("ferriteClaim");
        if meta.is_empty() {
            task.as_object_mut().map(|t| t.remove("metadata"));
        }
    }
    match tasks.save(&task_id, &task, version).await {
        Err(e) => rpc_error(id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
        Ok(false) => {
            // A cancel that landed while the skill ran must not read as a clean
            // cancellation: the skill finished and its effect happened.
            if let Ok(Some((current, _))) = load_reconciled(tasks, &task_id).await {
                if current["status"]["state"] == "canceled" || current["status"]["state"] == "failed" {
                    return rpc_error(
                        id,
                        INTERNAL_ERROR,
                        &format!(
                            "task '{task_id}' was {} while its skill was running; the skill completed and its effect happened — read the task before retrying",
                            current["status"]["state"].as_str().unwrap_or("changed")
                        ),
                    );
                }
            }
            replayed(tasks, id, &task_id, message).await
        }
        Ok(true) => rpc_result(id, task),
    }
}

/// The task id a message opens: a digest of its `messageId`, so a replay of
/// the same message names the same task. The store is already scoped to the
/// caller, so two callers' identical message ids never meet.
fn task_id_for(message: &Map<String, Value>) -> String {
    let message_id = message.get("messageId").and_then(Value::as_str).unwrap_or("");
    let digest = crate::agent_ready::sha256::sha256_concat(&[b"a2a-task\0", message_id.as_bytes()]);
    let hex = crate::agent_ready::sha256::to_hex(&digest);
    format!("task-{}", &hex[..32])
}

/// Whether `task` already holds the user message carrying this `messageId`.
fn has_message(task: &Value, message: &Map<String, Value>) -> bool {
    let Some(message_id) = message.get("messageId").and_then(Value::as_str) else {
        return false;
    };
    task["history"].as_array().is_some_and(|h| {
        h.iter().any(|m| m["role"] == "user" && m["messageId"].as_str() == Some(message_id))
    })
}

/// Answer a message that lost its compare-and-set: if the task now carries
/// this very message, a duplicate already claimed it and the current task is
/// the answer; anything else is a genuine concurrent change.
async fn replayed<S: TaskStore>(tasks: &S, id: &Value, task_id: &str, message: &Map<String, Value>) -> Value {
    match load_reconciled(tasks, task_id).await {
        Err(e) => rpc_error(id, INTERNAL_ERROR, &format!("task storage failed: {e}")),
        Ok(Some((task, _))) if has_message(&task, message) => rpc_result(id, task),
        Ok(_) => rpc_error(id, INTERNAL_ERROR, "the task changed concurrently; read it and retry"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn surface() -> Surface {
        Surface {
            name: "notes".into(),
            owner: "labs".into(),
            origin: "https://notes.example".into(),
            description: "A note-keeping API.".into(),
            version: "1.0.0".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "notes API".into(),
                operations: vec![Operation {
                    name: "list_notes".into(),
                    method: "GET".into(),
                    path: "/api/notes".into(),
                    description: "List notes.".into(),
                    input_schema: None,
                    output_schema: None,
                    read_only: true,
                    idempotent: true,
                    price_micros: 0,
                }],
            }],
            pages: vec![],
        }
    }

    /// A caller-scoped in-memory store: keys are `scope/id`.
    struct MemTasks<'a> {
        scope: &'static str,
        rows: &'a RefCell<BTreeMap<String, (Value, u64)>>,
        next: RefCell<u64>,
    }

    /// A store with a clock and a kill switch: `fail_saves_after` makes every
    /// save past that count error, which is what a process dying between two
    /// writes looks like to the next reader.
    struct FaultyTasks<'a> {
        inner: MemTasks<'a>,
        now: RefCell<u64>,
        saves: RefCell<u32>,
        fail_saves_after: u32,
    }

    impl TaskStore for FaultyTasks<'_> {
        fn new_id(&self) -> Result<String, String> {
            self.inner.new_id()
        }
        fn now_ms(&self) -> u64 {
            *self.now.borrow()
        }
        async fn load(&self, id: &str) -> Result<Option<(Value, u64)>, String> {
            self.inner.load(id).await
        }
        async fn save(&self, id: &str, task: &Value, expected: Option<u64>) -> Result<bool, String> {
            *self.saves.borrow_mut() += 1;
            if *self.saves.borrow() > self.fail_saves_after {
                return Err("process stopped".into());
            }
            self.inner.save(id, task, expected).await
        }
    }

    fn counting_exec<'r>(runs: &'r RefCell<u32>) -> impl Fn(String, Value) -> std::future::Ready<ToolOutcome> + 'r {
        move |name, _| {
            *runs.borrow_mut() += 1;
            std::future::ready(ToolOutcome::ok(serde_json::json!({ "tool": name })))
        }
    }

    fn run_store<S: TaskStore>(store: &S, req: &Value, runs: &RefCell<u32>) -> Value {
        let body = serde_json::to_vec(req).unwrap();
        let (_, bytes) = block(handle_with(&surface(), &body, store, counting_exec(runs)));
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn a_claim_abandoned_after_the_effect_is_reconciled_without_rerunning() {
        let rows = RefCell::new(BTreeMap::new());
        let runs = RefCell::new(0);
        // Save 1 is the claim; save 2 (the result) dies after the skill ran.
        let dying = FaultyTasks { inner: MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) }, now: RefCell::new(1_000), saves: RefCell::new(0), fail_saves_after: 1 };
        let open = msg_with_id(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), None, "after-effect");
        let died = run_store(&dying, &open, &runs);
        assert_eq!(died["error"]["code"], INTERNAL_ERROR, "{died}");
        assert_eq!(*runs.borrow(), 1);
        let task_id = task_id_for(open["params"]["message"].as_object().unwrap());

        // A healthy process inside the lease: still working, replay does not run.
        let healthy = FaultyTasks { inner: MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) }, now: RefCell::new(2_000), saves: RefCell::new(0), fail_saves_after: u32::MAX };
        let during = run_store(&healthy, &open, &runs);
        assert_eq!(during["result"]["status"]["state"], "working");
        assert_eq!(*runs.borrow(), 1);

        // After the lease the first reader reconciles to failed, effect unknown.
        *healthy.now.borrow_mut() = 1_000 + DEFAULT_LEASE_MS + 1;
        let read = run_store(&healthy, &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":task_id}}), &runs);
        assert_eq!(read["result"]["status"]["state"], "failed", "{read}");
        assert_eq!(read["result"]["status"]["message"]["metadata"]["effectUnknown"], true);
        assert!(read["result"]["metadata"].get("ferriteClaim").is_none());
        // A replay now reads the failure; the skill never runs twice.
        let replay = run_store(&healthy, &open, &runs);
        assert_eq!(replay["result"]["status"]["state"], "failed");
        assert_eq!(*runs.borrow(), 1);
    }

    #[test]
    fn a_claim_abandoned_before_the_effect_is_reconciled_and_cancel_sees_it() {
        let rows = RefCell::new(BTreeMap::new());
        let runs = RefCell::new(0);
        // Simulate death right after the claim: the stored task is working
        // with a lease, and the skill never ran.
        let store = FaultyTasks { inner: MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) }, now: RefCell::new(5_000), saves: RefCell::new(0), fail_saves_after: u32::MAX };
        let open = msg_with_id(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), None, "before-effect");
        let task_id = task_id_for(open["params"]["message"].as_object().unwrap());
        let claimed = serde_json::json!({
            "kind": "task", "id": task_id, "contextId": "c1",
            "status": { "state": "working" },
            "history": [ open["params"]["message"].clone() ], "artifacts": [],
            "metadata": { "ferriteClaim": { "messageId": "before-effect", "leaseUntilMs": 5_000 + DEFAULT_LEASE_MS } }
        });
        assert!(block(store.save(&task_id, &claimed, None)).unwrap());

        // Inside the lease a cancel is allowed and wins over the claim.
        // Past the lease, reads reconcile instead.
        *store.now.borrow_mut() = 5_000 + DEFAULT_LEASE_MS + 1;
        let cancel = run_store(&store, &serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tasks/cancel","params":{"id":task_id}}), &runs);
        assert_eq!(cancel["error"]["code"], TASK_NOT_CANCELABLE, "a reconciled task is terminal: {cancel}");
        let cont = run_store(&store, &msg(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), Some(&task_id)), &runs);
        assert_eq!(cont["error"]["code"], INVALID_PARAMS, "a failed task cannot be continued");
        assert_eq!(*runs.borrow(), 0, "the abandoned skill is never run by a reader");
    }

    #[test]
    fn without_a_clock_claims_do_not_expire() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let task_id = "task-noclock";
        let claimed = serde_json::json!({
            "kind": "task", "id": task_id, "contextId": "c1", "status": { "state": "working" },
            "history": [], "artifacts": [], "metadata": { "ferriteClaim": { "messageId": "x", "leaseUntilMs": 1 } }
        });
        assert!(block(alice.save(task_id, &claimed, None)).unwrap());
        let read = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":task_id}}));
        assert_eq!(read["result"]["status"]["state"], "working");
    }

    impl TaskStore for MemTasks<'_> {
        fn new_id(&self) -> Result<String, String> {
            let mut n = self.next.borrow_mut();
            *n += 1;
            Ok(format!("{}-task-{n}", self.scope))
        }
        async fn load(&self, id: &str) -> Result<Option<(Value, u64)>, String> {
            Ok(self.rows.borrow().get(&format!("{}/{id}", self.scope)).cloned())
        }
        async fn save(&self, id: &str, task: &Value, expected: Option<u64>) -> Result<bool, String> {
            let key = format!("{}/{id}", self.scope);
            let mut rows = self.rows.borrow_mut();
            let current = rows.get(&key).map(|(_, v)| *v);
            if current != expected {
                return Ok(false);
            }
            rows.insert(key, (task.clone(), current.unwrap_or(0) + 1));
            Ok(true)
        }
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = Box::pin(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended in a ready-only test"),
        }
    }

    fn exec_ok(name: String, args: Value) -> std::future::Ready<ToolOutcome> {
        std::future::ready(ToolOutcome::ok(serde_json::json!({ "tool": name, "args": args })))
    }

    fn run(body: &[u8]) -> (u16, Value) {
        let (status, bytes) = block(handle(&surface(), body, exec_ok));
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn run_with(store: &MemTasks, req: Value) -> Value {
        let (_, bytes) = block(handle_with(&surface(), &serde_json::to_vec(&req).unwrap(), store, exec_ok));
        serde_json::from_slice(&bytes).unwrap()
    }

    fn msg(parts: Value, task_id: Option<&str>) -> Value {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let message_id = format!("m{}", NEXT.fetch_add(1, Ordering::Relaxed));
        msg_with_id(parts, task_id, &message_id)
    }

    fn msg_with_id(parts: Value, task_id: Option<&str>, message_id: &str) -> Value {
        let mut m = serde_json::json!({"kind":"message","messageId":message_id,"role":"user","contextId":"c1","parts":parts});
        if let Some(t) = task_id {
            m["taskId"] = Value::String(t.into());
        }
        serde_json::json!({"jsonrpc":"2.0","id":"r1","method":"message/send","params":{"message":m}})
    }

    fn send(parts: Value) -> (u16, Value) {
        run(&serde_json::to_vec(&msg(parts, None)).unwrap())
    }

    #[test]
    fn stateless_data_part_runs_the_skill_through_the_host() {
        let (status, v) = send(serde_json::json!([{"kind":"data","data":{"skill":"list_notes","arguments":{"q":"x"}}}]));
        assert_eq!(status, 200);
        let r = &v["result"];
        assert_eq!(r["kind"], "message");
        assert_eq!(r["role"], "agent");
        assert_eq!(r["contextId"], "c1");
        assert_eq!(r["parts"][0]["data"]["tool"], "list_notes");
        assert_eq!(r["parts"][0]["data"]["args"]["q"], "x");
        assert_eq!(r["metadata"]["isError"], false);
    }

    #[test]
    fn stateless_text_message_is_answered_with_guidance() {
        let (_, v) = send(serde_json::json!([{"kind":"text","text":"Hello from TCK!"}]));
        let text = v["result"]["parts"][0]["text"].as_str().unwrap();
        assert!(text.contains("list_notes"));
        assert!(text.contains("\"skill\""));
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"t1"}}"#).1["error"]["code"], TASK_NOT_FOUND);
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"id":"t1"}}"#).1["error"]["code"], TASK_NOT_FOUND);
    }

    #[test]
    fn invalid_messages_and_skills_are_invalid_params() {
        for parts in [serde_json::json!([]), serde_json::json!([{"kind":"text"}]), serde_json::json!([{"kind":"image","x":1}])] {
            assert_eq!(send(parts).1["error"]["code"], INVALID_PARAMS);
        }
        assert_eq!(send(serde_json::json!([{"kind":"data","data":{"skill":"drop_tables"}}])).1["error"]["code"], INVALID_PARAMS);
        assert_eq!(send(serde_json::json!([{"kind":"data","data":{"skill":"list_notes","arguments":[1]}}])).1["error"]["code"], INVALID_PARAMS);
        let (_, v) = run(br#"{"jsonrpc":"2.0","method":"message/send","params":{"":"not_a_dict"}}"#);
        assert_eq!(v["error"]["code"], INVALID_PARAMS);
        assert!(v["id"].is_null());
        let (_, v) = run(br#"{"jsonrpc":"2.0","id":2,"method":"message/send","params":{"message":{"kind":"message","messageId":"m","role":"user","taskId":5,"parts":[{"kind":"text","text":"x"}]}}}"#);
        assert_eq!(v["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn oversized_bodies_are_refused_before_parsing() {
        let text = "x".repeat(MAX_BODY_BYTES);
        let req = msg(serde_json::json!([{"kind":"text","text":text}]), None);
        let (status, v) = run(&serde_json::to_vec(&req).unwrap());
        assert_eq!(status, 413);
        assert_eq!(v["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn envelope_errors_match_jsonrpc() {
        let (status, v) = run(b"{nope");
        assert_eq!(status, 400);
        assert_eq!(v["error"]["code"], PARSE_ERROR);
        assert_eq!(run(br#"{"jsonrpc":"aaa","method":"message/send","params":{}}"#).1["error"]["code"], INVALID_REQUEST);
        assert_eq!(run(br#"{"jsonrpc":"2.0","params":{}}"#).1["error"]["code"], INVALID_REQUEST);
        assert_eq!(run(br#"{"jsonrpc":"2.0","method":"message/ssend","params":{}}"#).1["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(run(br#"{"jsonrpc":"2.0","method":"message/send","params":{},"id":{"bad":"type"}}"#).1["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn unoffered_operations_answer_typed_a2a_errors() {
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{}}"#).1["error"]["code"], INVALID_PARAMS);
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{}}"#).1["error"]["code"], UNSUPPORTED_OPERATION);
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set","params":{}}"#).1["error"]["code"], PUSH_NOT_SUPPORTED);
        assert_eq!(run(br#"{"jsonrpc":"2.0","id":1,"method":"agent/getAuthenticatedExtendedCard"}"#).1["error"]["code"], EXTENDED_CARD_NOT_CONFIGURED);
    }

    #[test]
    fn text_creates_input_required_task_that_a_skill_completes() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let created = run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"hello"}]), None));
        let task = &created["result"];
        assert_eq!(task["kind"], "task");
        assert_eq!(task["status"]["state"], "input-required");
        assert_eq!(task["contextId"], "c1");
        let task_id = task["id"].as_str().unwrap().to_string();
        assert_eq!(task["history"].as_array().unwrap().len(), 2);

        let done = run_with(&alice, msg(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), Some(&task_id)));
        assert_eq!(done["result"]["status"]["state"], "completed");
        assert_eq!(done["result"]["artifacts"][0]["parts"][0]["data"]["tool"], "list_notes");
        assert_eq!(done["result"]["history"].as_array().unwrap().len(), 4);

        let read = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tasks/get","params":{"id":task_id,"historyLength":1}}));
        assert_eq!(read["result"]["status"]["state"], "completed");
        assert_eq!(read["result"]["history"].as_array().unwrap().len(), 1);
        let bad = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tasks/get","params":{"id":task_id,"historyLength":-1}}));
        assert_eq!(bad["error"]["code"], INVALID_PARAMS);

        let cancel = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tasks/cancel","params":{"id":task_id}}));
        assert_eq!(cancel["error"]["code"], TASK_NOT_CANCELABLE);
        let cont = run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"again"}]), Some(&task_id)));
        assert_eq!(cont["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn cancel_is_terminal_and_tasks_are_caller_scoped() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let bob = MemTasks { scope: "bob", rows: &rows, next: RefCell::new(0) };
        let created = run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"hello"}]), None));
        let task_id = created["result"]["id"].as_str().unwrap().to_string();

        for req in [
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":task_id}}),
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"id":task_id}}),
        ] {
            assert_eq!(run_with(&bob, req)["error"]["code"], TASK_NOT_FOUND);
        }
        assert_eq!(run_with(&bob, msg(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), Some(&task_id)))["error"]["code"], TASK_NOT_FOUND);

        let canceled = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tasks/cancel","params":{"id":task_id}}));
        assert_eq!(canceled["result"]["status"]["state"], "canceled");
        assert_eq!(canceled["result"]["id"], task_id.as_str());
        let again = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tasks/cancel","params":{"id":task_id}}));
        assert_eq!(again["error"]["code"], TASK_NOT_CANCELABLE);
    }

    #[test]
    fn failed_operations_fail_the_task_and_history_is_bounded() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let created = run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"hello"}]), None));
        let task_id = created["result"]["id"].as_str().unwrap().to_string();
        for _ in 0..40 {
            run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"more"}]), Some(&task_id)));
        }
        let read = run_with(&alice, serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":task_id}}));
        assert_eq!(read["result"]["history"].as_array().unwrap().len(), HISTORY_LIMIT);

        let req = msg(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), Some(&task_id));
        let (_, bytes) = block(handle_with(&surface(), &serde_json::to_vec(&req).unwrap(), &alice, |_, _| {
            std::future::ready(ToolOutcome::err(serde_json::json!({"code":"APP_VALIDATION"})))
        }));
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["result"]["status"]["state"], "failed");
        assert_eq!(v["result"]["status"]["message"]["metadata"]["isError"], true);
    }

    fn run_counting(store: &MemTasks, req: &Value, runs: &RefCell<u32>) -> Value {
        let body = serde_json::to_vec(req).unwrap();
        let (_, bytes) = block(handle_with(&surface(), &body, store, |name, _| {
            *runs.borrow_mut() += 1;
            std::future::ready(ToolOutcome::ok(serde_json::json!({ "tool": name })))
        }));
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn replaying_a_message_runs_its_skill_once() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let runs = RefCell::new(0);
        let skill = serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]);

        // A new task opened by a skill message, sent twice.
        let open = msg_with_id(skill.clone(), None, "replay-open");
        let first = run_counting(&alice, &open, &runs);
        let second = run_counting(&alice, &open, &runs);
        assert_eq!(*runs.borrow(), 1, "the replay must not run the skill again");
        assert_eq!(first["result"]["id"], second["result"]["id"]);
        assert_eq!(second["result"]["status"]["state"], "completed");
        assert_eq!(second["result"]["artifacts"].as_array().unwrap().len(), 1);

        // A continuation replayed.
        let waiting = run_with(&alice, msg(serde_json::json!([{"kind":"text","text":"hi"}]), None));
        let task_id = waiting["result"]["id"].as_str().unwrap().to_string();
        let cont = msg_with_id(skill, Some(&task_id), "replay-continue");
        run_counting(&alice, &cont, &runs);
        let again = run_counting(&alice, &cont, &runs);
        assert_eq!(*runs.borrow(), 2);
        assert_eq!(again["result"]["status"]["state"], "completed");
        assert_eq!(again["result"]["artifacts"].as_array().unwrap().len(), 1);

        // The same message id from another caller is that caller's own task.
        let bob = MemTasks { scope: "bob", rows: &rows, next: RefCell::new(0) };
        run_counting(&bob, &open, &runs);
        assert_eq!(*runs.borrow(), 3);
    }

    #[test]
    fn a_duplicate_that_loses_the_claim_reads_the_task_instead_of_running() {
        let rows = RefCell::new(BTreeMap::new());
        let alice = MemTasks { scope: "alice", rows: &rows, next: RefCell::new(0) };
        let runs = RefCell::new(0);
        let open = msg_with_id(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), None, "dup");
        // Simulate the winning duplicate having claimed the task already.
        let claimed_id = task_id_for(open["params"]["message"].as_object().unwrap());
        let claimed = serde_json::json!({
            "kind": "task", "id": claimed_id, "contextId": "c1",
            "status": { "state": "working" },
            "history": [ open["params"]["message"].clone() ], "artifacts": []
        });
        assert!(block(alice.save(&claimed_id, &claimed, None)).unwrap());
        let answer = run_counting(&alice, &open, &runs);
        assert_eq!(*runs.borrow(), 0);
        assert_eq!(answer["result"]["status"]["state"], "working");

        // A different message on a working task is refused, not queued over it.
        let other = msg(serde_json::json!([{"kind":"data","data":{"skill":"list_notes"}}]), Some(&claimed_id));
        let refused = run_counting(&alice, &other, &runs);
        assert_eq!(refused["error"]["code"], INVALID_PARAMS);
        assert_eq!(*runs.borrow(), 0);
    }
}
