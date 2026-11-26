//! Durable MCP Tasks lifecycle. Storage implementations must provide atomic,
//! strongly consistent, caller-scoped compare-and-swap and cryptographic IDs.
use ferrite_app::serde_json::{json, Value};

pub const EXTENSION: &str = "io.modelcontextprotocol/tasks";
pub const DEFAULT_TTL_MS: u64 = 604_800_000;
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct TaskError {
    pub code: i64,
    pub message: &'static str,
    pub data: Option<Value>,
}
impl TaskError {
    pub fn invalid() -> Self {
        Self {
            code: -32602,
            message: "invalid task parameters",
            data: None,
        }
    }
    pub fn unavailable() -> Self {
        Self {
            code: -32602,
            message: "task unavailable",
            data: None,
        }
    }
    pub fn storage() -> Self {
        Self {
            code: -32603,
            message: "task storage unavailable",
            data: None,
        }
    }
    pub fn missing_capability() -> Self {
        Self::missing_client_capability(json!({"extensions":{EXTENSION:{}}}))
    }
    pub fn missing_client_capability(required: Value) -> Self {
        Self {
            code: -32021,
            message: "Missing required client capability",
            data: Some(json!({"requiredCapabilities":required})),
        }
    }
}

/// The revision is an opaque storage version. A successful save must be durable
/// before returning. `None` creates only if absent. Namespace every operation by
/// authenticated `owner`; never accept the owner from tool arguments. A store
/// must enforce bounded retained tasks/bytes per owner and garbage-collect expired
/// rows. IDs need at least 128 unpredictable bits. `load` must read its own writes.
pub trait TaskStore {
    fn new_id(&self) -> Result<String, String>;
    fn now_ms(&self) -> u64;
    async fn load(&self, owner: &str, id: &str) -> Result<Option<(Value, u64)>, String>;
    async fn save(
        &self,
        owner: &str,
        id: &str,
        record: &Value,
        expected: Option<u64>,
    ) -> Result<bool, String>;
}

pub fn client_supports(params: &Value) -> bool {
    params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
        .get(EXTENSION)
        .is_some_and(Value::is_object)
}
/// Retain only the input modes the originating client explicitly supports.
/// Arbitrary per-request metadata and credentials must never enter a task record.
pub fn input_capabilities(capabilities: &Value) -> Value {
    let mut result = json!({});
    if let Some(elicitation) = capabilities.get("elicitation").and_then(Value::as_object) {
        if elicitation.is_empty() || elicitation.get("form").is_some_and(Value::is_object) {
            result["elicitation"]["form"] = json!({});
        }
        if elicitation.get("url").is_some_and(Value::is_object) {
            result["elicitation"]["url"] = json!({});
        }
    }
    for name in ["sampling", "roots"] {
        if capabilities.get(name).is_some_and(Value::is_object) {
            result[name] = json!({});
        }
    }
    result
}

pub fn require_input_capability(capabilities: &Value, request: &Value) -> Result<(), TaskError> {
    let policy = input_capabilities(capabilities);
    let required = match request["method"].as_str() {
        Some("elicitation/create") => {
            if request["params"]
                .get("mode")
                .is_some_and(|mode| !mode.is_string())
            {
                return Err(TaskError::invalid());
            }
            let mode = request["params"]
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("form");
            if !["form", "url"].contains(&mode) {
                return Err(TaskError::invalid());
            }
            if policy["elicitation"][mode].is_object() {
                return Ok(());
            }
            json!({"elicitation":{mode:{}}})
        }
        Some("sampling/createMessage") => {
            if policy["sampling"].is_object() {
                return Ok(());
            }
            json!({"sampling":{}})
        }
        Some("roots/list") => {
            if policy["roots"].is_object() {
                return Ok(());
            }
            json!({"roots":{}})
        }
        _ => return Err(TaskError::invalid()),
    };
    Err(TaskError::missing_client_capability(required))
}

pub fn terminal(record: &Value) -> bool {
    matches!(
        record["task"]["status"].as_str(),
        Some("completed" | "failed" | "cancelled")
    )
}

/// Authenticated per-request coordinator. Worker callbacks use the same owner.
/// The durable `operation` and `arguments` describe pending work. `claim` records
/// dispatch once; after an uncertain worker crash reconcile the underlying job,
/// never clear the claim and blindly repeat side effects.
pub struct TaskHost<'a, S> {
    pub store: &'a S,
    pub owner: &'a str,
}
impl<'a, S: TaskStore> TaskHost<'a, S> {
    pub fn new(store: &'a S, owner: &'a str) -> Self {
        Self { store, owner }
    }
    pub async fn create(
        &self,
        operation: &str,
        arguments: Value,
        ttl_ms: u64,
    ) -> Result<Value, TaskError> {
        self.create_with_capabilities(operation, arguments, ttl_ms, &json!({}))
            .await
    }
    /// Bind optional server-to-client requests to the originating request's
    /// declared capabilities. A later poll cannot enlarge this permission.
    pub async fn create_with_capabilities(
        &self,
        operation: &str,
        arguments: Value,
        ttl_ms: u64,
        capabilities: &Value,
    ) -> Result<Value, TaskError> {
        if self.owner.is_empty()
            || operation.is_empty()
            || !arguments.is_object()
            || ttl_ms == 0
            || ttl_ms > DEFAULT_TTL_MS
        {
            return Err(TaskError::invalid());
        }
        let id = self.store.new_id().map_err(|_| TaskError::storage())?;
        if id.len() < 22
            || id.len() > 128
            || !id.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(TaskError::storage());
        }
        let now = self.store.now_ms();
        let record = json!({"task":{"taskId":id,"status":"working","createdAt":timestamp(now),"lastUpdatedAt":timestamp(now),"ttlMs":ttl_ms,"pollIntervalMs":3000},"createdMs":now,"expiresMs":now.saturating_add(ttl_ms),"operation":operation,"arguments":arguments,"cancelRequested":false,"dispatched":false,"inputResponses":{},"issuedInputKeys":[],"inputCapabilities":input_capabilities(capabilities)});
        if record.to_string().len() > MAX_RECORD_BYTES {
            return Err(TaskError::invalid());
        }
        if !self
            .store
            .save(self.owner, &id, &record, None)
            .await
            .map_err(|_| TaskError::storage())?
        {
            return Err(TaskError::storage());
        }
        // A returned handle must already be readable, even on a store whose
        // implementation accidentally acknowledges writes before visibility.
        let (record, _) = self.record(&id).await?;
        let mut task = record["task"].clone();
        task["resultType"] = json!("task");
        Ok(task)
    }
    pub async fn record(&self, id: &str) -> Result<(Value, u64), TaskError> {
        if self.owner.is_empty() || id.is_empty() || id.len() > 128 {
            return Err(TaskError::unavailable());
        }
        let (record, revision) = self
            .store
            .load(self.owner, id)
            .await
            .map_err(|_| TaskError::storage())?
            .ok_or_else(TaskError::unavailable)?;
        if record["expiresMs"]
            .as_u64()
            .is_none_or(|expiry| expiry <= self.store.now_ms())
        {
            return Err(TaskError::unavailable());
        }
        Ok((record, revision))
    }
    pub async fn get(&self, id: &str) -> Result<Value, TaskError> {
        let (record, _) = self.record(id).await?;
        let mut task = record["task"].clone();
        task["resultType"] = json!("complete");
        Ok(task)
    }
    async fn mutate<F>(&self, id: &str, update: F) -> Result<bool, TaskError>
    where
        F: Fn(&mut Value) -> Result<bool, TaskError>,
    {
        for _ in 0..8 {
            let (mut record, revision) = self.record(id).await?;
            if !update(&mut record)? {
                return Ok(false);
            }
            record["task"]["lastUpdatedAt"] = json!(timestamp(self.store.now_ms()));
            if record.to_string().len() > MAX_RECORD_BYTES {
                return Err(TaskError::invalid());
            }
            if self
                .store
                .save(self.owner, id, &record, Some(revision))
                .await
                .map_err(|_| TaskError::storage())?
            {
                return Ok(true);
            }
        }
        Err(TaskError {
            code: -32603,
            message: "task concurrently changed; retry the same request",
            data: None,
        })
    }
    pub async fn claim(&self, id: &str) -> Result<bool, TaskError> {
        self.mutate(id, |record| {
            if terminal(record) || record["dispatched"] == true || record["cancelRequested"] == true
            {
                return Ok(false);
            }
            record["dispatched"] = json!(true);
            Ok(true)
        })
        .await
    }
    pub async fn request_input(&self, id: &str, requests: Value) -> Result<bool, TaskError> {
        let requests = requests
            .as_object()
            .filter(|r| !r.is_empty())
            .ok_or_else(TaskError::invalid)?;
        if requests.len() > 32
            || requests.iter().any(|(key, request)| {
                key.is_empty()
                    || key.len() > 128
                    || !request.is_object()
                    || !request["method"].is_string()
                    || request
                        .get("params")
                        .is_some_and(|params| !params.is_object())
            })
        {
            return Err(TaskError::invalid());
        }
        self.mutate(id, |record| {
            if terminal(record) {
                return Ok(false);
            }
            if record["task"]["inputRequests"] == Value::Object(requests.clone()) {
                return Ok(false);
            }
            if record["task"]["status"] != "working" {
                return Err(TaskError::invalid());
            }
            for request in requests.values() {
                require_input_capability(&record["inputCapabilities"], request)?;
            }
            let issued = record["issuedInputKeys"]
                .as_array_mut()
                .ok_or_else(TaskError::storage)?;
            if requests.keys().any(|key| issued.contains(&json!(key))) {
                return Err(TaskError::invalid());
            }
            for key in requests.keys() {
                issued.push(json!(key));
            }
            record["task"]["status"] = json!("input_required");
            record["task"]["inputRequests"] = Value::Object(requests.clone());
            Ok(true)
        })
        .await
    }
    pub async fn update(&self, id: &str, responses: &Value) -> Result<(), TaskError> {
        let responses = responses.as_object().ok_or_else(TaskError::invalid)?;
        if responses.len() > 32
            || responses
                .values()
                .any(|v| !v.is_object() || v.get("jsonrpc").is_some())
        {
            return Err(TaskError::invalid());
        }
        self.mutate(id, |record| {
            if terminal(record) || record["task"]["status"] != "input_required" {
                return Ok(false);
            }
            let mut pending = record["task"]["inputRequests"]
                .as_object()
                .cloned()
                .ok_or_else(TaskError::storage)?;
            let mut changed = false;
            for (key, response) in responses {
                if let Some(request) = pending.get(key) {
                    validate_input_response(request, response)?;
                    pending.remove(key);
                    record["inputResponses"][key] = response.clone();
                    changed = true;
                }
            }
            if pending.is_empty() {
                record["task"]
                    .as_object_mut()
                    .unwrap()
                    .remove("inputRequests");
                record["task"]["status"] = json!("working");
            } else {
                record["task"]["inputRequests"] = Value::Object(pending);
            }
            Ok(changed)
        })
        .await?;
        Ok(())
    }
    pub async fn cancel(&self, id: &str) -> Result<(), TaskError> {
        self.mutate(id, |record| {
            if terminal(record) || record["cancelRequested"] == true {
                return Ok(false);
            }
            record["cancelRequested"] = json!(true);
            Ok(true)
        })
        .await?;
        Ok(())
    }
    async fn finish(
        &self,
        id: &str,
        status: &str,
        payload: Option<(&str, Value)>,
    ) -> Result<bool, TaskError> {
        self.mutate(id, |record| {
            if terminal(record) {
                return Ok(false);
            }
            if status == "cancelled" && record["cancelRequested"] != true {
                return Err(TaskError::invalid());
            }
            record["task"]
                .as_object_mut()
                .unwrap()
                .remove("inputRequests");
            record["task"]["status"] = json!(status);
            if let Some((key, value)) = &payload {
                record["task"][key] = value.clone();
            }
            Ok(true)
        })
        .await
    }
    pub async fn complete(&self, id: &str, result: Value) -> Result<bool, TaskError> {
        if !result.is_object()
            || result["resultType"] != "complete"
            || !result["content"].is_array()
        {
            return Err(TaskError::invalid());
        }
        self.finish(id, "completed", Some(("result", result))).await
    }
    pub async fn fail(&self, id: &str, error: Value) -> Result<bool, TaskError> {
        if !error.is_object() || !error["code"].is_i64() || !error["message"].is_string() {
            return Err(TaskError::invalid());
        }
        self.finish(id, "failed", Some(("error", error))).await
    }
    pub async fn confirm_cancel(&self, id: &str) -> Result<bool, TaskError> {
        self.finish(id, "cancelled", None).await
    }
    /// Update the live `statusMessage` displayed by clients (such as Claude Code `/tasks`).
    pub async fn set_status_message(&self, id: &str, message: Option<&str>) -> Result<bool, TaskError> {
        let owned = message.map(str::to_string);
        self.mutate(id, move |record| {
            if terminal(record) {
                return Ok(false);
            }
            match &owned {
                Some(text) if !text.is_empty() => {
                    record["task"]["statusMessage"] = json!(text);
                }
                _ => {
                    if let Some(obj) = record["task"].as_object_mut() {
                        obj.remove("statusMessage");
                    }
                }
            }
            Ok(true)
        })
        .await
    }
    /// Tune `pollIntervalMs` (clamped to Claude's 250..=30_000 ms bounds; always numeric).
    pub async fn set_poll_interval_ms(&self, id: &str, poll_ms: u64) -> Result<bool, TaskError> {
        let clamped = poll_ms.clamp(250, 30_000);
        self.mutate(id, move |record| {
            if terminal(record) {
                return Ok(false);
            }
            record["task"]["pollIntervalMs"] = json!(clamped);
            Ok(true)
        })
        .await
    }
    pub async fn call(&self, method: &str, params: &Value) -> Result<Value, TaskError> {
        let id = params["taskId"].as_str().ok_or_else(TaskError::invalid)?;
        match method {
            "tasks/get" => self.get(id).await,
            "tasks/update" => {
                self.update(id, &params["inputResponses"]).await?;
                Ok(json!({"resultType":"complete"}))
            }
            "tasks/cancel" => {
                self.cancel(id).await?;
                Ok(json!({"resultType":"complete"}))
            }
            _ => Err(TaskError {
                code: -32601,
                message: "unknown task method",
                data: None,
            }),
        }
    }
}

/// Validate the protocol envelope before consuming an outstanding answer. Hosts
/// additionally validate accepted content against their application field schema.
fn validate_input_response(request: &Value, response: &Value) -> Result<(), TaskError> {
    if request["method"] == "elicitation/create" {
        if !matches!(
            response["action"].as_str(),
            Some("accept" | "decline" | "cancel")
        ) || response
            .get("content")
            .is_some_and(|content| !content.is_object())
        {
            return Err(TaskError::invalid());
        }
        if response["action"] != "accept" && response.get("content").is_some() {
            return Err(TaskError::invalid());
        }
    }
    Ok(())
}

/// RFC 3339 UTC without a clock or time dependency in constrained apps.
pub fn timestamp(ms: u64) -> String {
    let (year, month, day) = super::artefacts::civil_date(ms);
    let seconds = ms / 1000 % 86400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    };
    #[derive(Default)]
    struct Store {
        rows: Mutex<BTreeMap<(String, String), (Value, u64)>>,
        now: AtomicU64,
        serial: AtomicU64,
        conflicts: AtomicU64,
    }
    impl TaskStore for Store {
        fn new_id(&self) -> Result<String, String> {
            Ok(format!(
                "fixture-test-only-id-{:032x}",
                self.serial.fetch_add(1, Ordering::SeqCst)
            ))
        }
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
        async fn load(&self, owner: &str, id: &str) -> Result<Option<(Value, u64)>, String> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(owner.into(), id.into()))
                .cloned())
        }
        async fn save(
            &self,
            owner: &str,
            id: &str,
            row: &Value,
            expected: Option<u64>,
        ) -> Result<bool, String> {
            if expected.is_some()
                && self
                    .conflicts
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                return Ok(false);
            }
            let mut rows = self.rows.lock().unwrap();
            let key = (owner.into(), id.into());
            if rows.get(&key).map(|(_, v)| *v) != expected {
                return Ok(false);
            }
            rows.insert(key, (row.clone(), expected.unwrap_or(0) + 1));
            Ok(true)
        }
    }
    fn run<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Wake, Waker};
        struct Noop;
        impl Wake for Noop {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test store unexpectedly pending"),
        }
    }
    async fn created(host: &TaskHost<'_, Store>) -> String {
        host.create_with_capabilities(
            "report",
            json!({}),
            1000,
            &json!({"elicitation":{"form":{}}}),
        )
        .await
        .unwrap()["taskId"]
            .as_str()
            .unwrap()
            .into()
    }
    fn result() -> Value {
        json!({"resultType":"complete","content":[{"type":"text","text":"done"}],"isError":false})
    }
    #[test]
    fn persisted_before_return_and_owner_scope_expiry() {
        run(async {
            let store = Store::default();
            let owner = TaskHost::new(&store, "alice");
            let id = created(&owner).await;
            assert_eq!(owner.get(&id).await.unwrap()["status"], "working");
            let other = TaskHost::new(&store, "bob");
            assert_eq!(
                other.get(&id).await.unwrap_err().message,
                "task unavailable"
            );
            assert!(other.cancel(&id).await.is_err());
            assert!(other.update(&id, &json!({})).await.is_err());
            store.now.store(1000, Ordering::SeqCst);
            assert_eq!(
                owner.get(&id).await.unwrap_err().message,
                "task unavailable"
            );
        });
    }
    #[test]
    fn durable_dispatch_claim_survives_reconstructed_host_and_conflicts() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let id = created(&host).await;
            store.conflicts.store(2, Ordering::SeqCst);
            assert!(host.claim(&id).await.unwrap());
            let resumed = TaskHost::new(&store, "alice");
            assert!(!resumed.claim(&id).await.unwrap());
            assert_eq!(resumed.record(&id).await.unwrap().0["operation"], "report");
        });
    }
    #[test]
    fn input_partial_duplicate_unknown_and_key_reuse() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let id = created(&host).await;
            let request = json!({"method":"elicitation/create","params":{"message":"approve"}});
            host.request_input(&id, json!({"first":request,"second":request}))
                .await
                .unwrap();
            host.update(
                &id,
                &json!({"unknown":{"action":"accept"},"first":{"action":"accept"}}),
            )
            .await
            .unwrap();
            let pending = host.get(&id).await.unwrap();
            assert_eq!(pending["status"], "input_required");
            assert_eq!(pending["inputRequests"].as_object().unwrap().len(), 1);
            host.update(
                &id,
                &json!({"first":{"action":"decline"},"second":{"action":"accept"}}),
            )
            .await
            .unwrap();
            assert_eq!(host.get(&id).await.unwrap()["status"], "working");
            assert_eq!(
                host.record(&id).await.unwrap().0["inputResponses"]["first"]["action"],
                "accept"
            );
            assert!(host
                .request_input(&id, json!({"first":request}))
                .await
                .is_err());
            assert!(host
                .update(&id, &json!({"x":{"jsonrpc":"2.0","result":{}}}))
                .await
                .is_err());
        });
    }
    #[test]
    fn malformed_elicitation_answer_preserves_the_pending_request() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let id = created(&host).await;
            host.request_input(
                &id,
                json!({"approval":{"method":"elicitation/create","params":{"message":"Approve"}}}),
            )
            .await
            .unwrap();
            for response in [
                json!({}),
                json!({"action":"unexpected"}),
                json!({"action":"accept","content":"bad"}),
                json!({"action":"decline","content":{}}),
            ] {
                assert!(host
                    .update(&id, &json!({"approval":response}))
                    .await
                    .is_err());
                let snapshot = host.get(&id).await.unwrap();
                assert_eq!(snapshot["status"], "input_required");
                assert!(snapshot["inputRequests"].get("approval").is_some());
            }
            host.update(&id, &json!({"approval":{"action":"decline"}}))
                .await
                .unwrap();
            assert_eq!(
                host.record(&id).await.unwrap().0["inputResponses"]["approval"]["action"],
                "decline"
            );
        });
    }
    #[test]
    fn cancel_is_intent_and_terminal_race_keeps_first_outcome() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let id = created(&host).await;
            host.cancel(&id).await.unwrap();
            host.cancel(&id).await.unwrap();
            assert_eq!(host.get(&id).await.unwrap()["status"], "working");
            assert!(!host.claim(&id).await.unwrap());
            assert!(host.complete(&id, result()).await.unwrap());
            assert!(!host.confirm_cancel(&id).await.unwrap());
            assert!(!host
                .fail(&id, json!({"code":-32603,"message":"late failure"}))
                .await
                .unwrap());
            host.cancel(&id).await.unwrap();
            assert_eq!(host.get(&id).await.unwrap()["status"], "completed");
            let second = created(&host).await;
            assert!(host.confirm_cancel(&second).await.is_err());
            host.cancel(&second).await.unwrap();
            assert!(host.confirm_cancel(&second).await.unwrap());
            assert!(!host.complete(&second, result()).await.unwrap());
        });
    }
    #[test]
    fn protocol_failure_and_tool_error_have_distinct_statuses() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let id = created(&host).await;
            let mut tool_error = result();
            tool_error["isError"] = json!(true);
            host.complete(&id, tool_error).await.unwrap();
            assert_eq!(host.get(&id).await.unwrap()["status"], "completed");
            let failed = created(&host).await;
            assert!(host
                .fail(&failed, json!({"message":"missing code"}))
                .await
                .is_err());
            host.fail(&failed, json!({"code":-32603,"message":"failed"}))
                .await
                .unwrap();
            let output = host.get(&failed).await.unwrap();
            assert_eq!(output["status"], "failed");
            assert_eq!(output["error"]["code"], -32603);
        });
    }
    #[test]
    fn originating_input_policy_is_durable_minimal_and_mode_specific() {
        run(async {
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            let denied = host.create("report", json!({}), 1000).await.unwrap();
            let form =
                json!({"method":"elicitation/create","params":{"mode":"form","message":"Approve"}});
            let id = denied["taskId"].as_str().unwrap();
            let error = host
                .request_input(id, json!({"approval":form}))
                .await
                .unwrap_err();
            assert_eq!(error.code, -32021);
            assert_eq!(
                error.data.unwrap()["requiredCapabilities"],
                json!({"elicitation":{"form":{}}})
            );
            assert_eq!(host.get(id).await.unwrap()["status"], "working");
            let caps = json!({"elicitation":{"form":{"private":"never retain"}},"unrelated":"credential-like metadata"});
            let handle = host
                .create_with_capabilities("report", json!({}), 1000, &caps)
                .await
                .unwrap();
            let id = handle["taskId"].as_str().unwrap();
            let restored = TaskHost::new(&store, "alice");
            assert_eq!(
                restored.record(id).await.unwrap().0["inputCapabilities"],
                json!({"elicitation":{"form":{}}})
            );
            for request in [
                json!({"method":"elicitation/create","params":{"mode":"url"}}),
                json!({"method":"sampling/createMessage","params":{}}),
                json!({"method":"roots/list"}),
            ] {
                assert_eq!(
                    restored
                        .request_input(id, json!({"unsupported":request}))
                        .await
                        .unwrap_err()
                        .code,
                    -32021
                );
            }
            assert!(restored
                .request_input(id, json!({"approval":form}))
                .await
                .unwrap());
            assert_eq!(
                input_capabilities(&json!({"elicitation":{}})),
                json!({"elicitation":{"form":{}}})
            );
            assert!(require_input_capability(
                &caps,
                &json!({"method":"elicitation/create","params":{"mode":null}})
            )
            .is_err());
        });
    }
    #[test]
    fn timestamps_and_bounds() {
        run(async {
            assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
            assert_eq!(timestamp(1709251200123), "2024-03-01T00:00:00.123Z");
            let store = Store::default();
            let host = TaskHost::new(&store, "alice");
            assert!(host.create("report", json!({}), 0).await.is_err());
            assert!(host
                .create("report", json!({}), DEFAULT_TTL_MS + 1)
                .await
                .is_err());
            assert!(host
                .create("report", json!({"text":"x".repeat(MAX_RECORD_BYTES)}), 1000)
                .await
                .is_err());
        });
    }
}
