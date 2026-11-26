//! Experimental MCP Events, modern SEP-3415 b08e4f9 and legacy WG d5316be2.
//! Hosts advertise only delivery modes they actually mount and authorize every request,
//! supply a caller-scoped retained log, and treat event data as untrusted.
use ferrite_app::serde_json::{self, Value};

#[derive(Clone, Debug)]
pub struct EventType {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub payload_schema: Value,
}
impl EventType {
    pub fn descriptor(&self) -> Value {
        self.descriptor_with_delivery(&["poll"])
    }
    pub fn descriptor_with_delivery(&self, delivery: &[&str]) -> Value {
        serde_json::json!({"name":self.name,"description":self.description,
            "inputSchema":self.input_schema,"payloadSchema":self.payload_schema,"delivery":delivery})
    }
}

#[derive(Debug, Clone)]
pub struct EventError {
    pub code: i64,
    pub message: &'static str,
    pub data: Option<Value>,
}
impl EventError {
    pub fn unsupported_delivery(mode: &str) -> Self {
        Self {
            code: -32026,
            message: "event delivery mode unsupported",
            data: Some(serde_json::json!({"feature":"deliveryMode","value":mode})),
        }
    }
    pub fn invalid() -> Self {
        Self {
            code: -32602,
            message: "invalid event parameters or cursor",
            data: None,
        }
    }
    pub fn forbidden() -> Self {
        Self {
            code: -32024,
            message: "event access denied",
            data: None,
        }
    }
    pub fn not_found() -> Self {
        Self {
            code: -32023,
            message: "unknown event",
            data: None,
        }
    }
    /// Authorization, type or argument loss: a subscription cannot recover.
    pub(crate) fn ends_subscription(&self) -> bool {
        matches!(self.code, -32023 | -32024 | -32602 | -32026)
    }
    pub fn unavailable() -> Self {
        Self {
            code: -32603,
            message: "event history unavailable",
            data: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PollRequest {
    pub name: String,
    pub arguments: Value,
    pub cursor: Option<String>,
    pub max_events: usize,
    pub max_age_ms: Option<u64>,
}
impl PollRequest {
    pub fn parse(params: &Value) -> Result<Self, EventError> {
        let invalid = EventError::invalid;
        let obj = params.as_object().ok_or_else(invalid)?;
        if obj.keys().any(|key| {
            ![
                "name",
                "arguments",
                "cursor",
                "maxEvents",
                "maxAgeMs",
                "_meta",
            ]
            .contains(&key.as_str())
        }) {
            return Err(invalid());
        }
        let name = params["name"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(invalid)?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if !arguments.is_object() || arguments.to_string().len() > 8192 {
            return Err(invalid());
        }
        let cursor = match params.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(v)) if v.len() <= 4096 => Some(v.clone()),
            _ => return Err(invalid()),
        };
        let max_events = match params.get("maxEvents") {
            None => 50,
            Some(v) => v.as_u64().filter(|v| *v > 0).ok_or_else(invalid)?.min(100) as usize,
        };
        let max_age_ms = params
            .get("maxAgeMs")
            .map(|v| v.as_u64().ok_or_else(invalid))
            .transpose()?;
        Ok(Self {
            name: name.into(),
            arguments,
            cursor,
            max_events,
            max_age_ms,
        })
    }
}

/// Stable IDs must be unique within the retained, append-ordered snapshot.
/// The host obtains this snapshot AFTER authorizing the current caller.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub id: String,
    pub at_ms: u64,
    pub data: Value,
}

/// Poll a bounded retained history. Scope includes the principal, event name,
/// filters and schema epoch. Cursors bind to that scope but are not credentials.
/// A lost position replays retained entries with `truncated: true`, never silently
/// claims complete delivery. Retried polls produce the same stable event IDs.
pub fn poll_snapshot(
    scope: &str,
    rows: &[EventRecord],
    now_ms: u64,
    retention_limit: usize,
    request: &PollRequest,
) -> Result<Value, EventError> {
    let invalid = EventError::invalid;
    if retention_limit == 0
        || retention_limit > 1000
        || rows.len() > retention_limit
        || rows.iter().any(|r| {
            r.id.is_empty()
                || r.id.len() > 256
                || !r.data.is_object()
                || timestamp(r.at_ms).is_none()
        })
    {
        return Err(EventError::unavailable());
    }
    let mut ids = std::collections::BTreeSet::new();
    if rows.iter().any(|r| !ids.insert(&r.id)) {
        return Err(EventError::unavailable());
    }
    let binding = serde_json::json!([scope, request.name, request.arguments]).to_string();
    let binding = super::sha256::to_hex(&super::sha256::sha256(binding.as_bytes()));
    let encode = |id: Option<&str>, since: u64| {
        serde_json::json!(["events-v1", binding, id, since]).to_string()
    };
    let Some(cursor) = &request.cursor else {
        return Ok(
            serde_json::json!({"events":[],"cursor":encode(rows.last().map(|r| r.id.as_str()), now_ms),"truncated":false,"hasMore":false,"nextPollMs":5000}),
        );
    };
    let position: Value = serde_json::from_str(cursor).map_err(|_| invalid())?;
    let p = position
        .as_array()
        .filter(|p| p.len() == 4)
        .ok_or_else(invalid)?;
    if p[0] != "events-v1"
        || p[1] != binding
        || (!p[2].is_null()
            && !p[2].is_string()
            && !(p[2].as_object().is_some_and(|v| v.len() == 1) && p[2]["before"].is_string()))
    {
        return Err(invalid());
    }
    let since = p[3].as_u64().ok_or_else(invalid)?;
    // An empty-bootstrap cursor has no source anchor. A full window cannot
    // establish whether older entries were evicted, so report the possible gap.
    let mut truncated = p[2].is_null() && rows.len() == retention_limit;
    let start = if let Some(id) = p[2]["before"].as_str() {
        match rows.iter().position(|r| r.id == id) {
            Some(index) => index,
            None => {
                truncated = true;
                0
            }
        }
    } else if let Some(id) = p[2].as_str() {
        match rows.iter().position(|r| r.id == id) {
            Some(index) => index + 1,
            None => {
                truncated = true;
                0
            }
        }
    } else {
        0
    };
    let floor = request.max_age_ms.map(|age| now_ms.saturating_sub(age));
    let mut events = Vec::new();
    let mut last = if rows.is_empty() { None } else { p[2].as_str() };
    let mut has_more = false;
    let mut replay_start = None;
    for row in &rows[start..] {
        if floor.is_some_and(|floor| row.at_ms < floor) {
            truncated = true;
            last = Some(&row.id);
            continue;
        }
        if events.len() == request.max_events {
            has_more = true;
            break;
        }
        if replay_start.is_none() {
            replay_start = Some(
                serde_json::json!(["events-v1", binding, {"before":row.id}, since]).to_string(),
            );
        }
        events.push(serde_json::json!({"eventId":row.id,"name":request.name,"timestamp":timestamp(row.at_ms).unwrap(),"data":row.data}));
        last = Some(&row.id);
    }
    Ok(
        serde_json::json!({"events":events,"cursor":encode(last, since),"truncated":truncated,"hasMore":has_more,"nextPollMs":5000,"_meta":{"io.ferrite/eventsReplayStart":replay_start}}),
    )
}

/// Validate a single-occurrence source read before delivery can acknowledge it.
/// The optional replay boundary is minted by the source, never inferred from IDs.
pub(crate) fn validate_delivery(value: &Value, name: &str) -> Result<(), EventError> {
    let events = value["events"]
        .as_array()
        .ok_or_else(EventError::unavailable)?;
    if events.len() > 1
        || !value["truncated"].is_boolean()
        || !value["hasMore"].is_boolean()
        || !(value
            .get("cursor")
            .is_some_and(|v| v.is_string() || v.is_null()))
    {
        return Err(EventError::unavailable());
    }
    for event in events {
        if event["name"] != name
            || !event["eventId"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
            || !event["timestamp"].is_string()
            || !event["data"].is_object()
        {
            return Err(EventError::unavailable());
        }
    }
    if value["truncated"] == true
        && !events.is_empty()
        && !value["_meta"]["io.ferrite/eventsReplayStart"].is_string()
    {
        return Err(EventError::unavailable());
    }
    Ok(())
}
pub(crate) fn replay_start(value: &Value) -> Value {
    if value["events"].as_array().is_some_and(|a| !a.is_empty()) {
        value["_meta"]["io.ferrite/eventsReplayStart"].clone()
    } else {
        value["cursor"].clone()
    }
}

/// RFC 3339 UTC, or `None` past the last instant of year 9999.
pub(crate) fn timestamp(ms: u64) -> Option<String> {
    (ms <= 253402300799999).then(|| super::tasks::timestamp(ms))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json::json;
    fn request(cursor: Value) -> PollRequest {
        PollRequest::parse(&json!({"name":"notes.changed","cursor":cursor,"maxEvents":1})).unwrap()
    }
    fn row(id: &str, at_ms: u64) -> EventRecord {
        EventRecord {
            id: id.into(),
            at_ms,
            data: json!({"note":id}),
        }
    }
    #[test]
    fn bootstrap_append_retry_and_drain() {
        let mut rows = vec![row("old", 1)];
        let boot = poll_snapshot("alice", &rows, 2, 100, &request(Value::Null)).unwrap();
        assert_eq!(boot["events"], json!([]));
        rows.extend([row("a", 3), row("b", 3)]);
        let req = request(boot["cursor"].clone());
        let first = poll_snapshot("alice", &rows, 4, 100, &req).unwrap();
        assert_eq!(first["events"][0]["eventId"], "a");
        assert_eq!(first["events"][0]["timestamp"], "1970-01-01T00:00:00.003Z");
        assert_eq!(first["hasMore"], true);
        assert_eq!(first, poll_snapshot("alice", &rows, 4, 100, &req).unwrap());
        let second =
            poll_snapshot("alice", &rows, 4, 100, &request(first["cursor"].clone())).unwrap();
        assert_eq!(second["events"][0]["eventId"], "b");
        assert_eq!(second["hasMore"], false);
        assert_eq!(
            poll_snapshot("alice", &rows, 5, 100, &request(second["cursor"].clone())).unwrap()
                ["events"],
            json!([])
        );
        assert_eq!(
            poll_snapshot("bob", &rows, 4, 100, &req).unwrap_err().code,
            -32602
        );
    }
    #[test]
    fn retention_age_and_empty_bootstrap() {
        let boot = poll_snapshot("alice", &[], 2, 100, &request(Value::Null)).unwrap();
        let rows = [row("a", 3), row("b", 4)];
        let first =
            poll_snapshot("alice", &rows, 4, 100, &request(boot["cursor"].clone())).unwrap();
        let mut req = request(first["cursor"].clone());
        let expired = poll_snapshot("alice", &rows[1..], 4, 100, &req).unwrap();
        assert_eq!(expired["truncated"], true);
        assert_eq!(expired["events"][0]["eventId"], "b");
        req.max_age_ms = Some(0);
        let aged = poll_snapshot("alice", &rows, 5, 100, &req).unwrap();
        assert_eq!(aged["truncated"], true);
        assert_eq!(aged["events"], json!([]));
        assert_eq!(timestamp(951782400000).unwrap(), "2000-02-29T00:00:00.000Z");
        assert_eq!(timestamp(253402300800000), None);
    }
    #[test]
    fn empty_start_keeps_late_commits_and_reports_full_retention_window() {
        let boot = poll_snapshot("alice", &[], 50, 2, &request(Value::Null)).unwrap();
        // Occurred before subscription, but was appended after its snapshot.
        let rows = [row("late", 10), row("new", 60)];
        let delivered =
            poll_snapshot("alice", &rows, 70, 2, &request(boot["cursor"].clone())).unwrap();
        assert_eq!(delivered["events"][0]["eventId"], "late");
        assert_eq!(delivered["truncated"], true);
        let lost =
            poll_snapshot("alice", &[], 80, 2, &request(delivered["cursor"].clone())).unwrap();
        assert_eq!(lost["truncated"], true);
        let recovered = poll_snapshot(
            "alice",
            &[row("after-reset", 20)],
            90,
            2,
            &request(lost["cursor"].clone()),
        )
        .unwrap();
        assert_eq!(recovered["events"][0]["eventId"], "after-reset");
        assert_eq!(recovered["truncated"], false);
    }
    #[test]
    fn malformed_limits_and_untrustworthy_history_are_refused() {
        for params in [
            json!({"name":"x","maxEvents":0}),
            json!({"name":"x","maxEvents":-1}),
            json!({"name":"x","maxAgeMs":-1}),
            json!({"name":"x","cursor":3}),
            json!({"name":"x","arguments":[]}),
            json!({"name":"x","token":"secret"}),
        ] {
            assert_eq!(PollRequest::parse(&params).unwrap_err().code, -32602);
        }
        assert!(poll_snapshot("a", &[], 0, 100, &request(json!("garbage"))).is_err());
        assert!(poll_snapshot(
            "a",
            &[row("x", 0), row("x", 0)],
            0,
            100,
            &request(Value::Null)
        )
        .is_err());
        assert_eq!(
            PollRequest::parse(&json!({"name":"x","maxEvents":1000000}))
                .unwrap()
                .max_events,
            100
        );
    }
}
