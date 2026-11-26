//! Transport-neutral push lifecycle. A host drives `next` at <=30s intervals,
//! forwards frames immediately and drops this value on transport cancellation.
//! Every read goes through the same caller-authorized source as polling.
use super::events::{replay_start, validate_delivery, EventError, PollRequest};
use ferrite_app::serde_json::{json, Value};

pub const HEARTBEAT_MS: u64 = 15_000;
pub const SUBSCRIPTION_META: &str = "io.modelcontextprotocol/subscriptionId";

pub struct PushStream {
    id: Value,
    request: PollRequest,
    started: bool,
    ended: bool,
    pub has_more: bool,
}
impl PushStream {
    pub fn new(id: Value, params: &Value) -> Result<Self, EventError> {
        if !(id.is_string() || id.is_i64() || id.is_u64()) || params.get("maxEvents").is_some() {
            return Err(EventError::invalid());
        }
        let mut request = PollRequest::parse(params)?;
        // One occurrence per read keeps every delivered cursor an exact position.
        request.max_events = 1;
        Ok(Self {
            id,
            request,
            started: false,
            ended: false,
            has_more: false,
        })
    }
    pub fn ended(&self) -> bool {
        self.ended
    }
    pub fn cursor(&self) -> Option<&str> {
        self.request.cursor.as_deref()
    }
    fn notification(&self, kind: &str, mut params: Value) -> Value {
        params["_meta"] = json!({SUBSCRIPTION_META: self.id});
        json!({"jsonrpc":"2.0","method":format!("notifications/events/{kind}"),"params":params})
    }
    pub fn finish(&mut self) -> Value {
        self.ended = true;
        self.has_more = false;
        json!({"jsonrpc":"2.0","id":self.id,"result":{"resultType":"complete","_meta":{SUBSCRIPTION_META:self.id}}})
    }
    /// Invalid opening reads fail before the host sends HTTP SSE headers.
    /// Once active, transient errors preserve position; authorization/type loss ends it.
    pub async fn next<F, Fut>(&mut self, poll: F) -> Result<Vec<Value>, EventError>
    where
        F: FnOnce(PollRequest) -> Fut,
        Fut: std::future::Future<Output = Result<Value, EventError>>,
    {
        if self.ended {
            return Ok(Vec::new());
        }
        self.has_more = false;
        let response = match poll(self.request.clone()).await {
            Ok(v) => v,
            Err(error) if !self.started => return Err(error),
            Err(error) => {
                let terminal = error.ends_subscription();
                let kind = if terminal { "terminated" } else { "error" };
                let mut frames = vec![self.notification(
                    kind,
                    json!({"error":{"code":error.code,"message":error.message,"data":error.data}}),
                )];
                if terminal {
                    frames.push(self.finish());
                }
                return Ok(frames);
            }
        };
        validate_delivery(&response, &self.request.name)?;
        let events = response["events"]
            .as_array()
            .ok_or_else(EventError::unavailable)?;
        if events.len() > 1
            || !response["truncated"].is_boolean()
            || !(response["cursor"].is_null() || response["cursor"].is_string())
        {
            return Err(EventError::unavailable());
        }
        let mut frames = Vec::new();
        // An initial/gap active frame must not advance past an event still to send.
        if !self.started || response["truncated"] == true {
            let cursor = if response["truncated"] == true {
                replay_start(&response)
            } else if events.is_empty() {
                response["cursor"].clone()
            } else {
                json!(self.request.cursor)
            };
            frames.push(self.notification(
                "active",
                json!({"cursor":cursor,"truncated":response["truncated"]}),
            ));
        }
        for event in events {
            let mut params = event.clone();
            if !params.is_object() {
                return Err(EventError::unavailable());
            }
            params["cursor"] = response["cursor"].clone();
            frames.push(self.notification("event", params));
        }
        if events.is_empty() && self.started {
            frames.push(self.notification("heartbeat", json!({"cursor":response["cursor"]})));
        }
        self.request.cursor = response["cursor"].as_str().map(str::to_string);
        self.has_more = response["hasMore"] == true;
        self.started = true;
        Ok(frames)
    }
}

pub fn sse(message: &Value) -> Vec<u8> {
    format!("event: message\ndata: {message}\n\n").into_bytes()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::events::{poll_snapshot, EventRecord};
    #[tokio::test]
    async fn replay_heartbeat_gap_and_revocation_share_poll_positions() {
        let mut stream = PushStream::new(json!(7), &json!({"name":"changed"})).unwrap();
        let mut rows = Vec::new();
        let frames = stream
            .next(|r| std::future::ready(poll_snapshot("alice", &rows, 100, 10, &r)))
            .await
            .unwrap();
        assert_eq!(frames[0]["method"], "notifications/events/active");
        let cursor = stream.cursor().unwrap().to_string();
        rows.push(EventRecord {
            id: "one".into(),
            at_ms: 101,
            data: json!({"state":"built"}),
        });
        let frames = stream
            .next(|r| std::future::ready(poll_snapshot("alice", &rows, 102, 10, &r)))
            .await
            .unwrap();
        assert_eq!(frames[0]["params"]["eventId"], "one");
        assert_eq!(frames[0]["params"]["_meta"][SUBSCRIPTION_META], 7);
        assert_ne!(stream.cursor(), Some(cursor.as_str()));
        let frames = stream
            .next(|r| std::future::ready(poll_snapshot("alice", &rows, 103, 10, &r)))
            .await
            .unwrap();
        assert_eq!(frames[0]["method"], "notifications/events/heartbeat");
        let frames = stream
            .next(|_| async { Err(EventError::forbidden()) })
            .await
            .unwrap();
        assert_eq!(frames[0]["method"], "notifications/events/terminated");
        assert_eq!(frames[1]["id"], 7);
        assert!(stream.ended());
        assert!(stream
            .next(|_| async { panic!("ended stream polled") })
            .await
            .unwrap()
            .is_empty());
    }
    #[tokio::test]
    async fn backlog_error_and_gap_never_skip_or_spin() {
        let mut stream = PushStream::new(json!(1), &json!({"name":"changed"})).unwrap();
        let first = vec![EventRecord {
            id: "gone".into(),
            at_ms: 1,
            data: json!({}),
        }];
        stream
            .next(|r| std::future::ready(poll_snapshot("alice", &first, 2, 2, &r)))
            .await
            .unwrap();
        let rows = vec![
            EventRecord {
                id: "one".into(),
                at_ms: 3,
                data: json!({}),
            },
            EventRecord {
                id: "two".into(),
                at_ms: 4,
                data: json!({}),
            },
        ];
        let frames = stream
            .next(|r| std::future::ready(poll_snapshot("alice", &rows, 5, 2, &r)))
            .await
            .unwrap();
        assert_eq!(frames[0]["params"]["truncated"], true);
        let replay = PollRequest::parse(
            &json!({"name":"changed","cursor":frames[0]["params"]["cursor"],"maxEvents":1}),
        )
        .unwrap();
        assert_eq!(
            poll_snapshot("alice", &rows, 5, 2, &replay).unwrap()["events"][0]["eventId"],
            "one"
        );
        assert!(stream.has_more);
        stream
            .next(|_| async { Err(EventError::unavailable()) })
            .await
            .unwrap();
        assert!(!stream.has_more);
        let cursor = stream.cursor().map(str::to_owned);
        assert!(stream
            .next(|_| async {
                Ok(json!({"events":[{},{}],"cursor":"unsafe","truncated":false,"hasMore":false}))
            })
            .await
            .is_err());
        assert_eq!(stream.cursor(), cursor.as_deref());
        stream.finish();
        assert!(!stream.has_more);
    }
    #[tokio::test]
    async fn no_successful_open_before_authorization() {
        let mut stream = PushStream::new(json!("s"), &json!({"name":"private"})).unwrap();
        assert_eq!(
            stream
                .next(|_| async { Err(EventError::forbidden()) })
                .await
                .unwrap_err()
                .code,
            -32024
        );
        assert!(!stream.started);
    }
}
