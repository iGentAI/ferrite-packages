//! Short-lived webhook subscriptions over an explicitly authorized host.
//! The host owns scheduling and an SSRF-safe HTTP transport: resolve/check/pin
//! the destination on EVERY POST, preserve TLS SNI, and never follow redirects.
//! Soft state grants at most five minutes; clients refresh and replay after restart.
use super::events::{replay_start, timestamp, validate_delivery, EventError, PollRequest};
use super::hmac::hmac_sha256;
use super::x402::{b64_decode, b64_encode};
use crate::crypto::constant_time_eq;
use ferrite_app::serde_json::{self, json, Value};
use std::collections::BTreeMap;

pub const MAX_TTL_MS: u64 = 300_000;
const MAX_SUBSCRIPTIONS: usize = 128;
/// One principal's share of the subscriptions, so it cannot fill the global
/// table for every other tenant.
const MAX_SUBSCRIPTIONS_PER_PRINCIPAL: usize = 16;
/// Callback challenges one principal may have in their 60-second cooldown at
/// once, across every URL: varying the path or query no longer buys another
/// outbound signed POST, nor fills the global attempt table.
const MAX_CHALLENGES_PER_PRINCIPAL: usize = 4;
const MAX_BODY: usize = 64 * 1024;

fn error(code: i64, message: &'static str) -> EventError {
    EventError {
        code,
        message,
        data: None,
    }
}
fn callback_error() -> EventError {
    EventError {
        code: -32027,
        message: "callback verification failed",
        data: Some(json!({"reason":"challenge_failed"})),
    }
}
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<_, _> = m.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            json!(sorted)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        _ => v.clone(),
    }
}
fn digest(v: &Value) -> String {
    super::sha256::to_hex(&super::sha256::sha256(canonical(v).to_string().as_bytes()))
}
fn key(secret: &str) -> Result<Vec<u8>, EventError> {
    let encoded = secret
        .strip_prefix("whsec_")
        .ok_or_else(EventError::invalid)?;
    let v = b64_decode(encoded).ok_or_else(EventError::invalid)?;
    if b64_encode(&v) != encoded {
        return Err(EventError::invalid());
    }
    if !(24..=64).contains(&v.len()) {
        return Err(EventError::invalid());
    }
    Ok(v)
}

/// The delivery of one retained occurrence, stamped with the read's cursor.
fn pending_event(event: &Value, polled: &Value, now: u64) -> Pending {
    let mut body = event.clone();
    body["cursor"] = polled["cursor"].clone();
    Pending {
        id: delivery_id(body["eventId"].as_str().unwrap_or("")),
        body,
        next_cursor: polled["cursor"].as_str().map(str::to_string),
        attempts: 0,
        next_ms: now,
        gap: false,
        abandoned: false,
    }
}

/// The Standard Webhooks `webhook-id` for an event. An eventId that is already a
/// valid id (visible ASCII, no '.', at most 256 bytes) is used as it is; any other
/// (`notes.changed.1`, non-ASCII) maps to a stable `msg_<sha256>`, so the event is
/// delivered rather than refused as an unsafe destination. The body keeps the eventId.
fn delivery_id(event_id: &str) -> String {
    let valid = !event_id.is_empty()
        && event_id.len() <= 256
        && event_id.bytes().all(|b| (33..=126).contains(&b) && b != b'.');
    if valid {
        event_id.to_string()
    } else {
        format!("msg_{}", super::sha256::to_hex(&super::sha256::sha256(event_id.as_bytes())))
    }
}

pub fn signed_headers(
    secret: &str,
    id: &str,
    subscription: &str,
    body: &[u8],
    now_ms: u64,
) -> Result<Vec<(String, String)>, EventError> {
    if id.is_empty()
        || id.len() > 256
        || subscription.len() > 256
        || id
            .bytes()
            .chain(subscription.bytes())
            .any(|b| !(33..=126).contains(&b) || b == b'.')
        || body.len() > MAX_BODY
    {
        return Err(EventError::invalid());
    }
    let time = (now_ms / 1000).to_string();
    let mut bytes = format!("{id}.{time}.").into_bytes();
    bytes.extend_from_slice(body);
    let sig = b64_encode(&hmac_sha256(&key(secret)?, &bytes));
    Ok(vec![
        ("content-type".into(), "application/json".into()),
        ("webhook-id".into(), id.into()),
        ("webhook-timestamp".into(), time),
        ("webhook-signature".into(), format!("v1,{sig}")),
        ("X-MCP-Subscription-Id".into(), subscription.into()),
    ])
}
/// Verify before JSON parsing. The caller deduplicates webhook-id per subscription.
pub fn verify(
    secret: &str,
    id: &str,
    time: &str,
    signature: &str,
    body: &[u8],
    now_ms: u64,
) -> bool {
    let Ok(seconds) = time.parse::<u64>() else {
        return false;
    };
    if seconds.abs_diff(now_ms / 1000) > 300 || seconds > u64::MAX / 1000 {
        return false;
    }
    let Ok(headers) = signed_headers(secret, id, "", body, seconds * 1000) else {
        return false;
    };
    let expected = &headers[3].1;
    signature
        .split_whitespace()
        .any(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()))
}

#[derive(Clone, Copy, Debug)]
pub enum DeliveryFailure {
    Timeout,
    Tls,
    Unreachable,
    UnsafeDestination,
}
impl DeliveryFailure {
    fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Tls => "tls_error",
            Self::Unreachable => "unreachable",
            Self::UnsafeDestination => "unsafe_destination",
        }
    }
}
pub struct CallbackResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
#[allow(async_fn_in_trait)]
pub trait WebhookHost {
    /// Must recheck current authorization, not just token validity at subscribe time.
    async fn poll(&self, principal: &str, request: PollRequest) -> Result<Value, EventError>;
    /// Audited egress only; no redirects, private IPs or DNS check/connect race.
    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<CallbackResponse, DeliveryFailure>;
    /// Fresh cryptographic nonce with at least 128 random bits; never caller input.
    fn nonce(&self) -> String;
    fn now_ms(&self) -> u64;
}
struct Pending {
    id: String,
    body: Value,
    next_cursor: Option<String>,
    attempts: u8,
    next_ms: u64,
    gap: bool,
    abandoned: bool,
}
struct Subscription {
    id: String,
    principal: String,
    url: String,
    secret: String,
    request: PollRequest,
    expires: u64,
    pending: Option<Pending>,
    last_error: Option<&'static str>,
    last_delivery: Option<u64>,
}
#[derive(Default)]
pub struct Webhooks {
    subscriptions: BTreeMap<String, Subscription>,
    verification: BTreeMap<(String, String), u64>,
    attempts: BTreeMap<(String, String), u64>,
}
impl Webhooks {
    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }
    pub fn prune(&mut self, now: u64) {
        self.subscriptions.retain(|_, s| s.expires > now);
        self.verification.retain(|_, until| *until > now);
        self.attempts.retain(|_, until| *until > now);
    }
    fn parse(
        principal: &str,
        params: &Value,
        subscribe: bool,
    ) -> Result<(String, String, PollRequest), EventError> {
        if principal.is_empty() || principal.len() > 512 || !params.is_object() {
            return Err(EventError::forbidden());
        }
        if params.as_object().unwrap().keys().any(|k| {
            ![
                "name",
                "arguments",
                "delivery",
                "cursor",
                "maxAgeMs",
                "ttlMs",
                "_meta",
            ]
            .contains(&k.as_str())
        }) {
            return Err(EventError::invalid());
        }
        let delivery = params["delivery"]
            .as_object()
            .ok_or_else(EventError::invalid)?;
        if delivery
            .keys()
            .any(|k| !["mode", "url", "secret"].contains(&k.as_str()))
            || params["delivery"]["mode"]
                .as_str()
                .is_some_and(|m| m != "webhook")
        {
            return Err(EventError::invalid());
        }
        let url = params["delivery"]["url"]
            .as_str()
            .filter(|s| {
                s.starts_with("https://")
                    && s.len() <= 2048
                    && !s.contains(['#', '\\'])
                    && !s.bytes().any(|b| b <= 32 || b == 127)
            })
            .ok_or_else(EventError::invalid)?;
        let authority = url[8..].split('/').next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return Err(EventError::invalid());
        }
        if subscribe {
            key(params["delivery"]["secret"]
                .as_str()
                .ok_or_else(EventError::invalid)?)?;
        }
        let mut request = PollRequest::parse(
            &json!({"name":params["name"],"arguments":params.get("arguments").cloned().unwrap_or(json!({})),"cursor":params["cursor"],"maxEvents":1}),
        )?;
        request.max_age_ms = params
            .get("maxAgeMs")
            .map(|v| v.as_u64().ok_or_else(EventError::invalid))
            .transpose()?;
        let id = format!(
            "sub_{}",
            digest(&json!([principal, url, request.name, request.arguments]))
        );
        Ok((id, url.into(), request))
    }
    pub async fn subscribe<H: WebhookHost>(
        &mut self,
        host: &H,
        principal: &str,
        params: &Value,
        now: u64,
    ) -> Result<Value, EventError> {
        let now = now.max(host.now_ms());
        self.prune(now);
        let (id, url, mut request) = Self::parse(principal, params, true)?;
        let ttl = match params.get("ttlMs") {
            None | Some(Value::Null) => MAX_TTL_MS,
            Some(v) => v
                .as_u64()
                .filter(|v| *v > 0)
                .ok_or_else(EventError::invalid)?
                .min(MAX_TTL_MS),
        };
        if !self.subscriptions.contains_key(&id) && self.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(error(-32025, "subscription limit reached"));
        }
        if !self.subscriptions.contains_key(&id)
            && self
                .subscriptions
                .values()
                .filter(|s| s.principal == principal)
                .count()
                >= MAX_SUBSCRIPTIONS_PER_PRINCIPAL
        {
            return Err(error(-32025, "subscription limit reached for this principal"));
        }
        let secret = params["delivery"]["secret"].as_str().unwrap();
        // Refresh never advances past an in-flight occurrence, nor applies a new cursor.
        if let Some(existing) = self.subscriptions.get(&id) {
            request.cursor = existing.request.cursor.clone();
        }
        let polled = host.poll(principal, request.clone()).await?;
        validate_delivery(&polled, &request.name)?;
        let verify_key = (principal.to_string(), url.clone());
        if !self.verification.contains_key(&verify_key) {
            // Rate-limit every attempted challenge (including failures), per principal + URL.
            if self.attempts.contains_key(&verify_key)
                || self.attempts.keys().filter(|(p, _)| p == principal).count()
                    >= MAX_CHALLENGES_PER_PRINCIPAL
            {
                return Err(error(-32025, "callback verification rate limited"));
            }
            if self.attempts.len() >= MAX_SUBSCRIPTIONS * 2 {
                return Err(error(-32025, "callback verification limit reached"));
            }
            self.attempts
                .insert(verify_key.clone(), now.saturating_add(60_000));
            let nonce = host.nonce();
            // The id is "msg_verification_" (17 bytes) plus the nonce, within signed_headers' 256.
            if nonce.len() < 22
                || nonce.len() > 256 - "msg_verification_".len()
                || nonce.bytes().any(|b| !(33..=126).contains(&b) || b == b'.')
            {
                return Err(EventError::unavailable());
            }
            let body = serde_json::to_vec(&json!({"type":"verification","challenge":nonce}))
                .map_err(|_| EventError::unavailable())?;
            let headers = signed_headers(
                secret,
                &format!("msg_verification_{nonce}"),
                &id,
                &body,
                now,
            )?;
            let response = host
                .post(&url, headers, body)
                .await
                .map_err(|e| EventError {
                    code: -32027,
                    message: "callback verification failed",
                    data: Some(json!({"reason":e.reason()})),
                })?;
            if response.body.len() > 4096 {
                return Err(callback_error());
            }
            let echoed: Value =
                serde_json::from_slice(&response.body).map_err(|_| callback_error())?;
            if !(200..300).contains(&response.status)
                || !echoed["challenge"]
                    .as_str()
                    .is_some_and(|s| constant_time_eq(s.as_bytes(), nonce.as_bytes()))
            {
                return Err(callback_error());
            }
            self.verification
                .insert(verify_key, host.now_ms().saturating_add(MAX_TTL_MS));
        }
        let now = host.now_ms().max(now);
        let truncated = polled["truncated"]
            .as_bool()
            .ok_or_else(EventError::unavailable)?;
        let max_age_ms = request.max_age_ms;
        if !self.subscriptions.contains_key(&id) {
            // Bootstrap (null cursor) starts at the head; replay retains its old position.
            if request.cursor.is_none() {
                request.cursor = polled["cursor"].as_str().map(str::to_string);
            }
            self.subscriptions.insert(
                id.clone(),
                Subscription {
                    id: id.clone(),
                    principal: principal.into(),
                    url,
                    secret: secret.into(),
                    request,
                    expires: now.saturating_add(ttl),
                    pending: None,
                    last_error: None,
                    last_delivery: None,
                },
            );
        }
        let subscription = self.subscriptions.get_mut(&id).unwrap();
        subscription.expires = now.saturating_add(ttl);
        subscription.secret = secret.into();
        subscription.request.max_age_ms = max_age_ms;
        Ok(
            json!({"resultType":"complete","id":id,"refreshBefore":timestamp(subscription.expires),"cursor":subscription.request.cursor,"truncated":truncated,"deliveryStatus":{"active":true,"lastError":subscription.last_error,"lastDeliveryAt":subscription.last_delivery.and_then(timestamp)}}),
        )
    }
    pub async fn unsubscribe<H: WebhookHost>(
        &mut self,
        host: &H,
        principal: &str,
        params: &Value,
    ) -> Result<Value, EventError> {
        let (id, _, request) = Self::parse(principal, params, false)?;
        host.poll(principal, request).await?;
        if self.subscriptions.remove(&id).is_none() {
            return Err(EventError {
                code: -32023,
                message: "unknown subscription",
                data: Some(json!({"kind":"subscription"})),
            });
        }
        Ok(json!({"resultType":"complete"}))
    }
    /// Drive from the host's existing scheduler, never from a request-only app that
    /// cannot guarantee another tick. At most one attempt per subscription per tick.
    pub async fn tick<H: WebhookHost>(&mut self, host: &H) {
        self.prune(host.now_ms());
        let ids: Vec<_> = self.subscriptions.keys().cloned().collect();
        for id in ids {
            let now = host.now_ms();
            if self.subscriptions[&id].expires <= now {
                self.subscriptions.remove(&id);
                continue;
            }
            let s = self.subscriptions.get_mut(&id).unwrap();
            let polled = match host.poll(&s.principal, s.request.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    if host.now_ms() >= s.expires {
                        self.subscriptions.remove(&id);
                        continue;
                    }
                    if e.ends_subscription() {
                        let body=json!({"type":"terminated","error":{"code":e.code,"message":e.message,"data":e.data}}).to_string().into_bytes();
                        if let Ok(h) = signed_headers(
                            &s.secret,
                            &format!("msg_terminated_{}", host.nonce()),
                            &s.id,
                            &body,
                            host.now_ms(),
                        ) {
                            let _ = host.post(&s.url, h, body).await;
                        }
                        self.subscriptions.remove(&id);
                    }
                    continue;
                }
            };
            if validate_delivery(&polled, &s.request.name).is_err() {
                s.last_error = Some("invalid_source_response");
                continue;
            }
            if s.pending.is_none() {
                let event = polled["events"].as_array().and_then(|a| a.first());
                // A gap does not consume the first retained event; after the notice, replay it.
                if polled["truncated"] == true {
                    s.pending = Some(Pending {
                        id: format!("msg_gap_{}", host.nonce()),
                        body: json!({"type":"gap","cursor":replay_start(&polled)}),
                        next_cursor: s.request.cursor.clone(),
                        attempts: 0,
                        next_ms: now,
                        gap: true,
                        abandoned: false,
                    });
                } else if let Some(event) = event {
                    s.pending = Some(pending_event(event, &polled, now));
                } else {
                    s.request.cursor = polled["cursor"].as_str().map(str::to_string);
                    continue;
                }
            }
            let now = host.now_ms();
            if now >= s.expires {
                self.subscriptions.remove(&id);
                continue;
            }
            let p = s.pending.as_mut().unwrap();
            if p.next_ms > now {
                continue;
            }
            let body = p.body.to_string().into_bytes();
            let response = match signed_headers(&s.secret, &p.id, &s.id, &body, now) {
                Ok(h) => host.post(&s.url, h, body).await,
                Err(_) => Err(DeliveryFailure::UnsafeDestination),
            };
            let status = response.as_ref().map(|r| r.status).unwrap_or(0);
            if (200..300).contains(&status) {
                s.last_delivery = Some(now);
                s.last_error = None;
                if p.gap && p.abandoned {
                    s.request.cursor = p.next_cursor.clone();
                    s.pending = None;
                } else if p.gap {
                    // Keep replay position; suppress repeated gap on this live source read.
                    if let Some(event) = polled["events"].as_array().and_then(|a| a.first()) {
                        s.pending = Some(pending_event(event, &polled, now));
                    } else {
                        s.request.cursor = polled["cursor"].as_str().map(str::to_string);
                        s.pending = None;
                    }
                } else {
                    s.request.cursor = p.next_cursor.clone();
                    s.pending = None;
                }
            } else {
                s.last_error = Some(match response {
                    Err(e) => e.reason(),
                    Ok(_) => {
                        if status >= 500 {
                            "http_5xx"
                        } else if status >= 400 {
                            "http_4xx"
                        } else {
                            "redirect_refused"
                        }
                    }
                });
                p.attempts += 1;
                if p.attempts >= 6 || matches!(status, 410 | 413) {
                    if p.gap {
                        self.subscriptions.remove(&id);
                        continue;
                    }
                    // Abandon only with an explicit gap envelope; watermark stays behind it.
                    p.body = json!({"type":"gap","cursor":p.next_cursor});
                    p.gap = true;
                    p.abandoned = true;
                    p.attempts = 0;
                    p.id = format!("msg_gap_{}", host.nonce());
                }
                p.next_ms = now.saturating_add(1000u64 << p.attempts.min(6));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::events::{poll_snapshot, EventRecord};

    #[test]
    fn an_event_id_that_is_not_a_webhook_id_maps_to_a_stable_one() {
        // finding_1be82e90b06d213b
        assert_eq!(delivery_id("evt_1"), "evt_1");
        let dotted = delivery_id("notes.changed.1");
        assert!(dotted.starts_with("msg_") && !dotted.contains('.'));
        assert_eq!(dotted, delivery_id("notes.changed.1"));
        assert!(signed_headers(&format!("whsec_{}", b64_encode(b"0123456789abcdef0123456789abcdef")), &dotted, "sub", b"{}", 1).is_ok());
    }
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    };
    struct Host {
        rows: Mutex<Vec<EventRecord>>,
        posts: Mutex<Vec<Value>>,
        clock: AtomicU64,
        nonce: AtomicU64,
        allowed: AtomicBool,
        fail: AtomicBool,
        malformed: AtomicBool,
        poll_delay_ms: AtomicU64,
        secret: String,
    }
    impl Host {
        fn new() -> Self {
            Self {
                rows: Mutex::new(vec![]),
                posts: Mutex::new(vec![]),
                clock: AtomicU64::new(1_000_000),
                nonce: AtomicU64::new(1),
                allowed: AtomicBool::new(true),
                fail: AtomicBool::new(false),
                malformed: AtomicBool::new(false),
                poll_delay_ms: AtomicU64::new(0),
                secret: format!("whsec_{}", b64_encode(&[42u8; 32])),
            }
        }
        fn params(&self) -> Value {
            json!({"name":"changed","delivery":{"mode":"webhook","url":"https://hooks.example/events","secret":self.secret},"ttlMs":100_000})
        }
    }
    impl WebhookHost for Host {
        async fn poll(&self, principal: &str, request: PollRequest) -> Result<Value, EventError> {
            self.clock
                .fetch_add(self.poll_delay_ms.load(Ordering::SeqCst), Ordering::SeqCst);
            if self.malformed.load(Ordering::SeqCst) {
                return Ok(
                    json!({"events":"bad","cursor":"unsafe","truncated":false,"hasMore":false}),
                );
            }
            if !self.allowed.load(Ordering::SeqCst) {
                return Err(EventError::forbidden());
            }
            poll_snapshot(
                principal,
                &self.rows.lock().unwrap(),
                self.now_ms(),
                10,
                &request,
            )
        }
        async fn post(
            &self,
            _: &str,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        ) -> Result<CallbackResponse, DeliveryFailure> {
            let get = |n: &str| headers.iter().find(|(k, _)| k == n).unwrap().1.as_str();
            assert!(verify(
                &self.secret,
                get("webhook-id"),
                get("webhook-timestamp"),
                get("webhook-signature"),
                &body,
                self.now_ms()
            ));
            let value: Value = serde_json::from_slice(&body).unwrap();
            self.posts.lock().unwrap().push(value.clone());
            if value["type"] == "verification" {
                return Ok(CallbackResponse {
                    status: 200,
                    body: json!({"challenge":value["challenge"]})
                        .to_string()
                        .into_bytes(),
                });
            }
            Ok(CallbackResponse {
                status: if self.fail.load(Ordering::SeqCst) {
                    503
                } else {
                    204
                },
                body: vec![],
            })
        }
        fn nonce(&self) -> String {
            format!(
                "fixture-unique-{:032x}",
                self.nonce.fetch_add(1, Ordering::SeqCst)
            )
        }
        fn now_ms(&self) -> u64 {
            self.clock.load(Ordering::SeqCst)
        }
    }
    #[tokio::test]
    async fn callback_consent_retry_watermark_expiry_and_revocation() {
        let host = Host::new();
        let mut hooks = Webhooks::default();
        let params = host.params();
        let first = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        assert_eq!(host.posts.lock().unwrap().len(), 1);
        host.rows.lock().unwrap().push(EventRecord {
            id: "event-1".into(),
            at_ms: host.now_ms() + 1,
            data: json!({"ok":true}),
        });
        host.fail.store(true, Ordering::SeqCst);
        hooks.tick(&host).await;
        let refreshed = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        assert_eq!(first["id"], refreshed["id"]);
        assert_eq!(first["cursor"], refreshed["cursor"]);
        assert_eq!(
            host.posts.lock().unwrap().len(),
            2,
            "refresh should not challenge or deliver again"
        );
        host.clock.fetch_add(3000, Ordering::SeqCst);
        host.fail.store(false, Ordering::SeqCst);
        hooks.tick(&host).await;
        let refreshed = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        assert_ne!(first["cursor"], refreshed["cursor"]);
        {
            let posts = host.posts.lock().unwrap();
            assert_eq!(posts[1]["eventId"], posts[2]["eventId"]);
        }
        let mut second = params.clone();
        second["arguments"] = json!({"filter":"another"});
        hooks
            .subscribe(&host, "alice", &second, host.now_ms())
            .await
            .unwrap();
        assert_eq!(
            host.posts.lock().unwrap().len(),
            3,
            "consent reused for another subscription to same callback"
        );
        host.allowed.store(false, Ordering::SeqCst);
        hooks.tick(&host).await;
        assert!(hooks.is_empty());
        assert_eq!(
            host.posts.lock().unwrap().last().unwrap()["type"],
            "terminated"
        );
        host.allowed.store(true, Ordering::SeqCst);
        hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        host.clock.fetch_add(100_001, Ordering::SeqCst);
        let before = host.posts.lock().unwrap().len();
        hooks.tick(&host).await;
        assert!(hooks.is_empty());
        assert_eq!(host.posts.lock().unwrap().len(), before);
    }
    #[tokio::test]
    async fn invalid_source_and_expiry_during_read_cannot_send_or_acknowledge() {
        let host = Host::new();
        let mut hooks = Webhooks::default();
        let params = host.params();
        let first = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        host.malformed.store(true, Ordering::SeqCst);
        hooks.tick(&host).await;
        assert_eq!(
            hooks
                .subscriptions
                .values()
                .next()
                .unwrap()
                .request
                .cursor
                .as_deref(),
            first["cursor"].as_str()
        );
        assert_eq!(host.posts.lock().unwrap().len(), 1);
        host.malformed.store(false, Ordering::SeqCst);
        host.rows.lock().unwrap().push(EventRecord {
            id: "late".into(),
            at_ms: host.now_ms() + 1,
            data: json!({}),
        });
        host.poll_delay_ms.store(100001, Ordering::SeqCst);
        hooks.tick(&host).await;
        assert!(hooks.is_empty());
        assert_eq!(host.posts.lock().unwrap().len(), 1);
    }

    #[test]
    fn independent_standard_webhooks_vector_and_strict_encoding() {
        let fixture = format!("whsec_{}", b64_encode(&[42u8; 32]));
        let secret = fixture.as_str();
        let headers = signed_headers(
            secret,
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            "sub",
            br#"{"test": 2432232314}"#,
            1_614_265_330_000,
        )
        .unwrap();
        assert_eq!(
            headers[3].1,
            "v1,E6dWfEHORnXR6oV5qI5L2wAbNDJ0tdv1J9rAzZxm3rs="
        );
        assert!(key(&format!("{secret}A")).is_err());
        assert!(key(&format!("{secret}\n")).is_err());
    }
    #[tokio::test]
    async fn lost_anchor_gap_replays_first_retained_occurrence() {
        let host = Host::new();
        let mut hooks = Webhooks::default();
        host.rows.lock().unwrap().push(EventRecord {
            id: "gone".into(),
            at_ms: host.now_ms(),
            data: json!({}),
        });
        hooks
            .subscribe(&host, "alice", &host.params(), host.now_ms())
            .await
            .unwrap();
        *host.rows.lock().unwrap() = vec![EventRecord {
            id: "retained".into(),
            at_ms: host.now_ms() + 1,
            data: json!({}),
        }];
        hooks.tick(&host).await;
        let gap = host.posts.lock().unwrap().last().unwrap().clone();
        assert_eq!(gap["type"], "gap");
        let replay = host
            .poll(
                "alice",
                PollRequest::parse(&json!({"name":"changed","cursor":gap["cursor"],"maxEvents":1}))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay["events"][0]["eventId"], "retained");
        hooks.tick(&host).await;
        let event = host.posts.lock().unwrap().last().unwrap().clone();
        assert_eq!(event["eventId"], "retained");
        let after = host
            .poll(
                "alice",
                PollRequest::parse(
                    &json!({"name":"changed","cursor":event["cursor"],"maxEvents":1}),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after["events"], json!([]));
    }
    #[tokio::test]
    async fn exhausted_delivery_advances_only_after_gap_ack() {
        let host = Host::new();
        let mut hooks = Webhooks::default();
        let mut params = host.params();
        params["ttlMs"] = json!(300000);
        let first = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        host.rows.lock().unwrap().push(EventRecord {
            id: "dropped".into(),
            at_ms: host.now_ms() + 1,
            data: json!({}),
        });
        host.fail.store(true, Ordering::SeqCst);
        for _ in 0..6 {
            hooks.tick(&host).await;
            host.clock.fetch_add(32000, Ordering::SeqCst);
        }
        assert_eq!(
            hooks
                .subscriptions
                .values()
                .next()
                .unwrap()
                .request
                .cursor
                .as_deref(),
            first["cursor"].as_str()
        );
        host.fail.store(false, Ordering::SeqCst);
        hooks.tick(&host).await;
        assert_eq!(host.posts.lock().unwrap().last().unwrap()["type"], "gap");
        let delivered = hooks
            .subscribe(&host, "alice", &params, host.now_ms())
            .await
            .unwrap();
        assert_ne!(first["cursor"], delivered["cursor"]);
    }
    #[test]
    fn signatures_reject_tamper_expiry_wrong_secret_and_insecure_url() {
        let host = Host::new();
        let bytes = b"{\"hello\":\"world\"}";
        let h = signed_headers(&host.secret, "evt-1", "sub-1", bytes, 1_000_000).unwrap();
        assert!(verify(
            &host.secret,
            "evt-1",
            "1000",
            &h[3].1,
            bytes,
            1_000_000
        ));
        assert!(!verify(
            &host.secret,
            "evt-2",
            "1000",
            &h[3].1,
            bytes,
            1_000_000
        ));
        assert!(!verify(
            &host.secret,
            "evt-1",
            "1000",
            &h[3].1,
            b"different",
            1_000_000
        ));
        assert!(!verify(
            &host.secret,
            "evt-1",
            "1000",
            &h[3].1,
            bytes,
            1_301_000
        ));
        assert!(!verify(
            "whsec_c2hvcnQ=",
            "evt-1",
            "1000",
            &h[3].1,
            bytes,
            1_000_000
        ));
        let mut params = host.params();
        params["delivery"]["url"] = json!("http://internal/");
        assert!(Webhooks::parse("alice", &params, true).is_err());
    }

    #[tokio::test]
    async fn one_principal_cannot_spend_everyone_s_challenges_or_subscriptions() {
        let host = Host::new();
        let mut hooks = Webhooks::default();
        let now = host.now_ms();
        let with_url = |url: &str| {
            json!({"name":"changed","delivery":{"mode":"webhook","url":url,"secret":host.secret},"ttlMs":100_000})
        };
        // Varying the query buys at most MAX_CHALLENGES_PER_PRINCIPAL challenges.
        host.fail.store(true, Ordering::SeqCst);
        for i in 0..MAX_CHALLENGES_PER_PRINCIPAL {
            let _ = hooks.subscribe(&host, "mallory", &with_url(&format!("https://target.example/hook?{i}")), now).await;
        }
        let posts_before = host.posts.lock().unwrap().len();
        let refused = hooks.subscribe(&host, "mallory", &with_url("https://target.example/hook?more"), now).await;
        assert_eq!(refused.unwrap_err().message, "callback verification rate limited");
        assert_eq!(host.posts.lock().unwrap().len(), posts_before, "no further outbound challenge");
        assert!(hooks.attempts.len() <= MAX_CHALLENGES_PER_PRINCIPAL);
        host.fail.store(false, Ordering::SeqCst);
        // Another principal is unaffected.
        assert!(hooks.subscribe(&host, "alice", &host.params(), now).await.is_ok());
    }
}
