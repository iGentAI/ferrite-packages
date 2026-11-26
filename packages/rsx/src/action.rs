//! Actions: the only path by which a request may CHANGE something.
//!
//! Delivery is at-least-once and the gateway hedges, so "the client
//! pressed the button once" and "the effect happened once" are
//! different statements. An action closes the gap as far as it can
//! actually be closed: **a staged effect is applied at most once**, and
//! every duplicate is answered with the reply the winning delivery
//! recorded.
//!
//! * Effects are **staged**, not applied. The staged entries, the
//!   **admission marker** and the **recorded reply** commit as ONE
//!   atomic envelope, guarded on the marker's absence. Exactly one
//!   delivery can win that guard.
//! * Every other delivery — a hedge, a retry, a redelivered lease —
//!   REPLAYS the recorded reply verbatim.
//!
//! Replaying rather than acknowledging is the whole contract. A
//! duplicate that received a fabricated "ok" would report success for
//! an outcome that never happened, so a 404, a validation error and a
//! 500 each replay AS THEMSELVES.
//!
//! ## What is guaranteed, exactly
//!
//! **A staged APE ENTRY is applied at most once.** That is the property
//! the guard buys — the key/value entries passed to
//! [`ActionCtx::commit`], committed in the action's own envelope — and
//! it is the one worth having.
//!
//! **Cache invalidation is deliberately NOT in that set.**
//! [`ActionCtx::expire_tag`] rides the recorded reply and is applied on
//! every delivery, replays included. Bumping a tag twice invalidates
//! exactly what bumping it once invalidates, so repetition costs a
//! recomputation and nothing else — while applying it on replay REPAIRS
//! the case where the admitted delivery committed and then died before
//! invalidating. Cheap repetition beats a stale page nobody can
//! explain.
//!
//! **The handler body may run more than once.** Two deliveries racing
//! on a cold key both find no record and both execute; only one wins
//! the guard, and the loser discards its work and replays the winner's
//! reply. This is ordinary optimistic concurrency, and it is why
//! effects must be STAGED: a handler that writes through
//! [`ActionCtx::route`] instead of [`ActionCtx::commit`] steps outside
//! the envelope, and outside the guarantee. Use `route()` for READS,
//! for authorization, and for nothing that must happen once.
//!
//! An effect on a plane outside the action's envelope (a second store,
//! an email, a payment) is likewise not covered. Those belong in the
//! outbox tier, and the runtime refuses to pretend otherwise.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use ferrite_app::client::ApeClusterClient;
use ferrite_app::{serde, serde_json};

use super::server::RouteCtx;

/// The route prefix actions are posted to (wire-v1 §1).
pub const ACTION_PREFIX: &str = "/_rsx/action/";

/// The most entries one action envelope may carry, leaving room for the
/// marker and the reply record inside the platform's 64-key limit.
pub const MAX_EFFECT_ENTRIES: usize = 62;

/// A boxed future.
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A structured, client-safe action failure.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionError {
    /// A stable, machine-readable code.
    pub code: String,
    /// A human-readable message. Client-facing: never put internal
    /// detail here.
    pub message: String,
    /// Per-field validation messages, for forms.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

impl ActionError {
    /// An error with a code and message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            fields: BTreeMap::new(),
        }
    }

    /// Attach a field-level message.
    pub fn field(mut self, name: impl Into<String>, message: impl Into<String>) -> Self {
        self.fields.insert(name.into(), message.into());
        self
    }

    /// The HTTP status this error replays with.
    pub fn status(&self) -> u16 {
        match self.code.as_str() {
            "not_found" => 404,
            "unauthorized" => 401,
            "forbidden" => 403,
            // The action token was missing, wrong, or the post came from
            // another site (see `csrf`).
            "csrf" => 403,
            "conflict" => 409,
            "invalid" => 422,
            // A failure the SERVER owns must not be reported as a
            // client mistake: a 4xx tells the caller not to retry.
            "internal" => 500,
            _ => 400,
        }
    }
}

/// What an action handler returns.
pub type ActionResult = Result<serde_json::Value, ActionError>;

/// The action envelope (wire-v1 §4).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionEnvelope {
    /// Wire version.
    pub v: u32,
    /// `ok` | `error` | `pending`.
    pub status: String,
    /// The action's value, when `ok`.
    pub result: serde_json::Value,
    /// The failure, when `error`.
    pub error: Option<ActionError>,
    /// The saga this action started, for cross-plane work.
    pub saga_id: Option<String>,
    /// The HTTP status this envelope replays with.
    pub http_status: u16,
    /// Cache tags this action invalidated.
    pub expired_tags: Vec<String>,
    /// Where the client should go next.
    pub redirect: Option<String>,
    /// A page payload the client may apply without a round trip.
    #[serde(default)]
    pub refresh: Option<serde_json::Value>,
}

impl ActionEnvelope {
    fn ok(result: serde_json::Value, expired_tags: Vec<String>, redirect: Option<String>) -> Self {
        Self {
            v: 1,
            status: "ok".to_string(),
            result,
            error: None,
            saga_id: None,
            http_status: 200,
            expired_tags,
            redirect,
            refresh: None,
        }
    }

    pub(crate) fn failed(error: ActionError) -> Self {
        let http_status = error.status();
        Self {
            v: 1,
            status: "error".to_string(),
            result: serde_json::Value::Null,
            error: Some(error),
            saga_id: None,
            http_status,
            expired_tags: Vec::new(),
            redirect: None,
            refresh: None,
        }
    }

    /// Whether this envelope records a failure.
    pub fn is_error(&self) -> bool {
        self.status == "error"
    }
}

impl From<ActionError> for ActionEnvelope {
    fn from(error: ActionError) -> Self {
        ActionEnvelope::failed(error)
    }
}

/// What an action staged while it ran.
#[derive(Default)]
struct Staged {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    expired_tags: Vec<String>,
    redirect: Option<String>,
}

/// The context an action handler runs in.
///
/// Effects are STAGED rather than applied: the runtime commits them
/// together with the admission marker and the recorded reply in one
/// atomic envelope, which is what makes "ran once" true rather than
/// hoped for.
#[derive(Clone)]
pub struct ActionCtx {
    route: RouteCtx,
    args: serde_json::Value,
    staged: Arc<Mutex<Staged>>,
}

impl ActionCtx {
    /// The request context: planes, auth, headers.
    ///
    /// For READS and authorization. A write performed through a client
    /// obtained here is OUTSIDE the action's atomic envelope and
    /// therefore outside its at-most-once guarantee — under racing
    /// duplicates the handler body may run more than once. Anything
    /// that must happen once goes through [`ActionCtx::commit`].
    pub fn route(&self) -> &RouteCtx {
        &self.route
    }

    /// The decoded arguments.
    pub fn args(&self) -> &serde_json::Value {
        &self.args
    }

    /// One argument by name.
    pub fn arg(&self, name: &str) -> Option<&serde_json::Value> {
        self.args.get(name)
    }

    /// A string argument, or a validation error naming the field.
    pub fn require_str(&self, name: &str) -> Result<String, ActionError> {
        match self.args.get(name).and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(ActionError::new("invalid", "a required field is missing")
                .field(name, "required")),
        }
    }

    /// The client-minted idempotency key this action is admitted under.
    pub fn idempotency_key(&self) -> &str {
        self.route.idempotency_key()
    }

    /// Stage a key/value to commit atomically with this action.
    ///
    /// The entries land on the action's APE binding in ONE envelope with
    /// the admission marker, so either all of them and the marker commit
    /// or none of them do.
    pub fn commit(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let mut staged = self.staged.lock().unwrap();
        staged
            .entries
            .push((key.as_ref().to_vec(), value.as_ref().to_vec()));
    }

    /// Stage a JSON document.
    pub fn commit_json<T: serde::Serialize>(
        &self,
        key: impl AsRef<[u8]>,
        value: &T,
    ) -> Result<(), ActionError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| ActionError::new("internal", format!("encoding failed: {e}")))?;
        self.commit(key, bytes);
        Ok(())
    }

    /// Mark a cache tag expired.
    ///
    /// The tag rides the recorded reply, so it is applied on every
    /// delivery of this action — replays included. That is deliberate:
    /// invalidating twice invalidates exactly what invalidating once
    /// does, and re-applying on a replay repairs the case where the
    /// admitted delivery committed and then died before the cache heard
    /// about it. It is NOT part of the at-most-once guarantee.
    pub fn expire_tag(&self, tag: impl Into<String>) {
        let mut staged = self.staged.lock().unwrap();
        staged.expired_tags.push(tag.into());
    }

    /// Send the client somewhere after this action.
    pub fn redirect(&self, path: impl Into<String>) {
        let mut staged = self.staged.lock().unwrap();
        staged.redirect = Some(path.into());
    }
}

/// An action handler.
pub type ActionFn = Arc<dyn Fn(ActionCtx) -> BoxFut<ActionResult> + Send + Sync>;

/// Wrap an async fn as an [`ActionFn`].
pub fn action<F, Fut>(f: F) -> ActionFn
where
    F: Fn(ActionCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ActionResult> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// The longest idempotency key an action accepts. A browser key is a
/// 36-character UUID; without the header the gateway substitutes its
/// correlation id. Anything longer is refused rather than written into a
/// store key.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Resolves WHO an action invocation belongs to: a stable caller identity
/// the application vouches for (its own session's subject id, for
/// example), or `None` for an anonymous caller.
///
/// Registered with [`super::server::RsxAppBuilder::action_scope`].
/// The scope is part of the invocation's store keys, so a recorded reply is
/// only ever replayed to the caller that owns it: another caller presenting
/// the same idempotency key addresses a different record. It must be
/// STABLE for a caller — a subject id, never a session token or anything
/// else that rotates, since a retry after a rotation would then miss its
/// record and run the action again. Upstream Core states no caller
/// identity (see [`RouteCtx::auth`]), so without this hook the runtime has
/// none and invocations are addressed by action id and key alone.
pub type ActionScopeFn = Arc<dyn Fn(RouteCtx) -> BoxFut<Option<String>> + Send + Sync>;

/// The digest naming one action invocation in the store.
///
/// Every field is length-prefixed and the scope is tagged, so the encoding
/// is unambiguous: `("a:b", "c")` and `("a", "b:c")` no longer flatten to
/// the same `act:r:a:b:c`, and an unscoped invocation never encodes like a
/// scoped one. SHA-256 over that encoding is collision-resistant, and no
/// caller-supplied key can steer the store key out of its namespace. The
/// same construction as alloy's `invocation_digest`, plus the scope.
fn invocation_digest(id: &str, key: &str, scope: Option<&str>) -> String {
    let mut material = Vec::with_capacity(id.len() + key.len() + 32);
    material.extend_from_slice(&(id.len() as u64).to_be_bytes());
    material.extend_from_slice(id.as_bytes());
    material.extend_from_slice(&(key.len() as u64).to_be_bytes());
    material.extend_from_slice(key.as_bytes());
    match scope {
        None => material.push(0),
        Some(scope) => {
            material.push(1);
            material.extend_from_slice(&(scope.len() as u64).to_be_bytes());
            material.extend_from_slice(scope.as_bytes());
        }
    }
    let digest = ferrite_app::crypto::sha256(&material);
    let mut hex = String::with_capacity(64);
    for b in digest.iter() {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

fn marker_key(id: &str, key: &str, scope: Option<&str>) -> Vec<u8> {
    format!("act:m:{}", invocation_digest(id, key, scope)).into_bytes()
}

fn record_key(id: &str, key: &str, scope: Option<&str>) -> Vec<u8> {
    format!("act:r:{}", invocation_digest(id, key, scope)).into_bytes()
}

/// Where a reply was recorded before store keys were digested.
///
/// Read, never written: an invocation admitted by the previous runtime has
/// its marker and reply ONLY under this key (they committed in one
/// envelope), so a retry that spans the upgrade — a hedged delivery, or a
/// browser outbox entry replayed after the deploy — must still find it and
/// replay it instead of running the action a second time. Those records
/// predate caller scoping, so they are consulted for every caller, as the
/// previous runtime did.
fn legacy_record_key(id: &str, key: &str) -> Vec<u8> {
    format!("act:r:{id}:{key}").into_bytes()
}

/// The one read [`recorded`] needs, so the lookup order is testable
/// without a platform.
trait RecordRead {
    fn read(
        &mut self,
        key: &[u8],
    ) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;
}

impl RecordRead for ApeClusterClient {
    fn read(
        &mut self,
        key: &[u8],
    ) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send {
        self.get(key)
    }
}

/// How an envelope was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// This delivery ran the action.
    Admitted,
    /// A previous delivery ran it; this one replayed the record.
    Replayed,
}

/// Read a previously recorded reply, if this action was already
/// admitted under this key (and, when the app scopes invocations, for this
/// caller). A record from before store keys were digested is found too.
async fn recorded<S: RecordRead>(
    state: &mut S,
    id: &str,
    key: &str,
    scope: Option<&str>,
) -> io::Result<Option<ActionEnvelope>> {
    for at in [record_key(id, key, scope), legacy_record_key(id, key)] {
        if let Some(bytes) = state.read(&at).await? {
            // A record that exists but does not decode is an admitted invocation:
            // reading it as absent would run the action (and commit it) again.
            return serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("action record {} cannot be decoded ({error}); refusing to run it again", String::from_utf8_lossy(&at)),
                )
            });
        }
    }
    Ok(None)
}

/// Apply an action's staged effect AT MOST ONCE per idempotency key,
/// replaying the recorded reply for every duplicate.
///
/// The handler body itself may run more than once when deliveries race
/// on a cold key — see the module docs. What cannot happen twice is the
/// commit. Invocations are not scoped to a caller; see
/// [`run_action_scoped`].
pub async fn run_action(
    handler: &ActionFn,
    route: &RouteCtx,
    id: &str,
    args: serde_json::Value,
) -> io::Result<(ActionEnvelope, Admission)> {
    run_action_scoped(handler, route, id, args, None).await
}

/// [`run_action`], with the invocation owned by `scope` (see
/// [`ActionScopeFn`]): its marker and recorded reply live under keys that
/// include the scope, so a duplicate is answered only for the same caller.
pub async fn run_action_scoped(
    handler: &ActionFn,
    route: &RouteCtx,
    id: &str,
    args: serde_json::Value,
    scope: Option<&str>,
) -> io::Result<(ActionEnvelope, Admission)> {
    let mut state = route.app().ape("state")?;
    let key = route.idempotency_key().to_string();
    if key.is_empty() {
        return Ok((
            ActionEnvelope::failed(ActionError::new(
                "invalid",
                "an action requires an idempotency key",
            )),
            Admission::Admitted,
        ));
    }
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Ok((
            ActionEnvelope::failed(ActionError::new(
                "invalid",
                format!("an idempotency key may be at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes"),
            )),
            Admission::Admitted,
        ));
    }

    // A duplicate is answered from the record without running the
    // handler. This is a best-effort SHORTCUT, not the safety property:
    // two deliveries racing on a cold key both get here before either
    // records anything, and both proceed. Correctness comes from the
    // guarded commit below, which only one of them can win.
    if let Some(envelope) = recorded(&mut state, id, &key, scope).await? {
        return Ok((envelope, Admission::Replayed));
    }

    let actx = ActionCtx {
        route: route.clone(),
        args,
        staged: Arc::new(Mutex::new(Staged::default())),
    };
    let outcome = handler(actx.clone()).await;
    let staged = {
        let mut guard = actx.staged.lock().unwrap();
        std::mem::take(&mut *guard)
    };

    let envelope = match outcome {
        Ok(result) => ActionEnvelope::ok(result, staged.expired_tags.clone(), staged.redirect),
        Err(error) => ActionEnvelope::failed(error),
    };

    // A FAILED action stages nothing: its effects are not applied, and
    // the failure is still recorded so a duplicate replays the same
    // failure instead of retrying an operation that already refused.
    let effects: Vec<(Vec<u8>, Vec<u8>)> = if envelope.is_error() {
        Vec::new()
    } else {
        staged.entries
    };

    // An over-budget action is a terminal failure like any other, and it
    // takes the SAME recorded path: returning early here would leave no
    // record, so every duplicate would re-run a handler that cannot
    // succeed.
    let (envelope, effects) = if effects.len() > MAX_EFFECT_ENTRIES {
        (
            ActionEnvelope::failed(ActionError::new(
                "internal",
                format!("an action may stage at most {MAX_EFFECT_ENTRIES} entries"),
            )),
            Vec::new(),
        )
    } else if effects_collide(&effects) {
        // A staged key in the runtime's own `act:` namespace could plant a
        // replay record or marker for another invocation, and a duplicate
        // makes the envelope's outcome depend on entry order. Either is a
        // terminal failure, recorded like any other.
        (
            ActionEnvelope::failed(ActionError::new(
                "internal",
                "an action may not stage a reserved (act:) or duplicate key",
            )),
            Vec::new(),
        )
    } else {
        (envelope, effects)
    };

    let record = serde_json::to_vec(&envelope)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let marker = marker_key(id, &key, scope);
    let record_at = record_key(id, &key, scope);
    let mut entries: Vec<(&[u8], &[u8])> = Vec::with_capacity(effects.len() + 2);
    entries.push((marker.as_slice(), b"1"));
    entries.push((record_at.as_slice(), record.as_slice()));
    for (k, v) in &effects {
        entries.push((k.as_slice(), v.as_slice()));
    }

    // The GUARD is the whole admission: the envelope commits only while
    // the marker is still absent, so exactly one racing delivery wins
    // and the losers replay what the winner recorded.
    match state.commit_n_if(&marker, None, &entries).await? {
        Ok(()) => Ok((envelope, Admission::Admitted)),
        Err(_) => match recorded(&mut state, id, &key, scope).await? {
            Some(recorded) => Ok((recorded, Admission::Replayed)),
            // The marker exists but its record does not: the only way
            // that happens is a marker written by something other than
            // this runtime. Refusing is honest; inventing an answer is
            // not.
            None => Ok((
                ActionEnvelope::failed(ActionError::new(
                    "conflict",
                    "this request was already admitted, but its reply is not recorded",
                )),
                Admission::Replayed,
            )),
        },
    }
}

/// Parse `application/x-www-form-urlencoded` into action arguments.
///
/// Progressive enhancement: a form POST from a browser with no
/// JavaScript reaches the same action as the client runtime's fetch.
pub fn parse_form(body: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(body);
    let mut map = serde_json::Map::new();
    for (name, value) in super::router::parse_query(&text) {
        map.insert(name, serde_json::Value::String(value));
    }
    serde_json::Value::Object(map)
}

/// Whether staged effects touch the reserved `act:` namespace or repeat a key.
fn effects_collide(effects: &[(Vec<u8>, Vec<u8>)]) -> bool {
    let mut seen: std::collections::BTreeSet<&[u8]> = std::collections::BTreeSet::new();
    effects
        .iter()
        .any(|(k, _)| k.starts_with(b"act:") || !seen.insert(k.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_staged_key_cannot_enter_the_replay_namespace_or_repeat() {
        // finding_5a44789fdf976f26
        let e = |k: &str| (k.as_bytes().to_vec(), b"v".to_vec());
        assert!(effects_collide(&[e("act:r:save:k")]));
        assert!(effects_collide(&[e("act:m:x")]));
        assert!(effects_collide(&[e("notes/1"), e("notes/1")]));
        assert!(!effects_collide(&[e("notes/1"), e("notes/2")]));
        assert!(!effects_collide(&[]));
    }

    #[test]
    fn an_error_code_chooses_its_status() {
        assert_eq!(ActionError::new("not_found", "").status(), 404);
        assert_eq!(ActionError::new("unauthorized", "").status(), 401);
        assert_eq!(ActionError::new("forbidden", "").status(), 403);
        assert_eq!(ActionError::new("csrf", "").status(), 403);
        assert_eq!(ActionError::new("conflict", "").status(), 409);
        assert_eq!(ActionError::new("invalid", "").status(), 422);
        assert_eq!(
            ActionError::new("internal", "").status(),
            500,
            "a server failure is never reported as a client mistake"
        );
        assert_eq!(ActionError::new("whatever", "").status(), 400);
    }

    #[test]
    fn the_envelope_carries_every_wire_v1_field() {
        let envelope = ActionEnvelope::ok(serde_json::json!({"id": 1}), vec!["posts".into()], None);
        let json = serde_json::to_value(&envelope).unwrap();
        for field in [
            "v",
            "status",
            "result",
            "error",
            "saga_id",
            "http_status",
            "expired_tags",
            "redirect",
            "refresh",
        ] {
            assert!(json.get(field).is_some(), "missing {field} in {json}");
        }
    }

    #[test]
    fn an_envelope_records_the_failure_it_replays() {
        let envelope = ActionEnvelope::failed(
            ActionError::new("invalid", "bad title").field("title", "too short"),
        );
        assert!(envelope.is_error());
        assert_eq!(envelope.http_status, 422);
        assert_eq!(
            envelope.error.as_ref().unwrap().fields.get("title").unwrap(),
            "too short"
        );
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["status"], "error");
        assert!(json["result"].is_null());
        assert!(json["expired_tags"].is_array());
    }

    #[test]
    fn a_form_body_becomes_action_arguments() {
        let args = parse_form(b"title=Hello+World&body=a%20b&empty=");
        assert_eq!(args["title"], "Hello World");
        assert_eq!(args["body"], "a b");
        assert_eq!(args["empty"], "");
        assert!(parse_form(b"").as_object().unwrap().is_empty());
    }

    #[test]
    fn the_effect_budget_leaves_room_for_the_marker_and_the_record() {
        // The platform's envelope holds 64 entries; the marker and the
        // recorded reply are two of them.
        assert_eq!(MAX_EFFECT_ENTRIES, 62);
    }

    /// F489: the store keys are a SHA-256 digest over an unambiguous,
    /// length-prefixed encoding of (action id, key, scope), so distinct
    /// invocations do not share a record and no key can steer the store key
    /// out of its namespace.
    #[test]
    fn an_invocation_is_named_by_an_unambiguous_digest() {
        assert_ne!(record_key("a:b", "c", None), record_key("a", "b:c", None));
        assert_ne!(marker_key("a:b", "c", None), marker_key("a", "b:c", None));
        assert_ne!(record_key("a", "k", None), marker_key("a", "k", None));
        assert_eq!(record_key("a", "k", None), record_key("a", "k", None), "stable across deliveries");
        // A scope is part of the name, and an empty scope is not "no scope".
        assert_ne!(record_key("a", "k", Some("alice")), record_key("a", "k", Some("bob")));
        assert_ne!(record_key("a", "k", Some("")), record_key("a", "k", None));
        let longest = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
        for key in ["../../tagv/t", "k\u{0}x", longest.as_str()] {
            let record = String::from_utf8(record_key("place-order", key, Some("s"))).unwrap();
            let digest = record.strip_prefix("act:r:").expect("fixed prefix");
            assert_eq!(digest.len(), 64, "{record}");
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()), "{record}");
        }
    }

    /// An in-memory [`RecordRead`] whose reads complete immediately.
    #[derive(Default)]
    struct Memory(BTreeMap<Vec<u8>, Vec<u8>>);

    impl RecordRead for Memory {
        fn read(
            &mut self,
            key: &[u8],
        ) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send {
            std::future::ready(Ok(self.0.get(key).cloned()))
        }
    }

    /// Drive a future whose every await is already ready.
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("the in-memory store never pends"),
        }
    }

    fn envelope_bytes(result: &str) -> Vec<u8> {
        serde_json::to_vec(&ActionEnvelope::ok(serde_json::json!(result), Vec::new(), None)).unwrap()
    }

    /// A reply recorded by the previous runtime, under the undigested
    /// `act:r:{id}:{key}`, is still found, so a retry that spans the upgrade
    /// replays it instead of running the action a second time.
    #[test]
    fn a_retry_across_the_key_format_upgrade_replays_the_legacy_record() {
        let mut store = Memory::default();
        store
            .0
            .insert(b"act:r:place-order:3f1c-legacy-key".to_vec(), envelope_bytes("legacy"));
        let found = ready(recorded(&mut store, "place-order", "3f1c-legacy-key", None)).unwrap();
        assert_eq!(found.expect("the legacy record").result, "legacy");
        let scoped = ready(recorded(&mut store, "place-order", "3f1c-legacy-key", Some("alice"))).unwrap();
        assert!(scoped.is_some(), "a pre-upgrade record predates scoping and is found for any caller");
        assert!(ready(recorded(&mut store, "place-order", "other-key", None)).unwrap().is_none());
        // A current record wins over a legacy one for the same invocation.
        store.0.insert(record_key("place-order", "3f1c-legacy-key", None), envelope_bytes("current"));
        let found = ready(recorded(&mut store, "place-order", "3f1c-legacy-key", None)).unwrap();
        assert_eq!(found.expect("the current record").result, "current");
    }

    /// F489: with a scope, a recorded reply is replayed only to its owner;
    /// another caller presenting the same key finds nothing to replay.
    #[test]
    fn a_scoped_record_is_replayed_only_to_its_owner() {
        let mut store = Memory::default();
        store.0.insert(record_key("transfer", "k-1", Some("alice")), envelope_bytes("alice's receipt"));
        let own = ready(recorded(&mut store, "transfer", "k-1", Some("alice"))).unwrap();
        assert_eq!(own.expect("the owner's record").result, "alice's receipt");
        assert!(ready(recorded(&mut store, "transfer", "k-1", Some("bob"))).unwrap().is_none());
        assert!(ready(recorded(&mut store, "transfer", "k-1", None)).unwrap().is_none());
    }
}
