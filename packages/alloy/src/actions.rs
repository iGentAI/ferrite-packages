//! **Replay-safe mutations.**
//!
//! The gateway hedges an in-flight request up to three times and hedging is
//! method-blind, so a POST can genuinely be delivered more than once. An
//! action that is not replay-safe therefore double-charges a customer in
//! production, not in theory. Alloy makes replay safety mandatory rather than
//! optional: every action carries an idempotency key and a durable result
//! record, and a replay returns the FIRST admitted answer instead of
//! re-deriving one.
//!
//! # The guarantee is per effect class
//!
//! An APE marker committed atomically with the effect is exact only when the
//! effect is *in that envelope*. Actions touch other planes, so the framework
//! provides all four shapes and names which one applies:
//!
//! | Effect class | Mechanism | Guarantee |
//! |---|---|---|
//! | APE writes (≤62 keys + marker + guard) | marker rides the same envelope | **Exactly-once**, genuinely atomic |
//! | Store writes | the written value carries an [`ActionStamp`] | **Effectively-once**, race-safe |
//! | Blob writes | the key IS the digest | Naturally idempotent |
//! | Queue / egress / notification | [`OutboxIntent`] committed with the marker, drained after | At-least-once, idempotency key carried |
//!
//! # Why a store CAS cannot be guarded by reading the marker first
//!
//! Store and APE commit independently. A crash between a store CAS and its
//! APE marker leaves the write applied and unrecorded; the retry re-reads,
//! sees a version it did not expect, and **cannot tell whether it was itself
//! that wrote it**. Reading the marker first does not help — the gap is
//! between the two planes, not before them.
//!
//! The stamp answers the question from the value itself: the writer records
//! its own action id INSIDE the written value, so a retry that finds its own
//! id knows the write already landed and stops. That is what makes the store
//! path effectively-once rather than merely at-least-once.

use ferrite_app::client::{ApeClusterClient, StoreClusterClient};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};
use crate::alloy::tags::{decode_epoch, encode_epoch, tag_key, MAX_TAGS_PER_ADVANCE, VERSION_KEY};

/// The namespace action markers live under, disjoint from the tag namespace
/// and from the version guard.
pub const MARKER_PREFIX: &str = "act/";

/// The namespace outbox records live under, disjoint from every other.
pub const OUTBOX_PREFIX: &str = "outbox/";

/// How many times a guarded action commit retries before reporting conflict.
const MAX_ATTEMPTS: u32 = 8;

/// The digest identifying one action invocation.
///
/// Both halves are **length-prefixed** before hashing, so the pair
/// `(action, idempotency_key)` maps injectively onto the digest. Simple
/// concatenation does not: `("a:b", "c")` and `("a", "b:c")` both flatten to
/// `a:b:c`, and two unrelated invocations would then share a marker and an
/// outbox namespace — one silently answering with the other's result.
///
/// Hashing also means neither half can steer the key: an action named
/// `../../tagv/t` or an idempotency key full of slashes still yields 64 hex
/// characters under a fixed prefix, so no caller-supplied text can escape
/// its namespace or forge a tag or version key.
pub fn invocation_digest(action: &str, idempotency_key: &str) -> String {
    let mut material = Vec::with_capacity(action.len() + idempotency_key.len() + 16);
    crate::alloy::app::push_part(&mut material, action.as_bytes());
    crate::alloy::app::push_part(&mut material, idempotency_key.as_bytes());
    ferrite_app::crypto::hex(&ferrite_app::crypto::sha256(&material))
}

/// The marker key for one action invocation.
pub fn marker_key(action: &str, idempotency_key: &str) -> String {
    format!(
        "{MARKER_PREFIX}{}",
        invocation_digest(action, idempotency_key)
    )
}

/// The key the `i`th outbox record of one invocation lives under.
pub fn outbox_key(action: &str, idempotency_key: &str, i: usize) -> String {
    format!(
        "{OUTBOX_PREFIX}{}/{i}",
        invocation_digest(action, idempotency_key)
    )
}

/// The durable record one admitted action leaves behind.
///
/// It carries the action's own identity so a retry can recognise its OWN
/// earlier commit — the distinction a bare "key exists" check cannot make,
/// and the reason a guard mismatch alone is not a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionRecord {
    /// The action name.
    pub action: String,
    /// The caller's idempotency key: the identity a replay matches on.
    pub idempotency_key: String,
    /// When the first admission committed (epoch ms).
    pub at_ms: u64,
    /// The admitted result, as the action returned it.
    pub result: serde_json::Value,
    /// The tag epochs this action advanced, so a replay returns the same
    /// client invalidation set the original did.
    pub advanced: Vec<(String, u64)>,
}

impl ActionRecord {
    /// Encode for the marker cell.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AlloyError::internal(e.to_string()))
    }

    /// Decode a marker cell.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// A store value that records which action last wrote it.
///
/// This is the effectively-once mechanism for the store plane. The stamp is
/// part of the VALUE, so it survives exactly as long as the write does and a
/// retry can read it back without consulting another plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionStamp<T> {
    /// The application value.
    pub value: T,
    /// The action invocation that last wrote it (`{action}:{idempotency}`).
    pub last_action_id: String,
}

impl<T> ActionStamp<T> {
    /// Stamp a value with an action identity.
    pub fn new(value: T, action_id: impl Into<String>) -> Self {
        Self {
            value,
            last_action_id: action_id.into(),
        }
    }
}

/// The identity of one action invocation.
///
/// It is the injective [`invocation_digest`] of the pair, never the two
/// halves joined by a colon: `("order", "cancel:k1")` and
/// `("order:cancel", "k1")` are distinct invocations and must not share a
/// stamp, an outbox key or a notification dedup key. The digest is also
/// fixed-width hex, so it is always valid header material.
pub fn action_id(action: &str, idempotency_key: &str) -> String {
    invocation_digest(action, idempotency_key)
}

/// What one effect class needs performed after the guarded commit.
///
/// The intent commits atomically WITH the marker; a drain step performs it
/// and records completion. So the far side may see it more than once — which
/// is why the idempotency key travels with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    crate = "ferrite_app::serde",
    tag = "effect",
    rename_all = "snake_case"
)]
pub enum OutboxIntent {
    /// Publish onto a queue handle.
    Publish {
        /// The injected queue handle name.
        handle: String,
        /// The payload.
        payload: Vec<u8>,
        /// Absolute epoch-ms delivery gate, or 0 for immediate.
        not_before_ms: u64,
    },
    /// Make an outbound call through a declared egress handle.
    Egress {
        /// The injected egress handle name.
        handle: String,
        /// The destination URL (must sit under a declared prefix).
        url: String,
        /// The request body.
        body: Vec<u8>,
    },
    /// Emit an owner notification.
    Notify {
        /// `info` | `warn` | `error`.
        severity: String,
        /// The notification kind.
        kind: String,
        /// The body.
        body: String,
    },
}

/// One outbox record: the intent plus the identity that must reach the far
/// side so a duplicate delivery is recognisable there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct OutboxRecord {
    /// The action invocation that queued this effect.
    pub action_id: String,
    /// What to perform.
    pub intent: OutboxIntent,
}

/// The effects one action commits.
///
/// APE entries ride the action's own envelope and are therefore exactly-once.
/// Everything else is recorded as an [`OutboxRecord`] in that same envelope
/// and performed afterwards.
#[derive(Debug, Clone, Default)]
pub struct Effects {
    ape_entries: Vec<(Vec<u8>, Vec<u8>)>,
    outbox: Vec<OutboxIntent>,
    tags: Vec<String>,
}

impl Effects {
    /// No effects.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write one APE key inside the action's atomic envelope.
    pub fn ape(mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.ape_entries.push((key.into(), value.into()));
        self
    }

    /// Queue a cross-plane effect for the outbox drain.
    pub fn outbox(mut self, intent: OutboxIntent) -> Self {
        self.outbox.push(intent);
        self
    }

    /// Advance a tag when this action commits.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }

    /// Advance several tags.
    pub fn tags(mut self, tags: &[String]) -> Self {
        for t in tags {
            self = self.tag(t.clone());
        }
        self
    }

    /// The tags this action will advance.
    pub fn declared_tags(&self) -> &[String] {
        &self.tags
    }

    /// The queued cross-plane intents.
    pub fn intents(&self) -> &[OutboxIntent] {
        &self.outbox
    }
}

/// The outcome of running an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The admitted result.
    pub result: serde_json::Value,
    /// `(tag, new epoch)` for every tag advanced — the client invalidation
    /// set, returned so no extra round trip is needed.
    pub advanced: Vec<(String, u64)>,
    /// Whether this call performed the effect (`false` = a replay answered
    /// from the durable record).
    pub first_admission: bool,
}

/// Runs actions against an injected APE handle, enforcing replay safety.
pub struct ActionRunner {
    ape: ApeClusterClient,
}

/// One action invocation: its name, its idempotency key and the clock.
pub struct Invocation {
    pub name: &'static str,
    pub idem: String,
    pub now_ms: u64,
}

impl Invocation {
    /// The action id written into records this invocation touches.
    pub fn action_id(&self) -> String {
        action_id(self.name, &self.idem)
    }
}

/// Run one action replay-safely against the `tags` APE handle: answer a
/// recorded admission if this invocation already committed, otherwise run
/// `core` and commit its result with exactly `declared_tags`.
pub async fn perform<O, F, Fut>(
    ctx: &ferrite_app::AppContext,
    name: &'static str,
    idem: String,
    declared_tags: &[&str],
    is_declared: crate::alloy::tags::TagDeclared,
    core: F,
) -> Result<Admitted>
where
    O: Serialize,
    F: FnOnce(Invocation) -> Fut,
    Fut: std::future::Future<Output = Result<O>>,
{
    let mut runner = ActionRunner::new(ctx.ape("tags")?);
    if let Some(existing) = runner.recorded(name, &idem).await? {
        return Ok(Admitted {
            result: existing.result,
            advanced: existing.advanced,
            first_admission: false,
        });
    }
    let inv = Invocation {
        name,
        idem: idem.clone(),
        now_ms: ctx.now_ms(),
    };
    let out = core(inv).await?;
    crate::alloy::tags::check_declared(is_declared, name, declared_tags)?;
    let tags: Vec<String> = declared_tags.iter().map(|t| t.to_string()).collect();
    let effects = Effects::new().tags(&tags);
    // NOT `loader_value`: this runs AFTER the store writes landed, so a new
    // failure path here would strand a committed effect unrecorded.
    let result = serde_json::to_value(&out).unwrap_or_default();
    runner
        .commit(name, &idem, &effects, result, ctx.now_ms())
        .await
}

impl ActionRunner {
    /// Wrap an injected APE client (the plane holding tag epochs and markers).
    pub fn new(ape: ApeClusterClient) -> Self {
        Self { ape }
    }

    /// Read an existing admission for this action invocation, if any.
    pub async fn recorded(
        &mut self,
        action: &str,
        idempotency_key: &str,
    ) -> Result<Option<ActionRecord>> {
        let key = marker_key(action, idempotency_key);
        let Some(bytes) = self.ape.get(key.as_bytes()).await? else {
            return Ok(None);
        };
        // The cell EXISTS, so this invocation was already admitted — its effect
        // has been applied and its tags advanced. We just cannot recover what
        // it answered. Reporting `None` here would send the caller down the
        // commit path and apply the effect a second time, which is precisely
        // the failure this module exists to prevent. Fail closed instead.
        ActionRecord::decode(&bytes).map(Some).ok_or_else(|| {
            AlloyError::conflict(
                "this action's durable result record cannot be decoded; refusing to \
                 re-apply an effect that has already been admitted",
            )
        })
    }

    /// Commit an action with [`commit`](Self::commit) and answer with its first
    /// admitted result and the epochs it advanced.
    pub async fn commit_reply<T: Serialize>(
        &mut self,
        req: &ferrite_app::IngressRequest,
        action: &str,
        idempotency_key: &str,
        effects: &Effects,
        result: &T,
        now_ms: u64,
    ) -> Result<ferrite_app::IngressReply> {
        let admitted = self
            .commit(
                action,
                idempotency_key,
                effects,
                // NOT `loader_value` here, deliberately. This runs AFTER the
                // action's effect has already landed in the store, so a new
                // failure path at this point would return an error without
                // recording the idempotency marker — stranding a committed
                // effect and inviting a retry to repeat it. The place to refuse
                // a non-finite action result is the GENERATOR, before anything
                // runs.
                serde_json::to_value(result).unwrap_or_default(),
                now_ms,
            )
            .await?;
        Ok(replay_reply(req, &admitted.result, &admitted.advanced))
    }

    /// Commit an action: its effects, its tag advances, and its marker, in
    /// ONE atomic envelope guarded on the tag-table version.
    ///
    /// The marker is re-checked on every attempt of the guarded loop, not
    /// only before it. Two concurrent deliveries of the same request both
    /// observe an absent marker, but only one wins the version guard; the
    /// loser re-reads, now SEES the winner's marker, recognises the shared
    /// identity, and returns the admitted result instead of applying the
    /// effect a second time. Checking only before the loop would let the
    /// loser retry and commit again.
    pub async fn commit(
        &mut self,
        action: &str,
        idempotency_key: &str,
        effects: &Effects,
        result: serde_json::Value,
        now_ms: u64,
    ) -> Result<Admitted> {
        let id = action_id(action, idempotency_key);
        let mkey = marker_key(action, idempotency_key);
        let tag_keys: Vec<String> = effects.tags.iter().map(|t| tag_key(t)).collect();

        // Discovery rides THIS envelope. `ApeClusterClient` has no prefix
        // scan, so an intent committed without its index entry would be
        // durable and permanently invisible — nothing could ever find it.
        // Publishing a wake-up after the commit would not do: a crash in
        // between would strand the intent forever. The index entry and the
        // records it points at therefore land together or not at all.
        let digest = invocation_digest(action, idempotency_key);
        let shard_key = crate::alloy::outbox::shard_key(crate::alloy::outbox::shard_of(&digest));
        let indexed = !effects.outbox.is_empty();

        if effects.outbox.len() > crate::alloy::outbox::MAX_INTENTS_PER_ACTION {
            return Err(AlloyError::bad_request(format!(
                "an action commits at most {} outbox intents (got {})",
                crate::alloy::outbox::MAX_INTENTS_PER_ACTION,
                effects.outbox.len()
            )));
        }

        // The envelope holds: the version guard + the marker + one entry per
        // tag + the action's own APE entries + one outbox record per intent
        // + the pending-index entry that makes those records discoverable.
        let budget = 1
            + tag_keys.len()
            + effects.ape_entries.len()
            + effects.outbox.len()
            + usize::from(indexed);
        if budget > MAX_TAGS_PER_ADVANCE {
            return Err(AlloyError::bad_request(format!(
                "an action commits at most {MAX_TAGS_PER_ADVANCE} entries beside the version guard (got {} tags, {} APE writes and {} outbox intents)",
                tag_keys.len(),
                effects.ape_entries.len(),
                effects.outbox.len()
            )));
        }

        // An APE envelope applies its entries as a set: two entries naming
        // one key make the winner an implementation detail. Every key this
        // method contributes is part of the replay protocol — the version
        // guard, the marker, the tag epochs, the outbox records — so an
        // effect key that lands on one of them could overwrite the marker
        // that makes the action replay-safe, or forge a tag epoch, inside
        // the very envelope that is supposed to guarantee them. The keys are
        // all deterministic, so this is checked ONCE, before the retry loop.
        let outbox_keys: Vec<String> = (0..effects.outbox.len())
            .map(|i| outbox_key(action, idempotency_key, i))
            .collect();
        let mut seen: Vec<&[u8]> = Vec::with_capacity(budget + 1);
        seen.push(VERSION_KEY.as_bytes());
        seen.push(mkey.as_bytes());
        if indexed {
            seen.push(shard_key.as_bytes());
        }
        for k in &tag_keys {
            seen.push(k.as_bytes());
        }
        for k in &outbox_keys {
            seen.push(k.as_bytes());
        }
        for (key, _) in &effects.ape_entries {
            // The framework's own namespaces on the shared plane (replay markers,
            // tag epochs, outbox records, saga phases) are never an effect's to write.
            let reserved = [
                MARKER_PREFIX,
                OUTBOX_PREFIX,
                crate::alloy::tags::TAG_PREFIX,
                crate::alloy::tags::VERSION_KEY,
                crate::alloy::saga::SAGA_PREFIX,
                "tagv/",
            ];
            if key.is_empty() || reserved.iter().any(|prefix| key.starts_with(prefix.as_bytes())) {
                return Err(AlloyError::bad_request(format!(
                    "action effect key '{}' is empty or in a namespace the framework reserves",
                    String::from_utf8_lossy(key)
                )));
            }
            if seen.contains(&key.as_slice()) {
                return Err(AlloyError::bad_request(format!(
                    "action effect key '{}' collides with a key this action already commits \
                     (the version guard, the replay marker, a tag epoch, an outbox record, \
                     or another effect entry)",
                    String::from_utf8_lossy(key)
                )));
            }
            seen.push(key.as_slice());
        }

        for _ in 0..MAX_ATTEMPTS {
            // Re-read the marker EVERY attempt: a concurrent delivery of this
            // same request may have committed since the last one.
            if let Some(existing) = self.recorded(action, idempotency_key).await? {
                if existing.idempotency_key == idempotency_key && existing.action == action {
                    return Ok(Admitted {
                        result: existing.result,
                        advanced: existing.advanced,
                        first_admission: false,
                    });
                }
                // The same marker cell naming a different invocation is a
                // genuine collision, not a replay: refuse rather than
                // overwrite someone else's admitted effect.
                return Err(AlloyError::conflict(
                    "this idempotency key is already held by a different action invocation",
                ));
            }

            let version = self.ape.get(VERSION_KEY.as_bytes()).await?;
            let current = if tag_keys.is_empty() {
                Vec::new()
            } else {
                let refs: Vec<&[u8]> = tag_keys.iter().map(|k| k.as_bytes()).collect();
                let read = self.ape.multi_get(&refs).await?;
                // A short read would drop trailing tag advances through the zip below.
                if read.len() != tag_keys.len() {
                    return Err(AlloyError::internal(format!(
                        "tag epoch read returned {} values for {} tags",
                        read.len(),
                        tag_keys.len()
                    )));
                }
                read
            };

            let next_version = encode_epoch(decode_epoch(version.as_ref()).wrapping_add(1));
            let next_epochs: Vec<u64> = current
                .iter()
                .map(|v| decode_epoch(v.as_ref()).wrapping_add(1))
                .collect();
            let encoded: Vec<Vec<u8>> = next_epochs.iter().map(|e| encode_epoch(*e)).collect();
            let advanced: Vec<(String, u64)> = effects
                .tags
                .iter()
                .cloned()
                .zip(next_epochs.iter().copied())
                .collect();

            let record = ActionRecord {
                action: action.to_string(),
                idempotency_key: idempotency_key.to_string(),
                at_ms: now_ms,
                result: result.clone(),
                advanced: advanced.clone(),
            };
            let record_bytes = record.encode()?;

            // Outbox records ride the same envelope as the marker, so an
            // intent cannot exist without its action having been admitted,
            // and an admitted action cannot lose its intents.
            let outbox_values: Vec<Vec<u8>> = effects
                .outbox
                .iter()
                .map(|intent| {
                    let rec = OutboxRecord {
                        action_id: id.clone(),
                        intent: intent.clone(),
                    };
                    serde_json::to_vec(&rec).map_err(|e| AlloyError::internal(e.to_string()))
                })
                .collect::<Result<Vec<_>>>()?;

            let mut entries: Vec<(&[u8], &[u8])> = Vec::with_capacity(budget + 1);
            entries.push((VERSION_KEY.as_bytes(), next_version.as_slice()));
            entries.push((mkey.as_bytes(), record_bytes.as_slice()));
            // Re-read the shard EVERY attempt: a concurrent action may have
            // indexed a digest since the last one, and the pending list is
            // rewritten whole rather than appended to.
            let shard_bytes = if indexed {
                let cell = self.ape.get(shard_key.as_bytes()).await?;
                let pending = crate::alloy::outbox::decode_pending(cell.as_ref());
                if pending.len() >= crate::alloy::outbox::MAX_PENDING_PER_SHARD
                    && !pending.iter().any(|d| d == &digest)
                {
                    // A backlog only grows while the drain is down. Refusing
                    // the mutation is the honest answer: a refused action is
                    // retryable, whereas an admitted action whose intent the
                    // index could not carry is an effect lost silently.
                    return Err(AlloyError::conflict(
                        "the outbox backlog is saturated; retry once the drain has caught up",
                    ));
                }
                crate::alloy::outbox::pending_add(&pending, &digest)
                    .map(|list| crate::alloy::outbox::encode_pending(&list))
            } else {
                None
            };
            if let Some(bytes) = shard_bytes.as_ref() {
                entries.push((shard_key.as_bytes(), bytes.as_slice()));
            }
            for (k, v) in tag_keys.iter().zip(encoded.iter()) {
                entries.push((k.as_bytes(), v.as_slice()));
            }
            for (k, v) in &effects.ape_entries {
                entries.push((k.as_slice(), v.as_slice()));
            }
            for (k, v) in outbox_keys.iter().zip(outbox_values.iter()) {
                entries.push((k.as_bytes(), v.as_slice()));
            }

            let committed = self
                .ape
                .commit_n_if(VERSION_KEY.as_bytes(), version.as_deref(), &entries)
                .await?;
            if committed.is_ok() {
                return Ok(Admitted {
                    result,
                    advanced,
                    first_admission: true,
                });
            }
            // Nothing was written. The next attempt re-reads the marker first,
            // which is what turns a lost race into a recognised replay rather
            // than a second application.
        }
        Err(AlloyError::conflict(
            "the action plane is under sustained contention; retry the request",
        ))
    }

    /// The underlying APE handle.
    pub fn ape_mut(&mut self) -> &mut ApeClusterClient {
        &mut self.ape
    }
}

/// Write a stamped value to the store, effectively-once.
///
/// Returns `true` when this call performed the write and `false` when the
/// stamp shows this same action invocation already did. The CAS is what makes
/// it race-safe: a concurrent writer that moved the version loses, re-reads,
/// and re-decides on fresh state.
pub async fn put_stamped<T>(
    store: &mut StoreClusterClient,
    key: &[u8],
    value: &T,
    action_id: &str,
) -> Result<bool>
where
    T: Serialize,
{
    for _ in 0..MAX_ATTEMPTS {
        let existing = store.get_versioned(key).await?;
        if let Some((bytes, _)) = &existing {
            if let Ok(prev) = serde_json::from_slice::<ActionStamp<serde_json::Value>>(bytes) {
                if prev.last_action_id == action_id {
                    // This invocation already wrote this key. A crash between
                    // the CAS and the marker cannot make us write twice,
                    // because the value itself remembers who wrote it.
                    return Ok(false);
                }
            }
        }
        let stamped = ActionStamp {
            value,
            last_action_id: action_id.to_string(),
        };
        let bytes =
            serde_json::to_vec(&stamped).map_err(|e| AlloyError::internal(e.to_string()))?;
        let expected = existing.as_ref().map(|(_, v)| *v);
        match store.put_if_version(key, &bytes, expected).await? {
            Ok(_) => return Ok(true),
            Err(_) => continue,
        }
    }
    Err(AlloyError::conflict(
        "this key is under sustained write contention; retry the request",
    ))
}

/// Decode an action's JSON request body, answering with a 400 on malformed input.
pub fn decode_input<T: ferrite_app::serde::de::DeserializeOwned>(
    req: &ferrite_app::IngressRequest,
) -> Result<T> {
    serde_json::from_slice(&req.body)
        .map_err(|e| AlloyError::bad_request(format!("invalid action input: {e}")))
}

/// The reply a replayed delivery answers with: the first admitted result and
/// the tag epochs its admission advanced.
pub fn replay_reply(
    req: &ferrite_app::IngressRequest,
    result: &serde_json::Value,
    advanced: &[(String, u64)],
) -> ferrite_app::IngressReply {
    crate::alloy::app::json_reply(
        req,
        200,
        &serde_json::json!({ "result": result, "advanced": advanced }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_keys_separate_actions_from_their_idempotency_keys() {
        let a = marker_key("toggle_repost", "k1");
        let b = marker_key("toggle_repost", "k2");
        let c = marker_key("delete_drop", "k1");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, marker_key("toggle_repost", "k1"));
        // The key is a fixed-width digest under a fixed prefix: neither half
        // of the invocation appears verbatim, so neither can steer the key.
        assert!(a.starts_with(MARKER_PREFIX));
        assert_eq!(a.len(), MARKER_PREFIX.len() + 64);
        assert!(!a.contains("toggle_repost"));
    }

    #[test]
    fn ambiguous_action_and_idempotency_pairs_never_share_a_key() {
        // Plain concatenation flattens BOTH of these to "a:b:c", so the two
        // unrelated invocations would share a marker and an outbox namespace
        // and one would silently answer with the other's result.
        assert_ne!(marker_key("a:b", "c"), marker_key("a", "b:c"));
        assert_ne!(outbox_key("a:b", "c", 0), outbox_key("a", "b:c", 0));
        assert_ne!(marker_key("", "ab"), marker_key("a", "b"));
    }

    #[test]
    fn outbox_keys_are_namespaced_indexed_and_distinct_from_markers() {
        let k0 = outbox_key("a", "k", 0);
        let k1 = outbox_key("a", "k", 1);
        assert!(k0.starts_with(OUTBOX_PREFIX));
        assert_ne!(k0, k1);
        assert_ne!(k0, marker_key("a", "k"));
        assert!(!k0.starts_with("tagv/"));
        assert_ne!(k0, VERSION_KEY);
    }

    #[test]
    fn action_records_round_trip() {
        let r = ActionRecord {
            action: "toggle_repost".into(),
            idempotency_key: "abc".into(),
            at_ms: 42,
            result: serde_json::json!({ "reposted": true }),
            advanced: vec![("drop-1".into(), 3)],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(ActionRecord::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn a_corrupt_marker_decodes_to_none() {
        assert!(ActionRecord::decode(b"not json").is_none());
        assert!(ActionRecord::decode(b"{}").is_none());
    }

    #[test]
    fn effects_deduplicate_tags() {
        let e = Effects::new()
            .tag("drops")
            .tag("drop-1")
            .tag("drops")
            .tags(&["drop-1".into(), "users".into()]);
        assert_eq!(e.declared_tags(), &["drops", "drop-1", "users"]);
    }

    #[test]
    fn an_action_id_names_both_halves() {
        assert_eq!(action_id("a", "k"), invocation_digest("a", "k"));
        // finding_d555a9080c4047be: a colon cannot move between the halves.
        assert_ne!(action_id("order", "cancel:k1"), action_id("order:cancel", "k1"));
        let id = action_id("a\r\n", "k");
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn outbox_records_round_trip_every_intent_shape() {
        let intents = vec![
            OutboxIntent::Publish {
                handle: "jobs".into(),
                payload: b"x".to_vec(),
                not_before_ms: 0,
            },
            OutboxIntent::Egress {
                handle: "stripe".into(),
                url: "https://api.stripe.com/v1/charges".into(),
                body: b"{}".to_vec(),
            },
            OutboxIntent::Notify {
                severity: "warn".into(),
                kind: "payment.failed".into(),
                body: "card declined".into(),
            },
        ];
        for intent in intents {
            let rec = OutboxRecord {
                action_id: "a:k".into(),
                intent: intent.clone(),
            };
            let bytes = serde_json::to_vec(&rec).unwrap();
            let back: OutboxRecord = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(back.intent, intent);
            assert_eq!(back.action_id, "a:k");
        }
    }
}
