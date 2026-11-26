//! **The outbox drain**: performing the cross-plane effects an action
//! committed durably.
//!
//! [`crate::alloy::actions`] already commits an [`OutboxRecord`] inside the
//! SAME guarded APE envelope as the action's replay marker, so an intent
//! cannot exist without its action having been admitted, and an admitted
//! action cannot lose its intents. Nothing performed them. This module is
//! the consumer that does.
//!
//! # Discovery cannot ride a queue signal
//!
//! `ApeClusterClient` offers `get`, `multi_get`, `commit`, `commit_n` and
//! `commit_n_if` — and **no prefix scan**. So the drain cannot enumerate the
//! `outbox/` namespace, and publishing a wake-up onto a queue AFTER the
//! action commits is a second plane: a crash in between would leave a
//! durable intent that nothing ever discovers. The record would sit in APE
//! forever, admitted and unperformed.
//!
//! Discovery therefore rides the action's own envelope. The commit that
//! writes the marker, the tag epochs and the outbox records ALSO updates a
//! pending index:
//!
//! ```text
//! APE   outbox/pending/{shard}      -> newline-separated digests
//! APE   outbox/{digest}/{i}         -> the OutboxRecord
//! APE   outbox/done/{digest}/{i}    -> the completion record
//! ```
//!
//! `shard` is a fixed function of the digest, so the key set is finite and
//! known at compile time: the drain finds work with ONE `multi_get` over
//! [`PENDING_SHARDS`] keys. An intent and its discoverability commit
//! together or not at all.
//!
//! A queue wake-up may still be published as a latency optimisation, but it
//! is not the discovery path: a lost signal costs the delay until the next
//! poll, and cannot cost the effect.
//!
//! # The guarantee is at-least-once, deliberately
//!
//! The drain performs an external effect and then records completion, and
//! those are two different planes: a crash in between leaves the effect
//! performed and unrecorded, and the redelivery performs it a second time.
//! Recording first would be worse — it would mark an effect complete that
//! never happened, and no retry could discover it.
//!
//! So the order is deliberate, and the guarantee is exactly what the record
//! carries: **at-least-once, with the action's idempotency key travelling to
//! the far side** so a duplicate is recognisable there. That is why
//! [`OutboxRecord`] carries `action_id` rather than leaving the far side to
//! guess.

use ferrite_app::client::{ApeClusterClient, StoreClusterClient};
use ferrite_app::serde_json;
use ferrite_app::tracing;
use ferrite_app::AppContext;

use crate::alloy::actions::{OutboxIntent, OutboxRecord, OUTBOX_PREFIX};
use crate::alloy::error::{AlloyError, Result};

/// How many pending-index shards the drain polls.
///
/// The set is FIXED and small, because it is the only way work is
/// discovered: `multi_get` over these keys replaces the prefix scan APE
/// does not offer. Sixteen also bounds drain concurrency, since a consumer
/// holds one shard lease at a time.
pub const PENDING_SHARDS: usize = 16;

/// The namespace the pending index lives under.
pub const PENDING_PREFIX: &str = "outbox/pending/";

/// The namespace completion records live under.
pub const DONE_PREFIX: &str = "outbox/done/";

/// The namespace quarantined records live under.
///
/// A record that cannot be decoded can never be performed, and leaving it
/// pending would block its digest — and therefore its shard — forever. But
/// marking it complete would convert corruption into a silently dropped
/// effect, which is the one thing this module exists to prevent. So it is
/// moved HERE instead: the raw bytes are preserved for recovery, the digest
/// drains, and the pass reports a quarantine an operator can act on.
pub const POISON_PREFIX: &str = "outbox/poison/";

/// The most intents one action may commit.
///
/// The envelope budget already bounds this far below 63; the constant is
/// what lets the drain read a digest's records with a bounded `multi_get`
/// rather than probing one key at a time.
pub const MAX_INTENTS_PER_ACTION: usize = 32;

/// The most digests one shard may hold before an action carrying intents is
/// refused.
///
/// A backlog only grows while the drain is down. When it saturates, the
/// honest answer is to REFUSE the mutation rather than admit it with an
/// effect the index cannot carry: a refused action is retryable, and an
/// admitted action whose intent was dropped is silently lost forever.
pub const MAX_PENDING_PER_SHARD: usize = 512;

/// How long a shard lease is held before it self-releases.
pub const DRAIN_LEASE_MS: u64 = 30_000;

/// The most records one pass performs before returning to its caller.
///
/// A drain shares the request loop, and an effect is a network call: an
/// unbounded pass over a large backlog would hold that loop for as long as
/// the backlog took to clear. The budget makes a pass's cost proportional
/// to this constant rather than to the backlog, so a burst drains over
/// several passes and the loop keeps polling between them.
///
/// Nothing is lost by stopping early. A record with no completion record
/// stays pending, its digest stays in the index, and the next pass resumes
/// exactly where this one stopped — the same property that makes a crashed
/// pass safe.
pub const MAX_RECORDS_PER_PASS: usize = 32;

/// The store namespace shard leases live under.
pub const LEASE_PREFIX: &str = "od/";

/// The shard a digest belongs to.
///
/// The first byte of the digest, which is uniform for SHA-256 output, so
/// the shards fill evenly without any coordination.
pub fn shard_of(digest: &str) -> usize {
    let byte = digest
        .get(0..2)
        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        .unwrap_or(0);
    usize::from(byte) % PENDING_SHARDS
}

/// The pending-index key for one shard.
pub fn shard_key(shard: usize) -> String {
    format!("{PENDING_PREFIX}{shard}")
}

/// The completion-record key for the `i`th record of one digest.
pub fn done_key(digest: &str, i: usize) -> String {
    format!("{DONE_PREFIX}{digest}/{i}")
}

/// The record key for the `i`th record of one digest.
///
/// This is the same layout [`crate::alloy::actions::outbox_key`] writes, but
/// derived from the DIGEST alone — the drain never learns the action name
/// or the idempotency key that produced it, and does not need to.
pub fn record_key(digest: &str, i: usize) -> String {
    format!("{OUTBOX_PREFIX}{digest}/{i}")
}

/// The quarantine key for the `i`th record of one digest.
pub fn poison_key(digest: &str, i: usize) -> String {
    format!("{POISON_PREFIX}{digest}/{i}")
}

/// The store key of one shard's drain lease.
///
/// Named distinctly from the cache's own refresh lease: both live in a
/// store plane, and a reader who confused them would be reasoning about
/// the wrong lock.
pub fn drain_lease_key(shard: usize) -> String {
    format!("{LEASE_PREFIX}{shard}")
}

/// Whether `s` is a well-formed invocation digest.
///
/// The index is parsed on every drain pass and on every action commit, so a
/// malformed line must be ignored rather than propagated: a corrupt entry
/// cannot be turned into a key that names anything, and refusing the whole
/// shard over one bad line would wedge every action in it.
pub fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Encode a pending list for the index cell.
pub fn encode_pending(digests: &[String]) -> Vec<u8> {
    digests.join("\n").into_bytes()
}

/// Decode a pending list, dropping anything malformed.
pub fn decode_pending(bytes: Option<&Vec<u8>>) -> Vec<String> {
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim();
        if is_digest(line) && !out.iter().any(|d| d == line) {
            out.push(line.to_string());
        }
    }
    out
}

/// Add `digest` to a shard's pending list, preserving order.
///
/// Returns the new list, or `None` when the digest is already present — in
/// which case the caller must NOT rewrite the cell, because a rewrite would
/// spend an envelope entry to change nothing.
pub fn pending_add(current: &[String], digest: &str) -> Option<Vec<String>> {
    if current.iter().any(|d| d == digest) {
        return None;
    }
    let mut next = current.to_vec();
    next.push(digest.to_string());
    Some(next)
}

/// Remove `digests` from a shard's pending list.
pub fn pending_remove(current: &[String], digests: &[String]) -> Vec<String> {
    current
        .iter()
        .filter(|d| !digests.iter().any(|done| &done == d))
        .cloned()
        .collect()
}

/// What one drain pass did, so an operator surface can report it and a test
/// can assert the path taken rather than merely the end state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Shards that held at least one pending digest.
    pub shards_with_work: usize,
    /// Shards skipped because another consumer holds the lease.
    pub shards_leased_elsewhere: usize,
    /// Records whose effect was performed by THIS pass.
    pub performed: usize,
    /// Records already carrying a completion record, so skipped.
    pub already_done: usize,
    /// Records whose effect failed and which stay pending for a retry.
    pub failed: usize,
    /// Records that could not be decoded and were quarantined unperformed.
    ///
    /// This is never expected to be non-zero. When it is, an effect the
    /// application committed will not happen until someone recovers the
    /// bytes from the quarantine namespace, so it is reported rather than
    /// folded into `performed`.
    pub quarantined: usize,
    /// Digests whose every record is complete and which left the index.
    pub completed: usize,
    /// Whether the pass stopped on its budget with work still pending.
    ///
    /// Not a failure: the caller is expected to come back. It is reported
    /// so an idle-detecting caller does not mistake a truncated pass for a
    /// drained outbox and wait before looking again.
    pub budget_exhausted: bool,
}

impl DrainReport {
    /// Whether this pass found nothing to do.
    pub fn is_idle(&self) -> bool {
        self.shards_with_work == 0
    }
}

/// The outbox consumer.
///
/// It holds its own plane handles rather than borrowing the request path's,
/// so a drain pass cannot interleave with a mutation's own reads.
pub struct OutboxDrain {
    ape: ApeClusterClient,
    leases: StoreClusterClient,
    /// Retirements still to fail (see [`OutboxDrain::fail_next_retirements`]).
    retire_faults: u32,
    /// The shard the next pass starts at. It rotates, so failing records at the
    /// head of one shard cannot spend every pass's budget before the others.
    next_shard: usize,
}

impl OutboxDrain {
    /// Bind the drain to the APE plane holding the outbox and a store plane
    /// for its shard leases.
    pub fn new(ape: ApeClusterClient, leases: StoreClusterClient) -> Self {
        Self {
            ape,
            leases,
            retire_faults: 0,
            next_shard: 0,
        }
    }

    /// Build a drain from the handles a Alloy application declares.
    pub fn from_context(ctx: &AppContext, ape: &str, store: &str) -> Result<Self> {
        Ok(Self::new(ctx.ape(ape)?, ctx.store(store)?))
    }

    /// Run one pass over every shard.
    ///
    /// This is the correctness path: it depends on no queue signal, so an
    /// intent committed by an action that then crashed before publishing a
    /// wake-up is still found here.
    pub async fn drain_once(&mut self, ctx: &AppContext, now_ms: u64) -> Result<DrainReport> {
        let keys: Vec<String> = (0..PENDING_SHARDS).map(shard_key).collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
        let cells = self.ape.multi_get(&refs).await?;

        let mut report = DrainReport::default();
        let mut budget = MAX_RECORDS_PER_PASS;
        let start = self.next_shard % PENDING_SHARDS;
        self.next_shard = (start + 1) % PENDING_SHARDS;
        for offset in 0..PENDING_SHARDS {
            let shard = (start + offset) % PENDING_SHARDS;
            let Some(cell) = cells.get(shard) else { continue };
            if budget == 0 {
                // Out of budget with shards still unexamined. Say so, so
                // the caller comes straight back rather than treating this
                // as a drained outbox.
                report.budget_exhausted = true;
                break;
            }
            let pending = decode_pending(cell.as_ref());
            if pending.is_empty() {
                continue;
            }
            report.shards_with_work += 1;

            // One consumer per shard at a time. The lease is bounded, so a
            // consumer killed mid-pass releases it by expiry rather than
            // wedging the shard for the life of the deployment.
            if !self.take_lease(shard, now_ms).await? {
                report.shards_leased_elsewhere += 1;
                continue;
            }

            let mut completed: Vec<String> = Vec::new();
            for digest in &pending {
                if budget == 0 {
                    report.budget_exhausted = true;
                    break;
                }
                match self
                    .drain_digest(ctx, digest, &mut report, &mut budget)
                    .await
                {
                    Ok(true) => completed.push(digest.clone()),
                    // A digest whose effect failed stays in the index. The
                    // pass continues to its siblings: one unreachable
                    // destination must not stall every other effect.
                    Ok(false) => {}
                    // A plane error reading or completing this digest is
                    // NOT success. Swallowing it would let the pass answer
                    // with a healthy report while durable work sat
                    // unperformed — the drain would look idle precisely
                    // when it was failing.
                    Err(e) => {
                        tracing::warn!(
                            target: "alloy::outbox",
                            digest = %digest,
                            error = %e,
                            "draining this digest failed; it stays pending for the next pass"
                        );
                        report.failed += 1;
                    }
                }
            }
            let retired = if completed.is_empty() {
                Ok(())
            } else {
                self.retire(shard, &completed).await
            };
            settle_retirement(&mut report, shard, completed.len(), retired);
            // Released whichever way the retirement went: a lease left held
            // after a failure would park this shard, with nobody working it,
            // for the rest of `DRAIN_LEASE_MS`.
            self.release_lease(shard).await;
        }
        Ok(report)
    }

    /// Perform every outstanding record of one digest, within `budget`.
    ///
    /// Returns whether the digest is now fully complete. A digest truncated
    /// by the budget reports `false`, so it stays indexed and resumes next
    /// pass.
    async fn drain_digest(
        &mut self,
        ctx: &AppContext,
        digest: &str,
        report: &mut DrainReport,
        budget: &mut usize,
    ) -> Result<bool> {
        let record_keys: Vec<String> = (0..MAX_INTENTS_PER_ACTION)
            .map(|i| record_key(digest, i))
            .collect();
        let refs: Vec<&[u8]> = record_keys.iter().map(|k| k.as_bytes()).collect();
        let cells = self.ape.multi_get(&refs).await?;

        // Records are written contiguously from zero, so the first absent
        // key ends the list. A digest with NO records is complete: it was
        // already drained and retired, or its records never existed, and
        // either way leaving it in the index would spin forever.
        let count = cells.iter().take_while(|c| c.is_some()).count();
        if count == 0 {
            return Ok(true);
        }

        let done_keys: Vec<String> = (0..count).map(|i| done_key(digest, i)).collect();
        let done_refs: Vec<&[u8]> = done_keys.iter().map(|k| k.as_bytes()).collect();
        let done = self.ape.multi_get(&done_refs).await?;

        let mut all = true;
        for i in 0..count {
            let is_done = done[i].as_ref().is_some_and(|cell| !cell.is_empty());
            if is_done {
                report.already_done += 1;
                continue;
            }
            if *budget == 0 {
                // Stopping here leaves this record pending and its digest
                // indexed, which is exactly the state a crashed pass would
                // leave. The next pass resumes at this index.
                report.budget_exhausted = true;
                return Ok(false);
            }
            let Some(bytes) = cells[i].as_ref() else {
                continue;
            };
            let Ok(record) = ferrite_app::serde_json::from_slice::<OutboxRecord>(bytes) else {
                // An undecodable record can never be performed, and leaving
                // it pending would block its digest — and so its shard —
                // forever. But marking it DONE would convert corruption
                // into a silently dropped effect, which is the one outcome
                // this module exists to prevent. Copy the raw bytes into
                // the quarantine namespace first, so the effect is
                // recoverable by hand, and report it.
                tracing::error!(
                    target: "alloy::outbox",
                    digest = %digest,
                    index = i,
                    "outbox record cannot be decoded; quarantining it unperformed"
                );
                self.quarantine(digest, i, bytes).await?;
                report.quarantined += 1;
                *budget -= 1;
                continue;
            };

            // The effect happens BEFORE its completion record, so a crash
            // between them repeats the effect rather than losing it.
            *budget -= 1;
            match perform(ctx, &record, i as usize).await {
                Ok(()) => {
                    self.mark_done(digest, i).await?;
                    report.performed += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "alloy::outbox",
                        digest = %digest,
                        index = i,
                        error = %e,
                        "outbox effect failed; it stays pending for a retry"
                    );
                    report.failed += 1;
                    all = false;
                }
            }
        }
        Ok(all)
    }

    /// Record that one effect has been performed.
    ///
    /// Value-idempotent: writing the same byte twice is the same commit, so
    /// a retry of this write costs nothing.
    async fn mark_done(&mut self, digest: &str, i: usize) -> Result<()> {
        let key = done_key(digest, i);
        self.ape.commit_n(&[(key.as_bytes(), b"1")]).await?;
        Ok(())
    }

    /// Move an undecodable record into the quarantine namespace.
    ///
    /// The raw bytes are preserved and the completion marker is written in
    /// ONE envelope, so the record cannot be retired without its evidence
    /// having been kept: a crash between the two would otherwise lose the
    /// very bytes an operator needs to replay the effect by hand.
    async fn quarantine(&mut self, digest: &str, i: usize, bytes: &[u8]) -> Result<()> {
        let poison = poison_key(digest, i);
        let done = done_key(digest, i);
        self.ape
            .commit_n(&[(poison.as_bytes(), bytes), (done.as_bytes(), b"poison")])
            .await?;
        Ok(())
    }

    /// Remove completed digests from a shard, guarded on the shard itself.
    ///
    /// The guard is the SHARD key rather than the tag-table version, so a
    /// retirement does not serialise against every unrelated action. An
    /// action committing to this shard between the read and the commit
    /// moves the cell, the guard mismatches, and this pass leaves the
    /// digests in place — they are re-examined next pass, find every record
    /// already done, and retire then. A benign extra pass, never a lost
    /// effect.
    async fn retire(&mut self, shard: usize, completed: &[String]) -> Result<()> {
        if self.retire_faults > 0 {
            self.retire_faults -= 1;
            return Err(AlloyError::conflict(
                "injected retirement failure (fail_next_retirements)",
            ));
        }
        let key = shard_key(shard);
        let mut current = self.ape.get(key.as_bytes()).await?;
        // A concurrent action may write the shard between the read and the commit:
        // retry against what it wrote, and report a failure rather than a retirement
        // that did not happen.
        for _ in 0..4 {
            let pending = decode_pending(current.as_ref());
            let next = pending_remove(&pending, completed);
            if next == pending {
                return Ok(());
            }
            let encoded = encode_pending(&next);
            match self
                .ape
                .commit_n_if(
                    key.as_bytes(),
                    current.as_deref(),
                    &[(key.as_bytes(), encoded.as_slice())],
                )
                .await?
            {
                Ok(()) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
        Err(AlloyError::conflict("the pending shard kept changing; its digests retire next pass"))
    }

    /// Take this shard's lease, or report that another consumer holds it.
    ///
    /// `expected = None` is create-if-absent, and an EXPIRED lease reads as
    /// absent — which is what makes the lock self-releasing when a holder
    /// dies mid-pass.
    async fn take_lease(&mut self, shard: usize, now_ms: u64) -> Result<bool> {
        let key = drain_lease_key(shard);
        let expires = now_ms.saturating_add(DRAIN_LEASE_MS);
        let taken = self
            .leases
            .put_if_version_expiring(key.as_bytes(), b"1", None, expires)
            .await?;
        Ok(taken.is_ok())
    }

    /// Release a shard lease.
    ///
    /// A failed release is not worth failing a completed pass over: the
    /// lease carries a TTL, so the cost is one delayed pass rather than a
    /// wedged shard.
    async fn release_lease(&mut self, shard: usize) {
        let _ = self.leases.delete(drain_lease_key(shard).as_bytes()).await;
    }

    /// The APE handle, for a caller that must inspect the outbox directly.
    pub fn ape_mut(&mut self) -> &mut ApeClusterClient {
        &mut self.ape
    }

    /// Make the next `n` shard retirements fail as a transient APE error
    /// would, before they touch the plane.
    ///
    /// For tests of the drain pass itself: a real plane gives no way to fail
    /// only the retirement write while the reads and completion records
    /// around it succeed, and that is the failure the pass must survive
    /// (release the shard's lease, go on to later shards). Nothing in the
    /// runtime calls it.
    #[doc(hidden)]
    pub fn fail_next_retirements(&mut self, n: u32) {
        self.retire_faults = n;
    }
}

/// Fold one shard's retirement into the pass report.
///
/// A failed retirement is a digest-level failure, not a pass-level one: every
/// completed digest simply stays indexed and retires on the next pass (where
/// it finds every record already done — see
/// `a_resurrected_digest_costs_a_pass_and_never_a_repeated_effect`). So the
/// failure is counted and logged, and the pass goes on to release this
/// shard's lease and drain the shards after it. Propagating it would strand
/// the lease for its full TTL, skip every later shard, and hand the pump an
/// error in place of the report it settles on.
fn settle_retirement(
    report: &mut DrainReport,
    shard: usize,
    completed: usize,
    retired: Result<()>,
) {
    match retired {
        Ok(()) => report.completed += completed,
        Err(e) => {
            tracing::warn!(
                target: "alloy::outbox",
                shard,
                digests = completed,
                error = %e,
                "retiring completed digests failed; they stay indexed and retire next pass"
            );
            report.failed += 1;
        }
    }
}

/// Perform one intent against the application's declared handles.
///
/// Every shape carries the action's identity to the far side, because the
/// drain's guarantee is at-least-once: the receiver is the only place a
/// duplicate can finally be recognised.
async fn perform(ctx: &AppContext, record: &OutboxRecord, index: usize) -> Result<()> {
    match &record.intent {
        OutboxIntent::Publish {
            handle,
            payload,
            not_before_ms,
        } => {
            let mut queue = ctx.queue(handle)?;
            if *not_before_ms == 0 {
                queue.publish(payload).await?;
            } else {
                // The platform's own delayed-delivery primitive. This is
                // what makes a follow-up reminder a real occurrence rather
                // than a field nobody reads.
                queue.publish_at(payload, *not_before_ms).await?;
            }
            Ok(())
        }
        OutboxIntent::Egress { handle, url, body } => {
            let mut egress = ctx.egress(handle)?;
            let headers = [ferrite_app::EgressHeader {
                name: "idempotency-key".to_string(),
                value: intent_key(&record.action_id, index),
            }];
            let outcome = egress
                .deliver_http(ferrite_app::EgressHttpMethod::Post, url, &headers, body)
                .await?;
            match outcome {
                // A 5xx is a transient far-side failure and must be
                // retried; a 4xx is a definitive refusal that retrying
                // cannot fix, so it is recorded rather than spun on.
                ferrite_app::EgressOutcome::Delivered { status, .. } => {
                    if egress_status_is_transient(status) {
                        return Err(AlloyError::conflict(format!(
                            "egress to '{url}' answered {status}; the intent stays pending"
                        )));
                    }
                    Ok(())
                }
                // The gate refused the destination, which is a manifest
                // problem rather than a far-side one. It stays PENDING
                // deliberately: adding the destination to the app's
                // `egress` block makes the very same intent deliver on the
                // next pass. Marking it done would lose an effect the
                // application durably committed, for a fault that is
                // entirely recoverable.
                ferrite_app::EgressOutcome::Denied { reason } => Err(AlloyError::conflict(
                    format!("egress to '{url}' was denied ({reason}); declare it in ferrite.json"),
                )),
            }
        }
        OutboxIntent::Notify {
            severity,
            kind,
            body,
        } => {
            ctx.notify_deduped(severity, kind, body, &intent_key(&record.action_id, index))
                .await?;
            Ok(())
        }
    }
}

/// The far-side identity of intent `index` of one action invocation.
///
/// One action may commit several intents, and each is a distinct effect: a
/// shared key would let the receiver (or the notification feed's dedup)
/// collapse the second notification or POST into the first. Intent 0 keeps
/// the bare action id, so records committed before intents were numbered
/// keep the key they were first delivered under.
fn intent_key(action_id: &str, index: usize) -> String {
    if index == 0 {
        action_id.to_string()
    } else {
        format!("{action_id}:{index}")
    }
}

/// Whether an egress answer is a transient refusal the intent must outlive.
///
/// A 5xx is a far-side failure; 429 (rate limited) and 408 (timed out) are
/// explicit "try again later" answers. Every other 4xx is a definitive
/// refusal that retrying cannot fix.
fn egress_status_is_transient(status: u16) -> bool {
    status >= 500 || status == 429 || status == 408
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_intent_of_one_action_carries_its_own_far_side_key() {
        // finding_da2c2ed67ccfa6ad
        let id = "a".repeat(64);
        assert_eq!(intent_key(&id, 0), id);
        assert_ne!(intent_key(&id, 1), intent_key(&id, 0));
        assert_ne!(intent_key(&id, 1), intent_key(&id, 2));
    }

    #[test]
    fn rate_limited_and_timed_out_egress_stays_pending() {
        // finding_b87abfe297e94e0b
        assert!(egress_status_is_transient(429));
        assert!(egress_status_is_transient(408));
        assert!(egress_status_is_transient(503));
        assert!(!egress_status_is_transient(404));
        assert!(!egress_status_is_transient(409));
        assert!(!egress_status_is_transient(200));
    }

    fn digest(prefix: &str) -> String {
        let mut d = prefix.to_string();
        while d.len() < 64 {
            d.push('0');
        }
        d
    }

    #[test]
    fn a_digest_always_lands_in_a_real_shard() {
        for prefix in ["00", "0f", "7a", "ff", "a1"] {
            let s = shard_of(&digest(prefix));
            assert!(s < PENDING_SHARDS, "'{prefix}' shard {s} is out of range");
        }
        // The same digest always resolves to the same shard, or an action
        // would index into one shard and the drain look in another.
        assert_eq!(shard_of(&digest("7a")), shard_of(&digest("7a")));
        // A malformed digest still resolves rather than panicking.
        assert!(shard_of("") < PENDING_SHARDS);
        assert!(shard_of("zz") < PENDING_SHARDS);
        // …including one whose first bytes are not a char boundary.
        assert!(shard_of("é") < PENDING_SHARDS);
    }

    #[test]
    fn the_first_byte_spreads_digests_across_every_shard() {
        // An index that piled every digest into one shard would serialise
        // the whole application's effects behind a single lease.
        let mut seen = [false; PENDING_SHARDS];
        for byte in 0u16..256 {
            seen[shard_of(&digest(&format!("{byte:02x}")))] = true;
        }
        assert!(seen.iter().all(|hit| *hit), "some shard is unreachable");
    }

    #[test]
    fn pending_lists_round_trip_through_their_encoding() {
        let list = vec![digest("aa"), digest("bb"), digest("cc")];
        let bytes = encode_pending(&list);
        assert_eq!(decode_pending(Some(&bytes)), list);
        // An absent cell is an empty list, not an error: a shard nobody has
        // written to simply has no work.
        assert!(decode_pending(None).is_empty());
        assert!(decode_pending(Some(&Vec::new())).is_empty());
    }

    #[test]
    fn a_corrupt_index_line_is_dropped_rather_than_wedging_its_shard() {
        // Refusing the whole shard over one bad line would block every
        // action whose digest lands in it.
        let mut bytes = encode_pending(&[digest("aa")]);
        bytes.extend_from_slice(b"\nnot-a-digest\n");
        bytes.extend_from_slice(digest("bb").as_bytes());
        let back = decode_pending(Some(&bytes));
        assert_eq!(back, vec![digest("aa"), digest("bb")]);
        // Invalid UTF-8 is the same verdict.
        assert!(decode_pending(Some(&vec![0xff, 0xfe])).is_empty());
    }

    #[test]
    fn a_digest_is_indexed_once_however_often_it_is_added() {
        let list = vec![digest("aa")];
        // A replayed action must not spend a second envelope entry on an
        // index it is already in.
        assert!(pending_add(&list, &digest("aa")).is_none());
        let grown = pending_add(&list, &digest("bb")).expect("a new digest is added");
        assert_eq!(grown, vec![digest("aa"), digest("bb")]);
        // …and a duplicate already in the cell is collapsed on decode.
        let doubled = format!("{d}\n{d}", d = digest("aa"));
        assert_eq!(decode_pending(Some(&doubled.into_bytes())).len(), 1);
    }

    #[test]
    fn a_failed_retirement_is_counted_and_never_ends_the_pass() {
        // F469: a transient APE error while retiring one shard must not
        // escape the pass. It is folded into the report — the digests stay
        // indexed and retire next pass — so the caller still releases the
        // shard's lease and drains every later shard.
        let mut report = DrainReport {
            shards_with_work: 1,
            performed: 3,
            ..DrainReport::default()
        };
        settle_retirement(
            &mut report,
            4,
            3,
            Err(AlloyError::conflict("ape: transient")),
        );
        assert_eq!(report.failed, 1, "the failed retirement is reported");
        assert_eq!(report.completed, 0, "nothing retired, nothing counted");
        assert_eq!(report.performed, 3, "the effects themselves stand");

        // A retirement that worked counts every digest it removed.
        settle_retirement(&mut report, 5, 2, Ok(()));
        assert_eq!(report.completed, 2);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn retiring_removes_only_what_completed() {
        let list = vec![digest("aa"), digest("bb"), digest("cc")];
        let next = pending_remove(&list, &[digest("bb")]);
        assert_eq!(next, vec![digest("aa"), digest("cc")]);
        // Retiring nothing changes nothing, which is what lets the caller
        // skip a pointless commit.
        assert_eq!(pending_remove(&list, &[]), list);
        assert!(pending_remove(&list, &list).is_empty());
    }

    #[test]
    fn every_namespace_is_disjoint_from_every_other() {
        // These keys share one APE plane with the tag epochs, the version
        // guard and the replay markers. A collision would let an index
        // write clobber a marker inside the very envelope that is supposed
        // to guarantee it.
        let d = digest("aa");
        let keys = [
            shard_key(0),
            record_key(&d, 0),
            done_key(&d, 0),
            crate::alloy::tags::VERSION_KEY.to_string(),
            crate::alloy::tags::tag_key("drops"),
            crate::alloy::actions::marker_key("a", "k"),
        ];
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b.as_str()), "'{a}' shadows '{b}'");
                }
            }
        }
        // The record key the drain derives from a digest ALONE must equal
        // the one the action wrote from its name and idempotency key, or
        // the drain would read nothing at all.
        assert_eq!(
            record_key(&crate::alloy::actions::invocation_digest("a", "k"), 3),
            crate::alloy::actions::outbox_key("a", "k", 3)
        );
    }

    #[test]
    fn a_completion_record_never_collides_with_the_record_it_completes() {
        let d = digest("aa");
        assert_ne!(done_key(&d, 0), record_key(&d, 0));
        assert_ne!(done_key(&d, 0), done_key(&d, 1));
        assert!(done_key(&d, 0).starts_with(DONE_PREFIX));
    }

    #[test]
    fn a_lease_key_is_namespaced_away_from_the_shard_it_guards() {
        // The leases live in the STORE and the index in APE, but a shared
        // prefix would still make a scan of one sweep the other.
        for shard in 0..PENDING_SHARDS {
            assert!(drain_lease_key(shard).starts_with(LEASE_PREFIX));
            assert_ne!(drain_lease_key(shard), shard_key(shard));
            assert!(!drain_lease_key(shard).starts_with(PENDING_PREFIX));
        }
        // Distinct shards take distinct leases, or one consumer would lock
        // the whole index.
        assert_ne!(drain_lease_key(0), drain_lease_key(1));
    }

    #[test]
    fn the_lease_is_bounded_so_a_dead_consumer_cannot_wedge_a_shard() {
        // A lease with no expiry would make one crashed replica stop every
        // future drain of that shard for the life of the deployment. These
        // are CONST assertions, so a change that violated the bound would
        // fail the build rather than wait for anyone to run this test.
        const _: () = assert!(DRAIN_LEASE_MS > 0);
        const _: () = assert!(DRAIN_LEASE_MS <= 60_000);
    }

    #[test]
    fn the_index_fits_the_reads_and_the_envelope_that_carry_it() {
        // Discovery is ONE multi_get over the shard keys, so the shard
        // count may not exceed what a single call accepts.
        const _: () = assert!(PENDING_SHARDS <= 256);
        // A digest's records are read in one bounded call too.
        const _: () = assert!(MAX_INTENTS_PER_ACTION <= 256);
        // An action's envelope holds the version guard, its marker, its tag
        // epochs, its own APE writes, one record per intent AND the shard
        // index entry. The intent ceiling must leave room for the rest.
        const _: () = assert!(MAX_INTENTS_PER_ACTION < crate::alloy::tags::MAX_TAGS_PER_ADVANCE);
    }

    #[test]
    fn a_report_says_whether_the_pass_found_anything() {
        let idle = DrainReport::default();
        assert!(idle.is_idle());
        let busy = DrainReport {
            shards_with_work: 1,
            performed: 2,
            ..DrainReport::default()
        };
        assert!(!busy.is_idle());
    }

    #[test]
    fn one_pass_is_bounded_so_a_backlog_cannot_hold_the_request_loop() {
        // A drain shares the request loop with the app's own ingress. An
        // unbounded pass over a large backlog of network effects would hold
        // that loop for the whole backlog, which is starvation however the
        // pass is scheduled. These are CONST assertions, so shipping an
        // unbounded budget fails the build.
        const _: () = assert!(MAX_RECORDS_PER_PASS > 0);
        const _: () = assert!(MAX_RECORDS_PER_PASS <= 64);
    }
}
