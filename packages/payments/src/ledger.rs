//! Event admission: the marker that makes a webhook fold idempotent.
//!
//! A processor redelivers. Stripe retries a webhook for days, and an event
//! that is folded twice is money credited twice, so admission has to be keyed
//! on the processor's own event id and it has to be durable.
//!
//! # The rule this type exists to enforce
//!
//! **The marker and the state it admits ride ONE committed envelope.** Mark
//! first and a crash before the fold loses the payment; fold first and a crash
//! before the mark folds it again on redelivery. Neither ordering is
//! recoverable, so neither is offered: [`EventLog`] is a plain value that
//! lives INSIDE the application's own committed image, so recording the marker
//! and applying the transition are the same write by construction.
//!
//! On a single-document application state that is one `commit_n_if` guarded on
//! the document's previous bytes. On a multi-key layout it is one
//! `commit_n_if` whose entry list carries the row and the marker together —
//! the shape the payments contract's reference sketch (b) writes out.
//!
//! # The networked-CAS seam
//!
//! `ferrite-ape`'s `commit_n_if` documents an at-least-once seam beside
//! itself: a commit that is retried at the transport level can have APPLIED on
//! its first attempt and still report a guard mismatch to the caller. A loop
//! that read a mismatch as "not applied" would fold the event a second time.
//! The loop must therefore re-read and let the MARKER decide — which is what
//! [`EventLog::admit`] answers at the top of every attempt, and why
//! [`GUARD_RETRIES`] bounds the loop rather than letting it spin.
//!
//! # Retention
//!
//! The log lives inside the committed image, so every marker it keeps is
//! re-serialized on every guarded commit. Kept forever, it grows with lifetime
//! webhook traffic (ignored event types included), every money commit's
//! payload grows with it, and eventually the document crosses the store's
//! value ceiling and no fold can commit at all. A marker has to outlive the
//! processor's automatic redelivery window: Stripe stops retrying after about
//! three days, so [`RETENTION_MS`] (30 days) is ample for that.
//!
//! The guarantee is therefore BOUNDED: a pruned event admits as Fresh again.
//! That is safe only for deliveries the horizon covers. A manual redelivery
//! from the processor's dashboard, an application-side replay of an old
//! event, or a provider with no enforced delivery-age limit can present an
//! event after its marker is gone. A fold whose effect must never repeat
//! either refuses events older than the horizon (compare the event's own
//! `created` time with `now_ms`) or keys the effect itself on durable
//! business state (for example: an order already `paid` is not paid again).
//!
//! Record with [`EventLog::record_at`], which stamps the marker with the time
//! it was first seen, and call [`EventLog::prune`] inside the SAME guarded
//! commit, before recording:
//!
//! ```ignore
//! doc.webhook_events.prune(now_ms, RETENTION_MS);
//! if doc.webhook_events.admit(&event.id) == Admission::Duplicate { /* 2xx */ }
//! doc.webhook_events.record_at(&event.id, &order_id, now_ms);
//! ```
//!
//! Markers written by [`EventLog::record`] (and every marker in a document
//! stored before stamps existed) carry no time. [`EventLog::prune`] stamps
//! them with the time of the prune that first sees them, so they age out one
//! horizon later instead of being kept forever or dropped at once.

use std::collections::BTreeMap;

use ferrite_app::serde;

/// How many times a guarded money commit re-reads and re-applies before giving
/// up and letting the processor redeliver.
///
/// Bounded because a caller that keeps losing the guard is a caller under
/// write pressure, and an unbounded loop there is a livelock. Exhaustion is
/// not a loss: the event was never marked, so the processor's next delivery
/// folds it. The platform's own credit ledger bounds the same loop
/// (`GUARD_RETRIES = 32` in `ferrite-client`); a payments fold sits behind a
/// synchronous webhook reply, so it gives up sooner and answers rather than
/// holding the connection.
pub const GUARD_RETRIES: usize = 12;

/// How long an admission marker must be kept: comfortably longer than any
/// processor's redelivery window (Stripe retries for about three days).
pub const RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Whether this event has already been folded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Not seen before: fold it, and record the marker in the same commit.
    Fresh,
    /// Seen: this is a redelivery. Reply 2xx and change nothing.
    Duplicate,
}

/// One marker: the application's outcome word, and when the event was first
/// seen when that is known.
///
/// Untagged, so a bare string (every marker stored before stamps existed, and
/// every marker [`EventLog::record`] writes) still decodes, and still encodes
/// as a bare string.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
#[serde(untagged)]
enum Marker {
    Stamped { outcome: String, first_seen_ms: u64 },
    Unstamped(String),
}

impl Marker {
    fn outcome(&self) -> &str {
        match self {
            Marker::Stamped { outcome, .. } | Marker::Unstamped(outcome) => outcome,
        }
    }
}

/// The processed-event markers, `event id → the outcome that was recorded`.
///
/// Serializes as a map keyed by event id, so an application already
/// persisting a `BTreeMap<String, String>` of processed event ids can adopt
/// this type without migrating a single stored document: those values decode
/// as unstamped markers.
///
/// The recorded value is the application's own word for what it did with the
/// event (an order id, `ignored`, a refusal code). The kit does not constrain
/// it: only the KEY carries the idempotency guarantee.
///
/// The log is bounded only if the application prunes it; see the module's
/// Retention section and [`EventLog::prune`].
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
#[serde(transparent)]
pub struct EventLog {
    entries: BTreeMap<String, Marker>,
}

impl EventLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Has this event been folded already?
    ///
    /// Call this at the TOP of every attempt of the guarded loop, not once
    /// before it: a retried commit whose first attempt applied reports a guard
    /// mismatch, and re-reading the marker is what distinguishes that case
    /// from losing a race to another writer.
    #[must_use]
    pub fn admit(&self, event_id: &str) -> Admission {
        if self.entries.contains_key(event_id) {
            Admission::Duplicate
        } else {
            Admission::Fresh
        }
    }

    /// Record the marker for `event_id`, without a first-seen time.
    ///
    /// Mutates the in-memory image only. It becomes durable when the caller
    /// commits that image — the same commit that carries the transition, which
    /// is the whole point of the type.
    ///
    /// Prefer [`EventLog::record_at`]: an unstamped marker is only aged out
    /// once a [`EventLog::prune`] has stamped it.
    pub fn record(&mut self, event_id: &str, outcome: &str) {
        match self.entries.get_mut(event_id) {
            Some(Marker::Stamped { outcome: kept, .. }) => *kept = outcome.to_string(),
            _ => {
                self.entries
                    .insert(event_id.to_string(), Marker::Unstamped(outcome.to_string()));
            }
        }
    }

    /// Record the marker for `event_id`, stamped with `now_ms` as the time the
    /// event was first seen, so [`EventLog::prune`] can age it out.
    ///
    /// Re-recording an event keeps its original first-seen time.
    pub fn record_at(&mut self, event_id: &str, outcome: &str, now_ms: u64) {
        let first_seen_ms = match self.entries.get(event_id) {
            Some(Marker::Stamped { first_seen_ms, .. }) => *first_seen_ms,
            _ => now_ms,
        };
        self.entries.insert(
            event_id.to_string(),
            Marker::Stamped {
                outcome: outcome.to_string(),
                first_seen_ms,
            },
        );
    }

    /// Drop every marker first seen at least `horizon_ms` before `now_ms`, and
    /// return how many were dropped.
    ///
    /// Call it inside the same guarded commit that records, with a horizon
    /// longer than the processor's automatic redelivery window
    /// ([`RETENTION_MS`]). Deduplication is bounded by the horizon: an event
    /// presented again after its marker is pruned admits as Fresh, so see the
    /// module's Retention section for what else a fold must enforce.
    ///
    /// Unstamped markers (from [`EventLog::record`] or a document stored before
    /// stamps existed) are stamped with `now_ms` instead of being dropped: their
    /// age is unknown, so they are kept for one full horizon from here.
    pub fn prune(&mut self, now_ms: u64, horizon_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, marker| match marker {
            Marker::Stamped { first_seen_ms, .. } => {
                now_ms.saturating_sub(*first_seen_ms) < horizon_ms
            }
            Marker::Unstamped(outcome) => {
                *marker = Marker::Stamped {
                    outcome: std::mem::take(outcome),
                    first_seen_ms: now_ms,
                };
                true
            }
        });
        before - self.entries.len()
    }

    /// What was recorded for `event_id`, if anything.
    #[must_use]
    pub fn outcome(&self, event_id: &str) -> Option<&str> {
        self.entries.get(event_id).map(Marker::outcome)
    }

    /// How many markers the log currently holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the log empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json;

    #[test]
    fn a_fresh_event_admits_once_and_every_redelivery_is_a_duplicate() {
        let mut log = EventLog::new();
        assert_eq!(log.admit("evt_1"), Admission::Fresh);
        log.record("evt_1", "ORD-1");
        assert_eq!(log.admit("evt_1"), Admission::Duplicate);
        assert_eq!(log.admit("evt_2"), Admission::Fresh);
        assert_eq!(log.outcome("evt_1"), Some("ORD-1"));
        assert_eq!(log.outcome("evt_2"), None);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn the_log_serializes_as_a_bare_map_so_stored_state_needs_no_migration() {
        let mut log = EventLog::new();
        log.record("evt_1", "ORD-1");
        let encoded = serde_json::to_string(&log).expect("encodes");
        assert_eq!(encoded, r#"{"evt_1":"ORD-1"}"#);
        let decoded: EventLog = serde_json::from_str(r#"{"evt_2":"ignored"}"#).expect("decodes");
        assert_eq!(decoded.admit("evt_2"), Admission::Duplicate);
        assert_eq!(decoded.outcome("evt_2"), Some("ignored"));
    }

    /// F487: a stamped marker round-trips, and a document mixing stored bare
    /// strings with stamped markers decodes.
    #[test]
    fn stamped_and_stored_bare_markers_share_one_document() {
        let mut log: EventLog =
            serde_json::from_str(r#"{"evt_old":"ORD-0"}"#).expect("decodes a stored bare map");
        log.record_at("evt_new", "ORD-1", 5_000);
        let encoded = serde_json::to_string(&log).expect("encodes");
        assert_eq!(
            encoded,
            r#"{"evt_new":{"outcome":"ORD-1","first_seen_ms":5000},"evt_old":"ORD-0"}"#
        );
        let decoded: EventLog = serde_json::from_str(&encoded).expect("round-trips");
        assert_eq!(decoded, log);
        assert_eq!(decoded.outcome("evt_old"), Some("ORD-0"));
        assert_eq!(decoded.outcome("evt_new"), Some("ORD-1"));
    }

    /// F487: pruning drops markers older than the horizon, keeps the rest,
    /// and keeps a re-recorded event's original first-seen time.
    #[test]
    fn prune_forgets_only_markers_older_than_the_horizon() {
        let mut log = EventLog::new();
        log.record_at("evt_1", "ignored", 1_000);
        log.record_at("evt_2", "ORD-2", 2_000);
        // Re-recording does not refresh the stamp.
        log.record_at("evt_1", "ignored-again", 1_900);
        assert_eq!(log.prune(1_999, 1_000), 0, "evt_1 is 999 ms old");
        assert_eq!(log.prune(2_000, 1_000), 1, "evt_1 reaches the horizon");
        assert_eq!(log.admit("evt_1"), Admission::Fresh);
        assert_eq!(log.admit("evt_2"), Admission::Duplicate, "inside the horizon");
        assert_eq!(log.len(), 1);
    }

    /// F487: markers with no stamp (stored before stamps, or written by
    /// `record`) are adopted by the first prune and age out one horizon later.
    #[test]
    fn unstamped_markers_age_out_one_horizon_after_the_first_prune() {
        let mut log: EventLog =
            serde_json::from_str(r#"{"evt_a":"ignored"}"#).expect("decodes");
        log.record("evt_b", "ORD-1");
        assert_eq!(log.prune(10_000, RETENTION_MS), 0, "adopted, not dropped");
        assert_eq!(log.admit("evt_a"), Admission::Duplicate);
        assert_eq!(log.prune(10_000 + RETENTION_MS - 1, RETENTION_MS), 0);
        assert_eq!(log.prune(10_000 + RETENTION_MS, RETENTION_MS), 2);
        assert!(log.is_empty());
    }

    /// F487: with a prune in every commit the log is bounded by the traffic
    /// of one horizon, not by lifetime traffic.
    #[test]
    fn a_log_pruned_on_every_commit_stays_bounded() {
        const HOUR: u64 = 60 * 60 * 1000;
        let mut log = EventLog::new();
        let mut high_water = 0;
        // One event an hour for a year, against a 30-day horizon.
        for hour in 0..(365 * 24) {
            let now = hour * HOUR;
            log.prune(now, RETENTION_MS);
            log.record_at(&format!("evt_{hour}"), "ignored", now);
            high_water = high_water.max(log.len());
        }
        assert_eq!(high_water, (RETENTION_MS / HOUR) as usize);
    }
}
