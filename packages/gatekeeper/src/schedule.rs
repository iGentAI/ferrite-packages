//! Governed schedules: registration is NOT activation.
//!
//! An agent registering a schedule creates it **disabled**; a human must
//! enable it. Before every firing, admission is re-checked — the registering
//! agent still live, the backing capability unexpired and unrevoked, the
//! account still entitled. A delivery skipped by a failed admission check
//! does not consume retries. Deliveries are fenced by `run_id` so a retried
//! fire is idempotent, and failures retry a bounded number of times with
//! exponential backoff into a `Dead` (needs-attention) terminal state.
//!
//! Blueprint-instantiated surfaces never inherit schedules — the recipient
//! registers their own (enforced by the `blueprints` package, stated here as
//! contract).

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::gatekeeper::calendar::CalendarSpec;
use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Bounded retries before a schedule goes `Dead`.
pub const MAX_DELIVERY_RETRIES: u32 = 8;
/// Minimum interval for `Every` schedules (60s, as adopted).
pub const MIN_INTERVAL_MS: u64 = 60_000;
/// Bounded per-account count of live (not `Dead`/`Completed`) schedules.
pub const MAX_SCHEDULES_PER_ACCOUNT: usize = 64;

/// When a schedule fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum ScheduleKind {
    /// Interval schedule; `interval_ms >= MIN_INTERVAL_MS`.
    Every { interval_ms: u64 },
    /// Calendar schedule with a mandatory timezone — `"UTC"` or a fixed
    /// offset `"±HH:MM"` in this package (see [`crate::gatekeeper::calendar`]
    /// for the recorded IANA/DST delta).
    CalendarAt {
        expression: String,
        timezone: String,
    },
    /// One-shot.
    RunAt { at: TimestampMs },
}

/// Lifecycle of a registered schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum ScheduleState {
    /// Registered by an agent; will NOT fire until a human enables it.
    Disabled,
    /// Human-enabled; fires are admitted per-delivery.
    Enabled,
    /// Paused by a human; re-enabling resumes.
    Paused,
    /// Exhausted its retries — needs human attention.
    Dead,
    /// One-shot that fired successfully, or an expired registration.
    Completed,
}

impl ScheduleState {
    /// `Dead` and `Completed` never fire again.
    pub fn is_terminal(self) -> bool {
        matches!(self, ScheduleState::Dead | ScheduleState::Completed)
    }
}

/// One registered schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Schedule {
    pub id: String,
    /// The account that owns the schedule (every schedule has an accountable
    /// human owner).
    pub owner: String,
    /// The agent/hook the delivery invokes.
    pub target: String,
    pub kind: ScheduleKind,
    pub state: ScheduleState,
    pub registered_at: TimestampMs,
    pub enabled_at: Option<TimestampMs>,
    /// Consecutive delivery failures (reset on success; NOT consumed by
    /// admission skips).
    pub failures: u32,
    /// Monotonic run counter — the `run_id` fence.
    pub next_run_id: u64,
    /// The run currently being attempted (set at first admission, kept
    /// across retries so a retry reuses the SAME fenced run id, cleared on
    /// recorded delivery).
    pub inflight_run_id: Option<u64>,
    /// The last run id actually delivered (idempotency fence).
    pub last_delivered_run_id: Option<u64>,
    /// When the next fire is due (None until enabled; recomputed after
    /// every recorded delivery).
    pub next_due: Option<TimestampMs>,
}

/// The admission questions re-checked before EVERY delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AdmissionCheck {
    /// Is the registering agent still deployed/live?
    pub agent_live: bool,
    /// Is the backing capability grant still valid (unexpired, epoch current)?
    pub capability_valid: bool,
    /// Is the owning account still entitled to scheduled work?
    pub account_entitled: bool,
}

impl AdmissionCheck {
    pub fn pass() -> Self {
        Self {
            agent_live: true,
            capability_valid: true,
            account_entitled: true,
        }
    }

    pub fn ok(&self) -> bool {
        self.agent_live && self.capability_valid && self.account_entitled
    }

    pub(crate) fn refusal(&self) -> &'static str {
        if !self.agent_live {
            "registering agent is no longer live"
        } else if !self.capability_valid {
            "backing capability expired or revoked"
        } else {
            "account is no longer entitled"
        }
    }
}

/// The outcome of attempting one delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum AdmissionDecision {
    /// Deliver now, fenced by this run id.
    Deliver { run_id: u64 },
    /// Skipped: admission failed. Does NOT consume a retry.
    Skipped { reason: String },
    /// Not yet due; come back at `due`.
    NotDue { due: TimestampMs },
    /// The schedule is not in a fire-able state.
    NotFireable { state: ScheduleState },
}

/// Compute the next due instant for a schedule kind, strictly after `now`.
fn compute_next_due(kind: &ScheduleKind, now: TimestampMs) -> Result<TimestampMs, GatekeeperError> {
    match kind {
        ScheduleKind::Every { interval_ms } => Ok(now.saturating_add(*interval_ms)),
        ScheduleKind::CalendarAt {
            expression,
            timezone,
        } => CalendarSpec::parse(expression, timezone)?.next_fire_after(now),
        ScheduleKind::RunAt { at } => Ok(*at),
    }
}

/// The per-account schedule registry and its governance state machine.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ScheduleRegistry {
    schedules: BTreeMap<String, Schedule>,
    next_seq: u64,
}

impl ScheduleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schedule. It is born `Disabled` — registration is not
    /// activation, no matter who registers.
    pub fn register(
        &mut self,
        owner: impl Into<String>,
        target: impl Into<String>,
        kind: ScheduleKind,
        now: TimestampMs,
    ) -> Result<&Schedule, GatekeeperError> {
        let owner = owner.into();
        if let ScheduleKind::Every { interval_ms } = &kind {
            if *interval_ms < MIN_INTERVAL_MS {
                return Err(GatekeeperError::Invalid(format!(
                    "interval {interval_ms}ms is below the {MIN_INTERVAL_MS}ms minimum"
                )));
            }
        }
        if let ScheduleKind::CalendarAt {
            expression,
            timezone,
        } = &kind
        {
            if timezone.is_empty() {
                return Err(GatekeeperError::Invalid(
                    "calendar schedules require a timezone (\"UTC\" or \"±HH:MM\")".into(),
                ));
            }
            // Full validation: parse the cron expression and the timezone,
            // and prove the spec can actually fire.
            CalendarSpec::parse(expression, timezone)?.next_fire_after(now)?;
        }
        let owned = self
            .schedules
            .values()
            .filter(|s| s.owner == owner && !s.state.is_terminal())
            .count();
        if owned >= MAX_SCHEDULES_PER_ACCOUNT {
            return Err(GatekeeperError::Invalid(format!(
                "account {owner} already holds {MAX_SCHEDULES_PER_ACCOUNT} live schedules"
            )));
        }
        self.next_seq += 1;
        let id = format!("sched-{:08}", self.next_seq);
        let s = Schedule {
            id: id.clone(),
            owner,
            target: target.into(),
            kind,
            state: ScheduleState::Disabled,
            registered_at: now,
            enabled_at: None,
            failures: 0,
            next_run_id: 1,
            inflight_run_id: None,
            last_delivered_run_id: None,
            next_due: None,
        };
        self.schedules.insert(id.clone(), s);
        Ok(self.schedules.get(&id).expect("just inserted"))
    }

    pub fn get(&self, id: &str) -> Option<&Schedule> {
        self.schedules.get(id)
    }

    /// Remove a schedule (human action): clears `Completed`/`Dead` entries
    /// and unwanted registrations. An `Enabled` schedule must be paused
    /// first, so a live schedule is never dropped mid-delivery.
    pub fn remove(&mut self, id: &str) -> Result<Schedule, GatekeeperError> {
        let s = self.get_mut(id)?;
        if s.state == ScheduleState::Enabled {
            return Err(GatekeeperError::AdmissionRefused(
                "pause an enabled schedule before removing it".into(),
            ));
        }
        if s.inflight_run_id.is_some() && !s.state.is_terminal() {
            return Err(GatekeeperError::AdmissionRefused(
                "a delivery is in flight; record its outcome before removing the schedule".into(),
            ));
        }
        Ok(self.schedules.remove(id).expect("present: get_mut succeeded"))
    }

    /// Human enablement — the only path from Disabled/Paused to Enabled.
    /// Computes the first due instant from the schedule kind.
    pub fn enable(&mut self, id: &str, now: TimestampMs) -> Result<(), GatekeeperError> {
        let s = self.get_mut(id)?;
        match s.state {
            ScheduleState::Disabled | ScheduleState::Paused => {
                s.state = ScheduleState::Enabled;
                s.enabled_at = Some(now);
                s.failures = 0;
                s.next_due = Some(compute_next_due(&s.kind, now)?);
                Ok(())
            }
            other => Err(GatekeeperError::AdmissionRefused(format!(
                "cannot enable a schedule in state {other:?}"
            ))),
        }
    }

    pub fn pause(&mut self, id: &str) -> Result<(), GatekeeperError> {
        let s = self.get_mut(id)?;
        if s.state == ScheduleState::Enabled {
            s.state = ScheduleState::Paused;
            Ok(())
        } else {
            Err(GatekeeperError::AdmissionRefused(format!(
                "cannot pause a schedule in state {:?}",
                s.state
            )))
        }
    }

    /// Attempt one delivery AT `now`: check due time, re-check admission,
    /// then hand out a fenced `run_id`. A failed admission SKIPS (no retry
    /// consumed). A retry of an in-flight run reuses the SAME run id — the
    /// fence — until `record_delivery` clears it; the next run id is only
    /// allocated after the previous delivery was recorded.
    pub fn admit_delivery_at(
        &mut self,
        id: &str,
        check: AdmissionCheck,
        now: TimestampMs,
    ) -> Result<AdmissionDecision, GatekeeperError> {
        let s = self.get_mut(id)?;
        if s.state != ScheduleState::Enabled {
            return Ok(AdmissionDecision::NotFireable { state: s.state });
        }
        if let Some(due) = s.next_due {
            if now < due {
                return Ok(AdmissionDecision::NotDue { due });
            }
        }
        if !check.ok() {
            return Ok(AdmissionDecision::Skipped {
                reason: check.refusal().to_string(),
            });
        }
        // Reuse the in-flight run id across retries (the idempotency fence);
        // only allocate a fresh one when nothing is in flight.
        let run_id = match s.inflight_run_id {
            Some(rid) => rid,
            None => {
                let rid = s.next_run_id;
                s.next_run_id += 1;
                s.inflight_run_id = Some(rid);
                rid
            }
        };
        Ok(AdmissionDecision::Deliver { run_id })
    }

    /// Admit with no due-time constraint.
    pub fn admit_delivery(
        &mut self,
        id: &str,
        check: AdmissionCheck,
    ) -> Result<AdmissionDecision, GatekeeperError> {
        let now = self.get(id).and_then(|s| s.next_due).unwrap_or(u64::MAX);
        self.admit_delivery_at(id, check, now)
    }

    /// Record a delivered run at `now`. Only the run currently in flight
    /// can be recorded, and run ids only move forward: a duplicate or a
    /// stale run id (a retry racing a success, a delayed hedged delivery)
    /// is refused by the fence and changes nothing. On success the in-flight
    /// run clears and the next due instant is recomputed from the schedule
    /// kind.
    pub fn record_delivery_at(
        &mut self,
        id: &str,
        run_id: u64,
        now: TimestampMs,
    ) -> Result<(), GatekeeperError> {
        let s = self.get_mut(id)?;
        let one_shot = matches!(s.kind, ScheduleKind::RunAt { .. });
        if s.last_delivered_run_id.is_some_and(|last| run_id <= last) {
            return Err(GatekeeperError::Invalid(format!(
                "run {run_id} already delivered (fence)"
            )));
        }
        if s.state != ScheduleState::Enabled {
            return Err(GatekeeperError::AdmissionRefused(format!(
                "cannot record a delivery for a schedule in state {:?}",
                s.state
            )));
        }
        if s.inflight_run_id != Some(run_id) {
            return Err(GatekeeperError::Invalid(format!(
                "run {run_id} is not the run in flight (fence)"
            )));
        }
        // The run was delivered whatever comes next: record it and clear the
        // fence before anything can fail, so a delivered run is never handed
        // out again. A recurring schedule whose next instant cannot be
        // computed stops firing (Dead, needs a person) instead of re-firing.
        let next_due = if one_shot {
            Ok(None)
        } else {
            compute_next_due(&s.kind, now).map(Some)
        };
        s.last_delivered_run_id = Some(run_id);
        s.inflight_run_id = None;
        s.failures = 0;
        if one_shot {
            s.state = ScheduleState::Completed;
        }
        match next_due {
            Ok(next) => {
                s.next_due = next;
                Ok(())
            }
            Err(e) => {
                s.next_due = None;
                s.state = ScheduleState::Dead;
                Err(e)
            }
        }
    }

    /// Record a delivery using the schedule's current due
    /// instant as the reference time.
    pub fn record_delivery(&mut self, id: &str, run_id: u64) -> Result<(), GatekeeperError> {
        let now = self.get(id).and_then(|s| s.next_due).unwrap_or_default();
        self.record_delivery_at(id, run_id, now)
    }

    /// Record a delivery failure. After `MAX_DELIVERY_RETRIES` consecutive
    /// failures the schedule goes `Dead` (needs attention). Returns the
    /// suggested backoff before the next retry.
    pub fn record_failure(&mut self, id: &str) -> Result<Option<u64>, GatekeeperError> {
        let s = self.get_mut(id)?;
        if s.state != ScheduleState::Enabled {
            return Err(GatekeeperError::AdmissionRefused(format!(
                "cannot record a failure for a schedule in state {:?}",
                s.state
            )));
        }
        if s.inflight_run_id.is_none() {
            return Err(GatekeeperError::Invalid(
                "no delivery is in flight to fail (fence)".into(),
            ));
        }
        s.failures = s.failures.saturating_add(1);
        if s.failures >= MAX_DELIVERY_RETRIES {
            s.state = ScheduleState::Dead;
            s.inflight_run_id = None;
            return Ok(None);
        }
        // Exponential backoff: 1s, 2s, 4s, ... capped at 5 minutes.
        let backoff = (1_000u64 << (s.failures - 1)).min(300_000);
        Ok(Some(backoff))
    }

    /// Schedules needing human attention.
    pub fn dead(&self) -> Vec<&Schedule> {
        self.schedules
            .values()
            .filter(|s| s.state == ScheduleState::Dead)
            .collect()
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut Schedule, GatekeeperError> {
        self.schedules
            .get_mut(id)
            .ok_or_else(|| GatekeeperError::UnknownSchedule(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_minute() -> ScheduleKind {
        ScheduleKind::Every {
            interval_ms: 60_000,
        }
    }

    #[test]
    fn registration_is_not_activation() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        // Disabled at birth: not fireable.
        let d = reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap();
        assert_eq!(
            d,
            AdmissionDecision::NotFireable {
                state: ScheduleState::Disabled
            }
        );
        // Human enables; now it fires.
        reg.enable(&id, 20).unwrap();
        let d = reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap();
        assert_eq!(d, AdmissionDecision::Deliver { run_id: 1 });
    }

    #[test]
    fn admission_failure_skips_without_consuming_retries() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        let mut check = AdmissionCheck::pass();
        check.capability_valid = false;
        let d = reg.admit_delivery(&id, check).unwrap();
        assert!(matches!(d, AdmissionDecision::Skipped { .. }));
        assert_eq!(reg.get(&id).unwrap().failures, 0);
        // Run ids are not consumed by skips either.
        let d = reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap();
        assert_eq!(d, AdmissionDecision::Deliver { run_id: 1 });
    }

    #[test]
    fn run_id_fences_duplicate_deliveries() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        let AdmissionDecision::Deliver { run_id } =
            reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap()
        else {
            panic!("expected delivery")
        };
        reg.record_delivery(&id, run_id).unwrap();
        assert!(reg.record_delivery(&id, run_id).is_err()); // fence
    }

    #[test]
    fn retry_reuses_the_same_fenced_run_id() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        let AdmissionDecision::Deliver { run_id: first } = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), 100_000)
            .unwrap()
        else {
            panic!("expected delivery")
        };
        // The delivery attempt fails downstream; the retry admits again and
        // must receive the SAME run id — that is what makes the fence an
        // idempotency fence across retries.
        reg.record_failure(&id).unwrap();
        let AdmissionDecision::Deliver { run_id: retry } = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), 160_000)
            .unwrap()
        else {
            panic!("expected delivery")
        };
        assert_eq!(retry, first, "a retry must reuse the in-flight run id");
        // Once delivered, the next admission allocates a fresh run id.
        reg.record_delivery_at(&id, retry, 160_001).unwrap();
        let next_due = reg.get(&id).unwrap().next_due.unwrap();
        let AdmissionDecision::Deliver { run_id: next } = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), next_due)
            .unwrap()
        else {
            panic!("expected delivery")
        };
        assert_eq!(next, first + 1);
    }

    #[test]
    fn due_time_gates_delivery_and_recomputes() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        let due = reg.get(&id).unwrap().next_due.unwrap();
        assert_eq!(due, 20 + 60_000, "interval due = enable time + interval");
        // Too early: NotDue names the instant to come back at.
        let d = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), due - 1)
            .unwrap();
        assert_eq!(d, AdmissionDecision::NotDue { due });
        // At the due instant it delivers, and recording recomputes the next due.
        let AdmissionDecision::Deliver { run_id } = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), due)
            .unwrap()
        else {
            panic!("expected delivery")
        };
        reg.record_delivery_at(&id, run_id, due).unwrap();
        assert_eq!(reg.get(&id).unwrap().next_due, Some(due + 60_000));
    }

    #[test]
    fn one_shot_run_at_respects_its_instant() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "t", ScheduleKind::RunAt { at: 500_000 }, 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        // Before the instant: not due.
        let d = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), 499_999)
            .unwrap();
        assert_eq!(d, AdmissionDecision::NotDue { due: 500_000 });
        // At the instant: delivers, then record_delivery completes the RunAt
        // schedule with no further due instant.
        let AdmissionDecision::Deliver { run_id } = reg
            .admit_delivery_at(&id, AdmissionCheck::pass(), 500_000)
            .unwrap()
        else {
            panic!("expected delivery")
        };
        reg.record_delivery(&id, run_id).unwrap();
        let s = reg.get(&id).unwrap();
        assert_eq!(s.state, ScheduleState::Completed);
        assert_eq!(s.next_due, None);
    }

    #[test]
    fn calendar_schedule_due_uses_calendar_evaluation() {
        let mut reg = ScheduleRegistry::new();
        // 03:00 daily at Amsterdam's summer offset (+02:00), registered in
        // July. The deployment supplies the offset per-schedule — IANA-zone
        // DST evaluation is a recorded delta (see `calendar`).
        let spec = crate::gatekeeper::calendar::CalendarSpec::parse("0 3 * * *", "+02:00").unwrap();
        let start = spec.local_instant(2026, 7, 10, 12, 0).unwrap();
        let id = reg
            .register(
                "alice",
                "t",
                ScheduleKind::CalendarAt {
                    expression: "0 3 * * *".into(),
                    timezone: "+02:00".into(),
                },
                start,
            )
            .unwrap()
            .id
            .clone();
        reg.enable(&id, start).unwrap();
        let due = reg.get(&id).unwrap().next_due.unwrap();
        assert_eq!(due, spec.next_fire_after(start).unwrap());
    }

    #[test]
    fn failures_retry_bounded_then_dead() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        deliver(&mut reg, &id, 60_020);
        let mut backoffs = Vec::new();
        for _ in 0..MAX_DELIVERY_RETRIES {
            match reg.record_failure(&id).unwrap() {
                Some(b) => backoffs.push(b),
                None => break,
            }
        }
        assert_eq!(reg.get(&id).unwrap().state, ScheduleState::Dead);
        assert_eq!(backoffs.len() as u32, MAX_DELIVERY_RETRIES - 1);
        assert!(backoffs.windows(2).all(|w| w[1] >= w[0])); // monotone backoff
        assert_eq!(reg.dead().len(), 1);
        // Dead schedules do not fire.
        let d = reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap();
        assert_eq!(
            d,
            AdmissionDecision::NotFireable {
                state: ScheduleState::Dead
            }
        );
    }

    #[test]
    fn refuses_subminute_intervals_and_missing_timezone() {
        let mut reg = ScheduleRegistry::new();
        assert!(reg
            .register(
                "a",
                "t",
                ScheduleKind::Every {
                    interval_ms: 59_999
                },
                1
            )
            .is_err());
        assert!(reg
            .register(
                "a",
                "t",
                ScheduleKind::CalendarAt {
                    expression: "0 9 * * MON".into(),
                    timezone: "".into()
                },
                1
            )
            .is_err());
    }

    #[test]
    fn per_account_schedule_count_is_bounded() {
        let mut reg = ScheduleRegistry::new();
        for _ in 0..MAX_SCHEDULES_PER_ACCOUNT {
            reg.register("alice", "t", every_minute(), 1).unwrap();
        }
        assert!(reg.register("alice", "t", every_minute(), 1).is_err());
        // A different account is unaffected.
        assert!(reg.register("bob", "t", every_minute(), 1).is_ok());
    }

    #[test]
    fn pause_and_reenable() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "t", every_minute(), 1)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 2).unwrap();
        reg.pause(&id).unwrap();
        let d = reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap();
        assert_eq!(
            d,
            AdmissionDecision::NotFireable {
                state: ScheduleState::Paused
            }
        );
        reg.enable(&id, 3).unwrap();
        assert!(matches!(
            reg.admit_delivery(&id, AdmissionCheck::pass()).unwrap(),
            AdmissionDecision::Deliver { .. }
        ));
    }

    fn deliver(reg: &mut ScheduleRegistry, id: &str, now: TimestampMs) -> u64 {
        let AdmissionDecision::Deliver { run_id } =
            reg.admit_delivery_at(id, AdmissionCheck::pass(), now).unwrap()
        else {
            panic!("expected delivery")
        };
        run_id
    }

    /// F187: a delayed duplicate of an older run cannot record, regress the
    /// fence, release the in-flight run, or reset the failure count; and an
    /// id that is not in flight is refused.
    #[test]
    fn stale_and_foreign_run_ids_are_fenced() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "agent-1", every_minute(), 10)
            .unwrap()
            .id
            .clone();
        reg.enable(&id, 20).unwrap();
        let run1 = deliver(&mut reg, &id, 60_020);
        reg.record_delivery_at(&id, run1, 60_020).unwrap();
        let run2 = deliver(&mut reg, &id, 120_020);
        reg.record_delivery_at(&id, run2, 120_020).unwrap();

        // Run 3 is in flight and failing.
        let run3 = deliver(&mut reg, &id, 180_020);
        reg.record_failure(&id).unwrap();
        let before = reg.get(&id).unwrap().clone();

        // A delayed duplicate of run 1 is refused and changes nothing.
        assert!(reg.record_delivery_at(&id, run1, 180_030).is_err());
        // So is a replay of run 2, and an id that was never issued.
        assert!(reg.record_delivery_at(&id, run2, 180_031).is_err());
        assert!(reg.record_delivery_at(&id, run3 + 7, 180_032).is_err());
        assert_eq!(reg.get(&id).unwrap(), &before);
        assert_eq!(before.inflight_run_id, Some(run3));
        assert_eq!(before.last_delivered_run_id, Some(run2));
        assert_eq!(before.failures, 1);

        // The retry reuses run 3, and only it records.
        assert_eq!(deliver(&mut reg, &id, 180_040), run3);
        reg.record_delivery_at(&id, run3, 180_040).unwrap();
        assert_eq!(reg.get(&id).unwrap().last_delivered_run_id, Some(run3));
    }

    /// F483: terminal schedules stop counting toward the quota, and a human
    /// can remove them.
    #[test]
    fn completed_schedules_free_quota_and_can_be_removed() {
        let mut reg = ScheduleRegistry::new();
        let mut ids = Vec::new();
        for i in 0..MAX_SCHEDULES_PER_ACCOUNT as u64 {
            let id = reg
                .register("alice", "t", ScheduleKind::RunAt { at: 100 + i }, 1)
                .unwrap()
                .id
                .clone();
            reg.enable(&id, 2).unwrap();
            let run_id = deliver(&mut reg, &id, 100 + i);
            reg.record_delivery_at(&id, run_id, 100 + i).unwrap();
            assert_eq!(reg.get(&id).unwrap().state, ScheduleState::Completed);
            ids.push(id);
        }
        // 64 fired reminders do not wedge the account.
        let live = reg
            .register("alice", "t", every_minute(), 3)
            .unwrap()
            .id
            .clone();
        // Completed entries can be cleared; an enabled one must be paused first.
        assert_eq!(reg.remove(&ids[0]).unwrap().state, ScheduleState::Completed);
        assert!(reg.get(&ids[0]).is_none());
        reg.enable(&live, 4).unwrap();
        assert!(reg.remove(&live).is_err());
        reg.pause(&live).unwrap();
        assert!(reg.remove(&live).is_ok());
        assert!(matches!(
            reg.remove("sched-missing"),
            Err(GatekeeperError::UnknownSchedule(_))
        ));
        // The live cap still holds.
        for _ in 0..MAX_SCHEDULES_PER_ACCOUNT {
            reg.register("bob", "t", every_minute(), 5).unwrap();
        }
        assert!(reg.register("bob", "t", every_minute(), 5).is_err());
    }

    #[test]
    fn leap_day_calendar_schedule_records_delivery_and_advances_without_looping() {
        let spec = CalendarSpec::parse("0 0 29 2 *", "UTC").unwrap();
        let reg_time = spec.local_instant(2027, 6, 1, 0, 0).unwrap();
        let due_2028 = spec.local_instant(2028, 2, 29, 0, 0).unwrap();
        let due_2032 = spec.local_instant(2032, 2, 29, 0, 0).unwrap();
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register(
                "alice",
                "agent-leap",
                ScheduleKind::CalendarAt {
                    expression: "0 0 29 2 *".into(),
                    timezone: "UTC".into(),
                },
                reg_time,
            )
            .unwrap()
            .id
            .clone();
        reg.enable(&id, reg_time).unwrap();
        assert_eq!(reg.get(&id).unwrap().next_due, Some(due_2028));
        let run1 = deliver(&mut reg, &id, due_2028);
        reg.record_delivery(&id, run1).unwrap();
        let after = reg.get(&id).unwrap();
        assert_eq!(after.last_delivered_run_id, Some(run1));
        assert_eq!(after.inflight_run_id, None);
        assert_eq!(after.next_due, Some(due_2032));
        assert!(matches!(
            reg.admit_delivery_at(&id, AdmissionCheck::pass(), due_2028 + 60_000).unwrap(),
            AdmissionDecision::NotDue { .. }
        ));
    }

    #[test]
    fn failures_and_deliveries_are_fenced_by_state_and_flight() {
        let mut reg = ScheduleRegistry::new();
        let id = reg
            .register("alice", "t", every_minute(), 1)
            .unwrap()
            .id
            .clone();
        // Nothing in flight on a Disabled schedule: no failure can kill it.
        assert!(reg.record_failure(&id).is_err());
        assert_eq!(reg.get(&id).unwrap().state, ScheduleState::Disabled);
        reg.enable(&id, 2).unwrap();
        // Enabled, nothing in flight yet: still refused.
        assert!(reg.record_failure(&id).is_err());
        let run = deliver(&mut reg, &id, 60_002);
        reg.pause(&id).unwrap();
        // A late failure or delivery after a person paused it changes nothing.
        assert!(reg.record_failure(&id).is_err());
        assert!(reg.record_delivery_at(&id, run, 60_003).is_err());
        assert_eq!(reg.get(&id).unwrap().state, ScheduleState::Paused);
        assert_eq!(reg.get(&id).unwrap().failures, 0);
        // A paused schedule with a run in flight cannot be dropped.
        assert!(reg.remove(&id).is_err());
        reg.enable(&id, 60_004).unwrap();
        let again = deliver(&mut reg, &id, 120_004);
        assert_eq!(again, run, "the in-flight run id is reused");
        for _ in 0..MAX_DELIVERY_RETRIES {
            if reg.record_failure(&id).unwrap().is_none() {
                break;
            }
        }
        let dead = reg.get(&id).unwrap();
        assert_eq!(dead.state, ScheduleState::Dead);
        assert_eq!(dead.inflight_run_id, None);
        // A late delivery cannot revive a Dead schedule.
        assert!(reg.record_delivery_at(&id, run, 120_005).is_err());
        assert_eq!(reg.get(&id).unwrap().state, ScheduleState::Dead);
        assert!(reg.remove(&id).is_ok());
    }
}
