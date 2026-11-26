//! **The saga engine**: a cross-key write as a declared sequence of
//! phases, resumable at the first one that has not happened.
//!
//! The store offers no transaction across keys, so every operation touching
//! two records is a phase order plus a repair path, such as a CRM lead merge
//! or an inventory count close.
//!
//! # What a declaration buys that prose does not
//!
//! Two things, and both are the reason this module exists rather than a
//! style guide.
//!
//! **Resume.** On redelivery the engine re-enters at the first phase whose
//! completion record is absent.
//!
//! **Enumeration.** [`crash_points`] returns every boundary a crash can fall
//! between, so a test can drive them all without the author writing one per
//! boundary. A two-phase saga has one interior boundary; a four-phase saga
//! has three.
//!
//! # The completion record is not the idempotence
//!
//! A phase records that it ran, and that record is a separate write from the
//! phase's own effect: a crash between them re-runs the phase. So a phase
//! body must ALSO be idempotent by its own observable state — the winner's
//! `last_action_id`, the loser's `merged_into`, the line's `applied` flag.
//!
//! The record is an optimisation that skips work already known to be done.
//! The state is what makes re-running safe when the record was lost. Both
//! are required; the type documents it and the harness proves it.

use ferrite_app::client::ApeClusterClient;
use ferrite_app::serde::{Deserialize, Serialize};

use crate::alloy::actions::invocation_digest;
use crate::alloy::error::{AlloyError, Result};

/// The namespace saga phase records live under.
pub const SAGA_PREFIX: &str = "saga/";

/// The most phases one saga may declare.
///
/// A saga is a hand-reviewed sequence, not a workflow engine: past a handful
/// of phases the right answer is a different design, and the bound keeps the
/// crash matrix small enough to actually run.
pub const MAX_PHASES: usize = 8;

/// The key recording that one phase of one invocation has completed.
pub fn phase_key(digest: &str, phase: &str) -> String {
    format!("{SAGA_PREFIX}{digest}/{phase}")
}

/// One phase's declaration: its name and why its position is what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PhaseSpec {
    /// The phase name, which is also its record key component.
    pub name: String,
    /// What is true if a crash happens immediately AFTER this phase.
    ///
    /// It lives in the declaration so a reviewer reads the order and its
    /// consequence together rather than reconstructing it.
    pub after_crash: String,
}

/// A declared cross-key write.
#[derive(Debug, Clone, Default)]
pub struct SagaSpec {
    name: String,
    phases: Vec<PhaseSpec>,
}

impl SagaSpec {
    /// Declare a saga.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            phases: Vec::new(),
        }
    }

    /// Add a phase and the state a crash after it leaves behind.
    pub fn phase(mut self, name: impl Into<String>, after_crash: impl Into<String>) -> Self {
        self.phases.push(PhaseSpec {
            name: name.into(),
            after_crash: after_crash.into(),
        });
        self
    }

    /// The saga's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared phases, in order.
    pub fn phases(&self) -> &[PhaseSpec] {
        &self.phases
    }

    /// Validate the declaration.
    ///
    /// A duplicate phase name would make two phases share one completion
    /// record, so the second would be skipped the moment the first ran —
    /// silently dropping half the write.
    pub fn validate(&self) -> Result<()> {
        if self.phases.len() < 2 {
            return Err(AlloyError::internal(format!(
                "saga '{}' declares {} phase(s); a saga exists to order at least two \
                 writes that cannot share a transaction",
                self.name,
                self.phases.len()
            )));
        }
        if self.phases.len() > MAX_PHASES {
            return Err(AlloyError::internal(format!(
                "saga '{}' declares {} phases; at most {MAX_PHASES} are supported",
                self.name,
                self.phases.len()
            )));
        }
        for (i, p) in self.phases.iter().enumerate() {
            if p.name.is_empty() || p.name.contains('/') {
                return Err(AlloyError::internal(format!(
                    "saga '{}' phase {i} has an unusable name '{}'",
                    self.name, p.name
                )));
            }
            if self.phases.iter().skip(i + 1).any(|q| q.name == p.name) {
                return Err(AlloyError::internal(format!(
                    "saga '{}' declares phase '{}' twice; two phases sharing a completion \
                     record would skip the second as soon as the first had run",
                    self.name, p.name
                )));
            }
        }
        Ok(())
    }

    /// Every boundary a crash can fall between, as phase indices.
    ///
    /// A crash before phase 0 leaves nothing done and is the ordinary retry
    /// path; a crash after the last phase is completion. The INTERESTING
    /// points are the interior boundaries, and this enumerates exactly
    /// those — so a harness drives them all and the author writes none.
    pub fn crash_points(&self) -> Vec<usize> {
        (1..self.phases.len()).collect()
    }

    /// Bind this declaration to one invocation.
    pub fn run(&self, ape: ApeClusterClient, idempotency_key: &str) -> Saga<'_> {
        Saga {
            spec: self,
            ape,
            digest: invocation_digest(&self.name, idempotency_key),
            performed: Vec::new(),
            skipped: Vec::new(),
            stop_after: None,
            next_index: 0,
            stopped: false,
        }
    }
}

/// What one [`Saga::step`] call did.
///
/// These are three genuinely different outcomes and a boolean conflates
/// two of them catastrophically. A resume re-enters at the FIRST incomplete
/// phase, which means it walks past every phase that is already recorded —
/// so "this phase was already done" must mean *keep going*, while "the run
/// stopped" must mean *halt*. A caller told only `false` for both would
/// stop at the first completed phase and never reach the incomplete one,
/// which is precisely the resume this engine exists to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// The body ran and its completion was recorded.
    Performed,
    /// The phase was already recorded complete; the body did not run and
    /// the caller should CONTINUE to the next phase.
    Skipped,
    /// The run stopped before this phase, simulating a crash. The caller
    /// must not run any later phase.
    Stopped,
}

impl StepOutcome {
    /// Whether the run has stopped and no later phase may execute.
    pub fn is_stop(&self) -> bool {
        matches!(self, StepOutcome::Stopped)
    }

    /// Whether this call performed the phase's effect.
    pub fn performed(&self) -> bool {
        matches!(self, StepOutcome::Performed)
    }
}

/// One running saga.
pub struct Saga<'a> {
    spec: &'a SagaSpec,
    ape: ApeClusterClient,
    digest: String,
    performed: Vec<String>,
    skipped: Vec<String>,
    stop_after: Option<usize>,
    /// The declared index the next `step` must name.
    next_index: usize,
    /// Set once a step returned `Stopped`: no later phase may run.
    stopped: bool,
}

impl<'a> Saga<'a> {
    /// Stop the run immediately after `n` phases, simulating a crash.
    ///
    /// This exists so [`SagaSpec::crash_points`] can be driven by a test
    /// without the application exposing a test-only code path: the phases
    /// themselves are unchanged, and the run simply stops between two of
    /// them exactly as a killed process would.
    pub fn stop_after(mut self, n: usize) -> Self {
        self.stop_after = Some(n);
        self
    }

    /// The invocation digest this run is recorded under.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Phases this run performed.
    pub fn performed(&self) -> &[String] {
        &self.performed
    }

    /// Phases this run skipped because they were already recorded.
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    /// Run one phase, in declaration order.
    ///
    /// The outcome distinguishes a phase that was ALREADY complete — where
    /// the caller continues to the next phase, which is how a resume works
    /// — from a run that has STOPPED, where no later phase may execute.
    /// Collapsing those two into one boolean makes a redelivery halt at the
    /// first recorded phase and never reach the unfinished one.
    pub async fn step<F, Fut>(&mut self, name: &str, body: F) -> Result<StepOutcome>
    where
        F: FnOnce() -> Fut,
        Fut: core::future::Future<Output = Result<()>>,
    {
        // The declaration is checked on the production path, not only in the
        // crash harness: a duplicate phase name would resolve both `step`
        // calls to the FIRST declaration and one completion record, so the
        // second body would be skipped as already done — the silent
        // half-write `validate` exists to rule out. Refusing before any
        // plane is touched makes a malformed saga fail loudly on its first
        // invocation instead.
        self.spec.validate()?;
        let index = self
            .spec
            .phases
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| {
                AlloyError::internal(format!(
                    "saga '{}' has no declared phase '{name}'; a phase that runs without \
                     a declaration has no crash-safety statement and no crash test",
                    self.spec.name
                ))
            })?;

        // Declaration order is the crash-safety statement: phases run in it, each
        // once, and nothing runs after a stop.
        if self.stopped {
            return Err(AlloyError::internal(format!(
                "saga '{}' stopped; phase '{name}' may not run after it",
                self.spec.name
            )));
        }
        if index != self.next_index {
            return Err(AlloyError::internal(format!(
                "saga '{}' ran phase '{name}' out of declaration order (phase {} is next)",
                self.spec.name, self.next_index
            )));
        }

        // A simulated crash: stop before this phase's effect, leaving every
        // earlier phase's record in place. That IS the resumable state.
        if let Some(stop) = self.stop_after {
            if index >= stop {
                self.stopped = true;
                return Ok(StepOutcome::Stopped);
            }
        }

        let key = phase_key(&self.digest, name);
        let recorded = self.ape.get(key.as_bytes()).await?;
        if recorded.is_some_and(|cell| !cell.is_empty()) {
            // Already done by an earlier delivery. The caller CONTINUES:
            // the phase this resume actually needs is a later one.
            self.skipped.push(name.to_string());
            self.next_index += 1;
            return Ok(StepOutcome::Skipped);
        }

        // The effect happens BEFORE its record, so a crash between them
        // re-runs the phase rather than skipping it. That is why a phase
        // body must be idempotent by its own observable state as well.
        body().await?;
        self.ape.commit_n(&[(key.as_bytes(), b"1")]).await?;
        self.performed.push(name.to_string());
        self.next_index += 1;
        Ok(StepOutcome::Performed)
    }

    /// Whether every declared phase is now recorded complete.
    pub async fn is_complete(&mut self) -> Result<bool> {
        let keys: Vec<String> = self
            .spec
            .phases
            .iter()
            .map(|p| phase_key(&self.digest, &p.name))
            .collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
        let cells = self.ape.multi_get(&refs).await?;
        Ok(cells
            .iter()
            .all(|c| c.as_ref().is_some_and(|v| !v.is_empty())))
    }

    /// The first phase that has not been recorded, which is where a resume
    /// re-enters.
    pub async fn next_phase(&mut self) -> Result<Option<String>> {
        let keys: Vec<String> = self
            .spec
            .phases
            .iter()
            .map(|p| phase_key(&self.digest, &p.name))
            .collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
        let cells = self.ape.multi_get(&refs).await?;
        for (i, cell) in cells.iter().enumerate() {
            if !cell.as_ref().is_some_and(|v| !v.is_empty()) {
                return Ok(Some(self.spec.phases[i].name.clone()));
            }
        }
        Ok(None)
    }
}

/// Drives a declared saga's crash matrix.
///
/// A two-phase saga has one boundary, a four-phase saga has three, and the
/// author writes a test for none of them: the matrix is derived from the
/// declaration's own shape. That is the whole point of declaring phases
/// rather than hand-writing them: writing a crash test by hand means
/// reproducing a kill between two specific writes.
///
/// # What a run proves
///
/// For each boundary `n` the harness runs the saga twice against the SAME
/// idempotency key:
///
/// 1. once stopped after `n` phases, which leaves exactly the durable
///    state a crash at that point would leave;
/// 2. once to completion, which is the redelivery.
///
/// It then asserts the property that makes a saga correct: **every phase
/// ran exactly once across the two deliveries**. A phase that re-ran was
/// not idempotent by its own observable state; a phase that never ran
/// means the resume stopped early and the work was silently abandoned.
///
/// # The boundary this is NOT enough to cover
///
/// Stopping between phases is only half the matrix. A phase records its
/// completion in a SEPARATE write from its own effect, so the other crash
/// window is *inside* a phase: the effect lands, the process dies, and the
/// completion record never appears. The redelivery then re-runs a body
/// whose effect has already happened — and nothing about the phase records
/// makes that safe, because the record is exactly what was lost.
///
/// [`crash_after_effect_of_every_phase`](SagaHarness::crash_after_effect_of_every_phase)
/// drives that window. Both are needed: this one proves the resume reaches
/// the unfinished work, and that one proves re-entering finished work is
/// harmless.
pub struct SagaHarness<'a> {
    spec: &'a SagaSpec,
}

/// What one crash point did, so a failure names the boundary it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashRun {
    /// The boundary this run crashed at: phases before it had committed.
    pub stopped_after: usize,
    /// The phases the FIRST delivery performed before the simulated crash.
    pub before: Vec<String>,
    /// The phases the redelivery performed.
    pub after: Vec<String>,
    /// The phases the redelivery recognised as already done and skipped.
    pub skipped: Vec<String>,
}

impl CrashRun {
    /// Every phase that actually executed across both deliveries.
    pub fn executed(&self) -> Vec<String> {
        let mut all = self.before.clone();
        all.extend(self.after.iter().cloned());
        all
    }
}

impl<'a> SagaHarness<'a> {
    /// Bind a harness to a declaration.
    pub fn new(spec: &'a SagaSpec) -> Self {
        Self { spec }
    }

    /// Run the saga once per declared crash boundary, resuming each time.
    ///
    /// `body` performs one phase by name and records that it ran; the
    /// caller supplies it because only the application knows what a phase
    /// does. `ape` yields a FRESH handle per delivery, because a client is
    /// not clonable and each delivery is a separate one.
    ///
    /// Returns one [`CrashRun`] per boundary. An error is returned rather
    /// than a panic, so a caller can assert on the whole matrix at once.
    pub async fn crash_between_every_phase<A, F, Fut>(
        &self,
        mut ape: A,
        mut body: F,
    ) -> Result<Vec<CrashRun>>
    where
        A: FnMut() -> ApeClusterClient,
        F: FnMut(String) -> Fut,
        Fut: core::future::Future<Output = Result<()>>,
    {
        self.spec.validate()?;
        let mut runs: Vec<CrashRun> = Vec::new();
        for stop in self.spec.crash_points() {
            // Each boundary needs its OWN durable state, or the second
            // boundary would resume the first one's completed run and
            // prove nothing at all.
            let key = format!("{}-crash-{stop}", self.spec.name);

            let before = {
                let mut saga = self.spec.run(ape(), &key).stop_after(stop);
                for phase in self.spec.phases() {
                    let name = phase.name.clone();
                    if saga.step(&name, || body(name.clone())).await?.is_stop() {
                        break;
                    }
                }
                saga.performed().to_vec()
            };

            let (after, skipped) = {
                let mut saga = self.spec.run(ape(), &key);
                for phase in self.spec.phases() {
                    let name = phase.name.clone();
                    if saga.step(&name, || body(name.clone())).await?.is_stop() {
                        break;
                    }
                }
                if !saga.is_complete().await? {
                    return Err(AlloyError::internal(format!(
                        "saga '{}' did not complete after resuming from a crash at \
                         boundary {stop}; the redelivery abandoned unfinished work",
                        self.spec.name
                    )));
                }
                (saga.performed().to_vec(), saga.skipped().to_vec())
            };

            // The property that makes a saga correct: across the crash and
            // its redelivery, every declared phase ran EXACTLY once.
            let executed: Vec<String> = before.iter().chain(after.iter()).cloned().collect();
            let declared: Vec<String> = self.spec.phases().iter().map(|p| p.name.clone()).collect();
            if executed != declared {
                return Err(AlloyError::internal(format!(
                    "saga '{}' crashed at boundary {stop} ran phases {executed:?}, \
                     but its declaration is {declared:?}; a phase was applied twice \
                     or abandoned",
                    self.spec.name
                )));
            }

            runs.push(CrashRun {
                stopped_after: stop,
                before,
                after,
                skipped,
            });
        }
        Ok(runs)
    }

    /// Run the saga once per phase, losing THAT phase's completion record.
    ///
    /// This is the crash window
    /// [`crash_between_every_phase`](Self::crash_between_every_phase)
    /// cannot reach. A phase's effect and its completion record are two
    /// writes, so a crash between them leaves the effect applied and
    /// unrecorded — and the redelivery re-enters a body whose work has
    /// already happened. Recording first would be worse: it would mark a
    /// phase complete that never ran, and no retry could discover it.
    ///
    /// So the re-entry is a PROPERTY of the design, not a defect, and what
    /// makes it safe is the phase body's own observable state: the winner's
    /// `last_action_id`, the loser's `merged_into`, the line's `applied`
    /// flag. This harness forces that re-entry to happen so the caller's
    /// own end-state assertion actually exercises it, instead of the
    /// idempotence being assumed.
    ///
    /// Each returned [`CrashRun`] names the phase whose record was lost in
    /// `after`: that is the body which ran a second time. A caller asserts
    /// on its domain state — the note count, the received quantity, the
    /// balance — and a body that was not idempotent shows up there.
    pub async fn crash_after_effect_of_every_phase<A, F, Fut>(
        &self,
        mut ape: A,
        mut body: F,
    ) -> Result<Vec<CrashRun>>
    where
        A: FnMut() -> ApeClusterClient,
        F: FnMut(String) -> Fut,
        Fut: core::future::Future<Output = Result<()>>,
    {
        self.spec.validate()?;
        let mut runs: Vec<CrashRun> = Vec::new();
        for (index, phase) in self.spec.phases().iter().enumerate() {
            // Each phase needs its own durable state, or a later run would
            // resume an earlier one's completed saga and prove nothing.
            let key = format!("{}-lost-{index}", self.spec.name);

            // The first delivery stops right after this phase: later phases have not
            // run when the crash lands, so the redelivery meets the real crash state.
            let before = {
                let mut saga = self.spec.run(ape(), &key).stop_after(index + 1);
                for p in self.spec.phases() {
                    let name = p.name.clone();
                    if saga.step(&name, || body(name.clone())).await?.is_stop() {
                        break;
                    }
                }
                saga.performed().to_vec()
            };

            // The crash: this phase's effect HAPPENED, and its completion
            // record did not land. APE offers no delete, so the cell is
            // emptied — which `step` treats as absent content, exactly as a
            // torn write would be.
            let digest = invocation_digest(self.spec.name(), &key);
            let record = phase_key(&digest, &phase.name);
            let mut handle = ape();
            handle.commit_n(&[(record.as_bytes(), b"")]).await?;

            let (after, skipped) = {
                let mut saga = self.spec.run(ape(), &key);
                for p in self.spec.phases() {
                    let name = p.name.clone();
                    if saga.step(&name, || body(name.clone())).await?.is_stop() {
                        break;
                    }
                }
                if !saga.is_complete().await? {
                    return Err(AlloyError::internal(format!(
                        "saga '{}' did not complete after losing the completion record \
                         of phase '{}'",
                        self.spec.name, phase.name
                    )));
                }
                (saga.performed().to_vec(), saga.skipped().to_vec())
            };

            // The redelivery must re-enter EXACTLY the phase whose record was
            // lost and then complete the ones the crash prevented. Re-entering
            // nothing would mean the lost record was never consulted; any other
            // sequence means the resume point is wrong.
            let expected: Vec<String> = self.spec.phases()[index..].iter().map(|p| p.name.clone()).collect();
            if after != expected {
                return Err(AlloyError::internal(format!(
                    "saga '{}' lost the completion record of phase '{}', so the \
                     redelivery had to run {expected:?}; it ran {after:?}",
                    self.spec.name, phase.name
                )));
            }

            runs.push(CrashRun {
                stopped_after: index,
                before,
                after,
                skipped,
            });
        }
        Ok(runs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merge() -> SagaSpec {
        SagaSpec::new("merge_lead")
            .phase(
                "absorb",
                "the winner holds every note and the loser is still live: duplicated, \
                 visible data that a retry reconciles",
            )
            .phase(
                "archive",
                "the merge is complete; the loser points at the winner",
            )
    }

    #[test]
    fn a_saga_enumerates_the_boundaries_a_crash_can_fall_between() {
        // Two phases have exactly one interior boundary; four have three.
        // The author writes no crash test — the count comes from the shape.
        assert_eq!(merge().crash_points(), vec![1]);

        let four = SagaSpec::new("receipt")
            .phase("a", "x")
            .phase("b", "x")
            .phase("c", "x")
            .phase("d", "x");
        assert_eq!(four.crash_points(), vec![1, 2, 3]);
    }

    #[test]
    fn a_duplicate_phase_name_is_refused() {
        // Two phases sharing one completion record would skip the second as
        // soon as the first ran, silently dropping half the write.
        let dup = SagaSpec::new("s").phase("a", "x").phase("a", "y");
        assert!(dup.validate().is_err());
    }

    #[test]
    fn a_single_phase_saga_is_refused() {
        // One write needs no saga: claiming one implies a crash-safety story
        // that does not exist.
        assert!(SagaSpec::new("s").phase("only", "x").validate().is_err());
        assert!(merge().validate().is_ok());
    }

    #[test]
    fn a_phase_name_cannot_escape_its_key_namespace() {
        let hostile = SagaSpec::new("s")
            .phase("a", "x")
            .phase("../../tagv/t/drops", "x");
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn phase_records_are_namespaced_away_from_every_other_key() {
        // These share one APE plane with tag epochs, the version guard, the
        // replay markers and the outbox index.
        let d = "a".repeat(64);
        let key = phase_key(&d, "absorb");
        assert!(key.starts_with(SAGA_PREFIX));
        assert_ne!(key, crate::alloy::tags::VERSION_KEY);
        assert!(!key.starts_with("tagv/"));
        assert!(!key.starts_with("act/"));
        assert!(!key.starts_with("outbox/"));
        assert_ne!(key, phase_key(&d, "archive"));
    }

    #[test]
    fn one_invocation_maps_to_one_digest_and_two_do_not() {
        let spec = merge();
        // The same delivery always records under the same keys, which is
        // what makes a redelivery resume rather than restart.
        assert_eq!(
            invocation_digest(spec.name(), "k1"),
            invocation_digest(spec.name(), "k1")
        );
        assert_ne!(
            invocation_digest(spec.name(), "k1"),
            invocation_digest(spec.name(), "k2")
        );
    }

    #[test]
    fn the_phase_bound_keeps_the_crash_matrix_runnable() {
        const _: () = assert!(MAX_PHASES >= 2);
        const _: () = assert!(MAX_PHASES <= 16);
        let mut spec = SagaSpec::new("wide");
        for i in 0..(MAX_PHASES + 1) {
            spec = spec.phase(format!("p{i}"), "x");
        }
        assert!(spec.validate().is_err());
    }
}
