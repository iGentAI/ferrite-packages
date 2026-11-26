//! The async approval queue with simulated outcomes.
//!
//! Side-effecting actions are *submitted*, not executed: `submit_action`
//! records the action durably and returns immediately, so the agent keeps
//! working against the author's simulated outcome and can queue dependent
//! actions. A human approves or rejects later — in bulk, at their
//! convenience. This is the deliberate answer to the failure mode where
//! synchronous approval prompts train users into blanket auto-approval.
//!
//! Vocabulary (adopted from the Cloudflare OS gatekeeper contract):
//!
//! * [`ActionKind`] — a stable tag + label, the key for per-kind
//!   auto-approval rules and future policy engines.
//! * `auto_approvable` — the AUTHOR's per-action verdict that this specific
//!   action is safe to auto-apply *if* the user opted into its kind. Both
//!   sides must agree; either alone is insufficient.
//! * `implements_revert` — the connector can undo the applied action.
//! * `await_decision` — advisory hint for actions the connector does not
//!   simulate: the harness should suspend rather than let the agent observe
//!   a world where its action "didn't happen".

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::gatekeeper::grants::CapabilityGrant;
use crate::gatekeeper::{sha256, GatekeeperError, TimestampMs};

fn digest_mismatch(id: &str) -> GatekeeperError {
    GatekeeperError::Invalid(format!(
        "action {id}: approval digest mismatch — the arguments reviewed are not the arguments queued"
    ))
}

fn illegal_transition(id: &str, from: ActionState, to: ActionState) -> GatekeeperError {
    GatekeeperError::InvalidActionTransition(format!(
        "action {id}: {from:?} -> {to:?} is not a legal transition"
    ))
}

/// The canonical digest binding an action's ARGUMENTS to its approval:
/// lowercase sha256 hex over the arguments' canonical JSON bytes
/// (`serde_json` object keys are ordered, so the bytes are deterministic).
/// The connector computes this at submit; the approving surface echoes it
/// back with the decision, so what the human saw is provably what executes.
pub fn args_digest(args: &Value) -> String {
    // Keys sorted explicitly: with serde_json's preserve_order (which feature
    // unification can switch on) equal objects would otherwise hash differently.
    // Without it the bytes are exactly serde_json's, so existing digests hold.
    let mut bytes = Vec::new();
    write_canonical(args, &mut bytes);
    sha256::to_hex(&sha256::sha256(&bytes))
}

/// Serialize with object members in sorted order whatever the map type keeps.
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).unwrap_or_default());
                out.push(b':');
                write_canonical(&map[key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => out.extend(serde_json::to_vec(other).unwrap_or_default()),
    }
}

/// A stable action classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionKind {
    /// Stable machine tag, e.g. `github.pr.open`.
    pub tag: String,
    /// Human label, e.g. `Open a pull request`.
    pub label: String,
}

impl ActionKind {
    pub fn new(tag: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            label: label.into(),
        }
    }
}

/// What a connector submits for one side-effecting action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionDescription {
    /// Short human title, e.g. `Open PR “fix flaky test” on example-org/example-repo`.
    pub title: String,
    /// Longer human description of exactly what will happen.
    pub description: String,
    /// The classification key for auto-approval policy.
    pub kind: ActionKind,
    /// The author's verdict that THIS action is safe to auto-apply if the
    /// user opted into its kind.
    pub auto_approvable: bool,
    /// The connector implements `revert_action` for this action once applied.
    pub implements_revert: bool,
    /// The connector cannot simulate this action; the harness should suspend
    /// the turn until the human decides.
    pub await_decision: bool,
    /// The simulated outcome the agent proceeds against (None when the
    /// connector does not simulate — pair with `await_decision`).
    pub simulated_outcome: Option<Value>,
    /// The action's EXACT arguments as the connector will execute them —
    /// the reviewable ground truth, not a prose summary. `Value::Null` for
    /// argument-free actions.
    #[serde(default)]
    pub args: Value,
    /// [`args_digest`] over `args`, checked at submit and again at approval:
    /// an approval carrying a stale digest (the arguments changed under the
    /// reviewer) is rejected.
    #[serde(default)]
    pub args_digest: String,
}

/// Lifecycle of a submitted action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum ActionState {
    /// Recorded, awaiting a human (or auto-approval) decision.
    Pending,
    /// Approved and applied to the external service.
    Applied,
    /// Rejected before application; simulation cleaned up.
    Rejected,
    /// Applied, then reverted via `revert_action`.
    Reverted,
    /// Application was approved but failed against the vendor.
    Failed,
}

/// A recorded action in the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct QueuedAction {
    pub id: String,
    pub description: ActionDescription,
    pub state: ActionState,
    pub submitted_at: TimestampMs,
    pub decided_at: Option<TimestampMs>,
    /// True when the transition to Applied happened through auto-approval.
    pub auto_approved: bool,
    /// The principal whose decision applied the action (None while pending,
    /// after rejection, and for auto-approvals — those record the POLICY,
    /// not a human).
    #[serde(default)]
    pub approved_by: Option<String>,
    /// The principal that submitted the action: the one named to
    /// [`ApprovalQueue::submit_action_as`], or the principal of the capability
    /// grant a connector binds to it. A record written before this field
    /// existed reads as `None`.
    #[serde(default)]
    pub submitted_by: Option<String>,
    /// Immutable vendor result identifying the exact effect an undo may target.
    /// Old records without this receipt cannot be reverted by a connector.
    #[serde(default)]
    pub(crate) applied_effect: Option<Value>,
    #[serde(default)]
    pub(crate) authority: Option<CapabilityGrant>,
    /// Set before undo I/O. If completion is unknown, retain this fence and
    /// reconcile externally; never retry the vendor operation automatically.
    #[serde(default)]
    pub revert_attempted: bool,
}

/// Per-user auto-approval opt-ins, by action-kind tag.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AutoApprovalPolicy {
    opted_in_kinds: BTreeSet<String>,
}

impl AutoApprovalPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn opt_in(&mut self, kind_tag: impl Into<String>) {
        self.opted_in_kinds.insert(kind_tag.into());
    }

    pub fn opt_out(&mut self, kind_tag: &str) {
        self.opted_in_kinds.remove(kind_tag);
    }

    /// Auto-approval requires BOTH the user's kind opt-in AND the author's
    /// per-action verdict.
    pub fn allows(&self, desc: &ActionDescription) -> bool {
        desc.auto_approvable && self.opted_in_kinds.contains(&desc.kind.tag)
    }
}

/// The outcome of deciding one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum DecisionOutcome {
    Applied,
    Rejected,
    Reverted,
    Failed { reason: String },
}

/// The approval queue: durable record of submitted actions and their fates.
///
/// The host app persists this structure (Store + APE for the guarded state
/// transitions); this crate owns the state machine.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ApprovalQueue {
    actions: BTreeMap<String, QueuedAction>,
    order: Vec<String>,
    next_seq: u64,
}

impl QueuedAction {
    pub fn applied_effect(&self) -> Option<&Value> {
        self.applied_effect.as_ref()
    }

    pub fn authority(&self) -> Option<&CapabilityGrant> {
        self.authority.as_ref()
    }
}

impl ApprovalQueue {
    fn action(&self, id: &str) -> Result<&QueuedAction, GatekeeperError> {
        self.actions
            .get(id)
            .ok_or_else(|| GatekeeperError::UnknownAction(id.to_string()))
    }

    fn action_mut(&mut self, id: &str) -> Result<&mut QueuedAction, GatekeeperError> {
        self.actions
            .get_mut(id)
            .ok_or_else(|| GatekeeperError::UnknownAction(id.to_string()))
    }

    pub(crate) fn bind_authority(
        &mut self,
        id: &str,
        grant: &CapabilityGrant,
    ) -> Result<(), GatekeeperError> {
        let a = self.action_mut(id)?;
        if a.authority.is_some() {
            return Err(GatekeeperError::Invalid(
                "action authority is immutable".into(),
            ));
        }
        a.authority = Some(grant.clone());
        // The grant's principal is who the action was submitted under.
        if a.submitted_by.is_none() {
            a.submitted_by = Some(grant.principal.clone());
        }
        Ok(())
    }

    pub(crate) fn check_authority(
        &self,
        id: &str,
        grant: &CapabilityGrant,
    ) -> Result<(), GatekeeperError> {
        if self.action(id)?.authority.as_ref() != Some(grant) {
            return Err(GatekeeperError::Invalid(
                "action grant does not match queued authority".into(),
            ));
        }
        Ok(())
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Submit an action. Returns immediately with the queued record — the
    /// caller proceeds against `description.simulated_outcome`. When the
    /// policy allows auto-approval the action is marked Applied at once and
    /// `auto_approved` is set.
    ///
    /// A connector that submits this way names its submitter by binding its
    /// capability grant to the action; any other caller uses
    /// [`Self::submit_action_as`], so the record says who asked.
    pub fn submit_action(
        &mut self,
        description: ActionDescription,
        policy: &AutoApprovalPolicy,
        now: TimestampMs,
    ) -> Result<QueuedAction, GatekeeperError> {
        self.submit(description, None, policy, now)
    }

    /// [`Self::submit_action`], recording `submitter` (the authenticated
    /// principal that asked for the action, never empty) as `submitted_by`.
    pub fn submit_action_as(
        &mut self,
        description: ActionDescription,
        submitter: &str,
        policy: &AutoApprovalPolicy,
        now: TimestampMs,
    ) -> Result<QueuedAction, GatekeeperError> {
        if submitter.trim().is_empty() {
            return Err(GatekeeperError::Invalid(
                "submitter must be non-empty".into(),
            ));
        }
        self.submit(description, Some(submitter.to_string()), policy, now)
    }

    fn submit(
        &mut self,
        description: ActionDescription,
        submitted_by: Option<String>,
        policy: &AutoApprovalPolicy,
        now: TimestampMs,
    ) -> Result<QueuedAction, GatekeeperError> {
        if description.title.is_empty() {
            return Err(GatekeeperError::Invalid(
                "action title must be non-empty".into(),
            ));
        }
        if description.await_decision && description.simulated_outcome.is_some() {
            return Err(GatekeeperError::Invalid(
                "await_decision is for unsimulated actions; simulated_outcome must be None".into(),
            ));
        }
        // The digest must cover the arguments AT SUBMIT: a wrong (or unset)
        // digest here would make every later approval unverifiable, so it is
        // refused up front. Authors compute it with [`args_digest`].
        if description.args_digest != args_digest(&description.args) {
            return Err(GatekeeperError::Invalid(
                "args_digest does not match args — compute it with actions::args_digest".into(),
            ));
        }
        self.next_seq += 1;
        let id = format!("act-{:08}", self.next_seq);
        let auto = policy.allows(&description);
        let rec = QueuedAction {
            id: id.clone(),
            description,
            state: if auto {
                ActionState::Applied
            } else {
                ActionState::Pending
            },
            submitted_at: now,
            decided_at: if auto { Some(now) } else { None },
            auto_approved: auto,
            approved_by: None,
            submitted_by,
            applied_effect: None,
            authority: None,
            revert_attempted: false,
        };
        self.actions.insert(id.clone(), rec.clone());
        self.order.push(id);
        Ok(rec)
    }

    pub fn get(&self, id: &str) -> Option<&QueuedAction> {
        self.actions.get(id)
    }

    /// All actions pending a decision, in submission order — the bulk-review
    /// surface.
    pub fn pending(&self) -> Vec<&QueuedAction> {
        self.order
            .iter()
            .filter_map(|id| self.actions.get(id))
            .filter(|a| a.state == ActionState::Pending)
            .collect()
    }

    /// Approve one pending action (human decision). `approver` is the
    /// deciding principal, recorded as `approved_by`: the queue cannot
    /// authenticate it, so the calling surface passes the principal its own
    /// session verified, never a value from the request; `args_digest` is the
    /// digest of the arguments the approver REVIEWED — it must match the
    /// queued action's digest, so an approval replayed against changed
    /// arguments (or minted without seeing them) is rejected, not applied.
    /// The caller applies the real side effect; a vendor failure is
    /// recorded with `record_failure`.
    pub fn approve(
        &mut self,
        id: &str,
        approver: &str,
        args_digest: &str,
        now: TimestampMs,
    ) -> Result<&QueuedAction, GatekeeperError> {
        if approver.is_empty() {
            return Err(GatekeeperError::Invalid(
                "approver must be non-empty".into(),
            ));
        }
        if self.action(id)?.description.args_digest != args_digest {
            return Err(digest_mismatch(id));
        }
        self.transition(id, ActionState::Pending, ActionState::Applied, now)?;
        let a = self.action_mut(id)?;
        a.approved_by = Some(approver.to_string());
        Ok(&*a)
    }

    /// Reject one pending action: the simulation is cleaned up, nothing was
    /// ever applied.
    pub fn reject(&mut self, id: &str, now: TimestampMs) -> Result<&QueuedAction, GatekeeperError> {
        self.transition(id, ActionState::Pending, ActionState::Rejected, now)
    }

    /// Queue-only undo cannot certify a vendor effect. Use the owning connector.
    pub fn revert(&mut self, _id: &str, _now: TimestampMs) -> Result<&QueuedAction, GatekeeperError> {
        Err(GatekeeperError::InvalidActionTransition("vendor-confirmed connector undo required".into()))
    }

    pub(crate) fn record_applied_effect(
        &mut self,
        id: &str,
        mut effect: Value,
    ) -> Result<(), GatekeeperError> {
        let a = self.action_mut(id)?;
        if a.state != ActionState::Applied || a.applied_effect.is_some() || a.revert_attempted {
            return Err(GatekeeperError::InvalidActionTransition(
                "effect receipt is immutable and requires an applied action".into(),
            ));
        }
        let grant = a.authority.as_ref().ok_or_else(|| {
            GatekeeperError::Invalid("effect requires queued authority".into())
        })?;
        let object = effect
            .as_object_mut()
            .ok_or_else(|| GatekeeperError::Invalid("effect must be an object".into()))?;
        object.insert("grant_id".into(), serde_json::json!(grant.id));
        object.insert("principal".into(), serde_json::json!(grant.principal));
        object.insert("grant_epoch".into(), serde_json::json!(grant.epoch));
        object.insert("grant_not_after".into(), serde_json::json!(grant.not_after));
        a.applied_effect = Some(effect);
        Ok(())
    }

    pub fn check_revert_state(&self, id: &str) -> Result<(), GatekeeperError> {
        let state = self.action(id)?.state;
        if state != ActionState::Applied {
            return Err(illegal_transition(id, state, ActionState::Reverted));
        }
        Ok(())
    }

    pub(crate) fn begin_revert(&mut self, id: &str) -> Result<(), GatekeeperError> {
        self.check_revert_state(id)?;
        let a = self.action_mut(id)?;
        if !a.description.implements_revert || a.applied_effect.is_none() || a.revert_attempted {
            return Err(GatekeeperError::InvalidActionTransition(
                "revert requires an applied receipt and no previous revert attempt".into(),
            ));
        }
        a.revert_attempted = true;
        Ok(())
    }

    /// Only a vendor's typed, completed no-effect refusal may release this fence.
    pub(crate) fn revert_refused_without_effect(
        &mut self,
        id: &str,
    ) -> Result<(), GatekeeperError> {
        let a = self.action_mut(id)?;
        if a.state != ActionState::Applied || !a.revert_attempted {
            return Err(GatekeeperError::InvalidActionTransition(
                "no pending undo".into(),
            ));
        }
        a.revert_attempted = false;
        Ok(())
    }

    pub(crate) fn finish_revert(&mut self, id: &str, now: TimestampMs) -> Result<&QueuedAction, GatekeeperError> {
        if !self.actions.get(id).is_some_and(|a| a.revert_attempted) {
            return Err(GatekeeperError::InvalidActionTransition("revert was not started".into()));
        }
        self.transition(id, ActionState::Applied, ActionState::Reverted, now)
    }

    /// Record that an approved application failed against the vendor. Only
    /// an Applied action can fail: a Pending action leaves the queue only
    /// through a human (or auto-approval) decision.
    pub fn record_failure(
        &mut self,
        id: &str,
        now: TimestampMs,
    ) -> Result<&QueuedAction, GatekeeperError> {
        let a = self.action(id)?;
        if a.applied_effect.is_some() || a.revert_attempted {
            return Err(GatekeeperError::InvalidActionTransition(
                "an action with a recorded vendor effect or a started undo cannot be marked failed"
                    .into(),
            ));
        }
        self.transition(id, ActionState::Applied, ActionState::Failed, now)
    }

    /// Approve every listed pending action — bulk decision. Each entry is
    /// `(id, args_digest)` so a bulk approval binds arguments and approver
    /// exactly like a single one.
    ///
    /// All or nothing: every entry is checked (known id, matching digest,
    /// still Pending, listed once) before any is approved, so a refused
    /// batch leaves every action as it was.
    pub fn approve_all(
        &mut self,
        decisions: &[(String, String)],
        approver: &str,
        now: TimestampMs,
    ) -> Result<usize, GatekeeperError> {
        if approver.is_empty() {
            return Err(GatekeeperError::Invalid(
                "approver must be non-empty".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (id, digest) in decisions {
            if !seen.insert(id.as_str()) {
                return Err(GatekeeperError::InvalidActionTransition(format!(
                    "action {id} is listed twice in one bulk approval"
                )));
            }
            let a = self.action(id)?;
            if &a.description.args_digest != digest {
                return Err(digest_mismatch(id));
            }
            if a.state != ActionState::Pending {
                return Err(illegal_transition(id, a.state, ActionState::Applied));
            }
        }
        for (id, digest) in decisions {
            self.approve(id, approver, digest, now)?;
        }
        Ok(decisions.len())
    }

    fn transition(
        &mut self,
        id: &str,
        from: ActionState,
        to: ActionState,
        now: TimestampMs,
    ) -> Result<&QueuedAction, GatekeeperError> {
        let a = self.action_mut(id)?;
        if a.state != from {
            return Err(illegal_transition(id, a.state, to));
        }
        a.state = to;
        a.decided_at = Some(now);
        Ok(&*a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json;

    #[test]
    fn the_queue_records_who_submitted_an_action() {
        let mut q = ApprovalQueue::new();
        let policy = AutoApprovalPolicy::new();
        assert!(q.submit_action_as(open_pr(), "  ", &policy, 1).is_err());
        let rec = q.submit_action_as(open_pr(), "user:alice", &policy, 1).unwrap();
        assert_eq!(rec.submitted_by.as_deref(), Some("user:alice"));
        let anonymous = q.submit_action(open_pr(), &policy, 2).unwrap();
        assert_eq!(anonymous.submitted_by, None);
        // A record written before the field existed still decodes.
        let mut legacy = serde_json::to_value(&rec).unwrap();
        legacy.as_object_mut().unwrap().remove("submitted_by");
        let back: QueuedAction = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.submitted_by, None);
    }

    fn open_pr() -> ActionDescription {
        let args = serde_json::json!({"repo": "a/b", "head": "fix", "base": "main"});
        ActionDescription {
            title: "Open PR 'fix' on a/b".into(),
            description: "Opens a pull request from branch fix to main".into(),
            kind: ActionKind::new("github.pr.open", "Open a pull request"),
            auto_approvable: true,
            implements_revert: true,
            await_decision: false,
            simulated_outcome: Some(serde_json::json!({"number": 101, "simulated": true})),
            args_digest: args_digest(&args),
            args,
        }
    }

    #[test]
    fn submit_returns_immediately_with_simulation() {
        let mut q = ApprovalQueue::new();
        let rec = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        assert_eq!(rec.state, ActionState::Pending);
        assert_eq!(
            rec.description.simulated_outcome.as_ref().unwrap()["number"],
            serde_json::json!(101)
        );
        assert_eq!(q.pending().len(), 1);
    }

    #[test]
    fn bulk_approve_then_revert() {
        let mut q = ApprovalQueue::new();
        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        let b = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 11)
            .unwrap();
        let digest = open_pr().args_digest;
        q.approve_all(
            &[(a.id.clone(), digest.clone()), (b.id.clone(), digest)],
            "reviewer@labs",
            20,
        )
        .unwrap();
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Applied);
        assert_eq!(
            q.get(&a.id).unwrap().approved_by.as_deref(),
            Some("reviewer@labs")
        );
        assert!(q.revert(&a.id, 30).is_err());
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Applied);
    }

    #[test]
    fn reject_cleans_up_pending() {
        let mut q = ApprovalQueue::new();
        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        // Revert before apply is refused: there is nothing to revert.
        assert!(matches!(
            q.revert(&a.id, 15),
            Err(GatekeeperError::InvalidActionTransition(_))
        ));
        q.reject(&a.id, 20).unwrap();
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Rejected);
        assert_eq!(q.get(&a.id).unwrap().approved_by, None);
        // Rejecting again is an invalid transition, not a silent no-op.
        assert!(matches!(
            q.reject(&a.id, 25),
            Err(GatekeeperError::InvalidActionTransition(_))
        ));
        // A rejected action cannot be approved afterwards.
        assert!(q
            .approve(&a.id, "reviewer@labs", &open_pr().args_digest, 30)
            .is_err());
    }

    /// The approval is bound to the ARGUMENTS the approver reviewed: a
    /// mismatched digest is refused before any transition, and the digest
    /// itself is validated at submit so it can never be a rubber stamp.
    #[test]
    fn approval_is_bound_to_args_digest_and_approver() {
        let mut q = ApprovalQueue::new();
        // A wrong digest at submit is refused up front.
        let mut desc = open_pr();
        desc.args_digest = "deadbeef".into();
        assert!(q
            .submit_action(desc, &AutoApprovalPolicy::new(), 9)
            .is_err());

        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        // Approving with a digest over DIFFERENT arguments is refused and
        // the action stays pending.
        let other = args_digest(&serde_json::json!({"repo": "a/b", "head": "fix", "base": "release"}));
        assert!(q.approve(&a.id, "reviewer@labs", &other, 20).is_err());
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Pending);
        // An anonymous approval is refused.
        assert!(q
            .approve(&a.id, "", &a.description.args_digest, 20)
            .is_err());
        // The matching digest applies and records who decided.
        let decided = q
            .approve(&a.id, "reviewer@labs", &a.description.args_digest, 21)
            .unwrap();
        assert_eq!(decided.state, ActionState::Applied);
        assert_eq!(decided.approved_by.as_deref(), Some("reviewer@labs"));
    }

    #[test]
    fn auto_approval_needs_both_sides() {
        let mut q = ApprovalQueue::new();
        // User opted in, author says auto_approvable: auto-applied.
        let mut pol = AutoApprovalPolicy::new();
        pol.opt_in("github.pr.open");
        let rec = q.submit_action(open_pr(), &pol, 10).unwrap();
        assert_eq!(rec.state, ActionState::Applied);
        assert!(rec.auto_approved);
        assert_eq!(
            rec.approved_by, None,
            "auto-approval records the policy, not a human"
        );
        // Author refuses even though the user opted in.
        let mut desc = open_pr();
        desc.auto_approvable = false;
        let rec = q.submit_action(desc, &pol, 11).unwrap();
        assert_eq!(rec.state, ActionState::Pending);
        // User never opted in even though the author allows.
        let rec = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 12)
            .unwrap();
        assert_eq!(rec.state, ActionState::Pending);
    }

    #[test]
    fn await_decision_requires_no_simulation() {
        let mut q = ApprovalQueue::new();
        let mut desc = open_pr();
        desc.await_decision = true; // but simulated_outcome is Some -> invalid
        assert!(q
            .submit_action(desc, &AutoApprovalPolicy::new(), 10)
            .is_err());
        let mut desc = open_pr();
        desc.await_decision = true;
        desc.simulated_outcome = None;
        let rec = q
            .submit_action(desc, &AutoApprovalPolicy::new(), 10)
            .unwrap();
        assert!(rec.description.await_decision);
    }

    #[test]
    fn revert_requires_declared_support() {
        let mut q = ApprovalQueue::new();
        let mut desc = open_pr();
        desc.implements_revert = false;
        let a = q
            .submit_action(desc, &AutoApprovalPolicy::new(), 10)
            .unwrap();
        q.approve(&a.id, "reviewer@labs", &a.description.args_digest, 20)
            .unwrap();
        assert!(q.revert(&a.id, 30).is_err());
    }

    /// F476: a submitter cannot move its own Pending action to Failed and
    /// out of the review queue; only an Applied action can fail.
    #[test]
    fn record_failure_refuses_a_pending_action() {
        let mut q = ApprovalQueue::new();
        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        let err = q.record_failure(&a.id, 11).unwrap_err();
        assert!(matches!(err, GatekeeperError::InvalidActionTransition(_)));
        let rec = q.get(&a.id).unwrap();
        assert_eq!(rec.state, ActionState::Pending);
        assert_eq!(rec.decided_at, None);
        assert_eq!(q.pending().len(), 1);
        // After approval, a vendor failure is recorded as before.
        q.approve(&a.id, "reviewer@labs", &a.description.args_digest, 12)
            .unwrap();
        assert_eq!(q.record_failure(&a.id, 13).unwrap().state, ActionState::Failed);
    }

    /// F477: a bulk approval that fails on any entry approves none of them.
    #[test]
    fn approve_all_is_all_or_nothing() {
        let mut q = ApprovalQueue::new();
        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        let b = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 11)
            .unwrap();
        let digest = open_pr().args_digest;
        // The second entry carries a stale digest.
        let err = q
            .approve_all(
                &[
                    (a.id.clone(), digest.clone()),
                    (b.id.clone(), "stale".into()),
                ],
                "reviewer@labs",
                20,
            )
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::Invalid(_)));
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Pending);
        assert_eq!(q.get(&a.id).unwrap().approved_by, None);
        assert_eq!(q.pending().len(), 2);
        // Unknown ids and duplicates are refused the same way.
        assert!(q
            .approve_all(
                &[(a.id.clone(), digest.clone()), ("act-missing".into(), digest.clone())],
                "reviewer@labs",
                21,
            )
            .is_err());
        assert!(q
            .approve_all(
                &[(a.id.clone(), digest.clone()), (a.id.clone(), digest.clone())],
                "reviewer@labs",
                22,
            )
            .is_err());
        assert_eq!(q.pending().len(), 2);
        // The corrected batch then approves both.
        assert_eq!(
            q.approve_all(
                &[(a.id.clone(), digest.clone()), (b.id.clone(), digest)],
                "reviewer@labs",
                23,
            )
            .unwrap(),
            2
        );
        assert!(q.pending().is_empty());
    }

    #[test]
    fn record_failure_cannot_overwrite_an_applied_effect_or_a_started_undo() {
        let mut q = ApprovalQueue::new();
        let a = q
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        let digest = a.description.args_digest.clone();
        q.approve(&a.id, "alice", &digest, 11).unwrap();
        // A receipt has been recorded for the live vendor effect.
        q.action_mut(&a.id).unwrap().applied_effect = Some(serde_json::json!({"pr": 7}));
        assert!(matches!(
            q.record_failure(&a.id, 12),
            Err(GatekeeperError::InvalidActionTransition(_))
        ));
        assert_eq!(q.get(&a.id).unwrap().state, ActionState::Applied);
        assert_eq!(q.get(&a.id).unwrap().decided_at, Some(11));
        // An undo in progress is fenced the same way.
        let mut q2 = ApprovalQueue::new();
        let b = q2
            .submit_action(open_pr(), &AutoApprovalPolicy::new(), 10)
            .unwrap();
        let digest = b.description.args_digest.clone();
        q2.approve(&b.id, "alice", &digest, 11).unwrap();
        q2.action_mut(&b.id).unwrap().revert_attempted = true;
        assert!(q2.record_failure(&b.id, 12).is_err());
        assert_eq!(q2.get(&b.id).unwrap().state, ActionState::Applied);
    }
}
