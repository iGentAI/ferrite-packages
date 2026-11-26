//! Observation authorization: every connector read is authorized *before*
//! data is returned to the caller.
//!
//! An [`ObservationDescription`] names what is about to be read; the
//! [`ObservationAuthorizer`] decides whether the read may proceed given the
//! registered observers, records an audit entry either way, and accumulates
//! the sharing posture of everything observed so far:
//!
//! * `prohibit_all_sharing` — one maximally sensitive observation makes the
//!   consuming surface unshareable and locked down (lockdown: reads only, no
//!   further side effects).
//! * `exclude_observers` — a milder form naming specific recipients who may
//!   not see this observation. It holds in both orders: a named recipient
//!   who is already registered is excluded from (or blocks) the read, and
//!   one who is not yet registered is refused registration later, because
//!   the surface already holds data they must not see.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::gatekeeper::{GatekeeperError, TimestampMs};

const MAX_AUDIT_FIELD_BYTES: usize = 512;
const MAX_AUDIT_NAME_BYTES: usize = 128;
const MAX_AUDIT_NAMES: usize = 32;
const MAX_RETAINED_REFUSALS: usize = 32;

fn clip(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn clip_names(names: &mut Vec<String>) {
    names.truncate(MAX_AUDIT_NAMES);
    for name in names {
        clip(name, MAX_AUDIT_NAME_BYTES);
    }
}

fn is_refusal(record: &AuditRecord) -> bool {
    matches!(record.decision, ObservationDecision::Blocked { .. })
}

/// The sharing posture one observation carries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct SharingPolicy {
    /// This observation is maximally sensitive: the consuming artifact
    /// becomes unshareable and locked down.
    pub prohibit_all_sharing: bool,
    /// Specific recipients who may not see this observation.
    pub exclude_observers: Vec<String>,
}

/// A description of one read, submitted before the data moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ObservationDescription {
    /// Resource kind, e.g. `github.repo`.
    pub kind: String,
    /// The unit read, e.g. `example-org/example-repo`.
    pub unit: String,
    /// A sub-resource within the unit when the strategy tracks datasets
    /// (e.g. a table, a page). Empty for single-unit reads.
    pub sub_resource: String,
    /// Human summary of what is being read.
    pub summary: String,
    /// The sharing posture this observation carries.
    pub policy: SharingPolicy,
}

/// The authorizer's decision for one observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum ObservationDecision {
    /// The read proceeds; data may be returned to the caller.
    Allowed,
    /// The read proceeds but the named observers must not see the result.
    AllowedExcluding(Vec<String>),
    /// The read is blocked: at least one registered observer may not see it
    /// and exclusion was not possible.
    Blocked { reason: String },
}

/// One audit record. Every authorization attempt writes one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AuditRecord {
    pub at: TimestampMs,
    pub description: ObservationDescription,
    pub decision: ObservationDecision,
}

/// The per-surface observation authorizer and audit trail.
///
/// One authorizer exists per consuming surface (an agent session, a shared
/// artifact). It remembers everything observed so far, which is what observer
/// verification replays (`crate::gatekeeper::observers`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ObservationAuthorizer {
    /// Everything observed so far (allowed observations only).
    observed: Vec<ObservationDescription>,
    /// The audit trail: every attempt, allowed or blocked.
    audit: Vec<AuditRecord>,
    /// Total refused attempts, including entries evicted from the small refusal ring.
    #[serde(default)]
    refused_attempts: u64,
    /// Observers currently registered on the consuming surface.
    observers: BTreeSet<String>,
    /// Set once a `prohibit_all_sharing` observation lands.
    locked_down: bool,
    /// Recipients named in `exclude_observers` of an allowed observation
    /// while they were NOT registered: the surface holds data they must not
    /// see, so they may never be registered on it.
    #[serde(default)]
    denied_observers: BTreeSet<String>,
}

impl ObservationAuthorizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Why `observer` may not be registered on this surface, if anything:
    /// the surface is locked down, or it already observed data whose policy
    /// excludes `observer` (recorded while they were not registered). An
    /// already-registered observer re-registers freely: exclusions naming
    /// them were enforced when the data was read.
    pub fn registration_refusal(&self, observer: &str) -> Option<GatekeeperError> {
        if self.locked_down {
            return Some(GatekeeperError::SharingProhibited(
                "surface is locked down by a prohibit_all_sharing observation".into(),
            ));
        }
        if !self.observers.contains(observer) && self.denied_observers.contains(observer) {
            return Some(GatekeeperError::SharingProhibited(format!(
                "surface already observed data whose sharing policy excludes {observer}"
            )));
        }
        None
    }

    /// Register a recipient of the consuming surface. Fails when the surface
    /// is already locked down — a lockdown artifact is unshareable — or when
    /// it observed data excluding this recipient.
    pub fn register_observer(
        &mut self,
        observer: impl Into<String>,
    ) -> Result<(), GatekeeperError> {
        let observer = observer.into();
        if let Some(refusal) = self.registration_refusal(&observer) {
            return Err(refusal);
        }
        self.observers.insert(observer);
        Ok(())
    }

    /// Drop a recipient (e.g. after a failed re-verification). Returns
    /// whether they were registered.
    pub fn unregister_observer(&mut self, observer: &str) -> bool {
        self.observers.remove(observer)
    }

    pub fn observers(&self) -> impl Iterator<Item = &String> {
        self.observers.iter()
    }

    pub fn is_locked_down(&self) -> bool {
        self.locked_down
    }

    /// Everything observed so far (the history observer verification replays).
    pub fn observed(&self) -> &[ObservationDescription] {
        &self.observed
    }

    pub fn audit_trail(&self) -> &[AuditRecord] {
        &self.audit
    }

    pub fn refused_attempts(&self) -> u64 { self.refused_attempts }

    // Refusals cannot evict allowed audit evidence or sharing authority history.
    fn push_audit(&mut self, mut record: AuditRecord) {
        let description = &mut record.description;
        for s in [
            &mut description.kind,
            &mut description.unit,
            &mut description.sub_resource,
            &mut description.summary,
        ] {
            clip(s, MAX_AUDIT_FIELD_BYTES);
        }
        clip_names(&mut description.policy.exclude_observers);
        match &mut record.decision {
            ObservationDecision::Blocked { reason } => clip(reason, MAX_AUDIT_FIELD_BYTES),
            ObservationDecision::AllowedExcluding(names) => clip_names(names),
            ObservationDecision::Allowed => {}
        }
        if is_refusal(&record) {
            self.refused_attempts = self.refused_attempts.saturating_add(1);
            while self.audit.iter().filter(|a| is_refusal(a)).count() >= MAX_RETAINED_REFUSALS {
                let index = self
                    .audit
                    .iter()
                    .position(is_refusal)
                    .expect("a refusal exists");
                self.audit.remove(index);
            }
        }
        self.audit.push(record);
    }

    /// Record a connector admission or observer refusal without recording any data as read.
    pub fn record_refusal(
        &mut self,
        description: ObservationDescription,
        reason: String,
        now: TimestampMs,
    ) {
        self.push_audit(AuditRecord {
            at: now,
            description,
            decision: ObservationDecision::Blocked { reason },
        });
    }

    /// Authorize one observation before its data is returned.
    ///
    /// Rules:
    /// 1. A locked-down surface still reads (lockdown blocks sharing and side
    ///    effects, not reads), but every new observation is implicitly
    ///    unshared — there are no observers on a locked surface.
    /// 2. An observation excluding a registered observer is BLOCKED unless
    ///    the caller can honor per-recipient exclusion (`allow_exclusion`).
    /// 3. A `prohibit_all_sharing` observation is refused outright while
    ///    observers are registered — the artifact is already shared and
    ///    cannot retroactively unshare.
    pub fn authorize_observation(
        &mut self,
        description: ObservationDescription,
        allow_exclusion: bool,
        now: TimestampMs,
    ) -> ObservationDecision {
        let decision = self.decide(&description, allow_exclusion);
        self.push_audit(AuditRecord {
            at: now,
            description: description.clone(),
            decision: decision.clone(),
        });
        match &decision {
            ObservationDecision::Allowed | ObservationDecision::AllowedExcluding(_) => {
                if description.policy.prohibit_all_sharing {
                    self.locked_down = true;
                }
                // Exclusions naming recipients who are not registered yet
                // are remembered, so they cannot be registered later.
                for excluded in &description.policy.exclude_observers {
                    if !self.observers.contains(excluded) {
                        self.denied_observers.insert(excluded.clone());
                    }
                }
                self.observed.push(description);
            }
            ObservationDecision::Blocked { .. } => {}
        }
        decision
    }

    fn decide(
        &self,
        description: &ObservationDescription,
        allow_exclusion: bool,
    ) -> ObservationDecision {
        if description.policy.prohibit_all_sharing {
            if self.observers.is_empty() {
                return ObservationDecision::Allowed;
            }
            return ObservationDecision::Blocked {
                reason: "prohibit_all_sharing observation on an already-shared surface".into(),
            };
        }
        let excluded: Vec<String> = description
            .policy
            .exclude_observers
            .iter()
            .filter(|o| self.observers.contains(*o))
            .cloned()
            .collect();
        if excluded.is_empty() {
            return ObservationDecision::Allowed;
        }
        if allow_exclusion {
            ObservationDecision::AllowedExcluding(excluded)
        } else {
            ObservationDecision::Blocked {
                reason: format!(
                    "observation excludes registered observer(s) {} and exclusion is not supported here",
                    excluded.join(", ")
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(summary: &str) -> ObservationDescription {
        ObservationDescription {
            kind: "github.repo".into(),
            unit: "a/b".into(),
            sub_resource: String::new(),
            summary: summary.into(),
            policy: SharingPolicy::default(),
        }
    }


    #[test]
    fn refusal_flood_retains_allowed_audit_and_bounds_only_refusals() {
        let mut a=ObservationAuthorizer::new();
        let description=ObservationDescription{kind:"google.doc".into(),unit:"accepted".into(),sub_resource:String::new(),summary:"read".into(),policy:SharingPolicy::default()};
        assert_eq!(a.authorize_observation(description.clone(),false,0),ObservationDecision::Allowed);
        for i in 0..300 {a.record_refusal(description.clone(),"denied".repeat(1000),i+1);}
        assert_eq!(a.refused_attempts(),300);assert_eq!(a.audit_trail().len(),33);
        assert_eq!(a.audit_trail()[0].decision,ObservationDecision::Allowed);assert_eq!(a.observed().len(),1);
        assert!(a.audit_trail().iter().all(|a|match &a.decision{ObservationDecision::Blocked{reason}=>reason.len()<=512,_=>true}));
    }
    #[test]
    fn plain_read_is_allowed_and_audited() {
        let mut auth = ObservationAuthorizer::new();
        let d = auth.authorize_observation(obs("read issues"), false, 10);
        assert_eq!(d, ObservationDecision::Allowed);
        assert_eq!(auth.observed().len(), 1);
        assert_eq!(auth.audit_trail().len(), 1);
    }

    #[test]
    fn prohibit_all_sharing_locks_the_surface() {
        let mut auth = ObservationAuthorizer::new();
        let mut o = obs("read salaries");
        o.policy.prohibit_all_sharing = true;
        assert_eq!(
            auth.authorize_observation(o, false, 10),
            ObservationDecision::Allowed
        );
        assert!(auth.is_locked_down());
        // Locked surfaces cannot gain observers.
        assert!(auth.register_observer("bob").is_err());
    }

    #[test]
    fn sensitive_read_refused_on_shared_surface() {
        let mut auth = ObservationAuthorizer::new();
        auth.register_observer("bob").unwrap();
        let mut o = obs("read salaries");
        o.policy.prohibit_all_sharing = true;
        let d = auth.authorize_observation(o, false, 10);
        assert!(matches!(d, ObservationDecision::Blocked { .. }));
        assert_eq!(auth.observed().len(), 0);
        assert_eq!(auth.audit_trail().len(), 1); // blocked attempts audit too
    }

    #[test]
    fn exclusion_names_only_registered_observers() {
        let mut auth = ObservationAuthorizer::new();
        auth.register_observer("bob").unwrap();
        let mut o = obs("read partner deals");
        o.policy.exclude_observers = vec!["bob".into(), "carol".into()];
        // With exclusion support: allowed, excluding bob (carol is not registered).
        let d = auth.authorize_observation(o.clone(), true, 10);
        assert_eq!(d, ObservationDecision::AllowedExcluding(vec!["bob".into()]));
        // Without exclusion support: blocked.
        let d = auth.authorize_observation(o, false, 11);
        assert!(matches!(d, ObservationDecision::Blocked { .. }));
    }

    #[test]
    fn exclusion_of_unregistered_recipient_is_noop() {
        let mut auth = ObservationAuthorizer::new();
        let mut o = obs("read x");
        o.policy.exclude_observers = vec!["mallory".into()];
        assert_eq!(
            auth.authorize_observation(o, false, 10),
            ObservationDecision::Allowed
        );
    }

    /// F183: an exclusion recorded before the recipient registered still
    /// keeps them off the surface.
    #[test]
    fn excluded_recipient_cannot_register_after_the_observation() {
        let mut auth = ObservationAuthorizer::new();
        let mut o = obs("read partner deals");
        o.policy.exclude_observers = vec!["bob".into()];
        assert_eq!(
            auth.authorize_observation(o, false, 10),
            ObservationDecision::Allowed
        );
        let err = auth.register_observer("bob").unwrap_err();
        assert!(matches!(err, GatekeeperError::SharingProhibited(_)));
        assert_eq!(auth.observers().count(), 0);
        // Someone the policy does not name is unaffected.
        auth.register_observer("carol").unwrap();
    }

    /// A recipient who was registered when the exclusion was honoured
    /// (AllowedExcluding) keeps re-registering: the surface already hides
    /// that data from them.
    #[test]
    fn honoured_exclusion_does_not_block_reregistration() {
        let mut auth = ObservationAuthorizer::new();
        auth.register_observer("bob").unwrap();
        let mut o = obs("read partner deals");
        o.policy.exclude_observers = vec!["bob".into()];
        assert_eq!(
            auth.authorize_observation(o, true, 10),
            ObservationDecision::AllowedExcluding(vec!["bob".into()])
        );
        auth.register_observer("bob").unwrap();
        assert!(auth.unregister_observer("bob"));
        assert!(!auth.unregister_observer("bob"));
    }
}
