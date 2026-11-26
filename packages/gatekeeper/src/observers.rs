//! The observer model: sharing a surface must never grant access to data the
//! recipient couldn't already read.
//!
//! When Bob opens a surface Alice shared, Bob supplies his OWN connected
//! account per connector; the connector verifies Bob can directly read
//! everything the surface has historically observed. Verification re-runs on
//! every open (catching upstream revocation), and afterwards any new
//! observation at least one registered observer may not see is blocked (or
//! names them in `exclude_observers`).
//!
//! Verification also honours each observation's recorded
//! [`SharingPolicy`](crate::gatekeeper::observations::SharingPolicy): a
//! history containing a `prohibit_all_sharing` observation is never
//! shareable, and an observer named in an observation's `exclude_observers`
//! is refused. Connectors that also keep an
//! [`ObservationAuthorizer`] register through
//! [`ObserverRegistry::admit_observer`], which updates both in one step so a
//! refusal on either side leaves no partial registration.
//!
//! The verification strategy is chosen per resource type:
//!
//! | Strategy | Meaning | Examples |
//! |---|---|---|
//! | A `PrivateOnly` | never shareable | Gmail, ZoomInfo |
//! | B `SingleUnitAcl` | one ACL check on the unit | GitHub repo, Google Doc |
//! | C `DataSetTracking` | verify each touched sub-resource | BigQuery datasets, Notion workspaces |
//! | D `LowStakesNoOp` | verification is a no-op | Spotify, Home Assistant |

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::gatekeeper::observations::{ObservationAuthorizer, ObservationDescription};
use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Per-resource-kind verification strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum VerificationStrategy {
    /// A: this kind is private-only; a surface that observed it is never
    /// shareable.
    PrivateOnly,
    /// B: one ACL check against the unit (repo, document).
    SingleUnitAcl,
    /// C: the connector logged touched sub-resources; verify each one.
    DataSetTracking,
    /// D: low-stakes; verification passes without a vendor call.
    LowStakesNoOp,
}

/// The result of one observer verification pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ObserverVerification {
    pub observer: String,
    pub verified_at: TimestampMs,
    /// Units checked, in order, with the strategy used.
    pub checked: Vec<(String, String)>, // (kind, unit-or-subresource)
}

/// The connector-side access checker: "can `observer` directly read
/// `kind`/`unit` with their own credentials?"
///
/// Implemented by each connector against its vendor; tests use closures.
pub trait AccessVerifier {
    fn can_read(&self, observer: &str, kind: &str, unit: &str) -> bool;
}

impl<F: Fn(&str, &str, &str) -> bool> AccessVerifier for F {
    fn can_read(&self, observer: &str, kind: &str, unit: &str) -> bool {
        self(observer, kind, unit)
    }
}

/// Registry of observers on one shared surface, with per-kind strategies.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ObserverRegistry {
    strategies: BTreeMap<String, VerificationStrategy>,
    verified: BTreeMap<String, ObserverVerification>,
}

impl ObserverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the strategy for a resource kind.
    pub fn set_strategy(&mut self, kind: impl Into<String>, strategy: VerificationStrategy) {
        self.strategies.insert(kind.into(), strategy);
    }

    pub fn strategy_for(&self, kind: &str) -> Option<VerificationStrategy> {
        self.strategies.get(kind).copied()
    }

    pub fn verified_observers(&self) -> impl Iterator<Item = &String> {
        self.verified.keys()
    }

    /// Add (or re-verify) an observer against everything historically
    /// observed. Throws when the observer cannot directly read any observed
    /// unit — sharing must not widen access — when the history holds a
    /// `prohibit_all_sharing` observation, or when an observation's
    /// `exclude_observers` names this observer.
    ///
    /// Call this on EVERY open, not only the first: upstream revocation must
    /// surface as a failed re-verification.
    pub fn add_observer(
        &mut self,
        observer: &str,
        history: &[ObservationDescription],
        verifier: &dyn AccessVerifier,
        now: TimestampMs,
    ) -> Result<ObserverVerification, GatekeeperError> {
        self.verify(observer, history, verifier, now, true)
    }

    /// Register `observer` on a surface whose reads go through `authorizer`,
    /// verifying them against its history, atomically: on success the
    /// observer is verified here AND registered on the authorizer; on any
    /// refusal (lockdown, an exclusion naming them, a failed access check)
    /// they are removed from both, so the two never disagree.
    ///
    /// Exclusions are judged by the authorizer, which knows whether an
    /// exclusion was honoured for an observer already registered at read
    /// time; the per-kind access checks run here.
    pub fn admit_observer(
        &mut self,
        observer: &str,
        authorizer: &mut ObservationAuthorizer,
        verifier: &dyn AccessVerifier,
        now: TimestampMs,
    ) -> Result<ObserverVerification, GatekeeperError> {
        let outcome = match authorizer.registration_refusal(observer) {
            Some(refusal) => Err(refusal),
            None => self.verify(observer, authorizer.observed(), verifier, now, false),
        };
        match outcome {
            Ok(v) => {
                authorizer.register_observer(observer)?;
                Ok(v)
            }
            Err(err) => {
                self.verified.remove(observer);
                authorizer.unregister_observer(observer);
                Err(err)
            }
        }
    }

    fn verify(
        &mut self,
        observer: &str,
        history: &[ObservationDescription],
        verifier: &dyn AccessVerifier,
        now: TimestampMs,
        check_policy: bool,
    ) -> Result<ObserverVerification, GatekeeperError> {
        let checked = match self.check_history(observer, history, verifier, check_policy) {
            Ok(checked) => checked,
            Err(err) => {
                // Any failure revokes the observer's verified status: a kind
                // with no strategy is a configuration error, but an observer
                // who cannot be verified against what the surface observed
                // must not stay verified from an earlier open.
                self.verified.remove(observer);
                return Err(err);
            }
        };
        let v = ObserverVerification {
            observer: observer.to_string(),
            verified_at: now,
            checked,
        };
        self.verified.insert(observer.to_string(), v.clone());
        Ok(v)
    }

    /// The units `observer` was checked against, each once, in history order.
    fn check_history(
        &self,
        observer: &str,
        history: &[ObservationDescription],
        verifier: &dyn AccessVerifier,
        check_policy: bool,
    ) -> Result<Vec<(String, String)>, GatekeeperError> {
        let refuse = |reason: String| GatekeeperError::ObserverVerificationFailed {
            observer: observer.to_string(),
            reason,
        };
        let mut checked: Vec<(String, String)> = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for obs in history {
            if check_policy {
                if obs.policy.prohibit_all_sharing {
                    return Err(refuse(format!(
                        "{}:{} was observed under prohibit_all_sharing",
                        obs.kind, obs.unit
                    )));
                }
                if obs.policy.exclude_observers.iter().any(|o| o == observer) {
                    return Err(refuse(format!(
                        "the sharing policy of {}:{} excludes this observer",
                        obs.kind, obs.unit
                    )));
                }
            }
            let strategy = self.strategy_for(&obs.kind).ok_or_else(|| {
                GatekeeperError::Invalid(format!("no verification strategy for kind {}", obs.kind))
            })?;
            let unit = match strategy {
                VerificationStrategy::PrivateOnly => {
                    return Err(refuse(format!(
                        "kind {} is private-only and was observed",
                        obs.kind
                    )));
                }
                VerificationStrategy::LowStakesNoOp => continue,
                VerificationStrategy::DataSetTracking if !obs.sub_resource.is_empty() => {
                    format!("{}/{}", obs.unit, obs.sub_resource)
                }
                VerificationStrategy::SingleUnitAcl | VerificationStrategy::DataSetTracking => {
                    obs.unit.clone()
                }
            };
            let key = (obs.kind.clone(), unit);
            if seen.insert(key.clone()) {
                if !verifier.can_read(observer, &key.0, &key.1) {
                    return Err(refuse(format!("cannot read {}:{}", key.0, key.1)));
                }
                checked.push(key);
            }
        }
        Ok(checked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatekeeper::observations::SharingPolicy;

    fn obs(kind: &str, unit: &str, sub: &str) -> ObservationDescription {
        ObservationDescription {
            kind: kind.into(),
            unit: unit.into(),
            sub_resource: sub.into(),
            summary: String::new(),
            policy: SharingPolicy::default(),
        }
    }

    #[test]
    fn single_unit_acl_checks_each_unit_once() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        let history = vec![
            obs("github.repo", "a/b", ""),
            obs("github.repo", "a/b", ""),
            obs("github.repo", "c/d", ""),
        ];
        let v = reg
            .add_observer(
                "bob",
                &history,
                &|o: &str, _k: &str, _u: &str| o == "bob",
                10,
            )
            .unwrap();
        assert_eq!(v.checked.len(), 2); // deduplicated
    }

    #[test]
    fn failed_acl_check_refuses_and_unregisters() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        let history = vec![obs("github.repo", "secret/repo", "")];
        let err = reg
            .add_observer(
                "bob",
                &history,
                &|_: &str, _: &str, u: &str| u != "secret/repo",
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            GatekeeperError::ObserverVerificationFailed { .. }
        ));
        assert_eq!(reg.verified_observers().count(), 0);
    }

    #[test]
    fn private_only_kind_is_never_shareable() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("gmail.mailbox", VerificationStrategy::PrivateOnly);
        let history = vec![obs("gmail.mailbox", "me", "")];
        let err = reg
            .add_observer("bob", &history, &|_: &str, _: &str, _: &str| true, 10)
            .unwrap_err();
        assert!(matches!(
            err,
            GatekeeperError::ObserverVerificationFailed { .. }
        ));
    }

    #[test]
    fn dataset_tracking_verifies_each_touched_subresource() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("bigquery.dataset", VerificationStrategy::DataSetTracking);
        let history = vec![
            obs("bigquery.dataset", "proj", "sales.q1"),
            obs("bigquery.dataset", "proj", "sales.q2"),
        ];
        let v = reg
            .add_observer(
                "bob",
                &history,
                &|_: &str, _: &str, u: &str| u.starts_with("proj/sales."),
                10,
            )
            .unwrap();
        assert_eq!(v.checked.len(), 2);
        // A sub-resource bob cannot read fails the whole verification.
        let history2 = vec![obs("bigquery.dataset", "proj", "hr.salaries")];
        assert!(reg
            .add_observer(
                "bob",
                &history2,
                &|_: &str, _: &str, u: &str| u.starts_with("proj/sales."),
                11,
            )
            .is_err());
    }

    #[test]
    fn low_stakes_noop_passes_without_vendor_calls() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("spotify.playlist", VerificationStrategy::LowStakesNoOp);
        let history = vec![obs("spotify.playlist", "pl1", "")];
        let v = reg
            .add_observer("bob", &history, &|_: &str, _: &str, _: &str| false, 10)
            .unwrap();
        assert!(v.checked.is_empty());
    }

    #[test]
    fn missing_strategy_is_refused_not_defaulted() {
        let mut reg = ObserverRegistry::new();
        let history = vec![obs("unknown.kind", "u", "")];
        assert!(reg
            .add_observer("bob", &history, &|_: &str, _: &str, _: &str| true, 10)
            .is_err());
    }

    /// F184: share-time verification refuses a history holding a
    /// prohibit_all_sharing observation, and an observer the recorded
    /// policy excludes — even when the vendor ACL would let them read.
    #[test]
    fn recorded_sharing_policy_is_honoured_at_share_time() {
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        let everyone = |_: &str, _: &str, _: &str| true;

        let mut locked = obs("github.repo", "a/b", "advisories");
        locked.policy.prohibit_all_sharing = true;
        let err = reg
            .add_observer("bob", &[locked], &everyone, 10)
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::ObserverVerificationFailed { .. }));
        assert_eq!(reg.verified_observers().count(), 0);

        let mut excluding = obs("github.repo", "a/b", "");
        excluding.policy = SharingPolicy {
            prohibit_all_sharing: false,
            exclude_observers: vec!["bob".into()],
        };
        let history = vec![excluding];
        assert!(reg.add_observer("bob", &history, &everyone, 11).is_err());
        assert!(reg.add_observer("carol", &history, &everyone, 12).is_ok());
        assert_eq!(
            reg.verified_observers().cloned().collect::<Vec<_>>(),
            vec!["carol".to_string()]
        );
    }

    /// F184: registration through the authorizer is atomic — a refusal on
    /// either side leaves the observer in neither.
    #[test]
    fn admit_observer_leaves_no_partial_state() {
        use crate::gatekeeper::observations::ObservationAuthorizer;
        let mut reg = ObserverRegistry::new();
        reg.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        let mut auth = ObservationAuthorizer::new();
        let can_read = |o: &str, _: &str, _: &str| o != "mallory";

        auth.authorize_observation(obs("github.repo", "a/b", ""), false, 1);
        reg.admit_observer("bob", &mut auth, &can_read, 2).unwrap();
        assert_eq!(reg.verified_observers().count(), 1);
        assert_eq!(auth.observers().count(), 1);

        // A failed access check registers nowhere.
        assert!(reg.admit_observer("mallory", &mut auth, &can_read, 3).is_err());
        assert!(!reg.verified_observers().any(|o| o == "mallory"));
        assert!(!auth.observers().any(|o| o == "mallory"));

        // Lockdown: the authorizer refuses, and the registry keeps no entry.
        let mut sensitive = obs("github.repo", "a/b", "advisories");
        sensitive.policy.prohibit_all_sharing = true;
        let mut solo = ObservationAuthorizer::new();
        solo.authorize_observation(sensitive, false, 4);
        let mut reg2 = ObserverRegistry::new();
        reg2.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        assert!(reg2.admit_observer("bob", &mut solo, &can_read, 5).is_err());
        assert_eq!(reg2.verified_observers().count(), 0);
        assert_eq!(solo.observers().count(), 0);

        // Revocation on re-open removes the observer from both sides.
        let revoked = |_: &str, _: &str, _: &str| false;
        assert!(reg.admit_observer("bob", &mut auth, &revoked, 6).is_err());
        assert_eq!(reg.verified_observers().count(), 0);
        assert_eq!(auth.observers().count(), 0);
    }
}
