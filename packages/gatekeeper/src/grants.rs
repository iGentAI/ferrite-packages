//! Platform-shaped capability grants.
//!
//! Every piece of authority a connector issues is expressed as a
//! [`CapabilityGrant`]: scoped to named resources, expiring at `not_after`,
//! and checked against a revocation epoch on every admission. This is
//! deliberately NOT a new token scheme — it is the vocabulary the platform's
//! multi-tenant security requirements already specify, restated so connector code has one type to carry.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// How far a grant's `issued_at` may lie ahead of the admitting clock
/// (hosts' clocks differ a little); beyond it the grant is not yet valid.
pub const MAX_ISSUE_CLOCK_SKEW_MS: TimestampMs = 5 * 60 * 1000;

/// What a grant authorizes, named narrowly.
///
/// A scope names a *resource kind* and a *unit* within it (a single repo, a
/// single document, a dataset). Whole-account scopes are representable but
/// discouraged; connectors should issue the narrowest unit their vendor
/// supports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct GrantScope {
    /// Resource kind, e.g. `github.repo`, `google.doc`.
    pub kind: String,
    /// The specific unit, e.g. `example-org/example-repo`. `*` means the whole
    /// account for kinds where the vendor offers no narrower unit.
    pub unit: String,
    /// Rights within the unit. Conventional values: `read`, `write`.
    pub rights: Vec<String>,
}

impl GrantScope {
    pub fn new(kind: impl Into<String>, unit: impl Into<String>, rights: &[&str]) -> Self {
        Self {
            kind: kind.into(),
            unit: unit.into(),
            rights: rights.iter().map(|r| r.to_string()).collect(),
        }
    }

    /// Whether this scope covers `kind`/`unit` with `right`.
    pub fn covers(&self, kind: &str, unit: &str, right: &str) -> bool {
        if kind.is_empty() || unit.is_empty() || right.is_empty() {
            return false;
        }
        self.kind == kind
            && (self.unit == "*" || self.unit == unit)
            && self.rights.iter().any(|r| r == right)
    }
}

/// A scoped, expiring, revocation-epoch-checked capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct CapabilityGrant {
    /// Stable grant id.
    pub id: String,
    /// The principal the grant was issued to (a user, an agent deployment).
    pub principal: String,
    /// The connector that issued it, e.g. `github`.
    pub connector: String,
    /// The scopes it carries.
    pub scopes: Vec<GrantScope>,
    /// Issue time.
    pub issued_at: TimestampMs,
    /// Hard expiry. Admission after this instant fails closed.
    pub not_after: TimestampMs,
    /// The revocation epoch the grant was minted under.
    pub epoch: u64,
}

/// The outcome of validating a grant at a moment in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantValidity {
    Valid,
    Expired,
    Revoked,
    /// Not usable at all: no principal, issued after its own expiry, or
    /// issued further in the future than [`MAX_ISSUE_CLOCK_SKEW_MS`].
    Malformed,
}

impl CapabilityGrant {
    /// Validate against the clock and the current epoch for its principal.
    pub fn validity(&self, now: TimestampMs, current_epoch: u64) -> GrantValidity {
        if self.principal.trim().is_empty()
            || self.issued_at > self.not_after
            || now.saturating_add(MAX_ISSUE_CLOCK_SKEW_MS) < self.issued_at
        {
            GrantValidity::Malformed
        } else if self.epoch != current_epoch {
            GrantValidity::Revoked
        } else if now > self.not_after {
            GrantValidity::Expired
        } else {
            GrantValidity::Valid
        }
    }

    /// Fail-closed admission: error unless valid AND the scope covers the ask.
    pub fn admit(
        &self,
        kind: &str,
        unit: &str,
        right: &str,
        now: TimestampMs,
        current_epoch: u64,
    ) -> Result<(), GatekeeperError> {
        match self.validity(now, current_epoch) {
            GrantValidity::Expired => {
                return Err(GatekeeperError::GrantExpired {
                    not_after: self.not_after,
                    now,
                })
            }
            GrantValidity::Revoked => {
                return Err(GatekeeperError::GrantRevoked {
                    grant_epoch: self.epoch,
                    current_epoch,
                })
            }
            GrantValidity::Malformed => {
                return Err(GatekeeperError::Invalid(format!(
                    "grant {} has no principal, or is not valid at {now} (issued {}, not after {})",
                    self.id, self.issued_at, self.not_after
                )))
            }
            GrantValidity::Valid => {}
        }
        if self.scopes.iter().any(|s| s.covers(kind, unit, right)) {
            Ok(())
        } else {
            Err(GatekeeperError::ScopeViolation(format!(
                "grant {} does not cover {kind}:{unit}:{right}",
                self.id
            )))
        }
    }
}

impl CapabilityGrant {
    /// [`Self::admit`] for a named connector, reading the revocation epoch
    /// of the grant's OWN principal from `epochs`, so a caller cannot pair a
    /// grant with another principal's epoch or present one connector's grant
    /// to another.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_epochs(
        &self,
        connector: &str,
        kind: &str,
        unit: &str,
        right: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), GatekeeperError> {
        if connector.is_empty() || self.connector != connector {
            return Err(GatekeeperError::ScopeViolation(format!(
                "grant {} was issued by connector {:?}, not {connector:?}",
                self.id, self.connector
            )));
        }
        self.admit(kind, unit, right, now, epochs.current(&self.principal))
    }
}

/// Per-principal revocation epochs.
///
/// Bumping a principal's epoch invalidates every grant minted under an
/// earlier one — cheap, transitive revocation exactly as the platform's capability model specifies.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct EpochRegistry {
    epochs: BTreeMap<String, u64>,
}

impl EpochRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current epoch for a principal (0 when never bumped).
    pub fn current(&self, principal: &str) -> u64 {
        self.epochs.get(principal).copied().unwrap_or(0)
    }

    /// Revoke everything minted before now for `principal`; returns the new epoch.
    /// Revoke every grant of `principal`. An exhausted counter stays at `u64::MAX`
    /// rather than wrapping to 0, which would revive every epoch-0 grant; a grant
    /// can only be minted at the current epoch, so nothing older matches.
    pub fn bump(&mut self, principal: &str) -> u64 {
        let e = self.epochs.entry(principal.to_string()).or_insert(0);
        *e = e.saturating_add(1);
        *e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> CapabilityGrant {
        CapabilityGrant {
            id: "g1".into(),
            principal: "alice".into(),
            connector: "github".into(),
            scopes: vec![GrantScope::new(
                "github.repo",
                "example-org/example-repo",
                &["read"],
            )],
            issued_at: 1_000,
            not_after: 10_000,
            epoch: 0,
        }
    }


    #[test]
    fn a_future_epoch_is_not_a_current_grant() {
        let mut g=grant();g.epoch=2;
        assert_eq!(g.validity(1_500,1),GrantValidity::Revoked);
        assert!(g.admit("github.repo","a/b","write",1_500,1).is_err());
    }
    #[test]
    fn admits_in_scope_before_expiry() {
        assert_eq!(
            grant().admit("github.repo", "example-org/example-repo", "read", 5_000, 0),
            Ok(())
        );
    }

    #[test]
    fn refuses_after_expiry() {
        let err = grant()
            .admit("github.repo", "example-org/example-repo", "read", 10_001, 0)
            .unwrap_err();
        assert_eq!(
            err,
            GatekeeperError::GrantExpired {
                not_after: 10_000,
                now: 10_001
            }
        );
    }

    #[test]
    fn refuses_when_epoch_bumped() {
        let mut reg = EpochRegistry::new();
        reg.bump("alice");
        let err = grant()
            .admit(
                "github.repo",
                "example-org/example-repo",
                "read",
                5_000,
                reg.current("alice"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            GatekeeperError::GrantRevoked {
                grant_epoch: 0,
                current_epoch: 1
            }
        );
    }

    #[test]
    fn refuses_out_of_scope_right() {
        let err = grant()
            .admit("github.repo", "example-org/example-repo", "write", 5_000, 0)
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::ScopeViolation(_)));
    }

    #[test]
    fn wildcard_unit_covers_everything_of_kind() {
        let s = GrantScope::new("github.repo", "*", &["read"]);
        assert!(s.covers("github.repo", "anything/at-all", "read"));
        assert!(!s.covers("google.doc", "anything", "read"));
    }

    #[test]
    fn malformed_and_future_grants_are_refused() {
        let mut g = grant();
        g.issued_at = 1_000_000;
        g.not_after = 2_000_000;
        // Issued more than the allowed clock skew in the future.
        assert_eq!(g.validity(5_000, 0), GrantValidity::Malformed);
        assert!(g.admit("github.repo", "example-org/example-repo", "read", 5_000, 0).is_err());
        assert_eq!(g.validity(1_000_000 - MAX_ISSUE_CLOCK_SKEW_MS, 0), GrantValidity::Valid);
        let mut inverted = grant();
        inverted.issued_at = 20_000;
        assert_eq!(inverted.validity(5_000, 0), GrantValidity::Malformed);
        let mut anonymous = grant();
        anonymous.principal = "  ".into();
        assert_eq!(anonymous.validity(5_000, 0), GrantValidity::Malformed);
        assert_eq!(grant().validity(5_000, 0), GrantValidity::Valid);
    }

    #[test]
    fn wildcard_scopes_do_not_match_empty_units_and_epochs_bind_to_the_principal() {
        let mut g = grant();
        g.scopes = vec![GrantScope::new("github.repo", "*", &["read"])];
        assert!(g.admit("github.repo", "", "read", 5_000, 0).is_err());
        assert!(g.admit("github.repo", "a/b", "read", 5_000, 0).is_ok());
        let mut epochs = EpochRegistry::new();
        assert!(g.admit_with_epochs("github", "github.repo", "a/b", "read", 5_000, &epochs).is_ok());
        assert!(g.admit_with_epochs("google", "github.repo", "a/b", "read", 5_000, &epochs).is_err());
        epochs.bump("bob");
        assert!(g.admit_with_epochs("github", "github.repo", "a/b", "read", 5_000, &epochs).is_ok());
        epochs.bump("alice");
        assert!(g.admit_with_epochs("github", "github.repo", "a/b", "read", 5_000, &epochs).is_err());
    }
}
