//! Hooks: persistent callbacks for external events, disabled until a human
//! enables them.
//!
//! A gadget/agent registers a hook (`bind_hook`) for an external event
//! (a webhook, a schedule firing). Registration alone delivers nothing:
//! the hook is born [`HookState::Disabled`] and a HUMAN must enable it.
//! Every delivery begins with `start_hook()`, which re-checks admission and
//! returns a fresh [`crate::gatekeeper::actions::ApprovalQueue`] so hook-driven reads and
//! writes flow through the same observation/action governance as an
//! interactive session.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::gatekeeper::actions::ApprovalQueue;
use crate::gatekeeper::schedule::AdmissionCheck;
use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Longest hook source, owner, or enabling principal accepted.
pub const MAX_HOOK_FIELD_LEN: usize = 256;
/// Live (not revoked) hooks one owner may hold, as schedules are bounded per account.
pub const MAX_HOOKS_PER_OWNER: usize = 64;
/// Revoked hooks retained for audit before the oldest are pruned on a new bind.
pub const MAX_REVOKED_HOOKS: usize = 256;

fn named(field: &str, value: &str) -> Result<(), GatekeeperError> {
    if value.trim().is_empty() || value.len() > MAX_HOOK_FIELD_LEN {
        return Err(GatekeeperError::Invalid(format!(
            "hook {field} must be 1 to {MAX_HOOK_FIELD_LEN} bytes and not blank"
        )));
    }
    Ok(())
}

/// Hook lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum HookState {
    /// Registered but never enabled — deliveries are refused.
    Disabled,
    /// A human enabled it — deliveries admit (subject to re-checks).
    Enabled,
    /// Explicitly revoked; a revoked hook cannot be re-enabled, only re-bound.
    Revoked,
}

/// A registered hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Hook {
    pub id: String,
    /// The event source, e.g. `github.webhook:example-org/example-repo`.
    pub source: String,
    /// The owning principal — the accountable human. Every hook has one.
    pub owner: String,
    pub state: HookState,
    pub bound_at: TimestampMs,
    /// Who enabled it and when (None while disabled).
    pub enabled_by: Option<(String, TimestampMs)>,
}

/// The registry of hooks for one connector.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct HookRegistry {
    hooks: BTreeMap<String, Hook>,
    next_seq: u64,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook. It starts Disabled: registration is not activation.
    /// The source and the accountable owner must both be named.
    pub fn bind_hook(
        &mut self,
        source: impl Into<String>,
        owner: impl Into<String>,
        now: TimestampMs,
    ) -> Result<&Hook, GatekeeperError> {
        let (source, owner) = (source.into(), owner.into());
        named("source", &source)?;
        named("owner", &owner)?;
        let live = self
            .hooks
            .values()
            .filter(|h| h.owner == owner && h.state != HookState::Revoked)
            .count();
        if live >= MAX_HOOKS_PER_OWNER {
            return Err(GatekeeperError::Invalid(format!(
                "owner {owner} already holds {MAX_HOOKS_PER_OWNER} live hooks; revoke one first"
            )));
        }
        // Revoke-and-rebind cycles must not grow the registry without bound.
        let mut revoked: Vec<(TimestampMs, String)> = self
            .hooks
            .values()
            .filter(|h| h.state == HookState::Revoked)
            .map(|h| (h.bound_at, h.id.clone()))
            .collect();
        if revoked.len() >= MAX_REVOKED_HOOKS {
            revoked.sort();
            for (_, id) in revoked.iter().take(revoked.len() + 1 - MAX_REVOKED_HOOKS) {
                self.hooks.remove(id);
            }
        }
        self.next_seq += 1;
        let id = format!("hook-{:06}", self.next_seq);
        let hook = Hook {
            id: id.clone(),
            source,
            owner,
            state: HookState::Disabled,
            bound_at: now,
            enabled_by: None,
        };
        self.hooks.insert(id.clone(), hook);
        Ok(self.hooks.get(&id).expect("just inserted"))
    }

    pub fn get(&self, id: &str) -> Option<&Hook> {
        self.hooks.get(id)
    }

    fn hook_mut(&mut self, id: &str) -> Result<&mut Hook, GatekeeperError> {
        self.hooks
            .get_mut(id)
            .ok_or_else(|| GatekeeperError::UnknownHook(id.to_string()))
    }

    /// A human enables the hook. Records who.
    pub fn enable(
        &mut self,
        id: &str,
        by_human: impl Into<String>,
        now: TimestampMs,
    ) -> Result<&Hook, GatekeeperError> {
        let by_human = by_human.into();
        named("enabling principal", &by_human)?;
        let h = self.hook_mut(id)?;
        match h.state {
            HookState::Revoked => {
                return Err(GatekeeperError::HookDisabled(format!(
                    "hook {id} is revoked; re-bind instead of re-enabling"
                )))
            }
            HookState::Enabled => {
                return Err(GatekeeperError::Invalid(format!(
                    "hook {id} is already enabled; its enabling record stands"
                )))
            }
            HookState::Disabled => {}
        }
        h.state = HookState::Enabled;
        h.enabled_by = Some((by_human, now));
        Ok(&*h)
    }

    /// Disable without revoking (e.g. the owner pauses it).
    pub fn disable(&mut self, id: &str) -> Result<&Hook, GatekeeperError> {
        let h = self.hook_mut(id)?;
        if h.state == HookState::Enabled {
            h.state = HookState::Disabled;
            h.enabled_by = None;
        }
        Ok(&*h)
    }

    /// Revoke permanently.
    pub fn revoke(&mut self, id: &str) -> Result<&Hook, GatekeeperError> {
        let h = self.hook_mut(id)?;
        h.state = HookState::Revoked;
        h.enabled_by = None;
        Ok(&*h)
    }

    /// Transfer ownership — "the human owns the output": when an owner
    /// departs, their hooks become their manager's responsibility.
    pub fn transfer_owner(
        &mut self,
        id: &str,
        new_owner: impl Into<String>,
    ) -> Result<&Hook, GatekeeperError> {
        let new_owner = new_owner.into();
        named("owner", &new_owner)?;
        let h = self.hook_mut(id)?;
        if h.state == HookState::Revoked {
            return Err(GatekeeperError::HookDisabled(format!(
                "hook {id} is revoked; its ownership is closed"
            )));
        }
        h.owner = new_owner;
        Ok(&*h)
    }

    /// Begin one delivery. Admission is re-checked HERE, at delivery time —
    /// an enabled-then-disabled hook refuses, and so does one whose backing
    /// capability has expired or been revoked, whose agent is gone, or whose
    /// account is no longer entitled (the same [`AdmissionCheck`] a scheduled
    /// delivery answers). On success returns a fresh ApprovalQueue:
    /// hook-driven side effects flow through the same governance as
    /// interactive ones.
    pub fn start_hook(
        &self,
        id: &str,
        check: &AdmissionCheck,
    ) -> Result<ApprovalQueue, GatekeeperError> {
        let h = self
            .hooks
            .get(id)
            .ok_or_else(|| GatekeeperError::UnknownHook(id.to_string()))?;
        match h.state {
            HookState::Enabled if !check.ok() => Err(GatekeeperError::AdmissionRefused(format!(
                "hook {id} delivery refused at admission: {}",
                check.refusal()
            ))),
            HookState::Enabled => Ok(ApprovalQueue::new()),
            HookState::Disabled => Err(GatekeeperError::HookDisabled(format!(
                "hook {id} is registered but not human-enabled"
            ))),
            HookState::Revoked => Err(GatekeeperError::HookDisabled(format!(
                "hook {id} is revoked"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_not_activation() {
        let mut reg = HookRegistry::new();
        let id = reg.bind_hook("github.webhook:a/b", "alice", 10).unwrap().id.clone();
        assert!(matches!(
            reg.start_hook(&id, &AdmissionCheck::pass()),
            Err(GatekeeperError::HookDisabled(_))
        ));
        reg.enable(&id, "alice", 20).unwrap();
        assert!(reg.start_hook(&id, &AdmissionCheck::pass()).is_ok());
    }

    #[test]
    fn delivery_recheck_catches_disable() {
        let mut reg = HookRegistry::new();
        let id = reg.bind_hook("src", "alice", 10).unwrap().id.clone();
        reg.enable(&id, "alice", 20).unwrap();
        assert!(reg.start_hook(&id, &AdmissionCheck::pass()).is_ok());
        reg.disable(&id).unwrap();
        assert!(reg.start_hook(&id, &AdmissionCheck::pass()).is_err());
    }

    #[test]
    fn revoked_hooks_cannot_be_reenabled() {
        let mut reg = HookRegistry::new();
        let id = reg.bind_hook("src", "alice", 10).unwrap().id.clone();
        reg.revoke(&id).unwrap();
        assert!(reg.enable(&id, "alice", 30).is_err());
        assert!(reg.start_hook(&id, &AdmissionCheck::pass()).is_err());
    }

    #[test]
    fn ownership_transfers_to_manager() {
        let mut reg = HookRegistry::new();
        let id = reg.bind_hook("src", "alice", 10).unwrap().id.clone();
        reg.transfer_owner(&id, "alice-manager").unwrap();
        assert_eq!(reg.get(&id).unwrap().owner, "alice-manager");
    }

    #[test]
    fn unknown_hook_is_an_error() {
        let reg = HookRegistry::new();
        assert!(matches!(
            reg.start_hook("nope", &AdmissionCheck::pass()),
            Err(GatekeeperError::UnknownHook(_))
        ));
    }

    #[test]
    fn hooks_need_named_people_and_keep_their_enabling_record() {
        let mut reg = HookRegistry::new();
        assert!(reg.bind_hook("", "alice", 10).is_err());
        assert!(reg.bind_hook("src", "  ", 10).is_err());
        let id = reg.bind_hook("src", "alice", 10).unwrap().id.clone();
        assert!(reg.enable(&id, " ", 20).is_err());
        reg.enable(&id, "alice", 20).unwrap();
        assert!(reg.enable(&id, "mallory", 30).is_err());
        assert_eq!(reg.get(&id).unwrap().enabled_by, Some(("alice".to_string(), 20)));
        assert!(reg.transfer_owner(&id, "").is_err());
        reg.revoke(&id).unwrap();
        assert!(reg.transfer_owner(&id, "bob").is_err());
        assert_eq!(reg.get(&id).unwrap().owner, "alice");
    }

    #[test]
    fn delivery_rechecks_capability_and_entitlement() {
        let mut reg = HookRegistry::new();
        let id = reg.bind_hook("src", "alice", 10).unwrap().id.clone();
        reg.enable(&id, "alice", 20).unwrap();
        let mut check = AdmissionCheck::pass();
        assert!(reg.start_hook(&id, &check).is_ok());
        check.capability_valid = false;
        assert!(matches!(
            reg.start_hook(&id, &check),
            Err(GatekeeperError::AdmissionRefused(_))
        ));
        check.capability_valid = true;
        check.account_entitled = false;
        assert!(reg.start_hook(&id, &check).is_err());
    }
}
