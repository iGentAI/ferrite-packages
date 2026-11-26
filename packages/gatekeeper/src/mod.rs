//! The connector (gatekeeper) contract.
//!
//! A *gatekeeper* is a service that sits between the platform and one external
//! service (GitHub, Google, …). It owns that service's credentials, its
//! resource scoping, its observation log, and its action approval queue. The
//! agent and any consuming app see only the small typed API a gatekeeper
//! exposes; the credential never enters a sandbox.
//!
//! This is the *contract* — the vocabulary and state machines every connector
//! implements — as a **source package**: composed into a consuming app's
//! `src/` tree by `tools/ferrite-pkg`, running under that app's injected
//! authority alone. It is not a crate and not a service.
//!
//! Nothing here introduces an authorization scheme parallel to the platform's capability model:
//! authority is carried by [`grants::CapabilityGrant`] — scoped, expiring,
//! revocation-epoch-checked.
//!
//! Nothing here reads a clock, an environment variable, a socket, or a file:
//! every timestamp is a parameter, entropy comes from the host, and calendar
//! evaluation is civil arithmetic over UTC/fixed-offset zones (see
//! [`calendar`] for the recorded IANA/DST delta).
//!
//! Module map:
//!
//! | Module | Adopts |
//! |---|---|
//! | [`oauth`] | connector-owned OAuth: nonce-protected callbacks, token vault, refresh |
//! | [`grants`] | platform-shaped capability grants |
//! | [`resources`] | `SupportedResource` URL-pattern scoping, incremental `ensure_resources` |
//! | [`observations`] | observation authorization before data moves; audit trail; sharing prohibitions |
//! | [`observers`] | read-through sharing permissions (strategies A/B/C/D) |
//! | [`actions`] | async approval queue with simulated outcomes, revert, per-kind auto-approval |
//! | [`catalog`] | bounded, untrusted agent catalogs |
//! | [`typed`] | typed TypeScript tool surfaces for code-mode agents |
//! | [`hooks`] | persistent callbacks, disabled until a human enables them |
//! | [`schedule`] | governed schedules: registration ≠ activation, delivery-time re-admission |
//! | [`calendar`] | cron validation + next-fire evaluation (UTC / fixed offsets) |
//! | [`sha256`] | vendored FIPS 180-4 digest (token fingerprints) |

pub mod actions;
pub mod calendar;
pub mod catalog;
pub mod grants;
pub mod hooks;
pub mod oauth;
pub mod observations;
pub mod observers;
pub mod resources;
pub mod schedule;
pub mod sha256;
pub mod typed;

pub use actions::{
    ActionDescription, ActionKind, ActionState, ApprovalQueue, AutoApprovalPolicy, DecisionOutcome,
};
pub use calendar::CalendarSpec;
pub use catalog::{
    AgentCatalog, CatalogEntry, CATALOG_MAX_DESCRIPTION, CATALOG_MAX_ENTRIES, CATALOG_MAX_ID,
};
pub use grants::{CapabilityGrant, EpochRegistry, GrantScope, GrantValidity};
pub use hooks::{Hook, HookRegistry, HookState};
pub use oauth::{PendingAuthorization, TokenFingerprint, TokenState, TokenVault, NONCE_TTL_MS};
pub use observations::{
    ObservationAuthorizer, ObservationDecision, ObservationDescription, SharingPolicy,
};
pub use observers::{ObserverRegistry, ObserverVerification, VerificationStrategy};
pub use resources::{ResourceGrant, ResourcePattern, SupportedResource};
pub use schedule::{
    AdmissionCheck, AdmissionDecision, Schedule, ScheduleKind, ScheduleRegistry, ScheduleState,
};
pub use typed::{ToolSurface, TypedMethod, TypedParam};

/// Milliseconds since the Unix epoch. All contract timestamps use this unit
/// so constrained hosts can supply their own clock.
pub type TimestampMs = u64;

/// Errors shared across the gatekeeper contract.
#[derive(Debug, PartialEq, Eq)]
pub enum GatekeeperError {
    GrantExpired {
        not_after: TimestampMs,
        now: TimestampMs,
    },
    GrantRevoked {
        grant_epoch: u64,
        current_epoch: u64,
    },
    ScopeViolation(String),
    ObservationBlocked(String),
    SharingProhibited(String),
    ObserverVerificationFailed {
        observer: String,
        reason: String,
    },
    UnknownAction(String),
    InvalidActionTransition(String),
    CatalogBound(String),
    HookDisabled(String),
    UnknownHook(String),
    AdmissionRefused(String),
    UnknownSchedule(String),
    Invalid(String),
}

impl std::fmt::Display for GatekeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GrantExpired { not_after, now } => {
                write!(f, "grant expired at {not_after} (now {now})")
            }
            Self::GrantRevoked {
                grant_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "grant revoked: epoch {grant_epoch} < current {current_epoch}"
                )
            }
            Self::ScopeViolation(msg) => write!(f, "scope violation: {msg}"),
            Self::ObservationBlocked(msg) => write!(f, "observation blocked: {msg}"),
            Self::SharingProhibited(msg) => write!(f, "sharing prohibited: {msg}"),
            Self::ObserverVerificationFailed { observer, reason } => {
                write!(f, "observer verification failed for {observer}: {reason}")
            }
            Self::UnknownAction(msg) => write!(f, "unknown action {msg}"),
            Self::InvalidActionTransition(msg) => {
                write!(f, "invalid action state transition: {msg}")
            }
            Self::CatalogBound(msg) => write!(f, "catalog bound exceeded: {msg}"),
            Self::HookDisabled(msg) => write!(f, "hook disabled: {msg}"),
            Self::UnknownHook(msg) => write!(f, "unknown hook {msg}"),
            Self::AdmissionRefused(msg) => write!(f, "schedule admission refused: {msg}"),
            Self::UnknownSchedule(msg) => write!(f, "unknown schedule {msg}"),
            Self::Invalid(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for GatekeeperError {}
