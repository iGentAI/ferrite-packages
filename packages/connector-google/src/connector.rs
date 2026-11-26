//! The connector core: a governed Google session.
//!
//! A [`GoogleConnector`] wires together the gatekeeper contract pieces for
//! one consuming surface (an agent session, a shared artifact):
//!
//! * a [`TokenVault`] holding the connector-owned OAuth token — every call
//!   requires a Valid token (`NotConnected` otherwise), and persistence only
//!   ever sees digests,
//! * a [`CapabilityGrant`] admission check on every call (expiry + epoch),
//! * a [`ResourceGrantSet`] naming the docs/sheets/folders this connection
//!   may touch,
//! * an [`ObservationAuthorizer`] every read passes through,
//! * an [`ApprovalQueue`] every side effect is submitted to,
//! * an [`ObserverRegistry`] enforcing read-through sharing — including on
//!   every NEW read: an observation at least one registered observer could
//!   not read directly is blocked BEFORE it is authorized or recorded, so a
//!   blocked read audits as Blocked and never enters observed history.
//!
//! Reads return data only after authorization fully completes (the observer
//! read-through check first, then observation authorization — which is what
//! records the observation); writes return SIMULATED outcomes immediately
//! and apply only on approval.

use crate::gatekeeper::actions::{
    self, ActionDescription, ActionKind, ApprovalQueue, AutoApprovalPolicy, QueuedAction,
};
use crate::gatekeeper::grants::{CapabilityGrant, EpochRegistry};
use crate::gatekeeper::oauth::{TokenFingerprint, TokenState, TokenVault};
use crate::gatekeeper::observations::{
    ObservationAuthorizer, ObservationDecision, ObservationDescription, SharingPolicy,
};
use crate::gatekeeper::observers::{ObserverRegistry, ObserverVerification, VerificationStrategy};
use crate::gatekeeper::resources::{ResourceGrantSet, ResourcePattern, SupportedResource};
use crate::gatekeeper::{GatekeeperError, TimestampMs};
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::connector_google::backend::{AppendEffect, FileMeta, GoogleBackend, RevertOutcome};

/// Errors a connector session can produce. The `Gatekeeper` variant is
/// transparent: its `Display` and `source` pass straight through to the inner
/// error.
#[derive(Debug)]
pub enum ConnectorError {
    Gatekeeper(GatekeeperError),
    Vendor(String),
    LockedDown,
    NotConnected(String),
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gatekeeper(inner) => inner.fmt(f),
            Self::Vendor(msg) => write!(f, "vendor error: {msg}"),
            Self::LockedDown => write!(f, "surface is locked down; side effects are refused"),
            Self::NotConnected(msg) => write!(f, "not connected: {msg}"),
        }
    }
}

impl std::error::Error for ConnectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gatekeeper(inner) => inner.source(),
            _ => None,
        }
    }
}

impl From<GatekeeperError> for ConnectorError {
    fn from(err: GatekeeperError) -> Self {
        Self::Gatekeeper(err)
    }
}

/// The resource kinds this connector supports.
pub fn supported_resources() -> Vec<SupportedResource> {
    vec![
        SupportedResource {
            kind: "google.doc".into(),
            label: "Google Doc".into(),
            patterns: vec![
                ResourcePattern::new("https://docs.google.com/document/d/{id}/*"),
                ResourcePattern::new("https://docs.google.com/document/d/{id}"),
            ],
            read_scopes: vec!["drive.file:read".into()],
            write_scopes: vec!["drive.file:write".into()],
        },
        SupportedResource {
            kind: "google.sheet".into(),
            label: "Google Sheet".into(),
            patterns: vec![
                ResourcePattern::new("https://docs.google.com/spreadsheets/d/{id}/*"),
                ResourcePattern::new("https://docs.google.com/spreadsheets/d/{id}"),
            ],
            read_scopes: vec!["drive.file:read".into()],
            write_scopes: vec!["drive.file:write".into()],
        },
        SupportedResource {
            kind: "google.drive.folder".into(),
            label: "Google Drive folder".into(),
            patterns: vec![ResourcePattern::new(
                "https://drive.google.com/drive/folders/{id}",
            )],
            read_scopes: vec!["drive.file:read".into()],
            write_scopes: vec!["drive.file:write".into()],
        },
    ]
}

/// One observation carrying no sharing restrictions.
fn observation(
    kind: &str,
    unit: &str,
    sub_resource: &str,
    summary: String,
) -> ObservationDescription {
    ObservationDescription {
        kind: kind.into(),
        unit: unit.into(),
        sub_resource: sub_resource.into(),
        summary,
        policy: SharingPolicy::default(),
    }
}

/// The receipt an append returns: simulated until approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AppendReceipt {
    pub action_id: String,
    /// The revision the vendor assigned when applied; `None` while simulated.
    pub revision: Option<u64>,
    pub simulated: bool,
}

/// A compact session summary for consoles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub units: Vec<String>,
    pub observations: usize,
    pub pending_actions: usize,
    pub locked_down: bool,
    /// A token is held for the principal (validity is checked per call).
    pub connected: bool,
}

/// One governed Google session.
pub struct GoogleConnector<B: GoogleBackend> {
    backend: B,
    grant: CapabilityGrant,
    resources: ResourceGrantSet,
    /// The connector-owned OAuth state: nonces + held tokens. Private — the
    /// only way out is a digest fingerprint.
    vault: TokenVault,
    pub observations: ObservationAuthorizer,
    approvals: ApprovalQueue,
    observed_epoch: std::cell::Cell<u64>,
    pub observers: ObserverRegistry,
    pub auto_approval: AutoApprovalPolicy,
    /// The consent flow each authorization nonce was begun for, newest last
    /// and bounded: a callback completes only the introductions its own
    /// flow named ([`ResourceGrantSet::begin_consent`]).
    consent_flows: Vec<(String, u64)>,
}

/// Most authorization nonces whose consent flow is remembered at once.
const MAX_CONSENT_FLOWS: usize = 16;

impl<B: GoogleBackend> GoogleConnector<B> {
    /// Open a session under `grant`. The observer registry is pre-loaded
    /// with this connector's verification strategies: single-unit ACL (B)
    /// for docs and sheets, dataset tracking (C) for Drive folders.
    pub fn new(backend: B, grant: CapabilityGrant) -> Self {
        let mut observers = ObserverRegistry::new();
        observers.set_strategy("google.doc", VerificationStrategy::SingleUnitAcl);
        observers.set_strategy("google.sheet", VerificationStrategy::SingleUnitAcl);
        observers.set_strategy("google.drive.folder", VerificationStrategy::DataSetTracking);
        Self {
            backend,
            grant,
            resources: ResourceGrantSet::new(),
            vault: TokenVault::new(),
            observations: ObservationAuthorizer::new(),
            approvals: ApprovalQueue::new(),
            observed_epoch: std::cell::Cell::new(0),
            observers,
            auto_approval: AutoApprovalPolicy::new(),
            consent_flows: Vec::new(),
        }
    }

    /// Begin connecting the principal's Google account: mint the single-use
    /// `state` nonce the authorization redirect carries. `scopes` is what
    /// `introduce_by_url` reported; `entropy` comes from the host.
    pub fn begin_connect(
        &mut self,
        scopes: Vec<String>,
        entropy: [u8; 16],
        now: TimestampMs,
    ) -> String {
        // The introductions pending now are the ones this authorization is
        // for; a later callback completes them and no others.
        let flow = self.resources.begin_consent(now);
        let nonce = self
            .vault
            .begin_authorization(self.grant.principal.clone(), scopes, entropy, now)
            .nonce
            .clone();
        self.consent_flows.push((nonce.clone(), flow.id));
        if self.consent_flows.len() > MAX_CONSENT_FLOWS {
            self.consent_flows.remove(0);
        }
        nonce
    }

    /// Handle the vendor callback: the nonce must be known, unused and
    /// fresh (replays are refused). On success the vault holds the token;
    /// the caller gets only a digest fingerprint. The scopes the nonce was
    /// minted for are recorded as consented, so pending introductions that
    /// needed them take effect.
    pub fn complete_connect(
        &mut self,
        state_nonce: &str,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        expires_at: TimestampMs,
        now: TimestampMs,
    ) -> Result<TokenFingerprint, ConnectorError> {
        let principal = self.grant.principal.clone();
        let flow = self
            .consent_flows
            .iter()
            .position(|(nonce, _)| nonce == state_nonce)
            .map(|at| self.consent_flows.remove(at).1);
        let fp = self.vault.complete_authorization(
            &principal,
            state_nonce,
            access_token,
            refresh_token,
            expires_at,
            now,
        )?;
        let held = self.vault.granted_scopes(&self.grant.principal);
        match flow {
            Some(flow) => self.resources.grant_consent_for(flow, &held, now),
            None => self.resources.grant_consent(&held, now),
        };
        Ok(fp)
    }

    /// Feed a completed vendor refresh back into the vault.
    pub fn complete_refresh(
        &mut self,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        expires_at: TimestampMs,
    ) -> Result<TokenFingerprint, ConnectorError> {
        Ok(self.vault.complete_refresh(
            &self.grant.principal,
            access_token,
            refresh_token,
            expires_at,
        )?)
    }

    /// Disconnect: drop the held token entirely. No introduced unit admits
    /// again until the account is reconnected.
    pub fn disconnect(&mut self) {
        self.vault.disconnect(&self.grant.principal);
        self.resources.revoke_consent();
    }

    /// What persistence may see: digest fingerprints, never the token.
    pub fn token_fingerprints(&self) -> Vec<TokenFingerprint> {
        self.vault.fingerprints()
    }

    /// Introduce a resource by URL (doc, sheet, or Drive folder). Returns
    /// `(kind, unit, scopes)`: the recognised kind, the canonical unit, and
    /// the delta of vendor OAuth scopes the grant expansion requires — the
    /// scopes to pass to [`Self::begin_connect`]. The expansion takes effect
    /// when the connect flow for those scopes completes.
    pub fn introduce_by_url(
        &mut self,
        url: &str,
        write: bool,
        now: TimestampMs,
    ) -> Result<(String, String, Vec<String>), ConnectorError> {
        let supported = supported_resources();
        let (kind, unit) = supported
            .iter()
            .find_map(|s| s.recognise(url).map(|u| (s.kind.clone(), u)))
            .ok_or_else(|| {
                GatekeeperError::Invalid(format!("url {url} is not a recognised Google resource"))
            })?;
        let scopes = self.resources.ensure_resources(
            &supported,
            &[(kind.clone(), unit.clone(), write)],
            now,
        )?;
        Ok((kind, unit, scopes))
    }

    fn document_kind(&self, unit: &str, right: &str, now: TimestampMs, epochs: &EpochRegistry) -> Result<&'static str, ConnectorError> {
        // Metadata is vendor I/O too. Before probing it, require a valid
        // capability and token plus this connection's explicit introduction.
        // The introduction selects only the preflight kind, never the actual
        // vendor kind used to select the final permission and operation.
        let introduced = if self.resources.is_granted("google.sheet", unit, false)
            && !self.resources.is_granted("google.doc", unit, false) { "google.sheet" } else { "google.doc" };
        self.admit(introduced, unit, right, now, epochs)?;
        // A pasted URL names a requested introduction, not the vendor's file type.
        // Resolve the actual kind before selecting a capability or vendor API.
        let kind = self.backend.resource_kind(unit).map_err(ConnectorError::Vendor)?;
        if !matches!(kind, "google.doc" | "google.sheet") {
            return Err(GatekeeperError::ScopeViolation("resource is not a document or spreadsheet".into()).into());
        }
        let other = if kind == "google.doc" { "google.sheet" } else { "google.doc" };
        if self.resources.is_granted(other, unit, false) {
            return Err(GatekeeperError::ScopeViolation("introduced resource kind conflicts with the vendor catalogue".into()).into());
        }
        Ok(kind)
    }

    /// Metadata admission is itself a write refusal when preparing an effect.
    /// Keep its audit before returning, including revocation before vendor I/O.
    fn write_document_kind(
        &mut self,
        doc: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<&'static str, ConnectorError> {
        match self.document_kind(doc, "write", now, epochs) {
            Ok(kind) => Ok(kind),
            Err(error) => {
                self.observations.record_refusal(
                    observation(
                        "google.resource",
                        doc,
                        "",
                        "Refused resource kind selection".into(),
                    ),
                    error.to_string(),
                    now,
                );
                Err(error)
            }
        }
    }

    /// Read-only action history. Mutations stay inside the connector that owns vendor effects.
    pub fn approvals(&self) -> &ApprovalQueue {
        &self.approvals
    }

    pub fn reject_action(
        &mut self,
        id: &str,
        now: TimestampMs,
    ) -> Result<QueuedAction, ConnectorError> {
        Ok(self.approvals.reject(id, now)?.clone())
    }

    // The highest epoch ever seen wins, so a stale registry cannot un-revoke a grant.
    fn current_epoch(&self, epochs: &EpochRegistry) -> u64 {
        let current = epochs
            .current(&self.grant.principal)
            .max(self.observed_epoch.get());
        self.observed_epoch.set(current);
        current
    }

    fn admit_write(
        &mut self,
        kind: &str,
        doc: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        let result = self.admit(kind, doc, "write", now, epochs).and_then(|_| {
            if self.observations.is_locked_down() {
                Err(ConnectorError::LockedDown)
            } else {
                Ok(())
            }
        });
        if let Err(error) = &result {
            self.observations.record_refusal(
                observation(kind, doc, "", "Refused connector write".into()),
                error.to_string(),
                now,
            );
        }
        result
    }

    /// Fail-closed admission for every call: grant validity + scope, then a
    /// Valid held token, then connection-level introduction.
    fn admit(
        &self,
        kind: &str,
        unit: &str,
        right: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        // 1. The capability grant must be valid and cover the ask.
        self.grant.admit(
            kind,
            unit,
            right,
            now,
            self.current_epoch(epochs),
        )?;
        // 2. The connector must hold a currently-Valid token for the principal.
        match self.vault.token_for(&self.grant.principal, now) {
            Ok(TokenState::Valid { .. }) => {}
            Ok(TokenState::NeedsRefresh { .. }) => {
                return Err(ConnectorError::NotConnected(format!(
                    "token for {} is expired and needs refresh",
                    self.grant.principal
                )))
            }
            Ok(TokenState::Expired) => {
                return Err(ConnectorError::NotConnected(format!(
                    "token for {} is expired; the human must reconnect",
                    self.grant.principal
                )))
            }
            Err(_) => {
                return Err(ConnectorError::NotConnected(format!(
                    "no connected Google account for {}",
                    self.grant.principal
                )))
            }
        }
        // 3. The resource must have been introduced on this connection.
        if !self.resources.is_granted(kind, unit, right == "write") {
            return Err(GatekeeperError::ScopeViolation(format!(
                "{kind} {unit} was not introduced on this connection"
            ))
            .into());
        }
        Ok(())
    }

    /// The new-observation observer rule, enforced BEFORE an observation is
    /// authorized (and therefore before anything is recorded or returned):
    /// every registered (verified) observer must be able to directly read
    /// `unit_key`, else the read is blocked naming the observers who may not
    /// see it.
    ///
    /// A failure still leaves an audit trace: `description` is resubmitted
    /// with a [`SharingPolicy`] excluding the failing observers and
    /// `allow_exclusion = false`, which the authorizer refuses (every
    /// verified observer was registered with it by [`Self::add_observer`]),
    /// writing a Blocked [`ObservationAuthorizer::audit_trail`] record. The
    /// authorizer stores history only for allowed decisions, so nothing is
    /// added to [`ObservationAuthorizer::observed`] — a blocked read never
    /// becomes an "observed" entry for observer verification to replay.
    fn enforce_observers_can_read(
        &mut self,
        unit_key: &str,
        description: &ObservationDescription,
        now: TimestampMs,
    ) -> Result<(), ConnectorError> {
        let failing: Vec<String> = self
            .observers
            .verified_observers()
            .filter(|observer| !self.backend.user_can_read(observer, unit_key))
            .cloned()
            .collect();
        if failing.is_empty() {
            return Ok(());
        }
        // Audit the refused attempt WITHOUT creating history.
        let decision = self.observations.authorize_observation(
            ObservationDescription {
                policy: SharingPolicy {
                    exclude_observers: failing.clone(),
                    ..SharingPolicy::default()
                },
                ..description.clone()
            },
            false,
            now,
        );
        debug_assert!(matches!(decision, ObservationDecision::Blocked { .. }));
        Err(GatekeeperError::ObservationBlocked(format!(
            "new observation of {unit_key} would not be visible to observer {}",
            failing.join(", ")
        ))
        .into())
    }

    /// Read a document body: an OBSERVED read.
    ///
    /// Ordering — authorization completes fully BEFORE any data is returned
    /// or any history is recorded:
    ///
    /// 1. admission (grant validity + Valid token + introduction),
    /// 2. the observer read-through check: every registered observer must be
    ///    able to read `doc` directly. A failure returns
    ///    [`GatekeeperError::ObservationBlocked`] naming the observers and
    ///    writes only a Blocked audit record — never an `observed()` entry,
    /// 3. only when all observers pass is the observation authorized — which
    ///    is what records it — and the data fetched and returned.
    pub fn read_document(
        &mut self,
        doc: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<String, ConnectorError> {
        let admission = (|| {
            let kind = self.document_kind(doc, "read", now, epochs)?;
            self.admit(kind, doc, "read", now, epochs)?;
            Ok::<_, ConnectorError>(kind)
        })();
        let kind = match admission {
            Ok(kind) => kind,
            Err(error) => {
                self.observations.record_refusal(
                    observation("google.resource", doc, "", "Refused connector read".into()),
                    error.to_string(),
                    now,
                );
                return Err(error);
            }
        };
        let description = observation(kind, doc, "", format!("read document {doc}"));
        // Observer read-through check FIRST: a read some observer may not
        // see must not become recorded (Allowed) history.
        self.enforce_observers_can_read(doc, &description, now)?;
        // Every observer passes: authorize — and thus record — the
        // observation, then return the data.
        let decision = self
            .observations
            .authorize_observation(description, false, now);
        match decision {
            ObservationDecision::Allowed | ObservationDecision::AllowedExcluding(_) => {
                if kind == "google.sheet" {
                    self.backend.read_sheet(doc)
                } else {
                    self.backend.read_document(doc)
                }
                .map_err(ConnectorError::Vendor)
            }
            ObservationDecision::Blocked { reason } => {
                Err(GatekeeperError::ObservationBlocked(reason).into())
            }
        }
    }

    /// List a Drive folder: an observed read with DATASET TRACKING. Each
    /// returned file is recorded as its own observation (`sub_resource` =
    /// file id), so observer verification later replays exactly the files
    /// this surface touched.
    ///
    /// Ordering — authorization completes fully BEFORE any data is returned
    /// or any history is recorded:
    ///
    /// 1. admission, then the listing is fetched INTERNALLY (the per-file
    ///    observations must name each touched file; nothing moves to the
    ///    caller yet),
    /// 2. the observer read-through check: every registered observer must be
    ///    able to read the folder AND each touched file's
    ///    `{folder}/{file id}` composite key. A failure returns
    ///    [`GatekeeperError::ObservationBlocked`] naming the observers and
    ///    writes only a Blocked audit record — never an `observed()` entry,
    ///    not even for files the observers could see,
    /// 3. only when all observers pass is each per-file observation
    ///    authorized — which is what records it — and the listing returned.
    pub fn list_folder(
        &mut self,
        folder: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<Vec<FileMeta>, ConnectorError> {
        const FOLDER_KIND: &str = "google.drive.folder";
        if let Err(error) = self.admit(FOLDER_KIND, folder, "read", now, epochs) {
            self.observations.record_refusal(
                observation(FOLDER_KIND, folder, "", "Refused connector folder listing".into()),
                error.to_string(),
                now,
            );
            return Err(error);
        }
        // Fetched internally first: the per-file observations must name each
        // touched file. The data does not move to the caller yet.
        let files = self
            .backend
            .list_folder(folder)
            .map_err(ConnectorError::Vendor)?;
        let descriptions: Vec<ObservationDescription> = files
            .iter()
            .map(|f| {
                let summary = format!("list folder {folder}: touched file {}", f.id);
                observation(FOLDER_KIND, folder, &f.id, summary)
            })
            .collect();
        // Observer read-through checks FIRST — the folder itself, then every
        // touched file — so a listing some observer may not fully see
        // records NO observed history at all.
        let folder_description =
            observation(FOLDER_KIND, folder, "", format!("list folder {folder}"));
        self.enforce_observers_can_read(folder, &folder_description, now)?;
        for (f, description) in files.iter().zip(&descriptions) {
            self.enforce_observers_can_read(&format!("{folder}/{}", f.id), description, now)?;
        }
        // Every observer passes: authorize — and thus record — the folder
        // itself (so an empty listing, or one whose files are shared more
        // widely than the folder, still leaves history that a later observer
        // is checked against), then one observation per touched file, then
        // return the data.
        for description in std::iter::once(folder_description).chain(descriptions) {
            let decision = self
                .observations
                .authorize_observation(description, false, now);
            if let ObservationDecision::Blocked { reason } = decision {
                return Err(GatekeeperError::ObservationBlocked(reason).into());
            }
        }
        Ok(files)
    }

    fn vendor_append(&self, kind: &str, doc: &str, text: &str) -> Result<AppendEffect, String> {
        if kind == "google.sheet" {
            self.backend.append_sheet_with_receipt(doc, text)
        } else {
            self.backend.append_document_with_receipt(doc, text)
        }
    }

    /// Settle an applied action on the vendor's answer: a failure is recorded
    /// as Failed, never left Applied; a success records the receipt a later
    /// revert must present. Returns the revision the vendor assigned.
    fn settle_append(
        &mut self,
        action_id: &str,
        kind: &str,
        doc: &str,
        outcome: Result<AppendEffect, String>,
        now: TimestampMs,
    ) -> Result<u64, ConnectorError> {
        let effect = match outcome {
            Ok(effect) => effect,
            Err(vendor) => {
                self.approvals.record_failure(action_id, now)?;
                return Err(ConnectorError::Vendor(vendor));
            }
        };
        self.approvals.record_applied_effect(
            action_id,
            serde_json::json!({
                "doc": doc,
                "resource_kind": kind,
                "revision": effect.revision,
                "token": effect.token,
            }),
        )?;
        Ok(effect.revision)
    }

    /// Append to a document: an APPROVABLE action. Returns immediately with
    /// a SIMULATED receipt; the real append lands only when a human approves
    /// (or the user opted into auto-approval for `google.doc.append`).
    pub fn append_to_document(
        &mut self,
        doc: &str,
        text: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<AppendReceipt, ConnectorError> {
        let kind = self.write_document_kind(doc, now, epochs)?;
        self.admit_write(kind, doc, now, epochs)?;
        // The EXACT arguments the apply path will execute — the reviewable
        // ground truth an approval's digest binds to.
        let args = serde_json::json!({ "doc": doc, "text": text, "resource_kind": kind });
        let desc = ActionDescription {
            title: format!("Append to Google Doc {doc}"),
            description: format!("Appends {} chars to document {doc}.", text.chars().count()),
            kind: ActionKind::new(
                format!("{kind}.append"),
                "Append to a Google document or sheet",
            ),
            auto_approvable: true,
            implements_revert: true, // revert = restore the prior revision
            await_decision: false,
            simulated_outcome: Some(serde_json::json!({
                "doc": doc, "text": text, "simulated": true
            })),
            args_digest: actions::args_digest(&args),
            args,
        };
        let rec = self
            .approvals
            .submit_action(desc, &self.auto_approval, now)?;
        let action_id = rec.id.clone();
        self.approvals.bind_authority(&action_id, &self.grant)?;
        if rec.auto_approved {
            let outcome = self.vendor_append(kind, doc, text);
            let revision = self.settle_append(&action_id, kind, doc, outcome, now)?;
            return Ok(AppendReceipt {
                action_id,
                revision: Some(revision),
                simulated: false,
            });
        }
        Ok(AppendReceipt {
            action_id,
            revision: None,
            simulated: true,
        })
    }

    /// Human approval path: apply one pending append for real. Returns the
    /// revision the vendor assigned (the revision before it is the revert
    /// target). `approver` is the deciding principal; `args_digest` is the
    /// digest of the arguments THEY reviewed — a stale digest (the queued
    /// arguments changed underneath the review) is rejected.
    pub fn approve_and_apply(
        &mut self,
        action_id: &str,
        approver: &str,
        args_digest: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<u64, ConnectorError> {
        self.approvals.check_authority(action_id, &self.grant)?;
        let rec = self
            .approvals
            .get(action_id)
            .ok_or_else(|| GatekeeperError::UnknownAction(action_id.to_string()))?
            .clone();
        let args = &rec.description.args;
        let text = |key: &str| {
            args.get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| GatekeeperError::Invalid(format!("reviewed append lacks {key}")))
        };
        let doc = text("doc")?;
        let value = text("text")?;
        // Pre-upgrade pending document actions have no resource_kind; their
        // original action tag already commits them to google.doc semantics.
        let kind = args
            .get("resource_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("google.doc");
        if !matches!(kind, "google.doc" | "google.sheet")
            || self.write_document_kind(doc, now, epochs)? != kind
            || rec.description.kind.tag != format!("{kind}.append")
        {
            return Err(GatekeeperError::Invalid(
                "approval is not the reviewed document append".into(),
            )
            .into());
        }
        self.admit_write(kind, doc, now, epochs)?;
        self.approvals
            .approve(action_id, approver, args_digest, now)?;
        let outcome = self.vendor_append(kind, doc, value);
        self.settle_append(action_id, kind, doc, outcome, now)
    }

    /// Undo only this recorded append, with a conditional vendor write that
    /// refuses if a later edit exists. Missing receipts cannot authorize undo.
    pub fn revert_append(
        &mut self,
        action_id: &str,
        revision: u64,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        self.approvals.check_revert_state(action_id)?;
        self.approvals.check_authority(action_id, &self.grant)?;
        let invalid = |message: &str| GatekeeperError::Invalid(message.into());
        let rec = self
            .approvals
            .get(action_id)
            .ok_or_else(|| GatekeeperError::UnknownAction(action_id.into()))?
            .clone();
        let effect = rec
            .applied_effect
            .as_ref()
            .ok_or_else(|| invalid("action has no vendor effect receipt"))?;
        let doc = effect["doc"]
            .as_str()
            .ok_or_else(|| invalid("effect lacks document"))?;
        let kind = effect["resource_kind"]
            .as_str()
            .ok_or_else(|| invalid("effect lacks resource kind"))?;
        let applied = effect["revision"]
            .as_u64()
            .ok_or_else(|| invalid("effect lacks revision"))?;
        if !matches!(kind, "google.doc" | "google.sheet")
            || self.write_document_kind(doc, now, epochs)? != kind
            || rec.description.kind.tag != format!("{kind}.append")
            || rec.description.args["doc"].as_str() != Some(doc)
            || applied.checked_sub(1) != Some(revision)
        {
            return Err(GatekeeperError::ScopeViolation(
                "revert must target the recorded append predecessor".into(),
            )
            .into());
        }
        self.admit_write(kind, doc, now, epochs)?;
        let token = effect["token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| invalid("effect lacks vendor mutation token"))?;
        self.approvals.begin_revert(action_id)?;
        let result = if kind == "google.sheet" {
            self.backend.revert_sheet_with_receipt(doc, revision, token)
        } else {
            self.backend.revert_document_with_receipt(doc, revision, token)
        };
        match result {
            Ok(RevertOutcome::Reverted) => {}
            Ok(RevertOutcome::Conflict) => {
                self.approvals.revert_refused_without_effect(action_id)?;
                return Err(ConnectorError::Vendor(
                    "document changed after this append; conditional revert refused".into(),
                ));
            }
            Err(error) => return Err(ConnectorError::Vendor(error)),
        }
        self.approvals.finish_revert(action_id, now)?;
        Ok(())
    }

    /// Register `observer` on this session — verified against every
    /// historical observation with the OBSERVER's own access (single-unit
    /// ACL for docs/sheets; per-touched-file for Drive folders) and against
    /// each observation's recorded sharing policy. A refusal leaves the
    /// observer registered nowhere.
    pub fn add_observer(
        &mut self,
        observer: &str,
        now: TimestampMs,
    ) -> Result<ObserverVerification, ConnectorError> {
        let backend = &self.backend;
        Ok(self.observers.admit_observer(
            observer,
            &mut self.observations,
            &|user: &str, _kind: &str, unit: &str| backend.user_can_read(user, unit),
            now,
        )?)
    }

    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            units: self
                .resources
                .grants()
                .iter()
                .map(|g| g.unit.clone())
                .collect(),
            observations: self.observations.observed().len(),
            pending_actions: self.approvals.pending().len(),
            locked_down: self.observations.is_locked_down(),
            connected: !self.vault.fingerprints().is_empty(),
        }
    }
}

/// End-to-end governance gate for the Google connector (the crate's
/// `tests/governance_gate.rs`, restructured as an in-file module — a source
/// package has no integration-test target).
///
/// Proves the full gatekeeper flow against the fixture backend: the OAuth
/// connect requirement (nonce-protected, replay-refused, tokens held by the
/// connector), introduction by URL, capability admission (expiry +
/// revocation epoch), observed reads with per-file dataset tracking,
/// simulated append actions with later approval and revert, observer
/// verification with the recipient's own access, the new-read observer
/// blocking rule (blocked reads audit as Blocked and never enter observed
/// history), and lockdown via prohibit_all_sharing.
#[cfg(test)]
mod governance_gate {
    use std::collections::BTreeMap;

    use crate::connector_google::{
        ConnectorError, DocState, FileMeta, FixtureBackend, FolderState, GoogleConnector,
    };
    use crate::gatekeeper::actions::ActionState;
    use crate::gatekeeper::grants::{CapabilityGrant, EpochRegistry, GrantScope};
    use crate::gatekeeper::observations::{
        ObservationDecision, ObservationDescription, SharingPolicy,
    };
    use crate::gatekeeper::GatekeeperError;
    use ferrite_app::serde_json;

    const DOC: &str = "doc-alpha";
    const DOC_URL: &str = "https://docs.google.com/document/d/doc-alpha/edit";
    const PRIVATE_DOC: &str = "doc-private";
    const PRIVATE_DOC_URL: &str = "https://docs.google.com/document/d/doc-private";
    const FOLDER: &str = "folder-team";
    const FOLDER_URL: &str = "https://drive.google.com/drive/folders/folder-team";

    fn seeded_backend() -> FixtureBackend {
        let b = FixtureBackend::new();
        b.seed_document(
            DOC,
            DocState {
                revisions: vec!["hello".into()],
                readers: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        );
        b.seed_document(
            PRIVATE_DOC,
            DocState {
                revisions: vec!["alice's eyes only".into()],
                readers: vec!["alice".into()],
            },
        );
        let mut file_readers = BTreeMap::new();
        file_readers.insert(
            "file-roadmap".to_string(),
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
        );
        // bob has NO direct access to the budget sheet inside the folder.
        file_readers.insert(
            "file-budget".to_string(),
            vec!["alice".to_string(), "carol".to_string()],
        );
        b.seed_folder(
            FOLDER,
            FolderState {
                files: vec![
                    FileMeta {
                        id: "file-roadmap".into(),
                        name: "Roadmap".into(),
                        mime_type: "application/vnd.google-apps.document".into(),
                    },
                    FileMeta {
                        id: "file-budget".into(),
                        name: "Budget".into(),
                        mime_type: "application/vnd.google-apps.spreadsheet".into(),
                    },
                ],
                readers: vec!["alice".into(), "bob".into(), "carol".into()],
                file_readers,
            },
        );
        b
    }

    fn grant(scopes: Vec<GrantScope>) -> CapabilityGrant {
        CapabilityGrant {
            id: "g1".into(),
            principal: "alice".into(),
            connector: "google".into(),
            scopes,
            issued_at: 0,
            not_after: 1_000_000,
            epoch: 0,
        }
    }

    fn rw_grant() -> CapabilityGrant {
        grant(vec![
            GrantScope::new("google.doc", "*", &["read", "write"]),
            GrantScope::new("google.sheet", "*", &["read"]),
            GrantScope::new("google.drive.folder", "*", &["read"]),
        ])
    }

    /// Connect alice's account with a token valid until t=900_000.
    fn connect(c: &mut GoogleConnector<FixtureBackend>, now: u64) {
        let nonce = c.begin_connect(
            vec!["drive.file:read".into(), "drive.file:write".into()],
            [7u8; 16],
            now,
        );
        c.complete_connect(
            &nonce,
            "ya29.fixture-token",
            Some("1//refresh".into()),
            900_000,
            now,
        )
        .unwrap();
    }





    #[test]
    fn actual_sheet_cannot_be_retyped_by_a_document_url() {
        let b=seeded_backend();b.seed_sheet("payroll",DocState{revisions:vec!["private budget".into()],readers:vec!["alice".into()]});
        let mut c=GoogleConnector::new(b,grant(vec![GrantScope::new("google.doc","*",&["read","write"]),GrantScope::new("google.sheet","*",&["read"])]));
        c.introduce_by_url("https://docs.google.com/document/d/payroll/edit",true,0).unwrap();connect(&mut c,0);let e=EpochRegistry::new();
        assert!(c.append_to_document("payroll","malicious",1,&e).is_err());
        assert_eq!(c.backend.document("payroll").unwrap().revisions,vec!["private budget"]);
        assert!(c.approvals.pending().is_empty());assert_eq!(c.observations.refused_attempts(),1);
    }
    #[test]
    fn undo_lockdown_and_exact_predecessor_are_independent_of_vendor_token() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();let v=c.approve_and_apply(&a.action_id,"alice",&d,2,&e).unwrap();
        assert!(matches!(c.revert_append(&a.action_id,v,3,&e), Err(ConnectorError::Gatekeeper(GatekeeperError::ScopeViolation(_)))));assert!(!c.approvals.get(&a.action_id).unwrap().revert_attempted);
        c.observations.authorize_observation(ObservationDescription{kind:"google.doc".into(),unit:DOC.into(),sub_resource:String::new(),summary:String::new(),policy:SharingPolicy{prohibit_all_sharing:true,..Default::default()}},false,4);
        assert!(matches!(c.revert_append(&a.action_id,v-1,5,&e),Err(ConnectorError::LockedDown)));assert_eq!(c.backend.document(DOC).unwrap().revisions.last().unwrap(),"helloA");
    }
    #[test]
    fn write_refusal_records_audit_without_observing_data() {
        let mut c=GoogleConnector::new(seeded_backend(),grant(vec![GrantScope::new("google.doc","*",&["read"])]));let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        assert!(c.append_to_document(DOC,"forbidden",1,&e).is_err());
        assert_eq!(c.observations.refused_attempts(),1);assert!(c.observations.observed().is_empty());
        assert!(matches!(c.observations.audit_trail().last().unwrap().decision,ObservationDecision::Blocked{..}));
    }
    #[test]
    fn queued_document_tag_must_match_even_when_kind_and_grant_are_valid() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();
        let mut value=ferrite_app::serde_json::to_value(&c.approvals).unwrap();value["actions"][&a.action_id]["description"]["kind"]["tag"]=ferrite_app::serde_json::json!("google.doc.delete");c.approvals=ferrite_app::serde_json::from_value(value).unwrap();
        assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&e).is_err());assert_eq!(c.backend.document(DOC).unwrap().revisions,vec!["hello"]);
    }
    #[test]
    fn undo_rechecks_the_reviewed_tag_and_document_with_a_live_receipt() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();let v=c.approve_and_apply(&a.action_id,"alice",&d,2,&e).unwrap();
        let saved=c.approvals.clone();
        for tag in [true,false] {
            let mut value=serde_json::to_value(&saved).unwrap();
            if tag {value["actions"][&a.action_id]["description"]["kind"]["tag"]=serde_json::json!("google.doc.delete");}
            else {value["actions"][&a.action_id]["description"]["args"]["doc"]=serde_json::json!("another-doc");}
            c.approvals=serde_json::from_value(value).unwrap();
            assert!(c.approvals.get(&a.action_id).unwrap().applied_effect.is_some());
            assert!(c.revert_append(&a.action_id,v-1,3,&e).is_err());
            assert!(!c.approvals.get(&a.action_id).unwrap().revert_attempted);
            assert_eq!(c.backend.document(DOC).unwrap().revisions.last().unwrap(),"helloA");
        }
        c.approvals=saved;c.revert_append(&a.action_id,v-1,4,&e).unwrap();
        assert_eq!(c.backend.document(DOC).unwrap().revisions.last().unwrap(),"hello");
    }
    fn locked_write_fixture() -> (GoogleConnector<FixtureBackend>, EpochRegistry, String, String, String, u64) {
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        let epochs = EpochRegistry::new();
        c.introduce_by_url(DOC_URL, true, 0).unwrap();
        connect(&mut c, 0);
        let pending = c.append_to_document(DOC, "P", 1, &epochs).unwrap();
        let digest = c.approvals.get(&pending.action_id).unwrap().description.args_digest.clone();
        let applied = c.append_to_document(DOC, "A", 1, &epochs).unwrap();
        let ad = c.approvals.get(&applied.action_id).unwrap().description.args_digest.clone();
        let revision = c.approve_and_apply(&applied.action_id, "alice", &ad, 2, &epochs).unwrap();
        c.observations.authorize_observation(
            ObservationDescription {
                kind: "google.doc".into(), unit: DOC.into(), sub_resource: String::new(),
                summary: "Private document locks side effects".into(),
                policy: SharingPolicy { prohibit_all_sharing: true, ..Default::default() },
            }, false, 3,
        );
        (c, epochs, pending.action_id, digest, applied.action_id, revision)
    }

    #[test]
    fn locked_append_refusal_audited_once() {
        let (mut c, epochs, _, _, _, _) = locked_write_fixture();
        let before = c.observations.refused_attempts();
        let pending = c.approvals.pending().len();
        assert!(matches!(c.append_to_document(DOC, "blocked", 4, &epochs), Err(ConnectorError::LockedDown)));
        assert_eq!(c.observations.refused_attempts(), before + 1);
        assert_eq!(c.approvals.pending().len(), pending);
        assert_eq!(c.backend.document(DOC).unwrap().revisions, vec!["hello", "helloA"]);
    }

    #[test]
    fn locked_approval_refusal_audited_once() {
        let (mut c, epochs, pending, digest, _, _) = locked_write_fixture();
        let before = c.observations.refused_attempts();
        assert!(matches!(c.approve_and_apply(&pending, "alice", &digest, 4, &epochs), Err(ConnectorError::LockedDown)));
        assert_eq!(c.observations.refused_attempts(), before + 1);
        assert_eq!(c.approvals.get(&pending).unwrap().state, ActionState::Pending);
        assert_eq!(c.backend.document(DOC).unwrap().revisions, vec!["hello", "helloA"]);
    }

    #[test]
    fn locked_undo_refusal_audited_once() {
        let (mut c, epochs, _, _, applied, revision) = locked_write_fixture();
        let before = c.observations.refused_attempts();
        assert!(matches!(c.revert_append(&applied, revision - 1, 4, &epochs), Err(ConnectorError::LockedDown)));
        assert_eq!(c.observations.refused_attempts(), before + 1);
        assert!(!c.approvals.get(&applied).unwrap().revert_attempted);
        assert_eq!(c.approvals.get(&applied).unwrap().state, ActionState::Applied);
        assert_eq!(c.backend.document(DOC).unwrap().revisions, vec!["hello", "helloA"]);
    }

    #[test]
    fn revoked_approval_and_undo_are_each_audited_before_metadata() {
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        let mut epochs = EpochRegistry::new();
        c.introduce_by_url(DOC_URL, true, 0).unwrap();
        connect(&mut c, 0);
        let pending = c.append_to_document(DOC, "A", 1, &epochs).unwrap();
        let digest = c.approvals.get(&pending.action_id).unwrap().description.args_digest.clone();
        let applied = c.append_to_document(DOC, "B", 1, &epochs).unwrap();
        let applied_digest = c.approvals.get(&applied.action_id).unwrap().description.args_digest.clone();
        let revision = c.approve_and_apply(&applied.action_id, "alice", &applied_digest, 2, &epochs).unwrap();
        epochs.bump("alice");
        let before = c.observations.refused_attempts();
        assert!(c.approve_and_apply(&pending.action_id, "alice", &digest, 3, &epochs).is_err());
        assert_eq!(c.observations.refused_attempts(), before + 1, "revoked approval must record one refusal");
        assert!(c.revert_append(&applied.action_id, revision - 1, 3, &epochs).is_err());
        assert_eq!(c.observations.refused_attempts(), before + 2, "revoked undo must record one refusal");
        assert_eq!(c.backend.document(DOC).unwrap().revisions.last().unwrap(), "helloB");
        assert_eq!(c.approvals.get(&pending.action_id).unwrap().state, ActionState::Pending);
        assert!(!c.approvals.get(&applied.action_id).unwrap().revert_attempted);
    }
    #[test]
    fn vendor_kind_is_rechecked_when_an_approved_action_executes() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"must not append",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();
        let original=c.backend.document(DOC).unwrap();c.backend.seed_sheet(DOC,original);
        assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&e).is_err());
        assert_eq!(c.backend.document(DOC).unwrap().revisions,vec!["hello"]);
        assert_eq!(c.approvals.get(&a.action_id).unwrap().state,ActionState::Pending);
    }
    #[test]
    fn ambiguous_vendor_undo_is_fenced_without_retry() {
        use crate::connector_google::GoogleBackend;
        use std::sync::atomic::{AtomicUsize,Ordering};
        struct UnknownUndo { inner: FixtureBackend, calls: AtomicUsize }
        impl GoogleBackend for UnknownUndo {
            fn resource_kind(&self,id:&str)->Result<&'static str,String>{self.inner.resource_kind(id)}
            fn read_document(&self,id:&str)->Result<String,String>{self.inner.read_document(id)}
            fn read_sheet(&self,id:&str)->Result<String,String>{self.inner.read_sheet(id)}
            fn append_to_sheet(&self,id:&str,t:&str)->Result<u64,String>{self.inner.append_to_sheet(id,t)}
            fn revert_sheet(&self,id:&str,v:u64)->Result<(),String>{self.inner.revert_sheet(id,v)}
            fn list_folder(&self,id:&str)->Result<Vec<FileMeta>,String>{self.inner.list_folder(id)}
            fn append_to_document(&self,id:&str,t:&str)->Result<u64,String>{self.inner.append_to_document(id,t)}
            fn revert_document(&self,id:&str,v:u64)->Result<(),String>{self.inner.revert_document(id,v)}
            fn user_can_read(&self,u:&str,id:&str)->bool{self.inner.user_can_read(u,id)}
            fn append_document_with_receipt(&self,id:&str,t:&str)->Result<crate::connector_google::backend::AppendEffect,String>{self.inner.append_document_with_receipt(id,t)}
            fn revert_document_with_receipt(&self,_:&str,_:u64,_:&str)->Result<crate::connector_google::backend::RevertOutcome,String>{self.calls.fetch_add(1,Ordering::SeqCst);Err("transport outcome unknown".into())}
        }
        let mut c=GoogleConnector::new(UnknownUndo{inner:seeded_backend(),calls:AtomicUsize::new(0)},rw_grant());
        c.introduce_by_url(DOC_URL,true,0).unwrap();let st=c.begin_connect(vec!["drive.file:read".into(),"drive.file:write".into()],[2;16],0);c.complete_connect(&st,"fixture",None,900000,0).unwrap();
        let e=EpochRegistry::new();let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();let v=c.approve_and_apply(&a.action_id,"alice",&d,2,&e).unwrap();
        assert!(c.revert_append(&a.action_id,v-1,3,&e).is_err());assert!(c.revert_append(&a.action_id,v-1,4,&e).is_err());
        assert_eq!(c.backend.calls.load(Ordering::SeqCst),1);assert!(c.approvals.get(&a.action_id).unwrap().revert_attempted);assert_eq!(c.approvals.get(&a.action_id).unwrap().state,ActionState::Applied);
    }

    #[test]
    fn confirmed_conflict_does_not_brick_earlier_undo_after_later_edit_reverted() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();let va=c.approve_and_apply(&a.action_id,"alice",&d,2,&e).unwrap();
        let b=c.append_to_document(DOC,"B",3,&e).unwrap();let d=c.approvals.get(&b.action_id).unwrap().description.args_digest.clone();let vb=c.approve_and_apply(&b.action_id,"alice",&d,4,&e).unwrap();
        assert!(c.revert_append(&a.action_id,va-1,5,&e).is_err());assert!(!c.approvals.get(&a.action_id).unwrap().revert_attempted);
        c.revert_append(&b.action_id,vb-1,6,&e).unwrap();c.revert_append(&a.action_id,va-1,7,&e).unwrap();assert_eq!(c.read_document(DOC,8,&e).unwrap(),"hello");
    }
    #[test]
    fn sheets_use_sheet_boundary_for_auto_and_manual_append_and_ambiguous_ids_refuse() {
        use crate::connector_google::GoogleBackend;
        struct Sheets(FixtureBackend);
        impl GoogleBackend for Sheets {
            fn resource_kind(&self,id:&str)->Result<&'static str,String>{self.0.resource_kind(id)}
            fn read_document(&self,_:&str)->Result<String,String>{Err("wrong Docs API".into())}
            fn append_to_document(&self,_:&str,_:&str)->Result<u64,String>{Err("wrong Docs API".into())}
            fn revert_document(&self,_:&str,_:u64)->Result<(),String>{Err("wrong Docs API".into())}
            fn read_sheet(&self,id:&str)->Result<String,String>{self.0.read_sheet(id)}
            fn append_to_sheet(&self,id:&str,text:&str)->Result<u64,String>{self.0.append_to_sheet(id,text)}
            fn revert_sheet(&self,id:&str,v:u64)->Result<(),String>{self.0.revert_sheet(id,v)}
            fn append_sheet_with_receipt(&self,id:&str,text:&str)->Result<crate::connector_google::backend::AppendEffect,String>{self.0.append_sheet_with_receipt(id,text)}
            fn revert_sheet_with_receipt(&self,id:&str,v:u64,t:&str)->Result<crate::connector_google::backend::RevertOutcome,String>{self.0.revert_sheet_with_receipt(id,v,t)}
            fn list_folder(&self,id:&str)->Result<Vec<FileMeta>,String>{self.0.list_folder(id)}
            fn user_can_read(&self,u:&str,id:&str)->bool{self.0.user_can_read(u,id)}
        }
        let backend=FixtureBackend::new();backend.seed_sheet("sheet1",DocState{revisions:vec!["base".into()],readers:vec!["alice".into()]});
        let mut c=GoogleConnector::new(Sheets(backend),grant(vec![GrantScope::new("google.sheet","sheet1",&["read","write"])]));
        let (_,_,scopes)=c.introduce_by_url("https://docs.google.com/spreadsheets/d/sheet1/edit",true,0).unwrap();let st=c.begin_connect(scopes,[1;16],0);c.complete_connect(&st,"fixture",None,900000,0).unwrap();let e=EpochRegistry::new();
        assert_eq!(c.read_document("sheet1",1,&e).unwrap(),"base");
        let a=c.append_to_document("sheet1","manual",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();c.approve_and_apply(&a.action_id,"alice",&d,2,&e).unwrap();
        c.auto_approval.opt_in("google.sheet.append");let a=c.append_to_document("sheet1","auto",3,&e).unwrap();assert!(!a.simulated);assert_eq!(c.read_document("sheet1",4,&e).unwrap(),"basemanualauto");
        c.introduce_by_url("https://docs.google.com/document/d/sheet1/edit",true,5).unwrap();assert!(c.append_to_document("sheet1","forbidden",6,&e).is_err());
    }
    #[test]
    fn reviewed_tag_epoch_and_lockdown_are_independent_fences() {
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let mut e=EpochRegistry::new();let stale=e.clone();
        c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();
        // 1. A persisted wrong tag must not turn a reviewed append into another operation.
        let saved=c.approvals.clone();let mut value=ferrite_app::serde_json::to_value(&saved).unwrap();value["actions"][&a.action_id]["description"]["kind"]["tag"]=ferrite_app::serde_json::json!("google.sheet.append");c.approvals=ferrite_app::serde_json::from_value(value).unwrap();
        assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&e).is_err());c.approvals=saved;
        // 2. Bumping the registry epoch or mutating the grant's bound epoch refuses approval.
        e.bump("alice");assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&e).is_err());assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&stale).is_err());
        c.grant.epoch=1;assert!(c.approve_and_apply(&a.action_id,"alice",&d,2,&e).is_err());
        // 3. With a valid tag and matching epoch, surface lockdown still refuses approval with LockedDown.
        let mut c=GoogleConnector::new(seeded_backend(),rw_grant());let e=EpochRegistry::new();c.introduce_by_url(DOC_URL,true,0).unwrap();connect(&mut c,0);
        let a=c.append_to_document(DOC,"A",1,&e).unwrap();let d=c.approvals.get(&a.action_id).unwrap().description.args_digest.clone();
        c.observations.authorize_observation(ObservationDescription{kind:"google.doc".into(),unit:DOC.into(),sub_resource:String::new(),summary:String::new(),policy:SharingPolicy{prohibit_all_sharing:true,..Default::default()}},false,2);
        assert!(matches!(c.approve_and_apply(&a.action_id,"alice",&d,3,&e),Err(ConnectorError::LockedDown)));
    }
    #[test]
    fn oauth_connect_gates_reads_and_replayed_nonce_is_refused() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        c.introduce_by_url(DOC_URL, false, 1).unwrap();

        // Unconnected: reads refuse with NotConnected, before any data moves.
        let err = c.read_document(DOC, 2, &epochs).unwrap_err();
        assert!(matches!(err, ConnectorError::NotConnected(_)));
        assert_eq!(c.observations.observed().len(), 0);

        // Connect: begin mints the redirect nonce, complete exchanges it for a
        // token the CONNECTOR holds.
        let nonce = c.begin_connect(vec!["drive.file:read".into()], [7u8; 16], 3);
        let fp = c
            .complete_connect(
                &nonce,
                "ya29.fixture-token",
                Some("1//refresh".into()),
                900_000,
                4,
            )
            .unwrap();
        assert_eq!(fp.principal, "alice");
        // Persistence posture: fingerprints carry digests, never the token.
        let json = serde_json::to_string(&c.token_fingerprints()).unwrap();
        assert!(!json.contains("ya29.fixture-token"));

        // Connected: the read now works.
        assert_eq!(c.read_document(DOC, 5, &epochs).unwrap(), "hello");

        // Replayed nonce: refused (single-use state).
        assert!(c
            .complete_connect(&nonce, "ya29.attacker", None, 900_000, 6)
            .is_err());

        // Expired token: reads refuse until the refresh is fed back.
        let err = c.read_document(DOC, 950_000, &epochs).unwrap_err();
        assert!(matches!(err, ConnectorError::NotConnected(_)));
        c.complete_refresh("ya29.fresh", None, 990_000).unwrap();
        assert_eq!(c.read_document(DOC, 960_000, &epochs).unwrap(), "hello");
    }

    #[test]
    fn full_flow_introduce_read_append_approve_revert() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());

        // Introduce by URL — the delta of vendor scopes is reported, and is what
        // the connect flow then requests.
        let (kind, unit, scopes) = c.introduce_by_url(DOC_URL, true, 1).unwrap();
        assert_eq!(kind, "google.doc");
        assert_eq!(unit, DOC);
        assert_eq!(
            scopes,
            vec![
                "drive.file:read".to_string(),
                "drive.file:write".to_string()
            ]
        );
        let nonce = c.begin_connect(scopes, [8u8; 16], 2);
        c.complete_connect(&nonce, "ya29.fixture-token", None, 900_000, 3)
            .unwrap();

        // Observed read.
        assert_eq!(c.read_document(DOC, 4, &epochs).unwrap(), "hello");
        assert_eq!(c.observations.observed().len(), 1);
        assert_eq!(c.observations.audit_trail().len(), 1);

        // Simulated append: returns immediately, queue pending, nothing landed
        // at the vendor.
        let receipt = c.append_to_document(DOC, " world", 5, &epochs).unwrap();
        assert!(receipt.simulated);
        assert_eq!(receipt.revision, None);
        assert_eq!(c.approvals.pending().len(), 1);
        let rec = c.approvals.get(&receipt.action_id).unwrap();
        let sim = rec.description.simulated_outcome.as_ref().unwrap();
        assert_eq!(sim["doc"], serde_json::json!(DOC));
        assert_eq!(sim["simulated"], serde_json::json!(true));
        assert_eq!(c.read_document(DOC, 6, &epochs).unwrap(), "hello"); // unchanged

        // Human approves the exact queued arguments: the append applies.
        let digest = c
            .approvals
            .get(&receipt.action_id)
            .unwrap()
            .description
            .args_digest
            .clone();
        let revision = c
            .approve_and_apply(&receipt.action_id, "alice", &digest, 10, &epochs)
            .unwrap();
        assert_eq!(revision, 1);
        assert_eq!(
            c.approvals.get(&receipt.action_id).unwrap().state,
            ActionState::Applied
        );
        assert_eq!(c.read_document(DOC, 11, &epochs).unwrap(), "hello world");

        // Revert restores the prior revision.
        c.revert_append(&receipt.action_id, revision - 1, 20, &epochs)
            .unwrap();
        assert_eq!(
            c.approvals.get(&receipt.action_id).unwrap().state,
            ActionState::Reverted
        );
        assert_eq!(c.read_document(DOC, 21, &epochs).unwrap(), "hello");
    }

    #[test]
    fn folder_listing_tracks_files_and_dataset_verification_catches_gaps() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        connect(&mut c, 1);
        c.introduce_by_url(FOLDER_URL, false, 1).unwrap();

        let files = c.list_folder(FOLDER, 2, &epochs).unwrap();
        assert_eq!(files.len(), 2);
        // The folder itself (sub_resource empty), then one observation per
        // touched file, sub_resource = file id.
        assert_eq!(c.observations.observed().len(), 3);
        let subs: Vec<&str> = c
            .observations
            .observed()
            .iter()
            .map(|o| o.sub_resource.as_str())
            .collect();
        assert!(subs.contains(&"file-roadmap") && subs.contains(&"file-budget"));

        // Carol can read every touched file: DataSetTracking verifies each one.
        let v = c.add_observer("carol", 3).unwrap();
        assert_eq!(v.checked.len(), 3);
        assert!(v
            .checked
            .iter()
            .any(|(k, u)| k == "google.drive.folder" && u == "folder-team/file-budget"));

        // Bob cannot read file-budget: verification catches the gap and refuses.
        let err = c.add_observer("bob", 4).unwrap_err();
        match err {
            ConnectorError::Gatekeeper(GatekeeperError::ObserverVerificationFailed {
                observer,
                reason,
            }) => {
                assert_eq!(observer, "bob");
                assert!(reason.contains("folder-team/file-budget"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn an_empty_folder_listing_is_recorded_and_checked_against_later_observers() {
        let epochs = EpochRegistry::new();
        let backend = seeded_backend();
        backend.seed_folder(
            "folder-empty",
            FolderState {
                files: vec![],
                readers: vec!["alice".into()],
                file_readers: BTreeMap::new(),
            },
        );
        let mut c = GoogleConnector::new(backend, rw_grant());
        connect(&mut c, 1);
        c.introduce_by_url("https://drive.google.com/drive/folders/folder-empty", false, 1)
            .unwrap();
        assert!(c.list_folder("folder-empty", 2, &epochs).unwrap().is_empty());
        assert_eq!(c.observations.observed().len(), 1);
        // Bob cannot read the folder: sharing the session with him is refused
        // even though the listing touched no file.
        assert!(c.add_observer("bob", 3).is_err());
    }

    #[test]
    fn new_reads_at_least_one_observer_cannot_see_are_blocked() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        connect(&mut c, 1);
        c.introduce_by_url(DOC_URL, false, 1).unwrap();
        c.introduce_by_url(PRIVATE_DOC_URL, false, 1).unwrap();

        // Alice reads the shared doc, then shares the surface with bob.
        c.read_document(DOC, 2, &epochs).unwrap();
        c.add_observer("bob", 3).unwrap();
        let observed_before = c.observations.observed().len();
        let audit_before = c.observations.audit_trail().len();

        // A NEW read bob could not see himself is BLOCKED, naming bob.
        let err = c.read_document(PRIVATE_DOC, 4, &epochs).unwrap_err();
        match err {
            ConnectorError::Gatekeeper(GatekeeperError::ObservationBlocked(reason)) => {
                assert!(reason.contains("bob"));
                assert!(reason.contains(PRIVATE_DOC));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Authorization completed BEFORE anything was recorded or returned: the
        // blocked read never became "observed" (Allowed) history — the history
        // observer verification replays is unchanged...
        assert_eq!(c.observations.observed().len(), observed_before);
        // ...while the refused attempt still audits as Blocked, excluding bob.
        assert_eq!(c.observations.audit_trail().len(), audit_before + 1);
        let audit = c.observations.audit_trail().last().unwrap();
        assert!(matches!(
            audit.decision,
            ObservationDecision::Blocked { .. }
        ));
        assert_eq!(audit.description.unit, PRIVATE_DOC);
        assert_eq!(
            audit.description.policy.exclude_observers,
            vec!["bob".to_string()]
        );

        // Reads bob CAN see still flow.
        assert_eq!(c.read_document(DOC, 5, &epochs).unwrap(), "hello");

        // Folder flavour: bob cannot read file-budget inside the folder, so the
        // listing (which would touch it) is blocked too.
        c.introduce_by_url(FOLDER_URL, false, 6).unwrap();
        let observed_before = c.observations.observed().len();
        let audit_before = c.observations.audit_trail().len();
        let err = c.list_folder(FOLDER, 7, &epochs).unwrap_err();
        assert!(matches!(
            err,
            ConnectorError::Gatekeeper(GatekeeperError::ObservationBlocked(_))
        ));
        // Nothing from the blocked listing became history — not even
        // file-roadmap, which bob CAN read — and the one Blocked audit record
        // names the sub-resource bob may not see.
        assert_eq!(c.observations.observed().len(), observed_before);
        assert_eq!(c.observations.audit_trail().len(), audit_before + 1);
        let audit = c.observations.audit_trail().last().unwrap();
        assert!(matches!(
            audit.decision,
            ObservationDecision::Blocked { .. }
        ));
        assert_eq!(audit.description.sub_resource, "file-budget");
        assert_eq!(
            audit.description.policy.exclude_observers,
            vec!["bob".to_string()]
        );
    }

    #[test]
    fn expired_grant_and_bumped_epoch_fail_closed() {
        let mut epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        // Long-lived token so the GRANT checks are what trip below.
        let nonce = c.begin_connect(vec![], [9u8; 16], 1);
        c.complete_connect(&nonce, "ya29.long-lived", None, 10_000_000, 1)
            .unwrap();
        c.introduce_by_url(DOC_URL, false, 1).unwrap();

        // Past grant expiry.
        let err = c.read_document(DOC, 2_000_000, &epochs).unwrap_err();
        assert!(err.to_string().contains("expired"));

        // Revocation epoch bump.
        epochs.bump("alice");
        let err = c.read_document(DOC, 2, &epochs).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn unintroduced_unit_is_refused_even_with_grant_and_token() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        connect(&mut c, 1);
        // No introduce_by_url: connection-level scoping refuses.
        let err = c.read_document(DOC, 2, &epochs).unwrap_err();
        assert!(err.to_string().contains("not introduced"));
    }

    #[test]
    fn auto_approval_applies_immediately_when_both_sides_agree() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        connect(&mut c, 1);
        c.introduce_by_url(DOC_URL, true, 1).unwrap();
        c.auto_approval.opt_in("google.doc.append");
        let receipt = c.append_to_document(DOC, "!", 2, &epochs).unwrap();
        assert!(!receipt.simulated); // applied for real, immediately
        assert_eq!(receipt.revision, Some(1));
        let rec = c.approvals.get(&receipt.action_id).unwrap();
        assert_eq!(rec.state, ActionState::Applied);
        assert!(rec.auto_approved);
        assert_eq!(c.read_document(DOC, 3, &epochs).unwrap(), "hello!");
    }

    #[test]
    fn lockdown_blocks_side_effects_and_sharing() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        connect(&mut c, 1);
        c.introduce_by_url(DOC_URL, true, 1).unwrap();

        // A maximally sensitive observation lands (e.g. unredacted board minutes).
        let d = c.observations.authorize_observation(
            ObservationDescription {
                kind: "google.doc".into(),
                unit: DOC.into(),
                sub_resource: String::new(),
                summary: "read the unredacted board minutes".into(),
                policy: SharingPolicy {
                    prohibit_all_sharing: true,
                    exclude_observers: vec![],
                },
            },
            false,
            2,
        );
        assert!(matches!(d, ObservationDecision::Allowed));
        assert!(c.observations.is_locked_down());

        // Side effects refuse.
        let err = c.append_to_document(DOC, "x", 3, &epochs).unwrap_err();
        assert!(matches!(err, ConnectorError::LockedDown));

        // Sharing refuses.
        assert!(c.add_observer("bob", 4).is_err());
        assert_eq!(c.observers.verified_observers().count(), 0);
    }

    /// F186 through the connector: an introduction whose consent was never
    /// completed does not admit, even with a valid token from an earlier
    /// read-only consent.
    #[test]
    fn abandoned_write_consent_does_not_admit_the_append() {
        let epochs = EpochRegistry::new();
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        let (_, _, scopes) = c.introduce_by_url(DOC_URL, false, 1).unwrap();
        let nonce = c.begin_connect(scopes, [3u8; 16], 2);
        c.complete_connect(&nonce, "ya29.read-only", None, 900_000, 3)
            .unwrap();
        assert_eq!(c.read_document(DOC, 4, &epochs).unwrap(), "hello");

        // Write is asked for; the human closes the consent tab.
        let (_, _, scopes) = c.introduce_by_url(DOC_URL, true, 5).unwrap();
        assert_eq!(scopes, vec!["drive.file:write".to_string()]);
        let _abandoned = c.begin_connect(scopes, [4u8; 16], 6);
        assert!(c.append_to_document(DOC, " world", 7, &epochs).is_err());
        // Reads keep working on the consented scope.
        assert_eq!(c.read_document(DOC, 8, &epochs).unwrap(), "hello");

        // Disconnect: nothing admits until reconnect.
        c.disconnect();
        assert!(c.read_document(DOC, 9, &epochs).is_err());
    }

    #[test]
    fn sheet_and_folder_urls_are_recognised_and_others_refused() {
        let mut c = GoogleConnector::new(seeded_backend(), rw_grant());
        let (kind, unit, scopes) = c
            .introduce_by_url(
                "https://docs.google.com/spreadsheets/d/sheet-99/edit#gid=0",
                false,
                1,
            )
            .unwrap();
        assert_eq!(kind, "google.sheet");
        assert_eq!(unit, "sheet-99");
        assert_eq!(scopes, vec!["drive.file:read".to_string()]);

        let (kind, unit, _) = c.introduce_by_url(FOLDER_URL, false, 2).unwrap();
        assert_eq!(kind, "google.drive.folder");
        assert_eq!(unit, FOLDER);

        // F482: Drive's share-button URL (?usp=sharing) introduces the folder id too.
        let (kind, unit, _) = c
            .introduce_by_url(&format!("{FOLDER_URL}?usp=sharing"), false, 2)
            .unwrap();
        assert_eq!(kind, "google.drive.folder");
        assert_eq!(unit, FOLDER);

        // Unrecognised URLs refuse.
        assert!(c
            .introduce_by_url("https://example.com/nope", false, 3)
            .is_err());
    }
    mod metadata_admission {

use super::*;
const T0:u64=1;
use crate::connector_google::{GoogleBackend, GoogleConnector};

use crate::gatekeeper::grants::EpochRegistry;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct Counting(FixtureBackend, Arc<AtomicUsize>);
impl GoogleBackend for Counting {
    fn resource_kind(&self, id: &str) -> Result<&'static str, String> { self.1.fetch_add(1, Ordering::SeqCst); self.0.resource_kind(id) }
    fn read_document(&self, d: &str) -> Result<String, String> { self.0.read_document(d) }
    fn read_sheet(&self, d: &str) -> Result<String, String> { self.0.read_sheet(d) }
    fn append_to_sheet(&self, d: &str, t: &str) -> Result<u64, String> { self.0.append_to_sheet(d, t) }
    fn revert_sheet(&self, d: &str, r: u64) -> Result<(), String> { self.0.revert_sheet(d, r) }
    fn list_folder(&self, d: &str) -> Result<Vec<crate::connector_google::FileMeta>, String> { self.0.list_folder(d) }
    fn append_to_document(&self, d: &str, t: &str) -> Result<u64, String> { self.0.append_to_document(d, t) }
    fn revert_document(&self, d: &str, r: u64) -> Result<(), String> { self.0.revert_document(d, r) }
    fn user_can_read(&self, u: &str, d: &str) -> bool { self.0.user_can_read(u, d) }
}

/// No vendor I/O for an id that was never introduced and with no connected token.
#[test]
fn x01_no_vendor_lookup_before_admission() {
    let n = Arc::new(AtomicUsize::new(0));
    let mut g = GoogleConnector::new(Counting(seeded_backend(), n.clone()), rw_grant());
    let e = EpochRegistry::new();
    let _ = g.read_document("doc-alpha", T0, &e);
    let _ = g.append_to_document("doc-alpha", "x", T0, &e);
    assert_eq!(n.load(Ordering::SeqCst), 0, "vendor metadata looked up before introduction and connection");
}

/// Unintroduced ids must not reveal whether they exist at the vendor.
#[test]
fn x02_no_existence_oracle_for_unintroduced_ids() {
    let mut g = GoogleConnector::new(seeded_backend(), rw_grant());
    let e = EpochRegistry::new();
    let a = g.read_document("doc-alpha", T0, &e).unwrap_err().to_string();
    let b = g.read_document("no-such-file", T0, &e).unwrap_err().to_string();
    let a = a.replace("doc-alpha", "ID"); let b = b.replace("no-such-file", "ID");
    assert_eq!(a, b, "existing vs absent ids are distinguishable before admission");
}

/// A read refused at kind selection is audited like a refused append.
#[test]
fn x03_refused_read_at_kind_selection_is_audited() {
    let mut g = GoogleConnector::new(seeded_backend(), rw_grant());
    let e = EpochRegistry::new();
    let before = g.observations.refused_attempts();
    assert!(g.read_document("no-such-file", T0, &e).is_err());
    assert!(g.observations.refused_attempts() > before, "refused read left no audit");
}

/// A folder listing refused at admission is audited like a refused read.
#[test]
fn x04_refused_folder_listing_is_audited() {
    let mut g = GoogleConnector::new(seeded_backend(), rw_grant());
    let e = EpochRegistry::new();
    let before = g.observations.refused_attempts();
    assert!(g.list_folder("folder-team", T0, &e).is_err());
    assert_eq!(
        g.observations.refused_attempts(),
        before + 1,
        "refused list_folder left no audit"
    );
}

    }

}
