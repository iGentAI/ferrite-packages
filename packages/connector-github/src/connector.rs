//! The connector core: a governed GitHub session.
//!
//! A [`GithubConnector`] wires together the gatekeeper contract pieces for
//! one consuming surface (an agent session, a shared artifact):
//!
//! * a [`CapabilityGrant`] admission check on every call (expiry + epoch),
//! * a [`ResourceGrantSet`] naming the repos this connection may touch,
//! * an [`ObservationAuthorizer`] every read passes through,
//! * an [`ApprovalQueue`] every side effect is submitted to,
//! * an [`ObserverRegistry`] enforcing read-through sharing.
//!
//! Reads return data only after observation authorization; writes return
//! SIMULATED outcomes immediately and apply only on approval.

use crate::gatekeeper::actions::{
    self, ActionDescription, ActionKind, ApprovalQueue, AutoApprovalPolicy, QueuedAction,
};
use crate::gatekeeper::grants::{CapabilityGrant, EpochRegistry};
use crate::gatekeeper::observations::{
    ObservationAuthorizer, ObservationDecision, ObservationDescription, SharingPolicy,
};
use crate::gatekeeper::observers::{ObserverRegistry, VerificationStrategy};
use crate::gatekeeper::resources::{ResourceGrantSet, ResourcePattern, SupportedResource};
use crate::gatekeeper::{GatekeeperError, TimestampMs};
use ferrite_app::serde_json;

use crate::connector_github::backend::{GithubBackend, Issue, PullRequest};

/// Errors a connector session can produce. The `Gatekeeper` variant is
/// transparent: it forwards the inner error's message and exposes it as source.
#[derive(Debug)]
pub enum ConnectorError {
    Gatekeeper(GatekeeperError),
    Vendor(String),
    LockedDown,
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gatekeeper(inner) => write!(f, "{inner}"),
            Self::Vendor(msg) => write!(f, "vendor error: {msg}"),
            Self::LockedDown => write!(f, "surface is locked down; side effects are refused"),
        }
    }
}

impl std::error::Error for ConnectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gatekeeper(inner) => Some(inner),
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
    vec![SupportedResource {
        kind: "github.repo".into(),
        label: "GitHub repository".into(),
        patterns: vec![ResourcePattern::new("https://github.com/{owner}/{repo}")],
        read_scopes: vec!["repo:read".into()],
        write_scopes: vec!["repo:write".into()],
    }]
}

/// One observation on a repo, carrying no sharing restrictions.
fn repo_observation(repo: &str, sub_resource: &str, summary: String) -> ObservationDescription {
    ObservationDescription {
        kind: "github.repo".into(),
        unit: repo.into(),
        sub_resource: sub_resource.into(),
        summary,
        policy: SharingPolicy::default(),
    }
}

/// A compact session summary for consoles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub repos: Vec<String>,
    pub observations: usize,
    pub pending_actions: usize,
    pub locked_down: bool,
}

/// One governed GitHub session.
pub struct GithubConnector<B: GithubBackend> {
    backend: B,
    grant: CapabilityGrant,
    resources: ResourceGrantSet,
    pub observations: ObservationAuthorizer,
    approvals: ApprovalQueue,
    observed_epoch: std::cell::Cell<u64>,
    pub observers: ObserverRegistry,
    pub auto_approval: AutoApprovalPolicy,
}

impl<B: GithubBackend> GithubConnector<B> {
    /// Open a session under `grant`. The observer registry is pre-loaded
    /// with this connector's verification strategy (B: single-unit ACL).
    pub fn new(backend: B, grant: CapabilityGrant) -> Self {
        let mut observers = ObserverRegistry::new();
        observers.set_strategy("github.repo", VerificationStrategy::SingleUnitAcl);
        Self {
            backend,
            grant,
            resources: ResourceGrantSet::new(),
            observations: ObservationAuthorizer::new(),
            approvals: ApprovalQueue::new(),
            observed_epoch: std::cell::Cell::new(0),
            observers,
            auto_approval: AutoApprovalPolicy::new(),
        }
    }

    /// Introduce a repository by URL (`https://github.com/{owner}/{repo}`).
    /// Returns the canonical unit and the vendor scopes the grant expansion
    /// requires. The expansion takes effect once those scopes are reported
    /// consented through [`Self::record_consent`].
    pub fn introduce_by_url(
        &mut self,
        url: &str,
        write: bool,
        now: TimestampMs,
    ) -> Result<(String, Vec<String>), ConnectorError> {
        let supported = supported_resources();
        let unit = supported
            .iter()
            .find_map(|s| s.recognise(url))
            .ok_or_else(|| {
                GatekeeperError::Invalid(format!("url {url} is not a recognised GitHub resource"))
            })?;
        let scopes = self.resources.ensure_resources(
            &supported,
            &[("github.repo".into(), unit.clone(), write)],
            now,
        )?;
        Ok((unit, scopes))
    }

    /// Record that the human consented to `scopes` for this connection's
    /// GitHub credential (the host calls this when its vendor authorization
    /// completes). Pending introductions whose scopes are now held take
    /// effect; returns how many did.
    pub fn record_consent(&mut self, scopes: &[String], now: TimestampMs) -> usize {
        self.resources.grant_consent(scopes, now)
    }

    /// Begin the consent the host is about to show: the pending repository
    /// introductions it is for, which the screen must name, and its id.
    /// Introductions shown in this flow are completed only by
    /// [`Self::record_consent_for`] with that id, so an abandoned consent
    /// never rides along with a later one.
    pub fn begin_consent(&mut self, now: TimestampMs) -> crate::gatekeeper::resources::ConsentFlow {
        self.resources.begin_consent(now)
    }

    /// The human consented to `scopes` in flow `flow`; returns how many of
    /// that flow's introductions took effect.
    pub fn record_consent_for(&mut self, flow: u64, scopes: &[String], now: TimestampMs) -> usize {
        self.resources.grant_consent_for(flow, scopes, now)
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
        repo: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        let result = self.admit(repo, "write", now, epochs).and_then(|_| {
            if self.observations.is_locked_down() {
                Err(ConnectorError::LockedDown)
            } else {
                Ok(())
            }
        });
        if let Err(error) = &result {
            self.observations.record_refusal(
                repo_observation(repo, "", "Refused connector write".into()),
                error.to_string(),
                now,
            );
        }
        result
    }

    fn admit(
        &self,
        repo: &str,
        right: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        // 1. The capability grant must be valid and cover the ask.
        self.grant.admit(
            "github.repo",
            repo,
            right,
            now,
            self.current_epoch(epochs),
        )?;
        // 2. The resource must have been introduced on this connection.
        if !self
            .resources
            .is_granted("github.repo", repo, right == "write")
        {
            return Err(GatekeeperError::ScopeViolation(format!(
                "repo {repo} was not introduced on this connection"
            ))
            .into());
        }
        Ok(())
    }

    /// Enforce the read-through rule on a NEW observation: every observer
    /// already registered on this surface must be able to read `repo` with
    /// their OWN access, or the read is blocked (the artifact is shared;
    /// letting it read further than its weakest observer would turn the
    /// share into a data leak).
    fn check_observers_can_read(&self, repo: &str) -> Result<(), ConnectorError> {
        let blocked: Vec<String> = self
            .observers
            .verified_observers()
            .filter(|o| !self.backend.user_can_read(o, repo))
            .cloned()
            .collect();
        if blocked.is_empty() {
            Ok(())
        } else {
            Err(GatekeeperError::ObservationBlocked(format!(
                "observer(s) {} cannot read {repo} with their own access",
                blocked.join(", ")
            ))
            .into())
        }
    }

    /// Authorize one observed read before the backend is called: admission,
    /// the observer read-through rule, then the observation itself. Every
    /// refusal is audited.
    fn authorize_read(
        &mut self,
        repo: &str,
        sub_resource: &str,
        summary: String,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        let description = repo_observation(repo, sub_resource, summary);
        if let Err(error) = self
            .admit(repo, "read", now, epochs)
            .and_then(|_| self.check_observers_can_read(repo))
        {
            self.observations
                .record_refusal(description, error.to_string(), now);
            return Err(error);
        }
        match self
            .observations
            .authorize_observation(description, false, now)
        {
            ObservationDecision::Allowed | ObservationDecision::AllowedExcluding(_) => Ok(()),
            ObservationDecision::Blocked { reason } => {
                Err(GatekeeperError::ObservationBlocked(reason).into())
            }
        }
    }

    /// Record a vendor failure on the action, so it is never left Applied.
    fn vendor_outcome<T>(
        &mut self,
        action_id: &str,
        outcome: Result<T, String>,
        now: TimestampMs,
    ) -> Result<T, ConnectorError> {
        match outcome {
            Ok(value) => Ok(value),
            Err(vendor) => {
                self.approvals.record_failure(action_id, now)?;
                Err(ConnectorError::Vendor(vendor))
            }
        }
    }

    /// List issues: an OBSERVED read. Data returns only when the
    /// observation is authorized against the registered observers.
    pub fn list_issues(
        &mut self,
        repo: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<Vec<Issue>, ConnectorError> {
        self.authorize_read(repo, "issues", format!("list issues on {repo}"), now, epochs)?;
        self.backend
            .list_issues(repo)
            .map_err(ConnectorError::Vendor)
    }

    /// List pull requests: an observed read, same governance as issues.
    pub fn list_pulls(
        &mut self,
        repo: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<Vec<PullRequest>, ConnectorError> {
        self.authorize_read(
            repo,
            "pulls",
            format!("list pull requests on {repo}"),
            now,
            epochs,
        )?;
        self.backend
            .list_pulls(repo)
            .map_err(ConnectorError::Vendor)
    }

    /// Open a PR: an APPROVABLE action. Returns immediately with the
    /// simulated PR; the real PR opens only when a human approves (or the
    /// user opted into auto-approval for `github.pr.open`).
    ///
    /// Returns `(action_id, simulated_pr)`.
    pub fn open_pull_request(
        &mut self,
        repo: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(String, PullRequest), ConnectorError> {
        self.admit_write(repo, now, epochs)?;
        let simulated = PullRequest {
            number: 0, // vendor assigns the real number on apply
            title: title.to_string(),
            body: body.to_string(),
            head: head.to_string(),
            base: base.to_string(),
            state: "open".into(),
            simulated: true,
        };
        // The EXACT arguments the apply path will execute — the reviewable
        // ground truth an approval's digest binds to.
        let args = serde_json::json!({
            "repo": repo, "title": title, "body": body, "head": head, "base": base
        });
        let desc = ActionDescription {
            title: format!("Open PR {title:?} on {repo}"),
            description: format!("Opens a pull request from {head} into {base} on {repo}."),
            kind: ActionKind::new("github.pr.open", "Open a pull request"),
            auto_approvable: true,
            implements_revert: true, // revert = close the PR
            await_decision: false,
            simulated_outcome: Some(serde_json::json!({
                "repo": repo, "title": title, "head": head, "base": base, "simulated": true
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
            let opened = self
                .backend
                .open_pull_request(repo, title, body, head, base);
            let pr = self.vendor_outcome(&action_id, opened, now)?;
            self.approvals.record_applied_effect(
                &action_id,
                serde_json::json!({"repo": repo, "pr_number": pr.number}),
            )?;
            return Ok((action_id, pr));
        }
        Ok((action_id, simulated))
    }

    /// Human approval path: apply one pending action for real. `approver`
    /// is the deciding principal; `args_digest` is the digest of the
    /// arguments THEY reviewed — a stale digest (the queued arguments
    /// changed underneath the review) is rejected.
    pub fn approve_and_apply(
        &mut self,
        action_id: &str,
        repo: &str,
        approver: &str,
        args_digest: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<PullRequest, ConnectorError> {
        let args = self.approved_arguments(action_id, repo, "github.pr.open", now, epochs)?;
        let text = |key: &str| {
            args.get(key)
                .and_then(|value| value.as_str())
                .ok_or_else(|| GatekeeperError::Invalid(format!("reviewed action lacks {key}")))
        };
        let (title, body, head, base) =
            (text("title")?, text("body")?, text("head")?, text("base")?);
        self.approvals
            .approve(action_id, approver, args_digest, now)?;
        let opened = self
            .backend
            .open_pull_request(repo, title, body, head, base);
        let pr = self.vendor_outcome(action_id, opened, now)?;
        self.approvals.record_applied_effect(
            action_id,
            serde_json::json!({"repo": repo, "pr_number": pr.number}),
        )?;
        Ok(pr)
    }

    fn approved_arguments(
        &mut self,
        action_id: &str,
        repo: &str,
        kind: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<serde_json::Value, ConnectorError> {
        self.approvals.check_authority(action_id, &self.grant)?;
        let rec = self
            .approvals
            .get(action_id)
            .ok_or_else(|| GatekeeperError::UnknownAction(action_id.into()))?.clone();
        if rec.description.kind.tag != kind
            || rec.description.args.get("repo").and_then(|v| v.as_str()) != Some(repo)
        {
            return Err(GatekeeperError::ScopeViolation(
                "approval must execute its reviewed action and repository".into(),
            )
            .into());
        }
        self.admit_write(repo, now, epochs)?;
        Ok(rec.description.args)
    }

    /// Queue a comment with exactly the arguments a human will approve.
    /// The optional id is present only when opt-in auto-approval applied it.
    pub fn add_comment(
        &mut self,
        repo: &str,
        issue: u64,
        body: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(String, Option<u64>), ConnectorError> {
        self.admit_write(repo, now, epochs)?;
        let args = serde_json::json!({"repo":repo,"issue":issue,"body":body});
        let rec = self.approvals.submit_action(
            ActionDescription {
                title: format!("Comment on {repo}#{issue}"),
                description: "Add the reviewed comment.".into(),
                kind: ActionKind::new("github.comment.add", "Add a comment"),
                auto_approvable: true,
                implements_revert: false,
                await_decision: false,
                simulated_outcome: Some(args.clone()),
                args_digest: actions::args_digest(&args),
                args,
            },
            &self.auto_approval,
            now,
        )?;
        let id = rec.id.clone();
        self.approvals.bind_authority(&id, &self.grant)?;
        if rec.auto_approved {
            let added = self.backend.add_comment(repo, issue, body);
            let comment = self.vendor_outcome(&id, added, now)?;
            return Ok((id, Some(comment)));
        }
        Ok((id, None))
    }

    pub fn approve_comment(
        &mut self,
        action_id: &str,
        repo: &str,
        approver: &str,
        args_digest: &str,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<u64, ConnectorError> {
        let args = self.approved_arguments(action_id, repo, "github.comment.add", now, epochs)?;
        let issue = args
            .get("issue")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| GatekeeperError::Invalid("reviewed comment lacks issue".into()))?;
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatekeeperError::Invalid("reviewed comment lacks body".into()))?;
        self.approvals
            .approve(action_id, approver, args_digest, now)?;
        let added = self.backend.add_comment(repo, issue, body);
        self.vendor_outcome(action_id, added, now)
    }

    /// Close only the PR recorded by this action. Missing legacy receipts,
    /// stale grants, lockdown, and a previous ambiguous attempt fail closed.
    pub fn revert_pull_request(
        &mut self,
        action_id: &str,
        repo: &str,
        pr_number: u64,
        now: TimestampMs,
        epochs: &EpochRegistry,
    ) -> Result<(), ConnectorError> {
        self.approvals.check_revert_state(action_id)?;
        self.approved_arguments(action_id, repo, "github.pr.open", now, epochs)?;
        let rec = self
            .approvals
            .get(action_id)
            .ok_or_else(|| GatekeeperError::UnknownAction(action_id.into()))?;
        let effect = rec.applied_effect.as_ref().ok_or_else(|| {
            GatekeeperError::Invalid("action has no vendor effect receipt".into())
        })?;
        if effect["repo"].as_str() != Some(repo) || effect["pr_number"].as_u64() != Some(pr_number) {
            return Err(GatekeeperError::ScopeViolation(
                "revert must target the recorded pull request".into(),
            )
            .into());
        }
        self.approvals.begin_revert(action_id)?;
        self.backend
            .close_pull_request(repo, pr_number)
            .map_err(ConnectorError::Vendor)?;
        self.approvals.finish_revert(action_id, now)?;
        Ok(())
    }

    /// Register `observer` on this session — verified against every
    /// historical observation with the OBSERVER's own access, and against
    /// each observation's recorded sharing policy. A refusal leaves the
    /// observer registered nowhere.
    pub fn add_observer(&mut self, observer: &str, now: TimestampMs) -> Result<(), ConnectorError> {
        let backend = &self.backend;
        self.observers.admit_observer(
            observer,
            &mut self.observations,
            &|user: &str, _kind: &str, unit: &str| backend.user_can_read(user, unit),
            now,
        )?;
        Ok(())
    }

    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            repos: self
                .resources
                .grants()
                .iter()
                .map(|g| g.unit.clone())
                .collect(),
            observations: self.observations.observed().len(),
            pending_actions: self.approvals.pending().len(),
            locked_down: self.observations.is_locked_down(),
        }
    }
}

/// End-to-end governance gate for the GitHub connector — the crate's
/// `tests/governance_gate.rs`, carried into the package in-file.
///
/// Proves the full Cloudflare-OS-derived flow against the fixture backend:
/// introduction by URL, capability admission (expiry + revocation epoch),
/// observed reads, simulated PR actions with later approval and revert,
/// auto-approval requiring both sides, observer verification with the
/// recipient's own access, and lockdown via prohibit_all_sharing.
#[cfg(test)]
mod tests {
    use super::{ConnectorError, GithubConnector};
    use crate::connector_github::backend::{FixtureBackend, Issue, RepoState};
    use crate::gatekeeper::actions::ActionState;
    use crate::gatekeeper::grants::{CapabilityGrant, EpochRegistry, GrantScope};
    use crate::gatekeeper::observations::{
        ObservationDecision, ObservationDescription, SharingPolicy,
    };
    use crate::gatekeeper::GatekeeperError;

    const REPO: &str = "example-org/example-repo";
    const REPO_URL: &str = "https://github.com/example-org/example-repo";

    fn seeded_backend() -> FixtureBackend {
        let b = FixtureBackend::new();
        b.seed_repo(
            REPO,
            RepoState {
                issues: vec![Issue {
                    number: 1,
                    title: "flaky test".into(),
                    body: "the gate flakes".into(),
                    state: "open".into(),
                }],
                pulls: vec![],
                comments: vec![],
                readers: vec!["alice".into(), "bob".into()],
            },
        );
        b.seed_repo(
            "acme/secret",
            RepoState {
                readers: vec!["alice".into()],
                ..Default::default()
            },
        );
        b
    }

    fn grant(scopes: Vec<GrantScope>) -> CapabilityGrant {
        CapabilityGrant {
            id: "g1".into(),
            principal: "alice".into(),
            connector: "github".into(),
            scopes,
            issued_at: 0,
            not_after: 1_000_000,
            epoch: 0,
        }
    }

    fn rw_grant() -> CapabilityGrant {
        grant(vec![GrantScope::new(
            "github.repo",
            REPO,
            &["read", "write"],
        )])
    }

    /// The host's GitHub authorization carries read and write.
    fn consent_all(c: &mut GithubConnector<FixtureBackend>) {
        c.record_consent(&["repo:read".into(), "repo:write".into()], 0);
    }


    fn ready() -> GithubConnector<FixtureBackend> {
        let mut c=GithubConnector::new(seeded_backend(),grant(vec![GrantScope::new("github.repo",REPO,&["read","write"]),GrantScope::new("github.repo","acme/secret",&["read","write"])]));
        c.introduce_by_url(REPO_URL,true,0).unwrap(); c.introduce_by_url("https://github.com/acme/secret",true,0).unwrap(); consent_all(&mut c); c
    }

    #[test]
    fn comments_require_reviewed_kind_fresh_authority_and_explicit_auto_opt_in() {
        let mut c=ready();let mut e=EpochRegistry::new();let (id,applied)=c.add_comment(REPO,1,"complete comment",1,&e).unwrap();assert!(applied.is_none());
        let saved=c.approvals.clone();let d=c.approvals.get(&id).unwrap().description.args_digest.clone();
        let mut raw=ferrite_app::serde_json::to_value(&saved).unwrap();raw["actions"][&id]["description"]["kind"]["tag"]=ferrite_app::serde_json::json!("github.pr.open");c.approvals=ferrite_app::serde_json::from_value(raw).unwrap();
        assert!(c.approve_comment(&id,REPO,"alice",&d,2,&e).is_err());c.approvals=saved;
        assert!(c.approve_comment(&id,"acme/secret","alice",&d,2,&e).is_err());
        e.bump("alice");assert!(c.approve_comment(&id,REPO,"alice",&d,2,&e).is_err());assert_eq!(c.approvals.get(&id).unwrap().state,crate::gatekeeper::actions::ActionState::Pending);
        let mut c=ready();c.auto_approval.opt_in("github.comment.add");let (_,applied)=c.add_comment(REPO,1,"explicit auto",1,&EpochRegistry::new()).unwrap();assert!(applied.is_some());
    }

    #[test]
    fn legacy_effect_absence_and_receipt_mutation_fail_closed() {
        let mut c=ready();let e=EpochRegistry::new();let (id,_)=c.open_pull_request(REPO,"t","b","h","main",1,&e).unwrap();let d=c.approvals.get(&id).unwrap().description.args_digest.clone();let pr=c.approve_and_apply(&id,REPO,"alice",&d,2,&e).unwrap();
        let bytes=ferrite_app::serde_json::to_vec(&c.approvals).unwrap();let restored:crate::gatekeeper::actions::ApprovalQueue=ferrite_app::serde_json::from_slice(&bytes).unwrap();assert_eq!(restored.get(&id),c.approvals.get(&id));
        // Private module-only historical shape exercise: no host restore API exists.
        let mut old=ferrite_app::serde_json::to_value(restored).unwrap();old["actions"][&id].as_object_mut().unwrap().remove("applied_effect");c.approvals=ferrite_app::serde_json::from_value(old).unwrap();
        assert!(c.revert_pull_request(&id,REPO,pr.number,3,&e).is_err());assert_eq!(c.backend.repo(REPO).unwrap().pulls.last().unwrap().state,"open");
    }
    #[test]
    fn denied_writes_have_bounded_audit_records() {
        let mut c=ready();let e=EpochRegistry::new();let before=c.observations.audit_trail().len();
        assert!(c.open_pull_request("acme/payroll","t","b","h","main",1,&e).is_err());assert!(c.add_comment("acme/payroll",1,"b",1,&e).is_err());assert_eq!(c.observations.audit_trail().len(),before+2);
    }
    #[test]
    fn two_writable_repositories_do_not_allow_retarget_or_wrong_kind() {
        let mut c=ready(); let e=EpochRegistry::new();
        let (id,_)=c.open_pull_request(REPO,"title","complete body","head","main",1,&e).unwrap();
        let d=c.approvals.get(&id).unwrap().description.args_digest.clone();
        assert!(c.approve_and_apply(&id,"acme/secret","alice",&d,2,&e).is_err());
        assert!(c.approve_comment(&id,REPO,"alice",&d,2,&e).is_err());
        assert!(c.backend.repo("acme/secret").unwrap().pulls.is_empty());
        let pr=c.approve_and_apply(&id,REPO,"alice",&d,2,&e).unwrap();assert_eq!(pr.body,"complete body");
        let effect=c.approvals.get(&id).unwrap().applied_effect().unwrap();assert_eq!(effect["grant_epoch"],0);assert_eq!(effect["grant_not_after"],1_000_000);
        assert!(c.approvals.record_applied_effect(&id,ferrite_app::serde_json::json!({"pr_number":7})).is_err());
    }
    #[test]
    fn queued_authority_cannot_be_regranted_and_observed_revocation_cannot_roll_back() {
        let mut c=ready();let mut e=EpochRegistry::new();let stale=e.clone();
        let (id,_)=c.open_pull_request(REPO,"t","b","h","main",1,&e).unwrap();let d=c.approvals.get(&id).unwrap().description.args_digest.clone();
        e.bump("alice");assert!(c.approve_and_apply(&id,REPO,"alice",&d,2,&e).is_err());
        assert!(c.approve_and_apply(&id,REPO,"alice",&d,2,&stale).is_err());
        c.grant.epoch=1;assert!(c.approve_and_apply(&id,REPO,"alice",&d,2,&e).is_err());
    }
    #[test]
    fn pulls_refusal_is_bounded_audited_and_lockdown_blocks_approval() {
        let mut c=ready();let e=EpochRegistry::new();
        for _ in 0..300 {assert!(c.list_pulls(&"x".repeat(10000),0,&e).is_err());}
        assert_eq!(c.observations.audit_trail().len(),32);assert_eq!(c.observations.refused_attempts(),300);assert!(c.observations.audit_trail().iter().all(|a|a.description.unit.len()<=512));
        let (id,_)=c.open_pull_request(REPO,"t","b","h","main",1,&e).unwrap();let d=c.approvals.get(&id).unwrap().description.args_digest.clone();
        c.observations.authorize_observation(ObservationDescription{kind:"github.repo".into(),unit:REPO.into(),sub_resource:String::new(),summary:String::new(),policy:SharingPolicy{prohibit_all_sharing:true,..Default::default()}},false,2);
        assert!(matches!(c.approve_and_apply(&id,REPO,"alice",&d,3,&e),Err(ConnectorError::LockedDown)));
    }
    #[test]
    fn full_flow_introduce_read_simulate_approve_revert() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(seeded_backend(), rw_grant());

        // Introduce by URL — the delta of vendor scopes is reported.
        let (unit, scopes) = c.introduce_by_url(REPO_URL, true, 1).unwrap();
        assert_eq!(unit, REPO);
        assert_eq!(
            scopes,
            vec!["repo:read".to_string(), "repo:write".to_string()]
        );
        // Not usable until the human consents to those scopes.
        assert!(c.list_issues(REPO, 2, &epochs).is_err());
        assert_eq!(c.record_consent(&scopes, 2), 1);

        // Observed read.
        let issues = c.list_issues(REPO, 2, &epochs).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(c.observations.observed().len(), 1);
        assert_eq!(c.observations.audit_trail().len(), 2);

        // Simulated PR: returns immediately, marked simulated, queue pending.
        let (action_id, sim) = c
            .open_pull_request(REPO, "fix flaky test", "body", "fix", "main", 3, &epochs)
            .unwrap();
        assert!(sim.simulated);
        assert_eq!(c.approvals.pending().len(), 1);
        // Nothing landed at the vendor yet.
        assert_eq!(c.summary().pending_actions, 1);

        // Human approves the exact queued arguments: the REAL PR opens.
        let digest = c
            .approvals
            .get(&action_id)
            .unwrap()
            .description
            .args_digest
            .clone();
        let pr = c
            .approve_and_apply(&action_id, REPO, "alice", &digest, 10, &epochs)
            .unwrap();
        assert!(!pr.simulated);
        assert_eq!(
            c.approvals.get(&action_id).unwrap().state,
            ActionState::Applied
        );

        // Revert closes it.
        c.revert_pull_request(&action_id, REPO, pr.number, 20, &epochs)
            .unwrap();
        assert_eq!(
            c.approvals.get(&action_id).unwrap().state,
            ActionState::Reverted
        );
    }

    #[test]
    fn unintroduced_repo_is_refused_even_with_grant() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(
            seeded_backend(),
            grant(vec![GrantScope::new("github.repo", "*", &["read"])]),
        );
        // No introduce_by_url: connection-level scoping refuses.
        let err = c.list_issues(REPO, 1, &epochs).unwrap_err();
        assert!(err.to_string().contains("not introduced"));
    }

    #[test]
    fn expired_grant_and_bumped_epoch_fail_closed() {
        let mut epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(seeded_backend(), rw_grant());
        consent_all(&mut c);
        c.introduce_by_url(REPO_URL, false, 1).unwrap();
        // Past expiry.
        let err = c.list_issues(REPO, 2_000_000, &epochs).unwrap_err();
        assert!(err.to_string().contains("expired"));
        // Revocation epoch bump.
        epochs.bump("alice");
        let err = c.list_issues(REPO, 2, &epochs).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn auto_approval_applies_immediately_when_both_sides_agree() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(seeded_backend(), rw_grant());
        consent_all(&mut c);
        c.introduce_by_url(REPO_URL, true, 1).unwrap();
        c.auto_approval.opt_in("github.pr.open");
        let (action_id, pr) = c
            .open_pull_request(REPO, "auto", "", "fix", "main", 2, &epochs)
            .unwrap();
        assert!(!pr.simulated); // applied for real, immediately
        let rec = c.approvals.get(&action_id).unwrap();
        assert_eq!(rec.state, ActionState::Applied);
        assert!(rec.auto_approved);
    }

    #[test]
    fn observer_needs_own_access_and_reverification_catches_revocation() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(seeded_backend(), rw_grant());
        consent_all(&mut c);
        c.introduce_by_url(REPO_URL, false, 1).unwrap();
        c.list_issues(REPO, 2, &epochs).unwrap();

        // Bob reads the repo directly: verification passes.
        c.add_observer("bob", 3).unwrap();
        assert_eq!(c.observations.observers().count(), 1);

        // Mallory has no direct access: sharing must not widen access.
        let err = c.add_observer("mallory", 4).unwrap_err();
        assert!(matches!(
            err,
            ConnectorError::Gatekeeper(GatekeeperError::ObserverVerificationFailed { .. })
        ));
    }

    #[test]
    fn new_reads_are_blocked_when_an_observer_cannot_see_them() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(
            seeded_backend(),
            grant(vec![
                GrantScope::new("github.repo", REPO, &["read"]),
                GrantScope::new("github.repo", "acme/secret", &["read"]),
            ]),
        );
        consent_all(&mut c);
        c.introduce_by_url(REPO_URL, false, 1).unwrap();
        c.introduce_by_url("https://github.com/acme/secret", false, 1)
            .unwrap();
        c.list_issues(REPO, 2, &epochs).unwrap();

        // Bob (a reader of REPO but NOT of acme/secret) becomes an observer.
        c.add_observer("bob", 3).unwrap();

        // A new read of acme/secret would show bob data he cannot read himself:
        // the read-through rule blocks it.
        let err = c.list_issues("acme/secret", 4, &epochs).unwrap_err();
        assert!(err.to_string().contains("bob"));
        // Alice alone (no observers) could have read it: prove the block came
        // from the observer, not the grant.
        let mut solo = GithubConnector::new(
            seeded_backend(),
            grant(vec![GrantScope::new(
                "github.repo",
                "acme/secret",
                &["read"],
            )]),
        );
        consent_all(&mut solo);
        solo.introduce_by_url("https://github.com/acme/secret", false, 1)
            .unwrap();
        assert!(solo.list_issues("acme/secret", 2, &epochs).is_ok());
    }

    #[test]
    fn lockdown_blocks_side_effects_and_sharing() {
        let epochs = EpochRegistry::new();
        let mut c = GithubConnector::new(seeded_backend(), rw_grant());
        consent_all(&mut c);
        c.introduce_by_url(REPO_URL, true, 1).unwrap();

        // A maximally sensitive observation lands (e.g. a security advisory).
        let d = c.observations.authorize_observation(
            ObservationDescription {
                kind: "github.repo".into(),
                unit: REPO.into(),
                sub_resource: "security-advisories".into(),
                summary: "read embargoed advisory".into(),
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
        let err = c
            .open_pull_request(REPO, "t", "", "h", "b", 3, &epochs)
            .unwrap_err();
        assert!(matches!(err, ConnectorError::LockedDown));

        // Sharing refuses.
        assert!(c.add_observer("bob", 4).is_err());
        // ...and the refused share left no verified observer behind.
        assert_eq!(c.observers.verified_observers().count(), 0);
    }
}
