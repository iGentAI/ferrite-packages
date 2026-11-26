//! Personal Agent Protocol (Poppy 1.0) discovery, exposure policy,
//! RFC 9651 structured-field parsing, OpenAPI/tasks/feedback projections,
//! and validation.
//!
//! Declaring a [`PoppyConfig`] on [`crate::agent_ready::well_known::PageSource::poppy`]
//! projects a Ferrite app's Poppy 1.0 surface mechanically from its existing
//! [`Surface`] — with explicit per-operation exposure controls deciding what
//! Personal Agents may call signed out, what requires user OAuth scopes, what
//! requires exact-terms approval (`operations` v3), and what stays internal-only.

use std::collections::BTreeMap;

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::artefacts;
use crate::agent_ready::catalog;
use crate::agent_ready::sha256;
use crate::agent_ready::skills::Skill;
use crate::agent_ready::surface::Surface;

/// Published Personal Agent Protocol version targeted by this implementation.
pub const PROTOCOL_VERSION: &str = "1.0";
pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

/// Agent Skills discovery schema pinned by Poppy 1.0 §9.4.
pub const AGENT_SKILLS_DISCOVERY_SCHEMA: &str =
    "https://schemas.agentskills.io/discovery/0.2.0/schema.json";

/// Reserved Poppy scope for signed-in browser sessions (§6).
pub const SCOPE_BROWSER_SIGN_IN: &str = "poppy:browser-sign-in";

/// Official Poppy extension names & major versions supported by this package.
pub const EXT_OPERATIONS: &str = "operations";
pub const EXT_OPERATIONS_VERSION: &str = "3";
pub const EXT_BROWSER_CONTROL: &str = "browser-control";
pub const EXT_BROWSER_CONTROL_VERSION: &str = "1";
pub const EXT_LINKS: &str = "links";
pub const EXT_LINKS_VERSION: &str = "1";
pub const EXT_DISCLOSURES: &str = "disclosures";
pub const EXT_DISCLOSURES_VERSION: &str = "1";
pub const EXT_UCP: &str = "ucp";
pub const EXT_UCP_VERSION: &str = "1";

/// Request & response header names used by Poppy 1.0 (lowercase).
pub mod headers {
    pub const SESSION: &str = "poppy-session";
    pub const VERSION: &str = "poppy-version";
    pub const EXTENSIONS: &str = "poppy-extensions";
    pub const APPROVAL: &str = "poppy-approval";
    pub const OPERATION: &str = "poppy-operation";
}

/// Canonical Poppy paths projected under the application's origin.
pub mod paths {
    pub const DISCOVERY: &str = "/.well-known/poppy.json";
    pub const OAUTH_PRM_DOMAIN: &str = "/.well-known/oauth-protected-resource";
    pub const OAUTH_PRM_MCP: &str = "/.well-known/oauth-protected-resource/mcp";
    pub const OAUTH_AS_METADATA: &str = "/.well-known/oauth-authorization-server";
    pub const POPPY_OPENAPI: &str = "/poppy/openapi.json";
    pub const TASKS: &str = "/poppy/tasks";
    pub const FEEDBACK: &str = "/poppy/feedback";
    pub const BROWSER_SESSION: &str = "/poppy/browser-session";
    pub const BROWSER_SESSION_AUTHORIZE: &str = "/poppy/browser-session/authorize";
    pub const OPERATIONS: &str = "/poppy/operations";
    pub const CONVERSATIONS: &str = "/poppy/conversations";
    pub const GUIDE: &str = "/poppy/guide";
    pub const GUIDE_JSON: &str = "/poppy/guide.json";
}

/// Consequence hint for an OAuth scope (§4.7 `auth.scope_hints`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum ScopeChanges {
    None,
    Reversible,
    Irreversible,
}

impl ScopeChanges {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeChanges::None => "none",
            ScopeChanges::Reversible => "reversible",
            ScopeChanges::Irreversible => "irreversible",
        }
    }
}

/// One OAuth scope offered to Personal Agents (§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ScopeSpec {
    pub name: String,
    pub description: String,
    pub changes: ScopeChanges,
    pub personal_data: bool,
}

impl ScopeSpec {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        changes: ScopeChanges,
        personal_data: bool,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            changes,
            personal_data,
        }
    }
}

/// Whether and how a declared [`Surface`] operation is exposed to Poppy Personal Agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum PoppyExposure {
    /// Callable by signed-out or signed-in Personal Agents.
    Public,
    /// Callable only by a signed-in Personal Agent holding all listed OAuth scopes.
    SignedIn { scopes: Vec<String> },
    /// Kept internal to the application: excluded from Poppy's OpenAPI projection
    /// and refused to Personal Agents.
    InternalOnly,
}

/// Exact-terms confirmation policy for an operation (`operations` v3 extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum ApprovalPolicy {
    /// No Poppy `operations` v3 confirmation required.
    None,
    /// Require an explicit `operations` v3 approval covering exact terms before executing.
    Required {
        /// Validity window of each computed revision, in seconds (guides recommend ≥900s when possible).
        ttl_secs: u64,
        /// When `true`, `approver="agent"` is declined (`403 approval_declined`) and only
        /// `approver="user"` is accepted.
        require_user_approver: bool,
    },
}

/// Per-operation Poppy policy: exposure boundary, optional scopes, and approval requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct OperationPolicy {
    pub exposure: PoppyExposure,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_scopes: Vec<String>,
    pub approval: ApprovalPolicy,
}

impl Default for OperationPolicy {
    fn default() -> Self {
        Self {
            exposure: PoppyExposure::Public,
            optional_scopes: Vec::new(),
            approval: ApprovalPolicy::None,
        }
    }
}

/// OAuth authorization posture for this Company (§3.2).
///
/// Poppy mandates one issuer per Company: unrelated tenant apps on Ferrite MUST NOT
/// share a single platform issuer. Each app chooses signed-out operation, its own
/// self-hosted issuer (`poppy-oauth`), a bring-your-own external OAuth issuer
/// (Okta, WorkOS, Auth0, customer AS), or a dedicated per-company issuer on a
/// multi-tenant OAuth service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum PoppyAuth {
    /// Signed-out Sessions only; no OAuth issuer (`/.well-known/oauth-protected-resource` returns 404).
    /// Company identifier is `https://{organization.domain}`.
    SignedOut,
    /// Company has an issuer (keeping one stable Company identifier) but turns off
    /// Personal Agent sign-in (`auth.disabled: true`, §3.2).
    Disabled { issuer: String },
    /// Bring-your-own external OAuth issuer (e.g. Okta, WorkOS, customer AS, or
    /// dedicated per-company issuer `https://auth.ferrite.cloud/<company-id>`).
    External {
        issuer: String,
        /// Set `true` only when the domain PRM lists multiple authorization servers
        /// and `poppy.json` must explicitly disambiguate `auth.issuer` (§3.1, §3.2).
        #[serde(default)]
        emit_issuer_in_poppy: bool,
        #[serde(default)]
        scopes: Vec<ScopeSpec>,
        #[serde(default)]
        extra_authorization_servers: Vec<String>,
    },
    /// Per-app self-hosted OAuth 2.1 issuer served on this app's own canonical origin
    /// (backed by `packages/poppy-oauth`).
    SelfHosted {
        #[serde(default)]
        scopes: Vec<ScopeSpec>,
        #[serde(default)]
        allow_device_sign_in: bool,
        #[serde(default)]
        require_par: bool,
        #[serde(default)]
        require_dpop: bool,
    },
}

/// Website browsing posture in `poppy.json` (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum PoppyWeb {
    /// Omit `web` from `poppy.json` entirely (API-only or agent-only service).
    Omitted,
    /// Ask Personal Agents not to browse in a browser (`web.disabled: true`).
    Disabled,
    /// Allow signed-out website browsing (`web: {}`, no `browser_session_endpoint`).
    SignedOut,
    /// Offer 3-step CSRF-safe Browser Join (`web.browser_session_endpoint`).
    BrowserJoin {
        /// Path or full HTTPS URL of the browser-session endpoint (default `/poppy/browser-session`).
        endpoint: String,
        /// Set `true` if the website cannot enforce fine-grained OAuth scopes and
        /// `poppy:browser-sign-in` grants full website account access (§6).
        unscoped: bool,
        /// Advertise the `browser-control` v1 extension (`data-poppy-user-step`).
        browser_control: bool,
        /// Advertise website-channel `operations` v3 (`extensions.operations[].endpoint`).
        website_operations: bool,
    },
}

/// Access hint on a `poppy` conversation protocol entry (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum AgentAccess {
    Session,
    SignedIn,
}

/// Company Agent conversation configuration (§8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PoppyAgent {
    /// Path or full HTTPS URL of the conversation endpoint (default `/poppy/conversations`).
    pub endpoint: String,
    /// Plain-language description of what the Company Agent can help with (§8.1).
    pub description: String,
    pub access: AgentAccess,
    /// Advertise the `links` v1 extension.
    pub links: bool,
    /// Advertise the `disclosures` v1 extension.
    pub disclosures: bool,
}

/// Reference inside a task [`Alternative`] (§9.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", tag = "type", rename_all = "snake_case")]
pub enum AlternativeRef {
    Openapi { url: String, operation_id: String },
    Mcp { url: String, tool: String },
    Web { url: String },
}

/// Another way to perform a task, used in excluded tasks and feedback responses (§9.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Alternative {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<AlternativeRef>,
}

/// A task the Company intentionally does not offer through Poppy (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ExcludedTask {
    pub task: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative: Option<Alternative>,
}

/// Additional extension entry for `poppy.json` (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ExtensionEntry {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Complete declarative Poppy 1.0 configuration for a Ferrite application.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PoppyConfig {
    /// Human-readable organization display name (§3.1 `organization.name`).
    pub organization_name: String,
    /// Optional HTTPS URL of the Company logo (§3.1 `organization.logo_uri`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// OAuth issuer and scope posture (§3.2).
    pub auth: PoppyAuth,
    /// Default exposure for declared [`Surface`] operations not named in `operation_policies`.
    pub default_exposure: PoppyExposure,
    /// Explicit per-operation exposure & approval policies keyed by `Operation::name`.
    #[serde(default)]
    pub operation_policies: BTreeMap<String, OperationPolicy>,
    /// Expose OpenAPI 3.1 in `poppy.json` `apis` when at least one non-internal operation exists.
    pub expose_openapi: bool,
    /// Expose MCP (`/mcp`) in `poppy.json` `apis` when at least one non-internal operation exists.
    pub expose_mcp: bool,
    /// Website browsing posture (§6).
    pub web: PoppyWeb,
    /// Optional Company Agent conversations endpoint (§8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<PoppyAgent>,
    /// Tasks explicitly not offered to Personal Agents (§9.1).
    #[serde(default)]
    pub excluded_tasks: Vec<ExcludedTask>,
    /// Publish `tasks.endpoint` (`/poppy/tasks`) with excluded tasks, `skill_index`, and feedback.
    pub enable_tasks: bool,
    /// Enable `POST /poppy/feedback` (§9.3).
    pub enable_feedback: bool,
    /// Optional UCP v1 extension advertisement.
    pub enable_ucp: bool,
    /// Optional path or HTTPS URL for a human/agent integration & error-recovery guide
    /// (advertised in `/poppy/openapi.json` `externalDocs` and `x-poppy-conversations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guide_url: Option<String>,
    /// Documented inactivity timeout for §8 conversations, in seconds (default 86400 = 24h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_idle_timeout_secs: Option<u64>,
    /// Documented event retention after a conversation closes, in seconds (default 604800 = 7d).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_retention_secs: Option<u64>,
    /// Additional custom domain-prefixed extensions (e.g. `example.com/gift-wrap`).
    #[serde(default)]
    pub custom_extensions: BTreeMap<String, Vec<ExtensionEntry>>,
}

impl PoppyConfig {
    /// Start a signed-out Poppy 1.0 configuration (no OAuth issuer required).
    pub fn signed_out(organization_name: impl Into<String>) -> Self {
        Self {
            organization_name: organization_name.into(),
            logo_uri: None,
            auth: PoppyAuth::SignedOut,
            default_exposure: PoppyExposure::Public,
            operation_policies: BTreeMap::new(),
            expose_openapi: true,
            expose_mcp: true,
            web: PoppyWeb::SignedOut,
            agent: None,
            excluded_tasks: Vec::new(),
            enable_tasks: true,
            enable_feedback: true,
            enable_ucp: false,
            guide_url: None,
            conversation_idle_timeout_secs: None,
            conversation_retention_secs: None,
            custom_extensions: BTreeMap::new(),
        }
    }

    /// Start a Poppy 1.0 configuration backed by an external OAuth issuer
    /// (customer's own IdP or a per-company issuer on a multi-tenant service).
    pub fn with_external_issuer(
        organization_name: impl Into<String>,
        issuer: impl Into<String>,
        scopes: Vec<ScopeSpec>,
    ) -> Self {
        let mut cfg = Self::signed_out(organization_name);
        cfg.auth = PoppyAuth::External {
            issuer: issuer.into(),
            emit_issuer_in_poppy: false,
            scopes,
            extra_authorization_servers: Vec::new(),
        };
        cfg
    }

    /// Start a Poppy 1.0 configuration backed by a per-app self-hosted OAuth 2.1 issuer
    /// on this application's own origin (`packages/poppy-oauth`).
    pub fn with_self_hosted_oauth(
        organization_name: impl Into<String>,
        scopes: Vec<ScopeSpec>,
    ) -> Self {
        let mut cfg = Self::signed_out(organization_name);
        cfg.auth = PoppyAuth::SelfHosted {
            scopes,
            allow_device_sign_in: false,
            require_par: false,
            require_dpop: false,
        };
        cfg
    }

    pub fn with_logo(mut self, logo_uri: impl Into<String>) -> Self {
        self.logo_uri = Some(logo_uri.into());
        self
    }

    pub fn default_internal_only(mut self) -> Self {
        self.default_exposure = PoppyExposure::InternalOnly;
        self
    }

    /// Explicitly expose an operation to signed-out & signed-in Poppy agents.
    pub fn expose_public(mut self, op_name: impl Into<String>) -> Self {
        let entry = self.operation_policies.entry(op_name.into()).or_default();
        entry.exposure = PoppyExposure::Public;
        self
    }

    /// Require user sign-in and specific OAuth scopes for an operation.
    pub fn require_scopes(mut self, op_name: impl Into<String>, scopes: &[&str]) -> Self {
        let entry = self.operation_policies.entry(op_name.into()).or_default();
        entry.exposure = PoppyExposure::SignedIn {
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        };
        self
    }

    /// Keep an operation internal-only (never exposed in Poppy OpenAPI or Poppy MCP).
    pub fn keep_internal(mut self, op_name: impl Into<String>) -> Self {
        let entry = self.operation_policies.entry(op_name.into()).or_default();
        entry.exposure = PoppyExposure::InternalOnly;
        self
    }

    /// Require Poppy `operations` v3 confirmation before executing an operation.
    pub fn require_approval(
        mut self,
        op_name: impl Into<String>,
        ttl_secs: u64,
        require_user_approver: bool,
    ) -> Self {
        let entry = self.operation_policies.entry(op_name.into()).or_default();
        entry.approval = ApprovalPolicy::Required {
            ttl_secs,
            require_user_approver,
        };
        self
    }

    pub fn exclude_task(
        mut self,
        task: impl Into<String>,
        alternative: Option<Alternative>,
    ) -> Self {
        self.excluded_tasks.push(ExcludedTask {
            task: task.into(),
            alternative,
        });
        self
    }

    pub fn with_web(mut self, web: PoppyWeb) -> Self {
        self.web = web;
        self
    }

    pub fn with_company_agent(mut self, agent: PoppyAgent) -> Self {
        self.agent = Some(agent);
        self
    }

    pub fn with_guide_url(mut self, guide_url: impl Into<String>) -> Self {
        self.guide_url = Some(guide_url.into());
        self
    }

    pub fn with_conversation_lifetime(mut self, idle_timeout_secs: u64, retention_secs: u64) -> Self {
        self.conversation_idle_timeout_secs = Some(idle_timeout_secs);
        self.conversation_retention_secs = Some(retention_secs);
        self
    }

    /// Look up the effective policy for an operation by name.
    pub fn policy_for(&self, op_name: &str) -> OperationPolicy {
        self.operation_policies
            .get(op_name)
            .cloned()
            .unwrap_or_else(|| OperationPolicy {
                exposure: self.default_exposure.clone(),
                optional_scopes: Vec::new(),
                approval: ApprovalPolicy::None,
            })
    }

    /// Whether an operation is exposed to Poppy Personal Agents at all.
    pub fn is_exposed(&self, op_name: &str) -> bool {
        !matches!(self.policy_for(op_name).exposure, PoppyExposure::InternalOnly)
    }

    /// Whether any exposed operation or website requires `operations` v3.
    pub fn uses_operations_extension(&self, surface: &Surface) -> bool {
        let any_op = surface.operations().any(|o| {
            let p = self.policy_for(&o.name);
            !matches!(p.exposure, PoppyExposure::InternalOnly)
                && matches!(p.approval, ApprovalPolicy::Required { .. })
        });
        let web_ops = matches!(
            self.web,
            PoppyWeb::BrowserJoin {
                website_operations: true,
                ..
            }
        );
        any_op || web_ops
    }

    /// The OAuth issuer URL, if this Company has one (§3.2).
    pub fn issuer(&self, surface: &Surface) -> Option<String> {
        match &self.auth {
            PoppyAuth::SignedOut => None,
            PoppyAuth::Disabled { issuer } => Some(issuer.trim_end_matches('/').to_string()),
            PoppyAuth::External { issuer, .. } => Some(issuer.trim_end_matches('/').to_string()),
            PoppyAuth::SelfHosted { .. } => Some(surface.origin.trim_end_matches('/').to_string()),
        }
    }

    /// The Company's identifier (§3.2): its issuer when present, else `https://{domain}`
    /// (lowercased host, no trailing slash). Used as Session JWT `aud`.
    pub fn company_identifier(&self, surface: &Surface) -> String {
        if let Some(issuer) = self.issuer(surface) {
            return issuer;
        }
        format!("https://{}", domain_from_origin(&surface.origin))
    }

    /// Configured OAuth scopes (empty for signed-out / disabled auth).
    pub fn scopes(&self) -> &[ScopeSpec] {
        match &self.auth {
            PoppyAuth::SignedOut | PoppyAuth::Disabled { .. } => &[],
            PoppyAuth::External { scopes, .. } | PoppyAuth::SelfHosted { scopes, .. } => scopes,
        }
    }

    /// Whether sign-in is offered to Personal Agents.
    pub fn offers_sign_in(&self) -> bool {
        matches!(
            self.auth,
            PoppyAuth::External { .. } | PoppyAuth::SelfHosted { .. }
        )
    }

    /// Validate the Poppy configuration against the [`Surface`].
    /// Returns `POPPY_*` gate-code violations, empty when clean.
    pub fn validate(&self, surface: &Surface) -> Vec<String> {
        let mut v = Vec::new();
        if self.organization_name.trim().is_empty() {
            v.push("POPPY_ORG_NAME_EMPTY: organization_name must be non-empty".into());
        }
        let domain = domain_from_origin(&surface.origin);
        if !is_valid_poppy_domain(&domain) {
            v.push(format!(
                "POPPY_DOMAIN_INVALID: origin '{}' does not yield a valid Poppy domain (must have at least one dot, e.g. app.example.com)",
                surface.origin
            ));
        }
        if let Some(logo) = &self.logo_uri {
            if !is_https_url(logo) {
                v.push(format!(
                    "POPPY_LOGO_HTTPS: organization.logo_uri '{}' must be an https:// URL",
                    logo
                ));
            }
        }

        let exposed_ops: Vec<_> = surface
            .operations()
            .filter(|o| self.is_exposed(&o.name))
            .collect();
        let has_apis = !exposed_ops.is_empty() && (self.expose_openapi || self.expose_mcp);
        let has_web = !matches!(self.web, PoppyWeb::Omitted);
        let has_agent = self.agent.is_some();
        if !has_apis && !has_web && !has_agent {
            v.push(
                "POPPY_NO_CHANNEL: poppy.json requires at least one of apis, web, or agent (§3.1)"
                    .into(),
            );
        }
        if matches!(self.web, PoppyWeb::Disabled) && !has_apis && !has_agent {
            v.push(
                "POPPY_WEB_DISABLED_NO_ALT: web.disabled requires apis or agent (§6)".into(),
            );
        }

        if let Some(agent) = &self.agent {
            if agent.description.trim().is_empty() {
                v.push("POPPY_AGENT_DESC_EMPTY: agent protocol description must be non-empty (§8.1)".into());
            }
            if agent.access == AgentAccess::SignedIn && !self.offers_sign_in() {
                v.push(
                    "POPPY_AGENT_SIGNED_IN_NO_AUTH: agent access=signed_in requires an active issuer (not SignedOut or auth.disabled) (§3.2)"
                        .into(),
                );
            }
        }

        if let Some(issuer) = self.issuer(surface) {
            if !is_https_url(&issuer) {
                v.push(format!(
                    "POPPY_ISSUER_HTTPS: issuer '{}' must be an https:// URL (§3)",
                    issuer
                ));
            }
        }

        let scope_names: std::collections::BTreeSet<&str> =
            self.scopes().iter().map(|s| s.name.as_str()).collect();
        for scope in self.scopes() {
            if !is_valid_oauth_scope_token(&scope.name) {
                v.push(format!(
                    "POPPY_SCOPE_SYNTAX: scope '{}' is not a valid OAuth scope token (RFC 6749 §3.3)",
                    scope.name
                ));
            }
            if scope.description.trim().is_empty() {
                v.push(format!(
                    "POPPY_SCOPE_DESC_EMPTY: scope '{}' needs a task-oriented description (§4.7)",
                    scope.name
                ));
            }
        }

        // §6: browser_session_endpoint + sign-in requires poppy:browser-sign-in scope.
        if matches!(self.web, PoppyWeb::BrowserJoin { .. })
            && self.offers_sign_in()
            && !scope_names.contains(SCOPE_BROWSER_SIGN_IN)
        {
            v.push(format!(
                "POPPY_MISSING_BROWSER_SCOPE: browser_session_endpoint with sign-in MUST declare scope '{SCOPE_BROWSER_SIGN_IN}' (§6)"
            ));
        }

        // Check every operation policy references valid scopes and exists on Surface.
        let surface_ops: std::collections::BTreeSet<&str> =
            surface.operations().map(|o| o.name.as_str()).collect();
        for (name, policy) in &self.operation_policies {
            if !surface_ops.contains(name.as_str()) {
                v.push(format!(
                    "POPPY_UNKNOWN_OP: operation policy '{}' does not match any declared Surface operation",
                    name
                ));
            }
            if let PoppyExposure::SignedIn { scopes } = &policy.exposure {
                if !self.offers_sign_in() {
                    v.push(format!(
                        "POPPY_SIGNED_IN_OP_NO_AUTH: operation '{}' requires sign-in, but auth offers no sign-in",
                        name
                    ));
                }
                if scopes.is_empty() {
                    v.push(format!(
                        "POPPY_SIGNED_IN_OP_NO_SCOPES: signed-in operation '{}' must name at least one scope",
                        name
                    ));
                }
                for sc in scopes {
                    if !scope_names.contains(sc.as_str()) {
                        v.push(format!(
                            "POPPY_OP_SCOPE_UNDECLARED: operation '{}' requires scope '{}' which is absent from PoppyAuth scopes",
                            name, sc
                        ));
                    }
                }
            }
        }

        for (ext_name, entries) in &self.custom_extensions {
            if !ext_name.contains('/') {
                v.push(format!(
                    "POPPY_EXT_NAMESPACE: custom extension '{}' MUST be domain-prefixed (e.g. example.com/name) (§3.3)",
                    ext_name
                ));
            }
            if entries.is_empty() {
                v.push(format!(
                    "POPPY_EXT_EMPTY: custom extension '{}' must list at least one version",
                    ext_name
                ));
            }
        }

        v
    }
}

/// Extract host[:port] lowercased from an origin URL (`https://example.com:8443` -> `example.com:8443`).
pub fn domain_from_origin(origin: &str) -> String {
    let authority = origin
        .split("://")
        .nth(1)
        .unwrap_or(origin)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    // Strip default port 443 (§3.1: include port only when not 443).
    authority.strip_suffix(":443").unwrap_or(&authority).to_string()
}

/// Check Poppy's domain pattern (`poppy.schema.json#/$defs/domain`).
pub fn is_valid_poppy_domain(domain: &str) -> bool {
    let (host, port) = match domain.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (domain, None),
    };
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if p.parse::<u16>().is_err() {
            return false;
        }
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// True when `url` is a valid `https://` URL with a non-empty host.
pub fn is_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !host.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// Resolve a path (`/poppy/tasks`) or full URL against `surface.origin`.
pub fn resolve_url(surface: &Surface, path_or_url: &str) -> String {
    if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
        path_or_url.to_string()
    } else {
        surface.url(path_or_url)
    }
}

/// Check RFC 6749 §3.3 scope-token syntax (`%x21 / %x23-5B / %x5D-7E`).
pub fn is_valid_oauth_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// Check Poppy ID syntax (`^[A-Za-z0-9_-]{1,256}$`, §8.2).
pub fn is_valid_poppy_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Project `/.well-known/poppy.json` from `Surface` + `PoppyConfig` (§3, §3.1).
pub fn poppy_json(surface: &Surface, cfg: &PoppyConfig) -> Value {
    let mut doc = Map::new();
    doc.insert("protocol_version".into(), Value::String(PROTOCOL_VERSION.into()));

    let mut org = Map::new();
    org.insert("name".into(), Value::String(cfg.organization_name.clone()));
    org.insert("domain".into(), Value::String(domain_from_origin(&surface.origin)));
    if let Some(logo) = &cfg.logo_uri {
        org.insert("logo_uri".into(), Value::String(logo.clone()));
    }
    doc.insert("organization".into(), Value::Object(org));

    // `auth` object (§3.1, §3.2, §4.7).
    match &cfg.auth {
        PoppyAuth::SignedOut => {}
        PoppyAuth::Disabled { issuer } => {
            doc.insert(
                "auth".into(),
                serde_json::json!({
                    "issuer": issuer.trim_end_matches('/'),
                    "disabled": true
                }),
            );
        }
        PoppyAuth::External {
            issuer,
            emit_issuer_in_poppy,
            scopes,
            extra_authorization_servers,
        } => {
            let mut auth = Map::new();
            if *emit_issuer_in_poppy || !extra_authorization_servers.is_empty() {
                auth.insert("issuer".into(), Value::String(issuer.trim_end_matches('/').into()));
            }
            insert_scope_maps(&mut auth, scopes);
            if !auth.is_empty() {
                doc.insert("auth".into(), Value::Object(auth));
            }
        }
        PoppyAuth::SelfHosted { scopes, .. } => {
            let mut auth = Map::new();
            insert_scope_maps(&mut auth, scopes);
            if !auth.is_empty() {
                doc.insert("auth".into(), Value::Object(auth));
            }
        }
    }

    // `agent` object (§8.1).
    if let Some(agent) = &cfg.agent {
        let mut entry = Map::new();
        entry.insert("type".into(), Value::String("poppy".into()));
        entry.insert("endpoint".into(), Value::String(resolve_url(surface, &agent.endpoint)));
        entry.insert("description".into(), Value::String(agent.description.clone()));
        if agent.access == AgentAccess::SignedIn {
            entry.insert("access".into(), Value::String("signed_in".into()));
        }
        doc.insert(
            "agent".into(),
            serde_json::json!({ "protocols": [Value::Object(entry)] }),
        );
    }

    // `web` object (§6).
    match &cfg.web {
        PoppyWeb::Omitted => {}
        PoppyWeb::Disabled => {
            doc.insert("web".into(), serde_json::json!({ "disabled": true }));
        }
        PoppyWeb::SignedOut => {
            doc.insert("web".into(), serde_json::json!({}));
        }
        PoppyWeb::BrowserJoin {
            endpoint,
            unscoped,
            ..
        } => {
            let mut web = Map::new();
            web.insert(
                "browser_session_endpoint".into(),
                Value::String(resolve_url(surface, endpoint)),
            );
            if *unscoped {
                web.insert("unscoped".into(), Value::Bool(true));
            }
            doc.insert("web".into(), Value::Object(web));
        }
    }

    // `tasks` object (§9).
    if cfg.enable_tasks {
        doc.insert(
            "tasks".into(),
            serde_json::json!({ "endpoint": surface.url(paths::TASKS) }),
        );
    }

    // `apis` array (§7) — projected only when at least one operation is exposed to Poppy.
    let exposed_count = surface
        .operations()
        .filter(|o| cfg.is_exposed(&o.name))
        .count();
    let mut apis = Vec::new();
    if exposed_count > 0 && cfg.expose_openapi {
        apis.push(serde_json::json!({
            "type": "openapi",
            "url": surface.url(paths::POPPY_OPENAPI),
            "description": surface.description,
        }));
    }
    if exposed_count > 0 && cfg.expose_mcp {
        apis.push(serde_json::json!({
            "type": "mcp",
            "url": surface.url(artefacts::paths::MCP),
            "description": format!("MCP tools for {}: {}", surface.name, surface.description),
        }));
    }
    if !apis.is_empty() {
        doc.insert("apis".into(), Value::Array(apis));
    }

    // `extensions` object (§3.3).
    let mut extensions = Map::new();
    if cfg.uses_operations_extension(surface) {
        let mut entry = Map::new();
        entry.insert("version".into(), Value::String(EXT_OPERATIONS_VERSION.into()));
        if matches!(
            cfg.web,
            PoppyWeb::BrowserJoin {
                website_operations: true,
                ..
            }
        ) {
            entry.insert(
                "endpoint".into(),
                Value::String(surface.url(paths::OPERATIONS)),
            );
        }
        extensions.insert(EXT_OPERATIONS.into(), Value::Array(vec![Value::Object(entry)]));
    }
    if matches!(
        cfg.web,
        PoppyWeb::BrowserJoin {
            browser_control: true,
            ..
        }
    ) {
        extensions.insert(
            EXT_BROWSER_CONTROL.into(),
            serde_json::json!([{ "version": EXT_BROWSER_CONTROL_VERSION }]),
        );
    }
    if let Some(agent) = &cfg.agent {
        if agent.links {
            extensions.insert(
                EXT_LINKS.into(),
                serde_json::json!([{ "version": EXT_LINKS_VERSION }]),
            );
        }
        if agent.disclosures {
            extensions.insert(
                EXT_DISCLOSURES.into(),
                serde_json::json!([{ "version": EXT_DISCLOSURES_VERSION }]),
            );
        }
    }
    if cfg.enable_ucp {
        extensions.insert(
            EXT_UCP.into(),
            serde_json::json!([{ "version": EXT_UCP_VERSION }]),
        );
    }
    for (name, entries) in &cfg.custom_extensions {
        let arr: Vec<Value> = entries
            .iter()
            .map(|e| {
                let mut m = Map::new();
                m.insert("version".into(), Value::String(e.version.clone()));
                if let Some(ep) = &e.endpoint {
                    m.insert("endpoint".into(), Value::String(resolve_url(surface, ep)));
                }
                Value::Object(m)
            })
            .collect();
        extensions.insert(name.clone(), Value::Array(arr));
    }
    if !extensions.is_empty() {
        doc.insert("extensions".into(), Value::Object(extensions));
    }

    Value::Object(doc)
}

fn insert_scope_maps(auth: &mut Map<String, Value>, scopes: &[ScopeSpec]) {
    if scopes.is_empty() {
        return;
    }
    let mut desc_map = Map::new();
    let mut hint_map = Map::new();
    for s in scopes {
        desc_map.insert(s.name.clone(), Value::String(s.description.clone()));
        hint_map.insert(
            s.name.clone(),
            serde_json::json!({
                "changes": s.changes.as_str(),
                "personal_data": s.personal_data,
            }),
        );
    }
    auth.insert("scopes".into(), Value::Object(desc_map));
    auth.insert("scope_hints".into(), Value::Object(hint_map));
}

/// Project domain RFC 9728 protected resource metadata (`/.well-known/oauth-protected-resource`).
/// Returns `None` for `PoppyAuth::SignedOut` (HTTP 404 means issuerless Company per §3.2).
pub fn domain_protected_resource_metadata(surface: &Surface, cfg: &PoppyConfig) -> Option<Value> {
    let issuer = cfg.issuer(surface)?;
    let mut servers = vec![issuer];
    if let PoppyAuth::External {
        extra_authorization_servers,
        ..
    } = &cfg.auth
    {
        for extra in extra_authorization_servers {
            let trimmed = extra.trim_end_matches('/').to_string();
            if !servers.contains(&trimmed) {
                servers.push(trimmed);
            }
        }
    }
    let mut doc = serde_json::json!({
        "resource": format!("https://{}", domain_from_origin(&surface.origin)),
        "authorization_servers": servers,
    });
    let scopes: Vec<&str> = cfg.scopes().iter().map(|s| s.name.as_str()).collect();
    if !scopes.is_empty() {
        doc["scopes_supported"] = serde_json::json!(scopes);
    }
    Some(doc)
}

/// Project MCP-specific RFC 9728 metadata (`/.well-known/oauth-protected-resource/mcp`, §7).
pub fn mcp_protected_resource_metadata(surface: &Surface, cfg: &PoppyConfig) -> Option<Value> {
    let issuer = cfg.issuer(surface)?;
    let mut doc = serde_json::json!({
        "resource": surface.url(artefacts::paths::MCP),
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    });
    let scopes: Vec<&str> = cfg.scopes().iter().map(|s| s.name.as_str()).collect();
    if !scopes.is_empty() {
        doc["scopes_supported"] = serde_json::json!(scopes);
    }
    Some(doc)
}

/// Project an exposure-filtered OpenAPI 3.1 catalog specifically for Poppy Personal Agents
/// (`/poppy/openapi.json`): omits `InternalOnly` operations, adds OAuth 2.0 security schemes,
/// per-operation `security` scopes, and `403 approval_required` documentation.
pub fn poppy_openapi(surface: &Surface, cfg: &PoppyConfig) -> Result<Value, Vec<String>> {
    // Build a filtered Surface containing only Poppy-exposed operations.
    let mut filtered = surface.clone();
    for route in &mut filtered.routes {
        route.operations.retain(|o| cfg.is_exposed(&o.name));
    }
    let mut doc = catalog::openapi(&filtered)?;

    // Attach OAuth 2.0 security scheme when sign-in is offered.
    if cfg.offers_sign_in() && !cfg.scopes().is_empty() {
        let mut scope_descs = Map::new();
        for s in cfg.scopes() {
            scope_descs.insert(s.name.clone(), Value::String(s.description.clone()));
        }
        let issuer = cfg.issuer(surface).unwrap_or_else(|| surface.origin.clone());
        doc["components"] = serde_json::json!({
            "securitySchemes": {
                "poppyOAuth": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": format!("{issuer}/oauth/authorize"),
                            "tokenUrl": format!("{issuer}/oauth/token"),
                            "scopes": scope_descs
                        }
                    }
                }
            }
        });
    }

    // Annotate each exposed operation with its required scopes and approval contract.
    if let Some(paths_obj) = doc.get_mut("paths").and_then(Value::as_object_mut) {
        for op in filtered.operations() {
            let policy = cfg.policy_for(&op.name);
            let method = op.method.to_ascii_lowercase();
            if let Some(op_obj) = paths_obj
                .get_mut(&op.path)
                .and_then(Value::as_object_mut)
                .and_then(|item| item.get_mut(&method))
                .and_then(Value::as_object_mut)
            {
                match &policy.exposure {
                    PoppyExposure::Public => {
                        op_obj.insert("security".into(), serde_json::json!([]));
                    }
                    PoppyExposure::SignedIn { scopes } => {
                        op_obj.insert(
                            "security".into(),
                            serde_json::json!([{ "poppyOAuth": scopes }]),
                        );
                    }
                    PoppyExposure::InternalOnly => {}
                }
                if let ApprovalPolicy::Required {
                    ttl_secs,
                    require_user_approver,
                } = policy.approval
                {
                    op_obj.insert(
                        "x-poppy-approval".into(),
                        serde_json::json!({
                            "required": true,
                            "extension": EXT_OPERATIONS,
                            "version": EXT_OPERATIONS_VERSION,
                            "ttl_secs": ttl_secs,
                            "require_user_approver": require_user_approver,
                        }),
                    );
                    if let Some(responses) =
                        op_obj.get_mut("responses").and_then(Value::as_object_mut)
                    {
                        responses.insert(
                            "403".into(),
                            serde_json::json!({
                                "description": if require_user_approver {
                                    "Approval required (Poppy operations v3: approval_required with exact terms & revision; retry with Poppy-Approval header and approver=\"user\", or approval_declined if approver=\"agent\")"
                                } else {
                                    "Approval required (Poppy operations v3: approval_required with exact terms & revision; retry with Poppy-Approval header containing operation_id, revision, and approver)"
                                },
                                "content": { "application/json": {} }
                            }),
                        );
                    }
                }
            }
        }
    }

    if let Some(guide) = &cfg.guide_url {
        doc["externalDocs"] = serde_json::json!({
            "description": "Poppy 1.0 Agent Guide: conversation flow, error recovery, idempotency, and capability matrix",
            "url": resolve_url(surface, guide),
        });
    }

    if let Some(agent) = &cfg.agent {
        let ep = resolve_url(surface, &agent.endpoint);
        let idle = cfg.conversation_idle_timeout_secs.unwrap_or(86_400);
        let retain = cfg.conversation_retention_secs.unwrap_or(604_800);
        let mut conv_meta = serde_json::json!({
            "endpoint": ep,
            "list_endpoint": ep,
            "close_endpoint_template": format!("{ep}/{{conversation_id}}/close"),
            "resume_endpoint_template": format!("{ep}/{{conversation_id}}/resume"),
            "idle_timeout_secs": idle,
            "retention_secs": retain,
            "operations_approval": cfg.uses_operations_extension(surface),
        });
        if let Some(guide) = &cfg.guide_url {
            conv_meta["guide_url"] = Value::String(resolve_url(surface, guide));
        }
        doc["x-poppy-conversations"] = conv_meta;
    }

    Ok(doc)
}

/// Project `GET /poppy/tasks` (§9, §9.1, §9.3, §9.4), including Agent Skills discovery `0.2.0`.
pub fn tasks_json(surface: &Surface, cfg: &PoppyConfig, authored_skills: &[Skill]) -> Value {
    let mut doc = Map::new();
    if !cfg.excluded_tasks.is_empty() {
        doc.insert(
            "excluded_tasks".into(),
            serde_json::to_value(&cfg.excluded_tasks).unwrap_or(Value::Array(Vec::new())),
        );
    }

    // Project `skill_index` in Agent Skills discovery 0.2.0 format (§9.4).
    let skills_arr: Vec<Value> = if !authored_skills.is_empty() {
        authored_skills
            .iter()
            .filter_map(|skill| {
                let primary = skill
                    .files
                    .iter()
                    .find(|f| f.uri == skill.uri || f.uri.ends_with("/SKILL.md"))
                    .or_else(|| skill.files.first())?;
                let name = skill
                    .frontmatter
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())?;
                let description = skill
                    .frontmatter
                    .get("description")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())?;
                let digest = format!("sha256:{}", sha256::to_hex(&sha256::sha256(&primary.bytes)));
                let rel = format!(
                    "/.well-known/agent-skills/{}",
                    primary.uri.trim_start_matches("skill://")
                );
                Some(serde_json::json!({
                    "name": name,
                    "description": description,
                    "type": "skill-md",
                    "url": surface.url(&rel),
                    "digest": digest,
                }))
            })
            .collect()
    } else {
        let generated = artefacts::skill_md(surface);
        let digest = format!(
            "sha256:{}",
            sha256::to_hex(&sha256::sha256(generated.as_bytes()))
        );
        vec![serde_json::json!({
            "name": "use-this-app",
            "description": surface.description,
            "type": "skill-md",
            "url": surface.url(artefacts::SKILL_PATH),
            "digest": digest,
        })]
    };

    if !skills_arr.is_empty() {
        doc.insert(
            "skill_index".into(),
            serde_json::json!({
                "$schema": AGENT_SKILLS_DISCOVERY_SCHEMA,
                "skills": skills_arr,
            }),
        );
    }

    if cfg.enable_feedback {
        doc.insert(
            "feedback".into(),
            serde_json::json!({ "endpoint": surface.url(paths::FEEDBACK) }),
        );
    }

    Value::Object(doc)
}

/// Validated feedback report submitted to `POST /poppy/feedback` (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackReport {
    pub task: String,
    pub description: String,
}

/// Parse and validate a `POST /poppy/feedback` JSON body (§9.3: `task` ≤200 chars,
/// `description` ≤2000 chars, both required non-empty strings).
pub fn parse_feedback_report(body: &[u8]) -> Result<FeedbackReport, PoppyError> {
    let val: Value = serde_json::from_slice(body)
        .map_err(|_| PoppyError::invalid_request("feedback body must be valid JSON"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| PoppyError::invalid_request("feedback body must be a JSON object"))?;
    let task = obj
        .get("task")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty() && s.chars().count() <= 200)
        .ok_or_else(|| {
            PoppyError::invalid_request("task must be a non-empty string of at most 200 characters")
        })?;
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty() && s.chars().count() <= 2000)
        .ok_or_else(|| {
            PoppyError::invalid_request(
                "description must be a non-empty string of at most 2000 characters",
            )
        })?;
    Ok(FeedbackReport {
        task: task.to_string(),
        description: description.to_string(),
    })
}

/// Parsed `Poppy-Version` header (`major.minor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoppyVersion {
    pub major: u32,
    pub minor: u32,
}

/// Parse and check `Poppy-Version` against this Company's served version (§3.4).
/// Compatible when major matches (for major >= 1). Missing or incompatible returns
/// `400 {"error": "version_unsupported"}`.
pub fn check_poppy_version(raw: Option<&str>) -> Result<PoppyVersion, PoppyError> {
    let text = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(PoppyError::version_unsupported)?;
    let (maj, min) = text
        .split_once('.')
        .ok_or_else(PoppyError::version_unsupported)?;
    if maj.is_empty()
        || min.is_empty()
        || !maj.bytes().all(|b| b.is_ascii_digit())
        || !min.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PoppyError::version_unsupported());
    }
    let major: u32 = maj.parse().map_err(|_| PoppyError::version_unsupported())?;
    let minor: u32 = min.parse().map_err(|_| PoppyError::version_unsupported())?;
    if major != PROTOCOL_MAJOR {
        return Err(PoppyError::version_unsupported());
    }
    Ok(PoppyVersion { major, minor })
}

/// Parse `Poppy-Extensions` (RFC 9651 List of Strings with `;v="N"` parameter, §3.4).
/// Per §3.4: without `Poppy-Extensions`, or when it fails to parse, the request
/// declares no extensions (returns an empty map, never an error).
pub fn parse_extensions_header(raw: Option<&str>) -> BTreeMap<String, String> {
    let Some(s) = raw else {
        return BTreeMap::new();
    };
    let s = s.trim();
    if s.is_empty() {
        return BTreeMap::new();
    }
    match parse_sf_extensions(s) {
        Some(map) => map,
        None => BTreeMap::new(),
    }
}

fn parse_sf_extensions(input: &str) -> Option<BTreeMap<String, String>> {
    let mut p = SfReader::new(input);
    let mut out = BTreeMap::new();
    loop {
        p.skip_ows();
        let name = p.quoted_string()?;
        let mut version: Option<String> = None;
        loop {
            p.skip_sp();
            if p.peek() != Some(b';') {
                break;
            }
            p.pos += 1;
            p.skip_sp();
            let key = p.key()?;
            if p.peek() == Some(b'=') {
                p.pos += 1;
                let val = p.bare_item()?;
                if key == "v" {
                    if let SfVal::String(v) = val {
                        version = Some(v);
                    }
                }
            }
        }
        if let Some(v) = version {
            if !name.is_empty() && !v.is_empty() {
                out.insert(name, v);
            }
        }
        p.skip_ows();
        match p.peek() {
            None => return Some(out),
            Some(b',') => {
                p.pos += 1;
            }
            Some(_) => return None,
        }
    }
}

/// Parsed `Poppy-Approval` RFC 9651 Dictionary header (`operations` v3 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ApprovalSubmission {
    pub operation_id: String,
    pub revision: String,
    pub approver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Parse `Poppy-Approval` Dictionary Structured Field (`operations` v3 §6).
/// Unknown dictionary members are ignored per the spec.
pub fn parse_approval_header(raw: &str) -> Option<ApprovalSubmission> {
    let mut p = SfReader::new(raw.trim());
    let mut operation_id = None;
    let mut revision = None;
    let mut approver = None;
    let mut approved_at = None;
    let mut input_type = None;
    let mut reference = None;

    loop {
        p.skip_ows();
        let key = p.key()?;
        let val = if p.peek() == Some(b'=') {
            p.pos += 1;
            p.bare_item()?
        } else {
            SfVal::Other
        };
        // Skip optional member parameters per RFC 9651.
        loop {
            p.skip_sp();
            if p.peek() != Some(b';') {
                break;
            }
            p.pos += 1;
            p.skip_sp();
            let _pk = p.key()?;
            if p.peek() == Some(b'=') {
                p.pos += 1;
                let _pv = p.bare_item()?;
            }
        }
        match (key.as_str(), val) {
            ("operation_id", SfVal::String(v)) => operation_id = Some(v),
            ("revision", SfVal::String(v)) => revision = Some(v),
            ("approver", SfVal::String(v)) => approver = Some(v),
            ("approved_at", SfVal::Integer(n)) => approved_at = Some(n),
            ("input_type", SfVal::String(v)) => input_type = Some(v),
            ("reference", SfVal::String(v)) => reference = Some(v),
            _ => {}
        }
        p.skip_ows();
        match p.peek() {
            None => break,
            Some(b',') => {
                p.pos += 1;
            }
            Some(_) => return None,
        }
    }

    let approver = approver?;
    let input_type = if approver == "agent" {
        None // Spec §6: Company ignores input_type with approver="agent"
    } else {
        input_type
    };
    Some(ApprovalSubmission {
        operation_id: operation_id?,
        revision: revision?,
        approver,
        approved_at,
        input_type,
        reference,
    })
}

/// Format `Poppy-Operation` RFC 9651 Dictionary header (`operations` v3 §4 Websites).
pub fn format_operation_header(sid: &str, reference: &str) -> String {
    format!(
        "sid=\"{}\", ref=\"{}\"",
        escape_sf_string(sid),
        escape_sf_string(reference)
    )
}

fn escape_sf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (' '..='~').contains(&c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// Minimal strict RFC 9651 structured-field reader.
#[derive(Debug, Clone)]
enum SfVal {
    String(String),
    Integer(i64),
    Other,
}

struct SfReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SfReader<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }
    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }
    fn key(&mut self) -> Option<String> {
        let start = self.pos;
        match self.peek()? {
            b'a'..=b'z' | b'*' => self.pos += 1,
            _ => return None,
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'-' | b'.' | b'*')
            {
                self.pos += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .map(str::to_string)
    }
    fn quoted_string(&mut self) -> Option<String> {
        if self.peek()? != b'"' {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'"' => return Some(out),
                b'\\' => {
                    let esc = self.peek()?;
                    if esc != b'"' && esc != b'\\' {
                        return None;
                    }
                    self.pos += 1;
                    out.push(esc as char);
                }
                0x20..=0x7E => out.push(b as char),
                _ => return None,
            }
        }
    }
    fn bare_item(&mut self) -> Option<SfVal> {
        match self.peek()? {
            b'"' => self.quoted_string().map(SfVal::String),
            b'?' => {
                self.pos += 1;
                match self.peek()? {
                    b'1' | b'0' => {
                        self.pos += 1;
                        Some(SfVal::Other)
                    }
                    _ => None,
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                if self.peek() == Some(b'-') {
                    self.pos += 1;
                }
                let digits_start = self.pos;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.pos += 1;
                }
                if self.pos == digits_start || self.pos - digits_start > 15 {
                    return None;
                }
                std::str::from_utf8(&self.bytes[start..self.pos])
                    .ok()?
                    .parse::<i64>()
                    .ok()
                    .map(SfVal::Integer)
            }
            b':' => {
                // Byte sequence `:...:` — skip safely for forward-compat unknown members.
                self.pos += 1;
                while let Some(b) = self.peek() {
                    self.pos += 1;
                    if b == b':' {
                        return Some(SfVal::Other);
                    }
                }
                None
            }
            c if c.is_ascii_alphabetic() || c == b'*' => {
                while let Some(b) = self.peek() {
                    if b.is_ascii_alphanumeric()
                        || b"!#$%&'*+-.^_`|~:/".contains(&b)
                    {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Some(SfVal::Other)
            }
            _ => None,
        }
    }
}

/// Standard Poppy JSON error response (`error.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoppyError {
    pub status: u16,
    pub error: &'static str,
    pub description: Option<String>,
    pub extra: Map<String, Value>,
    pub headers: Vec<(&'static str, String)>,
}

impl PoppyError {
    pub fn invalid_session(desc: impl Into<String>) -> Self {
        Self {
            status: 400,
            error: "invalid_session",
            description: Some(desc.into()),
            extra: Map::new(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    pub fn session_ended(desc: impl Into<String>) -> Self {
        Self {
            status: 400,
            error: "session_ended",
            description: Some(desc.into()),
            extra: Map::new(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    pub fn version_unsupported() -> Self {
        Self {
            status: 400,
            error: "version_unsupported",
            description: Some("Poppy-Version header is missing or incompatible with 1.0".into()),
            extra: Map::new(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    pub fn invalid_request(desc: impl Into<String>) -> Self {
        Self {
            status: 400,
            error: "invalid_request",
            description: Some(desc.into()),
            extra: Map::new(),
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    pub fn extension_required(extension: impl Into<String>) -> Self {
        let mut extra = Map::new();
        extra.insert("extension".into(), Value::String(extension.into()));
        Self {
            status: 403,
            error: "extension_required",
            description: None,
            extra,
            headers: vec![("cache-control", "no-store".into())],
        }
    }

    /// OAuth 401 challenge when a request needs account access and has no token (§7).
    pub fn auth_required(scopes: &[String], resource_metadata: Option<&str>) -> Self {
        let mut challenge = String::from("Bearer");
        let mut parts = Vec::new();
        if !scopes.is_empty() {
            parts.push(format!("scope=\"{}\"", scopes.join(" ")));
        }
        if let Some(rm) = resource_metadata {
            parts.push(format!("resource_metadata=\"{rm}\""));
        }
        if !parts.is_empty() {
            challenge.push(' ');
            challenge.push_str(&parts.join(", "));
        }
        Self {
            status: 401,
            error: "invalid_token",
            description: Some("account authorization required".into()),
            extra: Map::new(),
            headers: vec![
                ("www-authenticate", challenge),
                ("cache-control", "no-store".into()),
            ],
        }
    }

    /// OAuth 403 `insufficient_scope` challenge (§7).
    pub fn insufficient_scope(scopes: &[String], resource_metadata: Option<&str>) -> Self {
        let mut parts = vec!["error=\"insufficient_scope\"".to_string()];
        if !scopes.is_empty() {
            parts.push(format!("scope=\"{}\"", scopes.join(" ")));
        }
        if let Some(rm) = resource_metadata {
            parts.push(format!("resource_metadata=\"{rm}\""));
        }
        Self {
            status: 403,
            error: "insufficient_scope",
            description: Some("access token lacks required scope(s)".into()),
            extra: Map::new(),
            headers: vec![
                ("www-authenticate", format!("Bearer {}", parts.join(", "))),
                ("cache-control", "no-store".into()),
            ],
        }
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut obj = self.extra.clone();
        obj.insert("error".into(), Value::String(self.error.into()));
        if let Some(d) = &self.description {
            obj.insert("error_description".into(), Value::String(d.clone()));
        }
        serde_json::to_vec(&Value::Object(obj)).unwrap_or_else(|_| {
            format!("{{\"error\":\"{}\"}}", self.error).into_bytes()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind};

    fn sample_surface() -> Surface {
        Surface {
            name: "taskboard".into(),
            owner: "acme".into(),
            origin: "https://tasks.acme.example".into(),
            description: "Manage project tasks.".into(),
            version: "1.0.0".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "Task API".into(),
                operations: vec![
                    Operation::new(
                        "list_tasks",
                        "GET",
                        "/api/tasks",
                        "List tasks on the board.",
                        serde_json::json!({"type": "object", "properties": {}}),
                        true,
                    ),
                    Operation::new(
                        "delete_task",
                        "POST",
                        "/api/tasks/delete",
                        "Permanently delete a task.",
                        serde_json::json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}),
                        false,
                    ),
                    Operation::new(
                        "admin_reindex",
                        "POST",
                        "/api/internal/reindex",
                        "Internal maintenance reindex.",
                        serde_json::json!({"type": "object", "properties": {}}),
                        false,
                    ),
                ],
            }],
            pages: vec![],
        }
    }

    #[test]
    fn poppy_json_projects_exposure_scopes_and_extensions() {
        let s = sample_surface();
        let cfg = PoppyConfig::with_self_hosted_oauth(
            "Acme Tasks",
            vec![
                ScopeSpec::new(
                    "tasks:read",
                    "See your tasks and boards.",
                    ScopeChanges::None,
                    false,
                ),
                ScopeSpec::new(
                    "tasks:write",
                    "Create, edit, and delete tasks.",
                    ScopeChanges::Irreversible,
                    false,
                ),
                ScopeSpec::new(
                    SCOPE_BROWSER_SIGN_IN,
                    "Use the website signed in with your approved task scopes.",
                    ScopeChanges::None,
                    false,
                ),
            ],
        )
        .expose_public("list_tasks")
        .require_scopes("delete_task", &["tasks:write"])
        .require_approval("delete_task", 900, true)
        .keep_internal("admin_reindex")
        .with_web(PoppyWeb::BrowserJoin {
            endpoint: paths::BROWSER_SESSION.into(),
            unscoped: false,
            browser_control: true,
            website_operations: true,
        });

        assert!(cfg.validate(&s).is_empty(), "{:?}", cfg.validate(&s));

        let doc = poppy_json(&s, &cfg);
        assert_eq!(doc["protocol_version"], "1.0");
        assert_eq!(doc["organization"]["domain"], "tasks.acme.example");
        assert_eq!(doc["auth"]["scope_hints"]["tasks:write"]["changes"], "irreversible");
        assert_eq!(
            doc["web"]["browser_session_endpoint"],
            "https://tasks.acme.example/poppy/browser-session"
        );
        assert_eq!(doc["extensions"]["operations"][0]["version"], "3");
        assert_eq!(
            doc["extensions"]["operations"][0]["endpoint"],
            "https://tasks.acme.example/poppy/operations"
        );
        assert_eq!(doc["extensions"]["browser-control"][0]["version"], "1");

        // Exposure filter: internal-only op MUST NOT appear in Poppy OpenAPI.
        let oapi = poppy_openapi(&s, &cfg).unwrap();
        assert!(oapi["paths"].get("/api/tasks").is_some());
        assert!(oapi["paths"].get("/api/tasks/delete").is_some());
        assert!(oapi["paths"].get("/api/internal/reindex").is_none());
        assert_eq!(
            oapi["paths"]["/api/tasks/delete"]["post"]["security"][0]["poppyOAuth"],
            serde_json::json!(["tasks:write"])
        );
        assert!(oapi["paths"]["/api/tasks/delete"]["post"]["responses"]
            .get("403")
            .is_some());
    }

    #[test]
    fn rfc9651_extensions_and_approval_parsing() {
        let exts = parse_extensions_header(Some(r#""operations";v="3", "links";v="1""#));
        assert_eq!(exts.get("operations").map(String::as_str), Some("3"));
        assert_eq!(exts.get("links").map(String::as_str), Some("1"));
        // Malformed header parses as empty per §3.4.
        assert!(parse_extensions_header(Some("not-quoted;v=3")).is_empty());

        let apr = parse_approval_header(
            r#"operation_id="exc_5Rt2", revision="1791487200-abc", approver="user", approved_at=1791487260, input_type="tap", reference="apr_1", future_field="ignored""#,
        )
        .unwrap();
        assert_eq!(apr.operation_id, "exc_5Rt2");
        assert_eq!(apr.approver, "user");
        assert_eq!(apr.approved_at, Some(1_791_487_260));
        assert_eq!(apr.input_type.as_deref(), Some("tap"));
        assert_eq!(apr.reference.as_deref(), Some("apr_1"));

        // Agent approval ignores input_type per Operations §6.
        let agent_apr = parse_approval_header(
            r#"operation_id="op1", revision="r1", approver="agent", input_type="tap""#,
        )
        .unwrap();
        assert_eq!(agent_apr.input_type, None);
    }

    #[test]
    fn tasks_json_emits_pinned_0_2_0_skill_index_with_sha256_digest() {
        let s = sample_surface();
        let cfg = PoppyConfig::signed_out("Acme Tasks").exclude_task(
            "Delete the organization",
            Some(Alternative {
                instructions: Some("Use the organization admin console.".into()),
                references: vec![AlternativeRef::Web {
                    url: "https://tasks.acme.example/settings".into(),
                }],
            }),
        );
        let tasks = tasks_json(&s, &cfg, &[]);
        assert_eq!(tasks["skill_index"]["$schema"], AGENT_SKILLS_DISCOVERY_SCHEMA);
        let skill = &tasks["skill_index"]["skills"][0];
        assert_eq!(skill["type"], "skill-md");
        let digest = skill["digest"].as_str().unwrap();
        assert!(digest.starts_with("sha256:") && digest.len() == 7 + 64);
        assert_eq!(tasks["excluded_tasks"][0]["task"], "Delete the organization");
        assert_eq!(
            tasks["feedback"]["endpoint"],
            "https://tasks.acme.example/poppy/feedback"
        );
    }

    #[test]
    fn version_and_feedback_validation() {
        assert_eq!(
            check_poppy_version(Some("1.0")).unwrap(),
            PoppyVersion { major: 1, minor: 0 }
        );
        assert_eq!(
            check_poppy_version(Some("1.4")).unwrap(),
            PoppyVersion { major: 1, minor: 4 }
        );
        assert_eq!(
            check_poppy_version(Some("2.0")).unwrap_err().error,
            "version_unsupported"
        );
        assert_eq!(
            check_poppy_version(None).unwrap_err().error,
            "version_unsupported"
        );

        let too_long = serde_json::json!({
            "task": "x".repeat(201),
            "description": "ok"
        });
        assert_eq!(
            parse_feedback_report(too_long.to_string().as_bytes())
                .unwrap_err()
                .error,
            "invalid_request"
        );
    }
}
