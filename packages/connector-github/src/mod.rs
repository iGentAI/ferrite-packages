//! The GitHub connector: a concrete implementation of the
//! [`gatekeeper`](crate::gatekeeper) contract, proving the contract the way a
//! second consumer proves a package.
//!
//! One connector owns one external service. This one owns GitHub:
//!
//! * **Resource scoping** — connections are scoped to specific repositories
//!   (`github.repo`), introduced by URL, never to whole accounts.
//! * **Observed reads** — issue and PR reads pass through the
//!   `ObservationAuthorizer` before data is returned; every read audits.
//! * **Approvable actions** — opening a PR / commenting are submitted to the
//!   `ApprovalQueue` with a locally *simulated* outcome, so the agent keeps
//!   working while the human decides later. PR-opening implements revert
//!   (close the PR); comments do too (delete the comment).
//! * **Typed surface + bounded catalog** — code-mode agents get a `.d.ts`
//!   for the session API and a hard-capped discovery catalog.
//!
//! The vendor boundary is [`GithubBackend`]: the offline gates use the
//! in-memory [`FixtureBackend`]; a deployed connector app supplies a live
//! backend over its declared egress. Credentials never appear in this
//! package's types — the backend holds them, exactly as the AI gateway holds
//! provider keys.
//!
//! This is a **source package** (composed by `tools/ferrite-pkg`). Its one
//! package dependency is `gatekeeper`, reached as `crate::gatekeeper::…` in
//! the consumer's composed tree.

pub mod backend;
pub mod connector;
pub mod surface;

pub use backend::{FixtureBackend, GithubBackend, Issue, PullRequest, RepoState};
pub use connector::{ConnectorError, GithubConnector, SessionSummary};
pub use surface::{github_catalog, github_tool_surface};
