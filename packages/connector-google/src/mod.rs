//! The Google connector: a concrete implementation of the
//! `gatekeeper` contract for Google Docs, Sheets and Drive.
//!
//! One connector owns one external service. This one owns Google:
//!
//! * **Connector-owned OAuth** — the session runs the connect flow through
//!   the gatekeeper `TokenVault` (nonce-protected callbacks, replay refused)
//!   and HOLDS the token; every call requires a currently-Valid token and
//!   persistence only ever sees SHA-256 digests.
//! * **Resource scoping** — connections are scoped to specific documents
//!   (`google.doc`), spreadsheets (`google.sheet`) and Drive folders
//!   (`google.drive.folder`), introduced by URL, never to whole accounts.
//! * **Observed reads** — document reads and folder listings pass through
//!   the `ObservationAuthorizer` before data is returned; folder listings
//!   record every touched file as its own tracked sub-resource, and a new
//!   read at least one registered observer may not see is blocked.
//! * **Approvable actions** — appending to a document is submitted to the
//!   `ApprovalQueue` with a locally *simulated* outcome, so the agent keeps
//!   working while the human decides later. Appends implement revert
//!   (restore the prior revision).
//! * **Typed surface + bounded catalog** — code-mode agents get a `.d.ts`
//!   for the session API and a hard-capped discovery catalog.
//!
//! The vendor boundary is [`GoogleBackend`]: the offline gates use the
//! in-memory [`FixtureBackend`]; a deployed connector app supplies a live
//! backend over its declared egress. Credentials never appear in this
//! package's public types — the vault holds them, exactly as the AI gateway
//! holds provider keys.
//!
//! This is a *source package*: composed into a consuming app's `src/` tree
//! by `tools/ferrite-pkg` alongside its `gatekeeper` dependency, running
//! under that app's injected authority alone.

pub mod backend;
pub mod connector;
pub mod surface;

pub use backend::{DocState, FileMeta, FixtureBackend, FolderState, GoogleBackend};
pub use connector::{
    supported_resources, AppendReceipt, ConnectorError, GoogleConnector, SessionSummary,
};
pub use surface::{google_catalog, google_tool_surface};
