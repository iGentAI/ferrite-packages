# `connector-github`

`connector-github` implements the GitHub connector on the [`gatekeeper`](../gatekeeper/) contract.

It is a source package, not a standalone Cargo crate or service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree and transitively mounts its `gatekeeper` dependency. Inside that application, the package runs under the app's injected authority alone.

## Capabilities

| Area | Behavior |
| --- | --- |
| Repo-scoped grants | Connections are introduced by repository URL (`https://github.com/{owner}/{repo}`) and scoped to specific `github.repo` units, never whole accounts. `ensure_resources` expands grants by the delta and reports only the vendor OAuth scopes required by the new resources; the expansion takes effect once the host records consent with `record_consent`. |
| Observed reads | `list_issues` and `list_pulls` pass an `ObservationDescription` through `ObservationAuthorizer` before returning data. Every attempt, allowed or blocked, writes an audit record. |
| Approvable actions | `open_pull_request` queues an entry in `ApprovalQueue` and returns a simulated pull request immediately. Human approval (`approve_and_apply`) opens the real pull request, and `revert_pull_request` closes it. Auto-approval requires both the user's per-kind opt-in and the author's per-action verdict. |
| Observer sharing | Before registering a recipient, `add_observer` verifies every historical observation against that recipient's own access using the single-unit ACL strategy for repositories. |
| Typed surface and catalog | `github_tool_surface()` renders the `.d.ts` definitions injected into a code-mode worker, and `github_catalog()` returns the hard-capped discovery catalog. |

## Status

Ported from the retired standalone GitHub connector crate with all three modules and its full in-file unit suite (13 governance tests in `connector.rs` and 3 surface/catalog tests in `surface.rs`, 16 total); this package is now the canonical source. Tests are deterministic and unit-gated against `FixtureBackend`; nothing here is live-certified.

## Ferrite Platform Shape

`connector-github` declares one package dependency, `gatekeeper`, reached under `crate::gatekeeper` through the consumer's composed source tree, and no `hostImports`. It relies only on what `ferrite-app` re-exports (`serde` and `serde_json`). Rather than depending on `thiserror`, `ConnectorError` carries hand-written `Display` and `Error` implementations with the same error messages the derive produced; the `Gatekeeper` variant stays transparent and forwards the inner message and source.

The package holds no ambient authority. Nothing reads a clock, socket, environment variable, or file. Every timestamp is passed as a `TimestampMs` parameter, and all GitHub interactions sit behind the `GithubBackend` trait.

## Not Claimed

This package makes no live GitHub calls. Building a live backend over declared egress belongs to the consuming application, which implements `GithubBackend` on its own egress handle and holds its token the way the AI gateway holds provider keys. Only the in-memory `FixtureBackend` ships here, and no connector built on this package has run against the real GitHub API.

OAuth flows are outside this package. Token acquisition, refresh, and storage belong to the host (see `gatekeeper::oauth` for the contract pieces); `GithubBackend` never sees a credential type.

The package is not independently deployable. It has no `ferrite.json`, no `Cargo.toml`, and no bindings of its own.

## Validation

Because a source package is not a standalone build target, its tests run inside a consuming application:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check <consumer>
cargo test --manifest-path <consumer>/Cargo.toml
```

The 13 governance tests in `connector.rs` form the end-to-end gate: repository introduction, governed reads, simulated pull request creation with approval and revert, observer verification and refusal, lockdown semantics, and grant expiry or revocation refusals. `surface.rs` tests `.d.ts` rendering and catalog bounds (3 tests).

## Approval API in 2.0

`approve_and_apply` takes the current `EpochRegistry` and rechecks the reviewed repository, action kind, grant expiry, revocation, introduction, and lockdown before approving or issuing vendor I/O. The reviewed argument object supplies the complete pull request body. `add_comment` queues a comment, and `approve_comment` requires the exact same scope and digest and applies it once; comments do not advertise revert support. Every refused issue or pull request read records a blocked audit entry without adding an allowed observation.

## Reversal authorization in 3.0

Revert calls also require the current `EpochRegistry`. They recheck expiry, revocation, introduced write scope, and surface lockdown, and accept only the vendor effect recorded by that action. Restored pre-upgrade queue records lacking an applied-effect receipt fail closed; a caller-supplied PR number or revision cannot manufacture one. Auto-approved writes record the same receipt.

Reversal attempts are fenced before calling the backend. If the backend returns an error, the action stays `Applied` with `revert_attempted: true` instead of claiming a successful reversal or automatically retrying an unknown outcome. The host must preserve the queue and reconcile that outcome through its own vendor-aware recovery path. Because this synchronous connector is neither a database nor a crash-safe transaction coordinator, durable write-ahead intent and external idempotency remain the embedding host's responsibility.

## Approval and recovery boundary

Version 4 makes the connector-owned approval queue private. Use `approvals()` for read-only history and `reject_action()` for rejection. Applied receipts can only be recorded by the owning connector after its vendor operation succeeds, and queue-only `revert` always refuses. Queued records and applied receipts bind the exact grant identity, epoch, and expiry. Each connector instance retains the greatest epoch it has observed and refuses lower snapshots during its lifetime, though the host must still supply the authoritative current epoch registry.

Arbitrary serialized applied receipts cannot be restored through the public connector API. Undo after process loss requires a trusted host journal and an explicitly authenticated recovery design, neither of which this package provides. The in-memory epoch high-water mark is not durable anti-rollback across restarts. Receipts must never be reconstructed from caller-supplied vendor object identifiers, and vendor transport errors keep the attempted-undo fence for external reconciliation rather than retrying an uncertain effect.
