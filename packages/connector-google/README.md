# `connector-google`

`connector-google` implements the Google connector on the [`gatekeeper`](../gatekeeper/) contract for Docs, Sheets, and Drive folders. It provides scoped grants, observed reads, simulated approvable actions, observer-verified sharing, and connector-owned OAuth.

It is a source package, not a standalone Cargo crate or service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree and transitively mounts its `gatekeeper` dependency. Inside that application, the package runs under the app's injected authority alone.

## Status

Ported from the retired standalone Google connector crate, keeping the connector core, the `GoogleBackend` vendor boundary with its `FixtureBackend`, the typed surface and catalog, and the end-to-end governance gate; this package is now the canonical source. Tests are deterministic and unit-gated against fixtures; nothing here is live-certified.

## Ferrite Platform Shape

`connector-google` declares one package dependency, `gatekeeper`, and no `hostImports`. It relies only on what `ferrite-app` re-exports (`serde` and `serde_json`). `ConnectorError` carries hand-written `Display` and `Error` implementations with the same error messages previously derived with `thiserror`.

The vendor boundary is the `GoogleBackend` trait, so the connector core never sees a credential or socket. Offline gates run against the in-memory `FixtureBackend`; a deployed connector app supplies a live backend over its declared egress and passes vendor results back in.

| Resource kind | URL pattern | Observer verification |
| --- | --- | --- |
| `google.doc` | `https://docs.google.com/document/d/{id}` (with or without `/edit`) | Single-unit ACL (strategy B) |
| `google.sheet` | `https://docs.google.com/spreadsheets/d/{id}` | Single-unit ACL (strategy B) |
| `google.drive.folder` | `https://drive.google.com/drive/folders/{id}` | Dataset tracking (strategy C): every file touched by a listing is recorded as a `folder/file` sub-resource and re-verified per observer |

Read access requires the `drive.file:read` scope; write access adds `drive.file:write`.

Reads (`read_document`, `list_folder`) pass through `ObservationAuthorizer` before data is returned. If any registered observer could not see a new read themselves, the read is blocked and names those observers; blocked reads are audited as `Blocked` and never enter observed history. Writes (`append_to_document`, kind `google.doc.append` or `google.sheet.append`) return a simulated receipt immediately; the real append lands on approval and reverts by restoring the prior revision. Auto-approval requires both the user's per-kind opt-in and the author's per-action verdict.

The connector runs the OAuth connect flow (nonce-protected callbacks with replay refusal) and holds the token in the gatekeeper `TokenVault`. Every call requires a currently `Valid` token, returning `NotConnected` otherwise. Persistence sees only SHA-256 digests, never the raw token.

The package holds no ambient authority. Nothing reads a clock, environment variable, socket, or file. Every timestamp arrives as a `TimestampMs` parameter, OAuth entropy comes from the host, and vendor calls are executed by the host and fed back in.

## Not Claimed

This package makes no live Google API calls and runs no live OAuth flows. All gates run offline against `FixtureBackend`. Performing the real OAuth exchange, refresh calls, and Docs, Sheets, and Drive requests over declared egress belongs to the consuming application; this package defines only the `GoogleBackend` seam.

Credential handling stops at the vault posture. Token storage, rotation, and transport are not implemented here; `TokenVault` holds material in memory and exposes digests.

The package is not independently deployable. It has no `ferrite.json`, no `Cargo.toml`, and no bindings of its own.

## Validation

Because a source package is not a standalone build target, its tests, including the ported end-to-end governance gate in the `#[cfg(test)]` module of `src/connector.rs`, run inside a consuming application:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check <consumer>
cargo test --manifest-path <consumer>/Cargo.toml
```

## Approval and Sheets API in 2.0

`approve_and_apply` takes the current `EpochRegistry` and rechecks the reviewed resource kind, grant, connected token, introduction, and lockdown. A spreadsheet introduction stays `google.sheet`; read and append admission never substitutes `google.doc` rights. `GoogleBackend` requires `read_sheet`, `append_to_sheet`, and `revert_sheet`, so hosts must route those operations explicitly to their Sheets implementation. The offline fixture uses revisioned text for both kinds, which does not establish live Google API or OAuth acceptance.

## Reversal authorization in 3.0

Revert calls also require the current `EpochRegistry`. They recheck expiry, revocation, introduced write scope, and surface lockdown, and accept only the vendor effect recorded by that action. Restored pre-upgrade queue records lacking an applied-effect receipt fail closed; a caller-supplied revision cannot manufacture one. Auto-approved writes record the same receipt.

Reversal attempts are fenced before calling the backend. If the backend returns an error, the action stays `Applied` with `revert_attempted: true` instead of claiming a successful reversal or automatically retrying an unknown outcome. The host must preserve the queue and reconcile that outcome through its own vendor-aware recovery path. Because this synchronous connector is neither a database nor a crash-safe transaction coordinator, durable write-ahead intent and external idempotency remain the embedding host's responsibility.

Google backends implement `append_document_with_receipt` and `append_sheet_with_receipt`, along with `revert_document_with_receipt` and `revert_sheet_with_receipt`. An append returns `AppendEffect { revision, token }`, where `token` identifies that exact mutation and must never be recycled when a visible revision number is reused. Revert must atomically compare the current mutation token and restore its predecessor. The default implementations refuse without mutating; a read followed by an unconditional restore does not satisfy this contract. The offline fixture tracks distinct mutation tokens and tests intervening edits and revision-number reuse, which is not evidence of a live Google adapter.

## Approval and recovery boundary

Version 4 makes the connector-owned approval queue private. Use `approvals()` for read-only history and `reject_action()` for rejection. Applied receipts can only be recorded by the owning connector after its vendor operation succeeds, and queue-only `revert` always refuses. Queued records and applied receipts bind the exact grant identity, epoch, and expiry. Each connector instance retains the greatest epoch it has observed and refuses lower snapshots during its lifetime, though the host must still supply the authoritative current epoch registry.

Arbitrary serialized applied receipts cannot be restored through the public connector API. Undo after process loss requires a trusted host journal and an explicitly authenticated recovery design, neither of which this package provides. The in-memory epoch high-water mark is not durable anti-rollback across restarts. Receipts must never be reconstructed from caller-supplied vendor object identifiers, and vendor transport errors keep the attempted-undo fence for external reconciliation rather than retrying an uncertain effect.

The backend must also implement `resource_kind(id)` from trusted Drive metadata, returning `google.doc` or `google.sheet`; the default refuses unsupported adapters. Pasted URL shapes cannot establish resource identity or turn a read-only spreadsheet grant into document write authority. The fixture exposes separate `seed_document` and `seed_sheet` methods, and conflicting introductions fail closed.
