# blueprints

Blueprints and sharing mechanics packaged as vendored source. A blueprint captures a surface's code and binding requirements while excluding state, chat history, credentials, and live connections; recipients instantiate their own copy and wire their own accounts to each declared binding. Alongside blueprint packaging, this package provides three sharing patterns reusable wherever sharing exists: share keys stored only as hashes, lazy revocation via reachability over a permission graph with blast-radius preview, and capability-shaped role interfaces that fail closed.

This is a source package, not a standalone crate or a deployed service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree, where it executes solely under that application's injected authority.

## Status

Ported from the retired standalone blueprints crate, carrying all three modules (`blueprint`, `roles`, and `sharing`) and their tests; this package is now the canonical source. The code is deterministic and unit-gated; nothing here is live-certified.

## Ferrite Platform Shape

- Depends on the `gatekeeper` package (mounted transitively by `ferrite-pkg`) for `TimestampMs` and its SHA-256 surface, so share-key digests reuse that implementation instead of carrying a second copy. Since the crypto consolidation, that surface delegates to `ferrite_app::crypto`, leaving no FIPS 180-4 port behind it. There are no `hostImports`.
- Uses only what `ferrite-app` re-exports (`serde`, `serde_json`, `crypto`). `BlueprintError`, `SessionError`, and `SharingError` replace `thiserror` with hand-written `Display` and `Error` implementations preserving the exact messages the `thiserror` derive produced. `sha2` is replaced by the SDK digest reached through `gatekeeper`.
- Holds no ambient authority. Nothing reads a clock, environment variable, socket, or file: every timestamp is passed as `TimestampMs`, and share-key entropy is caller-supplied through `ShareKey::from_entropy`.
- Stores all state in in-memory `BTreeMap` and `BTreeSet` structures with deterministic iteration order. Every registry and graph round-trips through `serde` so consumers can persist state through their own storage bindings.

## Not Claimed

- State lives in process memory only. `BlueprintRegistry`, `ShareKeyStore`, and `PermissionGraph` discard their data on drop; each consumer owns persistence (by serializing through its own storage binding) and concurrency control.
- Transport and identity are outside this package. Nothing here mints links, serves routes, or authenticates parties; callers pass already-authenticated principal names and carry archives over their own channels.
- Publish and import screening is heuristic, not a general secret scanner. It refuses known state and credential shapes (paths, PEM blocks, vendor token prefixes, and SQLite magic) as a structural guard rather than claiming exhaustive secret detection.
- The package is not deployed by itself. It has no `ferrite.json`, no `Cargo.toml`, and no bindings of its own. Its only consumer is the offline benchmark harness; no deployed application mounts it.

## Validation

Because a source package is not a standalone build target, its tests run inside its consuming application:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check <consumer>
cargo test --manifest-path <consumer>/Cargo.toml
```

The governance bench mounts this package at `src/blueprints` (with `gatekeeper` at `src/gatekeeper`) behind that workspace's `ferrite_app` shim providing `serde`, `serde_json`, and `crypto`.
