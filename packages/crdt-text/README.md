# crdt-text

`crdt-text` is a pure-Rust sequence CRDT for collaborative plain-text and Markdown documents. It is packaged as `ferrite-pkg` source so a constrained Ferrite application can mount it without adding a second `[dependencies]` entry. It names no crate of its own and uses only `ferrite_app::serde` and `ferrite_app::serde_json`, the same re-exports used by the plane clients.

## Status

Implemented and unit-gated, though no application mounts it today. Because no `ferrite-packages.json` in the repository names `crdt-text`, its tests run only once a consumer mounts it. It was written for server-side merging in a collaborative editor, where the server validates and applies each update into the room's `Doc`, persists the compacted snapshot, and serves the merged snapshot and rendered text. The package itself makes no live claim; anything deployed is the consuming app's claim, defended by that app's gates.

## Ferrite Platform Shape

This is a source package, not a standalone Cargo crate or service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree, where it runs under that app's injected authority alone. It has zero preconditions on its host: no I/O, no clock, no entropy, and no `hostImports`. Replica identity (`site`) and counters arrive as parameters, which keeps the package within the one-dependency rule.

### Contract

Mount the package under the root module `crdt` and drive a per-document `Doc`:

```rust
use crate::crdt::{Doc, Update, alloc_between};

// Server owns the authoritative document.
let mut doc = Doc::new();

// Validate and merge an incoming update. Malformed JSON or a structurally
// invalid position id is rejected in full; nothing is applied.
let update = Update::from_slice(bytes)?;   // or Update::from_value(json)
doc.apply_update(&update)?;

// Compact to a canonical snapshot for durable storage, and render text.
let snapshot: Vec<u8> = doc.to_snapshot();
let text: String = doc.text();

// Rehydrate later.
let doc = Doc::from_snapshot(&snapshot)?;
```

A client mints operations with `alloc_between`, which returns a dense position ID strictly ordered between two neighbors or at a document end.

### Model

Each character (a Unicode scalar) carries an `Id` consisting of a `path` of `(digit, site)` levels and a per-replica `counter`. IDs are totally ordered and globally unique because the minting replica's `site` and `counter` make the final level unique to that replica, preventing collisions between distinct inserts.

The document is a sorted map from `Id` to cell. Convergence is structural: applying the same set of operations in any order produces the identical map, rendered text, and compacted snapshot.

Deletes use tombstones. A deleted cell stays in the map and is flagged rather than removed, so a delete delivered before its insert still converges. Re-applying operations is idempotent: an `Insert` never overwrites an existing character or clears a tombstone, and a `Delete` only sets the tombstone.

## Not Claimed

This package implements a Unicode-scalar text-sequence CRDT only.

It is deliberately not wire-compatible with Yjs (Y.js) binary updates or any other external CRDT format. Update and snapshot encodings use this package's own JSON shapes. A server owning this CRDT merges, validates, compacts, and renders text for documents modeled by this package, and does not interoperate with a Yjs client.

It does not model rich-text attributes, embedded objects, or awareness and cursor presence, only an ordered sequence of characters.

It is not a service and makes no live claim. Transport, persistence, and any deployed surface belong to the consuming application.

## Validation

The test suite lives in `src/mod.rs` under `#[cfg(test)]` and runs inside the consuming application because a package is not a build target:

```bash
cargo test --manifest-path <consumer>/Cargo.toml crdt
node tools/ferrite-pkg/ferrite-pkg.mjs check
```

That suite verifies six properties:

- Concurrent inserts and tombstone deletes from N replicas converge to the same document under in-order, reverse, round-robin, and 25 pseudo-random delivery orders, checked on both rendered text and the byte-exact compacted snapshot.
- Applying a batch two or three times produces the same state as applying it once.
- A delete delivered before its insert converges with in-order delivery.
- Concurrent inserts at the same position both survive and order deterministically.
- Snapshot round-trips preserve tombstones and continue to converge after rehydration.
- Validation rejects non-JSON input, wrong-shape JSON, empty position paths, and out-of-range digits.
