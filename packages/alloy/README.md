# alloy

Ferrite Alloy is the Rust half of a Next.js-class application framework, packaged as `ferrite-pkg` source so a constrained Ferrite app can mount it without naming a second Cargo dependency.

An Alloy application lives in one repository and produces two artifacts: this constrained Rust crate, which owns routing, data loading, mutations, caching, and document assembly, and an ordinary Vite + React 19 bundle, which owns the user interface. Between them sits a generated, typed contract emitted by `alloy-gen`, the CLI's generator, so changing a loader signature in Rust becomes a TypeScript compile error in the React app.

## Match a request to a page

Import routing types from `crate::alloy::router`. `RouteTable::resolve` returns a `router::Resolution` carrying either the matched route and path parameters or the redirect, method error, or missing-page response to return.

```rust
use crate::alloy::router::{Resolution, Route, RouteTable};

fn matches_catalog(path: &str, method: &str) -> Result<bool, String> {
    let mut routes = RouteTable::new();
    routes.push(Route::page("catalog-item", "/catalog/[id]")?);
    Ok(matches!(
        routes.resolve(path, method),
        Resolution::Matched { route, .. } if route.id == "catalog-item"
    ))
}
```

`matches_catalog("/catalog/42", "GET")` returns `Ok(true)`. `POST` on the same path yields `Resolution::MethodNotAllowed`, an unknown path yields `Resolution::NotFound`, and a declared redirect yields `Resolution::Redirect`.

## Status

Implemented and unit-gated. The owner harness mounts the canonical source and its crypto dependency directly; it is not a deployable package:

```sh
cargo test --locked --manifest-path packages/alloy/Cargo.toml --lib
```

Serve-loop regression tests cover GET copies queued after the gateway's hedge delay and copies arriving while reply publication is held. Both must reuse the first handler result while retaining admission for every delivery. Consumer deployment and hosted latency remain separate checks.

Replay memory is capped at 8 MiB of allocated reply buffers and correlation keys, 32 entries, and 60 seconds; oversized replies are served without caching. Requests taking more than 500 ms locally emit one structured timing event covering admission, handling, reply publication, and acknowledgement, including failed publication or acknowledgement. The event records the correlation ID and method, never paths, headers, or bodies, and does not measure time waiting in the queue.

The suite also runs inside consuming apps. For example, a social-feed application mounts it at `alloy` and serves cached loaders, a replay-safe repost action, tag-epoch invalidation, and Rust-assembled documents. The package itself makes no live claim; anything deployed is the consuming app's claim, defended by that app's gates.

Version 0.5.1 lets `alloy::Result` take its error type as an optional second parameter (`Result<T, E = AlloyError>`), so importing it no longer hides standard `Result<T, E>`. Version 0.5.0 adds `AlloyError::Reply`, a complete reply built by another component that the runtime sends as written instead of rendering a problem document. Applications that sign users in with the `auth` package pass the gate's own refusals (the 303 to sign-in, 401, and the 403 naming a failed CSRF check) through `AlloyApp::admit` and `answer` via `auth.gate(req, now).await.map_err(AlloyError::reply)?`. The recipe lives in the `auth` package's `SETUP.md` and `example-alloy/`, whose tests run this package's source through the real serve loop.

For loaders that await remote work, bind `CacheStore::with_clock` to the application's injected clock, such as `.with_clock(move || ctx.now_ms())` with an owned context clone. Freshness is then checked after cache reads, and new entries start their freshness window when the completed load is published to the cache (publication itself can still take time). Tag witnesses remain those captured before loading, so a concurrent tag advance invalidates the result. Fill and refresh leases use acquisition time and are never extended by a slow load. Without `with_clock`, the existing explicit `now_ms` argument continues to date the entire operation.

## Ferrite Platform Shape

Alloy is a source package, not a crate and not a service. `tools/ferrite-pkg` composes it into a consuming app's `src/` tree, where it runs under that app's injected authority alone and passes through the same admission gate as the app's own code. That composition model is what lets a framework exist under the one-dependency rule.

It names no Cargo crate of its own, declares one `ferrite-pkg` dependency (`sha256-hmac`, mounted transitively at `src/crypto/`), and otherwise uses only what `ferrite-app` re-exports (`serde`, `serde_json`, `tracing`, and `crypto`) plus the injected plane clients. There is no clock other than `ctx.now_ms()` and no I/O outside the plane handles, keeping framework logic as simulable as application logic.

| Module | Responsibility |
| --- | --- |
| `router` | Route patterns, parameter extraction, and left-to-right specificity ranking |
| `tags` | Tag-epoch table: O(1) invalidation over one guarded APE envelope |
| `cache` | Cache envelopes, the three freshness windows, witness validation, and the L1 LRU |
| `ctx` | Cached-loader path: L1/L2 lookup, stale-while-revalidate, and single-flight leases |
| `actions` | Replay-safe mutations: markers, action stamps, and the outbox |
| `app` | `AlloyApp` serve loop, admission, origin checks, reply replay, and asset dispatch |
| `outbox` | Durable post-action effect queue and drain helpers |
| `page` | Page response builders and loader payload envelopes |
| `saga` | Multi-step durable workflow helpers over store checkpoints |
| `activity` | Bounded activity-feed recording and queries |
| `draft` | Per-author draft persistence with revision fencing |
| `segments` | URL path segment normalization and matching utilities |
| `document` | Shell templates, `<head>` metadata, and script-safe payload injection |
| `assets` | Binary-safe archive, digest manifest, and blob seeding |
| `error` | Typed error surface, RFC 9457 rendering, and prepared replies sent as written |

Four platform constraints shape the design:

| Platform constraint | Consequence in Alloy |
| --- | --- |
| Single-buffer reply | `IngressReply.body` is a single `Vec<u8>`, so a document cannot stream. Alloy serves a build-time shell and substitutes metadata and loader data into it as a byte substitution rather than a render. |
| Single-key `commit_n_if` guard | APE has no increment operation. Advancing N tags atomically is a guarded read-modify-write over a shared version key, carrying every tag epoch and the action's marker inside the same 64-entry envelope. |
| Hard-cliff store TTL | Only the `expire` window maps onto the store TTL. The `stale` and `revalidate` windows ride inside the envelope and are evaluated at read time. |
| Caller-keyed blobs | Content addressing is an Alloy convention: the generator digests each asset and uses that digest as the blob key, making a redundant seed write a no-op. |

## Not Claimed

| Not claimed | Actual boundary |
| --- | --- |
| Server-side React rendering | No JavaScript runs on the server. React renders in the browser and at build time; a `Hybrid` route's body markup is the build-time skeleton until hydration. Use `Static` where fully rendered HTML without JavaScript is required. |
| Universal exactly-once delivery | The guarantee depends on the effect class: exactly-once for APE-local effects, effectively-once for store writes through an action stamp, naturally idempotent for digest-addressed blob writes, and at-least-once with a carried idempotency key for queue, egress, and notification effects. |
| Cross-shard atomicity | Multi-tag atomicity holds within one version guard. Sharding the guard is a declared future dial, not a current claim. |
| Deployed service | The package ships no transport, persistence, or live surface; those belong to the consuming app. |
| Cargo dependency | Mounting the package any other way than through `ferrite-pkg` breaks the one-dependency rule it exists to respect. |

## Validation

The suite lives beside each module under `#[cfg(test)]` and runs with the app that mounts the package:

```bash
cargo test --manifest-path <consumer>/Cargo.toml   # the package's tests run inside each consumer
node tools/ferrite-pkg/ferrite-pkg.mjs check
ferrite check                      # the real admission gate, from a consuming app
```

What that suite proves:

| Area | Verified behaviour |
| --- | --- |
| Routing | Static segments beat parameters and a longer literal prefix wins, compared segment by segment; catch-alls bind their tails; route groups never reach a URL; a wrong method returns 405 with an `Allow` set instead of 404; matching order does not depend on declaration order. |
| Tag epochs | No tag name, including `@ver`, can collide with the version guard; an advance carries at most 63 tags beside it; epochs are byte-ordered. |
| Caching | The three windows are ordered and relative to the write; an advanced tag epoch invalidates an otherwise-fresh entry; a witness is canonical regardless of tag order and refuses mismatched or conflicting inputs; L1 is bounded by both bytes and entries. |
| Actions | Marker keys are a length-prefixed digest, so `("a:b", "c")` and `("a", "b:c")` cannot collide and no caller-supplied text can escape its namespace; an undecodable marker fails closed rather than re-admitting; an effect key colliding with the protocol's own keys is refused. |
| Documents | A payload containing `</script><script>alert(1)</script>` cannot break out of its data island, and the escaped JSON still parses to the same value; a shell missing either marker is refused. |
| Assets | Base64 and LZSS round-trip arbitrary binary content; malformed streams, bad back-references, truncated archives, trailing bytes, and absurd file counts all return errors rather than panicking. |
