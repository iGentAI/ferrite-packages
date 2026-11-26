# wasm-runtime

WebAssembly interpreter that a constrained Ferrite app can compile directly into its crate: a runtime store and stack interpreter over pre-parsed modules, with no dependencies beyond the Rust standard library and the app's `ferrite-app`.

This tree is vendored from `tinywasm` and patched for Ferrite. The patch is central to how the package works, and it is why the two earlier hand-maintained copies of this code diverged.

## Status

A working interpreter, vendored and patched rather than written from scratch. Module types live under `types/` (there is no parser; modules arrive pre-parsed), the runtime store and stack interpreter live under `rt/`, and `serde_arc.rs` provides a serde shim so `Arc`-carrying types round-trip through `ferrite_app::serde`.

Consuming applications mount this package directly or transitively through `qjs-engine` to run precompiled QuickJS and SQLite guest workloads. Their gates, probes, and benchmarks exercise the interpreter under real workloads; in-tree unit tests cover the store, tables, and paged memory. Upstream tracking is manual. Every divergence from `tinywasm` is marked `FERRITE PATCH`, and those markers serve as the checklist when re-vendoring a newer upstream release.

## Ferrite Platform Shape

This is a vendored source package, not a Cargo crate and not a service. Consuming applications are deployable Ferrite apps, and a deployable app may depend on exactly one crate (`ferrite-app`). A shared interpreter crate cannot satisfy that rule, so shared source composed by `tools/ferrite-pkg` is the only mechanism (see `packages/README.md`). The source follows that constraint: serde derives go through `ferrite_app::serde`, everything else comes from the standard library, there are no external wasm crates or tokio, and `hostImports` is empty.

The package has one configuration and declares no Cargo features. Upstream gates `std`, NaN canonicalization, and `Debug` derives behind feature flags, whereas here all three are always enabled because every consumer turned them on and the disabled paths had stopped compiling (`std` off reached for a `no_std_floats` module this tree does not ship). Consumers' replay contracts depend on canonical NaNs. Because `ferrite-pkg check` rejects any `cfg(feature = ...)` not declared in the package manifest, a re-vendored upstream file cannot silently reintroduce a feature switch.

### The Ferrite patch: `Arc`, not `Rc`

Upstream uses `Rc` for the module instance, host-function handles, and lazily allocated linear memory. A Ferrite app's entry point is `FerriteApp::run`, an `async fn`, and a paged execution must survive being held across an `await`. Because `Rc` is not `Send`, every occurrence is replaced with `Arc`, and the memory trait object carries `+ Send`. Each patched site is marked `FERRITE PATCH` so re-vendoring a newer `tinywasm` has an explicit checklist.

Two further changes exist because upstream Ferrite Core's code gate would otherwise reject every app that mounts this package. First, upstream's `rt/std.rs` re-exported all of `std` under a local module named `std`, which the code gate flags as importing an ambient-authority ancestor and which also hid the tree's one clock read: `resume_with_time_budget` measured its budget with `std::time::Instant`. The local alias is removed so the source names `std::` directly, and `resume_with_time_budget` now takes the caller's injected `ferrite_app::Clock` at millisecond resolution. Second, every glob re-export is written as `self::...::*`, `Debug` derives keep their prelude identity, and `#[rustfmt::skip]` along with docs.rs-only `doc(cfg)` attributes are removed, keeping the mounting crate provably free of globs that could rebind a reviewed macro.

### Consuming it

Add the mount to `ferrite-packages.json`:

```json
{ "packages": { "wasm-runtime": { "mount": "wasm" } } }
```

Run `node tools/ferrite-pkg/ferrite-pkg.mjs sync`, then declare the module in the crate root (matching `crateRoot` in `ferrite-package.json`):

```rust
extern crate alloc;
mod wasm;
```

Mounting at `wasm` is not required, but it is the path of least friction: the source refers to itself as `crate::wasm`, so any other mount point is rewritten during sync and the vendored copy ceases to be textually identical to this tree.

### Editing

Edit files in this directory, then sync. Vendored copies carry a `@generated` header naming this path, and `ferrite-pkg check` fails if a copy is modified in place. Direct edits to a vendored copy are overwritten on the next sync.

## Not Claimed

This package is not a service and not a second implementation of an owned capability. There is no wasm-execution process or deployment here; the interpreter compiles into the app that mounts it and runs strictly under that app's authority.

It provides no host bindings, no WASI, no filesystem, and no clock. Those belong to the mounting app: QuickJS hosts supply their own `wasi` shim and capability gate, and SQLite hosts supply their guest layer and page store. The interpreter knows nothing about either, which is what allows multiple workloads to share it.

It is not a compiler. It is a stack interpreter with no JIT and no native code generation, which is what lets it run inside a constrained app.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check     # vendored copies match this source
cargo test --manifest-path <consumer>/Cargo.toml # each consumer runs the in-package tests
```
