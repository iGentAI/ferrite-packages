# Ferrite packages

Every deployable Ferrite application compiles against exactly one crate dependency, `ferrite-app`. That single-dependency rule keeps the entire application auditable by construction, and it shapes how code is shared: common subsystems like sign-in, payments, email, Alloy, Rsx, and agent-ready surfaces ship as verified source packages.

When you run `ferrite add`, the CLI fetches `registry.json`, verifies every file's SHA-256 digest, copies the source into `src/<mount>/` with `@generated` provenance headers, and records the mount in `ferrite-packages.json`. The code compiles directly inside your crate under the same security boundary as the rest of your app.

```bash
ferrite add agent-ready                           # install from the published registry
ferrite add mcp --path /path/to/this/repository   # or from a local checkout
ferrite check && ferrite test
```

`packages/registry.json` in this repository is the checksummed index for every package published here.

## Package catalogue

| Package | What it provides | Dependencies |
| --- | --- | --- |
| `mcp` | Model Context Protocol (revision 2026-07-28): wire protocol, stateless client, resource server, and OAuth 2.1 | `sha256-hmac` |
| `agent-ready` | Agent readiness by construction: Markdown twins and `Accept: text/markdown`, `llms.txt`, sitemaps, agent cards, MCP faces, RFC 9457 problems, and x402 payment challenges | `http-change-password`, `http-query`, `sha256-hmac` |
| `http-query` | Total query-string decoder | |
| `http-cookies` | `__Host-` prefixed session cookies, built and verified against the rendered header | |
| `http-change-password` | W3C well-known change-password URL and form | |
| `http-route-budget` | Shared, durable token bucket that admits each request against its route's declared budget, kept in a store the application already binds | |
| `sha256-hmac` | SHA-256, HMAC, constant-time compare, hex, PBKDF2 password records, and OS entropy over `ferrite_app::crypto`, mounted at `crypto` | |
| `regex-lite` | Panic-free, step-bounded regular-expression engine | |
| `crdt-text` | Logoot-style sequence CRDT for collaborative text | |
| `gatekeeper` | Governed-connector contract: scoped expiring grants, audit observations, approval queues, schedules, and token vault | |
| `connector-github`, `connector-google` | Connectors built on `gatekeeper`, including fixture backends for offline testing | `gatekeeper` |
| `context-library` | Organisation knowledge exposed as a governed, read-only runtime service | `gatekeeper` |
| `blueprints` | Capture and share a surface's code and binding requirements without its state or credentials | `gatekeeper` |
| `messaging` | Transactional email and chat: request builders, safe renderer, retry classification, and a single egress seam | |
| `poppy-oauth` | Per-application OAuth 2.1 issuer for the Personal Agent Protocol (Poppy 1.0) | `agent-ready`, `http-query`, `sha256-hmac` |
| `byok-vault` | Encrypted per-user storage for provider API keys a user brings, with key verification and request headers for the Ferrite AI Gateway | `sha256-hmac` |
| `payments` | Stripe request builders, webhook verification, an idempotent event ledger, and the x402 payment path | `agent-ready`, `sha256-hmac` |
| `alloy` | Rust runtime for the Alloy application framework: routing, tag-epoch caching, replay-safe actions, and document assembly | `sha256-hmac` |
| `alloy-auth` | Credential-verified actors, store-backed sessions, host-only cookies, and session-bound CSRF | `alloy`, `http-change-password`, `http-cookies`, `sha256-hmac` |
| `rsx` | Runtime half of the Rsx application framework | |
| `serde-codec` | Compact LEB128 binary codec for embedding modules in application source | |
| `wasm-runtime` | Safe-Rust WebAssembly interpreter that compiles inside a constrained application (derived from tinywasm; see `NOTICE`) | |

Each package directory includes its own README describing its interface, guarantees, and validation suite. Package unit tests live alongside the source in this repository; `ferrite add` strips `#[cfg(test)]` modules on install so `ferrite test` runs your application's own test suite. After installing a package, add the `pub mod` lines (and any `[features]` entries) printed by `ferrite add` to your crate root so Cargo compiles the mounted tree.

## Monorepo composition tool

`tools/ferrite-pkg/ferrite-pkg.mjs` applies the same composition inside a repository that holds both `packages/` and consuming applications. `sync` writes vendored copies with provenance headers, `check` fails on drift, and `registry` regenerates the index. It runs with zero npm dependencies on Node.js 18 or later:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
```

## Licence and contributions

MIT; see `LICENSE`. Third-party provenance is recorded in `NOTICE`; the vendored tinywasm interpreter retains its MIT and Apache-2.0 licence texts beside its source. This repository accepts issues and does not accept outside pull requests; see `CONTRIBUTING.md`. Report a security problem to security@ferrite.cloud, as `SECURITY.md` describes. The hosted Ferrite platform is proprietary and not open source.

This repository is a scrubbed public snapshot prepared by the Ferrite team and carries no private development history.
