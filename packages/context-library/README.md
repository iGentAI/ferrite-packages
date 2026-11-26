# `context-library`

`context-library` is a shared context and skills library modeled after Cloudflare OS `gatekeeper-context`. It stores collections of documents and `SKILL.md` skills with validated frontmatter, scoped as either `public` (tenant-wide) or `private` (per account), and delivers them to agents through search, list, and read operations, a bounded discovery catalog, and slash-command expansion. The library is strictly read-only for agents; publishing happens through a human or deploy path.

It is a source package, not a standalone Cargo crate or service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree, where it runs under that app's injected authority alone.

## Status

Ported from the retired standalone `context-library` crate with all six modules and their tests; this package is now the canonical source. Tests are deterministic and unit-gated; nothing here is live-certified.

## Ferrite Platform Shape

`context-library` declares one package dependency, `gatekeeper`, mounted at `crate::gatekeeper` and composed transitively by `ferrite-pkg`. Discovery and shared-surface access control delegate directly to `gatekeeper`:

- Discovery uses gatekeeper's hard-capped `AgentCatalog` (at most 25 entries, IDs up to 256 characters, descriptions up to 400 characters, treated as untrusted display data).
- Reads on shared surfaces are described to `ObservationAuthorizer`, and share-time access is re-verified per observer by `ObserverRegistry` (strategy B, one ACL check per observed collection) against the library's visibility rules.

The package has no other dependencies and no `hostImports`, using only what `ferrite-app` re-exports (`serde` and `serde_json`). Rather than depending on `thiserror`, `SkillError`, `CollectionError`, and `SlashError` carry hand-written `Display` and `Error` implementations with the same error messages the derive produced, with `CollectionError::Skill` remaining transparent.

The package holds no ambient authority. Nothing reads a clock, socket, or file: timestamps are passed as `TimestampMs` parameters, `SKILL.md` text and documents arrive as arguments, and git-backed collections record their remote as provenance only. Syncing repositories belongs to the host under its own scoped egress.

The frontmatter parser is a hand-written parser for the `key: value` subset. YAML constructs outside that subset are refused rather than guessed at, since a constrained application cannot link a YAML crate.

## Not Claimed

This package is not a deployed context service. No application serves it over a route today; the offline, deterministic gates verify access-control state machines rather than a live integration.

`SearchIndex` defines the search contract rather than a production search engine. It is a small deterministic AND-token index meant to be replaced by `ferrite-search` in a deployed service. What this package enforces is the visibility boundary: search, list, and read operate strictly over visible collections, and a query never returns content the account cannot read.

The package performs no git syncing. `git_remote` is stored purely as provenance metadata; nothing here fetches, clones, or diffs a repository.

The package is not independently deployable. It has no `ferrite.json`, no `Cargo.toml`, and no bindings of its own.

## Validation

Because a source package is not a standalone build target, its tests run inside a consuming application:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check <consumer>
cargo test --manifest-path <consumer>/Cargo.toml
```

The governance bench mounts this package as `context_library` alongside `gatekeeper`, behind that workspace's `ferrite_app` shim re-exporting `serde` and `serde_json`.
