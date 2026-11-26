# `gatekeeper`

`gatekeeper` defines the connector contract: the shared vocabulary and state machines that every connector implements. A gatekeeper sits between the platform and one external service (such as GitHub or Google) and owns that service's credentials, resource scoping, observation log, and action approval queue. The agent and consuming application interact only through the small typed API; credentials never enter a sandbox.

It is a source package, not a standalone Cargo crate or service. `tools/ferrite-pkg` composes it into a consuming application's `src/` tree, where it runs under that app's injected authority alone.

## Status

Ported from an earlier standalone gatekeeper crate with all twelve contract modules and their tests. The governance benchmark consumer mounts this package, and the earlier standalone crate has been removed. Tests are deterministic and unit-gated; nothing here is live-certified. Intended consumers are the connector packages and the governance bench.

## Ferrite Platform Shape

`gatekeeper` declares no package dependencies and no `hostImports`, using only what `ferrite-app` provides (`serde`, `serde_json`, and `crypto`). Functionality previously supplied by `thiserror` and `chrono`/`chrono-tz` is hand-written because a constrained application cannot add crates for it:

- `GatekeeperError` carries hand-written `Display` and `Error` implementations with the same error messages the `thiserror` derive produced.
- `sha256` exposes the token-fingerprint surface called by `oauth`. Crypto consolidation retired the earlier FIPS 180-4 port in favor of `ferrite_app::crypto`, replacing `sha2` with the SDK rather than keeping a local copy.
- `calendar` evaluates cron next-fires using hand-rolled proleptic-Gregorian civil math over UTC and fixed-offset timezones.

The package holds no ambient authority. Nothing reads a clock, environment variable, socket, or file: every timestamp is passed as a `TimestampMs` parameter, OAuth nonce entropy comes from the host, and vendor calls (OAuth exchange, refresh, ACL checks) are executed by the host and fed back in.

Nothing here introduces an authorization scheme parallel to the platform's capability model. Authority is carried by `CapabilityGrant`, which is scoped, expiring, and checked against revocation epochs.

## Not Claimed

No live vendor traffic runs through this package. No connector built on this contract has executed against a real vendor here; the deterministic offline gates verify state machines rather than live integrations.

IANA timezone DST evaluation is intentionally absent (a recorded delta from the node-tier crate). The node-tier crate computed DST-correct calendar fires with `chrono-tz`, such as `"03:00"` in `Europe/Amsterdam` with spring-forward gaps rolling forward. Because a constrained application has no tzdata, `calendar` accepts only `"UTC"` and fixed offsets such as `"+02:00"` or `"-05:30"`, and refuses IANA zone names loudly at registration. A deployment needing DST-correct wall-clock schedules supplies the active offset per schedule and re-registers at transitions.

The package is not independently deployable. It has no `ferrite.json`, no `Cargo.toml`, and no bindings of its own.

## Validation

Because a source package is not a standalone build target, its tests run inside a consuming application:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check <consumer>
cargo test --manifest-path <consumer>/Cargo.toml
```

The proof suite runs both commands along with the release scoring lane.

## Audit retention

Observation audit retention preserves allowed evidence for the lifetime of the surface. Refused attempts keep a separate saturating count and at most 32 recent records with bounded text fields, so a flood of refusals cannot evict allowed audit evidence or alter observed-data sharing history. This in-memory trail is not a durable external audit journal.
