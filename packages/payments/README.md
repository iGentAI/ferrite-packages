# payments

Customer payment handling for apps running inside Ferrite's constrained app
model. This package consolidates the three components Ferrite commerce apps
shared across implementations: Stripe request builders, the `t=,v1=` webhook
verifier, and an idempotent event-admission ledger. It also includes the x402
header path that a priced operation runs before serving a request.

The package implements the recorded customer-payments contract and its seven
correctness rules. The required core primitives (per-call egress headers and
methods, route-declared inbound header forwarding, reply headers, and the
crypto kernels) have landed in core; only egress response header visibility
(`Retry-After` in `dunning`) remains an open platform limit.

## Status

Source package mounted by Ferrite Supply (Stripe checkout, reconciliation,
refunds, webhooks) and the Quotes API (the x402 gate). Composed by
`tools/ferrite-pkg`; its tests travel with the source and run inside every
consumer.

## Ferrite Platform Shape

A deployable Ferrite app declares a single dependency, `ferrite-app`, so shared
subsystems travel as vendored source rather than crates. This package performs
no I/O of its own:

- Every builder returns a `payments::HttpRequest`. The host application sends
  it through an egress handle declared in its own manifest, keeping the
  destination scope-pinned and visible in the egress audit plane. Opening a
  socket inside the package would move both properties out of the application
  manifest where an operator can inspect them.
- Secrets arrive as `&str` from the caller's `ctx.secret(...)`. No builder
  accepts credentials embedded in a URL: the egress audit record persists
  destinations while omitting header values, so a key in a URL path leaks
  durably while a key in a header does not.
- Every digest, MAC, hex decode, and constant-time comparison delegates through
  the `sha256-hmac` source-package dependency (mounted at `crate::crypto`),
  which wraps `ferrite_app::crypto`. The package carries no local crypto
  implementation of its own (contract acceptance criterion 5), and signature
  comparison uses the SDK's constant-time comparator instead of `==`, which
  leaks comparison bytes through timing.

The package declares two source-package dependencies: `sha256-hmac` (for the
crypto surface above) and `agent-ready` (because the x402 wire protocol lives in
`agent_ready::x402` beside the `Surface` and `Operation` declarations that
price an operation). Moving the protocol here would either duplicate it or
require a `payments` mount in all nine `agent-ready` consumers. This package
owns the execution path: the settlement seam, the durable replay ledger, and
the order in which both run.

## Modules

| Module | Responsibility |
| --- | --- |
| `money` | Minor-unit and micros anchors, plus `verify_amount`, the server-side amount check required by contract rule 3 |
| `stripe` | Hosted Checkout creation, session re-read, refunds, form encoding, Stripe ID validation, and penny-exact discount allocation |
| `webhook` | `t=,v1=` verifier over the raw request bytes, replay window checks, and verify-then-parse ordering |
| `ledger` | `EventLog`, the processor-event-id marker that keeps folds idempotent, and the guarded-loop retry ceiling |
| `dunning` | Fixed retry ladder for failed charges |
| `x402_gate` | `Facilitator`, `LocalVerifier`, the store-backed replay ledger, and `require_payment` |

### Raw body as MAC input

Stripe's HMAC covers `"{t}.{raw payload}"`. Nothing on the Ferrite ingress path
re-serializes that payload: the gateway reads exactly `content-length` bytes
into `IngressRequest.body`, and `Vec<u8>` survives the envelope's JSON encoding
byte for byte. That makes `req.body` the exact MAC input. Parsing and
re-encoding first would alter key order and whitespace, failing every signature
with an error that looks like a key mismatch.

To prevent regressions in later edits, this ordering is enforced structurally.
`webhook::verified_event` accepts raw bytes, verifies the signature, and parses
only afterward. The parser is private, and no entry point in the package
accepts an already-parsed event.

### Missing signatures

A route that omits `"forward_headers": ["stripe-signature"]` receives an empty
header list on every envelope. `webhook::verify` returns `signature_missing` in
that case, the same class of refusal as a forged signature and the only
supported outcome. Contract rule 7 requires this behavior so an unconfigured
route cannot become an open "mark the order paid" endpoint for anyone who can
POST to it.

### Single-commit admission marker

`ledger::EventLog` is a plain value stored inside the application's committed
image, so recording the admission marker and applying the state transition
happen in one write by construction. Mark-then-apply can lose a payment on a
crash; apply-then-mark can fold it twice on redelivery. Neither split ordering
is offered.

`ferrite-ape` documents an at-least-once seam on `commit_n_if`: a commit
retried at the transport layer can succeed and still report a guard mismatch. A
retry loop that treated that mismatch as "not applied" would fold twice, so the
loop must re-read state and let the marker decide. `EventLog::admit` checks the
marker at the top of each attempt, and `ledger::GUARD_RETRIES` bounds the loop.

## Dunning and provider retry advice

The `dunning` module advances a fixed five-rung retry ladder
(`ATTEMPT_DELAYS_MS`). Constrained Ferrite applications cannot read egress
response headers today (`EgressOutcome::Delivered` carries only `{ status, body }`
and strips `Retry-After`), so contract acceptance criterion 7 remains unmet
until egress response visibility lands. Persist the next attempt before
acknowledging the current work.

See [Scoped egress](https://docs.ferrite.cloud/developers/secrets-egress/) for
the application networking contract.

## Not Claimed

Verification coverage varies by module:

| Surface | Evidence class |
| --- | --- |
| `stripe` builders | Unit-proven, and exercised by the demo shop's handlers. Verify the consuming app against its configured Stripe environment before claiming live payment acceptance. |
| `webhook` verifier | Unit-proven against synthesized signatures, and exercised end to end by demo-shop's in-process webhook tests. No internet-delivered webhook is recorded. |
| `ledger` | Unit-proven, including a contended fold driven through the at-least-once CAS seam. Exercised by demo-shop's redelivery test. |
| `money` | Unit-proven. `verify_amount` is exercised by demo-shop's webhook fold. |
| `dunning` | Unit-proven only. No Ferrite application runs a dunning schedule, so none of this code has met a real processor. |
| `x402_gate` | Unit-proven, and exercised by the Quotes API's full premium loop. Settlement runs in-process against a facilitator credential; no on-chain settlement is recorded. |

Outside those surfaces, this package does not:

- Settle a payment. `LocalVerifier` validates an HMAC settlement tag; an
  on-chain broadcast is a facilitator POST issued by the host app through its
  own egress.
- Handle card data. Hosted Checkout is the only flow implemented, so PANs never
  transit the application and stored state consists of opaque identifiers
  (`cs_...`, `pi_...`).
- Own an application's money rows. The package supplies the admission marker,
  the guarded-loop ceiling, and the amount check; the row schema and state
  transitions remain in application state where the product's rules live.
- Carry a currency table. `money` validates currency code shape and converts
  two-decimal minor units; callers with zero-decimal or three-decimal
  currencies convert on their own side.
- Parse `Retry-After` headers. See Dunning and provider retry advice above.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml   # for each consumer that mounts it
```

The package has no crate of its own, so its tests run inside its consumers.
Each vendored copy tests the package against the exact `ferrite-app` build that
consumer links, exercising the `ferrite_app::crypto` delegation directly rather
than a standalone local port.
