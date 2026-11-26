# messaging

Transactional messaging for constrained Ferrite apps, covering email, chat, and future provider adapters. This package consolidates the provider request builders, safe HTML email renderer, retry classification, and single egress delivery seam that two Ferrite apps were otherwise duplicating.

Build provider requests with this package and send them through the application's declared egress handle. Keep provider credentials in platform-managed secrets, persist delivery intent before sending, and classify retryable failures before rescheduling.

## Verify delivery

Builder tests check request shape and rendering only. Complete a real send through the consuming application's configured provider, read the provider result, and verify recipient delivery before claiming end-to-end acceptance. Also exercise a duplicate request and a retryable refusal without sending duplicate messages.

## Status

This is a source package composed by `tools/ferrite-pkg`; its tests travel with the source and run inside every consumer. It is mounted by Ferrite Supply (Resend order-confirmation email) and a scheduled-briefing application (Telegram and Cloudflare Email channels of the daily brief). `ferrite.cloud`'s own account mail is also sent through `postmark` by a platform service that compiles the package source by path rather than deploying it as an app.

## Ferrite Platform Shape

A deployable Ferrite app declares only one dependency (`ferrite-app`), so shared subsystems travel as source packages rather than Cargo crates.

- Every adapter is a pure builder returning `messaging::ProviderRequest` (named after the messaging contract). Builders use no clock, no `ctx`, and no I/O, so adapters are unit-testable offline and the consumer's manifest remains the sole place egress destinations are authorized.
- `send::deliver` is the only function that touches the network, operating on an `EgressHandle` opened by the caller from its manifest-declared binding. Opening a socket inside the package would move destination scope and egress audit records out of the application manifest where operators read them.
- Secrets arrive as `&str` from the caller's `ctx.secret(...)` and are written into headers because the egress audit record persists destinations durably while omitting header values. The Telegram Bot API is the one exception, required by the provider: its bot token sits in the URL path with no header alternative, and `telegram::send_message_url` documents that exposure at the call site.
- The package holds no state. Send ledgers, outboxes, suppression lists, and retry queues protect application state transitions and remain in the consuming app.

## Modules

| Module | Responsibilities |
| --- | --- |
| `mod` | `ProviderRequest`, the built-but-unsent request, and its JSON-POST constructor. |
| `resend` | Resend send builder, its idempotency-key contract, and accepted-response ID parsing. |
| `postmark` | Postmark send builder (tracking disabled per message), batch builder and matching of batch answers to messages, `ErrorCode` parsing, and broadcast-stream readers for stream type, suppression list, and delivery counts. |
| `telegram` | Bot API send URL, MarkdownV2 escape table, and truncation repair. |
| `cloudflare_email` | Cloudflare Email Sending URL and flat two-part REST payload. |
| `email_html` | Markdown to inline-styled HTML with a fixed emitted tag set; the broadcast form adds a hidden preheader and a footer whose links include the provider's unsubscribe placeholder. |
| `retry` | Classification of retryable provider statuses, the fixed backoff ladder, and `Retry-After` floor helpers (`retry_not_before_ms`, `retry_due_ms`). |
| `send` | `deliver` egress call and the two failure kinds a delivery ledger must distinguish. |

### Escaping by default

`email_html` carries no sanitizer and no denylist. It emits only `h1`, `h2`, `p`, `a`, and `hr`, and HTML-escapes every character it does not emit itself, so hostile input renders as literal text because no other code path writes `<`. Anchors are the one construct built from source text and enforce their own rule: only `http://` and `https://` URLs become an `href`, and both the label and the URL are escaped first.

### Caller-owned idempotency keys

`resend::send_request` accepts an idempotency key rather than deriving one. The key must stay stable across caller-scheduled retries, and only the caller knows what the send represents; `demo-shop` writes `order-confirmation-{order id}` onto the order's email ledger before the first attempt. A key derived inside the builder from a clock or message contents would change across attempts and disable provider-side deduplication when retries occur.

### Retryable refusals and unknown outcomes

`retry::is_retryable_status` classifies only HTTP statuses returned by the provider. A rejection status confirms that no message was sent, so a fresh attempt cannot duplicate one. A transport failure or a crash between the egress call and its local record is ambiguous because the send may already have left, so the package intentionally offers no classification for it. The briefing app settles that window as `NeedsAttention` and never resends; Ferrite Supply retries its local write and never repeats the provider call.

## Fixed retry ladder and response-header limits

A provider responding with `429` states when to retry in `Retry-After`, but a constrained Ferrite app cannot read egress response headers today: `EgressOutcome::Delivered` carries only `{ status, body }` with no response headers, so `EgressHandle::deliver_http` never exposes `Retry-After`.

That leaves acceptance criterion 5 of the messaging contract unmet; see [egress response visibility](https://docs.ferrite.cloud/developers/secrets-egress/). `retry` already provides the `Retry-After` floor helpers (`retry_not_before_ms`, `retry_due_ms`) alongside the linear backoff ladder, while `send::ProviderResponse` omits a header field until egress response visibility lands and callers invoke `retry_due_ms` with `None` as the provider minimum. Updating this once egress response visibility lands is a local change.

## Not Claimed

| Surface | Evidence class |
| --- | --- |
| `resend` builder | Unit-proven and called by `demo-shop`'s `send_email`. No live Resend call is recorded in this repository. |
| `postmark` builder | Unit-proven and compiled into `ferrite.cloud`'s Dashboard service, which sends platform account mail with it. Postmark has no idempotency key, so the Dashboard outbox provides the only deduplication. The batch builder and broadcast-stream readers are unit-proven against Postmark's documented responses and called by the Dashboard broadcast path. No live batch call, suppression read, or statistics read is recorded in this repository. |
| `telegram` builder | Unit-proven and called by the briefing application's delivery step. No live Telegram call from this package source is recorded; the `2026-07-15` run used the application's earlier local copy. |
| `cloudflare_email` builder | Unit-proven and called by the briefing application's delivery step. No live Cloudflare call from this package source is recorded; same `2026-07-15` caveat. |
| `email_html` | Unit-proven, including injected-link and attribute-escape cases, and exercised by the briefing application's HTML-injection regression tests. |
| `retry` | Unit-proven and exercised end to end by the briefing application's retry-ladder gate under a virtual clock against a scripted sender. |
| `send::deliver` | Compile-proven only. Both consumers call it in production paths, but neither exercises it in unit tests because the SDK does not provide a scripted `EgressHandle`. |

Beyond those verification boundaries, this package does not:

- send anything on its own; every builder returns a request that the host delivers through its own egress handle;
- own an outbox, send ledger, or suppression list, which remain durable application state in each consumer;
- render templates with `{var}` substitution, since `demo-shop` formats one message and the briefing app renders pre-frozen Markdown;
- reach APNs, because mobile push requires HTTP/2 egress that does not exist and no Ferrite app attempts push (the messaging contract stages push behind a named workload);
- speak SMTP, because submission requires a multi-round TCP dialogue and the platform has no raw TCP egress (`DeliverTcp` and `DeliverTcpStream` have zero hits in `ferrite`, a recorded platform gap), and HTTP provider APIs are preferred regardless;
- carry SendGrid, SES, Twilio, or FCM adapters listed in the messaging spec, because no consumer in this repository calls them and an uncalled adapter has nothing proving it;
- receive bounce or complaint webhooks, since inbound webhooks ride a route's `forward_headers` declaration in Core and no consumer registers one.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml   # for each consumer that mounts it
```

The package has no crate of its own, so its tests run inside its consumers. Each vendored copy proves the kit against the `ferrite-app` build that consumer links.
