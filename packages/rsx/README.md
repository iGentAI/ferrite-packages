# rsx

Runtime half of the Ferrite-native application framework: the library code a
compiled Rsx application executes on Ferrite's constrained surface. The
authoring side (`.rsx` templates, `app/` conventions, and the dev loop) lives in
the `ferrite` CLI's rsx compiler; this package is the runtime the generated code
calls into.

## Status

Delivered modules:

| Module | Scope |
| --- | --- |
| `html` | Escape-safe tree and builder with one normative escaper, active-markup refusals (`script`, `iframe`, `style`, event handlers, `srcdoc`), and a URL-scheme policy across every URL-bearing attribute |
| `router` | Strict path canonicalization (`CanonicalPath`) refusing dot segments, encoded separators, control bytes, and invalid UTF-8; documented segment precedence; one canonical query decoder |
| `server` | Competing-consumer worker pool, ingress bounds, absolute-deadline enforcement, middleware, page and layout composition, globally ordered route resolution, boundary taxonomy, panic isolation, poison handling, reply-first-ack-last ordering, and worker supervision |
| `nav` | Soft-navigation wire protocol with slot-anchored patches, per-layout hashes, and payload ETags |
| `cache` | Tag-generation invalidation, single-flight recomputation, stale-while-revalidate, and path tags |
| `action` | Guarded at-most-once staged effects with verbatim reply replay |
| `csrf` | Per-browser-session action token issued in `__Host-rsx_csrf`, written into every action form in served documents, and required in the `_rsx_csrf` body field of every action POST, while refusing a present foreign `Origin`. Under `ferrite dev` (signaled by the `ferrite:local-dev` secret in context), the cookie is `rsx_csrf_dev` without `Secure` so Safari keeps it on plain HTTP |
| `meta` | Page metadata for the document head and navigation payload, plus `robots.txt` and `sitemap.xml` |
| `assets` | Aggregated, scoped application stylesheet at a content-addressed URL with `immutable` caching and the `<link>` emitted on every document |
| `public` | Static files from `public/` embedded in the source image as chunked byte tables, with extension-derived content types, RFC 9110 `If-None-Match` handling (lists, weak validators, `*`), GET/HEAD-only enforcement, and revalidation rather than a false immutability claim |
| `islands` | Embedded `components/*.island.js` asset serving at `/_assets/island-<name>-<digest>.js` and the document boot manifest |
| `live` | Live regions over the platform's stream interface: subscriptions validated against declared source prefixes, resumed by dense log offset, with per-connection tailers that stop when their connection or worker stops. A declared stream queue is consumed even with no registered renderers so unknown sources receive a terminal refusal (requiring stream and frame queues, without an event log). An API-only app with neither renderers nor a stream binding starts without those services; registering a renderer still requires all three |
| `client` / `client_asset` | Browser runtime materialized into Rust source rather than loaded with `include_str!`, which the code gate refuses |

The compiler half adds page data loaders (a sibling `data.rs` supplying a
template's declared prop) and frontmatter-declared route lifetimes
(`route = { life = ... }` for cached routes); both run through this package's
`server` and `cache` modules.

## Shape

A source package (`ferrite-package.json`, root `rsx`) whose only dependency
surface is `ferrite-app`. Consumers vendor it through the rsx compiler
(`ferrite rsx new`) or `ferrite add rsx`. The composite consumer and gate is
the Rsx bench.

## Not Claimed

- No first-load HTML streaming. An API route returns one buffered reply, so a
  document resolves every `<Suspense>` boundary inline. Streamed replies are a
  recorded platform gap.
- Live-region tailers poll their log. The platform has no wake-on-append for a
  log reader yet (a recorded platform gap), so each subscription costs one
  bounded read per interval.
- No offline mutation queue, no i18n, and no image or font optimization (files
  under `public/` are served as they are, without transcoding or subsetting).
- The handler body of an action may run more than once under racing duplicate
  requests; only staged effects are at-most-once.
- `trusted_style_attr` carries no security claim; CSS is not policed.
- Local-edition semantics are only as strong as Forge's plane emulation; the
  platform's verdicts are authoritative.

## Validation

```bash
cargo test --manifest-path <consumer>/Cargo.toml   # for each consumer that mounts it
# the CLI's Rsx compiler suite regenerates client_asset.rs from client_asset.js
```

Unit tests travel inside the modules; the gates in the bench drive both the
fixture and a compiler-generated application through the real `TestHarness`
ingress path.
