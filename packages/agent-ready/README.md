# agent-ready

`agent-ready` is a source package that constrained Ferrite apps mount to derive their agent-readiness surfaces from one declared `Surface`. From that single declaration it generates:

- `robots.txt` (with Content-Signals), `sitemap.xml`, `llms.txt`, and `llms-full.txt`
- Markdown `.md` page twins with `Accept` negotiation and `Vary: Accept`
- RFC 9457 `problem+json` errors
- OpenAPI 3.1 catalog at `/.well-known/api-catalog`
- A2A agent card at `/.well-known/agent-card.json` pointing to A2A JSON-RPC at `/a2a` (with declared operations exposed as skills)
- Stateless MCP server at `/mcp` (with tools projected from declared operations) plus registry manifests at `/server.json` and `/.well-known/mcp/server-card.json`
- Agent Skills index at `/.well-known/agent-skills/index.json` with a projected `SKILL.md`
- Machine-readable pricing at `/pricing.md` and x402 payment challenges for priced operations
- Web Bot Auth header parsing and policy evaluation
- Readiness self-report at `/.well-known/agent-readiness` whose findings include the exact fix for each gap
- Opt-in Personal Agent Protocol (Poppy 1.0) discovery (`/.well-known/poppy.json`), RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource` and `.../mcp`), exposure-filtered `/poppy/openapi.json`, `/poppy/tasks` (Agent Skills discovery `0.2.0` + excluded tasks + feedback), `POST /poppy/feedback`, Session JWT + delegation verification, `operations` v3 approval gating, 3-step Browser Join, and §8 Conversations (`/poppy/conversations`)

Because a Ferrite application declares its `Surface` in code, readiness artefacts are generated projections instead of hand-maintained documents.

Password-change discovery (`/.well-known/change-password`) delegates to [`http-change-password`](../http-change-password/README.md). An application with a password-change page names it through `PageSource::change_password_url()`. An application without one leaves the default (`None`) so the endpoint returns 404 rather than advertising a page that cannot work. Call `well_known::handle_h` before catch-all routing and emit every header it returns.

When an agent integrates this package into an app, apply the crate declarations printed by `ferrite add`, declare the `Surface`, and wire `handle_h`. In local MCP (`ferrite mcp-serve`), call `local_add` with `package: "agent-ready"` and run `local_check`; in hosted MCP without a shell, pass `"packages": ["agent-ready"]` to `code_gate` and `deploy_source`. If the application serves its own password-change page, verify `GET` and `HEAD` against `/.well-known/change-password` and follow the redirect through the app's own sign-in and password-change flow; if it has none, leave `change_password_url()` unset and verify that `/.well-known/change-password` returns 404. Do not ask the user to enable discovery or put credentials in MCP. Generated app skills and MCP initialization carry this same guidance. See [the complete integration and verification contract](../http-change-password/README.md) for code examples, security behavior, custom destinations, and explicit opt-out.

## Status

Active and mounted by several applications. The canonical package tests run once through the direct-source `mcp-fixture` harness. Consumers own their integration and user-flow tests. Copies installed with `ferrite add` may omit test modules, and generated copies do not count as additional independent coverage.

## Ferrite Platform Shape

This package is not deployed and consumes no platform capability on its own. `tools/ferrite-pkg` composes it into each consumer's `src/agent_ready/`, where it runs strictly under the host app's injected authority. Outside the `ferrite_app` re-exports (`serde` and `serde_json`), it depends on [`http-query`](../http-query/README.md), [`http-change-password`](../http-change-password/README.md), and [`sha256-hmac`](../sha256-hmac/README.md), which `ferrite-pkg` mounts transitively at `src/http_query/`, `src/http_change_password/`, and `src/crypto/`. `hostImports` is empty.

| Module | Responsibility |
| --- | --- |
| `surface` | `Surface` declaration and `ARDY_*` validation |
| `artefacts` | `robots.txt`, `sitemap.xml`, `llms.txt`, and `llms-full.txt` |
| `markdown` | HTML to Markdown conversion for `.md` page twins |
| `problem` | RFC 9457 `problem+json` error formatting |
| `catalog` | OpenAPI 3.1 catalog and A2A agent card |
| `mcp_face` | JSON-RPC MCP server core (`2026-07-28` + `2025-11-25`) |
| `skills` | Authored workflow manifests, text/binary resources, and `resources/directory/read` (`directoryRead: true`) |
| `elicitation` | Standalone MCP `2026-07-28` Elicitation (form & URL modes) and HMAC-sealed SEP-2322 `requestState` |
| `files` | Experimental `io.modelcontextprotocol/files` uploads (`x-mcp-file`, `upload_required`) and `_meta` downloads |
| `a2a_face` | A2A JSON-RPC face with optional caller-bound durable tasks |
| `x402` | Payment challenge shapes and vendored base64 |
| `bot_auth` | RFC 9421 subset header parsing |
| `query` | Canonical query decoder re-exported from `http-query` |
| `well_known` | Single HTTP router |
| `score` | Readiness self-report |
| `events`, `event_stream`, `event_webhook` | Experimental MCP Events polling, POST streaming, and signed webhooks |
| `tasks`, `task_stream` | Durable MCP Tasks store contract and SSE subscriptions |
| `poppy` | Personal Agent Protocol (Poppy 1.0) config, exposure controls, discovery projections, RFC 9728 PRM, `/poppy/tasks`, feedback, RFC 9651 header parsers |
| `poppy_verify` | `Poppy-Session` + `poppy_dlg` delegation verification (`ES256`, `ath` binding, continuity, `private_key_jwt`) |
| `poppy_ops` | Poppy `operations` v3 stateless HMAC revisions, canonical JSON, at-most-once approval gating |
| `poppy_browser` | 3-step CSRF-safe Browser Join (`__Host-poppy_session` single-cookie handoff) and `browser-control` v1 helpers |
| `poppy_conv` | Poppy §8 Conversations handler (`/poppy/conversations`, handoff, Direct Conversations, `links`/`disclosures`/`operations` message gating) |
| `change_password` | Compatibility re-export of `http-change-password` |
| `sha256`, `hmac` | Compatibility re-exports of `sha256-hmac` |

## Protocol faces

### Authored workflow skills

Applications can expose authored workflow skills by implementing `PageSource::skills()`. The default returns no skills and keeps the tools-only MCP surface. A nonempty catalogue adds Resources and `io.modelcontextprotocol/skills` (`directoryRead: true`), serves `skills/list`, `skills/get`, `resources/list`, `resources/read`, `resources/directory/read`, and an empty `resources/templates/list`, and publishes the same authored text through the HTTP skill index. Each manifest carries the original frontmatter, exact byte size, and SHA-256 digest of every file, supporting both UTF-8 text and binary (`blob`) assets. Supply only public, caller-appropriate static guidance when using its public cache scope.

Keep substantial procedures in authored skills. The generated `use-this-app` skill remains a general API orientation and shares its name with its directory. It does not infer a booking sequence or recovery argument from an operation's HTTP idempotency declaration.

### MCP (`/mcp`)

The MCP face implements revision `2026-07-28` while retaining the released `2025-11-25` wire over stateless Streamable HTTP. Only `POST` is accepted; other methods return HTTP 405 with `Allow: POST`.

Both revisions share one endpoint, and the request body determines which protocol rules apply:

- A request whose `params._meta` names `io.modelcontextprotocol/protocolVersion` is handled as `2026-07-28`. The protocol header must agree (`-32020`), client capabilities must be declared (`-32602`), and an unserved version returns `-32022` with `supported` and `requested`. Results carry `resultType: "complete"`, list results include `ttlMs` and `cacheScope`, `server/discover` lists both versions, and any unknown method (including `initialize`) returns `-32601` with HTTP 404.
- A request without `_meta` is handled as `2025-11-25` (`initialize`, plain results, and `-32601` at HTTP 200).
- A bare `2026-07-28` header on a body without `_meta` is rejected as a malformed `2026-07-28` request rather than treated as legacy.

When the host forwards SEP-2243 `Mcp-Method` and `Mcp-Name` headers (`forward_headers`), mismatches return `-32020`. Missing headers are tolerated because a hosted app cannot tell an omitted header from an unforwarded one. Request IDs must be strings or integers (`null` is refused per MCP). A posted JSON-RPC response or notification returns HTTP 202 with an empty body, and `tools/call` refuses non-object `params` or `arguments` with `-32602`.

Any `Origin` that is neither the served origin nor a loopback origin returns HTTP 403 once the host forwards `origin`. A tool returns a `ToolOutcome`: its `value` becomes `structuredContent` and, by default, a single text block. A host returning richer output (a resource link, an image, or several blocks) calls `ToolOutcome::with_content(blocks)`. The face forwards those blocks verbatim and drops any block that lacks a string `type`.

### A2A (`/a2a`)

The A2A face implements 0.3.0 over JSON-RPC. The agent card's `url` points to `/a2a` with `preferredTransport: "JSONRPC"` and declares no streaming or push notifications. A data part `{"skill": "<operation>", "arguments": {...}}` runs the declared operation through the host's own handler.

`well_known::handle_h` answers statelessly with agent messages and no tasks. Passing a caller-bound `a2a_face::TaskStore` to `well_known::handle_ht` adds durable tasks: `input-required` until a skill runs, then `completed` or `failed`, readable with `tasks/get` (with `historyLength`) and cancelable while waiting.

### Served origin

`Surface::served_at(host)` sets the host used for every absolute URL in discovery documents. Upstream's ingress envelope carries no gateway-verified host (`IngressRequest::verified_host` existed only in the fork), so an application passes its configured origin from a secret or constant, or calls `served_at(None)` to emit relative URLs.

### Personal Agent Protocol (Poppy 1.0)

Implement `PageSource::poppy(&self) -> Option<PoppyConfig>` to opt an application into Poppy 1.0. Without it, all `/poppy/*` and `/.well-known/poppy.json` paths return 404 and existing behavior is unchanged.

Every operation on the `Surface` can be classified in `PoppyConfig.operation_policies` with explicit exposure and approval rules:

- `PoppyExposure::Public` — callable without sign-in; exposed in `/poppy/openapi.json` and `/mcp`.
- `PoppyExposure::SignedIn { scopes }` — requires a user-consented OAuth token carrying those scopes (projected into OpenAPI `security` and `scope_hints`).
- `PoppyExposure::InternalOnly` — omitted from `/poppy/openapi.json` and filtered out of `/mcp` `tools/list` / `tools/call` when a `Poppy-Session` header is present, while remaining available to internal or browser callers.
- `ApprovalPolicy::Required { require_user_approver }` — declares the `operations` v3 extension and enforces stateless HMAC-bound approval revisions through `poppy_ops::evaluate_gate`.

Per-Company OAuth isolation is enforced by construction: customer applications do not share a single platform SSO issuer. Choose one of four auth modes in `PoppyAuth`: `SignedOut` (no sign-in), `Disabled` (explicitly disables agent sign-in), `External { issuer, .. }` (bring your own OAuth 2.1 issuer such as Auth0, WorkOS, Clerk, or Okta), or `SelfHosted { .. }` paired with the `poppy-oauth` package (per-app OAuth 2.1 issuer with PAR, PKCE S256, `private_key_jwt`, multi-resource RFC 8707 refresh, optional DPoP, immediate revocation, and a Connected Personal Agents settings page).

#### Personal Agent trust model & key refresh

`poppy_verify` resolves Personal Agent CIMD metadata (`client_id`) and signing keys (`jwks_uri`) in three layers:

1. **Local pins / overrides** — agents explicitly registered in app settings or secrets take precedence (useful for custom, internal, or local development agents).
2. **Live egress fetch-and-cache (`fetch_agent_metadata`)** — for any HTTPS `client_id` reachable through the application's declared `egress` handle (for example `poppy-agents` in `ferrite.json`), `poppy_verify` fetches `GET <client_id>`, enforces `client_id == fetched URL` and same-domain `jwks_uri` (§4.1 / §5.3), fetches `GET <jwks_uri>`, rejects private key material, and caches the verified keys in the app store (default 15-minute TTL). When an incoming `Poppy-Session` or `client_assertion` presents an unknown `kid`, the app triggers an immediate refresh so key rotation succeeds without redeploying.
3. **Built-in well-known Personal Agents (`StaticAgentDirectory::with_well_known_agents()`)** — published agents (starting with Meta Muse at `https://muse.ai/poppy/agent.json`) ship with a verified fallback snapshot so first-contact requests verify out of the box even before the first refresh or in offline test harnesses.

Add `poppy-session`, `poppy-version`, `poppy-extensions`, `poppy-approval` (and `authorization` / `dpop` when signed-in) to each route's `forward_headers` allowlist in `ferrite.json` (up to 16 headers per route).

## The canonical query decoder

`query` fills a gap in the ingress contract through [`http-query`](../http-query/README.md): one total decoder shared across every consumer so `%2F`, `+`, and repeated names decode identically in every application. Because `IngressRequest.path` carries `path?query` verbatim, the module needs no wire change and works behind any gateway.

The implementation lives in [`packages/http-query`](../http-query/README.md), and `src/query.rs` re-exports it. The split exists because a `ferrite-pkg` mount is all-or-nothing: applications that already serve their own MCP face need the decoder but cannot mount `agent-ready` without picking up a second `mcp_face` beside `packages/mcp`. Extracting `http-query` keeps one implementation across all consumers. Callers already referencing `crate::<mount>::query` continue to work because `ferrite-pkg` mounts `http-query` transitively.

The public API has five functions: `split_query(target)`, `path_only(target)`, `parse_query(raw) -> Vec<(String, String)>`, `param(raw, name)`, and `target_param(target, name)`.

Every edge case is documented in `packages/http-query/src/mod.rs` and verified by `parse_query_decodes_every_edge`:

| Input case | Behavior |
| --- | --- |
| `+` | Decodes to a space |
| `%XX` | Decodes in upper or lower hex |
| Malformed `%` escape | Passes through verbatim |
| Parameter names | Decode identically to values |
| Pair without `=` | Yields an empty value and continues scanning |
| Empty segment | Skipped |
| Repeated parameter name | Keeps every occurrence in order; `param` returns the first |
| Control bytes | Decode like any other byte, so decoded values remain untrusted input |
| Non-UTF-8 bytes | Replaced lossily |
| Leading `?` | Stripped |
| `#` | Treated as data |

Two of those rules fixed real production defects before this decoder existed: an undecoded `%3A` in a stream cursor silently resumed a reconnecting client at the wrong offset, and a valueless `?debug` masked a valid token and rejected an authorized caller. Change a rule by updating the test first.

If the platform SDK adds equivalent functions at the `ferrite-app` crate root, `http-query` can delegate to them and later retire, and consumers do not change.

## Limits

- This package is neither an MCP client nor a complete MCP implementation. At `2026-07-28` the face serves `server/discover`, `tools/list`, and `tools/call`, plus opt-in Skills (`skills/list`, `skills/get`, `resources/directory/read`), Tasks (`tasks/get`, `tasks/update`, `tasks/cancel`), standalone Elicitation (`input_required` via `PageSource::mcp_tool_call_mrtr`), and File Transfers (`io.modelcontextprotocol/files` via `PageSource::mcp_files_config` and `mcp_file_http`). On the released `2025-11-25` wire it serves `initialize`, `ping`, `tools/list`, and `tools/call` (`ping` was removed at `2026-07-28` and returns HTTP 404 there). General resource templates and subscriptions, prompts, logging, completion, and sampling remain absent.
- A2A streaming and push notifications are not implemented, and the agent card advertises them as off.
- Retry safety belongs to the host handler. Mark an operation `idempotent` only when the handler returns the first result for a repeated `idempotency-key`.
- Markdown negotiation requires the route to forward `Accept` and the handler to use the package's header-aware response path. Preserve `Vary: Accept` and every returned header. Direct `.md` twin paths remain available independently.
- Web Bot Auth parses headers and checks policy without verifying signatures, because fetching a key directory is outside the constrained tier. Real x402 settlement is also absent: the facilitator is a seam the host wires to declared egress, and tests use a mock.
- Poppy `ES256` signature verification runs directly in-app through `ferrite_app::crypto::es256_verify` against a three-layer `AgentKeyResolver`: manual local overrides/pins, live egress-fetched CIMD + JWKS cache (`fetch_agent_metadata` over `ferrite_app::EgressHandle`, refreshing on TTL expiry or unknown `kid`), and built-in well-known Personal Agents (`StaticAgentDirectory::with_well_known_agents()`, including Meta Muse at `https://muse.ai/poppy/agent.json`). `PS384` verification is exposed through a `verify_ps384` hook on `AgentKeyResolver`. Fetching unlisted arbitrary domains requires declaring them in the app's `ferrite.json` `egress` allowlist; Browser Join uses a single `__Host-poppy_session` cookie per reply; and `/poppy/conversations/{id}/events` delivers polling/bounded snapshots when long-lived SSE handoff is unavailable.
- `query` is a re-export rather than an implementation. The decoder, its contract table, and its tests live in [`packages/http-query`](../http-query/README.md), where changes belong. Applications with their own MCP face should mount `http-query` directly so they do not pull in a second MCP face.

## Validation

In this repository, run the shared owner once and select consumers for distinct composition behavior. The fixture imports the canonical package and its three dependencies directly without a generated copy or Core checkout:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check     # vendored copies match
```

Test your deployed endpoint through the [Tasks](https://docs.ferrite.cloud/developers/mcp-tasks/) and [Events](https://docs.ferrite.cloud/developers/mcp-events/) client examples.

## Experimental Events MCP

Version 1.10 adds polling, a POST-stream lifecycle, and a signed webhook registry. Hosts advertise only the transports and scheduling they mount; body-only applications default to polling. Modern delivery follows draft SEP-3415 at `b08e4f9`, while the earlier profile retains polling compatibility.

See [Events and browser tools](https://docs.ferrite.cloud/developers/mcp-events/) for the complete integration contract, callback security, replay and expiry rules, JavaScript and Rust clients, runnable example, and acceptance boundaries. A library test does not prove that a deployed app has enabled delivery.

## Host a durable MCP task

A long-running MCP tool can return a task ID instead of holding its HTTP connection open. Implement `tasks::TaskStore` over caller-scoped persistent storage with atomic compare-and-swap. Your `PageSource` opts individual tools in with `task_tools` and handles task requests through `task_call`. Bind the owner from authenticated request context on reads and cancellation as well as creation. Persist the pending job before acknowledging it, and reconcile an uncertain dispatch with its underlying operation before starting more work.

The [text analysis demo](https://3ofgx9sfna22znb0.ferrite.cloud/) accepts input and exposes the task result and matching events. The [Tasks guide](https://docs.ferrite.cloud/developers/mcp-tasks/) explains how a client resumes a job. A2A tasks described above are a separate protocol.
