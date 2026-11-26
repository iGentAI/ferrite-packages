# HTTP route budgets

`http-route-budget` checks an incoming HTTP envelope against a token bucket for its matched route before the application performs any handler effects. Mount it as `http_route_budget` and pass an existing app-owned store binding. The package adds no runtime Cargo dependency beyond the public `ferrite-app` SDK.

```rust,ignore
const ROUTES: &[http_route_budget::Rule] = &[
    http_route_budget::Rule { route: "/api/", per_min: 600 },
    http_route_budget::Rule { route: "/", per_min: 1200 },
];
if let Some(reply) = http_route_budget::guard(ctx, req, "cache", ROUTES).await {
    // Publish this ordinary reply, then acknowledge the ingress lease.
    return reply;
}
// Only confirmed admission reaches handler effects.
```

## Integration rules and limits

Call `http_route_budget::guard` immediately after decoding the HTTP envelope, before replay or cache lookups, public asset serving, authentication callbacks, or handler effects. Keep the guard outside stream-open and message loops.

Route lookup requires `req.route` to match one declared prefix exactly. The guard does not fall back to `req.path`, longest-prefix matching, or caller-provided headers, so test requests must carry the actual ingress prefix. Empty or unknown routes, duplicate or invalid rules, and missing store bindings all return `503`.

| Limit | Value |
| --- | --- |
| Maximum routes | 64 |
| Maximum prefix length | 512 UTF-8 bytes |
| Rate (`per_min`) | Positive `u32` |

## Token bucket and refusals

Each bucket starts full with `per_min` requests of burst capacity. One request costs 60,000 integer units, and each elapsed millisecond restores `per_min` units up to the bucket capacity. This preserves the original route limiter's numeric burst and refill policy, so a full minute refills an empty bucket.

Clock regressions never lower the stored high-water timestamp, and the bounded refill arithmetic cannot overflow on extreme rates or timestamps. When a bucket is exhausted, the guard returns `429` with a positive, rounded-up `Retry-After` header in seconds that includes any clock rollback gap. Both `429` and `503` refusals return JSON with `Cache-Control: no-store`.

## Store CAS and failure behavior

Admission uses the public store's versioned read and compare-and-swap (CAS). A missing bucket is created only with expected version `None`.

On explicit version conflicts, the guard rereads and recomputes up to 16 CAS attempts. Only conflicts incur backoff: 2 ms, then 4 ms, then 8 ms for each remaining retry, totaling 110 ms of scheduled wait. Pausing on conflict lets concurrent replicas finish a normal burst instead of repeatedly colliding on the same bucket version.

Any returned I/O error, invalid stored state, or exhausted conflict budget returns `503` without dispatching the handler. A dropped write response can leave a committed debit even though the envelope was refused. Because the SDK can replay a CAS internally, a conflict reported after a committed write can cause a subsequent conservative admission to debit again. This package does not claim one debit per logical HTTP request and does not retry a returned uncertain-write error.

## Scope and storage layout

The allowance is shared across replicas and host aliases and survives restarts. Queue redelivery and hedges spend allowance again, and user IDs, cookies, keys, `Host`, and forwarded headers do not partition it. This is intentionally stricter than the former per-gateway in-memory bucket. Because enforcement occurs after queue delivery, it cannot protect edge parsing, ingress bandwidth, or initial queue publication, and it does not replace existing principal-specific policies. Native consumer deployment and live `429`/no-effect verification remain separate release requirements; the owner harness provides local proof only.

Buckets use the reserved store key prefix `http-route-budget/v1/` followed by the configured prefix, for example `http-route-budget/v1//api/`. There is one non-expiring row per declared route, never per request or per user. Application cleanup and reset paths must preserve this namespace.

A stored rate mismatch causes a refusal rather than a silent credit reset. Changing a route's rate requires a deliberate state migration while writers are quiescent. Each admitted delivery costs at least one store read and one CAS, so traffic capacity planning must account for those operations and bounded conflict retries.
