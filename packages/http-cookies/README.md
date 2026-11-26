# http-cookies

`__Host-` prefixed browser session cookies for constrained Ferrite apps. Browsers enforce the `__Host-` prefix, `Path=/`, `Secure`, and the absence of `Domain` together, and silently drop any cookie that fails one of those rules instead of rejecting it visibly. This package sets them in one constructor, reads them back under the same prefixed name, and re-checks the invariant against the rendered `Set-Cookie` header that the browser actually parses.

## Status

Delivered as a source package. It owns the cookie types.

Ferrite Core's `ferrite-app` crate has no cookie module, so `ResponseCookie`, `SameSite`, and `cookie_value` live in `src/cookie.rs`, moved over as source from the retained SDK's `ferrite_app::http`. `ResponseCookie` satisfies the prefix requirements by default: `Secure` is enabled, the path defaults to `/`, and there is deliberately no `Domain` builder. The `__Host-` helpers in `src/mod.rs` compose those defaults. Consumers import `crate::http_cookies::ResponseCookie` and `crate::http_cookies::cookie_value`.

The gateway relays only one `set-cookie` header per reply, keeping the first occurrence of a repeated header name and dropping the rest without an error. Set at most one cookie per reply and carry any second value in the response body.

## Background

The local development edition of `ferrite-app` previously exposed `ResponseCookie::host_session`, while the platform crate did not. The SDK surface contract forbids that divergence: a CLI-scaffolded app calling the local-only symbol passed every local check and was then rejected by the attested build. `surface_parity_gate` now fails on any such symbol.

Rather than deleting the constructor outright, it was moved into this package. Agent-written applications in the evaluation corpus call `ResponseCookie::host_session`, and deleting it would have regressed that measurement. Migrating a caller takes one line:

```rust
// before (symbol only existed in the local edition)
let cookie = ResponseCookie::host_session("session", token)?;

// after (ferrite add http-cookies)
let cookie = crate::http_cookies::host_session("session", token)?;
```

## API

Two files mounted at `http_cookies`: `src/cookie.rs` defines `ResponseCookie`, `SameSite`, and `cookie_value`; `src/mod.rs` re-exports them and provides one constant and five public functions.

| Item | Behaviour |
| --- | --- |
| `HOST_PREFIX` | `"__Host-"` |
| `host_session(suffix, value) -> Result<ResponseCookie, String>` | Prefixed, root-path, `Secure`, `HttpOnly`, `SameSite=Strict` cookie |
| `host_name(suffix) -> Result<String, String>` | Full prefixed name, so writers and readers cannot disagree on spelling |
| `render(&ResponseCookie) -> Result<String, String>` | `Set-Cookie` value, with browser `__Host-` rules re-checked when the name carries the prefix |
| `clear_host_session(suffix) -> Result<String, String>` | Expired header for the same prefixed name |
| `host_cookie_value(headers, suffix) -> Option<&str>` | Value of `__Host-<suffix>`, read through `cookie_value` |

An empty suffix or a suffix starting with `-` is rejected at construction because both produce names a browser drops silently. All other name and value rules remain in `ResponseCookie`, which rejects non-HTTP-token names and unsafe bytes in values.

`render` exists because `host_session` returns a standard `ResponseCookie`: a caller can still invoke `.path("/admin")` afterwards, and the platform crate's own validation has no `__Host-` check to catch it. `render` checks the rendered wire string rather than builder internals, because the wire form is what the browser evaluates and the only state observable on `ResponseCookie`.

## Not claimed

This package does not manage session state, mint or verify tokens, or interpret cookie values. The session packages (`alloy-auth` and `ferrite-sso`) build on this package to manage what a session cookie carries (while `auth` implements its own cookie module independently); this package handles only the cookie underneath.

It also does not make the platform stricter for unprefixed cookies. A cookie without the `__Host-` prefix renders identically to `ResponseCookie::render`, and a caller using `ResponseCookie::render` directly gets unchanged platform behaviour. The package adds the `__Host-` check without introducing refusals the platform would not make, avoiding the trap of a local mirror enforcing stricter rules than the platform.

## Validation

The tests travel with the source and run inside every in-repo consumer kept in sync by `ferrite-pkg sync`: `alloy-crm`, `alloy-inventory`, `alloy-ledger`, `alloy-tracker`, and `ferrite-helpdesk` mount it directly, and `ferrite-login` and `ferrite-booking` carry it through `ferrite-sso`. Because `ferrite add` strips a package's `#[cfg(test)]` modules, a standalone install proves that the package compiles in a fresh app, not that its tests pass:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path apps/ferrite-helpdesk/Cargo.toml http_cookies

# standalone install path (declare `pub mod http_cookies;` in src/lib.rs)
ferrite new hello cookie-probe --with-tests
ferrite add http-cookies --path <packages checkout> --dir cookie-probe
cargo test --manifest-path cookie-probe/Cargo.toml
```

`host_session_renders_the_prefixed_secure_root_path_cookie` asserts the exact byte string previously produced by the retired `ResponseCookie::host_session`, verifying that the move changed only the import path and not the output. `render_catches_a_prefix_invariant_broken_after_construction` verifies the case that the platform's own validation lets through.
