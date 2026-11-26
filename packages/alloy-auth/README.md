# Alloy Auth

Alloy Auth provides credential-verified actors, store-backed sessions, host-only cookies, and session-bound CSRF checks for Alloy applications. It does not provide account recovery or a password-change page.

## Where it sits on upstream Ferrite Core

Upstream Ferrite Core has no managed authentication, so there is no gateway-supplied password-change form and no `ferrite auth init`. An Alloy application whose users hold passwords issued by the app keeps this package. An application whose users sign in with an identity provider uses [`auth`](https://docs.ferrite.cloud/developers/authentication/) instead (`ferrite add auth`). The two packages keep separate session records, so choose the package that owns the app's sign-in flow.

Because this package includes no password-change backend and no account recovery, an application that installs it must not advertise a change-password page it cannot serve. [`http-change-password`](../http-change-password/README.md) answers 404 unless the application names a real destination.

## Sign-in routes and demo accounts

An app whose users live in its `data` store can route `/__auth/login`, `/__auth/logout`, and `/__auth/me` to `faces::login`, `faces::logout`, and `faces::whoami`. Each handler takes the app's list of published demo accounts; pass an empty slice if it has none. `demo::seed_demo_accounts` creates those accounts only when the `demo-accounts` secret is `enabled`, and otherwise retires any account that still accepts its published password. While demo accounts are off, the routes refuse both published credentials and any session opened with them.

## Sign-in attempts are limited per account

`SessionStore::login` checks passwords through `UserStore::verify_sign_in`, which admits `MAX_SIGN_IN_ATTEMPTS` (10) attempts per account within a `SIGN_IN_WINDOW_MS` (15-minute) window. Each attempt is counted before the password is checked so concurrent guesses cannot overrun the bound. Once the attempts are spent, every further attempt in the window, including the right password, is refused with `AlloyError::TooManyRequests` (HTTP 429; `retry_after` in the problem body reports the remaining seconds). A successful sign-in clears the counter. Unknown account IDs are counted just like known ones so the limit reveals nothing about which accounts exist.

Limiting is per account because an application receives no client address it can trust. Anyone who knows an account ID can therefore keep that account's sign-in shut for one window at a time. `UserStore::verify` counts nothing on its own; an application that signs users in without `SessionStore::login` must call `verify_sign_in`.

## Deliver the CSRF token in the reply body

The gateway relays one `set-cookie` header per reply, so a login sets only the `HttpOnly` session cookie. The CSRF token bound to that session travels to the client in JSON:

- `login_cookies(&token)` returns the single session cookie.
- `with_csrf(body, &session)` adds the token to a JSON object under `csrf`. Call it on both the login reply and the `/__auth/me` reply for signed-in callers, and send both responses with `cache-control: no-store`.
- The client keeps that value in memory and echoes it in the `x-alloy-csrf` header. After a reload it fetches the token again from `/__auth/me`.
- `csrf_cookie(&session.csrf)` renders the script-readable cookie for `/__auth/me`, which sets no other cookie. Clients emitted by `alloy-gen` keep the body field in memory and read this cookie when memory is empty (a reloaded document before its first `/__auth/me` returns). Older generated clients that predate the body field read only the cookie and continue to work.

Every route that accepts a mutation or sign-in POST must list `cookie`, `x-alloy-csrf`, `origin`, and `sec-fetch-site` in its `forward_headers` (plus `content-type` on `/__auth/login` when enforcing JSON media-type checks).

## Discover a password-change page

If your app has a password-change page, call `alloy_auth::change_password::handle` before authentication redirects and catch-all routing. Pass the page's canonical same-origin path as the destination. Leave it unset for apps without that flow; the helper returns `404 Not Found` rather than advertising an unusable page.

See [Password-change discovery](../http-change-password/README.md) for response handling, destination restrictions, and verification. Apps that also use `agent-ready` can configure `PageSource::change_password_url()` and let its `handle_h` router emit the same response.

## Status

Active source package mounted by Alloy applications that own local password credentials. Unit tests live alongside the source and run inside consuming crates.

## Ferrite Platform Shape

This is a source package, not a standalone crate or deployable service. `ferrite add alloy-auth` or `ferrite-pkg` mounts it at `src/alloy_auth/` along with its four transitive source-package dependencies (`alloy`, `http-change-password`, `http-cookies`, and `sha256-hmac`). At run time it uses only the host application's declared store handle and secrets.

## Not Claimed

This package is not independently deployable and provides no identity federation, passkeys, email delivery, account recovery, or password-change backend. Live browser sign-in is each consuming deployment's claim.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml
```
