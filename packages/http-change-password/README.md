# http-change-password

Answers `/.well-known/change-password`, the [W3C password-change URL draft](https://www.w3.org/TR/change-password-url/), with a validated same-origin redirect. The destination must be a page served by the application itself. Upstream Ferrite Core has no platform password store, so an application without a password-change page leaves the destination unset and discovery returns 404. Earlier versions carried a browser form posting to the archived fork's gateway auth routes; that form and its `ferrite auth` composition have been removed.

## Using with `agent-ready`

`ferrite add agent-ready` mounts this package transitively. Return the target path from `PageSource::change_password_url`, and dispatch through the header-preserving router `agent_ready::well_known::handle_h` before the application's catch-all route:

```rust
impl agent_ready::well_known::PageSource for Pages {
    fn change_password_url(&self) -> Option<&str> {
        Some("/account/password")
    }
    // markdown / html ...
}

if let Some((status, content_type, body, headers)) =
    agent_ready::well_known::handle_h(
        &surface, &request.method, &request.path, &request.headers,
        &request.body, &pages, execute_tool,
    ).await
{
    let mut reply = ferrite_app::IngressReply::new(&request.correlation_id, status, body);
    reply.headers.push(("content-type".to_string(), content_type.to_string()));
    reply.headers.extend(headers.into_iter().map(|(k, v)| (k.to_string(), v)));
    // emit `reply` through the application's reply binding
}
```

The default `change_password_url` returns `None`, so an application that has not configured a page advertises nothing. The legacy body-only `handle` adapter cannot emit a `Location` header and answers `GET` with the W3C HTML refresh document instead; use `handle_h`.

Without `agent-ready`, call `http_change_password::handle(method, path, Some("/account/password"))` for an existing page and emit every returned header. `alloy-auth` and `ferrite-sso` re-export this module as `change_password`.

## Browser behaviour

`GET` and `HEAD /.well-known/change-password` return `303 See Other` with the configured `Location` and `Cache-Control: no-store`. Incoming query parameters are ignored. Discovery never modifies a credential, consumes a token, or sends a reset email. Unsupported HTTP methods return `405`. Unknown well-known URLs must still return `404`, not a successful SPA shell.

Destinations must be canonical same-origin paths such as `/account/password`. External origins, percent-escapes, dot segments, whitespace, injection characters, and self-redirects are rejected. A malformed configured destination returns `500` without reflecting it. A disabled endpoint returns `404`.

## Status

Active source package with no package dependencies, compiled and tested inside consuming applications (mounted directly or transitively through `agent-ready`, `alloy-auth`, and `ferrite-sso`).

## Not claimed

This package performs no credential change, authentication, CSRF enforcement, or password-reset email delivery. Discovery only redirects a browser to a validated same-origin path supplied by the application and never authorizes a password change on its own.

## Verification

1. Request `/.well-known/change-password` without cookies using both `GET` and `HEAD`. Confirm `303`, the exact same-origin `Location`, `Cache-Control: no-store`, and an empty `HEAD` body.
2. Follow the redirect through the application's own sign-in flow to the password page and change a dedicated test account's password there.
3. Confirm that applications with no configured page, and unknown well-known paths, return `404`, and that private account content does not appear in Markdown twins or sitemaps.

Never ask a user to paste a password into an agent conversation. The package's own checks are its Rust unit tests plus:

```sh
node --test tools/ferrite-pkg/ferrite-pkg.test.mjs
node tools/ferrite-pkg/ferrite-pkg.mjs check
```
