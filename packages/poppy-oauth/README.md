# poppy-oauth

Per-application OAuth 2.1 Authorization Server for the **Personal Agent Protocol (Poppy 1.0)**, shipped as a `ferrite-pkg` source package with `ferrite-app` as its sole Cargo dependency.

## Why per-application OAuth?

Poppy §3.2 requires every independent Company to have its own OAuth issuer:

> *"An issuer MUST represent exactly one Company. A provider that hosts several Companies MUST give each its own issuer... Otherwise the Companies would be one Company under this protocol."*

Ferrite hosts applications for independent organizations. Customer applications must never share Ferrite's own sign-in broker (`login.ferrite.cloud`). With `agent-ready` + `poppy-oauth`, an application can choose any of three cleanly isolated issuer models:

1. **Self-hosted per-app issuer (this package):** The app serves its own OAuth 2.1 issuer on its own canonical origin (`https://<app-host>`), using its own secrets and authenticating end users through its own sign-in flow (`packages/auth`, `packages/alloy-auth`, or custom login).
2. **Bring-your-own external OAuth issuer (`PoppyAuth::External`):** The app delegates authorization to Okta, WorkOS, Auth0, Descope, or the customer's own authorization server without mounting `poppy-oauth`.
3. **Multi-tenant per-Company issuer service:** A dedicated multi-tenant service instantiates `PoppyOAuthServer` with a distinct `issuer = "https://auth.platform.example/<company-id>"` and partitioned `OAuthStore` per company.

## Endpoints

| Route | Standard | Behavior |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 + Poppy §3.2 | Metadata with `protected_resources`, `revocation_endpoint`, `pushed_authorization_request_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported: ["private_key_jwt"]`, `token_endpoint_auth_signing_alg_values_supported: ["ES256", "PS384"]`, `client_id_metadata_document_supported: true`, `dpop_signing_alg_values_supported: ["ES256"]`, `scopes_supported`. |
| `POST /oauth/par` | RFC 9126 | Pushed Authorization Requests authenticated with `private_key_jwt`, PKCE `S256` required, 120-second single-use `request_uri`. |
| `GET/POST /oauth/authorize` | OAuth 2.1 + Poppy §4.2 | Direct Sign-In with PKCE `S256`, exact `redirect_uri` matching (+ RFC 8252 loopback port variance), `prompt=consent`, anti-phishing Poppy consent HTML page highlighting `irreversible` and `personal_data` scopes, and `iss` on every redirect (RFC 9207). |
| `POST /oauth/device`, `GET/POST /oauth/device/verify` | RFC 8628 + RFC 10027 | Opt-in Device Sign-In (off by default); never approves on `GET`, enforces `slow_down` and short expiry. |
| `POST /oauth/token` | OAuth 2.1 + Poppy §4.4–4.7 | `authorization_code`, `refresh_token`, and opt-in `device_code` grants; `private_key_jwt` (`aud == issuer`, `jti` replay burn); multi-resource tokens (RFC 8707); downscoping; refresh token rotation with grant-family replay revocation (RFC 9700 §4.14.2); optional DPoP proof & refresh-key binding (RFC 9449). |
| `POST /oauth/revoke` | RFC 7009 + Poppy §4.6 | Revokes the grant family and immediately invalidates all access tokens issued under it. |
| `GET/POST /oauth/connected-agents` | Poppy Guides ("Account settings") | Lists connected Personal Agents (name, `client_id` domain, granted scopes, last used) with one-click Disconnect. |

## Security invariants

- Never grants scopes beyond those requested (§4.7).
- Requires non-empty `scope` on every sign-in request; rejects unknown scopes with `invalid_scope`.
- Enforces `aud == issuer` (exact string match, never the token endpoint URL) and burns assertion `jti` until expiry.
- Access tokens bound to a specific `resource` (such as `/mcp`) are rejected at every other resource (§7).
- Family revocation (`POST /oauth/revoke` or user Disconnect) invalidates both refresh tokens and active access tokens immediately (§5.5).
