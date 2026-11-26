# byok-vault

Encrypted per-user Bring-Your-Own-Key (BYOK) vault and Ferrite AI Gateway verification helpers for constrained Ferrite apps.

## Why use this package

A Ferrite app that lets end users bring their own Anthropic, OpenAI, or Gemini API keys should **never** call provider APIs directly and should **never** spend the platform's or app owner's credentials on an unconfigured user. `byok-vault` gives your app:

1. **Authenticated encryption at rest** in any Ferrite `store` binding, bound by `(owner, provider)` associated data so rows cannot cross users or providers.
2. **Live key validation through the Ferrite AI Gateway** (`POST https://ai.ferrite.cloud/gw/v1/byok/verify`) using your app's existing `gateway-egress` handle — zero direct `api.openai.com`, `api.anthropic.com`, or `generativelanguage.googleapis.com` egress entries needed.
3. **Per-request BYOK headers** (`x-ferrite-provider-key` + `x-ferrite-byok-only: request`) so every inference call to `ai.ferrite.cloud` bills the end user's own provider key and strictly refuses platform-key fallback.

## Quick usage

```rust
use crate::byok_vault::{self, ByokVault, Provider};

// 1. Validate a submitted key through the Ferrite AI Gateway
let check = byok_vault::verify_via_gateway(
    ctx,
    "gateway-egress",
    "https://ai.ferrite.cloud",
    &gateway_key,
    Provider::Anthropic,
    &submitted_key,
)
.await?;

// 2. Seal the validated key for the signed-in user
if check.valid {
    let mut vault = ByokVault::new(store, &app_session_key)?;
    vault.save_verified(&owner_id, Provider::Anthropic, &submitted_key, check.models, now_ms).await?;
}

// 3. On each inference request to ai.ferrite.cloud, attach the owner's key
let headers = byok_vault::request_headers(&user_api_key);
```
