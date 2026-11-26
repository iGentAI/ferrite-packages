# sha256-hmac

Cryptographic helpers that constrained Ferrite apps need beyond what upstream
Ferrite Core's SDK exports, built over the platform SDK kernel
(`ferrite_app::crypto`). Mounted at `crypto`, so consumers call
`crate::crypto::hex_encode`, `crate::crypto::Sha256`,
`crate::crypto::password_verify`, and related helpers. Validated against the
NIST, RFC 4231, and RFC 7914 test vectors, which run inside every consumer and
therefore verify each app's own SDK build.

## What it provides

Upstream's SDK exports one-shot `sha256`, `hmac_sha256`, the constant-time
comparator `ct_eq`, a lowercase `hex` encoder, and its JWT keys, and nothing
else. Everything else a application SDK needs is value computation and lives here as
source: where a name has a platform primitive the body delegates to it, and
where it does not the implementation is moved from the application SDK so hashes
and passwords stored under the fork verify byte for byte.

| File | Provides | Delegates to |
| --- | --- | --- |
| `sha256.rs` | Incremental `Sha256` (FIPS 180-4), `sha256_concat`, `to_hex`, `BLOCK_LEN`, `DIGEST_LEN` | `ferrite_app::crypto::sha256` for the one-shot digest |
| `hmac.rs` | `hmac_sha256`, `hmac_sha256_concat`, the `hmac` alias | `ferrite_app::crypto::hmac_sha256` |
| `hex.rs` | `hex_encode`, `hex_decode` | `ferrite_app::crypto::hex` for encoding |
| `password.rs` | PBKDF2-HMAC-SHA-256 (RFC 8018), `password_hash`, `password_hash_with`, `password_verify`, the `pbkdf2-sha256$...` record | `hmac_sha256` above |
| `random.rs` | `random_fill`, `random_bytes`, `random_token`, `random_u64` | `Ed25519SigningKey::generate_pkcs8`, the SDK's one route to the OS generator |
| `mod.rs` | `constant_time_eq` and every re-export | `ferrite_app::crypto::ct_eq` |

Upstream exports no random function, and the code gate refuses `getrandom`,
`rand`, and `std::fs`. To reach the OS generator, each 32 bytes are derived as
the HMAC of a fixed label under a freshly generated Ed25519 key document, which
is then dropped (`packages/auth` draws its identifiers the same way). When
upstream exports a random function, only `random_fill`'s body needs to change.

## Why a package

The application crypto modules were byte-identical hand copies backing
session tokens, invites, and GitHub webhook verification. Leaving
security-critical code outside `ferrite-pkg check` allowed silent drift. Moving
it into this package turns that duplication into one canonical source, a
declared mount, and a drift gate.

`mcp` and `agent-ready` re-export the digest and MAC functions from here
instead of carrying a second kernel; other source packages such as `alloy`,
`alloy-auth`, `nitro`, `payments`, `agent-sdk`, and `ferrite-sso` depend on it
for the comparator, hex, passwords, and entropy.

Both Buzz apps keep their own `crypto` module and mount this package at
`crypto_kernel`. `ferrite-pkg` rewrites `crate::crypto` in every dependent
package to match, so a package never has to know where its consumer mounted it.

## Comparing a tag

Never compare tags or digests with `==`. Use `crate::crypto::constant_time_eq`,
which wraps the platform's `ct_eq`; a length mismatch returns `false`, and
length is not a secret.

## Status

Active source package with no package dependencies, compiled and validated
against NIST, RFC 4231, and RFC 7914 vectors inside every consuming app.

## Not claimed

This package is not a standalone Cargo crate and provides no asymmetric
signature verification or AEAD encryption. `random_*` derives OS entropy via
`Ed25519SigningKey::generate_pkcs8` rather than a native SDK RNG primitive.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml
```
