//! x402 — HTTP-native payments for priced operations.
//!
//! Implements the x402 v1 wire protocol: a priced operation answered without
//! payment returns `402` with a JSON body carrying `x402Version`, an
//! `accepts` array of payment requirements, and an `error` string; the
//! client retries with an `X-PAYMENT` header (base64 JSON payload). This
//! module owns the complete protocol surface a serving app needs:
//! requirement generation, payload decoding, [`verify_payment`] (the full
//! structural verification of an `exact`-scheme EIP-3009 authorization
//! against the operation's requirements), and the facilitator wire bodies
//! ([`facilitator_verify_body`] / [`facilitator_settle_body`] for the
//! standard `POST /verify` and `POST /settle` endpoints) that the host app
//! submits through its declared egress. Signature recovery itself is
//! on-chain state the facilitator owns at settlement — exactly the split
//! the x402 spec draws between resource server and facilitator.

use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::surface::{Operation, Surface};

/// The x402 protocol version this module speaks.
pub const X402_VERSION: u64 = 1;

/// The request header carrying the payment payload (v1 naming; Cloudflare's
/// 2026 gateway uses `PAYMENT-SIGNATURE`, same handshake).
pub const PAYMENT_HEADER: &str = "X-PAYMENT";

/// The response header carrying settlement confirmation.
pub const PAYMENT_RESPONSE_HEADER: &str = "X-PAYMENT-RESPONSE";

/// Default payment network for generated requirements (Base USDC — the
/// x402 `exact` scheme's canonical rail).
pub const DEFAULT_NETWORK: &str = "base";
/// USDC on Base (the `asset` contract address agents recognise).
pub const DEFAULT_ASSET: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/// One `accepts` entry: the payment requirements for an operation.
pub fn payment_requirements(s: &Surface, o: &Operation, pay_to: &str) -> Value {
    serde_json::json!({
        "scheme": "exact",
        "network": DEFAULT_NETWORK,
        // USD micros -> USDC atomic units (6 decimals): 1 micro-USD == 1 unit.
        "maxAmountRequired": o.price_micros.to_string(),
        "resource": s.url(&o.path),
        "description": o.description,
        "mimeType": "application/json",
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        "asset": DEFAULT_ASSET,
        "extra": { "name": "USD Coin", "version": "2" }
    })
}

/// The full 402 challenge body for `o`.
pub fn challenge_body(s: &Surface, o: &Operation, pay_to: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "x402Version": X402_VERSION,
        "error": "X-PAYMENT header is required",
        "accepts": [ payment_requirements(s, o, pay_to) ]
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// A parsed `X-PAYMENT` payload (the fields the host's verifier needs).
#[derive(Debug, Clone)]
pub struct PaymentPayload {
    /// Declared x402 version.
    pub x402_version: u64,
    /// Payment scheme (v1: `exact`).
    pub scheme: String,
    /// Network id (e.g. `base`).
    pub network: String,
    /// The raw decoded payload (scheme-specific `payload` object included),
    /// handed to the facilitator seam verbatim.
    pub raw: Value,
}

/// Decode a base64url-or-standard base64 `X-PAYMENT` header value into a
/// payload. Returns `Err(reason)` on malformed input.
pub fn decode_payment(header_value: &str) -> Result<PaymentPayload, String> {
    let bytes = b64_decode(header_value.trim()).ok_or("X-PAYMENT is not valid base64")?;
    let raw: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("X-PAYMENT is not JSON: {e}"))?;
    let x402_version = raw.get("x402Version").and_then(Value::as_u64).unwrap_or(0);
    if x402_version != X402_VERSION {
        return Err(format!("unsupported x402Version {x402_version}"));
    }
    let scheme = raw
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let network = raw
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if scheme.is_empty() || network.is_empty() {
        return Err("X-PAYMENT missing scheme/network".into());
    }
    Ok(PaymentPayload {
        x402_version,
        scheme,
        network,
        raw,
    })
}

/// The `payload.authorization` object, when the payment carries one.
fn authorization(payload: &PaymentPayload) -> Option<&Map<String, Value>> {
    payload.raw.get("payload")?.get("authorization")?.as_object()
}

/// An epoch-seconds field, as a JSON number or a decimal string.
fn epoch_secs(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// Verify a decoded payment against an operation's requirements — the
/// resource-server half of x402 verification, run before submitting the
/// payload for settlement. Checks the scheme, the network, the EIP-3009
/// authorization envelope (`from`/`to`/`value`/`validAfter`/`validBefore`/
/// `nonce`), the recipient binding, the amount, the validity window, and
/// the signature's presence and hex shape. Returns `Err(reason)` with a
/// machine-readable reason on the first failed check.
///
/// This is the STRUCTURAL half. Cryptographic acceptance is
/// [`verify_payment_signed`]: the constrained tier cannot vendor secp256k1
/// recovery, so the settlement trust anchor is a facilitator credential —
/// an HMAC-SHA-256 tag over the canonical authorization fields, keyed by
/// the secret the app shares with its facilitator. Only a payload bearing
/// a valid tag settles; everything else is rejected.
pub fn verify_payment(
    payload: &PaymentPayload,
    price_micros: u64,
    pay_to: &str,
    now_epoch_secs: u64,
) -> Result<(), String> {
    if payload.scheme != "exact" {
        return Err(format!("unsupported scheme '{}'", payload.scheme));
    }
    if payload.network != DEFAULT_NETWORK {
        return Err(format!("unsupported network '{}'", payload.network));
    }
    let inner = payload.raw.get("payload").ok_or("payload object missing")?;
    let auth = inner
        .get("authorization")
        .and_then(Value::as_object)
        .ok_or("payload.authorization missing")?;
    for field in ["from", "to", "value", "validAfter", "validBefore", "nonce"] {
        if !auth.contains_key(field) {
            return Err(format!("authorization.{field} missing"));
        }
    }
    // The parties and the nonce must be real strings: an empty payee would
    // otherwise match an empty or non-string `to`, and a non-string nonce
    // would verify here only to be refused later, after settlement.
    for field in ["from", "to", "nonce"] {
        if auth
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|v| v.trim().is_empty())
        {
            return Err(format!("authorization.{field} is not a non-empty string"));
        }
    }
    if pay_to.trim().is_empty() {
        return Err("no payee is configured".into());
    }
    let to = auth.get("to").and_then(Value::as_str).unwrap_or_default();
    if !to.eq_ignore_ascii_case(pay_to) {
        return Err(format!("authorization.to '{to}' is not the payee"));
    }
    let value: u128 = auth
        .get("value")
        .and_then(Value::as_str)
        .and_then(|v| v.parse().ok())
        .or_else(|| auth.get("value").and_then(Value::as_u64).map(u128::from))
        .ok_or("authorization.value is not an amount")?;
    if value < u128::from(price_micros) {
        return Err(format!(
            "authorization.value {value} is below the price {price_micros}"
        ));
    }
    // The validity window is REQUIRED and must parse: an authorization
    // whose `validBefore` is absent or unparseable would otherwise skip the
    // expiry check and be accepted forever, so absence rejects.
    let window = |k: &str| -> Result<u64, String> {
        auth.get(k)
            .and_then(epoch_secs)
            .ok_or_else(|| format!("authorization.{k} is not an epoch-seconds value"))
    };
    if now_epoch_secs < window("validAfter")? {
        return Err("authorization not yet valid".into());
    }
    if now_epoch_secs >= window("validBefore")? {
        return Err("authorization expired".into());
    }
    let sig = inner
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let hex = sig.strip_prefix("0x").unwrap_or(sig);
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("payload.signature is not hex".into());
    }
    Ok(())
}

/// Domain-separation prefix for the v2 canonical serialization. Versioned
/// so a future framing change cannot collide with today's bytes.
const AUTH_DOMAIN_V2: &str = "x402-auth-v2";

/// The canonical byte string a payment's settlement tag covers (v2): the
/// domain prefix, then the signed tuple — protocol version, scheme,
/// network, and every EIP-3009 authorization field — as a JSON array. JSON
/// serialization is INJECTIVE over the tuple: each field is carried as its
/// JSON value (missing is `null`, distinct from `""`), and string escaping
/// means no field content can forge a boundary — the exact framing hazard
/// `hmac.rs` documents for concatenated parts ("callers that authenticate
/// several fields must encode unambiguous framing"). Both sides (the
/// payer's facilitator credential and the resource server) compute the tag
/// over exactly these bytes.
pub fn canonical_authorization(payload: &PaymentPayload) -> Result<Vec<u8>, String> {
    let auth = authorization(payload).ok_or("payload.authorization missing")?;
    let field = |k: &str| auth.get(k).cloned().unwrap_or(Value::Null);
    let tuple = serde_json::json!([
        payload.x402_version,
        payload.scheme,
        payload.network,
        field("from"),
        field("to"),
        field("value"),
        field("validAfter"),
        field("validBefore"),
        field("nonce"),
    ]);
    let mut out = format!("{AUTH_DOMAIN_V2}:").into_bytes();
    out.extend(
        serde_json::to_vec(&tuple).map_err(|e| format!("canonical serialization failed: {e}"))?,
    );
    Ok(out)
}

/// One signed field's string form in the v1 framing.
fn v1_field(auth: &Map<String, Value>, k: &str) -> String {
    match auth.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

/// The LEGACY (v1) canonical bytes: the same fields in string form joined
/// with `\n`. Non-injective — a field containing `\n` shifts every later
/// field, and missing fields degrade to `""` — so v1 tags are ACCEPTED only
/// when [`v1_join_is_unambiguous`] holds, and new tags are always minted
/// over the v2 bytes.
fn canonical_authorization_v1(payload: &PaymentPayload) -> Result<Vec<u8>, String> {
    let auth = authorization(payload).ok_or("payload.authorization missing")?;
    let field = |k: &str| v1_field(auth, k);
    Ok(format!(
        "x402v{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        payload.x402_version,
        payload.scheme,
        payload.network,
        field("from"),
        field("to"),
        field("value"),
        field("validAfter"),
        field("validBefore"),
        field("nonce"),
    )
    .into_bytes())
}

/// v1 acceptance guard: the `\n` join is injective only while no signed
/// field contains the separator itself, so a v1 tag is considered at all
/// only when every field's v1 string form is newline-free.
fn v1_join_is_unambiguous(payload: &PaymentPayload) -> bool {
    let Some(auth) = authorization(payload) else {
        return false;
    };
    !payload.scheme.contains('\n')
        && !payload.network.contains('\n')
        && ["from", "to", "value", "validAfter", "validBefore", "nonce"]
            .iter()
            .all(|k| !v1_field(auth, k).contains('\n'))
}

/// `0x`-prefixed hex of the HMAC-SHA-256 of `msg` under `secret`.
/// An empty facilitator key is public (anyone can compute HMAC under it), so
/// a blank credential refuses every payment rather than accepting forged
/// tags.
fn require_secret(secret: &[u8]) -> Result<(), String> {
    if secret.iter().all(u8::is_ascii_whitespace) {
        return Err("facilitator secret is empty".into());
    }
    Ok(())
}

fn settlement_tag(msg: &[u8], secret: &[u8]) -> String {
    let tag = crate::agent_ready::hmac::hmac_sha256(secret, msg);
    format!("0x{}", crate::agent_ready::sha256::to_hex(&tag))
}

/// Compute the settlement tag for a payload with the facilitator
/// credential `secret` — the client-side half (and the test half): the
/// value the `payload.signature` field must carry, `0x`-prefixed hex of
/// HMAC-SHA-256 over the v2 [`canonical_authorization`] bytes.
pub fn sign_payment(payload: &PaymentPayload, secret: &[u8]) -> Result<String, String> {
    require_secret(secret)?;
    Ok(settlement_tag(&canonical_authorization(payload)?, secret))
}

/// Constant-time equality of two `0x`-prefixed hex tags (equal length or
/// reject; case-insensitive over the hex digits).
///
/// Case folding happens first, over the whole of both strings, so it leaks
/// nothing; the comparison itself is the SDK's
/// (`crate::crypto::constant_time_eq`) rather than a local loop.
fn tag_matches(presented: &str, expected: &str) -> bool {
    let a = presented
        .trim_start_matches("0x")
        .as_bytes()
        .to_ascii_lowercase();
    let b = expected
        .trim_start_matches("0x")
        .as_bytes()
        .to_ascii_lowercase();
    crate::crypto::constant_time_eq(&a, &b)
}

/// Full verification: the structural battery ([`verify_payment`]) plus
/// cryptographic acceptance — the payload's `signature` must be the valid
/// HMAC-SHA-256 settlement tag under `secret`. Constant-time comparison;
/// rejects on any mismatch. This is what makes an unpaid or forged premium
/// call impossible: without the facilitator credential no acceptable
/// signature can be constructed.
///
/// The v2 canonical bytes are checked first; a legacy v1 tag is accepted
/// only while no signed field contains `\n` — a payload smuggling `\n`
/// through a field can never settle on the v1 framing.
pub fn verify_payment_signed(
    payload: &PaymentPayload,
    price_micros: u64,
    pay_to: &str,
    now_epoch_secs: u64,
    secret: &[u8],
) -> Result<(), String> {
    require_secret(secret)?;
    verify_payment(payload, price_micros, pay_to, now_epoch_secs)?;
    let presented = payload
        .raw
        .get("payload")
        .and_then(|p| p.get("signature"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tag_matches(presented, &sign_payment(payload, secret)?) {
        return Ok(());
    }
    if v1_join_is_unambiguous(payload)
        && tag_matches(
            presented,
            &settlement_tag(&canonical_authorization_v1(payload)?, secret),
        )
    {
        return Ok(());
    }
    Err("payload.signature is not a valid settlement tag".into())
}

/// The request body for a facilitator's `POST /verify`: the decoded payment
/// plus the requirements it must satisfy, per the x402 facilitator API.
pub fn facilitator_verify_body(
    s: &Surface,
    o: &Operation,
    pay_to: &str,
    payload: &PaymentPayload,
) -> Vec<u8> {
    let body = serde_json::json!({
        "x402Version": X402_VERSION,
        "paymentPayload": payload.raw,
        "paymentRequirements": payment_requirements(s, o, pay_to)
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// The request body for a facilitator's `POST /settle` — same shape as
/// verify; the facilitator broadcasts the pre-signed transfer.
pub fn facilitator_settle_body(
    s: &Surface,
    o: &Operation,
    pay_to: &str,
    payload: &PaymentPayload,
) -> Vec<u8> {
    facilitator_verify_body(s, o, pay_to, payload)
}

/// `authorization.nonce`, ASCII-lowercased: an EIP-3009 nonce is a
/// `bytes32` whose hex digits are case-insensitive, so `0xAB..` and `0xab..`
/// are the same nonce under the same signature.
pub fn payment_nonce(payload: &PaymentPayload) -> Result<String, String> {
    authorization(payload)
        .and_then(|a| a.get("nonce"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| "authorization.nonce is not a non-empty string".into())
}

/// The replay key for a payment: the case-normalized `(from, nonce)` pair.
/// EIP-3009 scopes nonces per authorizer and they are single-use on-chain;
/// the resource server mirrors that with a [`ReplayLedger`] keyed by this
/// value, so a mixed-case copy of a nonce cannot settle twice and two payers
/// who pick the same nonce do not collide.
pub fn payment_replay_key(payload: &PaymentPayload) -> Result<String, String> {
    let from = authorization(payload)
        .and_then(|a| a.get("from"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .ok_or("authorization.from is not a non-empty string")?
        .to_ascii_lowercase();
    Ok(format!("{from}:{}", payment_nonce(payload)?))
}

/// The replay-ledger seam: one settlement tag authorizes ONE serve. The
/// host checks-and-inserts the payment's [`payment_replay_key`] ATOMICALLY (a
/// store CAS, create-if-absent) before treating a payment as settled;
/// implementations record `nonce → first_seen_ms` under a host-chosen key
/// (deployed apps key by `tenant:nonce`) and fail CLOSED — a ledger that
/// cannot answer rejects the payment rather than settling a possible
/// replay.
///
/// `expires_at_ms` is the absolute epoch-ms deadline past which the row may
/// self-delete: a replay is only possible while the payment could still verify,
/// and verification hard-rejects once `validBefore` passes — so a row that
/// outlives `validBefore` protects nothing and would otherwise accumulate
/// forever. Use [`replay_expiry_ms`] to derive it from the payload. `0` means
/// no expiry (the fail-safe when the window cannot be read).
pub trait ReplayLedger {
    /// Atomically record `nonce` if unseen, self-deleting at `expires_at_ms`:
    /// `Ok(())` exactly once per nonce; `Err(reason)` on replay or on ledger
    /// failure.
    fn check_and_insert(
        &self,
        nonce: &str,
        expires_at_ms: u64,
    ) -> impl core::future::Future<Output = Result<(), String>> + Send;
}

/// How long past `validBefore` a replay row is kept, in ms. A small margin
/// over the window covers clock skew between the verifier's `now` and the
/// store's expiry clock, so a nonce cannot become replayable in the seam
/// between the two.
pub const REPLAY_LEDGER_MARGIN_MS: u64 = 5 * 60 * 1000;

/// The absolute epoch-ms deadline a replay row for `payload` may self-delete
/// at: the authorization's `validBefore` (epoch SECONDS) in ms, plus
/// [`REPLAY_LEDGER_MARGIN_MS`]. `0` when `validBefore` is absent or unparseable
/// — a fail-safe "no expiry" so a still-verifiable payment can never be
/// replayed after the row lapses (verification requires the field, so a settled
/// payment reaching the ledger has one).
pub fn replay_expiry_ms(payload: &PaymentPayload) -> u64 {
    authorization(payload)
        .and_then(|a| a.get("validBefore"))
        .and_then(epoch_secs)
        .and_then(|secs| secs.checked_mul(1000))
        .map(|ms| ms.saturating_add(REPLAY_LEDGER_MARGIN_MS))
        .unwrap_or(0)
}

/// The verdict the settlement path returns for one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// Verified and settled; carries the settlement receipt (rendered into
    /// `X-PAYMENT-RESPONSE` by the host).
    Settled { receipt: String },
    /// Rejected with a machine-readable reason.
    Rejected { reason: String },
}

/// Base64 decode accepting standard and url-safe alphabets, with or without
/// padding.
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'\n' && *b != b'\r')
        .collect();
    // Padding only at the end, at most two, and a lone trailing character (six
    // bits, never a byte) is not base64.
    let body_len = s.iter().rposition(|b| *b != b'=').map_or(0, |i| i + 1);
    if s.len() - body_len > 2 || s[..body_len].contains(&b'=') || body_len % 4 == 1 {
        return None;
    }
    let s = &s[..body_len];
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
            bits += 6;
        }
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Base64 standard encode (for tests and receipt rendering).
pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind, Surface};

    fn surface() -> Surface {
        Surface {
            name: "quotes".into(),
            owner: "labs".into(),
            origin: "https://quotes.example".into(),
            description: "Quote API.".into(),
            version: "1.0.0".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "api".into(),
                operations: vec![Operation {
                    name: "premium_quote".into(),
                    method: "POST".into(),
                    path: "/api/premium".into(),
                    description: "A premium quote.".into(),
                    input_schema: None,
                    output_schema: None,
                    read_only: false,
                    idempotent: true,
                    price_micros: 10_000,
                }],
            }],
            pages: vec![],
        }
    }

    #[test]
    fn challenge_shape() {
        let s = surface();
        let o = s.operation("premium_quote").unwrap();
        let body: Value = serde_json::from_slice(&challenge_body(&s, o, "0xABC")).unwrap();
        assert_eq!(body["x402Version"], 1);
        let acc = &body["accepts"][0];
        assert_eq!(acc["scheme"], "exact");
        assert_eq!(acc["maxAmountRequired"], "10000");
        assert_eq!(acc["payTo"], "0xABC");
        assert_eq!(acc["resource"], "https://quotes.example/api/premium");
    }

    #[test]
    fn decode_roundtrip() {
        let payload = serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": { "authorization": {}, "signature": "0x0" }
        });
        let header = b64_encode(&serde_json::to_vec(&payload).unwrap());
        let p = decode_payment(&header).unwrap();
        assert_eq!(p.scheme, "exact");
        assert_eq!(p.network, "base");
    }

    #[test]
    fn decode_rejects_bad_version() {
        let payload = serde_json::json!({ "x402Version": 9, "scheme": "exact", "network": "base" });
        let header = b64_encode(&serde_json::to_vec(&payload).unwrap());
        assert!(decode_payment(&header).is_err());
    }

    #[test]
    fn b64_helpers() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        // url-safe alphabet accepted
        assert_eq!(b64_decode("aGVsbG8").unwrap(), b"hello");
        assert!(b64_decode("!!!").is_none());
        // finding_e5a1e141fe044416: a lone trailing character and interior padding are refused.
        assert!(b64_decode("A").is_none());
        assert!(b64_decode("a=GVs=bG8=A").is_none());
        assert!(b64_decode("aGVsbG8===").is_none());
    }

    #[test]
    fn signed_settlement_round_trip() {
        let secret = b"facilitator-credential";
        let mk = |sig: &str| {
            let payload = serde_json::json!({
                "x402Version": 1,
                "scheme": "exact",
                "network": "base",
                "payload": {
                    "authorization": {
                        "from": "0xClient", "to": "0xPayee", "value": "10000",
                        "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
                    },
                    "signature": sig
                }
            });
            decode_payment(&b64_encode(&serde_json::to_vec(&payload).unwrap())).unwrap()
        };
        // Sign with the credential -> accepted.
        let unsigned = mk("0x0");
        let tag = sign_payment(&unsigned, secret).unwrap();
        let signed = mk(&tag);
        assert!(verify_payment_signed(&signed, 10_000, "0xPayee", 1_000, secret).is_ok());
        // A forged tag (any other hex) -> rejected.
        let forged = mk("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(verify_payment_signed(&forged, 10_000, "0xPayee", 1_000, secret).is_err());
        // The right tag under the WRONG secret -> rejected.
        let other = sign_payment(&unsigned, b"other-secret").unwrap();
        let wrong = mk(&other);
        assert!(verify_payment_signed(&wrong, 10_000, "0xPayee", 1_000, secret).is_err());
        // Structural failures still reject before crypto: wrong payee.
        assert!(verify_payment_signed(&signed, 10_000, "0xOther", 1_000, secret).is_err());
        // Expired window.
        assert!(
            verify_payment_signed(&signed, 10_000, "0xPayee", 100_000_000_000, secret).is_err()
        );
    }

    fn payload_with_auth(auth: Value, sig: &str) -> PaymentPayload {
        let payload = serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": { "authorization": auth, "signature": sig }
        });
        decode_payment(&b64_encode(&serde_json::to_vec(&payload).unwrap())).unwrap()
    }

    /// The validity window is required: an authorization with no
    /// `validBefore` — or one that does not parse as epoch seconds — is
    /// rejected instead of silently skipping the expiry check.
    #[test]
    fn missing_or_unparseable_expiry_is_rejected() {
        let missing = payload_with_auth(
            serde_json::json!({
                "from": "0xClient", "to": "0xPayee", "value": "10000",
                "validAfter": "0", "nonce": "0x1"
            }),
            "0x0",
        );
        assert!(verify_payment(&missing, 10_000, "0xPayee", 1_000)
            .unwrap_err()
            .contains("validBefore"));
        let unparseable = payload_with_auth(
            serde_json::json!({
                "from": "0xClient", "to": "0xPayee", "value": "10000",
                "validAfter": "0", "validBefore": "later", "nonce": "0x1"
            }),
            "0x0",
        );
        assert!(verify_payment(&unparseable, 10_000, "0xPayee", 1_000)
            .unwrap_err()
            .contains("validBefore"));
        // validAfter is equally required.
        let no_after = payload_with_auth(
            serde_json::json!({
                "from": "0xClient", "to": "0xPayee", "value": "10000",
                "validBefore": "99999999999", "nonce": "0x1"
            }),
            "0x0",
        );
        assert!(verify_payment(&no_after, 10_000, "0xPayee", 1_000)
            .unwrap_err()
            .contains("validAfter"));
    }

    /// A legacy v1 settlement tag (HMAC over the `\n`-joined fields) still
    /// settles — but ONLY while no signed field contains `\n`.
    #[test]
    fn legacy_v1_tag_accepted_only_when_unambiguous() {
        let secret = b"facilitator-credential";
        let clean_auth = serde_json::json!({
            "from": "0xClient", "to": "0xPayee", "value": "10000",
            "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
        });
        let unsigned = payload_with_auth(clean_auth.clone(), "0x0");
        let v1_tag = {
            let msg = canonical_authorization_v1(&unsigned).unwrap();
            let tag = crate::agent_ready::hmac::hmac_sha256(secret, &msg);
            format!("0x{}", crate::agent_ready::sha256::to_hex(&tag))
        };
        let legacy = payload_with_auth(clean_auth, &v1_tag);
        assert!(verify_payment_signed(&legacy, 10_000, "0xPayee", 1_000, secret).is_ok());

        // The same v1 framing over a newline-embedded field is REFUSED even
        // with a matching tag: the join is non-injective there.
        let sneaky_auth = serde_json::json!({
            "from": "0xEvil\n0xShifted", "to": "0xPayee", "value": "10000",
            "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
        });
        let sneaky_unsigned = payload_with_auth(sneaky_auth.clone(), "0x0");
        assert!(!v1_join_is_unambiguous(&sneaky_unsigned));
        let sneaky_tag = {
            let msg = canonical_authorization_v1(&sneaky_unsigned).unwrap();
            let tag = crate::agent_ready::hmac::hmac_sha256(secret, &msg);
            format!("0x{}", crate::agent_ready::sha256::to_hex(&tag))
        };
        let sneaky = payload_with_auth(sneaky_auth, &sneaky_tag);
        assert!(
            verify_payment_signed(&sneaky, 10_000, "0xPayee", 1_000, secret).is_err(),
            "a newline-embedded field must never settle on the v1 framing"
        );
    }

    /// The v1 `\n` join lets DISTINCT tuples serialize to identical signed
    /// bytes (the framing hazard hmac.rs documents); the v2 JSON
    /// serialization keeps them distinct.
    #[test]
    fn v2_canonicalization_is_injective_where_v1_collides() {
        let a = payload_with_auth(
            serde_json::json!({
                "from": "0xEvil", "to": "0xMule\n0xPayee", "value": "10000",
                "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
            }),
            "0x0",
        );
        let b = payload_with_auth(
            serde_json::json!({
                "from": "0xEvil\n0xMule", "to": "0xPayee", "value": "10000",
                "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
            }),
            "0x0",
        );
        assert_eq!(
            canonical_authorization_v1(&a).unwrap(),
            canonical_authorization_v1(&b).unwrap(),
            "the v1 join collides by construction"
        );
        assert_ne!(
            canonical_authorization(&a).unwrap(),
            canonical_authorization(&b).unwrap(),
            "the v2 serialization must keep distinct tuples distinct"
        );
        // And a MISSING field is distinct from an empty one under v2.
        let missing = payload_with_auth(
            serde_json::json!({ "from": "0xEvil", "to": "0xPayee", "value": "10000" }),
            "0x0",
        );
        let empty = payload_with_auth(
            serde_json::json!({
                "from": "0xEvil", "to": "0xPayee", "value": "10000",
                "validAfter": "", "validBefore": "", "nonce": ""
            }),
            "0x0",
        );
        assert_ne!(
            canonical_authorization(&missing).unwrap(),
            canonical_authorization(&empty).unwrap()
        );
    }

    #[test]
    fn payment_nonce_extraction() {
        let p = payload_with_auth(
            serde_json::json!({
                "from": "0xClient", "to": "0xPayee", "value": "10000",
                "validAfter": "0", "validBefore": "99999999999", "nonce": "0xabc"
            }),
            "0x0",
        );
        assert_eq!(payment_nonce(&p).unwrap(), "0xabc");
        let none = payload_with_auth(
            serde_json::json!({ "from": "0xClient", "to": "0xPayee", "value": "10000" }),
            "0x0",
        );
        assert!(payment_nonce(&none).is_err());
        let empty = payload_with_auth(serde_json::json!({ "nonce": "" }), "0x0");
        assert!(payment_nonce(&empty).is_err());
    }

    #[test]
    fn replay_expiry_tracks_valid_before() {
        // validBefore in seconds → ms + margin, from a string or a number.
        let as_str = payload_with_auth(
            serde_json::json!({ "validBefore": "1993456800", "nonce": "0xabc" }),
            "0x0",
        );
        assert_eq!(
            replay_expiry_ms(&as_str),
            1_993_456_800_000 + REPLAY_LEDGER_MARGIN_MS
        );
        let as_num = payload_with_auth(
            serde_json::json!({ "validBefore": 1_000, "nonce": "0xabc" }),
            "0x0",
        );
        assert_eq!(
            replay_expiry_ms(&as_num),
            1_000_000 + REPLAY_LEDGER_MARGIN_MS
        );
        // Absent or unparseable → 0 (no expiry, the fail-safe).
        let missing = payload_with_auth(serde_json::json!({ "nonce": "0xabc" }), "0x0");
        assert_eq!(replay_expiry_ms(&missing), 0);
        let junk = payload_with_auth(serde_json::json!({ "validBefore": "soon" }), "0x0");
        assert_eq!(replay_expiry_ms(&junk), 0);
    }

    #[test]
    fn blank_credentials_payees_and_parties_never_settle() {
        let auth = serde_json::json!({
            "from": "0xClient", "to": "", "value": "10000",
            "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
        });
        let p = payload_with_auth(auth, "0x0");
        assert!(verify_payment(&p, 10_000, "", 1).is_err(), "empty payee matched empty to");
        let p = payload_with_auth(
            serde_json::json!({
                "from": "0xClient", "to": null, "value": "10000",
                "validAfter": "0", "validBefore": "99999999999", "nonce": 7
            }),
            "0x0",
        );
        assert!(verify_payment(&p, 10_000, "", 1).is_err());
        let good = serde_json::json!({
            "from": "0xClient", "to": "0xPayee", "value": "10000",
            "validAfter": "0", "validBefore": "99999999999", "nonce": "0x1"
        });
        let p = payload_with_auth(good.clone(), "0x0");
        assert!(sign_payment(&p, b"").is_err());
        let forged = payload_with_auth(
            good,
            &settlement_tag(&canonical_authorization(&p).unwrap(), b""),
        );
        assert!(verify_payment_signed(&forged, 10_000, "0xPayee", 1, b"").is_err());
    }

    #[test]
    fn replay_keys_fold_case_and_are_scoped_by_payer() {
        let with = |from: &str, nonce: &str| {
            payload_with_auth(
                serde_json::json!({
                    "from": from, "to": "0xPayee", "value": "10000",
                    "validAfter": "0", "validBefore": "99999999999", "nonce": nonce
                }),
                "0x0",
            )
        };
        assert_eq!(
            payment_replay_key(&with("0xClient", "0xABCD")).unwrap(),
            payment_replay_key(&with("0xclient", "0xabcd")).unwrap()
        );
        assert_ne!(
            payment_replay_key(&with("0xAlice", "0x1")).unwrap(),
            payment_replay_key(&with("0xBob", "0x1")).unwrap()
        );
    }
}
