//! The x402 header path: from an `X-PAYMENT` header to a settled serve.
//!
//! # What lives here, and what lives in `agent-ready`
//!
//! The x402 WIRE — requirement generation, payload decoding, the structural
//! and cryptographic verification battery, the facilitator bodies, the nonce
//! and its replay-window arithmetic — is
//! [`crate::agent_ready::x402`](crate::agent_ready::x402), where it sits
//! beside the `Surface` and `Operation` declarations that price an operation
//! in the first place. Splitting it out would have meant either a second
//! implementation of the protocol or nine agent-ready consumers suddenly
//! needing a payments mount, and neither is worth the tidier diagram.
//!
//! What lives here is the PATH a serving application runs, which is the part
//! two apps would otherwise re-derive: the settlement seam, its in-process
//! implementation, the durable replay ledger over a store binding, and the
//! ordering the three are used in ([`require_payment`]).
//!
//! # The ordering is the correctness
//!
//! Verify, then check-and-insert the nonce, then serve. A settlement tag is
//! not a licence to serve repeatedly: one tag authorizes ONE serve, and the
//! replay ledger is what makes that true across restarts and across replicas.
//! The ledger is consulted AFTER verification (an unverified payload's nonce
//! is attacker-chosen and would let anyone poison the ledger) and BEFORE the
//! response is produced (a serve that happened cannot be taken back).
//!
//! Everything fails CLOSED. A ledger that cannot answer rejects the payment;
//! a missing facilitator credential rejects every payment rather than
//! accepting one.

use crate::agent_ready::surface::{Operation, Surface};
use crate::agent_ready::x402::{self, PaymentPayload, PaymentVerdict, ReplayLedger};
use ferrite_app::serde_json::{self, Value};
use ferrite_app::AppContext;

/// A refusal to serve: an HTTP status and the body to write.
///
/// Always `402` today, carrying the x402 challenge document with its `error`
/// field set to the reason. The status travels with the body because a caller
/// that only forwarded the bytes would have to re-derive it.
pub type Challenge = (u16, Vec<u8>);

/// The settlement seam: verify and settle one decoded payment.
///
/// A deployment that wants an on-chain broadcast implements this over its own
/// facilitator egress, POSTing
/// [`x402::facilitator_settle_body`](crate::agent_ready::x402::facilitator_settle_body)
/// after local acceptance. [`LocalVerifier`] is the in-process implementation.
pub trait Facilitator {
    /// Verify and settle; `amount_micros` is the price the operation declares.
    fn settle(&self, payload: &PaymentPayload, amount_micros: u64) -> PaymentVerdict;
}

/// In-process x402 verification and receipt issuance.
///
/// The structural battery (scheme, network, EIP-3009 envelope, payee binding,
/// amount, validity window) plus CRYPTOGRAPHIC acceptance: the payload must
/// carry a valid HMAC-SHA-256 settlement tag under the facilitator credential
/// the application holds. Without that credential no acceptable payment can be
/// constructed, so an unpaid or tampered premium call is rejected rather than
/// settled — and an application deployed without the secret rejects every
/// payment, which is the fail-closed direction.
pub struct LocalVerifier {
    /// The payee address every authorization must name.
    pub pay_to: String,
    /// Current epoch seconds, read from the host's clock each envelope
    /// (`ctx.now_ms() / 1000`) so validity windows are judged against now and
    /// not against process start.
    pub now_epoch_secs: u64,
    /// The facilitator credential settlement tags are keyed by
    /// (`ctx.secret("x402-facilitator-key")` on a deployed fleet).
    pub facilitator_key: Vec<u8>,
}

impl Facilitator for LocalVerifier {
    fn settle(&self, payload: &PaymentPayload, amount_micros: u64) -> PaymentVerdict {
        match x402::verify_payment_signed(
            payload,
            amount_micros,
            &self.pay_to,
            self.now_epoch_secs,
            &self.facilitator_key,
        ) {
            Ok(()) => PaymentVerdict::Settled {
                receipt: x402::b64_encode(
                    serde_json::to_vec(&serde_json::json!({
                        "success": true,
                        "network": payload.network,
                        "payer": payer(payload),
                        "amountMicros": amount_micros,
                    }))
                    .unwrap_or_default()
                    .as_slice(),
                ),
            },
            Err(reason) => PaymentVerdict::Rejected { reason },
        }
    }
}

/// The `authorization.from` address, as a JSON value so an absent payer is
/// `null` rather than an empty string a reader could mistake for an address.
fn payer(payload: &PaymentPayload) -> Value {
    payload
        .raw
        .get("payload")
        .and_then(|p| p.get("authorization"))
        .and_then(|a| a.get("from"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The durable replay ledger: `nonce → first-seen ms`, in a store binding.
///
/// `put_if_version(expected = None)` is a create-if-absent compare-and-swap,
/// so check-and-insert is ATOMIC — two concurrent presentations of one nonce
/// race on the store version and exactly one settles. Fails CLOSED: a store
/// error rejects the payment rather than serving a possible replay.
///
/// Rows self-delete once the payment they guard can no longer verify, so a
/// settled nonce does not accumulate forever; see
/// [`x402::replay_expiry_ms`](crate::agent_ready::x402::replay_expiry_ms) for
/// the deadline and the margin that covers clock skew.
pub struct StoreLedger<'a> {
    /// The app context the store binding is drawn from.
    pub ctx: &'a AppContext,
    /// The store binding's handle, as the application's manifest names it.
    pub binding: &'a str,
    /// The tenant segment of the ledger key, so one store can hold several.
    pub tenant: &'a str,
    /// Epoch ms stamped as the nonce's first-seen value.
    pub now_ms: u64,
}

impl StoreLedger<'_> {
    /// The row key for one nonce. Stable, because changing it would make every
    /// already-settled nonce replayable exactly once.
    #[must_use]
    pub fn key(tenant: &str, nonce: &str) -> String {
        format!("x402:replay:{tenant}:{nonce}")
    }
}

impl ReplayLedger for StoreLedger<'_> {
    fn check_and_insert(
        &self,
        nonce: &str,
        expires_at_ms: u64,
    ) -> impl core::future::Future<Output = Result<(), String>> + Send {
        let key = Self::key(self.tenant, nonce);
        let value = self.now_ms.to_string();
        let store = self.ctx.store(self.binding);
        async move {
            let mut store = store.map_err(|e| format!("replay ledger unavailable: {e}"))?;
            match store
                .put_if_version_expiring(key.as_bytes(), value.as_bytes(), None, expires_at_ms)
                .await
            {
                Ok(Ok(_version)) => Ok(()),
                Ok(Err(_current)) => Err("payment nonce already settled (replay)".into()),
                Err(e) => Err(format!("replay ledger unavailable: {e}")),
            }
        }
    }
}

/// Build the 402 challenge for `operation`, with `error` set to `reason`.
#[must_use]
pub fn challenge(surface: &Surface, operation: &Operation, pay_to: &str, reason: &str) -> Challenge {
    let mut body: Value = serde_json::from_slice(&x402::challenge_body(surface, operation, pay_to))
        .unwrap_or_default();
    body["error"] = serde_json::json!(reason);
    (402, serde_json::to_vec(&body).unwrap_or_default())
}

/// Run the payment gate for one priced operation.
///
/// `Ok(receipt)` means the payment verified, its nonce cleared the replay
/// ledger, and the caller may serve — rendering the receipt into
/// `X-PAYMENT-RESPONSE`. `Err(challenge)` is the status and body to answer
/// with, and covers every other case: no header, an undecodable header, a
/// rejected payment, a payload with no usable nonce, and a replay.
///
/// # Errors
///
/// Returns the 402 [`Challenge`] to serve. The reason is always in the body's
/// `error` field, never only in a log, because the caller is a machine that
/// has to decide what to retry.
pub async fn require_payment<F: Facilitator, L: ReplayLedger>(
    surface: &Surface,
    operation: &Operation,
    pay_to: &str,
    facilitator: &F,
    ledger: &L,
    presented: Option<&str>,
) -> Result<String, Challenge> {
    let reject = |reason: &str| challenge(surface, operation, pay_to, reason);
    let rejected = |reason: String| reject(&format!("payment rejected: {reason}"));
    let header = presented.ok_or_else(|| reject("X-PAYMENT header is required"))?;
    let payload = x402::decode_payment(header).map_err(|reason| reject(&reason))?;
    let receipt = match facilitator.settle(&payload, operation.price_micros) {
        PaymentVerdict::Settled { receipt } => receipt,
        PaymentVerdict::Rejected { reason } => return Err(rejected(reason)),
    };
    // Verified first, so the nonce is one the payer actually signed; inserted
    // before the serve, so one tag buys one response.
    let nonce = x402::payment_replay_key(&payload).map_err(rejected)?;
    let expires_at_ms = x402::replay_expiry_ms(&payload);
    ledger
        .check_and_insert(&nonce, expires_at_ms)
        .await
        .map_err(rejected)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind, Surface};
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    const PAY_TO: &str = "0x000000000000000000000000000000000000dEaD";
    const KEY: &[u8] = b"test-facilitator-key";
    const NOW: u64 = 1_754_524_800;

    fn block<T>(f: impl core::future::Future<Output = T>) -> T {
        use core::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = Box::pin(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended in a ready-only test"),
        }
    }

    /// In-memory replay ledger. The check completes synchronously, so the
    /// ready-only executor drives it.
    #[derive(Default)]
    struct MemLedger(Mutex<BTreeSet<String>>);
    impl ReplayLedger for MemLedger {
        fn check_and_insert(
            &self,
            nonce: &str,
            _expires_at_ms: u64,
        ) -> impl core::future::Future<Output = Result<(), String>> + Send {
            let r = if self.0.lock().unwrap().insert(nonce.to_string()) {
                Ok(())
            } else {
                Err("payment nonce already settled (replay)".into())
            };
            async move { r }
        }
    }

    fn surface() -> Surface {
        Surface {
            name: "payments-kit-test".into(),
            owner: "labs".into(),
            origin: "https://kit.example".into(),
            description: "A test surface with one priced operation.".into(),
            version: "1".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "The priced API.".into(),
                operations: vec![Operation {
                    name: "premium".into(),
                    method: "POST".into(),
                    path: "/api/premium".into(),
                    description: "A priced operation.".into(),
                    input_schema: None,
                    output_schema: None,
                    read_only: false,
                    idempotent: true,
                    price_micros: 10_000,
                }],
            }],
            pages: Vec::new(),
        }
    }

    fn payload_json(nonce: &str) -> Value {
        serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "authorization": {
                    "from": "0x00000000000000000000000000000000000000aa",
                    "to": PAY_TO,
                    "value": "10000",
                    "validAfter": (NOW - 60).to_string(),
                    "validBefore": (NOW + 600).to_string(),
                    "nonce": nonce,
                }
            }
        })
    }

    /// A base64 `X-PAYMENT` header value carrying a correctly tagged payment.
    fn signed_header(nonce: &str) -> String {
        let mut value = payload_json(nonce);
        let unsigned =
            x402::decode_payment(&x402::b64_encode(&serde_json::to_vec(&value).unwrap())).unwrap();
        let tag = x402::sign_payment(&unsigned, KEY).unwrap();
        value["payload"]["signature"] = serde_json::json!(tag);
        x402::b64_encode(&serde_json::to_vec(&value).unwrap())
    }

    fn verifier() -> LocalVerifier {
        LocalVerifier {
            pay_to: PAY_TO.into(),
            now_epoch_secs: NOW,
            facilitator_key: KEY.to_vec(),
        }
    }

    fn gate(header: Option<&str>, ledger: &MemLedger) -> Result<String, Challenge> {
        let s = surface();
        let op = s.operation("premium").expect("declared").clone();
        block(require_payment(
            &s,
            &op,
            PAY_TO,
            &verifier(),
            ledger,
            header,
        ))
    }

    fn error_of(challenge: &Challenge) -> String {
        let v: Value = serde_json::from_slice(&challenge.1).expect("challenge is JSON");
        v["error"].as_str().unwrap_or_default().to_string()
    }

    #[test]
    fn no_header_answers_the_bare_challenge() {
        let ledger = MemLedger::default();
        let challenge = gate(None, &ledger).expect_err("unpaid");
        assert_eq!(challenge.0, 402);
        let v: Value = serde_json::from_slice(&challenge.1).unwrap();
        assert_eq!(v["x402Version"], 1);
        assert_eq!(v["accepts"][0]["maxAmountRequired"], "10000");
        assert_eq!(v["accepts"][0]["payTo"], PAY_TO);
        assert_eq!(error_of(&challenge), "X-PAYMENT header is required");
    }

    #[test]
    fn a_correctly_tagged_payment_settles_and_yields_a_receipt() {
        let ledger = MemLedger::default();
        let receipt = gate(Some(&signed_header("nonce-1")), &ledger).expect("settles");
        let decoded = x402::b64_decode(&receipt).expect("receipt is base64");
        let v: Value = serde_json::from_slice(&decoded).expect("receipt is JSON");
        assert_eq!(v["success"], true);
        assert_eq!(v["network"], "base");
        assert_eq!(v["amountMicros"], 10_000);
    }

    #[test]
    fn one_settlement_tag_buys_exactly_one_serve() {
        let ledger = MemLedger::default();
        let header = signed_header("nonce-replay");
        assert!(gate(Some(&header), &ledger).is_ok());
        let replay = gate(Some(&header), &ledger).expect_err("replayed");
        assert_eq!(replay.0, 402);
        assert!(
            error_of(&replay).contains("already settled"),
            "the reason reaches the caller: {}",
            error_of(&replay)
        );
    }

    #[test]
    fn a_payment_without_the_facilitator_credential_cannot_be_forged() {
        let mut value = payload_json("nonce-forged");
        value["payload"]["signature"] = serde_json::json!("0xdeadbeef");
        let header = x402::b64_encode(&serde_json::to_vec(&value).unwrap());
        let ledger = MemLedger::default();
        let refused = gate(Some(&header), &ledger).expect_err("forged");
        assert_eq!(refused.0, 402);
        assert!(error_of(&refused).starts_with("payment rejected:"));
    }

    #[test]
    fn an_undecodable_header_is_a_challenge_and_never_a_panic() {
        let ledger = MemLedger::default();
        for header in ["", "not-base64-!!", &x402::b64_encode(b"{}")] {
            let refused = gate(Some(header), &ledger).expect_err("undecodable");
            assert_eq!(refused.0, 402);
            assert!(!error_of(&refused).is_empty());
        }
    }

    #[test]
    fn a_rejected_payment_never_reaches_the_replay_ledger() {
        // A forged payload's nonce is attacker-chosen; inserting it before
        // verification would let anyone burn a nonce the real payer holds.
        let ledger = MemLedger::default();
        let mut value = payload_json("nonce-shared");
        value["payload"]["signature"] = serde_json::json!("0xdeadbeef");
        let forged = x402::b64_encode(&serde_json::to_vec(&value).unwrap());
        assert!(gate(Some(&forged), &ledger).is_err());
        // The genuine payment carrying the same nonce still settles.
        assert!(gate(Some(&signed_header("nonce-shared")), &ledger).is_ok());
    }

    #[test]
    fn the_replay_key_is_tenant_scoped_and_stable() {
        assert_eq!(
            StoreLedger::key("quotes-api", "n1"),
            "x402:replay:quotes-api:n1"
        );
    }
}
