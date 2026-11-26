//! The `t=,v1=` webhook verifier, over the bytes as received.
//!
//! # Why the raw body, and why the ordering is the design
//!
//! Stripe's MAC covers `"{t}.{raw payload}"`. Nothing on the Ferrite ingress
//! path re-serializes that payload — the gateway reads exactly
//! `content-length` bytes off the socket into `IngressRequest.body`, and a
//! `Vec<u8>` survives the envelope's own JSON encoding as an array of
//! integers — so `req.body` IS the correct MAC input. A verifier that parsed
//! first and re-encoded would change key order and whitespace, and every
//! signature would fail for reasons that look like a key mismatch.
//!
//! That property is easy to state and easy to lose, so this module makes it
//! structural rather than documentary: [`verified_event`] takes the raw bytes,
//! verifies them, and only then parses them, and there is no entry point that
//! accepts an already-parsed [`Event`]. A caller cannot reach the parse
//! without having passed the bytes through the MAC first.
//!
//! # The kernels
//!
//! `hmac_sha256`, `hex_decode` and `constant_time_eq` come from
//! `ferrite_app::crypto` — the platform SDK kernel, which is the contract's acceptance
//! criterion 5. The kit carries no MAC of its own. The compare is
//! constant-time because a signature check written with `==` leaks its own
//! answer one byte at a time.
//!
//! # Refusal codes
//!
//! Every failure is a stable `&'static str` a host can serve as a
//! machine-readable error code: `signature_missing`, `signature_malformed`,
//! `signature_future`, `signature_stale`, `signature_invalid`,
//! `event_invalid`. They are strings rather than an enum because they cross
//! into an application's own error vocabulary unchanged.

use std::collections::BTreeMap;

use crate::crypto::{constant_time_eq, hex_decode, hmac_sha256};
use ferrite_app::{serde, serde_json};

/// The forwarded caller header the signature arrives on, lowercase — the
/// normalization the gateway applies to every allowlisted header name.
///
/// A route must declare it: `"forward_headers": ["stripe-signature"]`. A route
/// that does not observes an EMPTY header list on every envelope, and
/// [`verify`] then answers `signature_missing`, which is the contract's rule 7.
pub const SIGNATURE_HEADER: &str = "stripe-signature";

/// The replay window, in seconds, on either side of the host's clock. Five
/// minutes: the tolerance the platform's own billing front applies.
pub const SIGNATURE_TOLERANCE_SECS: u64 = 300;

/// Find the signature header in an ingress envelope's forwarded header list.
///
/// The comparison is ASCII case-insensitive even though the gateway
/// lowercases what it forwards, because a host may hand this function headers
/// from a source that does not.
#[must_use]
pub fn signature_header(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(SIGNATURE_HEADER))
        .map(|(_, value)| value.as_str())
}

/// Verify a presented `Stripe-Signature` value against the raw request bytes.
///
/// `raw_body` must be the bytes as received. `now_ms` is the host's clock
/// (`ctx.now_ms()`).
///
/// Every `v1=` candidate in the header is considered, because Stripe presents
/// several during a webhook-secret rotation and accepting only the first would
/// make a rotation an outage. A malformed candidate is a refusal for the whole
/// header rather than a skipped entry: a header this verifier does not fully
/// understand is not a header it should partially trust.
///
/// # Errors
///
/// `signature_malformed` when the header is not `t=…` plus at least one
/// `v1=<hex>`; `signature_future` and `signature_stale` outside
/// [`SIGNATURE_TOLERANCE_SECS`]; `signature_invalid` when no candidate matches.
pub fn verify_signature(
    secret: &str,
    header_value: &str,
    raw_body: &[u8],
    now_ms: u64,
) -> Result<(), &'static str> {
    if secret.trim().is_empty() {
        return Err("signature_invalid");
    }
    let mut timestamp: Option<u64> = None;
    let mut saw_t = false;
    let mut candidates = Vec::new();
    for part in header_value.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            return Err("signature_malformed");
        };
        match key {
            "t" => {
                // A second `t` would let a presenter pick which timestamp the
                // MAC covers and which one the window checks. The slot is
                // marked as SEEN before the value is parsed, so an unparseable
                // first `t` cannot leave room for a second one.
                if saw_t {
                    return Err("signature_malformed");
                }
                saw_t = true;
                // An unparseable `t` (not digits, or past u64) is a refusal
                // now rather than an empty slot resolved at the end.
                timestamp = Some(value.parse::<u64>().map_err(|_| "signature_malformed")?);
            }
            "v1" => candidates.push(hex_decode(value).ok_or("signature_malformed")?),
            // Forward-compatible: an unknown scheme (`v0` on the connect
            // events, anything Stripe adds later) is ignored, not refused.
            _ => {}
        }
    }
    let t = timestamp.ok_or("signature_malformed")?;
    if candidates.is_empty() {
        return Err("signature_malformed");
    }
    let now = now_ms / 1000;
    if t > now.saturating_add(SIGNATURE_TOLERANCE_SECS) {
        return Err("signature_future");
    }
    if now.saturating_sub(t) > SIGNATURE_TOLERANCE_SECS {
        return Err("signature_stale");
    }
    let mut signed = t.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(raw_body);
    let expected = hmac_sha256(secret.as_bytes(), &signed);
    if !candidates
        .iter()
        .any(|candidate| constant_time_eq(&expected, candidate))
    {
        return Err("signature_invalid");
    }
    Ok(())
}

/// Verify an ingress envelope's forwarded headers against its raw body.
///
/// An envelope with no signature header refuses with `signature_missing`, and
/// that is the ONLY outcome available for it. This is the contract's rule 7 in code: a
/// route whose manifest omits `stripe-signature` observes an empty header list
/// on every request, so a handler that treated absence as a soft path would be
/// an open "mark the order paid" endpoint for anyone who can POST to the route.
///
/// # Errors
///
/// `signature_missing`, plus everything [`verify_signature`] returns.
pub fn verify(
    secret: &str,
    headers: &[(String, String)],
    raw_body: &[u8],
    now_ms: u64,
) -> Result<(), &'static str> {
    let presented = signature_header(headers).ok_or("signature_missing")?;
    verify_signature(secret, presented, raw_body, now_ms)
}

/// A processor event, as much of it as a payments fold reads.
///
/// Unknown fields are ignored rather than refused, because a processor adds
/// them without notice and an event this application does not act on must
/// still be admitted and marked, not rejected into a redelivery loop.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(crate = "ferrite_app::serde")]
pub struct Event {
    /// The processor's event id (`evt_…`) — the idempotency key the
    /// admission ledger is keyed on.
    pub id: String,
    /// The event type (`checkout.session.completed`).
    #[serde(rename = "type")]
    pub kind: String,
    /// When the processor created the event (Unix seconds). A fold that is not
    /// idempotent compares this with now to refuse a resend older than the
    /// admission ledger's retention (see `ledger.rs`).
    #[serde(default)]
    pub created: Option<u64>,
    /// The event payload wrapper.
    pub data: EventData,
}

/// `null` reads as the default, as a missing member does.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: ferrite_app::serde::Deserializer<'de>,
    T: Default + ferrite_app::serde::Deserialize<'de>,
{
    use ferrite_app::serde::Deserialize;
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A reference that is either an id or the expanded object carrying it.
fn id_or_expanded<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: ferrite_app::serde::Deserializer<'de>,
{
    use ferrite_app::serde::Deserialize;
    Ok(match Option::<serde_json::Value>::deserialize(deserializer)? {
        Some(serde_json::Value::String(id)) => Some(id),
        Some(serde_json::Value::Object(object)) => object.get("id").and_then(serde_json::Value::as_str).map(str::to_string),
        _ => None,
    })
}

/// The `data` wrapper of an event.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(crate = "ferrite_app::serde")]
pub struct EventData {
    /// The object the event is about.
    pub object: EventObject,
}

/// The subset of a Checkout Session (or PaymentIntent) a fold needs.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(crate = "ferrite_app::serde")]
pub struct EventObject {
    /// The object id — the session id an application matches against its own
    /// stored `cs_…`, which is what stops one customer's event settling
    /// another customer's order. Empty for an object that has none (a
    /// `balance.available` payload), so the event is still admitted and marked.
    #[serde(default)]
    pub id: String,
    /// `paid` on a completed session.
    #[serde(default)]
    pub payment_status: Option<String>,
    /// The PaymentIntent a later refund is issued against (an id, or the
    /// expanded object's id).
    #[serde(default, deserialize_with = "id_or_expanded")]
    pub payment_intent: Option<String>,
    /// The metadata the create call attached, echoed back (`null` reads as none).
    #[serde(default, deserialize_with = "null_as_default")]
    pub metadata: BTreeMap<String, String>,
    /// Total charged, in the processor's minor units. Absent on event shapes
    /// that do not carry a total; see [`super::money::AmountCheck`].
    #[serde(default)]
    pub amount_total: Option<u64>,
    /// The charged currency, lowercase.
    #[serde(default)]
    pub currency: Option<String>,
}

/// Verify an envelope and return the event it carries.
///
/// The ordering is the point: MAC the raw bytes, then parse the same bytes.
/// The kit exposes no verifier that takes an [`Event`], so a caller cannot
/// accidentally authenticate a re-serialization of one.
///
/// # Errors
///
/// Everything [`verify`] returns, plus `event_invalid`.
pub fn verified_event(
    secret: &str,
    headers: &[(String, String)],
    raw_body: &[u8],
    now_ms: u64,
) -> Result<Event, &'static str> {
    verify(secret, headers, raw_body, now_ms)?;
    serde_json::from_slice(raw_body).map_err(|_| "event_invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex_encode;

    const SECRET: &str = "whsec_test";

    fn sign(body: &[u8], t: u64) -> String {
        let mut signed = format!("{t}.").into_bytes();
        signed.extend_from_slice(body);
        hex_encode(&hmac_sha256(SECRET.as_bytes(), &signed))
    }

    fn headers(value: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.into(), value.into())]
    }

    #[test]
    fn any_presented_v1_candidate_may_match_so_a_secret_rotation_is_not_an_outage() {
        let body = br#"{"id":"evt_1"}"#;
        let header = format!("t=1000,v1=00,v1={}", sign(body, 1_000));
        assert_eq!(verify_signature(SECRET, &header, body, 1_100_000), Ok(()));
    }

    #[test]
    fn a_wrong_secret_or_a_tampered_body_refuses() {
        let body = br#"{"id":"evt_1"}"#;
        let header = format!("t=1000,v1={}", sign(body, 1_000));
        assert_eq!(
            verify_signature("wrong", &header, body, 1_100_000),
            Err("signature_invalid")
        );
        assert_eq!(
            verify_signature(SECRET, &header, b"tampered", 1_100_000),
            Err("signature_invalid")
        );
    }

    #[test]
    fn the_mac_covers_the_bytes_as_received_not_a_re_serialization() {
        // Two byte strings that parse to the SAME JSON value: reordered keys
        // and different whitespace. Only the bytes that were signed verify.
        let signed_bytes = br#"{"id":"evt_1","type":"checkout.session.completed","data":{"object":{"id":"cs_1"}}}"#;
        let equivalent = br#"{ "type":"checkout.session.completed", "data":{"object":{"id":"cs_1"}}, "id":"evt_1" }"#;
        let header = format!("t=1000,v1={}", sign(signed_bytes, 1_000));
        assert_eq!(
            verify_signature(SECRET, &header, signed_bytes, 1_100_000),
            Ok(())
        );
        assert_eq!(
            verify_signature(SECRET, &header, equivalent, 1_100_000),
            Err("signature_invalid"),
            "a verifier that re-serialized a parsed value would accept this"
        );
    }

    #[test]
    fn the_replay_window_bounds_both_directions() {
        let body = br#"{"id":"evt_1"}"#;
        let header = format!("t=1000,v1={}", sign(body, 1_000));
        assert_eq!(verify_signature(SECRET, &header, body, 1_300_000), Ok(()));
        assert_eq!(
            verify_signature(SECRET, &header, body, 1_301_000),
            Err("signature_stale")
        );
        assert_eq!(verify_signature(SECRET, &header, body, 700_000), Ok(()));
        assert_eq!(
            verify_signature(SECRET, &header, body, 699_000),
            Err("signature_future")
        );
    }

    #[test]
    fn a_header_this_verifier_cannot_fully_read_is_refused_whole() {
        let body = br#"{"id":"evt_1"}"#;
        let good = sign(body, 1_000);
        for header in [
            "".to_string(),
            "t=1000".to_string(),
            format!("v1={good}"),
            format!("t=1000,t=1001,v1={good}"),
            format!("t=1000,v1=zz,v1={good}"),
            format!("t=notanumber,v1={good}"),
            format!("t=1000;v1={good}"),
        ] {
            assert_eq!(
                verify_signature(SECRET, &header, body, 1_100_000),
                Err("signature_malformed"),
                "header {header:?} must refuse"
            );
        }
    }

    /// F488: the one-`t` rule held only while the first `t` parsed. An
    /// unparseable or u64-overflowing first `t` left the slot empty, so a
    /// second `t` carrying a valid MAC was accepted.
    #[test]
    fn an_unparseable_first_t_does_not_make_room_for_a_second_one() {
        let body = br#"{"id":"evt_1"}"#;
        let good = sign(body, 1_000);
        for header in [
            format!("t=notanumber,t=1000,v1={good}"),
            format!("t=99999999999999999999999,t=1000,v1={good}"),
            format!("t=,t=1000,v1={good}"),
            format!("t=1000,t=notanumber,v1={good}"),
        ] {
            assert_eq!(
                verify_signature(SECRET, &header, body, 1_100_000),
                Err("signature_malformed"),
                "header {header:?} must refuse"
            );
        }
        // The single, valid `t` still verifies.
        assert_eq!(
            verify_signature(SECRET, &format!("t=1000,v1={good}"), body, 1_100_000),
            Ok(())
        );
    }

    #[test]
    fn an_unknown_scheme_is_ignored_rather_than_refused() {
        let body = br#"{"id":"evt_1"}"#;
        let header = format!("t=1000,v0=deadbeef,v1={}", sign(body, 1_000));
        assert_eq!(verify_signature(SECRET, &header, body, 1_100_000), Ok(()));
    }

    #[test]
    fn an_absent_signature_is_the_same_refusal_a_forgery_gets() {
        // The empty header list is exactly what a route that forgot to declare
        // `forward_headers: ["stripe-signature"]` observes.
        let body = br#"{"id":"evt_1"}"#;
        assert_eq!(verify(SECRET, &[], body, 1_100_000), Err("signature_missing"));
        assert_eq!(
            verify(
                SECRET,
                &[("x-order-token".into(), "anything".into())],
                body,
                1_100_000
            ),
            Err("signature_missing")
        );
        assert!(verified_event(SECRET, &[], body, 1_100_000).is_err());
    }

    #[test]
    fn a_forwarded_header_name_matches_case_insensitively() {
        let body = br#"{"id":"evt_1","type":"x","data":{"object":{"id":"cs_1"}}}"#;
        let value = format!("t=1000,v1={}", sign(body, 1_000));
        assert_eq!(
            verify(
                SECRET,
                &[("Stripe-Signature".into(), value)],
                body,
                1_100_000
            ),
            Ok(())
        );
    }

    #[test]
    fn a_verified_event_parses_the_fields_a_fold_reads() {
        let body = br#"{
            "id":"evt_9","type":"checkout.session.completed",
            "data":{"object":{
                "id":"cs_9","payment_status":"paid","payment_intent":"pi_9",
                "amount_total":11990,"currency":"gbp",
                "metadata":{"order_id":"ORD-9"}
            }}
        }"#;
        let value = format!("t=1000,v1={}", sign(body, 1_000));
        let event = verified_event(SECRET, &headers(&value), body, 1_100_000).expect("verified");
        assert_eq!(event.id, "evt_9");
        assert_eq!(event.kind, "checkout.session.completed");
        assert_eq!(event.data.object.id, "cs_9");
        assert_eq!(event.data.object.payment_status.as_deref(), Some("paid"));
        assert_eq!(event.data.object.payment_intent.as_deref(), Some("pi_9"));
        assert_eq!(event.data.object.amount_total, Some(11_990));
        assert_eq!(event.data.object.currency.as_deref(), Some("gbp"));
        assert_eq!(
            event.data.object.metadata.get("order_id").map(String::as_str),
            Some("ORD-9")
        );
    }

    #[test]
    fn a_verified_body_that_is_not_an_event_refuses_after_the_mac() {
        let body = br#"{"not":"an event"}"#;
        let value = format!("t=1000,v1={}", sign(body, 1_000));
        assert_eq!(
            verified_event(SECRET, &headers(&value), body, 1_100_000)
                .err()
                .expect("refusal"),
            "event_invalid"
        );
    }

    #[test]
    fn an_event_with_no_totals_still_parses_so_absence_reaches_the_amount_check() {
        let body = br#"{"id":"e","type":"t","data":{"object":{"id":"cs_1"}}}"#;
        let value = format!("t=1000,v1={}", sign(body, 1_000));
        let event = verified_event(SECRET, &headers(&value), body, 1_100_000).expect("verified");
        assert_eq!(event.data.object.amount_total, None);
        assert_eq!(event.data.object.currency, None);
        assert!(event.data.object.metadata.is_empty());
    }

    #[test]
    fn ignored_event_shapes_still_parse_and_carry_their_creation_time() {
        // finding_99b8fd127638d17c: no object id, null metadata, an expanded payment_intent.
        let body = br#"{"id":"e","type":"balance.available","created":1700000000,"data":{"object":{"metadata":null,"payment_intent":{"id":"pi_1"}}}}"#;
        let value = format!("t=1000,v1={}", sign(body, 1_000));
        let event = verified_event(SECRET, &headers(&value), body, 1_100_000).expect("verified");
        assert_eq!(event.created, Some(1_700_000_000));
        assert_eq!(event.data.object.id, "");
        assert!(event.data.object.metadata.is_empty());
        assert_eq!(event.data.object.payment_intent.as_deref(), Some("pi_1"));
    }

    #[test]
    fn empty_or_whitespace_secrets_refuse_even_for_a_matching_mac() {
        let body = br#"{"id":"evt_empty","type":"checkout.session.completed","data":{"object":{"id":"cs_1"}}}"#;
        for blank in ["", " ", "   ", "\t\r\n"] {
            let mut signed = b"1000.".to_vec();
            signed.extend_from_slice(body);
            let forged_v1 = hex_encode(&hmac_sha256(blank.as_bytes(), &signed));
            let header = format!("t=1000,v1={forged_v1}");
            assert!(
                verify_signature(blank, &header, body, 1_100_000).is_err(),
                "blank secret {blank:?} must fail closed"
            );
            assert!(
                verified_event(blank, &headers(&header), body, 1_100_000).is_err(),
                "verified_event with blank secret {blank:?} must fail closed"
            );
        }
    }
}
