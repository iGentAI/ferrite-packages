//! Stripe request builders over the header-carrying egress call.
//!
//! Every function here is pure: it returns a [`HttpRequest`] and sends
//! nothing. The host delivers it through the egress handle its own manifest
//! declares, which is what keeps the destination scope-pinned and the attempt
//! audited. The recorded reference shape is the platform's own
//! `stripe_post` (`ferrite-billing/src/bin/ferrite-billing-front.rs`), with
//! one difference this kit exists to get right: the platform's client writes
//! its headers over direct rustls and carries no audit-plane record, whereas
//! an application taking the same shape through `ctx.egress` gets one.
//!
//! # What is built, and what deliberately is not
//!
//! Hosted Checkout sessions, a session re-read, and a refund. That is the
//! whole surface, and it is bounded by the contract's rule 5: the only checkout shape
//! this kit can build is the hosted one, so the PAN never transits the
//! application and the stored state is opaque identifiers (`cs_…`, `pi_…`).
//! There is no PaymentIntent-with-card builder and there will not be one.
//!
//! # Credentials
//!
//! The secret arrives as a `&str` the caller read from `ctx.secret(...)`. It
//! is written into an `authorization` header, never into a URL: the egress
//! audit record keeps destinations durably and header values out, so a
//! credential in a path would be a durable credential leak. Every builder that
//! interpolates an identifier into a path validates that identifier first, so
//! a hostile session id cannot walk out of the API prefix the manifest pinned.

use super::HttpRequest;

/// The Stripe REST base every builder targets. A consuming app's manifest
/// pins its egress destination to the `https://api.stripe.com/` prefix.
pub const API_BASE: &str = "https://api.stripe.com/v1";

/// The content type Stripe's REST API takes.
pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Percent-encode one `application/x-www-form-urlencoded` component.
///
/// The unreserved set is RFC 3986's; everything else is percent-encoded, and a
/// space becomes `+` as the form encoding requires. Encoding is applied to
/// KEYS as well as values, because Stripe's nested keys carry brackets.
#[must_use]
pub fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Join encoded key/value pairs into a form body, preserving caller order.
#[must_use]
pub fn form_body(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The bearer header pair for `secret`, lowercase-named.
#[must_use]
pub fn bearer(secret: &str) -> (String, String) {
    ("authorization".into(), format!("Bearer {secret}"))
}

/// Is this the shape of a Stripe object id with `prefix`?
///
/// Stripe ids are `prefix_` followed by an opaque alphanumeric tail. The check
/// is what makes path interpolation safe: no `/`, no `.`, no `%`, so a value
/// taken from a request body cannot traverse out of [`API_BASE`].
#[must_use]
pub fn is_object_id(id: &str, prefix: &str) -> bool {
    id.len() > prefix.len()
        && id.starts_with(prefix)
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Is this a Checkout Session id (`cs_…`)?
#[must_use]
pub fn is_session_id(id: &str) -> bool {
    is_object_id(id, "cs_")
}

/// Is this a PaymentIntent id (`pi_…`)?
#[must_use]
pub fn is_payment_intent_id(id: &str) -> bool {
    is_object_id(id, "pi_")
}

/// One priced line on a Checkout Session, in the processor's minor units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineItem {
    /// The product name the customer sees on the hosted page.
    pub name: String,
    /// Unit price in minor units (pence, cents).
    pub unit_amount_minor: u32,
    /// How many of this line.
    pub quantity: u32,
}

/// A hosted Checkout Session to create.
///
/// `metadata` is emitted in caller order, so an application that keys its
/// webhook fold on `metadata[order_id]` controls exactly what it will read
/// back. `idempotency_key` must be derived from the application's OWN key for
/// the operation (an order id, not a random value) — that is what makes a
/// retried create return the first session instead of opening a second one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSession {
    /// ISO 4217 code, lowercase on the wire (`gbp`).
    pub currency: String,
    /// Where the hosted page returns a paying customer.
    pub success_url: String,
    /// Where it returns one who abandoned.
    pub cancel_url: String,
    /// The application's own reference for this purchase.
    pub client_reference_id: String,
    /// The customer's email, prefilled on the hosted page.
    pub customer_email: String,
    /// Metadata pairs, echoed back on every event for this session.
    pub metadata: Vec<(String, String)>,
    /// The priced lines. Their minor units must sum to the total the
    /// application already committed; see [`allocate_discount`].
    pub line_items: Vec<LineItem>,
    /// The `Idempotency-Key` header value.
    pub idempotency_key: String,
}

/// `POST /v1/checkout/sessions` for a hosted card payment.
///
/// The field order is fixed rather than incidental: a stable body makes the
/// request reproducible across builds, which is what lets a consumer assert on
/// it and lets an operator compare two attempts.
#[must_use]
pub fn create_checkout_session(session: &CheckoutSession, secret: &str) -> HttpRequest {
    let mut fields: Vec<(String, String)> = vec![
        ("mode".into(), "payment".into()),
        ("payment_method_types[0]".into(), "card".into()),
        ("success_url".into(), session.success_url.clone()),
        ("cancel_url".into(), session.cancel_url.clone()),
        (
            "client_reference_id".into(),
            session.client_reference_id.clone(),
        ),
        ("customer_email".into(), session.customer_email.clone()),
    ];
    for (name, value) in &session.metadata {
        fields.push((format!("metadata[{name}]"), value.clone()));
    }
    for (index, item) in session.line_items.iter().enumerate() {
        fields.push((
            format!("line_items[{index}][price_data][currency]"),
            session.currency.clone(),
        ));
        fields.push((
            format!("line_items[{index}][price_data][unit_amount]"),
            item.unit_amount_minor.to_string(),
        ));
        fields.push((
            format!("line_items[{index}][price_data][product_data][name]"),
            item.name.clone(),
        ));
        fields.push((
            format!("line_items[{index}][quantity]"),
            item.quantity.to_string(),
        ));
    }
    HttpRequest {
        destination: format!("{API_BASE}/checkout/sessions"),
        body: form_body(&fields),
        headers: vec![
            bearer(secret),
            ("content-type".into(), FORM_CONTENT_TYPE.into()),
            ("idempotency-key".into(), session.idempotency_key.clone()),
        ],
    }
}

/// `GET /v1/checkout/sessions/{id}` — the authoritative re-read.
///
/// `None` when `session_id` is not a Stripe session id, which is the refusal
/// that keeps a caller-supplied string out of the URL path. This is the call
/// the contract's rule 3 names for "on doubt, re-read the payment object first"; it is
/// also the reconciliation path for a webhook that never arrived.
#[must_use]
pub fn retrieve_checkout_session(session_id: &str, secret: &str) -> Option<HttpRequest> {
    if !is_session_id(session_id) {
        return None;
    }
    Some(HttpRequest {
        destination: format!("{API_BASE}/checkout/sessions/{session_id}"),
        body: String::new(),
        headers: vec![bearer(secret)],
    })
}

/// `POST /v1/refunds` against a PaymentIntent.
///
/// `None` when `payment_intent` is not a PaymentIntent id. The refund is keyed
/// by the caller's own idempotency key, so a retried refund does not pay the
/// customer twice — the single most expensive mistake this builder can be
/// asked to make.
#[must_use]
pub fn create_refund(
    payment_intent: &str,
    metadata: &[(String, String)],
    idempotency_key: &str,
    secret: &str,
) -> Option<HttpRequest> {
    if !is_payment_intent_id(payment_intent) {
        return None;
    }
    let mut fields = vec![("payment_intent".to_string(), payment_intent.to_string())];
    for (name, value) in metadata {
        fields.push((format!("metadata[{name}]"), value.clone()));
    }
    Some(HttpRequest {
        destination: format!("{API_BASE}/refunds"),
        body: form_body(&fields),
        headers: vec![
            bearer(secret),
            ("content-type".into(), FORM_CONTENT_TYPE.into()),
            ("idempotency-key".into(), idempotency_key.into()),
        ],
    })
}

/// Split a whole-order discount across unit-priced lines without penny drift.
///
/// Returns one discount per entry of `unit_prices`, in the same order, summing
/// to exactly `min(discount, sum(unit_prices))`. Each unit takes its share of
/// the discount that REMAINS against the subtotal that remains, so the
/// rounding loss of every earlier unit is carried into the later ones and the
/// last unit absorbs the remainder exactly.
///
/// This matters because a processor re-adds the line amounts and compares them
/// with nothing: whatever the lines sum to is what the customer pays. Applying
/// a rounded proportional discount to each line independently drifts from the
/// total the application committed, by a penny per line in the worst case, and
/// the drift is invisible until a customer is charged the wrong amount.
///
/// Intermediates are 64-bit: the naive `discount * price` overflows a 32-bit
/// multiply well inside the range of real basket values.
#[must_use]
pub fn allocate_discount(unit_prices: &[u32], discount: u32) -> Vec<u32> {
    let subtotal: u64 = unit_prices.iter().map(|p| u64::from(*p)).sum();
    let mut remaining_subtotal = subtotal;
    let mut remaining_discount = u64::from(discount).min(subtotal);
    let mut out = Vec::with_capacity(unit_prices.len());
    for price in unit_prices {
        let price = u64::from(*price);
        // The final unit (and any unit that is the whole remaining subtotal)
        // takes everything left, which is what makes the sum exact.
        let share = if remaining_subtotal == price {
            remaining_discount
        } else if remaining_subtotal == 0 {
            0
        } else {
            remaining_discount * price / remaining_subtotal
        };
        remaining_discount -= share;
        remaining_subtotal -= price;
        out.push(u32::try_from(share).unwrap_or(u32::MAX));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> CheckoutSession {
        CheckoutSession {
            currency: "gbp".into(),
            success_url: "https://shop.example/return?checkout=success".into(),
            cancel_url: "https://shop.example/return?checkout=cancelled".into(),
            client_reference_id: "ORD-1".into(),
            customer_email: "ada@example.com".into(),
            metadata: vec![("order_id".into(), "ORD-1".into())],
            line_items: vec![LineItem {
                name: "Ferrite Mug".into(),
                unit_amount_minor: 1_200,
                quantity: 1,
            }],
            idempotency_key: "checkout-ORD-1".into(),
        }
    }

    #[test]
    fn a_checkout_session_carries_its_credential_in_a_header_and_never_in_the_url() {
        let r = create_checkout_session(&session(), "sk_test_secret");
        assert_eq!(r.destination, "https://api.stripe.com/v1/checkout/sessions");
        assert!(
            !r.destination.contains("sk_test_secret"),
            "the egress audit record keeps destinations durably; a key in the URL is a durable leak"
        );
        assert!(r
            .headers
            .contains(&("authorization".into(), "Bearer sk_test_secret".into())));
        assert!(r
            .headers
            .contains(&("idempotency-key".into(), "checkout-ORD-1".into())));
        assert!(r
            .headers
            .contains(&("content-type".into(), FORM_CONTENT_TYPE.into())));
        assert!(
            r.headers.iter().all(|(name, _)| *name == name.to_lowercase()),
            "the egress validator admits lowercase header names"
        );
    }

    #[test]
    fn the_checkout_body_encodes_nested_keys_and_customer_metadata() {
        let r = create_checkout_session(&session(), "sk_test_secret");
        assert!(r.body.contains("mode=payment"));
        assert!(r.body.contains("customer_email=ada%40example.com"));
        assert!(r.body.contains("metadata%5Border_id%5D=ORD-1"));
        assert!(r
            .body
            .contains("line_items%5B0%5D%5Bprice_data%5D%5Bcurrency%5D=gbp"));
        assert!(r
            .body
            .contains("line_items%5B0%5D%5Bprice_data%5D%5Bunit_amount%5D=1200"));
    }

    #[test]
    fn a_read_or_refund_refuses_an_identifier_it_cannot_place_in_a_path() {
        assert!(retrieve_checkout_session("cs_test_123", "sk").is_some());
        // Traversal, a wrong object class, and a bare prefix all refuse.
        assert!(retrieve_checkout_session("cs_../../account", "sk").is_none());
        assert!(retrieve_checkout_session("pi_test_123", "sk").is_none());
        assert!(retrieve_checkout_session("cs_", "sk").is_none());
        assert!(create_refund("pi_test_123", &[], "refund-ORD-1", "sk").is_some());
        assert!(create_refund("cs_test_123", &[], "refund-ORD-1", "sk").is_none());
        assert!(create_refund("pi_x/y", &[], "refund-ORD-1", "sk").is_none());
    }

    #[test]
    fn a_refund_is_keyed_so_a_retry_cannot_pay_the_customer_twice() {
        let r = create_refund(
            "pi_test_123",
            &[("order_id".into(), "ORD-1".into())],
            "refund-ORD-1",
            "sk",
        )
        .expect("valid id");
        assert_eq!(r.destination, "https://api.stripe.com/v1/refunds");
        assert_eq!(
            r.body,
            "payment_intent=pi_test_123&metadata%5Border_id%5D=ORD-1"
        );
        assert!(r
            .headers
            .contains(&("idempotency-key".into(), "refund-ORD-1".into())));
    }

    #[test]
    fn a_read_is_a_get_shaped_request_with_no_body() {
        let r = retrieve_checkout_session("cs_test_123", "sk").expect("valid id");
        assert_eq!(
            r.destination,
            "https://api.stripe.com/v1/checkout/sessions/cs_test_123"
        );
        assert!(r.body.is_empty());
        assert_eq!(r.headers, vec![bearer("sk")]);
    }

    #[test]
    fn a_discount_allocation_sums_to_the_discount_exactly() {
        // Three units at 4200 with a 10% discount: 1260 does not divide by
        // three, and the remainder must land somewhere rather than vanish.
        let units = [4_200u32, 4_200, 4_200];
        let shares = allocate_discount(&units, 1_260);
        assert_eq!(shares.iter().sum::<u32>(), 1_260);
        let charged: u32 = units
            .iter()
            .zip(&shares)
            .map(|(price, share)| price - share)
            .sum();
        assert_eq!(charged, 12_600 - 1_260);
    }

    #[test]
    fn a_discount_allocation_is_total_over_its_edges() {
        assert_eq!(allocate_discount(&[], 500), Vec::<u32>::new());
        // A discount larger than the basket is clamped to the basket.
        assert_eq!(allocate_discount(&[100, 100], 5_000), vec![100, 100]);
        // Zero-priced units take nothing, and the priced unit takes it all.
        assert_eq!(allocate_discount(&[0, 0, 500], 100), vec![0, 0, 100]);
        // All-zero prices cannot divide, and must not panic.
        assert_eq!(allocate_discount(&[0, 0], 100), vec![0, 0]);
        // A basket big enough to overflow a 32-bit `discount * price`.
        let big = [2_000_000_000u32, 2_000_000_000];
        assert_eq!(
            allocate_discount(&big, 1_000_000).iter().sum::<u32>(),
            1_000_000
        );
    }

    #[test]
    fn form_encoding_covers_the_component_charset() {
        assert_eq!(form_encode("a b"), "a+b");
        assert_eq!(form_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(form_encode("-_.~"), "-_.~");
        assert_eq!(form_encode("£"), "%C2%A3");
    }
}
