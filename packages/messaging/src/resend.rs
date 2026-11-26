//! The Resend transactional-email adapter: a pure request builder and the
//! one field a caller needs back out of an accepted send.
//!
//! # Idempotency is the caller's key, not a generated one
//!
//! [`send_request`] takes the idempotency key rather than deriving one,
//! because the key has to be STABLE across the retries the caller schedules,
//! and only the caller knows what the send is about. the demo shop
//! derives `order-confirmation-{order id}` and stores it on the order's email
//! ledger before the first attempt, so a second attempt presents the same key
//! and Resend collapses the two into one message. A key generated here — from
//! a clock, a counter, or the message contents — would differ per attempt and
//! turn provider-side deduplication off precisely when it is needed.
//!
//! # The credential is a header
//!
//! The API key rides `authorization: Bearer …`. The egress audit record keeps
//! destinations durably and header values out, so a key in a query string
//! would be a durable credential leak while a key in a header is not.

use ferrite_app::serde_json::{self, Value};

use super::ProviderRequest;

/// The Resend send endpoint. A consuming app's manifest pins its egress
/// destination to the `https://api.resend.com/` prefix.
pub const SEND_URL: &str = "https://api.resend.com/emails";

/// One transactional email, in the only shape this adapter sends: a single
/// recipient, a subject and a plain-text body.
///
/// HTML, attachments, tags and multi-recipient sends are all Resend features
/// and none has a consumer here, so none is built here. Adding one
/// is a field and a test; guessing at one is a surface nothing exercises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email<'a> {
    /// The `From` header value, for example `Ferrite <orders@example.com>`.
    pub from: &'a str,
    /// The single recipient address.
    pub to: &'a str,
    /// The subject line.
    pub subject: &'a str,
    /// The plain-text body.
    pub text: &'a str,
}

/// Build the Resend send request.
///
/// `api_key` is the value read from `ctx.secret(...)`. `idempotency_key`
/// identifies the MESSAGE, so every retry of one message presents the same
/// value. `user_agent` names the sending application, which is what a provider
/// support thread starts from.
#[must_use]
pub fn send_request(
    email: &Email<'_>,
    api_key: &str,
    idempotency_key: &str,
    user_agent: &str,
) -> ProviderRequest {
    let body = serde_json::json!({
        "from": email.from,
        "to": [email.to],
        "subject": email.subject,
        "text": email.text,
    })
    .to_string()
    .into_bytes();
    ProviderRequest {
        destination: SEND_URL.to_string(),
        body,
        headers: vec![
            ("authorization".to_string(), format!("Bearer {api_key}")),
            ("content-type".to_string(), "application/json".to_string()),
            ("user-agent".to_string(), user_agent.to_string()),
            ("idempotency-key".to_string(), idempotency_key.to_string()),
        ],
    }
}

/// The provider message id out of an accepted response body, or `None` when
/// the body is not the shape Resend documents.
///
/// A `2xx` whose body does not carry an id is NOT a success a ledger can
/// record: without the id there is nothing to quote in a support thread and
/// nothing to reconcile against. A caller treats `None` as an unresolved
/// attempt rather than as a send.
#[must_use]
pub fn accepted_id(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    match value.get("id") {
        Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    // A consumer crate may deny these lints for its own source; the kit's
    // tests travel into it, and an assertion is where an unwrap is the clearest
    // statement of intent.
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{accepted_id, send_request, Email, SEND_URL};
    use ferrite_app::serde_json::{self, Value};

    fn email() -> Email<'static> {
        Email {
            from: "Ferrite <orders@example.com>",
            to: "ada@example.com",
            subject: "Ferrite Supply order FS-1 confirmed",
            text: "Payment received for order FS-1.",
        }
    }

    #[test]
    fn the_request_is_exact_and_carries_the_callers_idempotency_key() {
        let request = send_request(&email(), "api-key", "order-confirmation-FS-1", "shop/0.1");
        assert_eq!(request.destination, SEND_URL);
        assert_eq!(request.header("authorization"), Some("Bearer api-key"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("user-agent"), Some("shop/0.1"));
        assert_eq!(
            request.header("idempotency-key"),
            Some("order-confirmation-FS-1")
        );

        let sent = serde_json::from_slice::<Value>(&request.body).expect("a JSON body");
        assert_eq!(sent["from"], "Ferrite <orders@example.com>");
        assert_eq!(sent["to"], serde_json::json!(["ada@example.com"]));
        assert_eq!(sent["subject"], "Ferrite Supply order FS-1 confirmed");
        assert_eq!(sent["text"], "Payment received for order FS-1.");
    }

    #[test]
    fn an_accepted_body_yields_its_id_and_anything_else_yields_none() {
        assert_eq!(
            accepted_id(br#"{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}"#),
            Some("49a3999c-0ce1-4ea6-ab68-afcd6dc2e794".to_string())
        );
        assert_eq!(accepted_id(br#"{"id":""}"#), None);
        assert_eq!(accepted_id(br#"{"id":42}"#), None);
        assert_eq!(accepted_id(br#"{"message":"queued"}"#), None);
        assert_eq!(accepted_id(b"not json at all"), None);
        assert_eq!(accepted_id(b""), None);
    }
}
