//! The Cloudflare Email Sending adapter: the per-account send URL and the flat
//! `{to, from, subject, html, text}` REST payload.
//!
//! The schema is the one documented at
//! `developers.cloudflare.com/email-service/api/send-emails/rest-api`. Both
//! parts are sent: the HTML part comes from [`super::email_html`], and the
//! plain-text part is the markdown source, so a client that refuses HTML still
//! receives the message rather than an empty body.
//!
//! The API token rides `authorization: Bearer …`, which keeps it out of the
//! egress audit record — the contrast with [`super::telegram`], where the
//! provider gives no such option, is deliberate and documented there.

use ferrite_app::serde_json;
use std::io;

use super::email_html::render_email_html;
use super::ProviderRequest;

/// The plain-text part's character ceiling. A brief is far shorter; the bound
/// exists so a runaway body cannot build an unbounded request.
pub const MAX_TEXT_CHARS: usize = 100_000;

/// The send endpoint for one Cloudflare account.
#[must_use]
pub fn send_url(account_id: &str) -> String {
    format!("https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send")
}

/// Build the send payload: one recipient, both body parts.
pub fn send_payload(
    from: &str,
    to: &str,
    subject: &str,
    body_md: &str,
    footer_note: &str,
) -> io::Result<Vec<u8>> {
    let html = render_email_html(subject, body_md, footer_note);
    let text: String = body_md.chars().take(MAX_TEXT_CHARS).collect();
    serde_json::to_vec(&serde_json::json!({
        "to": to,
        "from": from,
        "subject": subject,
        "html": html,
        "text": text,
    }))
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Build the whole send request: URL, JSON body, and the bearer credential in
/// a header.
pub fn send(
    account_id: &str,
    api_token: &str,
    from: &str,
    to: &str,
    subject: &str,
    body_md: &str,
    footer_note: &str,
) -> io::Result<ProviderRequest> {
    let body = send_payload(from, to, subject, body_md, footer_note)?;
    Ok(ProviderRequest::json(
        &send_url(account_id),
        body,
        &[("authorization".to_string(), format!("Bearer {api_token}"))],
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{send, send_payload};
    use ferrite_app::serde_json::{self, Value};

    #[test]
    fn the_payload_carries_both_parts() {
        let bytes = send_payload(
            "from@x.dev",
            "to@y.dev",
            "Subj",
            "# Daily\n\nBody text.",
            "note",
        )
        .expect("a payload");
        let value = serde_json::from_slice::<Value>(&bytes).expect("JSON");
        assert_eq!(value["from"], "from@x.dev");
        assert_eq!(value["to"], "to@y.dev");
        assert_eq!(value["subject"], "Subj");
        assert!(value["html"].as_str().expect("html").contains("<h1"));
        assert_eq!(value["text"], "# Daily\n\nBody text.");
    }

    #[test]
    fn the_credential_is_a_header_and_never_the_url() {
        let request = send(
            "acct-1",
            "cf-token",
            "from@x.dev",
            "to@y.dev",
            "Subj",
            "Body",
            "note",
        )
        .expect("a request");
        assert_eq!(
            request.destination,
            "https://api.cloudflare.com/client/v4/accounts/acct-1/email/sending/send"
        );
        assert_eq!(request.header("authorization"), Some("Bearer cf-token"));
        assert_eq!(request.header("content-type"), Some("application/json"));
    }
}
