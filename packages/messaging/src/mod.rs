//! messaging — transactional provider sends from inside the constrained app
//! model.
//!
//! A deployable Ferrite app names exactly one dependency, so this subsystem
//! travels as SOURCE. It carries the mainstream provider path two Ferrite
//! applications were otherwise re-deriving: the request builders for Resend,
//! Postmark, the Telegram Bot API and Cloudflare Email Sending, the safe markdown-to-HTML
//! email renderer, the retry classification a provider status maps to, and the
//! one seam that turns a built request into an egress call.
//!
//! # What this kit does not own
//!
//! It holds no state and runs no schedule. A send ledger, an outbox, a
//! suppression list and a retry queue are application state, because the
//! transitions they guard are the application's own — a shop
//! folds its outcome into an order row and a scheduled briefing drives a
//! claim/settle ledger over its APE. The kit supplies the request, the
//! classification and the call; the durable decisions stay with the consumer.
//!
//! It holds no secret either: provider credentials arrive as `&str` from the
//! caller's `ctx.secret(...)`. Every builder puts a credential in a header,
//! with one documented exception the Telegram Bot API forces
//! ([`telegram::send_message_url`]), because the egress audit record keeps
//! destinations durably and header values out.
//!
//! # The one place I/O happens
//!
//! [`send::deliver`] is the only function here that touches the network, and
//! it touches it through an [`ferrite_app::EgressHandle`] the CALLER opened
//! from its own manifest-declared handle. The kit opens no socket of its own,
//! so the destination stays scope-pinned by the consuming app's manifest and
//! the attempt stays in that app's egress audit plane.
//!
//! # Evidence class
//!
//! Every pure function here is proven by unit tests that travel with the
//! source and run inside every consumer. **No live provider send is recorded
//! in this repository** — not to Resend, not to Postmark, not to Telegram,
//! not to Cloudflare Email Sending. See this package's README for the per-module
//! evidence class, which is the honest reading of the messaging contract.

pub mod cloudflare_email;
pub mod email_html;
pub mod postmark;
pub mod resend;
pub mod retry;
pub mod send;
pub mod telegram;

/// One outbound provider request, built but not sent.
///
/// The name is the messaging contract's own: an adapter is a PURE request builder — no transport, no clock, no
/// `ctx` — and this is what it returns. The host delivers it, through
/// [`send::deliver`] or through its own `EgressHandle::deliver_http` call, so the
/// egress handle named in the application's manifest is what pins the
/// destination and records the attempt.
///
/// Header names are lowercase, because that is the form the egress validator
/// admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRequest {
    /// The absolute destination URL.
    pub destination: String,
    /// The request body, already encoded for the declared content type.
    pub body: Vec<u8>,
    /// Lowercase request header names and their values.
    pub headers: Vec<(String, String)>,
}

impl ProviderRequest {
    /// A JSON POST: `content-type: application/json` followed by the caller's
    /// own headers, in the order given.
    ///
    /// The content type leads so a caller cannot silently displace it, and the
    /// caller's headers follow because a per-channel `authorization` is the
    /// ordinary reason to supply any.
    #[must_use]
    pub fn json(destination: &str, body: Vec<u8>, extra_headers: &[(String, String)]) -> Self {
        let mut headers = Vec::with_capacity(extra_headers.len() + 1);
        headers.push(("content-type".to_string(), "application/json".to_string()));
        headers.extend_from_slice(extra_headers);
        Self {
            destination: destination.to_string(),
            body,
            headers,
        }
    }

    /// The value of one header, by lowercase name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderRequest;

    #[test]
    fn a_json_request_leads_with_its_content_type_and_keeps_caller_order() {
        let request = ProviderRequest::json(
            "https://api.example.test/send",
            b"{}".to_vec(),
            &[
                ("authorization".to_string(), "Bearer k".to_string()),
                ("x-trace".to_string(), "abc".to_string()),
            ],
        );
        assert_eq!(
            request.headers,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("authorization".to_string(), "Bearer k".to_string()),
                ("x-trace".to_string(), "abc".to_string()),
            ]
        );
        assert_eq!(request.header("authorization"), Some("Bearer k"));
        assert_eq!(request.header("idempotency-key"), None);
    }
}
