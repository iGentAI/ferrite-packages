//! The Postmark email adapter: pure request builders for `POST /email` and
//! `POST /email/batch`, the classification of Postmark's answers, and the
//! reading of a broadcast stream's type, suppression list and statistics.
//!
//! # Postmark has no idempotency key
//!
//! Unlike [`super::resend`], Postmark's send endpoint accepts no idempotency
//! header (its support article "What is an idempotency key?" says so). A
//! retried request that reached Postmark the first time is a second message.
//! The caller's outbox is therefore the only deduplication there is: it records
//! the intent before the first attempt, retries only a refusal Postmark
//! actually returned ([`super::retry::is_retryable_status`]), and never resends
//! after a transport failure or a crash between the call and its record.
//!
//! # The credential is a header
//!
//! The server token rides `x-postmark-server-token`, so the egress audit
//! record, which keeps destinations and drops header values, never holds it.

use ferrite_app::serde_json::{self, Value};

use super::ProviderRequest;

/// The send endpoint. A consumer's egress grant names the
/// `https://api.postmarkapp.com/` prefix.
pub const SEND_URL: &str = "https://api.postmarkapp.com/email";

/// Postmark's default transactional message stream.
pub const TRANSACTIONAL_STREAM: &str = "outbound";

/// Postmark's default broadcast message stream. Broadcast mail leaves from a
/// separate IP pool, so a newsletter's reputation never touches account mail.
pub const BROADCAST_STREAM: &str = "broadcast";

/// The batch endpoint: a JSON array of messages in, an array of answers out,
/// in the same order.
pub const BATCH_URL: &str = "https://api.postmarkapp.com/email/batch";

/// The most messages Postmark takes in one batch call.
pub const BATCH_MAX: usize = 500;

/// What a broadcast body writes where its unsubscribe link goes. Postmark
/// replaces it, per recipient, with that recipient's one-click unsubscribe
/// address, and adds the `List-Unsubscribe` headers itself.
pub const UNSUBSCRIBE_PLACEHOLDER: &str = "{{{ pm:unsubscribe }}}";

/// One transactional email to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email<'a> {
    /// The `From` header value, for example `Ferrite <hello@mail.ferrite.cloud>`.
    pub from: &'a str,
    /// The single recipient address.
    pub to: &'a str,
    /// Where a reply goes; the sending domain has no mailbox.
    pub reply_to: Option<&'a str>,
    /// The subject line.
    pub subject: &'a str,
    /// The plain-text part. Always sent, so a client that refuses HTML still
    /// receives the message.
    pub text: &'a str,
    /// The HTML part, when there is one.
    pub html: Option<&'a str>,
    /// A short category for Postmark's statistics, such as `welcome`.
    pub tag: Option<&'a str>,
    /// The message stream; [`TRANSACTIONAL_STREAM`] for everything this kit
    /// sends.
    pub stream: &'a str,
}

/// Build the Postmark send request. Open and link tracking are switched off
/// per message, whatever the server's defaults say: a transactional email
/// carries no tracking pixel and no rewritten link.
#[must_use]
pub fn send_request(email: &Email<'_>, server_token: &str, user_agent: &str) -> ProviderRequest {
    ProviderRequest {
        destination: SEND_URL.to_string(),
        body: message(email).to_string().into_bytes(),
        headers: headers(server_token, user_agent),
    }
}

/// One message as Postmark's JSON: the object `POST /email` takes, and one
/// element of the array `POST /email/batch` takes.
#[must_use]
pub fn message(email: &Email<'_>) -> Value {
    let mut body = serde_json::json!({
        "From": email.from,
        "To": email.to,
        "Subject": email.subject,
        "TextBody": email.text,
        "MessageStream": email.stream,
        "TrackOpens": false,
        "TrackLinks": "None",
    });
    if let Some(object) = body.as_object_mut() {
        if let Some(reply_to) = email.reply_to {
            object.insert("ReplyTo".to_string(), Value::from(reply_to));
        }
        if let Some(html) = email.html {
            object.insert("HtmlBody".to_string(), Value::from(html));
        }
        if let Some(tag) = email.tag {
            object.insert("Tag".to_string(), Value::from(tag));
        }
    }
    body
}

fn headers(server_token: &str, user_agent: &str) -> Vec<(String, String)> {
    vec![
        ("accept".to_string(), "application/json".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("x-postmark-server-token".to_string(), server_token.to_string()),
        ("user-agent".to_string(), user_agent.to_string()),
    ]
}

/// Build one batch call for up to [`BATCH_MAX`] messages, or `None` for an
/// empty or oversized slice: a caller that hands over too many has a bug, and
/// a truncated batch would silently drop recipients.
#[must_use]
pub fn batch_request(emails: &[Email<'_>], server_token: &str, user_agent: &str) -> Option<ProviderRequest> {
    if emails.is_empty() || emails.len() > BATCH_MAX {
        return None;
    }
    let body = Value::Array(emails.iter().map(message).collect());
    Some(ProviderRequest {
        destination: BATCH_URL.to_string(),
        body: body.to_string().into_bytes(),
        headers: headers(server_token, user_agent),
    })
}

/// Read a batch call's answer: one element per message, in request order, each
/// re-serialised so [`answer`] reads it exactly as it reads a single send.
/// `None` unless the body is an array of exactly `expected` objects whose `To`
/// (when Postmark names one) is the recipient at that position: an answer that
/// cannot be matched to its messages establishes nothing about any of them.
#[must_use]
pub fn batch_answers(body: &[u8], recipients: &[&str]) -> Option<Vec<Vec<u8>>> {
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else {
        return None;
    };
    if items.len() != recipients.len() {
        return None;
    }
    let mut out = Vec::with_capacity(items.len());
    for (item, recipient) in items.iter().zip(recipients) {
        if !item.is_object() {
            return None;
        }
        if let Some(to) = item.get("To").and_then(Value::as_str) {
            if !to.is_empty() && !to.eq_ignore_ascii_case(recipient) {
                return None;
            }
        }
        out.push(item.to_string().into_bytes());
    }
    Some(out)
}

/// `GET` this to read one message stream; [`stream_type`] reads the answer.
#[must_use]
pub fn stream_url(stream: &str) -> String {
    format!("https://api.postmarkapp.com/message-streams/{stream}")
}

/// The `MessageStreamType` of a stream record: `Broadcasts`, `Transactional`
/// or `Inbound`.
#[must_use]
pub fn stream_type(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("MessageStreamType")?
        .as_str()
        .map(str::to_string)
}

/// `GET` this for every address Postmark will not send to on a stream.
#[must_use]
pub fn suppressions_url(stream: &str) -> String {
    format!("https://api.postmarkapp.com/message-streams/{stream}/suppressions/dump")
}

/// `POST` [`suppressions_body`] here to lift suppressions: the way a person who
/// unsubscribed, then asked to hear from the sender again, is reactivated.
/// Postmark refuses to lift a spam complaint.
#[must_use]
pub fn suppressions_delete_url(stream: &str) -> String {
    format!("https://api.postmarkapp.com/message-streams/{stream}/suppressions/delete")
}

/// The body of a suppression create or delete call.
#[must_use]
pub fn suppressions_body(addresses: &[&str]) -> Vec<u8> {
    let list: Vec<Value> = addresses
        .iter()
        .map(|address| serde_json::json!({ "EmailAddress": address }))
        .collect();
    serde_json::json!({ "Suppressions": list }).to_string().into_bytes()
}

/// Why Postmark will not send to an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// The address does not exist or refuses mail.
    HardBounce,
    /// The recipient marked a message as spam. Never liftable.
    SpamComplaint,
    /// The recipient unsubscribed, or the sender suppressed the address.
    Manual,
}

/// One entry of a stream's suppression list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// The address, lower-cased.
    pub address: String,
    /// Why it is suppressed.
    pub reason: SuppressionReason,
}

/// Read a suppression dump. `None` for a body that is not one; an entry with a
/// reason this adapter does not know is kept as [`SuppressionReason::Manual`],
/// because the safe reading of an unknown suppression is "do not send".
#[must_use]
pub fn suppressions(body: &[u8]) -> Option<Vec<Suppression>> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let items = value.get("Suppressions")?.as_array()?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let address = item.get("EmailAddress")?.as_str()?.to_ascii_lowercase();
        let reason = match item.get("SuppressionReason").and_then(Value::as_str) {
            Some("HardBounce") => SuppressionReason::HardBounce,
            Some("SpamComplaint") => SuppressionReason::SpamComplaint,
            _ => SuppressionReason::Manual,
        };
        out.push(Suppression { address, reason });
    }
    Some(out)
}

/// Which addresses a suppression delete call lifted: Postmark answers each
/// with `Status` `Deleted` or `Failed`.
#[must_use]
pub fn suppressions_deleted(body: &[u8]) -> Option<Vec<(String, bool)>> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let items = value.get("Suppressions")?.as_array()?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let address = item.get("EmailAddress")?.as_str()?.to_ascii_lowercase();
        let deleted = item.get("Status").and_then(Value::as_str) == Some("Deleted");
        out.push((address, deleted));
    }
    Some(out)
}

/// `GET` this for the delivery counts of one tag on one stream.
#[must_use]
pub fn stats_url(stream: &str, tag: &str) -> String {
    format!("https://api.postmarkapp.com/stats/outbound?messagestream={stream}&tag={tag}")
}

/// What Postmark counted for a tag: accepted for delivery, bounced, and marked
/// as spam by a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboundStats {
    /// Messages Postmark sent.
    pub sent: u64,
    /// Messages that bounced.
    pub bounced: u64,
    /// Messages a recipient marked as spam.
    pub spam_complaints: u64,
}

/// Read an outbound statistics answer. A count Postmark leaves out is zero;
/// `None` only for a body that is not a statistics object at all.
#[must_use]
pub fn outbound_stats(body: &[u8]) -> Option<OutboundStats> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let object = value.as_object()?;
    if object.contains_key("ErrorCode") {
        return None;
    }
    let count = |name: &str| object.get(name).and_then(Value::as_u64).unwrap_or(0);
    Some(OutboundStats {
        sent: count("Sent"),
        bounced: count("Bounced"),
        spam_complaints: count("SpamComplaints"),
    })
}

/// What Postmark said about one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Accepted: Postmark's message id, the one to quote in a support thread.
    Accepted { message_id: String },
    /// Refused with Postmark's own error code and message. Repeating the same
    /// request gets the same refusal (an inactive recipient, a pending
    /// account, an unverified sender), so a caller records it and stops.
    Refused { error_code: i64, message: String },
    /// A body this adapter cannot read. A `2xx` that lands here is an
    /// unresolved attempt, not a send: there is no id to record.
    Unreadable,
}

/// Postmark's error code for a recipient on its suppression list (a hard
/// bounce, a spam complaint, or an unsubscribe).
pub const INACTIVE_RECIPIENT: i64 = 406;

/// Read Postmark's JSON answer. Postmark answers every request with
/// `{"ErrorCode": n, "Message": "...", "MessageID": "..."}`; `ErrorCode` zero
/// with a message id is the only acceptance.
#[must_use]
pub fn answer(body: &[u8]) -> Answer {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Answer::Unreadable;
    };
    let Some(error_code) = value.get("ErrorCode").and_then(Value::as_i64) else {
        return Answer::Unreadable;
    };
    let message = value
        .get("Message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if error_code != 0 {
        return Answer::Refused {
            error_code,
            message,
        };
    }
    match value.get("MessageID").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => Answer::Accepted {
            message_id: id.to_string(),
        },
        _ => Answer::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{
        answer, batch_answers, batch_request, outbound_stats, send_request, stream_type, suppressions,
        suppressions_body, suppressions_deleted, Answer, Email, OutboundStats, SuppressionReason, BATCH_MAX,
        BATCH_URL, BROADCAST_STREAM, SEND_URL, TRANSACTIONAL_STREAM,
    };
    use ferrite_app::serde_json::{self, Value};

    fn email() -> Email<'static> {
        Email {
            from: "Ferrite <hello@mail.ferrite.cloud>",
            to: "ada@example.com",
            reply_to: Some("support@example.com"),
            subject: "Welcome to Ferrite",
            text: "Your account is ready.",
            html: Some("<p>Your account is ready.</p>"),
            tag: Some("welcome"),
            stream: TRANSACTIONAL_STREAM,
        }
    }

    #[test]
    fn the_request_is_exact_and_the_token_is_a_header() {
        let request = send_request(&email(), "server-token", "ferrite-dashboard/1");
        assert_eq!(request.destination, SEND_URL);
        assert_eq!(request.header("x-postmark-server-token"), Some("server-token"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("user-agent"), Some("ferrite-dashboard/1"));
        assert!(!request.destination.contains("server-token"));

        let sent = serde_json::from_slice::<Value>(&request.body).expect("a JSON body");
        assert_eq!(sent["From"], "Ferrite <hello@mail.ferrite.cloud>");
        assert_eq!(sent["To"], "ada@example.com");
        assert_eq!(sent["ReplyTo"], "support@example.com");
        assert_eq!(sent["Subject"], "Welcome to Ferrite");
        assert_eq!(sent["TextBody"], "Your account is ready.");
        assert_eq!(sent["HtmlBody"], "<p>Your account is ready.</p>");
        assert_eq!(sent["Tag"], "welcome");
        assert_eq!(sent["MessageStream"], "outbound");
        assert_eq!(sent["TrackOpens"], false);
        assert_eq!(sent["TrackLinks"], "None");
    }

    #[test]
    fn optional_fields_are_omitted_rather_than_sent_empty() {
        let mut bare = email();
        bare.reply_to = None;
        bare.html = None;
        bare.tag = None;
        let sent = serde_json::from_slice::<Value>(&send_request(&bare, "t", "ua").body).unwrap();
        let object = sent.as_object().unwrap();
        assert!(!object.contains_key("ReplyTo"));
        assert!(!object.contains_key("HtmlBody"));
        assert!(!object.contains_key("Tag"));
    }

    #[test]
    fn only_error_code_zero_with_an_id_is_an_acceptance() {
        assert_eq!(
            answer(br#"{"To":"a@b.c","ErrorCode":0,"Message":"OK","MessageID":"b7bc2f4a-e38e-4336-af7d-e6c392c2f817"}"#),
            Answer::Accepted { message_id: "b7bc2f4a-e38e-4336-af7d-e6c392c2f817".to_string() }
        );
        assert_eq!(
            answer(br#"{"ErrorCode":412,"Message":"While your account is pending approval, all recipient addresses must share the same domain as the 'From' address."}"#),
            Answer::Refused {
                error_code: 412,
                message: "While your account is pending approval, all recipient addresses must share the same domain as the 'From' address.".to_string(),
            }
        );
        assert_eq!(
            answer(br#"{"ErrorCode":406,"Message":"You tried to send to recipient(s) that have been marked as inactive."}"#),
            Answer::Refused {
                error_code: super::INACTIVE_RECIPIENT,
                message: "You tried to send to recipient(s) that have been marked as inactive.".to_string(),
            }
        );
        assert_eq!(answer(br#"{"ErrorCode":0,"Message":"OK"}"#), Answer::Unreadable);
        assert_eq!(answer(br#"{"ErrorCode":0,"MessageID":""}"#), Answer::Unreadable);
        assert_eq!(answer(br#"{"Message":"no code"}"#), Answer::Unreadable);
        assert_eq!(answer(b"<html>bad gateway</html>"), Answer::Unreadable);
        assert_eq!(answer(b""), Answer::Unreadable);
    }

    #[test]
    fn a_batch_is_an_array_in_order_on_the_named_stream() {
        let mut first = email();
        first.stream = BROADCAST_STREAM;
        let mut second = first.clone();
        second.to = "bob@example.com";
        let request = batch_request(&[first, second], "server-token", "ua").expect("a batch");
        assert_eq!(request.destination, BATCH_URL);
        assert_eq!(request.header("x-postmark-server-token"), Some("server-token"));
        let sent = serde_json::from_slice::<Value>(&request.body).unwrap();
        let items = sent.as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["To"], "ada@example.com");
        assert_eq!(items[1]["To"], "bob@example.com");
        assert!(items.iter().all(|m| m["MessageStream"] == "broadcast" && m["TrackOpens"] == false));
    }

    #[test]
    fn an_empty_or_oversized_batch_is_refused_rather_than_truncated() {
        assert!(batch_request(&[], "t", "ua").is_none());
        let many = vec![email(); BATCH_MAX + 1];
        assert!(batch_request(&many, "t", "ua").is_none());
        assert!(batch_request(&many[..BATCH_MAX], "t", "ua").is_some());
    }

    #[test]
    fn batch_answers_are_matched_to_their_messages_or_not_at_all() {
        let body = br#"[{"ErrorCode":0,"Message":"OK","MessageID":"m-1","To":"Ada@example.com"},{"ErrorCode":406,"Message":"inactive","To":"bob@example.com"}]"#;
        let answers = batch_answers(body, &["ada@example.com", "bob@example.com"]).expect("matched");
        assert_eq!(answer(&answers[0]), Answer::Accepted { message_id: "m-1".to_string() });
        assert_eq!(answer(&answers[1]), Answer::Refused { error_code: 406, message: "inactive".to_string() });
        assert!(batch_answers(body, &["ada@example.com"]).is_none(), "a count mismatch matches nothing");
        assert!(batch_answers(body, &["bob@example.com", "ada@example.com"]).is_none(), "a reordered answer matches nothing");
        assert!(batch_answers(br#"{"ErrorCode":10,"Message":"bad token"}"#, &["ada@example.com"]).is_none());
        assert!(batch_answers(br#"[1]"#, &["ada@example.com"]).is_none());
    }

    #[test]
    fn a_stream_record_names_its_type() {
        assert_eq!(stream_type(br#"{"ID":"broadcast","MessageStreamType":"Broadcasts"}"#).as_deref(), Some("Broadcasts"));
        assert_eq!(stream_type(br#"{"ID":"outbound","MessageStreamType":"Transactional"}"#).as_deref(), Some("Transactional"));
        assert_eq!(stream_type(br#"{"ErrorCode":1226,"Message":"not found"}"#), None);
    }

    #[test]
    fn suppressions_are_read_with_their_reason_and_an_unknown_one_still_suppresses() {
        let body = br#"{"Suppressions":[
            {"EmailAddress":"Ada@Example.com","SuppressionReason":"ManualSuppression","Origin":"Recipient","CreatedAt":"2026-11-12T10:00:00-05:00"},
            {"EmailAddress":"gone@example.com","SuppressionReason":"HardBounce","Origin":"Recipient","CreatedAt":"x"},
            {"EmailAddress":"cross@example.com","SuppressionReason":"SpamComplaint","Origin":"Recipient","CreatedAt":"x"},
            {"EmailAddress":"new@example.com","SuppressionReason":"SomethingNew","Origin":"Admin","CreatedAt":"x"}]}"#;
        let list = suppressions(body).expect("a dump");
        assert_eq!(list[0].address, "ada@example.com");
        assert_eq!(
            list.iter().map(|s| s.reason).collect::<Vec<_>>(),
            [SuppressionReason::Manual, SuppressionReason::HardBounce, SuppressionReason::SpamComplaint, SuppressionReason::Manual]
        );
        assert_eq!(suppressions(br#"{"Suppressions":[]}"#), Some(Vec::new()));
        assert_eq!(suppressions(br#"{"ErrorCode":10}"#), None);
        let sent = serde_json::from_slice::<Value>(&suppressions_body(&["ada@example.com"])).unwrap();
        assert_eq!(sent["Suppressions"][0]["EmailAddress"], "ada@example.com");
        assert_eq!(
            suppressions_deleted(br#"{"Suppressions":[{"EmailAddress":"ada@example.com","Status":"Deleted","Message":null},{"EmailAddress":"cross@example.com","Status":"Failed","Message":"spam complaint"}]}"#),
            Some(vec![("ada@example.com".to_string(), true), ("cross@example.com".to_string(), false)])
        );
    }

    #[test]
    fn statistics_are_counts_and_an_error_is_not_zero() {
        assert_eq!(
            outbound_stats(br#"{"Sent":120,"Bounced":3,"SMTPApiErrors":0,"BounceRate":2.5,"SpamComplaints":1,"SpamComplaintsRate":0.8}"#),
            Some(OutboundStats { sent: 120, bounced: 3, spam_complaints: 1 })
        );
        assert_eq!(outbound_stats(br#"{}"#), Some(OutboundStats::default()));
        assert_eq!(outbound_stats(br#"{"ErrorCode":10,"Message":"bad token"}"#), None);
        assert_eq!(outbound_stats(b"<html>"), None);
    }
}
