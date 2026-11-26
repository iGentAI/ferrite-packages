//! The Telegram Bot API adapter: the send URL, the MarkdownV2 escape table,
//! and the `sendMessage` payload.
//!
//! # The credential is in the URL, and that is the provider's decision
//!
//! Every other adapter in this kit puts its credential in a header, because
//! the egress audit record keeps destinations durably and header values out.
//! The Telegram Bot API offers no such option: the bot token IS a path segment
//! of `https://api.telegram.org/bot{token}/sendMessage`, and there is no header
//! form. A consuming app therefore accepts that its egress audit records a
//! destination containing the token, and treats bot-token rotation as the
//! mitigation. [`send_message_url`] is where that cost is paid, and it is the
//! only place in this kit where a credential is written into a URL.
//!
//! # The truncation rule exists because escaping and truncating interact
//!
//! MarkdownV2 escaping inserts backslashes; truncating the escaped text can
//! cut between a backslash and the character it escapes, and Telegram answers
//! `400` for the dangling backslash that leaves. [`send_message_payload`]
//! truncates and then repairs, which is the order that cannot leave one.

use ferrite_app::serde_json;
use std::io;

use super::ProviderRequest;

/// The character budget one `sendMessage` body is truncated to.
///
/// Telegram's own limit is 4,096 UTF-16 code units for `text`. The margin
/// below it absorbs the escaping expansion, which is bounded by one backslash
/// per reserved character.
pub const MAX_MESSAGE_CHARS: usize = 3_500;

/// The `sendMessage` endpoint for one bot token.
///
/// The token is a path segment because the Bot API takes it nowhere else; see
/// this module's documentation for what that costs in the egress audit record.
#[must_use]
pub fn send_message_url(bot_token: &str) -> String {
    format!("https://api.telegram.org/bot{bot_token}/sendMessage")
}

/// Escape text for MarkdownV2.
///
/// Every character Telegram reserves is prefixed with a backslash, including
/// the ones that look harmless (`.`, `-`, `!`), because the API rejects an
/// unescaped occurrence of any of them wherever it appears. The backslash
/// itself is escaped too: left bare, it would escape whatever follows it and
/// let the text open formatting of its own.
#[must_use]
pub fn escape_markdown_v2(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\_*[]()~`>#+-=|{}.!".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Build the `sendMessage` JSON body: a bold subject, a blank line, then the
/// body, all MarkdownV2-escaped and truncated to [`MAX_MESSAGE_CHARS`].
pub fn send_message_payload(chat_id: &str, subject: &str, body_md: &str) -> io::Result<Vec<u8>> {
    let text = format!(
        "*{}*\n\n{}",
        escape_markdown_v2(subject),
        escape_markdown_v2(body_md)
    );
    let mut bounded: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
    // The truncation boundary can fall inside an inserted `\x` escape pair,
    // leaving a dangling backslash that Telegram's MarkdownV2 rejects (400).
    // In valid escaped text backslashes only appear as escape-introducers, so
    // an ODD run of trailing backslashes means the last one lost its follower.
    let trailing_backslashes = bounded.chars().rev().take_while(|&c| c == '\\').count();
    if trailing_backslashes % 2 == 1 {
        bounded.pop();
    }
    serde_json::to_vec(&serde_json::json!({
        "chat_id": chat_id,
        "text": bounded,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": true,
    }))
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Build the whole `sendMessage` request: URL, JSON body, content type.
///
/// The bot token is the only credential, and it is already in the URL, so this
/// request carries no `authorization` header.
pub fn send_message(
    bot_token: &str,
    chat_id: &str,
    subject: &str,
    body_md: &str,
) -> io::Result<ProviderRequest> {
    let body = send_message_payload(chat_id, subject, body_md)?;
    Ok(ProviderRequest::json(
        &send_message_url(bot_token),
        body,
        &[],
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{
        escape_markdown_v2, send_message, send_message_payload, send_message_url, MAX_MESSAGE_CHARS,
    };
    use ferrite_app::serde_json::{self, Value};

    #[test]
    fn every_reserved_character_is_escaped() {
        assert_eq!(
            escape_markdown_v2("a\\b_c*d[e]f(g)h~i`j>k#l+m-n=o|p{q}r.s!"),
            "a\\\\b\\_c\\*d\\[e\\]f\\(g\\)h\\~i\\`j\\>k\\#l\\+m\\-n\\=o\\|p\\{q\\}r\\.s\\!"
        );
        // A backslash in the text must not escape the reserved character
        // after it: `\*` would otherwise reach Telegram as `\\*`, an escaped
        // backslash followed by a bare `*` that opens bold.
        assert_eq!(escape_markdown_v2("\\*"), "\\\\\\*");
        assert_eq!(escape_markdown_v2("plain text"), "plain text");
    }

    #[test]
    fn truncation_never_leaves_a_dangling_escape() {
        // A body of reserved characters escapes to two chars each, so the
        // truncation boundary lands inside a pair.
        let body = ".".repeat(4_000);
        let bytes = send_message_payload("42", "subject", &body).expect("a payload");
        let value = serde_json::from_slice::<Value>(&bytes).expect("JSON");
        let text = value["text"].as_str().expect("text");
        assert!(text.chars().count() <= MAX_MESSAGE_CHARS);
        let trailing = text.chars().rev().take_while(|&c| c == '\\').count();
        assert_eq!(trailing % 2, 0, "a dangling backslash would be a 400");
    }

    #[test]
    fn the_payload_declares_markdown_v2_and_suppresses_previews() {
        let bytes = send_message_payload("42", "Subject", "body").expect("a payload");
        let value = serde_json::from_slice::<Value>(&bytes).expect("JSON");
        assert_eq!(value["chat_id"], "42");
        assert_eq!(value["parse_mode"], "MarkdownV2");
        assert_eq!(value["disable_web_page_preview"], true);
        assert_eq!(value["text"], "*Subject*\n\nbody");
    }

    #[test]
    fn the_token_is_a_path_segment_and_no_header_carries_it() {
        let url = send_message_url("123:ABC");
        assert_eq!(url, "https://api.telegram.org/bot123:ABC/sendMessage");
        let request = send_message("123:ABC", "42", "Subject", "body").expect("a request");
        assert_eq!(request.destination, url);
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("authorization"), None);
    }
}
