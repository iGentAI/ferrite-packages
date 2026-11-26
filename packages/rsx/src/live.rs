//! Live regions: a standing subscription that appends to a region of
//! the page as events land, resumed by LOG OFFSET rather than by replay.
//!
//! The transport is the platform's own: the `/_live/` route is a stream
//! (SSE) face bound to a queue, so the gateway publishes one lifecycle
//! envelope per subscription (`GET` to open, `STREAM_CLOSE` to end) and
//! the app pushes [`StreamFrame`](ferrite_app::StreamFrame)s onto the
//! shared frames queue. Nothing here invents a socket.
//!
//! ## Why the cursor is a log offset
//!
//! Every event is a record on the log plane, whose offsets are DENSE.
//! A region therefore knows exactly where it is, and a reconnect
//! resumes from the next offset instead of replaying a window and
//! deduplicating — which is what a topic without a cursor forces. A
//! dropped connection costs the events that arrived while it was down,
//! and nothing else.
//!
//! ## The honest boundary
//!
//! A tailer POLLS its log. The platform has no wake-on-append for a
//! log reader yet (a recorded platform gap), so a subscription costs one bounded read
//! per interval; that is the economics being bought, and it is stated
//! rather than implied away.

use std::sync::Arc;

use ferrite_app::serde_json;

use super::html::{el, Html};

/// The path a live region subscribes on. `/_live/` is reserved by
/// wire-v1 §1, so an application route can never collide with it.
pub const SUBSCRIBE_PATH: &str = "/_live/subscribe";

/// The SSE event name a live update carries.
pub const LIVE_EVENT: &str = "live";

/// How many records one tailer poll reads.
pub const TAIL_BATCH: u32 = 64;

/// How long a tailer waits between polls when its log is quiet.
pub const TAIL_IDLE_MS: u64 = 200;

/// Renders ONE appended record into the markup a region appends.
///
/// `None` drops the record: a log carries every source, so a renderer
/// is also the filter that decides what belongs in this region.
pub type LiveFn = Arc<dyn Fn(&str, &[u8]) -> Option<Html> + Send + Sync>;

/// The placeholder a `<Live source={…} />` region renders.
///
/// It carries its own cursor, so the client resumes from where the
/// server-rendered content ended rather than from zero.
pub fn region(source: impl std::fmt::Display, from: u64, initial: Html) -> Html {
    el("div")
        .attr("data-rsx-live", source)
        .attr("data-rsx-from", from)
        .child(initial)
        .build()
}

/// The payload one live frame carries: the record's offset and its
/// rendered markup.
pub fn frame_payload(offset: u64, html: &str) -> Vec<u8> {
    serde_json::json!({ "offset": offset, "html": html })
        .to_string()
        .into_bytes()
}

/// The payload a REFUSAL carries, so a client is told rather than left
/// waiting on a subscription that will never produce anything.
pub fn refusal_payload(reason: &str) -> Vec<u8> {
    serde_json::json!({ "refused": reason })
        .to_string()
        .into_bytes()
}

/// The `(source, from)` a subscription requested.
///
/// A missing or malformed cursor reads as 0 rather than refusing: the
/// worst outcome is a region that renders its whole history, and a
/// subscription that fails because a query parameter was ugly would be
/// worse.
pub fn parse_subscription(query: &[(String, String)]) -> Option<(String, u64)> {
    let source = query
        .iter()
        .find(|(name, _)| name == "source")
        .map(|(_, value)| value.clone())?;
    if source.is_empty() {
        return None;
    }
    let from = query
        .iter()
        .find(|(name, _)| name == "from")
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .unwrap_or(0);
    Some((source, from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_carries_its_source_and_cursor() {
        let html = region("room:general", 7, Html::text("seed")).into_string();
        assert!(html.contains("data-rsx-live=\"room:general\""), "{html}");
        assert!(html.contains("data-rsx-from=\"7\""), "{html}");
        assert!(html.contains("seed"), "{html}");
    }

    #[test]
    fn a_hostile_source_cannot_break_out_of_the_attribute() {
        let html = region("\"><script>alert(1)</script>", 0, Html::empty()).into_string();
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&quot;&gt;&lt;script&gt;"), "{html}");
    }

    #[test]
    fn a_subscription_needs_a_source_and_defaults_its_cursor() {
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        assert_eq!(
            parse_subscription(&pairs(&[("source", "room:a"), ("from", "12")])),
            Some(("room:a".to_string(), 12))
        );
        assert_eq!(
            parse_subscription(&pairs(&[("source", "room:a")])),
            Some(("room:a".to_string(), 0)),
            "an absent cursor starts at the beginning"
        );
        assert_eq!(
            parse_subscription(&pairs(&[("source", "room:a"), ("from", "nonsense")])),
            Some(("room:a".to_string(), 0)),
            "a malformed cursor is not worth failing a subscription over"
        );
        assert_eq!(parse_subscription(&pairs(&[("from", "3")])), None);
        assert_eq!(parse_subscription(&pairs(&[("source", "")])), None);
    }

    #[test]
    fn the_frame_payloads_are_the_documented_shapes() {
        let update: serde_json::Value =
            serde_json::from_slice(&frame_payload(4, "<li>hi</li>")).unwrap();
        assert_eq!(update["offset"], 4);
        assert_eq!(update["html"], "<li>hi</li>");
        let refusal: serde_json::Value =
            serde_json::from_slice(&refusal_payload("unknown source")).unwrap();
        assert_eq!(refusal["refused"], "unknown source");
    }
}
