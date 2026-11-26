//! **Streamed loader segments**: a slow part of a page must not hold
//! back a fast one.
//!
//! # The problem this solves
//!
//! A loader today returns one payload, so the document waits for the
//! slowest read in it. A product page that renders in 20ms but carries a
//! recommendation panel taking 400ms serves at 400ms, and the 380ms
//! difference is spent showing nothing at all.
//!
//! # The shape
//!
//! A loader returns a [`Segmented`] payload: a **ready** part, embedded in
//! the document exactly as an unsegmented payload is, and zero or more
//! **deferred** parts the client fetches after first paint. The document is
//! therefore served at the speed of the ready part, and the deferred parts
//! arrive into a page the reader is already looking at.
//!
//! # Why the manifest is part of the payload
//!
//! Each deferred segment is announced in the embedded payload by NAME before
//! its data exists. That is what lets the client render a placeholder of the
//! right shape immediately, and — more importantly — it is what stops a
//! deferred segment from being indistinguishable from one that failed. A
//! client that merely noticed a missing field could not tell "still coming"
//! from "will never come", so it would either spin forever on an error or
//! give up on a segment still in flight.
//!
//! # What this deliberately is not
//!
//! It is not HTTP chunked streaming of the document. Alloy's ingress is
//! request/reply over a queue, so a partial document cannot be flushed
//! mid-response; and a segment fetched separately is independently
//! cacheable, independently invalidated by its own tags, and retried on its
//! own when it fails. Streaming one document body gives up all three.

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};

/// The most deferred segments one route may declare.
///
/// Each is a separate round trip after first paint, so a page with dozens
/// would trade one slow response for a burst of requests — which is the
/// waterfall this mechanism exists to remove, rebuilt out of its own parts.
pub const MAX_SEGMENTS: usize = 8;

/// How a deferred segment is reported once it resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", tag = "state", rename_all = "snake_case")]
pub enum SegmentState {
    /// Still being produced. The client shows its placeholder.
    Pending,
    /// Resolved, carrying its data.
    Ready {
        /// The segment's payload.
        data: serde_json::Value,
    },
    /// Failed. The client shows an error in that region ONLY.
    ///
    /// A failed segment must not fail the page: the whole point of deferring
    /// a recommendation panel is that the product page survives without it.
    Failed {
        /// A digest of the cause, safe to show. The cause itself is logged.
        digest: String,
    },
}

impl SegmentState {
    /// Whether this segment has settled, either way.
    pub fn is_settled(&self) -> bool {
        !matches!(self, SegmentState::Pending)
    }
}

/// One deferred segment's declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Segment {
    /// The segment's name, unique within its route.
    pub name: String,
    /// Its state, FLATTENED into the segment object.
    ///
    /// Flattened rather than nested, so a segment reads as
    /// `{"name": "panel", "state": "ready", "data": …}` on the wire. A
    /// nested `state: {state: "ready"}` would make the client reach through
    /// a wrapper that carries no information, and the doubled key is the
    /// kind of shape someone later "tidies" into a breaking change.
    #[serde(flatten)]
    pub state: SegmentState,
}

/// A loader payload split into a ready part and deferred segments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Segmented {
    /// The part that is ready now, embedded in the document.
    pub ready: serde_json::Value,
    /// The deferred parts, announced by name before their data exists.
    pub segments: Vec<Segment>,
}

impl Segmented {
    /// A payload with nothing deferred.
    ///
    /// The common case, and deliberately cheap: a route that defers nothing
    /// pays no structural cost for the mechanism existing.
    pub fn ready(value: serde_json::Value) -> Self {
        Self {
            ready: value,
            segments: Vec::new(),
        }
    }

    /// Declare a deferred segment.
    ///
    /// Names must be unique within a route: two segments sharing a name
    /// would make the client's resolution ambiguous, and the second would
    /// silently overwrite the first in the region the reader is watching.
    pub fn defer(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(AlloyError::internal("a deferred segment needs a name"));
        }
        if self.segments.iter().any(|s| s.name == name) {
            return Err(AlloyError::internal(format!(
                "segment '{name}' is declared twice; the client could not tell \
                 which one resolved"
            )));
        }
        if self.segments.len() >= MAX_SEGMENTS {
            return Err(AlloyError::internal(format!(
                "a route may defer at most {MAX_SEGMENTS} segments; more would \
                 replace one slow response with a burst of round trips"
            )));
        }
        self.segments.push(Segment {
            name,
            state: SegmentState::Pending,
        });
        Ok(self)
    }

    /// Resolve a declared segment with its data.
    ///
    /// Resolving an UNDECLARED segment is refused: the client renders from
    /// the manifest embedded in the document, so data for a name it never
    /// saw has nowhere to go and would be silently dropped.
    pub fn resolve(&mut self, name: &str, data: serde_json::Value) -> Result<()> {
        let segment = self
            .segments
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| {
                AlloyError::internal(format!(
                    "segment '{name}' was resolved but never declared; the client \
                     has no region to put it in"
                ))
            })?;
        segment.state = SegmentState::Ready { data };
        Ok(())
    }

    /// Mark a declared segment failed, carrying a digest of the cause.
    ///
    /// A failed segment leaves the rest of the page intact. That is the
    /// whole reason to defer a panel rather than block on it.
    pub fn fail(&mut self, name: &str, digest: impl Into<String>) -> Result<()> {
        let segment = self
            .segments
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| {
                AlloyError::internal(format!("segment '{name}' was failed but never declared"))
            })?;
        segment.state = SegmentState::Failed {
            digest: digest.into(),
        };
        Ok(())
    }

    /// The names still pending.
    pub fn pending(&self) -> Vec<&str> {
        self.segments
            .iter()
            .filter(|s| !s.state.is_settled())
            .map(|s| s.name.as_str())
            .collect()
    }

    /// Whether every declared segment has settled.
    pub fn is_complete(&self) -> bool {
        self.segments.iter().all(|s| s.state.is_settled())
    }

    /// The payload as the document embeds it.
    ///
    /// A route with NO deferred segments embeds its ready value unchanged,
    /// so the wire format is identical to an unsegmented payload and a
    /// client that knows nothing about segments is unaffected.
    pub fn to_payload(&self) -> serde_json::Value {
        if self.segments.is_empty() {
            return self.ready.clone();
        }
        serde_json::json!({
            "ready": self.ready,
            "segments": self.segments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_that_defers_nothing_embeds_an_unchanged_payload() {
        // The mechanism must cost nothing to a route that does not use it,
        // or every existing client would need to learn about segments.
        let value = serde_json::json!({ "title": "a page" });
        let payload = Segmented::ready(value.clone()).to_payload();
        assert_eq!(payload, value);
        assert!(payload.get("segments").is_none());
    }

    #[test]
    fn a_deferred_segment_is_announced_before_its_data_exists() {
        // THE property that lets a client tell "still coming" from "never
        // coming". Without the manifest a missing field is ambiguous, and
        // the client either spins forever or gives up too early.
        let seg = Segmented::ready(serde_json::json!({ "title": "a page" }))
            .defer("recommendations")
            .unwrap();
        let payload = seg.to_payload();
        assert_eq!(payload["ready"]["title"], "a page");
        assert_eq!(payload["segments"][0]["name"], "recommendations");
        assert_eq!(payload["segments"][0]["state"], "pending");
        assert_eq!(seg.pending(), vec!["recommendations"]);
        assert!(!seg.is_complete());
    }

    #[test]
    fn a_resolved_segment_carries_its_data_and_settles() {
        let mut seg = Segmented::ready(serde_json::json!({}))
            .defer("panel")
            .unwrap();
        seg.resolve("panel", serde_json::json!({ "rows": [1, 2] }))
            .unwrap();
        assert!(seg.is_complete());
        assert!(seg.pending().is_empty());
        let payload = seg.to_payload();
        assert_eq!(payload["segments"][0]["state"], "ready");
        assert_eq!(payload["segments"][0]["data"]["rows"][1], 2);
    }

    #[test]
    fn a_failed_segment_leaves_the_rest_of_the_page_intact() {
        // Deferring a panel is only worth doing if the page survives without
        // it. A failure that took the document with it would be strictly
        // worse than having blocked on the slow read in the first place.
        let mut seg = Segmented::ready(serde_json::json!({ "title": "still here" }))
            .defer("panel")
            .unwrap();
        seg.fail("panel", "a1b2c3d4").unwrap();

        assert!(seg.is_complete(), "a failed segment has settled");
        let payload = seg.to_payload();
        assert_eq!(payload["ready"]["title"], "still here");
        assert_eq!(payload["segments"][0]["state"], "failed");
        // The digest is what reaches the reader; the cause reaches the log.
        assert_eq!(payload["segments"][0]["digest"], "a1b2c3d4");
    }

    #[test]
    fn one_segment_failing_does_not_disturb_another() {
        let mut seg = Segmented::ready(serde_json::json!({}))
            .defer("fast")
            .unwrap()
            .defer("slow")
            .unwrap();
        seg.resolve("fast", serde_json::json!("done")).unwrap();
        seg.fail("slow", "deadbeef").unwrap();

        let payload = seg.to_payload();
        let by_name = |n: &str| {
            payload["segments"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["name"] == n)
                .unwrap()
                .clone()
        };
        assert_eq!(by_name("fast")["state"], "ready");
        assert_eq!(by_name("fast")["data"], "done");
        assert_eq!(by_name("slow")["state"], "failed");
    }

    #[test]
    fn a_duplicate_segment_name_is_refused() {
        // Two segments sharing a name would make resolution ambiguous, and
        // the second would silently overwrite the first in the region the
        // reader is watching.
        let seg = Segmented::ready(serde_json::json!({}))
            .defer("panel")
            .unwrap();
        assert!(seg.defer("panel").is_err());
    }

    #[test]
    fn an_empty_segment_name_is_refused() {
        assert!(Segmented::ready(serde_json::json!({})).defer("").is_err());
    }

    #[test]
    fn resolving_a_segment_nobody_declared_is_refused() {
        // The client renders from the manifest, so data for a name it never
        // saw has nowhere to go — and dropping it silently would show an
        // empty region with no explanation.
        let mut seg = Segmented::ready(serde_json::json!({}));
        assert!(seg.resolve("ghost", serde_json::json!(1)).is_err());
        assert!(seg.fail("ghost", "d").is_err());
    }

    #[test]
    fn the_segment_count_is_bounded() {
        // Deferring everything replaces one slow response with a burst of
        // round trips, which is the waterfall this mechanism removes,
        // rebuilt out of its own parts.
        let mut seg = Segmented::ready(serde_json::json!({}));
        for i in 0..MAX_SEGMENTS {
            seg = seg.defer(format!("s{i}")).expect("within the bound");
        }
        assert!(seg.defer("one-too-many").is_err());
        const _: () = assert!(MAX_SEGMENTS > 0);
        const _: () = assert!(MAX_SEGMENTS <= 16);
    }
}
