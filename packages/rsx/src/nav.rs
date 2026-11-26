//! Soft navigation (wire-v1 §2): the page payload, segment
//! composition, and the hashes that let a client keep the DOM it
//! already has.
//!
//! A page is a CHAIN of segments — the layouts from root to leaf, then
//! the page itself. Each layout renders once with a [`HOLE`] sentinel
//! where its children go, so its hash describes its own chrome and NOT
//! the page inside it; that is what makes "this layout is unchanged" a
//! decidable question.
//!
//! **The patch anchor is a layout SLOT, never a page.** A slot exists
//! in the document for as long as its layout does, so navigating to a
//! different page under the same layout still has somewhere to patch.
//! Anchoring on the page would name an id that, by definition, is not
//! in the document being navigated away from.
//!
//! Boundaries are HTML COMMENTS rather than wrapper elements: a wrapper
//! would change the document's shape (and every CSS selector written
//! against it), while a comment is invisible to CSS, to layout, and to
//! screen readers, and a browser can still find it precisely.

use ferrite_app::{crypto, serde};

/// Where a layout's children go while it is rendered on its own.
pub const HOLE: &str = "<!--aly:hole-->";

/// The request header a soft navigation carries.
pub const NAV_HEADER: &str = "x-rsx-nav";
/// The request header carrying the client's current segment hashes.
pub const HAVE_HEADER: &str = "x-rsx-have";
/// The request header marking a low-priority prefetch.
pub const PREFETCH_HEADER: &str = "x-rsx-prefetch";
/// The request header naming the page the client is looking at.
///
/// An action posts to its own id rather than to a URL, so the answer
/// cannot know which page to re-render unless the client says. With it,
/// a mutation returns its result AND the new render in one round trip.
pub const PATH_HEADER: &str = "x-rsx-path";

/// Make an id safe to carry inside an HTML comment.
///
/// `--` would close the comment early and `>` can terminate a malformed
/// one, so both are neutralized. Route patterns never contain them, but
/// an id is data and data is not trusted to be well-behaved.
pub fn sanitize_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    let mut previous_dash = false;
    for c in id.chars() {
        let c = match c {
            '<' | '>' | '&' => '_',
            '-' if previous_dash => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        };
        previous_dash = c == '-';
        out.push(c);
    }
    out
}

/// The stable hash of one segment's own HTML (`h:` + 16 hex).
pub fn segment_hash(html: &str) -> String {
    let digest = crypto::sha256(html.as_bytes());
    let hex = crypto::hex(&digest);
    format!("h:{}", &hex[..16])
}

/// The hash of an arbitrary payload, for ETags.
pub fn payload_etag(bytes: &[u8]) -> String {
    let digest = crypto::sha256(bytes);
    format!("\"{}\"", &crypto::hex(&digest)[..16])
}

/// Wrap a layout's children in its SLOT markers — the anchor a soft
/// navigation patches.
pub fn wrap_slot(id: &str, inner: &str) -> String {
    let id = sanitize_id(id);
    format!("<!--aly:h:{id}-->{inner}<!--aly:/h:{id}-->")
}

/// One segment of the rendered chain: its id and its own hash.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct SegmentPayload {
    /// The stable segment id (`seg:/blog`, `page:/blog/[slug]`).
    pub id: String,
    /// The hash of this segment's own HTML.
    pub hash: String,
}

/// Document head values a soft navigation must carry.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct Head {
    /// The document title.
    pub title: Option<String>,
    /// `meta` entries as `[kind, name, content]` triples.
    #[serde(default)]
    pub meta: Vec<Vec<String>>,
    /// `link` entries as `[rel, href]` pairs.
    #[serde(default)]
    pub links: Vec<Vec<String>>,
}

/// A streamed hole in this render (wire-v1 §3).
///
/// Always empty until M6 introduces the slot streamer; the field exists
/// now so a client written against wire-v1 sees the shape it expects
/// rather than a missing key.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct SlotRef {
    /// The slot id, unique per render.
    pub id: String,
    /// Dense reveal order (1..=N).
    pub order: u32,
    /// `pending` until its frame arrives.
    pub status: String,
}

/// The transition hint a navigation carries.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct Transition {
    /// A named transition kind, or `null` for the default crossfade.
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

/// The soft-navigation page payload (wire-v1 §2).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "ferrite_app::serde")]
pub struct PagePayload {
    /// Wire version.
    pub v: u32,
    /// The path this payload renders.
    pub path: String,
    /// The render id slot frames are addressed by; absent when the
    /// render completed with no streamed holes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_id: Option<String>,
    /// Head values to apply.
    pub head: Head,
    /// The layout SLOT whose contents this payload replaces. `null`
    /// means no layout is shared with the client's current page, so
    /// there is nothing to patch and the client loads the document
    /// normally — an honest outcome, not a failure.
    pub patch_at: Option<String>,
    /// The replacement contents of that slot. `null` means the render
    /// is byte-identical to what the client already shows.
    pub html: Option<String>,
    /// The full segment chain after this navigation, root → leaf, so the
    /// client can answer the next `x-rsx-have`.
    pub segments: Vec<SegmentPayload>,
    /// Streamed holes awaiting frames.
    #[serde(default)]
    pub slots: Vec<SlotRef>,
    /// Cache tags this render read.
    pub tags: Vec<String>,
    /// How long the client may serve this without revalidating.
    pub stale_ms: u64,
    /// The transition hint.
    #[serde(default)]
    pub transition: Transition,
}

impl PagePayload {
    /// A payload for `path` carrying the chain it produces.
    pub fn new(path: impl Into<String>, segments: Vec<SegmentPayload>) -> Self {
        Self {
            v: 1,
            path: path.into(),
            render_id: None,
            head: Head::default(),
            patch_at: None,
            html: None,
            segments,
            slots: Vec::new(),
            tags: Vec::new(),
            stale_ms: 0,
            transition: Transition::default(),
        }
    }
}

/// The markup a client applies IMMEDIATELY on a soft navigation — the
/// Rsx analog of Next.js's `instant()` test helper.
///
/// A payload's `html` is the SHELL: layouts, the page, and a fallback for
/// every deferred boundary. A deferred body is absent from it by
/// construction, so "is this visible instantly?" is answerable by looking
/// here and nowhere else.
///
/// `None` when the bytes are not a navigation payload, or when the render
/// was byte-identical to what the client already had — a valid outcome
/// that carries no html at all.
pub fn shell_of(payload: &[u8]) -> Option<String> {
    let decoded: PagePayload = ferrite_app::serde_json::from_slice(payload).ok()?;
    decoded.html
}

/// Whether `needle` is in the shell: what a reader sees the instant a
/// navigation is applied, before any deferred region resolves.
///
/// A non-payload input answers `false` rather than being searched as
/// text, which is the whole reason to have this instead of a substring
/// check: a test that forgets `x-rsx-nav` gets a DOCUMENT, in which
/// every boundary is already resolved, and a plain `contains` would then
/// pass while proving the opposite of what it claims.
pub fn instantly_visible(payload: &[u8], needle: &str) -> bool {
    shell_of(payload).is_some_and(|html| html.contains(needle))
}

/// Whether `needle` is DEFERRED: absent from the shell, and delivered by
/// the boundary the shell left pending.
///
/// It takes BOTH halves — the navigation payload and the reply from
/// `/_rsx/slot/<id>` — because absence alone proves nothing. A needle
/// the page never renders at all is also absent, so a typo would
/// otherwise "prove" deferral, and so would any unrelated pending
/// region elsewhere on the page. Requiring the slot reply to CONTAIN it
/// ties the claim to content that really does arrive later.
pub fn deferred_into(shell: &[u8], slot_reply: &[u8], needle: &str) -> bool {
    let Some(html) = shell_of(shell) else {
        return false;
    };
    if html.contains(needle) || !html.contains("data-rsx-slot-pending") {
        return false;
    }
    // The slot endpoint answers `{v, html}`; anything else (a 404, a 410
    // for a boundary that no longer exists) is not evidence.
    ferrite_app::serde_json::from_slice::<ferrite_app::serde_json::Value>(slot_reply)
        .ok()
        .and_then(|value| {
            value
                .get("html")
                .and_then(|html| html.as_str())
                .map(|html| html.contains(needle))
        })
        .unwrap_or(false)
}

/// Parse the `x-rsx-have` header into `(id, hash)` pairs.
///
/// Malformed entries are skipped rather than failing the request: the
/// header is a CACHE hint, and the worst outcome of ignoring one is
/// sending HTML the client already had.
pub fn parse_have(header: &str) -> Vec<(String, String)> {
    header
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            let (id, hash) = entry.split_once('=')?;
            if id.is_empty() || hash.is_empty() {
                return None;
            }
            Some((id.to_string(), hash.to_string()))
        })
        .collect()
}

/// How many leading LAYOUTS the client already has, unchanged.
///
/// The prefix must be contiguous from the root: a client that shares
/// layout 0 and 2 but not 1 shares only layout 0, because the anchor it
/// would patch lives inside the layout that changed.
pub fn shared_prefix(chain: &[(String, String)], have: &[(String, String)]) -> usize {
    let mut shared = 0;
    for (id, hash) in chain {
        let matched = have
            .iter()
            .any(|(have_id, have_hash)| have_id == id && have_hash == hash);
        if !matched {
            break;
        }
        shared += 1;
    }
    shared
}

/// Compose a document (or a sub-tree) from layout shells and a page.
///
/// Composition runs leaf → root, substituting each composed child into
/// its parent's hole and marking every layout's slot.
pub fn compose(shells: &[(String, String)], content: &str) -> String {
    let mut inner = content.to_string();
    for (id, shell) in shells.iter().rev() {
        inner = replace_hole(shell, &wrap_slot(id, &inner));
    }
    inner
}

/// Substitute a layout's hole. A layout that lost its hole (it did not
/// render `<Children />`) still composes — its children are appended,
/// so a missing slot degrades to "children last" instead of silently
/// dropping the page.
fn replace_hole(shell: &str, inner: &str) -> String {
    match shell.find(HOLE) {
        Some(at) => {
            let mut out = String::with_capacity(shell.len() + inner.len());
            out.push_str(&shell[..at]);
            out.push_str(inner);
            out.push_str(&shell[at + HOLE.len()..]);
            out
        }
        None => format!("{shell}{inner}"),
    }
}

/// Extract `<title>` from a composed document, for the payload head.
pub fn document_title(html: &str) -> Option<String> {
    // Within <head> when there is one, as meta::remove_head_title: an
    // <svg><title> in the body is an icon's label, not the page's title.
    let scope = html.find("</head>").map_or(html, |end| &html[..end]);
    let start = scope.find("<title>")? + "<title>".len();
    let end = scope[start..].find("</title>")? + start;
    // document.title takes text, and the rendered title is escaped markup.
    Some(
        scope[start..end]
            .trim()
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&#x27;", "'")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_title_is_the_heads_and_is_text() {
        // finding_ff44cb7a263f5e10
        assert_eq!(document_title("<head><title>Q&amp;A &#39;x&#39;</title></head>").as_deref(), Some("Q&A 'x'"));
        assert_eq!(document_title("<head></head><body><svg><title>Play</title></svg></body>"), None);
        assert_eq!(document_title("<title>Fragment</title>").as_deref(), Some("Fragment"));
    }

    fn shells() -> Vec<(String, String)> {
        vec![
            (
                "seg:/".to_string(),
                format!("<html><head><title>T</title></head><body><nav></nav>{HOLE}</body></html>"),
            ),
            ("seg:/blog".to_string(), format!("<section>{HOLE}</section>")),
        ]
    }

    #[test]
    fn ids_cannot_break_out_of_a_comment() {
        assert_eq!(sanitize_id("seg:/a--b"), "seg:/a-_b");
        assert_eq!(sanitize_id("seg:/a>b"), "seg:/a_b");
        assert_eq!(sanitize_id("page:/blog/[slug]"), "page:/blog/[slug]");
        let wrapped = wrap_slot("x--><script>", "hi");
        assert!(!wrapped.contains("<script>"), "{wrapped}");
    }

    #[test]
    fn a_segment_hash_is_stable_and_short() {
        let a = segment_hash("<p>x</p>");
        assert_eq!(a, segment_hash("<p>x</p>"));
        assert_ne!(a, segment_hash("<p>y</p>"));
        assert!(a.starts_with("h:") && a.len() == 18, "{a}");
    }

    #[test]
    fn an_etag_is_stable_and_quoted() {
        let a = payload_etag(b"{}");
        assert_eq!(a, payload_etag(b"{}"));
        assert_ne!(a, payload_etag(b"{ }"));
        assert!(a.starts_with('"') && a.ends_with('"'), "{a}");
    }

    #[test]
    fn composition_fills_every_hole_and_marks_every_slot() {
        let doc = compose(&shells(), "<h1>post</h1>");
        assert_eq!(
            doc,
            "<html><head><title>T</title></head><body><nav></nav>\
<!--aly:h:seg:/--><section><!--aly:h:seg:/blog--><h1>post</h1>\
<!--aly:/h:seg:/blog--></section><!--aly:/h:seg:/--></body></html>"
        );
        assert!(!doc.contains(HOLE), "every hole is filled");
        // The doctype problem cannot arise: markers live INSIDE layouts,
        // never before the document's first token.
        let with_doctype = compose(
            &[("seg:/".to_string(), format!("<!doctype html><html>{HOLE}</html>"))],
            "<p>x</p>",
        );
        assert!(with_doctype.starts_with("<!doctype html>"), "{with_doctype}");
    }

    /// Composing a SUFFIX of the chain is exactly what a patch carries.
    #[test]
    fn composing_a_suffix_produces_the_patch_body() {
        let all = shells();
        let patch = compose(&all[1..], "<h1>post</h1>");
        assert_eq!(
            patch,
            "<section><!--aly:h:seg:/blog--><h1>post</h1><!--aly:/h:seg:/blog--></section>"
        );
        // And the deepest case: the page alone, patched into the leaf
        // layout's own slot.
        assert_eq!(compose(&[], "<h1>post</h1>"), "<h1>post</h1>");
    }

    #[test]
    fn a_layout_without_a_hole_still_renders_its_children() {
        let doc = compose(
            &[("seg:/".to_string(), "<body>no slot</body>".to_string())],
            "<h1>x</h1>",
        );
        assert!(doc.contains("<h1>x</h1>"), "children are never dropped: {doc}");
    }

    #[test]
    fn the_shared_prefix_is_contiguous_from_the_root() {
        let chain = vec![
            ("seg:/".to_string(), "h:a".to_string()),
            ("seg:/blog".to_string(), "h:b".to_string()),
        ];
        let all = vec![
            ("seg:/".to_string(), "h:a".to_string()),
            ("seg:/blog".to_string(), "h:b".to_string()),
        ];
        assert_eq!(shared_prefix(&chain, &all), 2);
        // The root changed: nothing below it can be reused.
        let changed_root = vec![
            ("seg:/".to_string(), "h:OTHER".to_string()),
            ("seg:/blog".to_string(), "h:b".to_string()),
        ];
        assert_eq!(shared_prefix(&chain, &changed_root), 0);
        // A client on a different section shares only the root.
        let other_section = vec![
            ("seg:/".to_string(), "h:a".to_string()),
            ("seg:/docs".to_string(), "h:d".to_string()),
        ];
        assert_eq!(shared_prefix(&chain, &other_section), 1);
        assert_eq!(shared_prefix(&chain, &[]), 0);
    }

    #[test]
    fn the_have_header_parses_leniently() {
        assert_eq!(
            parse_have("seg:/=h:aa,page:/x=h:bb"),
            vec![
                ("seg:/".to_string(), "h:aa".to_string()),
                ("page:/x".to_string(), "h:bb".to_string())
            ]
        );
        assert!(parse_have("garbage,=,x=").is_empty());
        assert!(parse_have("").is_empty());
    }

    #[test]
    fn the_payload_serializes_in_the_wire_v1_shape() {
        let mut payload = PagePayload::new(
            "/blog/hello",
            vec![SegmentPayload {
                id: "seg:/".to_string(),
                hash: "h:aa".to_string(),
            }],
        );
        payload.patch_at = Some("seg:/".to_string());
        payload.html = Some("<p>x</p>".to_string());
        let json = ferrite_app::serde_json::to_value(&payload).expect("serializes");
        assert_eq!(json["v"], 1);
        assert_eq!(json["path"], "/blog/hello");
        assert_eq!(json["patch_at"], "seg:/");
        assert_eq!(json["html"], "<p>x</p>");
        assert!(json["segments"].is_array());
        assert!(json["slots"].is_array(), "slots is always present");
        assert!(json["tags"].is_array());
        assert!(json["head"]["meta"].is_array());
        assert!(json["transition"]["type"].is_null());
        assert!(
            json.get("render_id").is_none(),
            "a complete render carries no render id"
        );
    }

    /// The `instant()` analog: the shell is what a reader sees at once.
    #[test]
    fn the_instant_helpers_read_the_shell_and_refuse_a_document() {
        let mut payload = PagePayload::new(
            "/albums/quorum",
            vec![SegmentPayload {
                id: "seg:/".to_string(),
                hash: "h:aa".to_string(),
            }],
        );
        payload.patch_at = Some("seg:/".to_string());
        payload.html = Some(
            "<h1>Quorum</h1><div data-rsx-slot=\"s1\" data-rsx-slot-pending>\
<p>finding related albums\u{2026}</p></div>"
                .to_string(),
        );
        let bytes = ferrite_app::serde_json::to_vec(&payload).unwrap();
        // What the slot endpoint would answer for that boundary.
        let slot = br#"{"v":1,"html":"<section data-loaded=\"1\"><h2>Related</h2></section>"}"#;

        assert!(instantly_visible(&bytes, "<h1>Quorum</h1>"));
        assert!(
            instantly_visible(&bytes, "finding related albums"),
            "a fallback IS instant — it is what the reader looks at"
        );
        assert!(
            deferred_into(&bytes, slot, "<h2>Related</h2>"),
            "absent from the shell AND delivered by the boundary"
        );
        assert!(
            !deferred_into(&bytes, slot, "<h2>Relatd</h2>"),
            "a TYPO is absent from both, so it proves nothing"
        );
        assert!(
            !deferred_into(&bytes, br#"{"v":1,"html":"<p>something else</p>"}"#, "<h2>Related</h2>"),
            "an unrelated boundary is not evidence either"
        );
        assert!(
            !deferred_into(&bytes, b"not json", "<h2>Related</h2>"),
            "and neither is a refusal from the slot endpoint"
        );
        assert!(
            !deferred_into(&bytes, slot, "<h1>Quorum</h1>"),
            "content already in the shell is not deferred"
        );
        assert_eq!(shell_of(&bytes).unwrap().len(), payload.html.unwrap().len());

        // A DOCUMENT is not a payload. Answering false is what stops a
        // test that forgot the nav header from passing vacuously — in a
        // document the deferred body is already there.
        let document = b"<html><body><h2>Related</h2></body></html>";
        assert!(!instantly_visible(document, "<h2>Related</h2>"));
        assert!(!deferred_into(document, slot, "<h2>Related</h2>"));
        assert!(shell_of(document).is_none());

        // An unchanged render carries no html, so nothing is claimed.
        let mut identical = PagePayload::new("/", Vec::new());
        identical.patch_at = Some("seg:/".to_string());
        let bytes = ferrite_app::serde_json::to_vec(&identical).unwrap();
        assert!(shell_of(&bytes).is_none());
        assert!(!instantly_visible(&bytes, "anything"));
        assert!(!deferred_into(&bytes, slot, "anything"));
    }

    #[test]
    fn the_title_comes_out_of_the_composed_document() {
        assert_eq!(
            document_title("<html><head><title> Hi </title></head></html>").as_deref(),
            Some("Hi")
        );
        assert_eq!(document_title("<html></html>"), None);
    }
}
