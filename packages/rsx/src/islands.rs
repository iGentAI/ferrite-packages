//! Client islands: the interactive parts of a server-rendered page.
//!
//! A template's `<Counter client:visible initial={n} />` renders a
//! MARKER — `data-rsx-island` plus its serialized props — and nothing
//! else. Something has to deliver the module that turns that marker
//! into an interface, and this is that half: each `components/*.island.js`
//! is embedded in the source image, served at a content-addressed URL,
//! and named in the document's boot state so the client can import it
//! exactly when a marker needs it.
//!
//! Why the manifest rides the boot state rather than the marker: a
//! template cannot know the module's digest (it is computed from the
//! bytes at build time), and putting a guessed URL on the marker would
//! be a URL that changes meaning between deploys. One manifest per
//! document is also one lookup per island rather than one attribute per
//! occurrence.

use ferrite_app::serde_json;

use super::assets::hashed_asset_reply;
use super::server::Reply;

/// The URL prefix an island module is served from.
pub const ISLAND_PREFIX: &str = "/_assets/island-";

/// One island: its name, its content-addressed URL, its bytes (chunked
/// like every other embedded asset), and the digest in that URL.
#[derive(Debug, Clone, Copy)]
pub struct Island {
    /// The name a marker refers to (`data-rsx-island`).
    pub name: &'static str,
    /// Where the module is served.
    pub url: &'static str,
    /// The module's bytes.
    pub chunks: &'static [&'static [u8]],
    /// The digest in `url`.
    pub etag: &'static str,
}

/// The boot manifest: island name → module URL.
pub fn manifest(islands: &[Island]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for island in islands {
        map.insert(
            island.name.to_string(),
            serde_json::Value::String(island.url.to_string()),
        );
    }
    serde_json::Value::Object(map)
}

/// The island a path addresses, by NAME rather than by exact URL.
///
/// A page cached in a browser from before a deploy names the previous
/// digest; answering it with the current module means that page
/// hydrates instead of losing its interactive parts entirely. Only the
/// exact digest is marked immutable.
fn find<'a>(islands: &'a [Island], path: &str) -> Option<(&'a Island, bool)> {
    let rest = path.strip_prefix(ISLAND_PREFIX)?.strip_suffix(".js")?;
    // `<name>-<digest>`; a name may not contain '-', which the compiler
    // enforces, so the split is unambiguous.
    let (name, digest) = rest.rsplit_once('-')?;
    let island = islands.iter().find(|i| i.name == name)?;
    Some((island, digest == island.etag))
}

/// Serve an island module.
///
/// GET and HEAD only, for the same reason a static file is: anything
/// else falls through to the application's own routing.
pub fn serve(islands: &[Island], method: &str, path: &str) -> Option<Reply> {
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    let (island, exact) = find(islands, path)?;
    let reply = hashed_asset_reply("text/javascript; charset=utf-8", island.etag, exact);
    if method == "HEAD" {
        return Some(reply);
    }
    Some(reply.body(island.chunks.concat()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: &[&[u8]] = &[b"export default", b" 1;"];
    const ISLANDS: &[Island] = &[Island {
        name: "counter",
        url: "/_assets/island-counter-abc123.js",
        chunks: COUNTER,
        etag: "abc123",
    }];

    #[test]
    fn the_manifest_names_every_module() {
        let m = manifest(ISLANDS);
        assert_eq!(m["counter"], "/_assets/island-counter-abc123.js");
        assert!(manifest(&[]).as_object().unwrap().is_empty());
    }

    #[test]
    fn a_module_is_served_immutably_from_its_digest() {
        let reply = serve(ISLANDS, "GET", "/_assets/island-counter-abc123.js").expect("served");
        assert_eq!(reply.status_code(), 200);
        assert_eq!(reply.body_len(), 17, "the chunks are concatenated");
        let headers = reply.headers_for_test();
        assert!(headers
            .iter()
            .any(|(n, v)| n == "content-type" && v.starts_with("text/javascript")));
        assert!(headers
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("immutable")));
    }

    /// A page cached from before a deploy names the old digest. Serving
    /// the current module keeps it interactive; only the exact URL is
    /// immutable.
    #[test]
    fn a_stale_digest_still_gets_a_module() {
        let stale = serve(ISLANDS, "GET", "/_assets/island-counter-000000.js").expect("served");
        assert_eq!(stale.status_code(), 200);
        assert!(stale
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("must-revalidate")));
    }

    #[test]
    fn an_unknown_island_and_a_wrong_method_are_not_served() {
        assert!(serve(ISLANDS, "GET", "/_assets/island-ghost-abc123.js").is_none());
        assert!(serve(ISLANDS, "GET", "/_assets/island-counter.js").is_none());
        assert!(serve(ISLANDS, "GET", "/counter.js").is_none());
        for method in ["POST", "PUT", "DELETE"] {
            assert!(serve(ISLANDS, method, "/_assets/island-counter-abc123.js").is_none());
        }
    }

    #[test]
    fn a_head_carries_the_headers_without_the_body() {
        let head = serve(ISLANDS, "HEAD", "/_assets/island-counter-abc123.js").expect("served");
        assert_eq!(head.body_len(), 0);
        assert!(head
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "etag" && v == "\"abc123\""));
    }
}
