//! Static assets from `public/`, embedded in the app's source image.
//!
//! A constrained app cannot read a file — not at runtime (no ambient
//! filesystem) and not at build time (the code gate refuses a
//! build-time read with CODE_BUILD_TIME_READ). So the compiler
//! materializes each file under `public/` into Rust source, and this
//! module serves it: the same discipline the platform's own
//! site-embedding path uses, and the same one the client runtime and
//! the stylesheet already follow.
//!
//! Bytes are carried as a SLICE OF CHUNKS rather than one literal, so a
//! large file does not become one enormous constant, and serving
//! concatenates only when a request actually asks for it.

use super::server::Reply;

/// One embedded file: its URL path, its bytes in order, its content
/// type, and the ETag its digest produced at build time.
pub type Asset = (&'static str, &'static [&'static [u8]], &'static str, &'static str);

/// Find the asset a path addresses.
pub fn find(files: &[Asset], path: &str) -> Option<&'static [&'static [u8]]> {
    files
        .iter()
        .find(|(url, _, _, _)| *url == path)
        .map(|(_, chunks, _, _)| *chunks)
}

/// The total embedded size, for a budget report.
pub fn total_bytes(files: &[Asset]) -> usize {
    files
        .iter()
        .map(|(_, chunks, _, _)| chunks.iter().map(|c| c.len()).sum::<usize>())
        .sum()
}

/// Whether an `if-none-match` header matches `etag` (already quoted).
///
/// RFC 9110: the header is a COMMA-SEPARATED list, `*` matches any
/// existing representation, and for GET the comparison is WEAK — so
/// `W/"abc"` matches `"abc"`. Accepting only one exact tag would send a
/// full body to a client that already had the file.
pub fn etag_matches(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate).trim() == etag
    })
}

/// Serve `path` from `files`, or `None` when nothing there matches —
/// including when the METHOD is not a retrieval.
///
/// The URL is NOT content-addressed — `public/logo.svg` is served at
/// `/logo.svg`, the path an author wrote in their markup — so the
/// response is revalidated rather than marked immutable. (Content
/// addressing is what the framework's own assets get, because it
/// generates those URLs itself.)
///
/// Only GET and HEAD are answered here. Anything else falls through to
/// routing, so an application that genuinely wants to POST to that path
/// can, and one that does not simply gets its ordinary 404 — rather
/// than an asset answering a method nobody meant it to.
pub fn serve(
    files: &[Asset],
    method: &str,
    path: &str,
    if_none_match: Option<&str>,
) -> Option<Reply> {
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    let (_, chunks, content_type, etag) = files.iter().find(|(url, _, _, _)| *url == path)?;
    let quoted = format!("\"{etag}\"");
    let cached = if_none_match.is_some_and(|header| etag_matches(header, &quoted));
    if cached {
        return Some(
            Reply::status(304)
                .header("etag", quoted)
                .header("cache-control", "public, max-age=0, must-revalidate"),
        );
    }
    let reply = Reply::status(200)
        .header("content-type", *content_type)
        .header("etag", quoted)
        .header("cache-control", "public, max-age=0, must-revalidate")
        .header("x-content-type-options", "nosniff");
    if method == "HEAD" {
        // A HEAD answers the headers a GET would, with no body. The
        // LENGTH is deliberately not stated: the platform gateway
        // refuses an application-supplied `content-length` (it owns
        // framing, and a wrong value is a protocol error), and
        // inventing a non-standard header in its place would look like
        // the real thing while meaning nothing to a client.
        return Some(reply);
    }
    Some(reply.body(chunks.concat()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGO: &[&[u8]] = &[b"<svg", b"/>"];
    const FILES: &[Asset] = &[("/logo.svg", LOGO, "image/svg+xml", "abc123")];

    #[test]
    fn an_asset_is_served_with_its_type_and_etag() {
        let reply = serve(FILES, "GET", "/logo.svg", None).expect("served");
        assert_eq!(reply.status_code(), 200);
        assert_eq!(reply.body_len(), 6, "the chunks are concatenated");
        let headers = reply.headers_for_test();
        assert!(headers
            .iter()
            .any(|(n, v)| n == "content-type" && v == "image/svg+xml"));
        assert!(headers.iter().any(|(n, v)| n == "etag" && v == "\"abc123\""));
        assert!(headers
            .iter()
            .any(|(n, v)| n == "x-content-type-options" && v == "nosniff"));
        // The URL is not content-addressed, so it must revalidate rather
        // than claim to be immutable.
        assert!(headers
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("must-revalidate")));
    }

    #[test]
    fn a_matching_etag_answers_304_with_no_body() {
        let reply = serve(FILES, "GET", "/logo.svg", Some("\"abc123\"")).expect("served");
        assert_eq!(reply.status_code(), 304);
        assert_eq!(reply.body_len(), 0);
        // A DIFFERENT etag is a full answer.
        let stale = serve(FILES, "GET", "/logo.svg", Some("\"other\"")).expect("served");
        assert_eq!(stale.status_code(), 200);
    }

    /// RFC 9110 shapes a browser really sends: a list, a weak validator,
    /// and `*`. Reading only one exact tag would re-send the whole file.
    #[test]
    fn conditional_requests_follow_the_http_rules() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""), "weak comparison");
        assert!(etag_matches("\"x\", \"abc\", \"y\"", "\"abc\""), "a list");
        assert!(etag_matches("*", "\"abc\""), "any representation");
        assert!(!etag_matches("\"other\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));

        let listed = serve(FILES, "GET", "/logo.svg", Some("W/\"abc123\", \"z\""))
            .expect("served");
        assert_eq!(listed.status_code(), 304, "a weak tag in a list still matches");
    }

    /// An asset answers retrievals. Anything else falls through to the
    /// application's own routing rather than being answered by a file.
    #[test]
    fn only_get_and_head_are_answered() {
        let head = serve(FILES, "HEAD", "/logo.svg", None).expect("served");
        assert_eq!(head.status_code(), 200);
        assert_eq!(head.body_len(), 0, "a HEAD carries no body");
        // Framing belongs to the transport: the gateway refuses an
        // app-set content-length, so none is claimed here.
        assert!(
            !head
                .headers_for_test()
                .iter()
                .any(|(n, _)| n.contains("content-length")),
            "an app does not set its own framing headers"
        );
        // What it DOES carry is everything a GET would, so a client can
        // decide whether to fetch the body.
        assert!(head
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "etag" && v == "\"abc123\""));
        assert!(head
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "content-type" && v == "image/svg+xml"));

        for method in ["POST", "PUT", "DELETE", "PATCH", "WS_OPEN"] {
            assert!(
                serve(FILES, method, "/logo.svg", None).is_none(),
                "{method} must fall through to routing"
            );
        }
    }

    #[test]
    fn an_unknown_path_is_not_an_asset() {
        assert!(serve(FILES, "GET", "/nope.svg", None).is_none());
        assert!(serve(FILES, "GET", "/", None).is_none());
        assert!(find(FILES, "/logo.svg").is_some());
        assert_eq!(total_bytes(FILES), 6);
    }
}
