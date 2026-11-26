//! The application's aggregated stylesheet, served content-addressed.
//!
//! Every template's scoped `<style>` block is collected by the compiler
//! into one Rust constant (never a build-time file read, which the code
//! gate refuses with CODE_BUILD_TIME_READ) and handed to the runtime at
//! startup. This module is the serving half: one URL that changes
//! whenever the bytes do, which is what makes `immutable` caching
//! honest, and one `<link>` in the head.

use ferrite_app::crypto;

use super::html::{trusted_el, TrustedTag};
use super::server::Reply;

/// The URL prefix the stylesheet is served from (wire-v1 §1 reserves
/// `/_assets/`).
pub const ASSET_PREFIX: &str = "/_assets/style-";

/// The first 16 hex characters of the stylesheet's SHA-256.
pub fn digest(css: &str) -> String {
    let digest = crypto::sha256(css.as_bytes());
    crypto::hex(&digest)[..16].to_string()
}

/// The content-addressed URL of the stylesheet.
pub fn stylesheet_url(css: &str) -> String {
    format!("{ASSET_PREFIX}{}.css", digest(css))
}

/// Whether a path addresses the stylesheet.
pub fn is_stylesheet(path: &str) -> bool {
    path.starts_with(ASSET_PREFIX) && path.ends_with(".css")
}

/// The headers of a content-addressed asset. Only the exact digest may be
/// marked immutable: a request naming another digest is answered with the
/// current bytes, which that URL must not pin.
pub(super) fn hashed_asset_reply(content_type: &str, etag: &str, exact: bool) -> Reply {
    Reply::status(200)
        .header("content-type", content_type)
        .header("etag", format!("\"{etag}\""))
        .header("x-content-type-options", "nosniff")
        .header(
            "cache-control",
            if exact {
                "public, max-age=31536000, immutable"
            } else {
                "public, max-age=0, must-revalidate"
            },
        )
}

/// Serve the stylesheet.
///
/// A request for a DIFFERENT digest is answered with the current sheet
/// rather than a 404 — a page cached in a browser from before a deploy
/// then renders styled rather than naked — but only the exact digest is
/// marked immutable.
pub fn stylesheet_reply(css: &str, path: &str) -> Reply {
    let current = digest(css);
    let exact = path == format!("{ASSET_PREFIX}{current}.css");
    hashed_asset_reply("text/css; charset=utf-8", &current, exact).body(css.as_bytes().to_vec())
}

/// The `<link>` a document carries.
///
/// Built through the framework's own trusted-element door: `link` is a
/// closed vocabulary entry, and the URL is generated rather than taken
/// from a request.
pub fn link(css: &str) -> String {
    trusted_el(TrustedTag::Link)
        .attr("rel", "stylesheet")
        .attr("href", stylesheet_url(css))
        .build()
        .into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_is_content_addressed() {
        let a = stylesheet_url(".a{color:red}");
        let b = stylesheet_url(".a{color:blue}");
        assert_ne!(a, b, "different bytes, different URL");
        assert_eq!(a, stylesheet_url(".a{color:red}"), "stable");
        assert!(is_stylesheet(&a), "{a}");
        assert!(!is_stylesheet("/_assets/client-abc.js"));
        assert!(!is_stylesheet("/_assets/style-abc.js"));
    }

    #[test]
    fn the_exact_digest_is_immutable_and_a_stale_one_is_not() {
        let css = ".a{color:red}";
        let exact = stylesheet_reply(css, &stylesheet_url(css));
        assert_eq!(exact.status_code(), 200);
        assert!(exact
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("immutable")));
        assert!(exact
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "content-type" && v.starts_with("text/css")));

        let stale = stylesheet_reply(css, "/_assets/style-0000000000000000.css");
        assert_eq!(stale.status_code(), 200, "a stale URL still gets styles");
        assert!(stale
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("must-revalidate")));
    }

    #[test]
    fn the_link_points_at_the_current_sheet() {
        let css = ".a{color:red}";
        let tag = link(css);
        assert!(tag.starts_with("<link rel=\"stylesheet\" href=\"/_assets/style-"), "{tag}");
        assert!(tag.contains(&digest(css)), "{tag}");
    }
}
