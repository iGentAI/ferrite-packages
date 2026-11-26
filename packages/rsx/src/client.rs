//! The client runtime asset: the browser half of instant navigation.
//!
//! The JavaScript is EMBEDDED in the application binary and served from
//! a content-addressed URL, so an app needs no object store, no CDN and
//! no build step to ship it — and the URL changes whenever the bytes do,
//! which is what makes `immutable` caching honest.

use ferrite_app::crypto;

use super::assets::hashed_asset_reply;
use super::server::Reply;

/// The client runtime source.
///
/// It lives in [`super::client_asset`] as a Rust CONSTANT rather than a
/// build-time file read: a constrained application may not read a file
/// while it is being built (the code gate refuses that with
/// `CODE_BUILD_TIME_READ`), so the JavaScript is materialized into
/// source by the compiler — the same discipline the platform's own
/// site-embedding path uses.
pub use super::client_asset::CLIENT_JS;

/// The URL prefix hashed immutable assets are served from (wire-v1 §1).
pub const ASSET_PREFIX: &str = "/_assets/client-";

/// The content-addressed URL of the client runtime.
pub fn client_url() -> String {
    format!("{ASSET_PREFIX}{}.js", client_digest())
}

/// The first 16 hex characters of the runtime's SHA-256.
pub fn client_digest() -> String {
    let digest = crypto::sha256(CLIENT_JS.as_bytes());
    crypto::hex(&digest)[..16].to_string()
}

/// Whether a path addresses the client runtime.
pub fn is_client_asset(path: &str) -> bool {
    path.starts_with(ASSET_PREFIX) && path.ends_with(".js")
}

/// Serve the client runtime.
///
/// A request for a DIFFERENT digest is answered with the current script
/// rather than a 404: an open tab holding a stale URL then upgrades
/// itself instead of losing its client runtime entirely. The response
/// is only marked immutable when the digest actually matches.
pub fn client_reply(path: &str) -> Reply {
    let current = client_digest();
    let exact = path == format!("{ASSET_PREFIX}{current}.js");
    hashed_asset_reply("text/javascript; charset=utf-8", &current, exact)
        .body(CLIENT_JS.as_bytes().to_vec())
}

/// The boot markup: the segment state the client resumes from, plus the
/// runtime itself.
///
/// The state rides a `application/rsx-state` script block — inert to
/// the browser, parsed by the runtime. Its JSON is escaped so a segment
/// id can never close the script element.
pub fn boot_markup(state_json: &str) -> String {
    let safe = state_json
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    format!(
        "<script type=\"application/rsx-state\">{safe}</script>\
<script src=\"{}\" defer></script>",
        client_url()
    )
}

/// Insert the boot markup into a rendered document.
///
/// Before `</body>` when there is one, else appended — a fragment that
/// is not a whole document still gets its runtime.
pub fn inject(document: &str, state_json: &str) -> String {
    let boot = boot_markup(state_json);
    match document.rfind("</body>") {
        Some(at) => {
            let mut out = String::with_capacity(document.len() + boot.len());
            out.push_str(&document[..at]);
            out.push_str(&boot);
            out.push_str(&document[at..]);
            out
        }
        None => format!("{document}{boot}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_asset_url_is_content_addressed() {
        let url = client_url();
        assert!(url.starts_with(ASSET_PREFIX) && url.ends_with(".js"), "{url}");
        assert!(is_client_asset(&url));
        assert!(!is_client_asset("/_assets/other.js"));
        assert!(!is_client_asset("/_assets/client-abc.css"));
        assert_eq!(url, client_url(), "stable across calls");
    }

    #[test]
    fn the_exact_digest_is_immutable_and_a_stale_one_is_not() {
        let reply = client_reply(&client_url());
        assert_eq!(reply.status_code(), 200);
        assert!(reply
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("immutable")));

        let stale = client_reply("/_assets/client-0000000000000000.js");
        assert_eq!(
            stale.status_code(),
            200,
            "a stale URL still gets a runtime"
        );
        assert!(stale
            .headers_for_test()
            .iter()
            .any(|(n, v)| n == "cache-control" && v.contains("must-revalidate")));
    }

    #[test]
    fn the_boot_state_cannot_close_its_own_script_element() {
        let markup = boot_markup("{\"x\":\"</script><script>alert(1)</script>\"}");
        assert!(
            !markup.contains("</script><script>alert(1)"),
            "escaped: {markup}"
        );
        assert!(markup.contains("\\u003c/script"), "{markup}");
    }

    #[test]
    fn injection_lands_before_the_body_close() {
        let doc = "<html><body><h1>x</h1></body></html>";
        let out = inject(doc, "{}");
        assert!(out.contains("<h1>x</h1><script type=\"application/rsx-state\">"));
        assert!(out.ends_with("</body></html>"));
        // A fragment still gets the runtime.
        assert!(inject("<p>x</p>", "{}").contains("rsx-state"));
    }

    #[test]
    fn the_runtime_stays_within_its_size_budget() {
        // The published budget is 15 KB min+gzip; this raw ceiling is the
        // proxy a build without a minifier can hold down. Raised from 64 KiB
        // when the action token landed: the runtime measured 8.2 KB with
        // esbuild --minify and gzip -9 then (7.8 KB before).
        assert!(
            CLIENT_JS.len() < 72 * 1024,
            "the client runtime is {} bytes",
            CLIENT_JS.len()
        );
        assert!(CLIENT_JS.contains("__rsx"), "it is the real runtime");
    }
}
