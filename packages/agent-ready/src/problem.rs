//! RFC 9457 problem details — machine-shaped errors for every surface.
//!
//! Agents recover from legible failure; they flail at HTML error pages. This
//! module mirrors the platform's gate-code discipline outward: every error a
//! readiness-mounted app serves carries a stable machine-readable `code`, a
//! human-readable `title`/`detail`, and the standard RFC 9457 fields, as
//! `application/problem+json`.

use ferrite_app::serde_json::{self, Value};

/// The media type problem responses carry.
pub const CONTENT_TYPE: &str = "application/problem+json";

/// Build one problem-details body.
///
/// `code` is the stable machine class (e.g. `APP_NOT_FOUND`,
/// `APP_VALIDATION`, `APP_PAYMENT_REQUIRED`) — the field agents branch on.
/// `type` is derived from it as a fragmentless relative URI so every code
/// has a stable identifier without requiring a documentation host.
pub fn problem(status: u16, code: &str, title: &str, detail: &str) -> Value {
    serde_json::json!({
        "type": format!("urn:ferrite:problem:{}", code.to_ascii_lowercase()),
        "title": title,
        "status": status,
        "detail": detail,
        "code": code
    })
}

/// Serialize a problem to bytes for an `IngressReply` body.
pub fn problem_bytes(status: u16, code: &str, title: &str, detail: &str) -> Vec<u8> {
    ferrite_app::serde_json::to_vec(&problem(status, code, title, detail)).unwrap_or_default()
}

/// 404 with a stable code and a pointer at the discovery artefacts — a lost
/// agent's next step is orientation, so the problem says where that lives.
pub fn not_found(path: &str, origin: &str) -> (u16, Vec<u8>) {
    let mut p = problem(
        404,
        "APP_NO_ROUTE",
        "No such resource",
        &format!("nothing is served at '{path}'"),
    );
    p["llms_txt"] = serde_json::json!(format!("{origin}/llms.txt"));
    p["api_catalog"] = serde_json::json!(format!("{origin}/.well-known/api-catalog"));
    (404, ferrite_app::serde_json::to_vec(&p).unwrap_or_default())
}

/// 400 for malformed input.
pub fn bad_request(detail: &str) -> (u16, Vec<u8>) {
    (
        400,
        problem_bytes(400, "APP_VALIDATION", "Invalid request", detail),
    )
}

/// 405 for a method the route does not serve.
pub fn method_not_allowed(method: &str, path: &str) -> (u16, Vec<u8>) {
    (
        405,
        problem_bytes(
            405,
            "APP_METHOD",
            "Method not allowed",
            &format!("'{method}' is not served at '{path}'"),
        ),
    )
}

/// 500 for an internal failure (never leaks internals — the detail is the
/// caller-safe half; diagnostics go to the app's own telemetry).
pub fn internal(detail: &str) -> (u16, Vec<u8>) {
    (
        500,
        problem_bytes(500, "APP_INTERNAL", "Internal error", detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_shape() {
        let p = problem(404, "APP_NO_ROUTE", "No such resource", "nothing at /x");
        assert_eq!(p["status"], 404);
        assert_eq!(p["code"], "APP_NO_ROUTE");
        assert_eq!(p["type"], "urn:ferrite:problem:app_no_route");
        assert_eq!(p["title"], "No such resource");
    }

    #[test]
    fn not_found_points_at_discovery() {
        let (status, body) = not_found("/missing", "https://a.example");
        assert_eq!(status, 404);
        let v: Value = ferrite_app::serde_json::from_slice(&body).unwrap();
        assert_eq!(v["llms_txt"], "https://a.example/llms.txt");
        assert_eq!(
            v["api_catalog"],
            "https://a.example/.well-known/api-catalog"
        );
    }
}
