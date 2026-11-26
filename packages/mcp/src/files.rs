//! Experimental MCP File Uploads and Downloads Extension (`io.modelcontextprotocol/files`).
//!
//! Client & server wire helpers plus strict §Targets security validation for
//! constrained Ferrite applications.

use ferrite_app::serde_json::{json, Value};

pub const EXTENSION: &str = "io.modelcontextprotocol/files";
pub const RESULT_UPLOAD_REQUIRED: &str = "upload_required";

/// Forbidden transfer headers (RFC/WHATWG + spec §Targets rules 3–4).
const ALWAYS_FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "host",
    "content-length",
    "date",
    "user-agent",
    "origin",
    "referer",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
    "via",
];

const INCLUDE_OR_PATH_FORBIDDEN_HEADERS: &[&str] = &[
    "forwarded",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

const FORM_FORBIDDEN_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "content-range",
    "content-digest",
    "repr-digest",
];

pub fn server_supports_upload(capabilities: &Value) -> bool {
    let Some(ext) = capabilities
        .get("extensions")
        .and_then(|e| e.get(EXTENSION))
        .and_then(Value::as_object)
    else {
        return false;
    };
    if ext.get("revision").is_some_and(|v| !v.is_null()) {
        return false;
    }
    ext.get("upload").is_some_and(Value::is_object)
}

pub fn server_max_inline_bytes(capabilities: &Value) -> u64 {
    let Some(ext) = capabilities
        .get("extensions")
        .and_then(|e| e.get(EXTENSION))
        .and_then(Value::as_object)
    else {
        return 0;
    };
    if ext.get("revision").is_some_and(|v| !v.is_null()) {
        return 0;
    }
    ext.get("maxInlineBytes")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

pub fn client_capability(upload: bool, download: bool) -> Value {
    let mut inner = ferrite_app::serde_json::Map::new();
    if upload {
        inner.insert("upload".into(), json!({}));
    }
    if download {
        inner.insert("download".into(), json!({}));
    }
    json!({ "extensions": { EXTENSION: Value::Object(inner) } })
}

pub fn sha256_b64url(bytes: &[u8]) -> String {
    crate::mcp::b64::encode_url(&crate::mcp::sha256::sha256(bytes))
}

/// Extract `_meta["io.modelcontextprotocol/files"]["downloads"]` from a `CallToolResult`.
pub fn downloads_in_result(result: &Value) -> Vec<&Value> {
    result
        .get("_meta")
        .and_then(|m| m.get(EXTENSION))
        .and_then(|f| f.get("downloads"))
        .and_then(Value::as_array)
        .map(|arr| arr.iter().collect())
        .unwrap_or_default()
}

/// Validate a target `path` against §Targets rule 2: `1*( "/" segment )`, no `.` or `..`.
pub fn valid_target_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('/').all(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'~' | b'.'))
    })
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.split('.');
    let mut out = [0u8; 4];
    for slot in &mut out {
        let p = parts.next()?;
        if p.is_empty() || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        *slot = p.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn is_private_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, ..] = octets;
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a >= 224
}

fn is_disallowed_ipv6(inner: &str) -> bool {
    // Reject anything that doesn't look like a public global unicast IPv6 literal
    // (loopback ::1, unspecified ::, ULA fc00::/7, link-local fe80::/10, multicast ff00::/8,
    // IPv4-mapped ::ffff:a.b.c.d / hex form, or malformed literals).
    let lower = inner.to_ascii_lowercase();
    if lower == "::" || lower == "::1" || lower.contains('%') {
        return true;
    }
    if let Some(rest) = lower.strip_prefix("::ffff:") {
        if let Some(v4) = parse_ipv4(rest) {
            return is_private_ipv4(v4);
        }
        // Hex-encoded IPv4-mapped (::ffff:7f00:0001) — block conservatively.
        return true;
    }
    let first_group = lower.split(':').next().unwrap_or("");
    if first_group.is_empty() {
        // Leading "::" other than :: / ::1 (e.g. ::0:1 or IPv4-compatible) — block non-global.
        return true;
    }
    let Ok(hi) = u16::from_str_radix(first_group, 16) else {
        return true;
    };
    (hi & 0xfe00) == 0xfc00 || (hi & 0xffc0) == 0xfe80 || (hi & 0xff00) == 0xff00 || hi == 0
}

fn is_disallowed_target_host(host: &str) -> bool {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty()
        || lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "metadata.google.internal"
    {
        return true;
    }
    if let Some(inner) = lower.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return is_disallowed_ipv6(inner);
    }
    if let Some(v4) = parse_ipv4(&lower) {
        return is_private_ipv4(v4);
    }
    // Also reject numeric-only / hex / octal IPv4 tricks (e.g. 2130706433, 0x7f000001).
    if lower.chars().all(|c| c.is_ascii_digit())
        || lower.starts_with("0x")
        || lower
            .split('.')
            .all(|p| !p.is_empty() && (p.starts_with("0x") || p.bytes().all(|b| b.is_ascii_digit())))
    {
        return true;
    }
    false
}

/// Extract the RFC 6454 origin (`https://host[:port]`, lowercase, default `:443` stripped)
/// of a clean HTTPS URL, rejecting CRLF/control chars, backslashes, userinfo, fragments,
/// and invalid host[:port] syntax.
fn https_origin(url: &str, reject_private_host: bool) -> Option<String> {
    if url.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b'\\') || url.contains('#') {
        return None;
    }
    if url.len() < 8 || !url[..8].eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &url[8..];
    let authority = rest.split(['/', '?']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let after = &authority[end + 1..];
        if after.is_empty() {
            (host, None)
        } else if let Some(p) = after.strip_prefix(':') {
            let port_num: u16 = p.parse().ok()?;
            if port_num == 0 {
                return None;
            }
            (host, Some(port_num))
        } else {
            return None;
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return None;
        }
        let port_num: u16 = p.parse().ok()?;
        if port_num == 0 {
            return None;
        }
        (h, Some(port_num))
    } else {
        (authority, None)
    };
    if host.is_empty() {
        return None;
    }
    if reject_private_host && is_disallowed_target_host(host) {
        return None;
    }
    let host_lower = host.to_ascii_lowercase();
    match port {
        None | Some(443) => Some(format!("https://{host_lower}")),
        Some(p) => Some(format!("https://{host_lower}:{p}")),
    }
}

/// Resolve a `path` target against an MCP endpoint URL per §Resolving `path`.
pub fn resolve_path(mcp_address: &str, path: &str) -> Result<String, &'static str> {
    if !valid_target_path(path) {
        return Err("invalid target path");
    }
    let (base, query) = match mcp_address.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (mcp_address, None),
    };
    let base = base.trim_end_matches('/');
    let mut resolved = format!("{base}{path}");
    if let Some(q) = query {
        resolved.push('?');
        resolved.push_str(q);
    }
    Ok(resolved)
}

/// Validate an `UploadTarget` or `DownloadTarget` against §Targets rules 1–5
/// and §Credentials same-origin enforcement.
pub fn validate_target(
    target: &Value,
    canonical_server_uri: &str,
    is_upload: bool,
) -> Result<(), &'static str> {
    let obj = target.as_object().ok_or("target must be an object")?;
    let has_url = obj.get("url").is_some_and(|v| !v.is_null());
    let has_path = obj.get("path").is_some_and(|v| !v.is_null());
    if has_url == has_path {
        return Err("target must have exactly one of url or path");
    }
    let creds = obj
        .get("credentials")
        .and_then(Value::as_str)
        .ok_or("target missing credentials")?;
    if !matches!(creds, "omit" | "include") {
        return Err("target credentials must be omit or include");
    }
    if has_path {
        let path = obj
            .get("path")
            .and_then(Value::as_str)
            .ok_or("target path must be a string")?;
        if !valid_target_path(path) {
            return Err("invalid target path");
        }
    } else {
        let url = obj
            .get("url")
            .and_then(Value::as_str)
            .ok_or("target url must be a string")?;
        let target_origin =
            https_origin(url, true).ok_or("target url must be public https without userinfo or control chars")?;
        if creds == "include" {
            let server_origin = https_origin(canonical_server_uri, false)
                .ok_or("canonical server URI must be https")?;
            if target_origin != server_origin {
                return Err("credentials: include target must match server origin");
            }
        }
    }

    let has_form = is_upload && obj.get("form").is_some_and(|v| !v.is_null());
    if is_upload {
        if obj
            .get("fileId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("upload target missing fileId");
        }
        let method = match obj.get("method") {
            None | Some(Value::Null) => "PUT",
            Some(Value::String(m)) => m.as_str(),
            Some(_) => return Err("upload target method must be a string"),
        };
        if !matches!(method, "PUT" | "POST") {
            return Err("upload target method must be PUT or POST");
        }
        if has_form && method != "POST" {
            return Err("form upload target requires method POST");
        }
    } else if obj.get("size").and_then(Value::as_u64).is_none()
        || obj.get("mimeType").and_then(Value::as_str).is_none()
    {
        return Err("download target requires mimeType and size");
    }

    if let Some(headers) = obj.get("headers").filter(|v| !v.is_null()) {
        let hdrs = headers
            .as_object()
            .ok_or("target headers must be an object")?;
        for (name, val) in hdrs {
            let Some(v) = val.as_str() else {
                return Err("target header value must be a string");
            };
            if name.is_empty()
                || name.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b':')
                || v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                return Err("invalid target header name or value");
            }
            let lower = name.to_ascii_lowercase();
            if ALWAYS_FORBIDDEN_HEADERS.contains(&lower.as_str())
                || lower.starts_with("proxy-")
                || lower.starts_with("sec-")
            {
                return Err("target lists a forbidden header");
            }
            if (has_path || creds == "include")
                && (INCLUDE_OR_PATH_FORBIDDEN_HEADERS.contains(&lower.as_str())
                    || lower.starts_with("x-forwarded-"))
            {
                return Err("target lists a forbidden proxy header");
            }
            if has_form && FORM_FORBIDDEN_HEADERS.contains(&lower.as_str()) {
                return Err("form target lists a forbidden content header");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_validation_enforces_security_boundaries() {
        let ok_path = json!({
            "fileId": "f1",
            "path": "/files/upload/slot1",
            "credentials": "include",
            "headers": {"Content-Type": "application/octet-stream"}
        });
        validate_target(&ok_path, "https://mcp.ferrite.cloud/mcp", true).unwrap();

        // Cross-origin include MUST be rejected.
        let cross_origin = json!({
            "fileId": "f1",
            "url": "https://evil.example/upload",
            "credentials": "include"
        });
        assert!(validate_target(&cross_origin, "https://mcp.ferrite.cloud/mcp", true).is_err());

        // Forbidden Authorization header MUST be rejected.
        let bad_hdr = json!({
            "fileId": "f1",
            "url": "https://storage.example/u1",
            "credentials": "omit",
            "headers": {"Authorization": "Bearer stolen"}
        });
        assert!(validate_target(&bad_hdr, "https://mcp.ferrite.cloud/mcp", true).is_err());

        // Traversal path MUST be rejected.
        assert!(!valid_target_path("/files/../secret"));
        assert_eq!(
            resolve_path("https://mcp.ferrite.cloud/mcp?v=1", "/files/download/abc").unwrap(),
            "https://mcp.ferrite.cloud/mcp/files/download/abc?v=1"
        );

        // Default :443 port normalizes to same origin for credentials: include.
        let explicit_443 = json!({
            "fileId": "f1",
            "url": "https://mcp.ferrite.cloud:443/mcp/files/upload/slot1",
            "credentials": "include"
        });
        validate_target(&explicit_443, "https://mcp.ferrite.cloud/mcp", true).unwrap();

        // CRLF, backslash, loopback, private, and cloud metadata targets MUST be rejected.
        for bad_url in [
            "https://storage.example/u1\r\nX-Injected: 1",
            "https://storage.example\\u1",
            "https://127.0.0.1/u1",
            "https://localhost/u1",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/u1",
            "https://10.0.0.5/u1",
            "https://2130706433/u1",
        ] {
            let t = json!({"fileId": "f1", "url": bad_url, "credentials": "omit"});
            assert!(
                validate_target(&t, "https://mcp.ferrite.cloud/mcp", true).is_err(),
                "expected rejection for {bad_url}"
            );
        }

        // Non-string method MUST be rejected instead of silently defaulting to PUT.
        let bad_method = json!({
            "fileId": "f1",
            "path": "/files/upload/slot1",
            "method": 123,
            "credentials": "include"
        });
        assert!(validate_target(&bad_method, "https://mcp.ferrite.cloud/mcp", true).is_err());

        // Unknown revision disables server_max_inline_bytes too.
        assert_eq!(
            server_max_inline_bytes(&json!({
                "extensions": {EXTENSION: {"maxInlineBytes": 1024, "revision": "v2"}}
            })),
            0
        );
    }
}
