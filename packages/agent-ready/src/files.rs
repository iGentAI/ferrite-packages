//! Experimental MCP File Uploads and Downloads Extension (`io.modelcontextprotocol/files`).
//!
//! Implements the draft specification in
//! `modelcontextprotocol/experimental-ext-file-uploads` (`specification/draft/file-uploads.md`)
//! for constrained Ferrite applications:
//! - `x-mcp-file` argument schema builder matching Claude's connector rules;
//! - Capability negotiation (`upload`, `download`, `maxInlineBytes`, unknown `revision`);
//! - Inline (`data`) and empty-file (`size == 0`) decoding with exact size and
//!   SHA-256 (`base64url`, unpadded) digest verification;
//! - Out-of-band `upload_required` MRTR result (`UploadTarget`, sealed `requestState`
//!   with `upload_issued: true` so a second upload request is never returned);
//! - Out-of-band download targets attached in `_meta["io.modelcontextprotocol/files"].downloads`
//!   plus HTTP `Range` (`206 Partial Content`) helper for `GET` download routes.

use std::collections::BTreeSet;

use ferrite_app::crypto::base64url_encode;
use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::elicitation::{
    args_digest, open_state_with_domain, seal_state_with_domain, ElicitationError, SealedState,
};

const UPLOAD_STATE_DOMAIN: &[u8] = b"ferrite/mcp-upload-state/v1:";

pub const EXTENSION: &str = "io.modelcontextprotocol/files";
pub const RESULT_UPLOAD_REQUIRED: &str = "upload_required";
pub const DEFAULT_MAX_INLINE_BYTES: u64 = 1_048_576;

/// Server-side advertisement under `capabilities.extensions["io.modelcontextprotocol/files"]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilesConfig {
    /// Whether the server accepts out-of-band uploads (`upload_required`).
    pub upload: bool,
    /// Maximum total decoded inline bytes accepted per request (`None` or `0` disables inline).
    pub max_inline_bytes: Option<u64>,
    /// Whether the server can attach download targets (`_meta`).
    pub download: bool,
}

impl FilesConfig {
    pub fn enabled(&self) -> bool {
        self.upload || self.download || self.max_inline_bytes.is_some_and(|n| n > 0)
    }

    /// JSON object advertised in `server/discover` under `capabilities.extensions`.
    pub fn capability_value(&self) -> Value {
        let mut obj = Map::new();
        if self.upload {
            obj.insert("upload".into(), serde_json::json!({}));
        }
        if let Some(max) = self.max_inline_bytes.filter(|&n| n > 0) {
            obj.insert("maxInlineBytes".into(), serde_json::json!(max));
        }
        Value::Object(obj)
    }
}

/// Client-declared file capabilities on one `2026-07-28` request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientFileCaps {
    pub declared: bool,
    pub upload: bool,
    pub download: bool,
}

/// Parse `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions["io.modelcontextprotocol/files"]`.
/// Per spec, an unrecognized `revision` string disables the extension.
pub fn client_caps(params: &Value) -> ClientFileCaps {
    let Some(ext) = params
        .pointer("/_meta/io.modelcontextprotocol~1clientCapabilities/extensions/io.modelcontextprotocol~1files")
        .and_then(Value::as_object)
    else {
        return ClientFileCaps::default();
    };
    if ext.get("revision").is_some_and(|v| !v.is_null()) {
        return ClientFileCaps::default();
    }
    ClientFileCaps {
        declared: true,
        upload: ext.get("upload").is_some_and(Value::is_object),
        download: ext.get("download").is_some_and(Value::is_object),
    }
}

pub fn missing_upload_capability() -> ElicitationError {
    ElicitationError {
        code: -32021,
        message: "This client did not declare file upload support, so the tool did not run.".into(),
        data: Some(serde_json::json!({
            "requiredCapabilities": {
                "extensions": { EXTENSION: { "upload": {} } }
            }
        })),
    }
}

pub fn missing_download_capability() -> ElicitationError {
    ElicitationError {
        code: -32021,
        message: "This client did not declare file download support, so the tool did not run."
            .into(),
        data: Some(serde_json::json!({
            "requiredCapabilities": {
                "extensions": { EXTENSION: { "download": {} } }
            }
        })),
    }
}

/// Build an `x-mcp-file` JSON Schema property matching the extension spec and
/// Claude's connector schema expectations verbatim.
pub fn file_input_schema(
    accept: &[&str],
    max_size: Option<u64>,
    require_digest: bool,
    description: Option<&str>,
) -> Value {
    let mut x_file = Map::new();
    if !accept.is_empty() {
        x_file.insert("accept".into(), serde_json::json!(accept));
    }
    if let Some(max) = max_size {
        x_file.insert("maxSize".into(), serde_json::json!(max));
    }
    let mut required = vec!["id", "mimeType", "size"];
    if require_digest {
        required.push("digest");
    }
    let mut schema = serde_json::json!({
        "type": "object",
        "x-mcp-file": Value::Object(x_file),
        "properties": {
            "id": { "type": "string", "minLength": 1, "maxLength": 128 },
            "name": { "type": "string" },
            "mimeType": { "type": "string" },
            "size": { "type": "integer", "minimum": 0 },
            "digest": {
                "type": "object",
                "properties": {
                    "algorithm": { "const": "sha-256" },
                    "value": { "type": "string" }
                },
                "required": ["algorithm", "value"]
            },
            "data": { "type": "string" }
        },
        "required": required
    });
    if let Some(desc) = description {
        schema["description"] = serde_json::json!(desc);
    }
    schema
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileInput {
    pub id: String,
    pub name: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub sha256_b64url: Option<String>,
    /// `Some(bytes)` for inline transfer or empty (`size == 0`) files;
    /// `None` when `size > 0` and `data` was omitted (needs out-of-band upload).
    pub inline_bytes: Option<Vec<u8>>,
}

/// Compute the spec's SHA-256 digest representation: unpadded base64url over raw bytes.
pub fn sha256_b64url(bytes: &[u8]) -> String {
    base64url_encode(&super::sha256::sha256(bytes))
}

/// Verify raw file bytes against declared `size` and optional `digest`.
pub fn verify_bytes(bytes: &[u8], expected_size: u64, expected_digest: Option<&str>) -> Result<(), &'static str> {
    if bytes.len() as u64 != expected_size {
        return Err("uploaded file size does not match declared size");
    }
    if let Some(want) = expected_digest {
        let got = sha256_b64url(bytes);
        if got != want {
            return Err("uploaded file SHA-256 digest does not match declared digest");
        }
    }
    Ok(())
}

/// Parse and validate one `FileInput` argument object.
pub fn parse_file_input(
    value: &Value,
    max_size: Option<u64>,
    max_inline_bytes: u64,
    require_digest: bool,
) -> Result<FileInput, &'static str> {
    let obj = value.as_object().ok_or("file argument must be an object")?;
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or("file.id must be 1..=128 characters")?
        .to_string();
    let name = match obj.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("file.name must be a string"),
    };
    let mime_type = obj
        .get("mimeType")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("file.mimeType must be a non-empty string")?
        .to_string();
    let size = obj
        .get("size")
        .and_then(Value::as_u64)
        .ok_or("file.size must be a non-negative integer")?;
    if let Some(limit) = max_size {
        if size > limit {
            return Err("file exceeds tool maxSize");
        }
    }
    let sha256_b64url_opt = match obj.get("digest") {
        None | Some(Value::Null) => {
            if require_digest {
                return Err("file.digest is required");
            }
            None
        }
        Some(d) => {
            if d.get("algorithm").and_then(Value::as_str) != Some("sha-256") {
                return Err("file.digest.algorithm must be \"sha-256\"");
            }
            let val = d
                .get("value")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && !s.contains('='))
                .ok_or("file.digest.value must be unpadded base64url")?;
            Some(val.to_string())
        }
    };

    let inline_bytes = match obj.get("data") {
        Some(Value::Null) => return Err("file.data must not be null"),
        Some(Value::String(b64)) => {
            if size == 0 && b64.is_empty() {
                verify_bytes(&[], 0, sha256_b64url_opt.as_deref())?;
                Some(Vec::new())
            } else {
                if max_inline_bytes == 0 || size > max_inline_bytes {
                    return Err("inline file data exceeds maxInlineBytes");
                }
                let max_b64_len = (max_inline_bytes as usize)
                    .div_ceil(3)
                    .saturating_mul(4);
                if b64.len() > max_b64_len {
                    return Err("inline file base64 payload exceeds maxInlineBytes");
                }
                let decoded = decode_std_b64(b64).ok_or("file.data is not valid base64")?;
                verify_bytes(&decoded, size, sha256_b64url_opt.as_deref())?;
                Some(decoded)
            }
        }
        Some(_) => return Err("file.data must be a base64 string"),
        None => {
            if size == 0 {
                verify_bytes(&[], 0, sha256_b64url_opt.as_deref())?;
                Some(Vec::new())
            } else {
                None
            }
        }
    };

    Ok(FileInput {
        id,
        name,
        mime_type,
        size,
        sha256_b64url: sha256_b64url_opt,
        inline_bytes,
    })
}

/// Check that every `FileInput.id` in a call is unique and total inline bytes
/// stay within `max_inline_bytes`.
pub fn check_file_batch(files: &[FileInput], max_inline_bytes: u64) -> Result<(), &'static str> {
    let mut ids = BTreeSet::new();
    let mut inline_total: u64 = 0;
    for f in files {
        if !ids.insert(f.id.as_str()) {
            return Err("duplicate file id in tool arguments");
        }
        if let Some(bytes) = &f.inline_bytes {
            if !bytes.is_empty() {
                inline_total = inline_total.saturating_add(bytes.len() as u64);
                if inline_total > max_inline_bytes {
                    return Err("total inline file bytes exceed maxInlineBytes");
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadTarget {
    pub file_id: String,
    pub path: Option<String>,
    pub url: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub credentials: &'static str,
    pub expires_at: Option<String>,
}

impl UploadTarget {
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("fileId".into(), serde_json::json!(self.file_id));
        if let Some(url) = &self.url {
            obj.insert("url".into(), serde_json::json!(url));
        } else if let Some(path) = &self.path {
            obj.insert("path".into(), serde_json::json!(path));
        }
        if self.method != "PUT" {
            obj.insert("method".into(), serde_json::json!(self.method));
        }
        if !self.headers.is_empty() {
            let mut hdrs = Map::new();
            for (k, v) in &self.headers {
                hdrs.insert(k.clone(), serde_json::json!(v));
            }
            obj.insert("headers".into(), Value::Object(hdrs));
        }
        obj.insert("credentials".into(), serde_json::json!(self.credentials));
        if let Some(exp) = &self.expires_at {
            obj.insert("expiresAt".into(), serde_json::json!(exp));
        }
        Value::Object(obj)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadTarget {
    pub name: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub sha256_b64url: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub headers: Vec<(String, String)>,
    pub credentials: &'static str,
    pub expires_at: Option<String>,
}

impl DownloadTarget {
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        if let Some(name) = &self.name {
            obj.insert("name".into(), serde_json::json!(name));
        }
        obj.insert("mimeType".into(), serde_json::json!(self.mime_type));
        obj.insert("size".into(), serde_json::json!(self.size));
        if let Some(digest) = &self.sha256_b64url {
            obj.insert(
                "digest".into(),
                serde_json::json!({"algorithm": "sha-256", "value": digest}),
            );
        }
        if let Some(url) = &self.url {
            obj.insert("url".into(), serde_json::json!(url));
        } else if let Some(path) = &self.path {
            obj.insert("path".into(), serde_json::json!(path));
        }
        if !self.headers.is_empty() {
            let mut hdrs = Map::new();
            for (k, v) in &self.headers {
                hdrs.insert(k.clone(), serde_json::json!(v));
            }
            obj.insert("headers".into(), Value::Object(hdrs));
        }
        obj.insert("credentials".into(), serde_json::json!(self.credentials));
        if let Some(exp) = &self.expires_at {
            obj.insert("expiresAt".into(), serde_json::json!(exp));
        }
        Value::Object(obj)
    }
}

/// Build an `UploadRequiredResult` (`resultType: "upload_required"`) sealing
/// `uploadIssued: true` and target slots into `requestState`.
pub fn upload_required_result(
    secret: &[u8],
    tool: &str,
    arguments: &Value,
    principal: &str,
    nonce: &str,
    expires_ms: u64,
    uploads: &[UploadTarget],
    slot_map: Value,
) -> Result<Value, &'static str> {
    if uploads.is_empty() {
        return Err("upload_required must list at least one UploadTarget");
    }
    let state = SealedState {
        tool: tool.to_string(),
        args_sha256: args_digest(arguments),
        principal: principal.to_string(),
        nonce: nonce.to_string(),
        expires_ms,
        context: serde_json::json!({
            "uploadIssued": true,
            "slots": slot_map,
        }),
    };
    let request_state = seal_state_with_domain(secret, UPLOAD_STATE_DOMAIN, &state)?;
    Ok(serde_json::json!({
        "resultType": RESULT_UPLOAD_REQUIRED,
        "uploads": uploads.iter().map(UploadTarget::to_json).collect::<Vec<_>>(),
        "requestState": request_state,
    }))
}

/// Verify an upload retry's `requestState` and confirm it came from an issued
/// upload request.
pub fn verify_upload_retry(
    secret: &[u8],
    request_state: &str,
    tool: &str,
    arguments: &Value,
    principal: &str,
    now_ms: u64,
) -> Result<SealedState, ElicitationError> {
    let state = open_state_with_domain(
        secret,
        UPLOAD_STATE_DOMAIN,
        request_state,
        tool,
        arguments,
        principal,
        now_ms,
    )?;
    if state.context.get("uploadIssued") != Some(&Value::Bool(true)) {
        return Err(ElicitationError::invalid_params(
            "requestState does not belong to an upload request",
        ));
    }
    Ok(state)
}

/// Attach `DownloadTarget` entries to a `CallToolResult`'s `_meta`.
pub fn attach_downloads(result: &mut Value, downloads: &[DownloadTarget]) {
    if downloads.is_empty() {
        return;
    }
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    let meta = obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    meta[EXTENSION] = serde_json::json!({
        "downloads": downloads.iter().map(DownloadTarget::to_json).collect::<Vec<_>>()
    });
}

/// Parse a single HTTP `Range: bytes=start-end` header against a file of `total` bytes.
/// Returns `Some((start, end_inclusive))` for a satisfiable range, `None` for invalid/multi-range.
pub fn parse_byte_range(header: &str, total: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }
    let trimmed = header.trim();
    if trimmed.len() < 6 || !trimmed[..6].eq_ignore_ascii_case("bytes=") {
        return None;
    }
    let spec = trimmed[6..].trim();
    if spec.contains(',') {
        return None;
    }
    let (start_s, end_s) = spec.split_once('-')?;
    if start_s.is_empty() {
        let suffix: usize = end_s.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        let start = total.saturating_sub(suffix);
        return Some((start, total - 1));
    }
    let start: usize = start_s.parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if end_s.is_empty() {
        total - 1
    } else {
        end_s.parse::<usize>().ok()?.min(total - 1)
    };
    if start > end {
        return None;
    }
    Some((start, end))
}

fn decode_std_b64(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut data_len = bytes.len();
    while data_len > 0 && bytes[data_len - 1] == b'=' {
        data_len -= 1;
    }
    let pad = bytes.len() - data_len;
    let data = &bytes[..data_len];
    if data.contains(&b'=') || pad > 2 {
        return None;
    }
    if data_len == 0 {
        return if pad == 0 { Some(Vec::new()) } else { None };
    }
    let rem = data_len % 4;
    if rem == 1 {
        return None;
    }
    if pad > 0 && ((rem == 2 && pad != 2) || (rem == 3 && pad != 1) || rem == 0) {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data_len / 4 * 3 + 3);
    for &c in data {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (acc & ((1u32 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json::json;

    #[test]
    fn capability_negotiation_and_unknown_revision() {
        let both = json!({
            "_meta": {"io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/files": {"upload": {}, "download": {}}}
            }}
        });
        let caps = client_caps(&both);
        assert!(caps.declared && caps.upload && caps.download);

        let future = json!({
            "_meta": {"io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/files": {"upload": {}, "revision": "v2"}}
            }}
        });
        assert!(!client_caps(&future).declared);
    }

    #[test]
    fn inline_empty_and_out_of_band_file_inputs_validate_strictly() {
        let payload = b"hello pdf";
        let digest = sha256_b64url(payload);
        let inline = json!({
            "id": "f1",
            "name": "doc.pdf",
            "mimeType": "application/pdf",
            "size": payload.len(),
            "digest": {"algorithm": "sha-256", "value": digest},
            "data": "aGVsbG8gcGRm"
        });
        let parsed = parse_file_input(&inline, Some(1024), 1024, true).unwrap();
        assert_eq!(parsed.inline_bytes.as_deref(), Some(payload.as_slice()));

        // Empty file has no target and accepts absent data.
        let empty = json!({"id": "f0", "mimeType": "text/plain", "size": 0});
        let parsed_empty = parse_file_input(&empty, Some(1024), 0, false).unwrap();
        assert_eq!(parsed_empty.inline_bytes.as_deref(), Some(&[][..]));

        // Non-empty without data -> needs out-of-band upload.
        let oob = json!({"id": "f2", "mimeType": "application/pdf", "size": 5000});
        let parsed_oob = parse_file_input(&oob, Some(10_000), 1024, false).unwrap();
        assert!(parsed_oob.inline_bytes.is_none());

        // Null data is rejected per spec.
        assert!(parse_file_input(
            &json!({"id": "f3", "mimeType": "text/plain", "size": 1, "data": null}),
            None,
            1024,
            false
        )
        .is_err());

        // Wrong digest rejected.
        assert!(parse_file_input(
            &json!({
                "id": "f4",
                "mimeType": "text/plain",
                "size": 9,
                "digest": {"algorithm": "sha-256", "value": "wrong"},
                "data": "aGVsbG8gcGRm"
            }),
            None,
            1024,
            true
        )
        .is_err());
    }

    #[test]
    fn upload_required_and_download_targets_round_trip() {
        let secret = b"upload-secret-key-0123456789abcd";
        let args = json!({"file": {"id": "f1", "mimeType": "application/pdf", "size": 4096}});
        let target = UploadTarget {
            file_id: "f1".into(),
            path: Some("/files/upload/slot1".into()),
            url: None,
            method: "PUT".into(),
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            credentials: "include",
            expires_at: Some("2026-11-24T22:00:00Z".into()),
        };
        let res = upload_required_result(
            secret,
            "save_file",
            &args,
            "user-1",
            "nonce-1",
            20_000,
            &[target],
            json!({"f1": "slot1"}),
        )
        .unwrap();
        assert_eq!(res["resultType"], "upload_required");
        let state_str = res["requestState"].as_str().unwrap();
        let verified = verify_upload_retry(secret, state_str, "save_file", &args, "user-1", 10_000).unwrap();
        assert_eq!(verified.context["slots"]["f1"], "slot1");

        // Domain separation: an upload requestState MUST NOT open as an elicitation state.
        assert!(crate::agent_ready::elicitation::open_state(
            secret,
            state_str,
            "save_file",
            &args,
            "user-1",
            10_000,
        )
        .is_err());

        // Oversized base64 string for small declared size rejected before decode.
        let big_b64 = "A".repeat(4096);
        assert!(parse_file_input(
            &json!({"id": "f5", "mimeType": "text/plain", "size": 1, "data": big_b64}),
            None,
            64,
            false
        )
        .is_err());

        let mut tool_res = json!({"resultType": "complete", "content": [{"type": "text", "text": "ok"}]});
        attach_downloads(
            &mut tool_res,
            &[DownloadTarget {
                name: Some("export.csv".into()),
                mime_type: "text/csv".into(),
                size: 12,
                sha256_b64url: Some(sha256_b64url(b"a,b\n1,2\n3,4\n")),
                path: Some("/files/download/tok1".into()),
                url: None,
                headers: vec![],
                credentials: "include",
                expires_at: Some("2026-11-24T22:00:00Z".into()),
            }],
        );
        assert_eq!(
            tool_res["_meta"][EXTENSION]["downloads"][0]["name"],
            "export.csv"
        );
    }

    #[test]
    fn byte_range_parsing() {
        assert_eq!(parse_byte_range("bytes=0-9", 100), Some((0, 9)));
        assert_eq!(parse_byte_range("BYTES=0-9", 100), Some((0, 9)));
        assert_eq!(parse_byte_range("bytes=50-", 100), Some((50, 99)));
        assert_eq!(parse_byte_range("bytes=-10", 100), Some((90, 99)));
        assert_eq!(parse_byte_range("bytes=100-110", 100), None);
        assert_eq!(parse_byte_range("bytes=0-1,2-3", 100), None);
    }
}
