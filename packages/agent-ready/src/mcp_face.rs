//! The MCP face — every agent-ready app is an MCP server.
//!
//! Projects the declared [`crate::agent_ready::surface::Surface`] operations
//! into MCP tools and answers the MCP Streamable HTTP surface (single `/mcp`
//! endpoint, JSON-RPC 2.0 POST bodies) in the platform's stateless shape:
//! every call arrives as one `IngressRequest` and leaves as one
//! `IngressReply`, no session affinity, no server-held state — exactly the
//! shape MCP's stateless core is designed for.
//!
//! # Two revisions, one face
//!
//! The face speaks **2026-07-28** ([`PROTOCOL_VERSION`]) and still answers
//! the released **2025-11-25** wire ([`LEGACY_PROTOCOL_VERSION`]) for the
//! clients in the field that have not moved. Both are stateless here, so the
//! same request handling serves both; what differs is the envelope each
//! revision requires and the shape of its results:
//!
//! | | 2026-07-28 | 2025-11-25 |
//! | --- | --- | --- |
//! | lifecycle | none; `server/discover` describes the server | `initialize`, `notifications/initialized` |
//! | per request | `params._meta` carries the protocol version and the client capabilities (both required) | nothing |
//! | headers | `MCP-Protocol-Version` MUST equal `_meta`; `Mcp-Method` and `Mcp-Name` mirror the body (SEP-2243) | `MCP-Protocol-Version` after initialize |
//! | results | carry `resultType: "complete"`; list results carry `ttlMs` and `cacheScope` (SEP-2549) | plain |
//! | unknown or removed method (`initialize`, `ping`, …) | `-32601` with HTTP 404 (SEP-2575) | `-32601` with HTTP 200 |
//! | version refused | `-32022` with `supported` and `requested` | `-32600` with `supported` |
//!
//! **How a request's revision is decided.** The body is authoritative: a
//! request whose `params._meta` names a protocol version is a 2026-07-28
//! request and is held to that revision's rules; a request without `_meta`
//! is a 2025-11-25 request (the header, when present, must then be
//! `2025-11-25` or absent — a bare `2026-07-28` header on a `_meta`-less
//! body is a malformed 2026-07-28 request, `-32602`). This is what lets one
//! endpoint serve both populations without a handshake to remember.
//!
//! **SEP-2243 mirrored headers.** A hosted app receives only the headers its
//! route declares in `forward_headers`, so the face cannot tell "the client
//! omitted `Mcp-Method`" from "the host did not forward it". It therefore
//! checks a mirrored header when it is present and refuses a disagreement
//! with `-32020`, but tolerates absence. A host that forwards `mcp-method`
//! and `mcp-name` gets the full check; one that does not still gets a
//! correct server, minus a refusal the specification asks for. `Mcp-Name`
//! mirrors `params.name` and so is compared only on `tools/call`; on any
//! other method it mirrors nothing and is ignored rather than refused, so a
//! front that sets it unconditionally does not break `tools/list`.
//!
//! Supported methods: `server/discover` (2026-07-28); `initialize`,
//! `notifications/initialized` and `ping` (2025-11-25 only: 2026-07-28
//! removed the lifecycle methods and `ping` with them, so under that
//! revision `initialize` and `ping` are removed methods, 404 with `-32601`,
//! and a `notifications/initialized` is simply a notification, accepted
//! with 202 like any other); `tools/list`, `tools/call`. Tool execution is
//! delegated to the host app
//! through the [`ToolExec`] callback so the package stays host-agnostic: the
//! same handler that answers the plain HTTP operation answers its MCP twin.

use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::surface::Surface;

/// The MCP protocol revision this face prefers and advertises first.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The released revision this face keeps answering for clients that have
/// not adopted [`PROTOCOL_VERSION`]: the `initialize` handshake, no
/// per-request `_meta`, plain results.
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

/// Every revision this face serves, preferred first.
pub const SUPPORTED_VERSIONS: &[&str] = &[PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION];

/// Earlier released revisions whose tool, resource and prompt calls are the
/// 2025-11-25 wire for everything this face serves. Clients that still send
/// them (Claude.ai and Claude Desktop custom connectors among them) are
/// answered as 2025-11-25 calls, and `initialize` echoes the version they
/// asked for, so the session is not refused at its first `tools/list`.
pub const COMPATIBLE_LEGACY_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26"];

fn served_header(v: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&v) || COMPATIBLE_LEGACY_VERSIONS.contains(&v)
}

/// JSON-RPC error codes used by this face.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// 2026-07-28: an HTTP header disagrees with the body it mirrors.
pub const HEADER_MISMATCH: i64 = -32020;
/// 2026-07-28: the request's protocol version is not one this face serves.
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// 2026-07-28 `_meta` keys, quoted verbatim from the schema.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The request headers the face reads (lowercase; hosts forward them so).
pub const HEADER_PROTOCOL_VERSION: &str = "mcp-protocol-version";
pub const HEADER_METHOD: &str = "mcp-method";
pub const HEADER_NAME: &str = "mcp-name";

/// 2026-07-28 `resultType` for a finished result. This face never needs
/// input from the client, so it is the only value it ever sends.
pub const RESULT_COMPLETE: &str = "complete";

/// How long a 2026-07-28 client may cache `server/discover` and
/// `tools/list` (SEP-2549). The surface is a compile-time declaration, so a
/// minute is conservative; both results are the same for every caller and
/// are marked shareable.
pub const LIST_TTL_MS: u64 = 60_000;

/// The request headers the face consults, already extracted by the host.
///
/// `None` means the header did not reach the face — not sent, or not in the
/// route's `forward_headers` — and the face cannot tell which; see the
/// module notes on SEP-2243.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestHeaders<'a> {
    /// `MCP-Protocol-Version`.
    pub protocol_version: Option<&'a str>,
    /// `Mcp-Method` (SEP-2243), mirroring the body's `method`.
    pub method: Option<&'a str>,
    /// `Mcp-Name` (SEP-2243), mirroring a `tools/call`'s `params.name`.
    pub name: Option<&'a str>,
}

impl<'a> RequestHeaders<'a> {
    /// Only the protocol version — the shape [`handle`] has always taken.
    pub fn version(protocol_version: Option<&'a str>) -> Self {
        Self {
            protocol_version,
            method: None,
            name: None,
        }
    }

    /// Read the three headers from a forwarded header list (names compared
    /// case-insensitively; the first occurrence wins).
    pub fn from_list(headers: &'a [(String, String)]) -> Self {
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        Self {
            protocol_version: get(HEADER_PROTOCOL_VERSION),
            method: get(HEADER_METHOD),
            name: get(HEADER_NAME),
        }
    }
}

/// Which revision's rules a request is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revision {
    /// 2026-07-28: `_meta` on every request, `resultType` on every result.
    Current,
    /// 2025-11-25: the released wire, unchanged.
    Legacy,
}

/// The outcome of one tool execution, produced by the host app.
pub struct ToolOutcome {
    /// Machine-readable JSON result (becomes `structuredContent` and, unless
    /// explicit blocks are given, the text content block).
    pub value: Value,
    /// True ⇒ the tool ran and failed (MCP `isError`, not a protocol error).
    pub is_error: bool,
    /// Explicit MCP content blocks (`text`, `image`, `audio`, `resource`,
    /// `resource_link`), when the host has something better than the JSON
    /// text rendering of `value`. `None` ⇒ the face renders `value` as one
    /// text block.
    pub content: Option<Vec<Value>>,
}

impl ToolOutcome {
    /// A successful outcome carrying `value`.
    pub fn ok(value: Value) -> Self {
        Self {
            value,
            is_error: false,
            content: None,
        }
    }
    /// A failed-tool outcome carrying a machine-readable error value.
    pub fn err(value: Value) -> Self {
        Self {
            value,
            is_error: true,
            content: None,
        }
    }
    /// Replace the rendered content with explicit MCP content blocks. Each
    /// block must be an object with a string `type`; the face accepts the
    /// type verbatim (forward-compatible with new block kinds) and does NOT
    /// check the per-type fields (`text`, `data`/`mimeType`, `resource`,
    /// `uri`): those stay the host's responsibility. Blocks without a
    /// string `type` are dropped, and an empty result falls back to the
    /// text rendering so a reply never carries an empty or malformed
    /// `content` array. `structuredContent` still follows `value`.
    pub fn with_content(mut self, blocks: Vec<Value>) -> Self {
        let blocks: Vec<Value> = blocks
            .into_iter()
            .filter(|b| b.get("type").is_some_and(Value::is_string))
            .collect();
        self.content = (!blocks.is_empty()).then_some(blocks);
        self
    }
}

/// One MCP request, parsed enough to dispatch.
enum Parsed {
    /// A call with an id (expects a response).
    Call {
        id: Value,
        method: String,
        params: Value,
    },
    /// A notification (no `id` member — accepted, never answered).
    Notification,
    /// A JSON-RPC response the client sent back (no `method`, a valid id and
    /// exactly one of `result`/`error`) — accepted, never answered.
    ClientResponse,
    /// Malformed JSON-RPC.
    Invalid(String),
}

/// A request id MCP admits: a string or an integer. JSON-RPC 2.0 allows
/// `null` and fractional numbers; MCP narrows both away ("the ID MUST NOT be
/// null"), and a boolean, array or object was never an id.
fn valid_id(id: &Value) -> bool {
    id.is_string() || id.is_i64() || id.is_u64()
}

fn parse(body: &[u8]) -> Result<Parsed, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let obj = match v.as_object() {
        Some(o) => o,
        None => return Ok(Parsed::Invalid("request must be a JSON object".into())),
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Ok(Parsed::Invalid("jsonrpc must be \"2.0\"".into()));
    }
    let id = obj.get("id");
    if let Some(id) = id {
        if !valid_id(id) {
            return Ok(Parsed::Invalid("id must be a string or an integer".into()));
        }
    }
    let method = match obj.get("method") {
        Some(Value::String(m)) => m.clone(),
        Some(_) => return Ok(Parsed::Invalid("method must be a string".into())),
        None => {
            let has_result = obj.contains_key("result");
            let has_error = obj.contains_key("error");
            if id.is_some() && has_result != has_error {
                return Ok(Parsed::ClientResponse);
            }
            return Ok(Parsed::Invalid("method missing".into()));
        }
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    match id {
        None => Ok(Parsed::Notification),
        Some(id) => Ok(Parsed::Call {
            id: id.clone(),
            method,
            params,
        }),
    }
}

pub(crate) fn rpc_result(id: &Value, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub(crate) fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_error_data(id: &Value, code: i64, message: &str, data: Value) -> Value {
    let mut r = rpc_error(id, code, message);
    r["error"]["data"] = data;
    r
}

fn rpc_error_with(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    match data {
        Some(data) => rpc_error_data(id, code, message, data),
        None => rpc_error(id, code, message),
    }
}

pub(crate) fn json_reply(status: u16, body: &Value) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(body).unwrap_or_default())
}

/// The HTTP status a 2026-07-28 protocol error travels with. SEP-2575 makes
/// an unimplemented method a 404; the envelope refusals the revision
/// introduced are 400s, because the server could read the request but must
/// not act on it. Any other JSON-RPC error (a tool that failed, an internal
/// fault) is still a successful HTTP exchange.
/// 2026-07-28: a request the server refuses for a missing client capability.
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;

fn http_status_for(code: i64) -> u16 {
    match code {
        METHOD_NOT_FOUND => 404,
        HEADER_MISMATCH
        | UNSUPPORTED_PROTOCOL_VERSION
        | MISSING_REQUIRED_CLIENT_CAPABILITY
        | INVALID_PARAMS
        | INVALID_REQUEST
        | PARSE_ERROR => 400,
        _ => 200,
    }
}

/// The tool list projected from the surface — one MCP tool per declared
/// operation, with annotations derived from the declaration.
pub fn tools(surface: &Surface) -> Value {
    let tools: Vec<Value> = surface
        .operations()
        .map(|o| {
            let input = o.input_schema.clone().unwrap_or_else(
                || serde_json::json!({ "type": "object", "properties": {}, "additionalProperties": true }),
            );
            let mut tool = serde_json::json!({
                "name": o.name,
                "description": o.description,
                "inputSchema": input,
                "annotations": {
                    "readOnlyHint": o.read_only,
                    "idempotentHint": o.idempotent,
                    "openWorldHint": false
                }
            });
            if let Some(out) = &o.output_schema {
                tool["outputSchema"] = out.clone();
            }
            tool
        })
        .collect();
    serde_json::json!({ "tools": tools })
}

/// The server's self-description for `_meta` and `initialize`.
fn server_info(surface: &Surface) -> Value {
    serde_json::json!({
        "name": surface.name,
        "title": surface.name,
        "version": if surface.version.is_empty() { "0.0.0" } else { &surface.version }
    })
}

/// The instructions both revisions hand a client.
fn instructions(surface: &Surface) -> String {
    format!(
        "{}\n\n{}",
        surface.description,
        crate::http_change_password::AGENT_GUIDANCE
    )
}

/// Refuse an unsupported `MCP-Protocol-Version` header, or `None` when the
/// request may proceed.
///
/// `version` is the header's value when the caller sent one. Missing ⇒
/// proceed (the body decides the revision; see [`revision_of`]). A
/// supported value ⇒ proceed. Present-but-unsupported ⇒ a typed 400: a
/// JSON-RPC `INVALID_REQUEST` error whose `data.supported` lists the
/// versions this face serves, per the transport's requirement to reject
/// invalid or unsupported versions with 400 Bad Request. Decided before the
/// body is parsed, so a notification under a bogus version is refused too.
pub fn version_refusal(version: Option<&str>) -> Option<(u16, Vec<u8>)> {
    let v = version?.trim();
    if served_header(v) {
        return None;
    }
    let r = rpc_error_data(
        &Value::Null,
        INVALID_REQUEST,
        &format!("unsupported MCP-Protocol-Version '{v}'"),
        serde_json::json!({ "supported": SUPPORTED_VERSIONS }),
    );
    Some(json_reply(400, &r))
}

/// Refuse a request whose `Origin` names a foreign site, or `None` when the
/// request may proceed.
///
/// The Streamable HTTP transport requires servers to validate `Origin` on
/// every incoming connection and answer an invalid one with 403, which is
/// what stops a DNS-rebinding page from driving the endpoint through a
/// victim's browser. Admitted: no `Origin` at all (a non-browser client),
/// the surface's own origin, and loopback origins (`localhost`, `127.0.0.1`,
/// `[::1]`, any port) — a page that can present a loopback origin is already
/// running on the caller's machine, which is outside the rebinding threat.
/// The host must forward `origin` for the check to see it (`forward_headers`
/// in `ferrite.json`).
pub fn origin_refusal(surface: &Surface, origin: Option<&str>) -> Option<(u16, Vec<u8>)> {
    let origin = origin?.trim();
    if origin_admitted(&surface.origin, origin) {
        return None;
    }
    let r = rpc_error(
        &Value::Null,
        INVALID_REQUEST,
        &format!("Origin '{origin}' is not allowed to use this endpoint"),
    );
    Some(json_reply(403, &r))
}

fn origin_admitted(own: &str, origin: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    if !own.is_empty() && norm(own) == norm(origin) {
        return true;
    }
    let rest = match origin.split_once("://") {
        Some(("http" | "https", rest)) => rest,
        _ => return false,
    };
    let host = if let Some(v6) = rest.strip_prefix('[') {
        match v6.split_once(']') {
            Some((addr, tail)) if tail.is_empty() || port_suffix(tail) => return addr == "::1",
            _ => return false,
        }
    } else {
        match rest.split_once(':') {
            Some((h, tail)) if port_suffix(&format!(":{tail}")) => h,
            Some(_) => return false,
            None => rest,
        }
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

fn port_suffix(tail: &str) -> bool {
    tail.strip_prefix(':')
        .is_some_and(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Does the body carry `params._meta` with a protocol version? Decided on
/// the raw body so a header refusal can defer to [`revision_of`].
fn body_names_a_version(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("params")?
                .get("_meta")?
                .get(META_PROTOCOL_VERSION)?
                .as_str()
                .map(|_| ())
        })
        .is_some()
}

/// Put the request's own id on a transport-level refusal built before parsing.
///
/// A header refusal (unsupported `MCP-Protocol-Version`, a foreign `Origin`)
/// is decided before dispatch, but a client still correlates the error with
/// its request, so a readable string or integer id replaces `null`.
pub fn with_request_id(refusal: (u16, Vec<u8>), body: &[u8]) -> (u16, Vec<u8>) {
    let (status, bytes) = refusal;
    let request_id = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .filter(valid_id);
    match (request_id, serde_json::from_slice::<Value>(&bytes)) {
        (Some(rid), Ok(mut r)) => {
            r["id"] = rid;
            (status, serde_json::to_vec(&r).unwrap_or(bytes))
        }
        _ => (status, bytes),
    }
}

/// Decide which revision a call is held to, from its header and its
/// `params._meta`, or the JSON-RPC error that refuses it.
///
/// The body is authoritative. With `_meta.protocolVersion` present the call
/// is a 2026-07-28 request: the version must be one this face serves
/// (`-32022` otherwise, naming `supported` and `requested`), the header —
/// when it reached the face — must agree (`-32020`), and the client
/// capabilities must be declared (`-32602`). Without `_meta` the call is a
/// 2025-11-25 request, unless the header itself says `2026-07-28`, which
/// makes it a malformed 2026-07-28 request (`-32602`): that client meant the
/// new revision and forgot the envelope, and serving it as legacy would hide
/// the mistake.
pub fn revision_of(
    header: Option<&str>,
    params: &Value,
) -> Result<Revision, (i64, String, Option<Value>)> {
    let header = header.map(str::trim);
    let meta = params.get("_meta");
    let body_version = meta
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(Value::as_str);
    match body_version {
        None => {
            if header == Some(PROTOCOL_VERSION) {
                return Err((
                    INVALID_PARAMS,
                    format!("a {PROTOCOL_VERSION} request must carry params._meta {META_PROTOCOL_VERSION}"),
                    None,
                ));
            }
            Ok(Revision::Legacy)
        }
        Some(v) => {
            if let Some(h) = header {
                if h != v {
                    return Err((
                        HEADER_MISMATCH,
                        "MCP-Protocol-Version header does not match params._meta protocolVersion"
                            .into(),
                        Some(serde_json::json!({ "header": h, "body": v })),
                    ));
                }
            }
            if !SUPPORTED_VERSIONS.contains(&v) {
                return Err((
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "unsupported protocol version".into(),
                    Some(serde_json::json!({ "supported": SUPPORTED_VERSIONS, "requested": v })),
                ));
            }
            if v == LEGACY_PROTOCOL_VERSION {
                // A 2025-11-25 client that volunteers `_meta` is still a
                // 2025-11-25 client; the released wire has no envelope rules.
                return Ok(Revision::Legacy);
            }
            if meta.and_then(|m| m.get(META_CLIENT_CAPABILITIES)).is_none() {
                return Err((
                    INVALID_PARAMS,
                    format!("params._meta must carry {META_CLIENT_CAPABILITIES}"),
                    None,
                ));
            }
            Ok(Revision::Current)
        }
    }
}

/// Decode SEP-2243 `=?base64?...?=` header wrapping when present.
/// Returns `None` for malformed base64 or non-UTF-8 payloads.
fn decode_mirrored_header(raw: &str) -> Option<String> {
    match raw.strip_prefix("=?base64?").and_then(|s| s.strip_suffix("?=")) {
        Some(encoded) => {
            let bytes = decode_std_b64_mirrored(encoded)?;
            String::from_utf8(bytes).ok()
        }
        None => Some(raw.to_string()),
    }
}

fn decode_std_b64_mirrored(input: &str) -> Option<Vec<u8>> {
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

/// SEP-2243: a mirrored header that reached the face must agree with the
/// body (unwrapping `=?base64?...?=` when used). `None` when it does, or when
/// it did not reach the face at all.
fn mirrored_disagreement(
    header: &str,
    supplied: Option<&str>,
    body: Option<&str>,
) -> Option<Value> {
    let (Some(supplied), Some(expected)) = (supplied.map(str::trim), body) else {
        return None;
    };
    let agrees = decode_mirrored_header(supplied)
        .as_deref()
        .is_some_and(|decoded| decoded == expected);
    (!agrees)
        .then(|| serde_json::json!({ "header": header, "headerValue": supplied, "body": expected }))
}

/// Answer one MCP POST body. `protocol_version` is the request's
/// `MCP-Protocol-Version` header, if sent; `exec` runs a named tool with its
/// arguments (the host's own handler); returns `(http_status,
/// response_body)`.
///
/// The original shape, kept for hosts that read only the version header.
/// It serves both revisions; SEP-2243's mirrored headers are simply never
/// seen, so never checked. Prefer [`handle_h`] where the host has the
/// header list.
pub async fn handle<F, Fut>(
    surface: &Surface,
    protocol_version: Option<&str>,
    body: &[u8],
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    handle_h(
        surface,
        RequestHeaders::version(protocol_version),
        body,
        exec,
    )
    .await
}

/// Answer one MCP POST body with the request headers the face consults.
///
/// Stateless by construction: the response depends only on the request
/// envelope, the headers and the surface. A notification returns 202 with
/// an empty body, per the Streamable HTTP transport.
pub async fn handle_h<F, Fut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    handle_h_with_skills(surface, headers, body, &[], exec).await
}

/// Serve optional workflow skills through the same validated MCP envelope.
pub async fn handle_h_with_skills<F, Fut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    skills: &[crate::agent_ready::skills::Skill],
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
{
    handle_h_with_events(
        surface,
        headers,
        body,
        skills,
        &[],
        |_| async { Err(crate::agent_ready::events::EventError::not_found()) },
        exec,
    )
    .await
}

/// Opt-in experimental Events MCP. The provider must re-authorize each poll;
/// catalogs and cursors never grant access. Only polling is advertised.
pub async fn handle_h_with_events<F, Fut, P, PFut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    skills: &[crate::agent_ready::skills::Skill],
    events: &[crate::agent_ready::events::EventType],
    poll: P,
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
    P: Fn(crate::agent_ready::events::PollRequest) -> PFut,
    PFut: std::future::Future<Output = Result<Value, crate::agent_ready::events::EventError>>,
{
    handle_h_with_event_dispatch(
        surface,
        headers,
        body,
        skills,
        events,
        &["poll"],
        |method, params| {
            let poll = &poll;
            async move {
                match method.as_str() {
                    "events/poll" => {
                        poll(crate::agent_ready::events::PollRequest::parse(&params)?).await
                    }
                    "events/stream" => {
                        Err(crate::agent_ready::events::EventError::unsupported_delivery("push"))
                    }
                    _ => {
                        Err(crate::agent_ready::events::EventError::unsupported_delivery("webhook"))
                    }
                }
            }
        },
        exec,
    )
    .await
}

/// Host-owned delivery hooks. Advertise a mode only when its real transport and
/// scheduler are mounted. The host authorizes every call and delivery.
pub async fn handle_h_with_event_dispatch<F, Fut, P, PFut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    skills: &[crate::agent_ready::skills::Skill],
    events: &[crate::agent_ready::events::EventType],
    delivery: &[&str],
    event_call: P,
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
    P: Fn(String, Value) -> PFut,
    PFut: std::future::Future<Output = Result<Value, crate::agent_ready::events::EventError>>,
{
    handle_h_with_extensions(
        surface,
        headers,
        body,
        skills,
        events,
        delivery,
        event_call,
        &[],
        false,
        |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
        exec,
    )
    .await
}

/// Opt-in durable task host. Only declared asynchronous tools are task augmented.
/// All hooks receive an authenticated host context and must authorize each call.
pub async fn handle_h_with_extensions<F, Fut, P, PFut, T, TFut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    skills: &[crate::agent_ready::skills::Skill],
    events: &[crate::agent_ready::events::EventType],
    delivery: &[&str],
    event_call: P,
    task_tools: &[String],
    task_streaming: bool,
    task_call: T,
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
    P: Fn(String, Value) -> PFut,
    PFut: std::future::Future<Output = Result<Value, crate::agent_ready::events::EventError>>,
    T: Fn(String, Value) -> TFut,
    TFut: std::future::Future<Output = Result<Value, crate::agent_ready::tasks::TaskError>>,
{
    let default_files = crate::agent_ready::files::FilesConfig::default();
    handle_h_full(
        surface,
        headers,
        body,
        skills,
        events,
        delivery,
        event_call,
        task_tools,
        task_streaming,
        task_call,
        &default_files,
        |_, _| async { None },
        exec,
    )
    .await
}

/// Full MCP 2026-07-28 + 2025-11-25 face with Skills (`directoryRead`), Events,
/// Tasks, standalone MRTR Elicitation (`input_required`), and File Transfers
/// (`io.modelcontextprotocol/files`, `upload_required` + `_meta` downloads).
#[allow(clippy::too_many_arguments)]
pub async fn handle_h_full<F, Fut, P, PFut, T, TFut, M, MFut>(
    surface: &Surface,
    headers: RequestHeaders<'_>,
    body: &[u8],
    skills: &[crate::agent_ready::skills::Skill],
    events: &[crate::agent_ready::events::EventType],
    delivery: &[&str],
    event_call: P,
    task_tools: &[String],
    task_streaming: bool,
    task_call: T,
    files_config: &crate::agent_ready::files::FilesConfig,
    mrtr_call: M,
    exec: F,
) -> (u16, Vec<u8>)
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
    P: Fn(String, Value) -> PFut,
    PFut: std::future::Future<Output = Result<Value, crate::agent_ready::events::EventError>>,
    T: Fn(String, Value) -> TFut,
    TFut: std::future::Future<Output = Result<Value, crate::agent_ready::tasks::TaskError>>,
    M: Fn(String, Value) -> MFut,
    MFut: std::future::Future<
        Output = Option<Result<Value, crate::agent_ready::elicitation::ElicitationError>>,
    >,
{
    // A header this face does not serve is refused before parsing, EXCEPT
    // when the body itself names a protocol version: that request is a
    // 2026-07-28 request and its own revision rules decide it (-32020 when
    // header and body disagree, -32022 when they agree on a version this
    // face does not serve), which is what the revision asks for.
    if let Some(refusal) = version_refusal(headers.protocol_version) {
        if !body_names_a_version(body) {
            return with_request_id(refusal, body);
        }
    }
    let parsed = match parse(body) {
        Ok(p) => p,
        Err(e) => {
            let r = rpc_error(&Value::Null, PARSE_ERROR, &format!("parse error: {e}"));
            return json_reply(400, &r);
        }
    };
    let (id, method, params) = match parsed {
        // A client response carries no params of its own: an unserved header is refused.
        Parsed::ClientResponse => {
            if let Some(refusal) = version_refusal(headers.protocol_version) {
                return with_request_id(refusal, body);
            }
            return (202, Vec::new());
        }
        // A notification is held to the same version and header rules as a request
        // before it is accepted; only its reply is empty.
        Parsed::Notification => {
            let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let method = value.get("method").and_then(Value::as_str);
            match revision_of(headers.protocol_version, &params) {
                // A notification may omit _meta: only a disagreement or an unserved version refuses it.
                Err((code, _, _)) if code != INVALID_PARAMS => return (http_status_for(code), Vec::new()),
                Err(_) => {}
                Ok(Revision::Current) => {
                    if mirrored_disagreement(HEADER_METHOD, headers.method, method).is_some() {
                        return (http_status_for(HEADER_MISMATCH), Vec::new());
                    }
                }
                Ok(_) => {}
            }
            return (202, Vec::new());
        }
        Parsed::Invalid(msg) => {
            let r = rpc_error(&Value::Null, INVALID_REQUEST, &msg);
            return json_reply(400, &r);
        }
        Parsed::Call { id, method, params } => (id, method, params),
    };
    let revision = match revision_of(headers.protocol_version, &params) {
        Ok(r) => r,
        Err((code, message, data)) => {
            return json_reply(http_status_for(code), &rpc_error_with(&id, code, &message, data));
        }
    };
    if revision == Revision::Current {
        let name = match method.as_str() {
            "tools/call" | "events/poll" | "events/stream" | "events/subscribe"
            | "events/unsubscribe" => params.get("name").and_then(Value::as_str),
            "skills/get" | "resources/read" | "resources/directory/read" => {
                params.get("uri").and_then(Value::as_str)
            }
            m if m.starts_with("tasks/") => params.get("taskId").and_then(Value::as_str),
            _ => None,
        };
        let disagreement =
            mirrored_disagreement(HEADER_METHOD, headers.method, Some(method.as_str()))
                .or_else(|| mirrored_disagreement(HEADER_NAME, headers.name, name));
        if let Some(data) = disagreement {
            let r = rpc_error_data(
                &id,
                HEADER_MISMATCH,
                "a standard request header does not match the request body",
                data,
            );
            return json_reply(http_status_for(HEADER_MISMATCH), &r);
        }
    }
    let delivery = if revision == Revision::Current {
        delivery
    } else {
        &["poll"]
    };
    let is_async_tool = method == "tools/call"
        && params["name"]
            .as_str()
            .is_some_and(|name| task_tools.iter().any(|tool| tool == name));
    let is_task_subscription =
        revision == Revision::Current && task_streaming && method == "subscriptions/listen";
    let resp = if is_async_tool
        || is_task_subscription
        || (revision == Revision::Current
            && !task_tools.is_empty()
            && matches!(
                method.as_str(),
                "tasks/get" | "tasks/update" | "tasks/cancel"
            )) {
        let result = if revision != Revision::Current
            || !crate::agent_ready::tasks::client_supports(&params)
        {
            Err(crate::agent_ready::tasks::TaskError::missing_capability())
        } else if is_async_tool
            && (params
                .get("arguments")
                .is_some_and(|args| !args.is_object())
                || !surface.operations().any(|op| params["name"] == op.name))
        {
            Err(crate::agent_ready::tasks::TaskError::invalid())
        } else {
            let mut task_params = params.clone();
            if is_async_tool && task_params.get("arguments").is_none() {
                task_params["arguments"] = serde_json::json!({});
            }
            task_call(method.clone(), task_params).await
        };
        match result {
            Ok(value) => rpc_result(&id, value),
            Err(error) => rpc_error_with(&id, error.code, error.message, error.data),
        }
    } else if method.starts_with("events/") && !events.is_empty() {
        let result = match method.as_str() {
            "events/list"
                if (params.is_null() || params.is_object())
                    && params.get("cursor").is_none_or(Value::is_null) =>
            {
                Ok(
                    serde_json::json!({"events":events.iter().map(|e| e.descriptor_with_delivery(delivery)).collect::<Vec<_>>()}),
                )
            }
            "events/list" => Err(crate::agent_ready::events::EventError::invalid()),
            "events/poll" => match crate::agent_ready::events::PollRequest::parse(&params) {
                Ok(request) if events.iter().any(|e| e.name == request.name) => {
                    event_call(method.clone(), params.clone()).await
                }
                Ok(_) => Err(crate::agent_ready::events::EventError::not_found()),
                Err(error) => Err(error),
            },
            "events/stream" | "events/subscribe" | "events/unsubscribe" => {
                let mode = if method == "events/stream" {
                    "push"
                } else {
                    "webhook"
                };
                if !delivery.contains(&mode) {
                    Err(crate::agent_ready::events::EventError::unsupported_delivery(mode))
                } else if !events.iter().any(|e| params["name"] == e.name) {
                    Err(crate::agent_ready::events::EventError::not_found())
                } else {
                    event_call(method.clone(), params.clone()).await
                }
            }
            _ => Err(crate::agent_ready::events::EventError {
                code: METHOD_NOT_FOUND,
                message: "unknown event method",
                data: None,
            }),
        };
        match result {
            Ok(mut value) => {
                if revision == Revision::Current {
                    value["resultType"] = serde_json::json!(RESULT_COMPLETE);
                }
                rpc_result(&id, value)
            }
            Err(error) => rpc_error_with(&id, error.code, error.message, error.data),
        }
    } else {
        dispatch(
            surface,
            revision,
            &id,
            &method,
            params,
            skills,
            !events.is_empty(),
            !task_tools.is_empty(),
            files_config,
            mrtr_call,
            exec,
        )
        .await
    };
    let status = match revision {
        // The released wire: every JSON-RPC answer, error or not, is a 200.
        Revision::Legacy => 200,
        Revision::Current => resp
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64)
            .map_or(200, http_status_for),
    };
    json_reply(status, &resp)
}

/// Route one call. Both revisions share `ping`, `tools/list` and
/// `tools/call`; `initialize` and `ping` belong to the released wire only
/// and `server/discover` to 2026-07-28 only — under the other revision each
/// is an unknown method, which is exactly what the revision it does not
/// belong to says it is (SEP-2575 lists `ping` among the removed methods
/// that MUST answer 404 with `-32601`).
async fn dispatch<F, Fut, M, MFut>(
    surface: &Surface,
    revision: Revision,
    id: &Value,
    method: &str,
    params: Value,
    skills: &[crate::agent_ready::skills::Skill],
    has_events: bool,
    has_tasks: bool,
    files_config: &crate::agent_ready::files::FilesConfig,
    mrtr_call: M,
    exec: F,
) -> Value
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = ToolOutcome>,
    M: Fn(String, Value) -> MFut,
    MFut: std::future::Future<
        Output = Option<Result<Value, crate::agent_ready::elicitation::ElicitationError>>,
    >,
{
    // 2026-07-28 results carry `resultType`; the released wire's do not, so
    // a 2025-11-25 client sees exactly the bytes it always has.
    let finish = |mut result: Map<String, Value>| -> Value {
        if revision == Revision::Current {
            result
                .entry("resultType")
                .or_insert_with(|| Value::String(RESULT_COMPLETE.into()));
        }
        rpc_result(id, Value::Object(result))
    };
    // SEP-2549: a 2026-07-28 list result says how long it may be cached and
    // that it is the same for every caller.
    let cacheable = |mut result: Map<String, Value>| -> Value {
        if revision == Revision::Current {
            result.insert("ttlMs".into(), serde_json::json!(LIST_TTL_MS));
            result.insert("cacheScope".into(), Value::String("public".into()));
        }
        finish(result)
    };
    let capabilities = |legacy: bool| {
        let mut caps = if legacy {
            serde_json::json!({"tools":{"listChanged":false}})
        } else {
            serde_json::json!({"tools":{}})
        };
        if !skills.is_empty() {
            caps["resources"] = serde_json::json!({});
            caps["extensions"][crate::agent_ready::skills::EXTENSION] =
                serde_json::json!({"directoryRead": true});
        }
        if has_events {
            if legacy {
                caps["events"] = serde_json::json!({"listChanged":false});
            } else {
                caps["extensions"]["io.modelcontextprotocol/events"] =
                    serde_json::json!({"listChanged":false});
            }
        }
        if has_tasks && !legacy {
            caps["extensions"][crate::agent_ready::tasks::EXTENSION] = serde_json::json!({});
        }
        if files_config.enabled() && !legacy {
            caps["extensions"][crate::agent_ready::files::EXTENSION] =
                files_config.capability_value();
        }
        caps
    };
    let skill_result = |mut value: Value| {
        value["resultType"] = serde_json::json!(RESULT_COMPLETE);
        value["ttlMs"] = serde_json::json!(LIST_TTL_MS);
        value["cacheScope"] = serde_json::json!("public");
        rpc_result(id, value)
    };
    match (method, revision) {
        ("initialize", Revision::Legacy) => {
            let mut r = Map::new();
            let asked = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let version = if COMPATIBLE_LEGACY_VERSIONS.contains(&asked) {
                asked
            } else {
                LEGACY_PROTOCOL_VERSION
            };
            r.insert("protocolVersion".into(), Value::String(version.into()));
            r.insert("capabilities".into(), capabilities(true));
            r.insert("serverInfo".into(), server_info(surface));
            r.insert("instructions".into(), Value::String(instructions(surface)));
            finish(r)
        }
        ("server/discover", Revision::Current) => {
            let mut r = Map::new();
            r.insert(
                "supportedVersions".into(),
                serde_json::json!(SUPPORTED_VERSIONS),
            );
            r.insert("capabilities".into(), capabilities(false));
            r.insert("instructions".into(), Value::String(instructions(surface)));
            let mut meta = Map::new();
            meta.insert(META_SERVER_INFO.into(), server_info(surface));
            r.insert("_meta".into(), Value::Object(meta));
            if has_events || has_tasks {
                r.insert("ttlMs".into(), serde_json::json!(0));
                r.insert("cacheScope".into(), serde_json::json!("private"));
                finish(r)
            } else {
                cacheable(r)
            }
        }
        ("ping", Revision::Legacy) => finish(Map::new()),
        ("skills/list", _) if !skills.is_empty() => {
            if (!params.is_object() && !params.is_null())
                || params.get("cursor").is_some_and(|v| !v.is_null())
            {
                rpc_error(id, INVALID_PARAMS, "unknown skill cursor or invalid params")
            } else {
                skill_result(crate::agent_ready::skills::list(skills))
            }
        }
        ("skills/get", _) if !skills.is_empty() => params
            .get("uri")
            .and_then(Value::as_str)
            .and_then(|uri| crate::agent_ready::skills::get(skills, uri))
            .map(skill_result)
            .unwrap_or_else(|| rpc_error(id, INVALID_PARAMS, "unknown skill URI")),
        ("resources/list", _) if !skills.is_empty() => {
            if params.get("cursor").is_some_and(|v| !v.is_null()) {
                rpc_error(id, INVALID_PARAMS, "unknown resource cursor")
            } else {
                skill_result(crate::agent_ready::skills::resources(skills))
            }
        }
        ("resources/templates/list", _) if !skills.is_empty() => {
            skill_result(serde_json::json!({"resourceTemplates":[]}))
        }
        ("resources/read", _) if !skills.is_empty() => params
            .get("uri")
            .and_then(Value::as_str)
            .and_then(|uri| crate::agent_ready::skills::read(skills, uri))
            .map(skill_result)
            .unwrap_or_else(|| rpc_error(id, INVALID_PARAMS, "unknown skill resource URI")),
        ("resources/directory/read", _) if !skills.is_empty() => {
            if params.get("cursor").is_some_and(|v| !v.is_null()) {
                rpc_error(id, INVALID_PARAMS, "unknown directory cursor")
            } else {
                params
                    .get("uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| crate::agent_ready::skills::directory_read(skills, uri))
                    .map(skill_result)
                    .unwrap_or_else(|| rpc_error(id, INVALID_PARAMS, "unknown skill directory URI"))
            }
        }
        ("tools/list", _) => {
            let Value::Object(list) = tools(surface) else {
                unreachable!("tools() builds an object")
            };
            cacheable(list)
        }
        ("tools/call", _) => {
            if !params.is_object() {
                return rpc_error(id, INVALID_PARAMS, "tools/call params must be an object");
            }
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return rpc_error(id, INVALID_PARAMS, "tools/call requires a string 'name'");
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            if !args.is_object() {
                return rpc_error(id, INVALID_PARAMS, "tools/call 'arguments' must be an object");
            }
            let Some(operation) = surface.operation(name) else {
                return rpc_error(id, INVALID_PARAMS, &format!("unknown tool '{name}'"));
            };
            // Optional host MRTR hook for standalone Elicitation (`input_required`),
            // File Uploads (`upload_required`), or tool results carrying `_meta` downloads.
            // Evaluated on both revisions so a legacy `2025-11-25` downgrade cannot silently
            // bypass a host's confirmation or upload policy; MRTR pause responses on Legacy
            // fail closed with `-32021` (missing 2026-07-28 capability).
            if let Some(mrtr_outcome) = mrtr_call(name.to_string(), params.clone()).await {
                return match mrtr_outcome {
                    Ok(mut raw) => {
                        let rt = raw.get("resultType").and_then(Value::as_str).unwrap_or("");
                        if revision != Revision::Current
                            && matches!(
                                rt,
                                crate::agent_ready::elicitation::RESULT_INPUT_REQUIRED
                                    | crate::agent_ready::files::RESULT_UPLOAD_REQUIRED
                            )
                        {
                            return rpc_error_with(
                                id,
                                -32021,
                                "this tool requires MCP 2026-07-28 for interactive input or file upload",
                                None,
                            );
                        }
                        if revision == Revision::Current {
                            if let Some(obj) = raw.as_object_mut() {
                                obj.entry("resultType")
                                    .or_insert_with(|| Value::String(RESULT_COMPLETE.into()));
                            }
                        } else if let Some(obj) = raw.as_object_mut() {
                            obj.remove("resultType");
                        }
                        rpc_result(id, raw)
                    }
                    Err(err) => rpc_error_with(id, err.code, &err.message, err.data),
                };
            }
            let outcome = exec(name.to_string(), args).await;
            let content = match outcome.content {
                Some(blocks) => Value::Array(blocks),
                None => {
                    let text = serde_json::to_string(&outcome.value).unwrap_or_default();
                    serde_json::json!([ { "type": "text", "text": text } ])
                }
            };
            let mut result = Map::new();
            result.insert("content".into(), content);
            result.insert("isError".into(), Value::Bool(outcome.is_error));
            // `structuredContent` must conform to a declared
            // `outputSchema`, and a failure value (a problem, an x402
            // challenge) does not; clients such as the official
            // TypeScript SDK validate it anyway and throw. A failed call
            // with a declared schema carries its JSON in the text block
            // only.
            if !(outcome.is_error && operation.output_schema.is_some()) {
                result.insert("structuredContent".into(), outcome.value);
            }
            finish(result)
        }
        (other, _) => rpc_error(
            id,
            METHOD_NOT_FOUND,
            &format!("method '{other}' not supported"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind};

    fn surface() -> Surface {
        Surface {
            name: "notes".into(),
            owner: "labs".into(),
            origin: "https://notes.example".into(),
            description: "A note-keeping API.".into(),
            version: "1.0.0".into(),
            routes: vec![Route {
                prefix: "/api/".into(),
                kind: RouteKind::Api,
                description: "notes API".into(),
                operations: vec![Operation {
                    name: "list_notes".into(),
                    method: "GET".into(),
                    path: "/api/notes".into(),
                    description: "List notes.".into(),
                    input_schema: None,
                    output_schema: None,
                    read_only: true,
                    idempotent: true,
                    price_micros: 0,
                }],
            }],
            pages: vec![],
        }
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended in a ready-only test"),
        }
    }

    fn run(version: Option<&str>, body: &Value) -> (u16, Vec<u8>) {
        block(handle(
            &surface(),
            version,
            &serde_json::to_vec(body).unwrap(),
            |name, _args| async move { ToolOutcome::ok(serde_json::json!({ "tool": name })) },
        ))
    }

    fn run_h(headers: RequestHeaders<'_>, body: &Value) -> (u16, Vec<u8>) {
        block(handle_h(
            &surface(),
            headers,
            &serde_json::to_vec(body).unwrap(),
            |name, _args| async move { ToolOutcome::ok(serde_json::json!({ "tool": name })) },
        ))
    }

    fn json(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    fn error_code(body: &[u8]) -> i64 {
        json(body)["error"]["code"].as_i64().unwrap()
    }

    /// A 2026-07-28 request: the envelope every call of that revision carries.
    fn current(id: u64, method: &str, params: Value) -> Value {
        let mut p = match params {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let mut meta = Map::new();
        meta.insert(
            META_PROTOCOL_VERSION.into(),
            serde_json::json!(PROTOCOL_VERSION),
        );
        meta.insert(META_CLIENT_CAPABILITIES.into(), serde_json::json!({}));
        meta.insert(
            META_CLIENT_INFO.into(),
            serde_json::json!({ "name": "t", "version": "0" }),
        );
        p.insert("_meta".into(), Value::Object(meta));
        serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": Value::Object(p) })
    }

    fn current_headers(
        method: &'static str,
        name: Option<&'static str>,
    ) -> RequestHeaders<'static> {
        RequestHeaders {
            protocol_version: Some(PROTOCOL_VERSION),
            method: Some(method),
            name,
        }
    }

    // ------------------------------------------------------- the released wire

    #[test]
    fn missing_version_header_assumes_the_released_wire() {
        let ping = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"});
        let (status, body) = run(None, &ping);
        assert_eq!(status, 200);
        let v = json(&body);
        assert!(v["result"].is_object());
        assert!(
            v["result"].get("resultType").is_none(),
            "a legacy result carries no resultType"
        );
    }

    #[test]
    fn a_2025_06_18_connector_initializes_and_lists_tools() {
        let init = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-ai","version":"1"}}});
        let (status, body) = run(None, &init);
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["protocolVersion"], "2025-06-18");
        let list = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let (status, body) = run(Some("2025-06-18"), &list);
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["tools"][0]["name"], "list_notes");
    }

    #[test]
    fn legacy_version_header_serves_plain_results() {
        let list = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let (status, body) = run(Some(LEGACY_PROTOCOL_VERSION), &list);
        assert_eq!(status, 200);
        let v = json(&body);
        assert_eq!(v["result"]["tools"][0]["name"], "list_notes");
        assert!(v["result"].get("ttlMs").is_none());
        assert!(v["result"].get("resultType").is_none());
    }

    #[test]
    fn initialize_answers_the_released_wire_and_discover_is_unknown_there() {
        let init = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let (status, body) = run(Some(LEGACY_PROTOCOL_VERSION), &init);
        assert_eq!(status, 200);
        let v = json(&body);
        assert_eq!(v["result"]["protocolVersion"], LEGACY_PROTOCOL_VERSION);
        assert_eq!(v["result"]["serverInfo"]["name"], "notes");
        assert!(v["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("note-keeping"));
        // 2026-07-28's discovery method is not part of the released wire.
        let disc = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"server/discover"});
        let (status, body) = run(None, &disc);
        assert_eq!(status, 200, "a legacy error is still a 200");
        assert_eq!(error_code(&body), METHOD_NOT_FOUND);
    }

    #[test]
    fn unsupported_version_is_typed_400() {
        let ping = serde_json::json!({"jsonrpc":"2.0","id":3,"method":"ping"});
        let (status, body) = run(Some("2024-11-05"), &ping);
        assert_eq!(status, 400);
        let v = json(&body);
        assert_eq!(v["id"], 3, "the readable request id is kept on the refusal");
        assert_eq!(v["error"]["code"], INVALID_REQUEST);
        assert_eq!(
            v["error"]["data"]["supported"],
            serde_json::json!(SUPPORTED_VERSIONS)
        );
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("2024-11-05"));
    }

    #[test]
    fn unsupported_version_refuses_notifications_too() {
        // The refusal happens before dispatch — even a notification (which
        // would otherwise 202 bodylessly) is answered with the typed 400.
        let note = serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let (status, _) = run(Some("bogus"), &note);
        assert_eq!(status, 400);
        let (status, body) = run(None, &note);
        assert_eq!(status, 202);
        assert!(body.is_empty());
        let (status, _) = run(Some(PROTOCOL_VERSION), &note);
        assert_eq!(status, 202, "a 2026-07-28 notification is accepted too");
        // finding_9e7cac91acae6c67: a notification naming a version in its body is still checked.
        let named = |v: &str| serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{META_PROTOCOL_VERSION: v}}});
        assert_eq!(run(Some("bogus"), &named(PROTOCOL_VERSION)).0, 400);
        assert_eq!(run(Some("1999-01-01"), &named("1999-01-01")).0, 400);
        assert_eq!(run(Some(PROTOCOL_VERSION), &named(PROTOCOL_VERSION)).0, 202);
    }

    #[test]
    fn version_refusal_trims_and_matches_exactly() {
        assert!(version_refusal(None).is_none());
        assert!(version_refusal(Some(PROTOCOL_VERSION)).is_none());
        assert!(version_refusal(Some(LEGACY_PROTOCOL_VERSION)).is_none());
        assert!(version_refusal(Some("2025-06-18")).is_none());
        assert!(version_refusal(Some("2025-03-26")).is_none());
        assert!(version_refusal(Some("2024-11-05")).is_some());
        assert!(version_refusal(Some(&format!(" {PROTOCOL_VERSION} "))).is_none());
        assert!(version_refusal(Some("")).is_some());
        assert!(version_refusal(Some("2024-11-05")).is_some());
    }

    #[test]
    fn null_and_non_scalar_ids_are_invalid_requests_not_notifications() {
        for id in [
            Value::Null,
            serde_json::json!(true),
            serde_json::json!({"a": 1}),
            serde_json::json!([1]),
            serde_json::json!(1.5),
        ] {
            let req = serde_json::json!({"jsonrpc":"2.0","id":id,"method":"ping"});
            let (status, body) = run(None, &req);
            assert_eq!(status, 400, "id {id} must be refused");
            assert_eq!(error_code(&body), INVALID_REQUEST);
        }
        let (status, body) = run(
            None,
            &serde_json::json!({"jsonrpc":"2.0","id":"s-1","method":"ping"}),
        );
        assert_eq!(status, 200);
        assert_eq!(json(&body)["id"], "s-1");
    }

    #[test]
    fn client_responses_are_accepted_with_202() {
        let (status, body) = run(
            None,
            &serde_json::json!({"jsonrpc":"2.0","id":7,"result":{}}),
        );
        assert_eq!(status, 202);
        assert!(body.is_empty());
        let (status, _) = run(
            None,
            &serde_json::json!({"jsonrpc":"2.0","id":7,"error":{"code":1,"message":"x"}}),
        );
        assert_eq!(status, 202);
        // Neither result nor error, or both: not a response, not a request.
        let (status, _) = run(None, &serde_json::json!({"jsonrpc":"2.0","id":7}));
        assert_eq!(status, 400);
        let (status, _) = run(
            None,
            &serde_json::json!({"jsonrpc":"2.0","id":7,"result":{},"error":{}}),
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn tools_call_shape_errors_are_invalid_params() {
        for params in [
            serde_json::json!("x"),
            serde_json::json!({"arguments": {}}),
            serde_json::json!({"name": 5}),
            serde_json::json!({"name": "list_notes", "arguments": [1, 2]}),
            serde_json::json!({"name": "list_notes", "arguments": "q"}),
            serde_json::json!({"name": "__internal_admin", "arguments": {}}),
        ] {
            let req =
                serde_json::json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":params});
            let (status, body) = run(None, &req);
            assert_eq!(status, 200);
            assert_eq!(error_code(&body), INVALID_PARAMS, "params {params}");
        }
        let ok = serde_json::json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"list_notes"}});
        let (status, body) = run(None, &ok);
        assert_eq!(status, 200);
        assert_eq!(
            json(&body)["result"]["structuredContent"]["tool"],
            "list_notes"
        );
    }

    #[test]
    fn origin_validation_admits_own_and_loopback_only() {
        let s = surface();
        assert!(origin_refusal(&s, None).is_none());
        assert!(origin_refusal(&s, Some("https://notes.example")).is_none());
        assert!(origin_refusal(&s, Some("https://NOTES.example/")).is_none());
        for loopback in [
            "http://localhost",
            "http://localhost:8787",
            "http://127.0.0.1:9711",
            "http://[::1]:3000",
            "https://[::1]",
        ] {
            assert!(origin_refusal(&s, Some(loopback)).is_none(), "{loopback}");
        }
        for foreign in [
            "https://attacker.example",
            "http://evil.example.com",
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1:80abc",
            "http://[::1].evil",
            "null",
            "file://",
            "https://notes.example.evil",
        ] {
            let (status, body) = origin_refusal(&s, Some(foreign)).expect(foreign);
            assert_eq!(status, 403, "{foreign}");
            assert_eq!(error_code(&body), INVALID_REQUEST);
        }
    }

    #[test]
    fn failed_calls_with_an_output_schema_omit_structured_content() {
        let mut s = surface();
        s.routes[0].operations[0].output_schema =
            Some(serde_json::json!({"type":"object","required":["text"]}));
        let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_notes"}});
        let body = serde_json::to_vec(&req).unwrap();
        let (_, failed) = block(handle(&s, None, &body, |_, _| async {
            ToolOutcome::err(serde_json::json!({"x402Version":1}))
        }));
        let v = json(&failed);
        assert_eq!(v["result"]["isError"], true);
        assert!(v["result"].get("structuredContent").is_none());
        let text: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["x402Version"], 1);
        let (_, ok) = block(handle(&s, None, &body, |_, _| async {
            ToolOutcome::ok(serde_json::json!({"text":"t"}))
        }));
        assert_eq!(json(&ok)["result"]["structuredContent"]["text"], "t");
        // Without a declared schema a failure keeps its structured value.
        let (_, plain) = block(handle(&surface(), None, &body, |_, _| async {
            ToolOutcome::err(serde_json::json!({"code":"X"}))
        }));
        assert_eq!(json(&plain)["result"]["structuredContent"]["code"], "X");
    }

    #[test]
    fn explicit_content_blocks_replace_the_text_rendering() {
        let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_notes"}});
        let body = serde_json::to_vec(&req).unwrap();
        let (_, rich) = block(handle(&surface(), None, &body, |_, _| async {
            ToolOutcome::ok(serde_json::json!({"notes": 2})).with_content(vec![
                serde_json::json!({"type":"text","text":"two notes"}),
                serde_json::json!({"type":"resource_link","uri":"https://notes.example/n/1","name":"n1"}),
                serde_json::json!({"type":"image","data":"aGk=","mimeType":"image/png"}),
                serde_json::json!({"text":"no type: dropped"}),
                serde_json::json!("not an object: dropped"),
            ])
        }));
        let v = json(&rich);
        let content = v["result"]["content"].as_array().unwrap();
        assert_eq!(content.len(), 3, "{v}");
        assert_eq!(content[0]["text"], "two notes");
        assert_eq!(content[1]["type"], "resource_link");
        assert_eq!(content[2]["mimeType"], "image/png");
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(
            v["result"]["structuredContent"]["notes"], 2,
            "structuredContent still follows value"
        );

        // Only malformed blocks ⇒ the text rendering, never an empty array.
        let (_, fallback) = block(handle(&surface(), None, &body, |_, _| async {
            ToolOutcome::err(serde_json::json!({"code":"X"}))
                .with_content(vec![serde_json::json!({"text":"typeless"})])
        }));
        let v = json(&fallback);
        assert_eq!(v["result"]["content"].as_array().unwrap().len(), 1);
        assert_eq!(v["result"]["content"][0]["type"], "text");
        let text: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["code"], "X");
        assert_eq!(v["result"]["isError"], true);
    }

    // ------------------------------------------------------------ 2026-07-28

    #[test]
    fn a_current_request_is_served_with_result_type_and_cache_hints() {
        let (status, body) = run_h(
            current_headers("tools/list", None),
            &current(1, "tools/list", serde_json::json!({})),
        );
        assert_eq!(status, 200);
        let r = &json(&body)["result"];
        assert_eq!(r["tools"][0]["name"], "list_notes");
        assert_eq!(r["resultType"], RESULT_COMPLETE);
        assert_eq!(r["ttlMs"], LIST_TTL_MS);
        assert_eq!(r["cacheScope"], "public");

        // SEP-2575 removed `ping` with the lifecycle: under 2026-07-28 it is
        // a removed method (404, -32601), while the released wire below
        // still answers it. The official runner's server-stateless scenario
        // checks exactly this (sep-2575-http-server-method-not-found-404-ping).
        let (status, body) = run_h(
            current_headers("ping", None),
            &current(2, "ping", serde_json::json!({})),
        );
        assert_eq!(status, 404);
        let v = json(&body);
        assert_eq!(v["id"], 2, "the refusal keeps the request id");
        assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);

        let call = current(
            3,
            "tools/call",
            serde_json::json!({ "name": "list_notes", "arguments": {} }),
        );
        let (status, body) = run_h(current_headers("tools/call", Some("list_notes")), &call);
        assert_eq!(status, 200);
        let r = &json(&body)["result"];
        assert_eq!(r["resultType"], RESULT_COMPLETE);
        assert_eq!(r["structuredContent"]["tool"], "list_notes");
        assert!(
            r.get("ttlMs").is_none(),
            "a call result is not a cacheable list"
        );
    }

    #[test]
    fn server_discover_describes_both_revisions_and_initialize_is_gone() {
        let (status, body) = run_h(
            current_headers("server/discover", None),
            &current(1, "server/discover", serde_json::json!({})),
        );
        assert_eq!(status, 200);
        let r = &json(&body)["result"];
        assert_eq!(
            r["supportedVersions"],
            serde_json::json!(SUPPORTED_VERSIONS)
        );
        assert_eq!(
            r["supportedVersions"][0], PROTOCOL_VERSION,
            "the preferred revision is listed first"
        );
        assert!(r["capabilities"]["tools"].is_object());
        assert_eq!(r["_meta"][META_SERVER_INFO]["name"], "notes");
        assert_eq!(r["resultType"], RESULT_COMPLETE);
        assert_eq!(r["cacheScope"], "public");
        // SEP-2575: a method the revision does not define is a 404 with -32601.
        let (status, body) = run_h(
            current_headers("initialize", None),
            &current(2, "initialize", serde_json::json!({})),
        );
        assert_eq!(status, 404);
        assert_eq!(error_code(&body), METHOD_NOT_FOUND);
        let (status, body) = run_h(
            current_headers("prompts/list", None),
            &current(3, "prompts/list", serde_json::json!({})),
        );
        assert_eq!(status, 404);
        assert_eq!(error_code(&body), METHOD_NOT_FOUND);
    }

    #[test]
    fn the_body_decides_the_revision_and_the_header_must_agree() {
        // A 2026-07-28 header on a body without the envelope: the client
        // meant the new revision and forgot _meta.
        let bare = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let (status, body) = run(Some(PROTOCOL_VERSION), &bare);
        assert_eq!(status, 400);
        assert_eq!(error_code(&body), INVALID_PARAMS);
        assert_eq!(json(&body)["id"], 1);
        // No header at all with a full envelope: the body is authoritative.
        let (status, body) = run(None, &current(2, "tools/list", serde_json::json!({})));
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["resultType"], RESULT_COMPLETE);
        // Header and body disagree: -32020, checked before support.
        let (status, body) = run(
            Some(LEGACY_PROTOCOL_VERSION),
            &current(3, "tools/list", serde_json::json!({})),
        );
        assert_eq!(status, 400);
        let v = json(&body);
        assert_eq!(v["error"]["code"], HEADER_MISMATCH);
        assert_eq!(v["error"]["data"]["header"], LEGACY_PROTOCOL_VERSION);
        assert_eq!(v["error"]["data"]["body"], PROTOCOL_VERSION);
        // A version this face does not serve: -32022 naming both lists.
        let mut future = current(4, "tools/list", serde_json::json!({}));
        future["params"]["_meta"][META_PROTOCOL_VERSION] = serde_json::json!("2027-01-01");
        let (status, body) = run(Some("2027-01-01"), &future);
        assert_eq!(
            status, 400,
            "header and body agree on an unserved version: the revision's own refusal"
        );
        let v = json(&body);
        assert_eq!(v["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(v["error"]["data"]["requested"], "2027-01-01");
        // Header and body name two different unserved versions: the
        // disagreement is reported before support is judged.
        let (status, body) = run(Some("2027-06-01"), &future);
        assert_eq!(status, 400);
        assert_eq!(error_code(&body), HEADER_MISMATCH);
        // An unserved header on a body WITHOUT _meta is still the transport
        // refusal, decided before parsing.
        let bare = serde_json::json!({"jsonrpc":"2.0","id":9,"method":"ping"});
        let (status, body) = run(Some("2027-01-01"), &bare);
        assert_eq!(status, 400);
        assert_eq!(error_code(&body), INVALID_REQUEST);
        let (status, body) = run(None, &future);
        assert_eq!(status, 400);
        let v = json(&body);
        assert_eq!(v["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            v["error"]["data"]["supported"],
            serde_json::json!(SUPPORTED_VERSIONS)
        );
        assert_eq!(v["error"]["data"]["requested"], "2027-01-01");
        // The envelope needs the client capabilities too.
        let mut no_caps = current(5, "tools/list", serde_json::json!({}));
        no_caps["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove(META_CLIENT_CAPABILITIES);
        let (status, body) = run(Some(PROTOCOL_VERSION), &no_caps);
        assert_eq!(status, 400);
        assert_eq!(error_code(&body), INVALID_PARAMS);
        // A 2025-11-25 client that volunteers _meta is still on the released wire.
        let mut legacy_meta =
            serde_json::json!({"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}});
        legacy_meta["params"]["_meta"] = serde_json::json!({});
        legacy_meta["params"]["_meta"][META_PROTOCOL_VERSION] =
            serde_json::json!(LEGACY_PROTOCOL_VERSION);
        let (status, body) = run(Some(LEGACY_PROTOCOL_VERSION), &legacy_meta);
        assert_eq!(status, 200);
        assert!(json(&body)["result"].get("resultType").is_none());
    }

    #[test]
    fn mirrored_headers_are_checked_when_they_reach_the_face() {
        let call = current(
            1,
            "tools/call",
            serde_json::json!({ "name": "list_notes", "arguments": {} }),
        );
        // Agreeing headers, padded: served.
        let padded = RequestHeaders {
            protocol_version: Some(PROTOCOL_VERSION),
            method: Some(" tools/call "),
            name: Some("list_notes"),
        };
        assert_eq!(run_h(padded, &call).0, 200);
        // A disagreeing Mcp-Method: an intermediary routed on one value and
        // the server would act on another.
        let wrong_method = current_headers("tools/list", Some("list_notes"));
        let (status, body) = run_h(wrong_method, &call);
        assert_eq!(status, 400);
        let v = json(&body);
        assert_eq!(v["error"]["code"], HEADER_MISMATCH);
        assert_eq!(v["error"]["data"]["header"], HEADER_METHOD);
        assert_eq!(v["error"]["data"]["body"], "tools/call");
        // A disagreeing Mcp-Name.
        let wrong_name = current_headers("tools/call", Some("other_tool"));
        let (status, body) = run_h(wrong_name, &call);
        assert_eq!(status, 400);
        assert_eq!(json(&body)["error"]["data"]["header"], HEADER_NAME);
        // Not forwarded: tolerated, because the face cannot tell an omission
        // from a host that did not forward the header.
        assert_eq!(
            run_h(RequestHeaders::version(Some(PROTOCOL_VERSION)), &call).0,
            200
        );
        // Under the released wire the mirrored headers are not a rule.
        let legacy_call = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_notes"}});
        let stray = RequestHeaders {
            protocol_version: None,
            method: Some("tools/list"),
            name: None,
        };
        assert_eq!(run_h(stray, &legacy_call).0, 200);
    }

    #[test]
    fn current_protocol_errors_travel_with_their_http_status() {
        // -32602 for an unknown tool is a 400 under 2026-07-28 and a 200
        // under the released wire: same JSON-RPC error, the revision's own
        // status rule.
        let unknown = current(
            1,
            "tools/call",
            serde_json::json!({ "name": "nope", "arguments": {} }),
        );
        let (status, body) = run_h(current_headers("tools/call", Some("nope")), &unknown);
        assert_eq!(status, 400);
        assert_eq!(error_code(&body), INVALID_PARAMS);
        let legacy_unknown = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}});
        let (status, body) = run(None, &legacy_unknown);
        assert_eq!(status, 200);
        assert_eq!(error_code(&body), INVALID_PARAMS);
        // A tool that ran and failed is a result, not a protocol error: 200.
        let call = current(2, "tools/call", serde_json::json!({ "name": "list_notes" }));
        let (status, body) = block(handle_h(
            &surface(),
            current_headers("tools/call", Some("list_notes")),
            &serde_json::to_vec(&call).unwrap(),
            |_, _| async { ToolOutcome::err(serde_json::json!({ "code": "X" })) },
        ));
        assert_eq!(status, 200);
        let r = &json(&body)["result"];
        assert_eq!(r["isError"], true);
        assert_eq!(r["resultType"], RESULT_COMPLETE);
    }

    #[test]
    fn request_headers_read_a_forwarded_list_case_insensitively() {
        let list = vec![
            ("Accept".to_string(), "*/*".to_string()),
            (
                "MCP-Protocol-Version".to_string(),
                PROTOCOL_VERSION.to_string(),
            ),
            ("mcp-method".to_string(), "tools/call".to_string()),
            ("Mcp-Name".to_string(), "list_notes".to_string()),
        ];
        let h = RequestHeaders::from_list(&list);
        assert_eq!(h.protocol_version, Some(PROTOCOL_VERSION));
        assert_eq!(h.method, Some("tools/call"));
        assert_eq!(h.name, Some("list_notes"));
        let none = RequestHeaders::from_list(&[]);
        assert!(none.protocol_version.is_none() && none.method.is_none() && none.name.is_none());
    }

    #[test]
    fn skills_directory_read_and_files_and_mrtr_elicitation_work_over_2026_07_28() {
        let skills = vec![crate::agent_ready::skills::Skill {
            uri: "skill://notes/triage/SKILL.md".into(),
            frontmatter: serde_json::json!({"name": "triage", "description": "Triage notes."}),
            files: vec![
                crate::agent_ready::skills::SkillFile {
                    uri: "skill://notes/triage/SKILL.md".into(),
                    mime_type: "text/markdown".into(),
                    bytes: b"---\nname: triage\ndescription: Triage notes.\n---\nBody.\n".to_vec(),
                },
                crate::agent_ready::skills::SkillFile {
                    uri: "skill://notes/triage/references/rules.md".into(),
                    mime_type: "text/markdown".into(),
                    bytes: b"# Rules\n".to_vec(),
                },
            ],
        }];
        let files_cfg = crate::agent_ready::files::FilesConfig {
            upload: true,
            max_inline_bytes: Some(1_048_576),
            download: true,
        };
        let disc_req = current(1, "server/discover", serde_json::json!({}));
        let (status, body) = block(handle_h_full(
            &surface(),
            current_headers("server/discover", None),
            &serde_json::to_vec(&disc_req).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async { None },
            |_, _| async { ToolOutcome::ok(serde_json::json!({})) },
        ));
        assert_eq!(status, 200);
        let caps = &json(&body)["result"]["capabilities"];
        assert_eq!(
            caps["extensions"]["io.modelcontextprotocol/skills"]["directoryRead"],
            true
        );
        assert_eq!(
            caps["extensions"]["io.modelcontextprotocol/files"]["upload"],
            serde_json::json!({})
        );
        assert_eq!(
            caps["extensions"]["io.modelcontextprotocol/files"]["maxInlineBytes"],
            1_048_576
        );

        let dir_req = current(
            2,
            "resources/directory/read",
            serde_json::json!({"uri": "skill://notes/triage"}),
        );
        let (status, body) = block(handle_h_full(
            &surface(),
            current_headers("resources/directory/read", Some("skill://notes/triage")),
            &serde_json::to_vec(&dir_req).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async { None },
            |_, _| async { ToolOutcome::ok(serde_json::json!({})) },
        ));
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["resources"].as_array().unwrap().len(), 2);

        // Standalone MRTR elicitation (`input_required`).
        let call_req = current(
            3,
            "tools/call",
            serde_json::json!({"name": "list_notes", "arguments": {}}),
        );
        let (status, body) = block(handle_h_full(
            &surface(),
            current_headers("tools/call", Some("list_notes")),
            &serde_json::to_vec(&call_req).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async {
                let mut reqs = Map::new();
                reqs.insert(
                    "confirm".into(),
                    crate::agent_ready::elicitation::form_request(
                        "Proceed?",
                        serde_json::json!({"type": "object", "properties": {"ok": {"type": "boolean"}}}),
                    )
                    .unwrap(),
                );
                Some(Ok(
                    crate::agent_ready::elicitation::input_required_result(reqs, "state-1".into())
                        .unwrap(),
                ))
            },
            |_, _| async { ToolOutcome::ok(serde_json::json!({})) },
        ));
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["resultType"], "input_required");
        assert_eq!(json(&body)["result"]["requestState"], "state-1");

        // SEP-2243 `=?base64?...?=` wrapped Mcp-Name header is decoded and accepted,
        // while a legacy 2025-11-25 downgrade CANNOT bypass mrtr_call's input_required gate.
        let dir_b64 = "=?base64?c2tpbGw6Ly9ub3Rlcy90cmlhZ2U=?="; // "skill://notes/triage"
        let (status, body) = block(handle_h_full(
            &surface(),
            current_headers("resources/directory/read", Some(dir_b64)),
            &serde_json::to_vec(&dir_req).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async { None },
            |_, _| async { ToolOutcome::ok(serde_json::json!({})) },
        ));
        assert_eq!(status, 200);
        assert_eq!(json(&body)["result"]["resources"].as_array().unwrap().len(), 2);

        // `"cursor": null` is accepted cleanly on skills/list and resources/directory/read.
        let null_cursor_req = current(4, "skills/list", serde_json::json!({"cursor": null}));
        let (status, _) = block(handle_h_full(
            &surface(),
            current_headers("skills/list", None),
            &serde_json::to_vec(&null_cursor_req).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async { None },
            |_, _| async { ToolOutcome::ok(serde_json::json!({})) },
        ));
        assert_eq!(status, 200);

        // Legacy 2025-11-25 request hitting a tool guarded by mrtr_call fails closed (-32021).
        let legacy_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "list_notes", "arguments": {}}
        });
        let (status, body) = block(handle_h_full(
            &surface(),
            RequestHeaders::default(),
            &serde_json::to_vec(&legacy_call).unwrap(),
            &skills,
            &[],
            &["poll"],
            |_, _| async { Err(crate::agent_ready::events::EventError::not_found()) },
            &[],
            false,
            |_, _| async { Err(crate::agent_ready::tasks::TaskError::unavailable()) },
            &files_cfg,
            |_, _| async {
                let mut reqs = Map::new();
                reqs.insert(
                    "confirm".into(),
                    crate::agent_ready::elicitation::form_request(
                        "Proceed?",
                        serde_json::json!({"type": "object", "properties": {"ok": {"type": "boolean"}}}),
                    )
                    .unwrap(),
                );
                Some(Ok(
                    crate::agent_ready::elicitation::input_required_result(reqs, "state-1".into())
                        .unwrap(),
                ))
            },
            |_, _| async { panic!("legacy call must not bypass mrtr_call and reach exec()") },
        ));
        assert_eq!(status, 200);
        assert_eq!(json(&body)["error"]["code"], -32021);
    }
}
