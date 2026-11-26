//! Stable MCP names shared by provider declarations and Code Mode.

use crate::mcp::sha256::{sha256, to_hex};

const MAX_TOOL_NAME: usize = 64;

/// Pi's model-visible name. ASCII letters, digits and underscores are
/// kept; each other UTF-16 code unit maps to an underscore. A changed
/// suffix identifies the exact original server and wire tool name.
pub fn tool_name(server: &str, tool: &str, taken: impl FnOnce(&str) -> bool) -> String {
    let qualified: String = format!("mcp__{server}__{tool}")
        .encode_utf16()
        .map(|unit| match u8::try_from(unit) {
            Ok(byte) if byte.is_ascii_alphanumeric() || byte == b'_' => char::from(byte),
            _ => '_',
        })
        .collect();
    if qualified.len() <= MAX_TOOL_NAME && !taken(&qualified) {
        return qualified;
    }
    let exact = format!("{server}\0{tool}");
    let digest = to_hex(&sha256(exact.as_bytes()));
    format!(
        "{}_{}",
        &qualified[..qualified.len().min(MAX_TOOL_NAME - 9)],
        &digest[..8]
    )
}

pub fn namespace(server: &str) -> String {
    format!("mcp__{}", server.replace('-', "_"))
}

pub fn server_summary<'a>(description: Option<&'a str>, instructions: Option<&'a str>) -> &'a str {
    description
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| instructions.map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
}
