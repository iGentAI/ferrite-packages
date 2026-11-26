//! Model-facing text and image projection of a tools/call response. The
//! caller can keep structured program data independently of this text limit.

use ferrite_app::serde_json::{self, json, Value};

pub const MODEL_TEXT_MAX_BYTES: usize = 20 * 1024;

/// The conversion retains only the fields used by models. When there are
/// no blocks, even a structured JSON null is a meaningful result.
pub fn to_model_content(result: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(blocks) = result.get("content").and_then(Value::as_array) {
        for block in blocks {
            let kind = block
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("undefined");
            let text_field = |value: &Value, key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let text = |text: String| json!({"type":"text","text":text});
            let image =
                |data: String, mime: String| json!({"type":"image","data":data,"mimeType":mime});
            let converted = match kind {
                "text" => text(text_field(block, "text")),
                "image" => image(text_field(block, "data"), text_field(block, "mimeType")),
                "audio" => text(format!("[audio {} omitted]", text_field(block, "mimeType"))),
                "resource_link" => text(format!(
                    "{}: {}",
                    text_field(block, "name"),
                    text_field(block, "uri")
                )),
                "resource" => {
                    let resource = &block["resource"];
                    if resource.get("text").is_some() {
                        text(text_field(resource, "text"))
                    } else if resource["mimeType"]
                        .as_str()
                        .is_some_and(|mime| mime.starts_with("image/"))
                    {
                        image(
                            text_field(resource, "blob"),
                            text_field(resource, "mimeType"),
                        )
                    } else {
                        let uri = text_field(resource, "uri");
                        let mime = resource["mimeType"].as_str().unwrap_or("unknown type");
                        text(format!("[binary resource {uri} ({mime}) omitted]"))
                    }
                }
                _ => text(format!("[unsupported MCP content {kind}]")),
            };
            out.push(converted);
        }
    }
    if out.is_empty() {
        if let Some(structured) = result.get("structuredContent") {
            let text =
                serde_json::to_string_pretty(structured).unwrap_or_else(|_| structured.to_string());
            out.push(json!({"type":"text","text":text}));
        }
    }
    out
}

/// A trimmed model response and, when truncation took place, the original
/// joined text for any caller that has a separately granted output store.
pub struct LimitedContent {
    pub content: Vec<Value>,
    pub full_text: Option<String>,
}

/// Keep the start and end of model-facing text above the byte limit. Images
/// follow the replacement text on truncation; otherwise block order remains.
pub fn limit_model_content(content: Vec<Value>) -> LimitedContent {
    let combined = content
        .iter()
        .filter(|block| block["type"] == "text")
        .filter_map(|block| block["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if combined.len() <= MODEL_TEXT_MAX_BYTES {
        return LimitedContent {
            content,
            full_text: None,
        };
    }
    let mut head = MODEL_TEXT_MAX_BYTES / 2;
    let mut tail = combined.len() - (MODEL_TEXT_MAX_BYTES - head);
    while !combined.is_char_boundary(head) {
        head -= 1;
    }
    while !combined.is_char_boundary(tail) {
        tail += 1;
    }
    let removed = combined[head..tail].chars().count();
    let tokens = combined.len().div_ceil(4);
    let lines = combined.bytes().filter(|&byte| byte == b'\n').count()
        + usize::from(!combined.ends_with('\n'));
    let text = format!(
        "Warning: truncated output (original token count: {tokens})\nTotal output lines: {lines}\n\n{}…{removed} chars truncated…{}",
        &combined[..head], &combined[tail..],
    );
    let content = std::iter::once(json!({"type":"text","text":text}))
        .chain(content.into_iter().filter(|block| block["type"] == "image"))
        .collect();
    LimitedContent {
        content,
        full_text: Some(combined),
    }
}

/// MCP descriptors may omit the object type or an empty properties map.
/// Preserve the supplied keywords and reject unusable shapes rather than
/// silently advertising an unconstrained object in their place.
pub fn normalize_tool_input_schema(schema: &Value) -> Result<Value, &'static str> {
    let mut normalized = schema
        .as_object()
        .cloned()
        .ok_or("inputSchema must be an object")?;
    if normalized.get("type").is_none_or(Value::is_null) {
        normalized.insert("type".to_owned(), json!("object"));
    }
    if normalized.get("type").and_then(Value::as_str) != Some("object") {
        return Err("tool input schema must describe an object");
    }
    if !normalized.contains_key("properties") {
        normalized.insert("properties".to_owned(), json!({}));
    }
    if !normalized.get("properties").is_some_and(Value::is_object) {
        return Err("tool input schema properties must be an object");
    }
    Ok(Value::Object(normalized))
}
