//! MCP 2026-07-28 Elicitation client & server helpers (form mode and URL mode).

use ferrite_app::serde_json::{json, Value};

pub const METHOD_CREATE: &str = "elicitation/create";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Form,
    Url,
}

/// Capabilities object declaring form mode, URL mode, or both.
pub fn capability(form: bool, url: bool) -> Value {
    let mut obj = ferrite_app::serde_json::Map::new();
    if form {
        obj.insert("form".into(), json!({}));
    }
    if url {
        obj.insert("url".into(), json!({}));
    }
    json!({ "elicitation": Value::Object(obj) })
}

/// Check whether client capabilities support the requested mode.
/// An empty `elicitation: {}` object declares form mode only.
pub fn client_supports(capabilities: &Value, mode: Mode) -> bool {
    let Some(elicit) = capabilities.get("elicitation").and_then(Value::as_object) else {
        return false;
    };
    match mode {
        Mode::Form => elicit.is_empty() || elicit.get("form").is_some_and(Value::is_object),
        Mode::Url => elicit.get("url").is_some_and(Value::is_object),
    }
}

pub fn form_request(message: &str, requested_schema: Value) -> Value {
    json!({
        "method": METHOD_CREATE,
        "params": {
            "mode": "form",
            "message": message,
            "requestedSchema": requested_schema,
        }
    })
}

pub fn url_request(message: &str, url: &str, elicitation_id: &str) -> Value {
    json!({
        "method": METHOD_CREATE,
        "params": {
            "mode": "url",
            "message": message,
            "url": url,
            "elicitationId": elicitation_id,
        }
    })
}

pub fn accept(content: Value) -> Value {
    json!({ "action": "accept", "content": content })
}

pub fn decline() -> Value {
    json!({ "action": "decline" })
}

pub fn cancel() -> Value {
    json!({ "action": "cancel" })
}

pub fn validate_response(response: &Value) -> Result<&str, &'static str> {
    let obj = response
        .as_object()
        .ok_or("elicitation response must be an object")?;
    if obj.contains_key("jsonrpc") {
        return Err("elicitation response must not be a JSON-RPC envelope");
    }
    match obj.get("action").and_then(Value::as_str) {
        Some("accept") => {
            if obj.get("content").is_some_and(|v| !v.is_object()) {
                return Err("elicitation accept content must be an object");
            }
            Ok("accept")
        }
        Some("decline") => Ok("decline"),
        Some("cancel") => Ok("cancel"),
        _ => Err("elicitation action must be accept, decline, or cancel"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elicitation_modes_and_responses() {
        let caps = capability(true, true);
        assert!(client_supports(&caps, Mode::Form));
        assert!(client_supports(&caps, Mode::Url));
        assert!(client_supports(&json!({"elicitation": {}}), Mode::Form));
        assert!(!client_supports(&json!({"elicitation": {}}), Mode::Url));
        assert_eq!(validate_response(&accept(json!({"ok": true}))), Ok("accept"));
        assert_eq!(validate_response(&decline()), Ok("decline"));
        assert_eq!(validate_response(&cancel()), Ok("cancel"));
        assert!(validate_response(&json!({"action": "accept", "content": 1})).is_err());
    }
}
