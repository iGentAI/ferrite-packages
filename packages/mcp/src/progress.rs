//! Correlated progress from the response body of one admitted MCP call.
//! This is not a session transport: no URL/header discovery or reconnection
//! occurs here. The caller supplies the request id and a unique progress token.

use ferrite_app::serde_json::{self, Value};

use crate::mcp::client::ClientError;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct Progress {
    pub current: f64,
    pub total: Option<f64>,
    pub message: Option<String>,
}

enum Mode {
    Unknown,
    Json,
    Sse,
}

pub struct ResponseBody {
    mode: Mode,
    bytes: usize,
    events: usize,
    buffer: Vec<u8>,
    previous_cr: bool,
    id: Value,
    token: Value,
    terminal: Option<Vec<u8>>,
}

impl ResponseBody {
    pub fn new(id: Value, token: Value) -> Self {
        Self {
            mode: Mode::Unknown,
            bytes: 0,
            events: 0,
            buffer: Vec::new(),
            previous_cr: false,
            id,
            token,
            terminal: None,
        }
    }

    /// Pump a wire chunk and return the progress frames known before any
    /// correlated terminal response in it. A response can end without SSE
    /// (the HTTP SDK does not expose upstream content-type headers).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Progress>, ClientError> {
        self.bytes = self.bytes.saturating_add(chunk.len());
        if self.bytes > MAX_BODY_BYTES {
            return Err(malformed("MCP response exceeded its body limit"));
        }
        if self.terminal.is_some() {
            return Ok(Vec::new());
        }
        if matches!(self.mode, Mode::Unknown) {
            let first = chunk.iter().find(|byte| !byte.is_ascii_whitespace());
            self.mode = match first {
                Some(b'{' | b'[') => Mode::Json,
                Some(_) => Mode::Sse,
                None => Mode::Unknown,
            };
        }
        if matches!(self.mode, Mode::Unknown | Mode::Json) {
            self.buffer.extend_from_slice(chunk);
            return Ok(Vec::new());
        }
        let mut progress = Vec::new();
        for &byte in chunk {
            if byte == b'\n' && self.previous_cr {
                self.previous_cr = false;
                continue;
            }
            self.previous_cr = byte == b'\r';
            self.buffer
                .push(if self.previous_cr { b'\n' } else { byte });
            if self.buffer.ends_with(b"\n\n") {
                if let Some(update) = self.event()? {
                    progress.push(update);
                }
                if self.terminal.is_some() {
                    break;
                }
            }
        }
        Ok(progress)
    }

    pub fn completed(&self) -> bool {
        self.terminal.is_some()
    }

    fn event(&mut self) -> Result<Option<Progress>, ClientError> {
        self.events += 1;
        if self.events > MAX_EVENTS {
            return Err(malformed("MCP response exceeded its event limit"));
        }
        let frame = std::mem::take(&mut self.buffer);
        let event =
            std::str::from_utf8(&frame).map_err(|_| malformed("MCP stream is not UTF-8"))?;
        let data = event
            .lines()
            .filter_map(|line| {
                line.strip_prefix("data:")
                    .map(|data| data.strip_prefix(' ').unwrap_or(data))
            })
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            return Ok(None);
        }
        let envelope: Value = serde_json::from_str(&data)
            .map_err(|_| malformed("MCP event contains invalid JSON"))?;
        if envelope["jsonrpc"] != "2.0" {
            return Err(malformed("MCP event is not a JSON-RPC 2.0 message"));
        }
        if envelope.get("id") == Some(&self.id)
            && envelope.get("method").is_none()
            && (envelope.get("result").is_some() ^ envelope.get("error").is_some())
        {
            self.terminal = Some(data.into_bytes());
            return Ok(None);
        }
        if envelope["method"] != "notifications/progress"
            || envelope.get("id").is_some()
            || envelope["params"].get("progressToken") != Some(&self.token)
        {
            return Ok(None);
        }
        let params = &envelope["params"];
        let Some(current) = params["progress"]
            .as_f64()
            .filter(|number| number.is_finite() && *number >= 0.0)
        else {
            return Ok(None);
        };
        let total = params["total"]
            .as_f64()
            .filter(|number| number.is_finite() && *number >= current);
        // The caller redacts credentials before applying its display bound.
        // The decoded frame is already subject to the bounded body limit.
        let message = params["message"].as_str().map(str::to_owned);
        Ok(Some(Progress {
            current,
            total,
            message,
        }))
    }

    /// Yield the raw ordinary JSON or the SSE terminal JSON. The main MCP
    /// client still checks the response id/status and handles typed errors.
    pub fn finish(self) -> Result<Vec<u8>, ClientError> {
        match self.mode {
            Mode::Sse => self.terminal.ok_or_else(|| {
                ClientError::Transport("MCP stream ended before the correlated response".into())
            }),
            _ => Ok(self.buffer),
        }
    }
}

fn malformed(message: &str) -> ClientError {
    ClientError::Malformed(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json::json;

    #[test]
    fn progress_precedes_terminal_and_matches_the_original_request_token() {
        let mut body = ResponseBody::new(json!(1), json!("call-a"));
        let frames = concat!(
            ": keepalive\r\n\r\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"call-b\",\"progress\":99}}\r\n\r\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\r\n",
            "data: \"params\":{\"progressToken\":\"call-a\",\"progress\":2,\"total\":3,\"message\":\"café\"}}\r\n\r\n",
        );
        let mut seen = Vec::new();
        for byte in frames.as_bytes() {
            seen.extend(body.push(&[*byte]).unwrap());
        }
        assert_eq!(
            seen,
            [Progress {
                current: 2.0,
                total: Some(3.0),
                message: Some("café".into())
            }]
        );
        assert!(!body.completed());
        body.push(b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n")
            .unwrap();
        assert!(!body.completed());
        body.push(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n")
            .unwrap();
        assert!(body.completed());
        let reply: Value = serde_json::from_slice(&body.finish().unwrap()).unwrap();
        assert_eq!(reply["result"], json!({"content":[]}));
    }

    #[test]
    fn ordinary_json_and_early_stream_disconnect_are_distinct() {
        let mut ordinary = ResponseBody::new(json!(1), json!("call-a"));
        ordinary.push(b"  {").unwrap();
        ordinary
            .push(b"\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
            .unwrap();
        let reply: Value = serde_json::from_slice(&ordinary.finish().unwrap()).unwrap();
        assert_eq!(reply["id"], 1);
        let mut partial = ResponseBody::new(json!(1), json!("call-a"));
        partial.push(b": open\r\n\r\n").unwrap();
        assert!(matches!(partial.finish(), Err(ClientError::Transport(_))));
    }
}
