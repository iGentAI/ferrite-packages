//! The Log, Console, Performance and Security domains.

use super::super::dom::NodeId;
use super::{CdpBrowser, CdpCommand, CdpError, JsonValue, console_message_event, invalid, log_entry_event, method_not_found};

impl CdpBrowser {
    pub(super) fn diagnostics_command(
        &mut self,
        cmd: &CdpCommand,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Log.enable" | "Console.enable" => {
                let is_log = cmd.method == "Log.enable";
                let sid = cmd.session_id.clone();
                let session = self.session_for(cmd)?;
                if is_log {
                    session.log_enabled = true;
                } else {
                    session.console_enabled = true;
                }
                // Enabling replays the entries retained so far (Chrome
                // semantics for Log.enable / Console.enable).
                let replay: Vec<(String, String)> = session.log_entries.clone();
                for (level, text) in replay {
                    if is_log {
                        self.events.push(log_entry_event(&level, &text, sid.clone()));
                    } else {
                        self.events
                            .push(console_message_event(&level, &text, sid.clone()));
                    }
                }
                Ok(JsonValue::obj(vec![]))
            }
            "Log.disable" => {
                let session = self.session_for(cmd)?;
                session.log_enabled = false;
                Ok(JsonValue::obj(vec![]))
            }
            "Console.disable" => {
                let session = self.session_for(cmd)?;
                session.console_enabled = false;
                Ok(JsonValue::obj(vec![]))
            }
            "Log.clear" | "Console.clearMessages" => {
                let session = self.session_for(cmd)?;
                session.log_entries.clear();
                Ok(JsonValue::obj(vec![]))
            }
            "Log.startViolationsReport" => {
                if !matches!(cmd.params.get("config"), Some(JsonValue::Arr(_))) {
                    return Err(invalid("config required"));
                }
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Log.stopViolationsReport" => {
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Performance.enable" | "Performance.disable" => {
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Performance.getMetrics" => {
                let page = self.page_for(cmd)?;
                let nodes = page.doc.descendants(NodeId::DOCUMENT).count();
                let boxes = page.layout.boxes.len();
                let (navs, scripts, remotes) = {
                    let session = self.session_for(cmd)?;
                    (
                        session.navigations,
                        session.script_runs,
                        session.remote_objects.len(),
                    )
                };
                let metric = |name: &str, value: f64| {
                    JsonValue::obj(vec![
                        ("name", JsonValue::str(name)),
                        ("value", JsonValue::Num(value)),
                    ])
                };
                Ok(JsonValue::obj(vec![(
                    "metrics",
                    JsonValue::Arr(vec![
                        metric("Timestamp", 0.0),
                        metric("Documents", 1.0),
                        metric("Frames", 1.0),
                        metric("JSEventListeners", 0.0),
                        metric("Nodes", nodes as f64),
                        metric("LayoutObjects", boxes as f64),
                        metric("LayoutCount", 1.0),
                        metric("RecalcStyleCount", 1.0),
                        metric("Navigations", navs as f64),
                        metric("ScriptRuns", scripts as f64),
                        metric("JSHeapUsedSize", (remotes * 64) as f64),
                    ]),
                )]))
            }
            "Security.enable" => {
                let session = self.session_for(cmd)?;
                session.security_enabled = true;
                Ok(JsonValue::obj(vec![]))
            }
            "Security.disable" => {
                let session = self.session_for(cmd)?;
                session.security_enabled = false;
                Ok(JsonValue::obj(vec![]))
            }
            "Security.setIgnoreCertificateErrors" => {
                let ignore = cmd
                    .params
                    .get("ignore")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("ignore required"))?;
                let session = self.session_for(cmd)?;
                session.ignore_cert_errors = ignore;
                Ok(JsonValue::obj(vec![]))
            }
            other => Err(method_not_found(other)),
        }
    }
}
