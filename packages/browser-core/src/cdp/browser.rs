//! The Browser, Schema and Target domains: version, window and browser-context
//! commands, and the target and session lifecycle.

use super::{CdpBrowser, CdpCommand, CdpError, CdpEvent, DEFAULT_CONTEXT, DEFAULT_USER_AGENT, JsonValue, Session, invalid, method_not_found};

impl CdpBrowser {
    pub(super) fn browser_command(
        &mut self,
        cmd: &CdpCommand,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Browser.getVersion" => Ok(JsonValue::obj(vec![
                ("protocolVersion", JsonValue::str("1.3")),
                (
                    "product",
                    JsonValue::str("agent-browser/0.1 (Kitesurf-style)"),
                ),
                ("revision", JsonValue::str("browser-core")),
                ("userAgent", JsonValue::str(DEFAULT_USER_AGENT)),
                ("jsVersion", JsonValue::str("fe-js/0.1 (std-only)")),
            ])),
            "Browser.close" => {
                self.closed = true;
                self.sessions.clear();
                self.targets.clear();
                Ok(JsonValue::obj(vec![]))
            }
            "Browser.getWindowForTarget" => Ok(JsonValue::obj(vec![
                ("windowId", JsonValue::Num(1.0)),
                (
                    "bounds",
                    JsonValue::obj(vec![
                        ("left", JsonValue::Num(0.0)),
                        ("top", JsonValue::Num(0.0)),
                        ("width", JsonValue::Num(1280.0)),
                        ("height", JsonValue::Num(720.0)),
                        ("windowState", JsonValue::str("normal")),
                    ]),
                ),
            ])),
            "Browser.setWindowBounds"
            | "Browser.setDownloadBehavior"
            | "Browser.grantPermissions"
            | "Browser.resetPermissions"
            | "Browser.setPermission" => Ok(JsonValue::obj(vec![])),
            "Schema.getDomains" => {
                let domains = [
                    "Browser",
                    "Target",
                    "Page",
                    "Runtime",
                    "DOM",
                    "CSS",
                    "Input",
                    "Emulation",
                    "Network",
                    "Accessibility",
                    "Schema",
                    "Log",
                    "Console",
                    "Performance",
                    "Security",
                ];
                Ok(JsonValue::obj(vec![(
                    "domains",
                    JsonValue::Arr(
                        domains
                            .iter()
                            .map(|d| {
                                JsonValue::obj(vec![
                                    ("name", JsonValue::str(*d)),
                                    ("version", JsonValue::str("1.3")),
                                ])
                            })
                            .collect(),
                    ),
                )]))
            }
            other => Err(method_not_found(other)),
        }
    }

    pub(super) fn target_command(
        &mut self,
        cmd: &CdpCommand,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Target.createBrowserContext" => {
                let id = self.fresh_id("context");
                self.browser_contexts.push(id.clone());
                Ok(JsonValue::obj(vec![("browserContextId", JsonValue::str(id))]))
            }
            "Target.disposeBrowserContext" => {
                let id = cmd
                    .params
                    .get("browserContextId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("browserContextId required"))?
                    .to_string();
                if id == DEFAULT_CONTEXT {
                    return Err(invalid("the default browser context cannot be disposed"));
                }
                if !self.browser_contexts.iter().any(|c| c == &id) {
                    return Err(invalid("no such browser context"));
                }
                self.browser_contexts.retain(|c| c != &id);
                let doomed: Vec<String> = self
                    .target_contexts
                    .iter()
                    .filter(|(_, c)| **c == id)
                    .map(|(t, _)| t.clone())
                    .collect();
                for tid in doomed {
                    self.targets.remove(&tid);
                    self.target_contexts.remove(&tid);
                    self.sessions.retain(|_, s| s.target_id != tid);
                }
                Ok(JsonValue::obj(vec![]))
            }
            "Target.getBrowserContexts" => Ok(JsonValue::obj(vec![(
                "browserContextIds",
                JsonValue::Arr(
                    self.browser_contexts
                        .iter()
                        .filter(|c| *c != DEFAULT_CONTEXT)
                        .map(|c| JsonValue::str(c.clone()))
                        .collect(),
                ),
            )])),
            "Target.activateTarget" => {
                let tid = cmd
                    .params
                    .get("targetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("targetId required"))?;
                if !self.targets.contains_key(tid) {
                    return Err(invalid("no such target"));
                }
                Ok(JsonValue::obj(vec![]))
            }
            "Target.attachToBrowserTarget" => {
                let sid = self.fresh_id("browser-session");
                Ok(JsonValue::obj(vec![("sessionId", JsonValue::str(sid))]))
            }
            "Target.getTargets" => {
                let infos: Vec<JsonValue> = self
                    .targets
                    .iter()
                    .map(|(tid, url)| target_info(tid, url))
                    .collect();
                Ok(JsonValue::obj(vec![("targetInfos", JsonValue::Arr(infos))]))
            }
            "Target.createTarget" => {
                let url = cmd
                    .params
                    .get("url")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("about:blank")
                    .to_string();
                let tid = self.fresh_id("target");
                self.targets.insert(tid.clone(), url);
                Ok(JsonValue::obj(vec![("targetId", JsonValue::str(tid))]))
            }
            "Target.getTargetInfo" => {
                let tid = cmd
                    .params
                    .get("targetId")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default();
                let url = self.targets.get(tid).cloned().unwrap_or_default();
                Ok(JsonValue::obj(vec![("targetInfo", target_info(tid, &url))]))
            }
            "Target.attachToTarget" => {
                let tid = cmd
                    .params
                    .get("targetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("targetId required"))?
                    .to_string();
                let url = self
                    .targets
                    .get(&tid)
                    .cloned()
                    .ok_or_else(|| invalid("no such target"))?;
                let sid = self.fresh_id("session");
                let mut fresh = Session::fresh(&tid, &url);
                fresh.browser_context = self
                    .target_contexts
                    .get(&tid)
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_CONTEXT.to_string());
                self.sessions.insert(sid.clone(), fresh);
                self.events.push(CdpEvent {
                    method: "Target.attachedToTarget".to_string(),
                    params: JsonValue::obj(vec![
                        ("sessionId", JsonValue::str(sid.clone())),
                        ("targetInfo", target_info(&tid, &url)),
                        ("waitingForDebugger", JsonValue::Bool(false)),
                    ]),
                    session_id: None,
                });
                Ok(JsonValue::obj(vec![("sessionId", JsonValue::str(sid))]))
            }
            "Target.detachFromTarget" => {
                let sid = cmd
                    .params
                    .get("sessionId")
                    .and_then(JsonValue::as_str)
                    .or(cmd.session_id.as_deref())
                    .unwrap_or_default()
                    .to_string();
                self.sessions.remove(&sid);
                Ok(JsonValue::obj(vec![]))
            }
            "Target.closeTarget" => {
                let tid = cmd
                    .params
                    .get("targetId")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                self.targets.remove(&tid);
                self.sessions.retain(|_, s| s.target_id != tid);
                Ok(JsonValue::obj(vec![("success", JsonValue::Bool(true))]))
            }
            "Target.setDiscoverTargets" | "Target.setAutoAttach" => Ok(JsonValue::obj(vec![])),
            other => Err(method_not_found(other)),
        }
    }
}

fn target_info(tid: &str, url: &str) -> JsonValue {
    JsonValue::obj(vec![
        ("targetId", JsonValue::str(tid)),
        ("type", JsonValue::str("page")),
        ("title", JsonValue::str("")),
        ("url", JsonValue::str(url)),
        ("attached", JsonValue::Bool(true)),
        ("canAccessOpener", JsonValue::Bool(false)),
    ])
}
