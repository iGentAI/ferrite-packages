//! The Network domain: cookies, headers and captured bodies.

use super::{CdpBrowser, CdpCommand, CdpError, CdpHost, Cookie, JsonValue, b64, cookie_matches, invalid, is_address, method_not_found, to_json, url_host};

impl CdpBrowser {
    pub(super) fn network_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Network.enable" => {
                let session = self.session_for(cmd)?;
                session.network_enabled = true;
                Ok(JsonValue::obj(vec![]))
            }
            "Network.disable" => {
                let session = self.session_for(cmd)?;
                session.network_enabled = false;
                Ok(JsonValue::obj(vec![]))
            }
            "Network.getCookies" => {
                let urls: Vec<String> = match cmd.params.get("urls") {
                    Some(JsonValue::Arr(a)) => a
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_string)
                        .collect(),
                    _ => Vec::new(),
                };
                let session = self.session_for(cmd)?;
                let urls = if urls.is_empty() {
                    vec![session.url.clone()]
                } else {
                    urls
                };
                let cookies: Vec<JsonValue> = session
                    .cookies
                    .iter()
                    .filter(|c| urls.iter().any(|u| cookie_matches(c, u)))
                    .map(cookie_json)
                    .collect();
                Ok(JsonValue::obj(vec![("cookies", JsonValue::Arr(cookies))]))
            }
            "Network.getAllCookies" => {
                let session = self.session_for(cmd)?;
                let cookies: Vec<JsonValue> = session.cookies.iter().map(cookie_json).collect();
                Ok(JsonValue::obj(vec![("cookies", JsonValue::Arr(cookies))]))
            }
            "Network.setCookie" => {
                let session = self.session_for(cmd)?;
                let Some(c) = cookie_from_params(&cmd.params, &session.url) else {
                    return Err(invalid(
                        "invalid cookie: needs a name, a valid domain or url, a path starting with '/', and the attributes its prefix requires",
                    ));
                };
                session
                    .cookies
                    .retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
                session.cookies.push(c);
                Ok(JsonValue::obj(vec![("success", JsonValue::Bool(true))]))
            }
            "Network.setCookies" => {
                let list = match cmd.params.get("cookies") {
                    Some(JsonValue::Arr(a)) => a.clone(),
                    _ => return Err(invalid("cookies required")),
                };
                let session = self.session_for(cmd)?;
                for p in &list {
                    if let Some(c) = cookie_from_params(p, &session.url) {
                        session.cookies.retain(|e| {
                            !(e.name == c.name && e.domain == c.domain && e.path == c.path)
                        });
                        session.cookies.push(c);
                    }
                }
                Ok(JsonValue::obj(vec![]))
            }
            "Network.deleteCookies" => {
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_string();
                let domain = cmd
                    .params
                    .get("domain")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        cmd.params
                            .get("url")
                            .and_then(JsonValue::as_str)
                            .map(url_host)
                    });
                let path = cmd
                    .params
                    .get("path")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string);
                let session = self.session_for(cmd)?;
                session.cookies.retain(|c| {
                    !(c.name == name
                        && domain
                            .as_deref()
                            .map(|d| c.domain.trim_start_matches('.') == d.trim_start_matches('.'))
                            .unwrap_or(true)
                        && path.as_deref().map(|p| c.path == p).unwrap_or(true))
                });
                Ok(JsonValue::obj(vec![]))
            }
            "Network.clearBrowserCookies" => {
                let session = self.session_for(cmd)?;
                session.cookies.clear();
                Ok(JsonValue::obj(vec![]))
            }
            "Network.setExtraHTTPHeaders" => {
                let headers = match cmd.params.get("headers") {
                    Some(JsonValue::Obj(entries)) => entries
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.to_ascii_lowercase(),
                                v.as_str().map(str::to_string).unwrap_or_else(|| to_json(v)),
                            )
                        })
                        .collect(),
                    _ => return Err(invalid("headers required")),
                };
                let session = self.session_for(cmd)?;
                session.extra_headers = headers;
                Ok(JsonValue::obj(vec![]))
            }
            "Network.setUserAgentOverride" | "Emulation.setUserAgentOverride" => {
                let ua = cmd
                    .params
                    .get("userAgent")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("userAgent required"))?
                    .to_string();
                let locale = cmd
                    .params
                    .get("acceptLanguage")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string);
                {
                    let session = self.session_for(cmd)?;
                    session.user_agent = Some(ua);
                    if locale.is_some() {
                        session.locale = locale;
                    }
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Network.getResponseBody" => {
                let rid = cmd
                    .params
                    .get("requestId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("requestId required"))?;
                let session = self.session_for(cmd)?;
                let Some(rec) = session.requests.iter().find(|r| r.id == rid) else {
                    return Err(CdpError {
                        code: -32000,
                        message: "No resource with given identifier found".to_string(),
                    });
                };
                match String::from_utf8(rec.body.clone()) {
                    Ok(text) => Ok(JsonValue::obj(vec![
                        ("body", JsonValue::str(text)),
                        ("base64Encoded", JsonValue::Bool(false)),
                    ])),
                    Err(_) => Ok(JsonValue::obj(vec![
                        ("body", JsonValue::str(b64(&rec.body))),
                        ("base64Encoded", JsonValue::Bool(true)),
                    ])),
                }
            }
            "Network.getRequestPostData" => {
                let rid = cmd
                    .params
                    .get("requestId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("requestId required"))?;
                let session = self.session_for(cmd)?;
                let Some(rec) = session.requests.iter().find(|r| r.id == rid) else {
                    return Err(CdpError {
                        code: -32000,
                        message: "No resource with given identifier found".to_string(),
                    });
                };
                match &rec.post_data {
                    Some(d) => Ok(JsonValue::obj(vec![
                        ("postData", JsonValue::str(d.clone())),
                        ("base64Encoded", JsonValue::Bool(false)),
                    ])),
                    None => Err(CdpError {
                        code: -32000,
                        message: "No post data available for the request".to_string(),
                    }),
                }
            }
            "Network.setCacheDisabled"
            | "Network.emulateNetworkConditions"
            | "Network.clearBrowserCache"
            | "Network.setBypassServiceWorker"
            | "Network.setBlockedURLs" => Ok(JsonValue::obj(vec![])),
            other => Err(method_not_found(other)),
        }
    }
}

/// Whether a cookie attribute value can travel unaltered: no control
/// characters and no `;`, which would end the attribute.
fn cookie_text_ok(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || c == ';')
}

/// A CDP `Network.Cookie` object.
fn cookie_json(c: &Cookie) -> JsonValue {
    let mut entries = vec![
        ("name", JsonValue::str(c.name.clone())),
        ("value", JsonValue::str(c.value.clone())),
        ("domain", JsonValue::str(c.domain.clone())),
        ("path", JsonValue::str(c.path.clone())),
        ("expires", JsonValue::Num(c.expires)),
        ("size", JsonValue::Num((c.name.len() + c.value.len()) as f64)),
        ("httpOnly", JsonValue::Bool(c.http_only)),
        ("secure", JsonValue::Bool(c.secure)),
        ("session", JsonValue::Bool(c.expires < 0.0)),
        ("priority", JsonValue::str("Medium")),
    ];
    if let Some(ss) = &c.same_site {
        entries.push(("sameSite", JsonValue::str(ss.clone())));
    }
    JsonValue::obj(entries)
}

/// Decode one `Network.CookieParam` into a jar entry, or `None` when it is
/// not a cookie a browser would store. `url` (else `default_url`, the
/// session's page) names the host. Without `domain` the cookie is
/// host-only; a `domain` that is a single label (`localhost`) or an
/// address is a public suffix, accepted only as the host itself and then
/// host-only (RFC 6265 §5.3 step 5). `__Host-` cookies must be secure,
/// host-only and rooted at `/`; `__Secure-` cookies must be secure.
fn cookie_from_params(p: &JsonValue, default_url: &str) -> Option<Cookie> {
    let name = p.get("name").and_then(JsonValue::as_str)?.to_string();
    let value = p
        .get("value")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let url = p.get("url").and_then(JsonValue::as_str).unwrap_or(default_url);
    let host = url_host(url);
    let domain = match p.get("domain").and_then(JsonValue::as_str) {
        Some(d) => {
            if !cookie_text_ok(d) || d.chars().any(char::is_whitespace) {
                return None;
            }
            let bare = d.trim_start_matches('.').to_ascii_lowercase();
            if !bare.contains('.') || is_address(&bare) {
                if bare != host {
                    return None;
                }
                bare
            } else {
                format!(".{bare}")
            }
        }
        None => host,
    };
    if domain.trim_start_matches('.').is_empty() {
        return None;
    }
    let path = p.get("path").and_then(JsonValue::as_str).unwrap_or("/").to_string();
    if !path.starts_with('/') || !cookie_text_ok(&path) {
        return None;
    }
    let secure = p.get("secure").and_then(JsonValue::as_bool).unwrap_or(false);
    if name.starts_with("__Secure-") && !secure {
        return None;
    }
    if name.starts_with("__Host-") && !(secure && path == "/" && !domain.starts_with('.')) {
        return None;
    }
    Some(Cookie {
        name,
        value,
        domain,
        path,
        secure,
        http_only: p.get("httpOnly").and_then(JsonValue::as_bool).unwrap_or(false),
        same_site: p
            .get("sameSite")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        expires: p.get("expires").and_then(JsonValue::as_f64).unwrap_or(-1.0),
    })
}
