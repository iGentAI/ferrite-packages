//! Active agentic telemetry header (`X-Ferrite-Agent-Event`).
//!
//! Emits a compact, strictly sanitized, ASCII-only, ≤256-byte semicolon-delimited
//! summary of an agentic interaction so the platform edge can observe protocol
//! surfaces, verdicts, and caller domains without inspecting response bodies or
//! exposing secrets, tokens, cookies, emails, user IDs, or request arguments.

/// Canonical lowercase HTTP response header name for active agent telemetry.
pub const AGENT_EVENT_HEADER: &str = "x-ferrite-agent-event";

/// Hard upper bound on the encoded header value, in ASCII bytes.
pub const MAX_EVENT_HEADER_BYTES: usize = 256;

/// Compact structured telemetry event serialized to [`AGENT_EVENT_HEADER`].
///
/// Wire format (only populated fields are emitted, in canonical order):
/// `s=<surface>;m=<method>;op=<op>;rev=<rev>;ok=<0|1>;err=<err>;verdict=<verdict>;approver=<user|agent>;ag=<agent_domain>;kind=<search|read|write>;x402=<micros>`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentEvent {
    pub surface: String,
    pub method: Option<String>,
    pub op: Option<String>,
    pub rev: Option<String>,
    pub ok: Option<bool>,
    pub err: Option<String>,
    pub verdict: Option<String>,
    pub approver: Option<String>,
    pub agent: Option<String>,
    pub kind: Option<String>,
    pub x402: Option<u64>,
}

impl AgentEvent {
    /// Start an event for `surface` (e.g. `"discovery"`, `"mcp"`, `"api"`).
    pub fn new(surface: &str) -> Self {
        Self {
            surface: sanitize_token(surface, 24),
            ..Self::default()
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = non_empty(sanitize_token(method, 40));
        self
    }

    pub fn with_op(mut self, op: &str) -> Self {
        self.op = non_empty(sanitize_path_or_op(op, 64));
        self
    }

    pub fn with_rev(mut self, rev: &str) -> Self {
        self.rev = non_empty(sanitize_token(rev, 24));
        self
    }

    pub fn with_ok(mut self, ok: bool) -> Self {
        self.ok = Some(ok);
        self
    }

    pub fn with_err(mut self, err: &str) -> Self {
        self.err = non_empty(sanitize_token(err, 32));
        self
    }

    pub fn with_verdict(mut self, verdict: &str) -> Self {
        self.verdict = non_empty(sanitize_token(verdict, 32));
        self
    }

    /// Record Poppy `operations` v3 approver; only `"user"` and `"agent"` are accepted.
    pub fn with_approver(mut self, approver: &str) -> Self {
        self.approver = match approver {
            "user" | "agent" => Some(approver.to_string()),
            _ => None,
        };
        self
    }

    /// Record caller agent domain extracted strictly via [`extract_agent_domain`].
    pub fn with_agent(mut self, client_id_or_url: &str) -> Self {
        self.agent = non_empty(extract_agent_domain(client_id_or_url));
        self
    }

    /// Record API action kind; only `"search"`, `"read"`, and `"write"` are accepted.
    pub fn with_kind(mut self, kind: &str) -> Self {
        self.kind = match kind {
            "search" | "read" | "write" => Some(kind.to_string()),
            _ => None,
        };
        self
    }

    /// Record settled x402 payment amount in USD micros (omitted when zero).
    pub fn with_x402(mut self, micros: u64) -> Self {
        self.x402 = (micros > 0).then_some(micros);
        self
    }

    /// Discovery document or well-known endpoint (`s=discovery;op=<path>;ok=1`).
    pub fn discovery(path: &str) -> Self {
        Self::new("discovery").with_op(path).with_ok(true)
    }

    /// Markdown twin or Accept-negotiated markdown response
    /// (`s=markdown;op=<path>;ok=1;verdict=negotiated|twin`).
    pub fn markdown(path: &str, negotiated: bool) -> Self {
        Self::new("markdown")
            .with_op(path)
            .with_ok(true)
            .with_verdict(if negotiated { "negotiated" } else { "twin" })
    }

    /// MCP Streamable HTTP response (`s=mcp;...`).
    #[allow(clippy::too_many_arguments)]
    pub fn mcp(
        revision: &str,
        method: &str,
        tool_opt: Option<&str>,
        ok: bool,
        err_code_opt: Option<i64>,
        mrtr_opt: Option<&str>,
        caller_agent_opt: Option<&str>,
    ) -> Self {
        let mut evt = Self::new("mcp").with_ok(ok);
        if !method.is_empty() {
            evt = evt.with_method(method);
        }
        if let Some(tool) = tool_opt {
            evt = evt.with_op(tool);
        }
        if !revision.is_empty() {
            evt = evt.with_rev(revision);
        }
        if let Some(code) = err_code_opt {
            evt = evt.with_err(&code.to_string());
        }
        if let Some(mrtr) = mrtr_opt {
            evt = evt.with_verdict(mrtr);
        }
        if let Some(ag) = caller_agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// A2A JSON-RPC response (`s=a2a;...`).
    pub fn a2a(
        method: &str,
        skill_opt: Option<&str>,
        task_state_opt: Option<&str>,
        ok: bool,
        err_opt: Option<&str>,
    ) -> Self {
        let mut evt = Self::new("a2a").with_ok(ok);
        if !method.is_empty() {
            evt = evt.with_method(method);
        }
        if let Some(skill) = skill_opt {
            evt = evt.with_op(skill);
        }
        if let Some(err) = err_opt {
            evt = evt.with_err(err);
        }
        if let Some(state) = task_state_opt {
            evt = evt.with_verdict(state);
        }
        evt
    }

    /// Poppy `operations` v3 confirmation gate outcome (`s=poppy_op;...`).
    pub fn poppy_op(
        op: &str,
        verdict: &str,
        approver_opt: Option<&str>,
        agent_opt: Option<&str>,
    ) -> Self {
        let ok = matches!(verdict, "executed" | "replayed" | "approved");
        let mut evt = Self::new("poppy_op")
            .with_op(op)
            .with_ok(ok)
            .with_verdict(verdict);
        if let Some(approver) = approver_opt {
            evt = evt.with_approver(approver);
        }
        if let Some(ag) = agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// Poppy Company Agent Conversation event (`s=poppy_conv;...`).
    pub fn poppy_conv(event: &str, agent_opt: Option<&str>) -> Self {
        let mut evt = Self::new("poppy_conv").with_op(event).with_ok(true);
        if let Some(ag) = agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// Poppy Browser Join / Browser Control event (`s=poppy_browser;...`).
    pub fn poppy_browser(event: &str, agent_opt: Option<&str>) -> Self {
        let mut evt = Self::new("poppy_browser").with_op(event).with_ok(true);
        if let Some(ag) = agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// Poppy OAuth 2.1 authorization / token / revocation event (`s=poppy_oauth;...`).
    pub fn poppy_oauth(verdict: &str, agent_opt: Option<&str>) -> Self {
        let ok = !matches!(verdict, "denied" | "error");
        let mut evt = Self::new("poppy_oauth").with_ok(ok).with_verdict(verdict);
        if let Some(ag) = agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// x402 HTTP payment event (`s=x402;...`).
    pub fn x402(op: &str, verdict: &str, settled_micros: u64) -> Self {
        let ok = verdict == "settled";
        let mut evt = Self::new("x402")
            .with_op(op)
            .with_ok(ok)
            .with_verdict(verdict);
        if settled_micros > 0 {
            evt = evt.with_x402(settled_micros);
        }
        evt
    }

    /// Application `/api/*` action helper (`s=api;op=...;ok=...;ag=...;kind=search|read|write`).
    pub fn api_action(op: &str, kind: &str, ok: bool, agent_opt: Option<&str>) -> Self {
        let mut evt = Self::new("api").with_op(op).with_ok(ok).with_kind(kind);
        if let Some(ag) = agent_opt {
            evt = evt.with_agent(ag);
        }
        evt
    }

    /// Encode to a strictly sanitized, ASCII-only, ≤256-byte semicolon-delimited string.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(96);
        let push_pair = |out: &mut String, key: &str, val: &str| {
            if val.is_empty() {
                return;
            }
            let sep_len = usize::from(!out.is_empty());
            let needed = sep_len + key.len() + 1 + val.len();
            if out.len() + needed <= MAX_EVENT_HEADER_BYTES {
                if sep_len == 1 {
                    out.push(';');
                }
                out.push_str(key);
                out.push('=');
                out.push_str(val);
            } else {
                // Truncate the value only if at least one byte of value still fits cleanly.
                let prefix_len = sep_len + key.len() + 1;
                if out.len() + prefix_len < MAX_EVENT_HEADER_BYTES {
                    let avail = MAX_EVENT_HEADER_BYTES - out.len() - prefix_len;
                    if sep_len == 1 {
                        out.push(';');
                    }
                    out.push_str(key);
                    out.push('=');
                    out.push_str(&val[..avail.min(val.len())]);
                }
            }
        };

        let surface = sanitize_token(&self.surface, 24);
        push_pair(&mut out, "s", &surface);
        if let Some(ref m) = self.method {
            let v = sanitize_token(m, 40);
            push_pair(&mut out, "m", &v);
        }
        if let Some(ref op) = self.op {
            let v = sanitize_path_or_op(op, 64);
            push_pair(&mut out, "op", &v);
        }
        if let Some(ref rev) = self.rev {
            let v = sanitize_token(rev, 24);
            push_pair(&mut out, "rev", &v);
        }
        if let Some(ok) = self.ok {
            push_pair(&mut out, "ok", if ok { "1" } else { "0" });
        }
        if let Some(ref err) = self.err {
            let v = sanitize_token(err, 32);
            push_pair(&mut out, "err", &v);
        }
        if let Some(ref verdict) = self.verdict {
            let v = sanitize_token(verdict, 32);
            push_pair(&mut out, "verdict", &v);
        }
        if let Some(ref approver) = self.approver {
            if matches!(approver.as_str(), "user" | "agent") {
                push_pair(&mut out, "approver", approver);
            }
        }
        if let Some(ref ag) = self.agent {
            let v = extract_agent_domain(ag);
            push_pair(&mut out, "ag", &v);
        }
        if let Some(ref kind) = self.kind {
            if matches!(kind.as_str(), "search" | "read" | "write") {
                push_pair(&mut out, "kind", kind);
            }
        }
        if let Some(micros) = self.x402 {
            if micros > 0 {
                let v = micros.to_string();
                push_pair(&mut out, "x402", &v);
            }
        }
        out
    }

    /// Return `(AGENT_EVENT_HEADER.to_string(), self.encode())` for owned header vectors.
    pub fn to_header(&self) -> (String, String) {
        (AGENT_EVENT_HEADER.to_string(), self.encode())
    }

    /// Return `(AGENT_EVENT_HEADER, self.encode())` for static-name header vectors
    /// (`well_known::AnswerH`, `OAuthReply`, `ConvHttpReply`, `BrowserJoinReply`).
    pub fn to_static_header(&self) -> (&'static str, String) {
        (AGENT_EVENT_HEADER, self.encode())
    }
}

/// Extract ONLY the public lowercase DNS host from a Poppy `client_id`, agent URL,
/// or bare hostname (e.g. `"https://muse.ai/poppy/agent.json"` -> `"muse.ai"`).
///
/// Returns an empty string for emails, tokens, JWTs, credentials (`user:pass@host`),
/// control characters, or malformed hosts so private identifiers are never emitted.
pub fn extract_agent_domain(client_id_or_url: &str) -> String {
    let trimmed = client_id_or_url.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b <= 0x1F || b >= 0x7F) {
        return String::new();
    }

    let (has_scheme, after_scheme) = if let Some((scheme, rest)) = trimmed.split_once("://") {
        if !(scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")) {
            return String::new();
        }
        (true, rest)
    } else {
        // Without a scheme, reject emails, key=value cookies, bearer headers, and JWT prefixes.
        if trimmed.contains('@')
            || trimmed.contains('=')
            || trimmed.contains(';')
            || trimmed.contains(char::is_whitespace)
            || trimmed.starts_with("eyJ")
        {
            return String::new();
        }
        (false, trimmed)
    };

    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    // Reject embedded credentials/userinfo (`user:pass@host`) even with a scheme.
    if authority.is_empty() || authority.contains('@') {
        return String::new();
    }

    // Strip optional `:port` (reject non-numeric ports or IPv6 literals with brackets).
    let host_raw = match authority.split_once(':') {
        Some((h, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return String::new();
            }
            h
        }
        None => authority,
    };

    let host = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 64 {
        return String::new();
    }

    if host == "localhost" {
        return host;
    }

    // Require at least two labels so opaque IDs (`usr_123`, `tok_abc`) never pass as domains.
    if !host.contains('.') {
        return String::new();
    }

    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return String::new();
        }
    }

    let last = *labels.last().unwrap_or(&"");
    let valid_tld =
        (2..=24).contains(&last.len()) && last.bytes().all(|b| b.is_ascii_lowercase());
    let valid_ipv4 = labels.len() == 4
        && labels
            .iter()
            .all(|l| l.len() <= 3 && l.parse::<u8>().is_ok());

    if valid_tld || (has_scheme && valid_ipv4) {
        host
    } else {
        String::new()
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn looks_sensitive(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.contains('@') {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("bearer ")
        || lower.starts_with("dpop ")
        || lower.starts_with("basic ")
        || lower.starts_with("cookie:")
    {
        return true;
    }
    // Reject JWT-like three-segment base64url strings (`eyJ...`).
    if trimmed.starts_with("eyJ") && trimmed.matches('.').count() >= 2 {
        return true;
    }
    false
}

/// Sanitize a path or operation name: strips any query string (`?…`) and
/// fragment (`#…`) before applying strict ASCII token filtering.
fn sanitize_path_or_op(raw: &str, max_len: usize) -> String {
    let stripped = raw.split(['?', '#']).next().unwrap_or("");
    sanitize_token(stripped, max_len)
}

/// Strictly sanitize a single header value token:
/// - rejects emails, auth headers, and JWTs;
/// - strips CR, LF, NUL, semicolons, `=`, spaces, quotes, control chars, and non-ASCII;
/// - permits only `[A-Za-z0-9._:/-]`;
/// - truncates cleanly to `max_len` ASCII bytes.
fn sanitize_token(raw: &str, max_len: usize) -> String {
    if raw.is_empty() || max_len == 0 || looks_sensitive(raw) {
        return String::new();
    }
    let mut out = String::with_capacity(raw.len().min(max_len));
    for b in raw.bytes() {
        if out.len() >= max_len {
            break;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':') {
            out.push(b as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convenience_constructors_encode_canonically() {
        assert_eq!(
            AgentEvent::discovery("/llms.txt").encode(),
            "s=discovery;op=/llms.txt;ok=1"
        );
        assert_eq!(
            AgentEvent::markdown("/docs/pricing", true).encode(),
            "s=markdown;op=/docs/pricing;ok=1;verdict=negotiated"
        );
        assert_eq!(
            AgentEvent::markdown("/docs/pricing", false).encode(),
            "s=markdown;op=/docs/pricing;ok=1;verdict=twin"
        );
        assert_eq!(
            AgentEvent::mcp(
                "2026-07-28",
                "tools/call",
                Some("list_notes"),
                true,
                None,
                Some("input_required"),
                Some("https://muse.ai/poppy/agent.json"),
            )
            .encode(),
            "s=mcp;m=tools/call;op=list_notes;rev=2026-07-28;ok=1;verdict=input_required;ag=muse.ai"
        );
        assert_eq!(
            AgentEvent::mcp(
                "2025-11-25",
                "tools/call",
                Some("bad_tool"),
                false,
                Some(-32602),
                None,
                None,
            )
            .encode(),
            "s=mcp;m=tools/call;op=bad_tool;rev=2025-11-25;ok=0;err=-32602"
        );
        assert_eq!(
            AgentEvent::a2a("message/send", Some("get_quote"), Some("completed"), true, None)
                .encode(),
            "s=a2a;m=message/send;op=get_quote;ok=1;verdict=completed"
        );
        assert_eq!(
            AgentEvent::a2a("tasks/get", None, None, false, Some("-32001")).encode(),
            "s=a2a;m=tasks/get;ok=0;err=-32001"
        );
        assert_eq!(
            AgentEvent::poppy_op(
                "booking.cancel",
                "executed",
                Some("user"),
                Some("https://muse.ai/poppy/agent.json"),
            )
            .encode(),
            "s=poppy_op;op=booking.cancel;ok=1;verdict=executed;approver=user;ag=muse.ai"
        );
        assert_eq!(
            AgentEvent::poppy_conv("message", Some("https://muse.ai/poppy/agent.json")).encode(),
            "s=poppy_conv;op=message;ok=1;ag=muse.ai"
        );
        assert_eq!(
            AgentEvent::poppy_browser("join_complete", Some("https://muse.ai/poppy/agent.json"))
                .encode(),
            "s=poppy_browser;op=join_complete;ok=1;ag=muse.ai"
        );
        assert_eq!(
            AgentEvent::poppy_oauth("grant_issued", Some("https://agent.example/agent.json"))
                .encode(),
            "s=poppy_oauth;ok=1;verdict=grant_issued;ag=agent.example"
        );
        assert_eq!(
            AgentEvent::x402("get_quote", "settled", 5000).encode(),
            "s=x402;op=get_quote;ok=1;verdict=settled;x402=5000"
        );
        assert_eq!(
            AgentEvent::x402("get_quote", "challenge", 0).encode(),
            "s=x402;op=get_quote;ok=0;verdict=challenge"
        );
        assert_eq!(
            AgentEvent::api_action("search_classes", "search", true, Some("https://muse.ai/a.json"))
                .encode(),
            "s=api;op=search_classes;ok=1;ag=muse.ai;kind=search"
        );
        let (k, v) = AgentEvent::discovery("/robots.txt").to_header();
        assert_eq!(k, AGENT_EVENT_HEADER);
        assert_eq!(v, "s=discovery;op=/robots.txt;ok=1");
    }

    #[test]
    fn extract_agent_domain_handles_urls_and_rejects_secrets() {
        assert_eq!(extract_agent_domain("https://muse.ai/poppy/agent.json"), "muse.ai");
        assert_eq!(
            extract_agent_domain("https://Sub.Agent.Example:8443/poppy/agent.json?tok=abc"),
            "sub.agent.example"
        );
        assert_eq!(extract_agent_domain("muse.ai"), "muse.ai");
        assert_eq!(extract_agent_domain("http://localhost:3000/agent.json"), "localhost");
        // Reject emails, credentials, JWTs, opaque user IDs, control characters.
        assert_eq!(extract_agent_domain("alice@example.com"), "");
        assert_eq!(extract_agent_domain("https://user:pass@evil.example/agent.json"), "");
        assert_eq!(extract_agent_domain("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sigvalue"), "");
        assert_eq!(extract_agent_domain("usr_123456"), "");
        assert_eq!(extract_agent_domain("Bearer secret.token.here"), "");
        assert_eq!(extract_agent_domain("https://muse.ai\r\nX-Injected: 1"), "");
    }

    #[test]
    fn sanitization_strips_controls_separators_query_and_enforces_256_byte_cap() {
        // Query strings, CR/LF/NUL/semicolons/non-ASCII are stripped.
        let evt = AgentEvent::discovery("/docs/guide?token=secret123&email=a@b.com#frag");
        assert_eq!(evt.encode(), "s=discovery;op=/docs/guide;ok=1");

        let hostile = AgentEvent::new("mcp;\r\n\0evil=1")
            .with_method("tools/call;injected=yes\r\n")
            .with_op("list_notes\0;x=1 café")
            .with_err("alice@example.com")
            .with_approver("admin_override")
            .with_kind("delete_all")
            .with_agent("alice@example.com");
        let encoded = hostile.encode();
        assert!(!encoded.contains('\r'));
        assert!(!encoded.contains('\n'));
        assert!(!encoded.contains('\0'));
        assert!(!encoded.contains("alice"));
        assert!(!encoded.contains("approver="));
        assert!(!encoded.contains("kind="));
        assert!(!encoded.contains("ag="));
        assert!(encoded.is_ascii());

        // Worst-case filled event stays strictly <= 256 ASCII bytes.
        let huge = "a".repeat(200);
        let full = AgentEvent::new(&huge)
            .with_method(&huge)
            .with_op(&huge)
            .with_rev(&huge)
            .with_ok(false)
            .with_err(&huge)
            .with_verdict(&huge)
            .with_approver("user")
            .with_agent("https://very-long-subdomain-name.agent-platform.example/poppy/agent.json")
            .with_kind("write")
            .with_x402(999_999_999);
        let encoded_full = full.encode();
        assert!(encoded_full.len() <= MAX_EVENT_HEADER_BYTES, "len={}", encoded_full.len());
        assert!(encoded_full.is_ascii());
        assert!(!encoded_full.ends_with(';'));
        assert!(!encoded_full.ends_with('='));
    }
}
