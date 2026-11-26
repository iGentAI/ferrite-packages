//! The declared serving surface — the single source every readiness artefact
//! is projected from.
//!
//! Ferrite's structural advantage over checklist-driven hosts: an app's
//! surface is DECLARED (routes, kinds, operations), not discovered by
//! crawling. This module is the in-app mirror of that declaration. An app
//! builds one [`Surface`] and hands it to
//! [`well_known::handle_h`](crate::agent_ready::well_known::handle_h),
//! which then answers every readiness endpoint (robots.txt, sitemap.xml,
//! llms.txt, the OpenAPI catalog, the agent card, the MCP face, markdown
//! negotiation) mechanically. Author once, project everywhere.

use ferrite_app::serde::{Deserialize, Serialize};

/// The kind of a declared route — mirrors the deployment spec's route kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum RouteKind {
    /// Request/reply JSON API.
    Api,
    /// Served content (HTML, markdown, assets).
    Content,
    /// Server-push stream (SSE).
    Stream,
    /// Bidirectional WebSocket.
    Ws,
}

impl RouteKind {
    /// The lowercase label used in generated artefacts.
    pub fn label(&self) -> &'static str {
        match self {
            RouteKind::Api => "api",
            RouteKind::Content => "content",
            RouteKind::Stream => "stream",
            RouteKind::Ws => "ws",
        }
    }
}

/// One HTTP operation on an API route — the unit an OpenAPI path item and an
/// MCP tool are both projected from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Operation {
    /// Machine name, `[a-z0-9_]+` — becomes the MCP tool name and the
    /// OpenAPI operationId.
    pub name: String,
    /// HTTP method (`GET` or `POST` on the current gateway surface).
    pub method: String,
    /// Concrete path under the app's host (e.g. `/api/notes`). `{param}`
    /// segments are allowed and projected into both OpenAPI and the MCP
    /// tool's input schema.
    pub path: String,
    /// One-line human/agent description. Written for an LLM reader: say what
    /// the operation does, what it returns, and when to use it.
    pub description: String,
    /// JSON Schema (as a serde_json value) for the request body or query
    /// parameters. `None` ⇒ generated skeleton (empty object schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<ferrite_app::serde_json::Value>,
    /// JSON Schema for the success response body, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<ferrite_app::serde_json::Value>,
    /// Safe to call without side effects (GET-shaped). Projected into the
    /// MCP tool annotation `readOnlyHint` and the agent card.
    #[serde(default)]
    pub read_only: bool,
    /// Retry-safe: the operation returns its first result when a request
    /// repeats the platform idempotency key. Every ingress request carries
    /// `idempotency_key`, but deduplicating on it is the host handler's job;
    /// set this only when the handler does, because llms.txt, the catalog
    /// and MCP `idempotentHint` advertise exactly this flag.
    #[serde(default = "default_true")]
    pub idempotent: bool,
    /// Price per call in USD micros (0 = free). Projected into the x402
    /// `accepts` block and the catalog's pricing extension.
    #[serde(default)]
    pub price_micros: u64,
}

fn default_true() -> bool {
    true
}

impl Operation {
    /// A free, retry-safe operation with a declared input schema and no
    /// declared output schema. Set `idempotent` only if the handler
    /// deduplicates on the idempotency key (see the field's contract).
    pub fn new(
        name: &str,
        method: &str,
        path: &str,
        description: &str,
        input: ferrite_app::serde_json::Value,
        read_only: bool,
    ) -> Self {
        Self {
            name: name.into(),
            method: method.into(),
            path: path.into(),
            description: description.into(),
            input_schema: Some(input),
            output_schema: None,
            read_only,
            idempotent: true,
            price_micros: 0,
        }
    }
}

/// The JSON Schema of an object with these properties.
pub fn object_schema(properties: ferrite_app::serde_json::Value, required: &[&str]) -> ferrite_app::serde_json::Value {
    ferrite_app::serde_json::json!({ "type": "object", "properties": properties, "required": required })
}

/// The JSON Schema of a described string.
pub fn string_schema(description: &str) -> ferrite_app::serde_json::Value {
    ferrite_app::serde_json::json!({ "type": "string", "description": description })
}

/// One declared route: prefix + kind + optional operations (api routes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Route {
    /// The route prefix, always starting and ending with `/` for prefixes
    /// (e.g. `/api/`) or a concrete path for single pages (`/`).
    pub prefix: String,
    pub kind: RouteKind,
    /// One-line description of what lives under this route.
    pub description: String,
    /// Declared operations (api routes; empty elsewhere).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Operation>,
}

/// One content page the app serves — enumerable, so the sitemap and llms.txt
/// can list it and markdown negotiation can serve its `.md` twin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Page {
    /// Absolute path (e.g. `/`, `/docs/pricing`).
    pub path: String,
    /// Page title (sitemap/llms.txt line).
    pub title: String,
    /// One-line summary for llms.txt.
    pub summary: String,
    /// Last modification, epoch ms (0 = unknown; sitemap omits lastmod).
    #[serde(default)]
    pub updated_ms: u64,
    /// Whether this page is important enough for the llms.txt core section
    /// (false ⇒ listed under the llms.txt `Optional` section).
    #[serde(default = "default_true")]
    pub core: bool,
}

impl Page {
    /// A page in the llms.txt core section.
    pub fn new(path: &str, title: &str, summary: &str, updated_ms: u64) -> Self {
        Self {
            path: path.into(),
            title: title.into(),
            summary: summary.into(),
            updated_ms,
            core: true,
        }
    }

    /// List this page under the llms.txt `Optional` section instead.
    pub fn optional(mut self) -> Self {
        self.core = false;
        self
    }
}

/// The complete declared surface of one app: identity + routes + pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Surface {
    /// The app's name (`{owner}/{name}` identity half).
    pub name: String,
    /// The owning account (identity half).
    pub owner: String,
    /// The canonical public origin, scheme + host, no trailing slash
    /// (e.g. `https://k3f9a2b8.ferrite.cloud`).
    pub origin: String,
    /// One-paragraph description of the app, written for an agent reader.
    pub description: String,
    /// Version label surfaced in the card/catalog.
    #[serde(default)]
    pub version: String,
    pub routes: Vec<Route>,
    /// Enumerable content pages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<Page>,
}

impl Surface {
    /// This surface as served on the request's verified authority.
    ///
    /// Discovery documents name absolute URLs — the card's A2A `url`, the MCP
    /// manifest's remote, sitemap entries — and an app deployed on an instance
    /// domain other than the one it declared would otherwise send agents to a
    /// host it does not serve. `verified_host` is the gateway-attested `Host`
    /// (`IngressRequest::verified_host`), never a caller header. Loopback
    /// authorities (`localhost`, `127.0.0.1`, `[::1]`, with any port) are served
    /// over `http://`; every other authority over `https://`. `None`, or a
    /// value that is not a plain authority, keeps the declared origin.
    pub fn served_at(mut self, verified_host: Option<&str>) -> Self {
        let Some(host) = verified_host.map(str::trim).filter(|h| !h.is_empty()) else {
            return self;
        };
        if host.len() > 256
            || host
                .bytes()
                .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@' | b' '))
        {
            return self;
        }
        let host = host.to_ascii_lowercase();
        let name = if host.starts_with('[') {
            host.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
        } else {
            host.split(':').next().unwrap_or_default().to_string()
        };
        let scheme = if matches!(name.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
            "http"
        } else {
            "https"
        };
        self.origin = format!("{scheme}://{host}");
        self
    }

    /// Every declared API operation across all routes, in declaration order.
    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.routes.iter().flat_map(|r| r.operations.iter())
    }

    /// Find an operation by its machine name.
    pub fn operation(&self, name: &str) -> Option<&Operation> {
        self.operations().find(|o| o.name == name)
    }

    /// HTTP projections cannot distinguish operations with the same method and path.
    pub fn http_collisions(&self) -> Vec<String> {
        let mut routes = std::collections::BTreeMap::new();
        let mut errors = Vec::new();
        for operation in self.operations() {
            let key = (operation.method.to_ascii_uppercase(), operation.path.as_str());
            if let Some(previous) = routes.insert(key.clone(), operation.name.as_str()) {
                errors.push(format!(
                    "ARDY_HTTP_DUP: operations '{previous}' and '{}' share {} {}",
                    operation.name, key.0, key.1
                ));
            }
        }
        errors
    }

    /// Validate the surface: names, paths, kinds. Returns a list of
    /// `ARDY_*` violation strings, empty when clean — the same gate-code
    /// discipline the platform applies to specs, applied to the readiness
    /// declaration.
    pub fn validate(&self) -> Vec<String> {
        let mut v = self.http_collisions();
        if self.name.is_empty() {
            v.push("ARDY_NAME_EMPTY: surface.name must be non-empty".to_string());
        }
        if !self.origin.starts_with("https://") && !self.origin.starts_with("http://") {
            v.push(format!(
                "ARDY_ORIGIN_SCHEME: origin '{}' must start with http:// or https://",
                self.origin
            ));
        }
        if self.origin.ends_with('/') {
            v.push(format!(
                "ARDY_ORIGIN_SLASH: origin '{}' must not end with '/'",
                self.origin
            ));
        }
        if self.description.is_empty() {
            v.push(
                "ARDY_DESC_EMPTY: surface.description must be non-empty (agents read it)"
                    .to_string(),
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for r in &self.routes {
            if !r.prefix.starts_with('/') {
                v.push(format!(
                    "ARDY_ROUTE_PREFIX: route '{}' must start with '/'",
                    r.prefix
                ));
            }
            for o in &r.operations {
                if r.kind != RouteKind::Api {
                    v.push(format!(
                        "ARDY_OP_ON_NON_API: operation '{}' declared on {} route '{}'",
                        o.name,
                        r.kind.label(),
                        r.prefix
                    ));
                }
                if o.name.is_empty()
                    || !o
                        .name
                        .bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
                {
                    v.push(format!(
                        "ARDY_OP_NAME: operation name '{}' must be [a-z0-9_]+",
                        o.name
                    ));
                }
                if !names.insert(o.name.clone()) {
                    v.push(format!(
                        "ARDY_OP_DUP: duplicate operation name '{}'",
                        o.name
                    ));
                }
                if !matches!(o.method.as_str(), "GET" | "POST") {
                    v.push(format!(
                        "ARDY_OP_METHOD: operation '{}' method '{}' must be GET or POST (the gateway's ingress surface)",
                        o.name, o.method
                    ));
                }
                if !o.path.starts_with('/') {
                    v.push(format!(
                        "ARDY_OP_PATH: operation '{}' path '{}' must start with '/'",
                        o.name, o.path
                    ));
                }
                if o.description.is_empty() {
                    v.push(format!(
                        "ARDY_OP_DESC: operation '{}' needs a description — agents choose tools by reading them",
                        o.name
                    ));
                }
            }
        }
        for p in &self.pages {
            if !p.path.starts_with('/') {
                v.push(format!(
                    "ARDY_PAGE_PATH: page '{}' must start with '/'",
                    p.path
                ));
            }
        }
        v
    }

    /// Absolute URL for a path on this surface.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.origin, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared() -> Surface {
        Surface {
            name: "notes".into(),
            owner: "labs".into(),
            origin: "https://notes.example".into(),
            description: "Notes.".into(),
            version: "1".into(),
            routes: vec![],
            pages: vec![],
        }
    }

    #[test]
    fn served_at_follows_the_verified_authority() {
        assert_eq!(declared().served_at(None).origin, "https://notes.example");
        assert_eq!(declared().served_at(Some("")).origin, "https://notes.example");
        assert_eq!(declared().served_at(Some("Notes.Customer.Build")).origin, "https://notes.customer.build");
        assert_eq!(declared().served_at(Some("app.example:8443")).origin, "https://app.example:8443");
        assert_eq!(declared().served_at(Some("127.0.0.1:8787")).origin, "http://127.0.0.1:8787");
        assert_eq!(declared().served_at(Some("localhost")).origin, "http://localhost");
        assert_eq!(declared().served_at(Some("[::1]:9000")).origin, "http://[::1]:9000");
        assert_eq!(declared().served_at(Some("127.0.0.1.evil.example")).origin, "https://127.0.0.1.evil.example");
        for hostile in ["evil.example/path", "a@b", "x y", "h?q", "h#f", "a\\b", "bad\u{7}"] {
            assert_eq!(declared().served_at(Some(hostile)).origin, "https://notes.example", "{hostile}");
        }
        assert_eq!(declared().served_at(Some("a.example")).url("/a2a"), "https://a.example/a2a");
    }
}
