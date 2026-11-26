//! The readiness self-report — the Tier-4 verb, in-package.
//!
//! [`readiness_report`] audits a declared [`Surface`] the way the external
//! scoring suite audits a served origin: which checks the surface will pass
//! by construction, which need annotation, and — in the platform's gate-code
//! style — the exact change that fixes each gap. The tool that audits you
//! hands you the fix.

use ferrite_app::serde_json::{self, Value};

use crate::agent_ready::surface::{RouteKind, Surface};

/// One readiness finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable check id (matches the external suite's ids).
    pub check: &'static str,
    /// `pass` | `warn` | `fail`.
    pub status: &'static str,
    /// What was observed.
    pub evidence: String,
    /// The exact fix, when status is not `pass`.
    pub fix: String,
}

fn pass(check: &'static str, evidence: impl Into<String>) -> Finding {
    Finding {
        check,
        status: "pass",
        evidence: evidence.into(),
        fix: String::new(),
    }
}

fn warn(check: &'static str, evidence: impl Into<String>, fix: impl Into<String>) -> Finding {
    Finding {
        check,
        status: "warn",
        evidence: evidence.into(),
        fix: fix.into(),
    }
}

/// Audit the surface. Structural checks (robots, sitemap, llms.txt, catalog,
/// card, MCP) pass by construction once the surface validates; annotation
/// depth (schemas, descriptions, pages) is what the report pushes on.
pub fn readiness_report(s: &Surface) -> Vec<Finding> {
    let mut out = Vec::new();
    let violations = s.validate();
    if violations.is_empty() {
        out.push(pass(
            "surface_valid",
            "surface validates with zero ARDY_* violations",
        ));
    } else {
        out.push(Finding {
            check: "surface_valid",
            status: "fail",
            evidence: violations.join("; "),
            fix: "resolve each ARDY_* violation listed in evidence".to_string(),
        });
    }

    // Readable tier — served by construction from the surface.
    out.push(pass(
        "robots_txt",
        "generated: permissive, content-signals, sitemap pointer",
    ));
    out.push(pass(
        "sitemap",
        format!("generated from {} declared page(s)", s.pages.len()),
    ));
    if s.pages.is_empty() && s.routes.iter().any(|r| r.kind == RouteKind::Content) {
        out.push(warn(
            "llms_txt",
            "llms.txt generated but no pages are declared for a content-serving app",
            "declare Surface.pages entries (path/title/summary) so llms.txt lists them",
        ));
    } else {
        out.push(pass(
            "llms_txt",
            format!("generated with {} page(s)", s.pages.len()),
        ));
    }
    out.push(pass(
        "markdown_alternates",
        "every declared page serves a .md twin and ?format=md",
    ));
    out.push(pass(
        "structured_errors",
        "RFC 9457 problem+json on every generated error",
    ));

    // Callable tier.
    let ops: Vec<_> = s.operations().collect();
    if ops.is_empty() {
        if s.routes.iter().any(|r| r.kind == RouteKind::Api) {
            out.push(warn(
                "api_catalog",
                "api routes declared but no operations annotated — catalog is skeletal",
                "add Operation entries (name/method/path/description) to each api route",
            ));
        } else {
            out.push(pass(
                "api_catalog",
                "no api routes; catalog check not applicable",
            ));
        }
    } else {
        out.push(pass(
            "api_catalog",
            format!("OpenAPI generated with {} operation(s)", ops.len()),
        ));
        out.push(pass(
            "mcp_endpoint",
            format!("{} MCP tool(s) projected from operations", ops.len()),
        ));
        out.push(pass(
            "agent_card",
            "A2A card generated with skills from operations",
        ));
        let unschemad: Vec<&str> = ops
            .iter()
            .filter(|o| o.input_schema.is_none())
            .map(|o| o.name.as_str())
            .collect();
        if unschemad.is_empty() {
            out.push(pass("schemas", "every operation declares an input schema"));
        } else {
            out.push(warn(
                "schemas",
                format!("operations without input schemas: {}", unschemad.join(", ")),
                "set Operation.input_schema so agents can call without guessing",
            ));
        }
    }

    // Payable & identity tier.
    out.push(pass(
        "idempotency_advertised",
        "idempotency-key contract advertised in llms.txt and the catalog",
    ));
    let priced = s.operations().filter(|o| o.price_micros > 0).count();
    if priced > 0 {
        out.push(pass(
            "x402_challenge",
            format!("{priced} priced operation(s) serve 402 challenges"),
        ));
    } else {
        out.push(warn(
            "x402_challenge",
            "no priced operations — x402 surface dormant",
            "set Operation.price_micros on operations to sell per-call (optional)",
        ));
    }
    out
}

/// The report as JSON (the `/.well-known/agent-readiness` body).
pub fn readiness_json(s: &Surface) -> Value {
    readiness_json_with_poppy(s, None)
}

/// The report as JSON, including Personal Agent Protocol (Poppy 1.0) findings
/// when `poppy` is configured.
pub fn readiness_json_with_poppy(
    s: &Surface,
    poppy: Option<&crate::agent_ready::poppy::PoppyConfig>,
) -> Value {
    let mut findings = readiness_report(s);
    match poppy {
        None => findings.push(warn(
            "poppy_discovery",
            "Personal Agent Protocol (Poppy 1.0) is not configured",
            "implement PageSource::poppy() to publish /.well-known/poppy.json and exposure rules",
        )),
        Some(cfg) => {
            let violations = cfg.validate(s);
            if violations.is_empty() {
                let exposed = s.operations().filter(|o| cfg.is_exposed(&o.name)).count();
                let total = s.operations().count();
                findings.push(pass(
                    "poppy_discovery",
                    format!(
                        "Poppy 1.0 active for {} ({exposed}/{total} operations exposed)",
                        cfg.organization_name
                    ),
                ));
            } else {
                findings.push(Finding {
                    check: "poppy_discovery",
                    status: "fail",
                    evidence: violations.join("; "),
                    fix: "resolve each POPPY_* violation listed in evidence".into(),
                });
            }
        }
    }
    let passed = findings.iter().filter(|f| f.status == "pass").count();
    serde_json::json!({
        "app": s.name,
        "origin": s.origin,
        "checks": findings.iter().map(|f| serde_json::json!({
            "check": f.check,
            "status": f.status,
            "evidence": f.evidence,
            "fix": if f.fix.is_empty() { Value::Null } else { serde_json::json!(f.fix) },
        })).collect::<Vec<_>>(),
        "summary": {
            "pass": passed,
            "total": findings.len(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, Surface};

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

    #[test]
    fn report_shape() {
        let r = readiness_report(&surface());
        assert!(r
            .iter()
            .any(|f| f.check == "surface_valid" && f.status == "pass"));
        assert!(r
            .iter()
            .any(|f| f.check == "mcp_endpoint" && f.status == "pass"));
        // No input schema declared → warn with a concrete fix.
        let schemas = r.iter().find(|f| f.check == "schemas").unwrap();
        assert_eq!(schemas.status, "warn");
        assert!(schemas.fix.contains("input_schema"));
    }

    #[test]
    fn json_summary_counts() {
        let v = readiness_json(&surface());
        assert_eq!(v["app"], "notes");
        assert!(v["summary"]["pass"].as_u64().unwrap() >= 5);
        assert!(v["checks"].as_array().unwrap().len() >= 8);
    }
}
