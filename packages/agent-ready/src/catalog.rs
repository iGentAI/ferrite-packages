//! Tier-2 catalog artefacts: the OpenAPI document and the A2A agent card,
//! projected from the declared [`Surface`].
//!
//! Both are *projections*: no tenant-authored spec files, no drift. The
//! OpenAPI document is served at `/.well-known/api-catalog` and the agent
//! card at `/.well-known/agent-card.json` (A2A convention).

use ferrite_app::serde_json::{self, Map, Value};

use crate::agent_ready::artefacts::paths;
use crate::agent_ready::surface::Surface;

/// The version a document names when the surface declares none.
fn version_label(s: &Surface) -> &str {
    if s.version.is_empty() {
        "0.0.0"
    } else {
        s.version.as_str()
    }
}

/// The OpenAPI 3.1 document projected from the surface.
pub fn openapi(s: &Surface) -> Result<Value, Vec<String>> {
    let collisions = s.http_collisions();
    if !collisions.is_empty() {
        return Err(collisions);
    }
    let mut paths_obj = Map::new();
    for o in s.operations() {
        let entry = paths_obj
            .entry(o.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let method = o.method.to_ascii_lowercase();
        let mut op = serde_json::json!({
            "operationId": o.name,
            "summary": o.description,
            "x-idempotent": o.idempotent,
            "x-read-only": o.read_only,
            "responses": {
                "200": { "description": "Success" },
                "default": {
                    "description": "Error (RFC 9457 problem details)",
                    "content": { "application/problem+json": {} }
                }
            }
        });
        if o.price_micros > 0 {
            op["x-price-usd-micros"] = serde_json::json!(o.price_micros);
            op["responses"]["402"] = serde_json::json!({
                "description": "Payment required (x402): body carries payment requirements"
            });
        }
        // A URL template is authoritative even when its input schema omits
        // the field or does not mark it required. OpenAPI path parameters
        // are always required and must not also become GET query parameters.
        let mut path_names = Vec::new();
        for tail in o.path.split('{').skip(1) {
            if let Some((name, _)) = tail.split_once('}') {
                if !name.is_empty() && !path_names.contains(&name) {
                    path_names.push(name);
                }
            }
        }
        let properties = o.input_schema.as_ref()
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object);
        let mut parameters: Vec<Value> = path_names.iter().map(|name| serde_json::json!({
            "name": name,
            "in": "path",
            "required": true,
            "schema": properties.and_then(|props| props.get(*name)).cloned()
                .unwrap_or_else(|| serde_json::json!({ "type": "string" }))
        })).collect();
        if o.method == "POST" {
            if let Some(schema) = &o.input_schema {
                op["requestBody"] = serde_json::json!({
                    "required": true,
                    "content": { "application/json": { "schema": schema } }
                });
            }
        } else if let Some(schema) = &o.input_schema {
            // GET: the remaining top-level properties are query parameters.
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                let required: Vec<&str> = schema
                    .get("required")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                parameters.extend(props
                    .iter()
                    .filter(|(name, _)| !path_names.contains(&name.as_str()))
                    .map(|(name, sch)| {
                        serde_json::json!({
                            "name": name,
                            "in": "query",
                            "required": required.contains(&name.as_str()),
                            "schema": sch
                        })
                    }));
            }
        }
        if let Some(out) = &o.output_schema {
            op["responses"]["200"]["content"] =
                serde_json::json!({ "application/json": { "schema": out } });
        }
        op["parameters"] = serde_json::json!(parameters);
        // Idempotency-Key is honored by operations declared idempotent;
        // advertise the header on mutating ops without promising more.
        if o.method == "POST" {
            if let Some(arr) = op["parameters"].as_array_mut() {
                arr.push(serde_json::json!({
                    "name": "idempotency-key",
                    "in": "header",
                    "required": false,
                    "description": if o.idempotent {
                        "Retry-safe: a request repeating this key returns the first result instead of running again."
                    } else {
                        "Recorded for tracing. This operation is not declared idempotent, so a retry may run again."
                    },
                    "schema": { "type": "string" }
                }));
            }
        }
        entry[method] = op;
    }

    Ok(serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": s.name,
            "version": version_label(s),
            "description": s.description,
        },
        "servers": [ { "url": s.origin } ],
        "paths": paths_obj,
        "x-mcp-endpoint": s.url(paths::MCP),
        "x-agent-card": s.url(paths::AGENT_CARD),
        "x-llms-txt": s.url(paths::LLMS)
    }))
}

/// The A2A agent card projected from the surface: identity from owner/name,
/// skills from operations, and the one interface this package actually
/// serves — A2A JSON-RPC at `/a2a` (see [`crate::agent_ready::a2a_face`]).
///
/// The card advertises only what the face implements. `streaming` and
/// `pushNotifications` are false because the face offers neither, whatever
/// stream routes the app itself declares; MCP and OpenAPI are discovered
/// through their own well-known documents, not as A2A transports.
pub fn agent_card(s: &Surface) -> Value {
    let skills: Vec<Value> = s
        .operations()
        .map(|o| {
            serde_json::json!({
                "id": o.name,
                "name": o.name,
                "description": o.description,
                "tags": [
                    if o.read_only { "read" } else { "write" },
                    if o.price_micros > 0 { "paid" } else { "free" }
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"]
            })
        })
        .collect();
    serde_json::json!({
        "protocolVersion": crate::agent_ready::a2a_face::PROTOCOL_VERSION,
        "name": format!("{}/{}", s.owner, s.name),
        "description": s.description,
        "url": s.url(paths::A2A),
        "preferredTransport": "JSONRPC",
        "version": version_label(s),
        "capabilities": { "streaming": false, "pushNotifications": false, "stateTransitionHistory": false },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": skills,
        "supportsAuthenticatedExtendedCard": false,
        "additionalInterfaces": [
            { "transport": "JSONRPC", "url": s.url(paths::A2A) }
        ]
    })
}

/// The MCP registry manifest served at `/server.json` (schema
/// static.modelcontextprotocol.io), and — identically — the well-known
/// server card. It names the remote Streamable HTTP endpoint so an agent
/// discovers the MCP face without probing.
pub fn mcp_manifest(s: &Surface) -> Value {
    serde_json::json!({
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json",
        "name": format!("{}/{}", s.owner, s.name),
        "description": s.description,
        "version": version_label(s),
        "remotes": [
            {
                "type": "streamable-http",
                "url": s.url(paths::MCP)
            }
        ],
        "websiteUrl": s.url(""),
    })
}

/// The Agent Skills index served at `/.well-known/agent-skills/index.json`
/// (skills.sh; schemas.agentskills.io): one skill, "use this app", whose
/// body is projected from the same surface.
pub fn skills_index(s: &Surface) -> Value {
    serde_json::json!({
        "$schema": "https://schemas.agentskills.io/index/v1.json",
        "skills": [
            {
                "id": format!("{}-use-this-app", s.name),
                "name": format!("Use the {} API", s.name),
                "description": s.description,
                "url": crate::agent_ready::artefacts::SKILL_PATH,
                "version": version_label(s)
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ready::surface::{Operation, Route, RouteKind, Surface};

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
                operations: vec![
                    Operation {
                        name: "list_notes".into(),
                        method: "GET".into(),
                        path: "/api/notes".into(),
                        description: "List notes.".into(),
                        input_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "q": { "type": "string" } }
                        })),
                        output_schema: None,
                        read_only: true,
                        idempotent: true,
                        price_micros: 0,
                    },
                    Operation {
                        name: "create_note".into(),
                        method: "POST".into(),
                        path: "/api/notes".into(),
                        description: "Create a note.".into(),
                        input_schema: Some(serde_json::json!({
                            "type": "object",
                            "properties": { "text": { "type": "string" } },
                            "required": ["text"]
                        })),
                        output_schema: Some(serde_json::json!({ "type": "object" })),
                        read_only: false,
                        idempotent: true,
                        price_micros: 250,
                    },
                ],
            }],
            pages: vec![],
        }
    }

    #[test]
    fn openapi_paths_and_operations() {
        let doc = openapi(&surface()).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(doc["servers"][0]["url"], "https://notes.example");
        let get = &doc["paths"]["/api/notes"]["get"];
        assert_eq!(get["operationId"], "list_notes");
        assert_eq!(get["parameters"][0]["name"], "q");
        let post = &doc["paths"]["/api/notes"]["post"];
        assert_eq!(post["operationId"], "create_note");
        assert_eq!(post["x-price-usd-micros"], 250);
        assert!(post["responses"]["402"].is_object());
        // Idempotency advertised on the mutating op.
        let has_idem = post["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "idempotency-key");
        assert!(has_idem);
    }

    #[test]
    fn openapi_get_path_parameters_are_required_and_not_duplicated_as_queries() {
        let mut s = surface();
        let operation = &mut s.routes[0].operations[0];
        operation.path = "/api/classes/{class_id}/slots/{slot}".into();
        operation.input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "class_id": { "type": "string", "minLength": 1 },
                "slot": { "type": "integer", "minimum": 0 },
                "timezone": { "type": "string" },
                "limit": { "type": "integer", "maximum": 20 }
            },
            "required": ["timezone"]
        }));
        let doc = openapi(&s).unwrap();
        assert_eq!(doc["paths"]["/api/classes/{class_id}/slots/{slot}"]["get"]["parameters"], serde_json::json!([
            { "name": "class_id", "in": "path", "required": true, "schema": { "type": "string", "minLength": 1 } },
            { "name": "slot", "in": "path", "required": true, "schema": { "type": "integer", "minimum": 0 } },
            { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "maximum": 20 } },
            { "name": "timezone", "in": "query", "required": true, "schema": { "type": "string" } }
        ]));
    }

    #[test]
    fn openapi_post_keeps_body_and_idempotency_alongside_its_path_parameter() {
        let mut s = surface();
        let operation = &mut s.routes[0].operations[1];
        operation.path = "/api/notes/{id}".into();
        operation.input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "id": { "type": "string", "pattern": "^n-" }, "text": { "type": "string" } },
            "required": ["text"]
        }));
        let expected_body = operation.input_schema.clone().unwrap();
        let doc = openapi(&s).unwrap();
        let post = &doc["paths"]["/api/notes/{id}"]["post"];
        let parameters = post["parameters"].as_array().unwrap();
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0], serde_json::json!({
            "name": "id", "in": "path", "required": true,
            "schema": { "type": "string", "pattern": "^n-" }
        }));
        assert_eq!(parameters[1]["name"], "idempotency-key");
        assert_eq!(parameters[1]["in"], "header");
        assert_eq!(post["requestBody"]["content"]["application/json"]["schema"], expected_body);
    }

    #[test]
    fn openapi_unannotated_template_parameters_have_a_string_schema_once() {
        let mut s = surface();
        let operation = &mut s.routes[0].operations[0];
        operation.path = "/api/files/{name}.{extension}/copies/{name}".into();
        operation.input_schema = None;
        let doc = openapi(&s).unwrap();
        assert_eq!(doc["paths"]["/api/files/{name}.{extension}/copies/{name}"]["get"]["parameters"], serde_json::json!([
            { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } },
            { "name": "extension", "in": "path", "required": true, "schema": { "type": "string" } }
        ]));
    }

    #[test]
    fn agent_card_shape() {
        let card = agent_card(&surface());
        assert_eq!(card["name"], "labs/notes");
        assert_eq!(card["protocolVersion"], "0.3.0");
        assert_eq!(card["skills"].as_array().unwrap().len(), 2);
        assert_eq!(card["skills"][1]["tags"][1], "paid");
        assert_eq!(card["capabilities"]["streaming"], false);
    }

    #[test]
    fn agent_card_url_is_the_a2a_jsonrpc_face() {
        let mut s = surface();
        // A declared stream route is the app's own face, not A2A streaming.
        s.routes.push(Route {
            prefix: "/events".into(),
            kind: RouteKind::Stream,
            description: "events".into(),
            operations: vec![],
        });
        let card = agent_card(&s);
        assert_eq!(card["url"], "https://notes.example/a2a");
        assert_eq!(card["preferredTransport"], "JSONRPC");
        assert_eq!(card["capabilities"]["streaming"], false);
        let interfaces = card["additionalInterfaces"].as_array().unwrap();
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0]["transport"], "JSONRPC");
        assert_eq!(interfaces[0]["url"], card["url"]);
    }
}
