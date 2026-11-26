//! Skills over MCP extension (`io.modelcontextprotocol/skills`, SEP-2640).
//!
//! Pure client discovery, capability detection, and manifest integrity
//! verification (byte size, SHA-256 digest, and URI containment) for
//! constrained Ferrite applications.

use ferrite_app::serde_json::Value;

pub const EXTENSION: &str = "io.modelcontextprotocol/skills";
pub const M_SKILLS_LIST: &str = "skills/list";
pub const M_SKILLS_GET: &str = "skills/get";
pub const M_RESOURCES_DIRECTORY_READ: &str = "resources/directory/read";

/// Whether server discovery capabilities advertise Skills over MCP
/// (requires both `resources` and `extensions["io.modelcontextprotocol/skills"]`).
pub fn supported(capabilities: &Value) -> bool {
    capabilities.get("resources").is_some_and(Value::is_object)
        && capabilities
            .get("extensions")
            .and_then(|e| e.get(EXTENSION))
            .is_some_and(Value::is_object)
}

/// Whether the server additionally advertises `resources/directory/read`.
pub fn supports_directory_read(capabilities: &Value) -> bool {
    supported(capabilities)
        && capabilities["extensions"][EXTENSION]
            .get("directoryRead")
            .and_then(Value::as_bool)
            == Some(true)
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn percent_decode_segment(seg: &str) -> Option<String> {
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn valid_contained_uri(root: &str, uri: &str) -> bool {
    let Some(rel) = uri.strip_prefix(root) else {
        return false;
    };
    if rel.is_empty()
        || uri.contains('\\')
        || uri.contains('?')
        || uri.contains('#')
        || uri.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return false;
    }
    rel.split('/').all(|seg| {
        if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('.') {
            return false;
        }
        let Some(decoded) = percent_decode_segment(seg) else {
            return false;
        };
        !decoded.is_empty()
            && decoded != "."
            && decoded != ".."
            && !decoded.starts_with('.')
            && !decoded.contains('/')
            && !decoded.contains('\\')
            && !decoded.bytes().any(|b| b < 0x20 || b == 0x7f)
    })
}

/// Verify raw bytes read via `resources/read` against a skill entry's manifest
/// (`uri` must be contained within the skill root, exist in `entry.resources`,
/// and match exact byte `size` and `sha256:` digest). Dynamic skills
/// (`"resources": "dynamic"`) return `Ok(())` only when `allow_dynamic` is true.
pub fn verify_manifest_file(
    entry: &Value,
    uri: &str,
    bytes: &[u8],
    allow_dynamic: bool,
) -> Result<(), String> {
    validate_entry(entry)?;
    let root = entry["uri"]
        .as_str()
        .and_then(|u| u.strip_suffix("SKILL.md"))
        .ok_or_else(|| "skill entry has invalid root URI".to_string())?;
    if !valid_contained_uri(root, uri) {
        return Err(format!("URI '{uri}' escapes skill root '{root}'"));
    }
    if entry.get("resources").and_then(Value::as_str) == Some("dynamic") {
        return if allow_dynamic {
            Ok(())
        } else {
            Err("dynamic skill declined by policy".into())
        };
    }
    let resources = entry
        .get("resources")
        .and_then(Value::as_array)
        .ok_or_else(|| "skill entry has no resources manifest".to_string())?;
    let declared = resources
        .iter()
        .find(|item| item.get("uri").and_then(Value::as_str) == Some(uri))
        .ok_or_else(|| format!("URI '{uri}' is not in the retained skill manifest"))?;
    let expected_size = declared
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| "manifest entry missing integer size".to_string())?;
    if bytes.len() as u64 != expected_size {
        return Err(format!(
            "skill file size mismatch for '{uri}': expected {expected_size}, got {}",
            bytes.len()
        ));
    }
    let expected_digest = declared
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "manifest entry missing digest".to_string())?;
    let actual_digest = format!(
        "sha256:{}",
        crate::mcp::sha256::to_hex(&crate::mcp::sha256::sha256(bytes))
    );
    if actual_digest != expected_digest {
        return Err(format!(
            "skill file digest mismatch for '{uri}': expected {expected_digest}, got {actual_digest}"
        ));
    }
    Ok(())
}

/// Validate that `skills/list` or `skills/get` entry carries required `skill://` `uri`,
/// slug-safe `frontmatter.name`, `frontmatter.description`, and strictly contained `resources`.
pub fn validate_entry(entry: &Value) -> Result<(), String> {
    let uri = entry
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| u.starts_with("skill://") && u.ends_with("/SKILL.md"))
        .ok_or_else(|| "skill entry uri must start with skill:// and end with /SKILL.md".to_string())?;
    let rest = uri
        .strip_prefix("skill://")
        .and_then(|s| s.strip_suffix("/SKILL.md"))
        .ok_or_else(|| "malformed skill entry uri".to_string())?;
    let (namespace, parent) = rest
        .split_once('/')
        .ok_or_else(|| "skill entry uri must have skill://<namespace>/<name>/SKILL.md shape".to_string())?;
    if !valid_slug(namespace) || !valid_slug(parent) {
        return Err("skill namespace and name must be lowercase alphanumeric hyphen slugs".into());
    }
    let fm = entry
        .get("frontmatter")
        .and_then(Value::as_object)
        .ok_or_else(|| "skill entry missing frontmatter object".to_string())?;
    let name = fm
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| valid_slug(s))
        .ok_or_else(|| "skill frontmatter name must be a valid slug".to_string())?;
    let desc = fm
        .get("description")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "skill frontmatter missing description".to_string())?;
    let _ = desc;
    // Parent directory segment must match frontmatter.name per SEP-2640.
    if parent != name {
        return Err(format!(
            "skill parent directory '{parent}' does not match frontmatter name '{name}'"
        ));
    }
    let root = uri
        .strip_suffix("SKILL.md")
        .ok_or_else(|| "skill uri missing SKILL.md suffix".to_string())?;
    match entry.get("resources") {
        Some(Value::String(s)) if s == "dynamic" => Ok(()),
        Some(Value::Array(items)) => {
            let mut seen = std::collections::BTreeSet::new();
            for item in items {
                let Some(item_uri) = item.get("uri").and_then(Value::as_str) else {
                    return Err("skill manifest resource missing string uri".into());
                };
                if !valid_contained_uri(root, item_uri) {
                    return Err(format!(
                        "skill resource '{item_uri}' escapes skill root '{root}'"
                    ));
                }
                if !seen.insert(item_uri) {
                    return Err(format!("duplicate skill resource URI '{item_uri}'"));
                }
            }
            if !seen.contains(uri) {
                return Err("skill manifest must include its own SKILL.md".into());
            }
            Ok(())
        }
        _ => Err("skill resources must be a manifest array or \"dynamic\"".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde_json::json;

    #[test]
    fn skill_capability_and_manifest_verification() {
        assert!(!supported(&json!({"extensions": {EXTENSION: {}}})));
        assert!(supported(&json!({"resources": {}, "extensions": {EXTENSION: {}}})));
        assert!(!supports_directory_read(&json!({"resources": {}, "extensions": {EXTENSION: {}}})));
        assert!(supports_directory_read(&json!({"resources": {}, "extensions": {EXTENSION: {"directoryRead": true}}})));

        let body = b"---\nname: review\ndescription: Review code.\n---\nBody.\n";
        let digest = format!(
            "sha256:{}",
            crate::mcp::sha256::to_hex(&crate::mcp::sha256::sha256(body))
        );
        let entry = json!({
            "uri": "skill://team/review/SKILL.md",
            "frontmatter": {"name": "review", "description": "Review code."},
            "resources": [{"uri": "skill://team/review/SKILL.md", "digest": digest, "size": body.len()}]
        });
        validate_entry(&entry).unwrap();
        verify_manifest_file(&entry, "skill://team/review/SKILL.md", body, false).unwrap();
        assert!(verify_manifest_file(&entry, "skill://team/review/SKILL.md", b"tampered", false).is_err());
        assert!(verify_manifest_file(&entry, "skill://team/review/other.md", body, false).is_err());

        // Security containment: reject foreign schemes, traversal slugs, out-of-tree & encoded traversal URIs.
        let bad_scheme = json!({
            "uri": "https://evil.example/review/SKILL.md",
            "frontmatter": {"name": "review", "description": "Bad scheme."},
            "resources": [{"uri": "https://evil.example/review/SKILL.md", "digest": digest, "size": body.len()}]
        });
        assert!(validate_entry(&bad_scheme).is_err());

        let dotdot_name = json!({
            "uri": "skill://team/../SKILL.md",
            "frontmatter": {"name": "..", "description": "Traversal slug."},
            "resources": [{"uri": "skill://team/../SKILL.md", "digest": digest, "size": body.len()}]
        });
        assert!(validate_entry(&dotdot_name).is_err());

        let escaped_res = json!({
            "uri": "skill://team/review/SKILL.md",
            "frontmatter": {"name": "review", "description": "Escaping resource."},
            "resources": [
                {"uri": "skill://team/review/SKILL.md", "digest": digest, "size": body.len()},
                {"uri": "file:///etc/passwd", "digest": digest, "size": 1}
            ]
        });
        assert!(validate_entry(&escaped_res).is_err());

        let pct_traversal = json!({
            "uri": "skill://team/review/SKILL.md",
            "frontmatter": {"name": "review", "description": "Encoded traversal."},
            "resources": [
                {"uri": "skill://team/review/SKILL.md", "digest": digest, "size": body.len()},
                {"uri": "skill://team/review/%2e%2e/secret.txt", "digest": digest, "size": 1}
            ]
        });
        assert!(validate_entry(&pct_traversal).is_err());

        let dup_res = json!({
            "uri": "skill://team/review/SKILL.md",
            "frontmatter": {"name": "review", "description": "Duplicate resource."},
            "resources": [
                {"uri": "skill://team/review/SKILL.md", "digest": digest, "size": body.len()},
                {"uri": "skill://team/review/SKILL.md", "digest": digest, "size": body.len()}
            ]
        });
        assert!(validate_entry(&dup_res).is_err());
    }
}
