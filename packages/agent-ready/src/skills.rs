//! Optional authored workflows (SEP-2640, `io.modelcontextprotocol/skills`).
//! Applications supply release-composed bytes; this module projects manifests,
//! reads, and directory listings without filesystem or network access.

use std::collections::BTreeMap;

use ferrite_app::serde_json::{self, Value};

pub const EXTENSION: &str = "io.modelcontextprotocol/skills";

pub struct SkillFile {
    pub uri: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

pub struct Skill {
    pub uri: String,
    pub frontmatter: Value,
    pub files: Vec<SkillFile>,
}

impl Skill {
    /// Digests describe the exact bytes served, including newlines and UTF-8.
    pub fn entry(&self) -> Value {
        serde_json::json!({
            "uri": self.uri,
            "frontmatter": self.frontmatter,
            "resources": self.files.iter().map(|file| serde_json::json!({
                "uri": file.uri,
                "digest": format!("sha256:{}", super::sha256::to_hex(&super::sha256::sha256(&file.bytes))),
                "size": file.bytes.len()
            })).collect::<Vec<_>>()
        })
    }
}

pub fn list(skills: &[Skill]) -> Value {
    serde_json::json!({"skills": skills.iter().map(Skill::entry).collect::<Vec<_>>()})
}

pub fn get(skills: &[Skill], uri: &str) -> Option<Value> {
    skills
        .iter()
        .find(|skill| skill.uri == uri)
        .map(|skill| serde_json::json!({"skill": skill.entry()}))
}

pub fn resources(skills: &[Skill]) -> Value {
    serde_json::json!({"resources": skills.iter().map(|skill| serde_json::json!({
        "uri": skill.uri,
        "name": skill.frontmatter["name"],
        "description": skill.frontmatter["description"],
        "mimeType": "text/markdown"
    })).collect::<Vec<_>>()})
}

pub fn read(skills: &[Skill], uri: &str) -> Option<Value> {
    let file = skills
        .iter()
        .flat_map(|skill| &skill.files)
        .find(|file| file.uri == uri)?;
    match std::str::from_utf8(&file.bytes) {
        Ok(text) => Some(serde_json::json!({
            "contents": [{"uri": file.uri, "mimeType": file.mime_type, "text": text}]
        })),
        Err(_) => Some(serde_json::json!({
            "contents": [{"uri": file.uri, "mimeType": file.mime_type, "blob": b64_std_encode(&file.bytes)}]
        })),
    }
}

/// SEP-2640 `resources/directory/read`: list direct children of a skill directory URI.
///
/// Directory URIs have no trailing slash (`skill://ns/my-skill` or
/// `skill://ns/my-skill/references`). Child directories are reported with
/// `mimeType: "inode/directory"`. Returns `None` for any unknown or malformed
/// directory URI (caller answers JSON-RPC `-32602`).
pub fn directory_read(skills: &[Skill], uri: &str) -> Option<Value> {
    if uri.is_empty()
        || !uri.starts_with("skill://")
        || uri.ends_with('/')
        || uri.contains("..")
        || uri.contains('\\')
        || uri.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return None;
    }
    let prefix = format!("{uri}/");
    let mut children: BTreeMap<String, Value> = BTreeMap::new();
    for file in skills.iter().flat_map(|skill| &skill.files) {
        let Some(rest) = file.uri.strip_prefix(&prefix) else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        match rest.split_once('/') {
            None => {
                children.insert(
                    file.uri.clone(),
                    serde_json::json!({
                        "uri": file.uri,
                        "name": rest,
                        "mimeType": file.mime_type,
                        "size": file.bytes.len(),
                    }),
                );
            }
            Some((dir_segment, _)) => {
                if dir_segment.is_empty() {
                    continue;
                }
                let child_uri = format!("{uri}/{dir_segment}");
                children.entry(child_uri.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "uri": child_uri,
                        "name": dir_segment,
                        "mimeType": "inode/directory",
                    })
                });
            }
        }
    }
    if children.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "resources": children.into_values().collect::<Vec<_>>()
    }))
}

fn b64_std_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        match chunk.len() {
            1 => {
                out.push('=');
                out.push('=');
            }
            2 => {
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
                out.push('=');
            }
            _ => {
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
                out.push(TABLE[(n & 63) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_skills() -> Vec<Skill> {
        vec![Skill {
            uri: "skill://demo/review/SKILL.md".into(),
            frontmatter: serde_json::json!({
                "name": "review",
                "description": "Review a change."
            }),
            files: vec![
                SkillFile {
                    uri: "skill://demo/review/SKILL.md".into(),
                    mime_type: "text/markdown".into(),
                    bytes: b"---\nname: review\ndescription: Review a change.\n---\n\nCheck it.\n"
                        .to_vec(),
                },
                SkillFile {
                    uri: "skill://demo/review/references/checklist.md".into(),
                    mime_type: "text/markdown".into(),
                    bytes: b"# Checklist\n".to_vec(),
                },
                SkillFile {
                    uri: "skill://demo/review/assets/badge.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    bytes: vec![0xff, 0x00, 0xfe, 0x01],
                },
            ],
        }]
    }

    #[test]
    fn directory_read_lists_direct_children_and_subdirectories() {
        let skills = sample_skills();
        let root = directory_read(&skills, "skill://demo/review").expect("skill root dir");
        let items = root["resources"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["uri"], "skill://demo/review/SKILL.md");
        assert_eq!(items[0]["mimeType"], "text/markdown");
        assert_eq!(items[1]["uri"], "skill://demo/review/assets");
        assert_eq!(items[1]["mimeType"], "inode/directory");
        assert_eq!(items[2]["uri"], "skill://demo/review/references");
        assert_eq!(items[2]["mimeType"], "inode/directory");

        let refs = directory_read(&skills, "skill://demo/review/references").expect("subdir");
        assert_eq!(
            refs["resources"],
            serde_json::json!([{
                "uri": "skill://demo/review/references/checklist.md",
                "name": "checklist.md",
                "mimeType": "text/markdown",
                "size": 12
            }])
        );

        assert!(directory_read(&skills, "skill://demo/review/").is_none());
        assert!(directory_read(&skills, "skill://demo/missing").is_none());
        assert!(directory_read(&skills, "skill://demo/review/..").is_none());
        assert!(directory_read(&skills, "skill:").is_none());
        assert!(directory_read(&skills, "https://example.com").is_none());
    }

    #[test]
    fn read_serves_text_and_binary_blobs_with_exact_manifest_digest() {
        let skills = sample_skills();
        let text = read(&skills, "skill://demo/review/SKILL.md").unwrap();
        assert!(text["contents"][0]["text"].is_string());

        let bin = read(&skills, "skill://demo/review/assets/badge.bin").unwrap();
        assert_eq!(bin["contents"][0]["blob"], "/wD+AQ==");
        assert!(bin["contents"][0].get("text").is_none());

        let entry = skills[0].entry();
        let asset_meta = entry["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["uri"] == "skill://demo/review/assets/badge.bin")
            .unwrap();
        assert_eq!(asset_meta["size"], 4);
        assert_eq!(
            asset_meta["digest"],
            format!(
                "sha256:{}",
                super::super::sha256::to_hex(&super::super::sha256::sha256(&[
                    0xff, 0x00, 0xfe, 0x01
                ]))
            )
        );
    }
}
