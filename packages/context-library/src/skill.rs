//! `SKILL.md` parsing with validated YAML frontmatter.
//!
//! A skill file is markdown whose first block is a `---`-fenced frontmatter
//! carrying at least `name` and `description`. Validation is strict and
//! adopted verbatim: `name` must be kebab-case and at most 64 chars;
//! `description` at most 1024 chars. Anything else in the frontmatter is
//! preserved as opaque metadata.
//!
//! The parser is deliberately a small hand parser for the `key: value`
//! subset — the format is ours, so we refuse rather than guess at YAML
//! constructs outside it (nested maps, anchors); a constrained app could not
//! link a YAML crate anyway.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Max chars in a skill name.
pub const MAX_NAME_LEN: usize = 64;
/// Max chars in a skill description.
pub const MAX_DESCRIPTION_LEN: usize = 1024;

/// A parsed, validated skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Skill {
    /// Kebab-case identifier, ≤64 chars.
    pub name: String,
    /// Human description, ≤1024 chars.
    pub description: String,
    /// Remaining frontmatter keys, preserved opaquely.
    pub metadata: BTreeMap<String, String>,
    /// The markdown body below the frontmatter.
    pub body: String,
}

/// Skill parsing/validation failures.
#[derive(Debug, PartialEq, Eq)]
pub enum SkillError {
    MissingFrontmatter,
    UnterminatedFrontmatter,
    MalformedLine(String),
    MissingKey(&'static str),
    NameNotKebab(String),
    NameTooLong,
    DescriptionTooLong,
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFrontmatter => {
                write!(
                    f,
                    "missing frontmatter: SKILL.md must start with a --- fence"
                )
            }
            Self::UnterminatedFrontmatter => write!(f, "unterminated frontmatter fence"),
            Self::MalformedLine(line) => {
                write!(f, "frontmatter line {line:?} is not `key: value`")
            }
            Self::MissingKey(key) => write!(f, "missing required key {key}"),
            Self::NameNotKebab(name) => write!(f, "name {name:?} is not kebab-case"),
            Self::NameTooLong => write!(f, "name exceeds {MAX_NAME_LEN} chars"),
            Self::DescriptionTooLong => {
                write!(f, "description exceeds {MAX_DESCRIPTION_LEN} chars")
            }
        }
    }
}

impl std::error::Error for SkillError {}

fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Parse and validate one `SKILL.md` text.
pub fn parse_skill(text: &str) -> Result<Skill, SkillError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines();
    match lines.next() {
        Some(l) if l.trim_end() == "---" => {}
        _ => return Err(SkillError::MissingFrontmatter),
    }
    let mut fm: BTreeMap<String, String> = BTreeMap::new();
    let mut closed = false;
    for line in lines.by_ref() {
        if line.trim_end() == "---" {
            closed = true;
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            return Err(SkillError::MalformedLine(line.to_string()));
        };
        let key = k.trim().to_string();
        let mut val = v.trim().to_string();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = val[1..val.len() - 1].to_string();
        }
        fm.insert(key, val);
    }
    if !closed {
        return Err(SkillError::UnterminatedFrontmatter);
    }
    let name = fm.remove("name").ok_or(SkillError::MissingKey("name"))?;
    let description = fm
        .remove("description")
        .ok_or(SkillError::MissingKey("description"))?;
    if name.chars().count() > MAX_NAME_LEN {
        return Err(SkillError::NameTooLong);
    }
    if !is_kebab(&name) {
        return Err(SkillError::NameNotKebab(name));
    }
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(SkillError::DescriptionTooLong);
    }
    let body: String = lines.collect::<Vec<_>>().join("\n");
    Ok(Skill {
        name,
        description,
        metadata: fm,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "---\nname: code-review-standards\ndescription: How we review code.\nversion: \"2\"\n---\n\n# Reviewing\n\nBe kind.";

    #[test]
    fn parses_valid_skill() {
        let s = parse_skill(GOOD).unwrap();
        assert_eq!(s.name, "code-review-standards");
        assert_eq!(s.description, "How we review code.");
        assert_eq!(s.metadata.get("version").map(String::as_str), Some("2"));
        assert!(s.body.contains("# Reviewing"));
    }

    #[test]
    fn refuses_missing_frontmatter() {
        assert_eq!(
            parse_skill("# no fence").unwrap_err(),
            SkillError::MissingFrontmatter
        );
        assert_eq!(
            parse_skill("---\nname: a\n").unwrap_err(),
            SkillError::UnterminatedFrontmatter
        );
    }

    #[test]
    fn refuses_bad_names() {
        let t = |name: &str| format!("---\nname: {name}\ndescription: d\n---\nbody");
        assert!(matches!(
            parse_skill(&t("Not-Kebab")),
            Err(SkillError::NameNotKebab(_))
        ));
        assert!(matches!(
            parse_skill(&t("has space")),
            Err(SkillError::NameNotKebab(_))
        ));
        assert!(matches!(
            parse_skill(&t("double--dash")),
            Err(SkillError::NameNotKebab(_))
        ));
        assert!(matches!(
            parse_skill(&t("-leading")),
            Err(SkillError::NameNotKebab(_))
        ));
        let long = "x".repeat(65);
        assert!(matches!(
            parse_skill(&t(&long)),
            Err(SkillError::NameTooLong)
        ));
    }

    #[test]
    fn refuses_oversize_description() {
        let d = "d".repeat(1025);
        let text = format!("---\nname: ok\ndescription: {d}\n---\nbody");
        assert_eq!(
            parse_skill(&text).unwrap_err(),
            SkillError::DescriptionTooLong
        );
    }

    #[test]
    fn missing_keys_are_named() {
        assert_eq!(
            parse_skill("---\ndescription: d\n---\n").unwrap_err(),
            SkillError::MissingKey("name")
        );
        assert_eq!(
            parse_skill("---\nname: a\n---\n").unwrap_err(),
            SkillError::MissingKey("description")
        );
    }
}
