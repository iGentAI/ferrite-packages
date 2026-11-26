//! Blueprints: publish code + binding requirements; instantiate with the
//! recipient's own authority.
//!
//! Publish = a snapshot of a surface's code (an agent bundle, an app source
//! tree) plus per-binding annotations. Instantiate = a new deployment where
//! the RECIPIENT supplies their own grants for every declared binding. The
//! hard rule, enforced here: a blueprint never carries state, credentials,
//! schedules, chat history, or live connections — only code and declared
//! requirements.

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;
use std::collections::BTreeMap;

use crate::gatekeeper::TimestampMs;

/// Size cap on an export archive (matches the adopted `.gadget` cap: 4 MiB).
pub const MAX_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;

/// One binding the instantiator must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct BindingRequirement {
    /// Binding name the code refers to, e.g. `github`.
    pub name: String,
    /// The connector/service kind required, e.g. `connector.github`.
    pub kind: String,
    /// Author-supplied annotation shown at instantiation.
    pub annotation: BindingAnnotation,
}

/// Author guidance for one binding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct BindingAnnotation {
    /// Friendly name, e.g. `Your GitHub account`.
    pub friendly_name: String,
    /// Guidance text, e.g. `Needs read access to the repo you track`.
    pub guidance: String,
    /// A suggested resource, e.g. a repo URL the author used.
    pub suggested_resource: Option<String>,
}

/// A published blueprint version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Blueprint {
    /// Stable blueprint id.
    pub id: String,
    /// Monotonic version. Old versions are retained.
    pub version: u64,
    pub title: String,
    pub author: String,
    /// The code snapshot: path -> file text. NEVER state or credentials.
    pub files: BTreeMap<String, String>,
    /// The bindings an instance must wire with its own authority.
    pub bindings: Vec<BindingRequirement>,
    /// Promoted into the deployment's "new document" menu when set.
    pub format: Option<String>,
    pub published_at: TimestampMs,
}

/// An instantiated copy: the recipient's own deployment of the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Instance {
    pub id: String,
    pub blueprint_id: String,
    pub blueprint_version: u64,
    pub owner: String,
    /// binding name -> the grant id the OWNER supplied. Every declared
    /// binding must be present before the instance is usable.
    pub wired: BTreeMap<String, String>,
    pub created_at: TimestampMs,
}

impl Instance {
    /// Whether every declared binding has been wired by the owner.
    pub fn fully_wired(&self, blueprint: &Blueprint) -> bool {
        blueprint
            .bindings
            .iter()
            .all(|b| self.wired.contains_key(&b.name))
    }
}

/// Blueprint failures.
#[derive(Debug, PartialEq, Eq)]
pub enum BlueprintError {
    Unknown(String),
    UnknownVersion { id: String, version: u64 },
    ForbiddenContent { path: String, reason: String },
    UndeclaredBinding(String),
    MissingBinding(String),
    ArchiveTooLarge,
    InvalidArchive(String),
}

impl std::fmt::Display for BlueprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "unknown blueprint {id}"),
            Self::UnknownVersion { id, version } => {
                write!(f, "unknown version {version} of blueprint {id}")
            }
            Self::ForbiddenContent { path, reason } => write!(
                f,
                "file {path} looks like state or a credential ({reason}); blueprints carry code only"
            ),
            Self::UndeclaredBinding(name) => {
                write!(f, "binding {name} is not declared by the blueprint")
            }
            Self::MissingBinding(name) => {
                write!(f, "missing binding {name}: every declared binding must be wired")
            }
            Self::ArchiveTooLarge => write!(f, "archive exceeds {MAX_ARCHIVE_BYTES} bytes"),
            Self::InvalidArchive(reason) => write!(f, "invalid archive: {reason}"),
        }
    }
}

impl std::error::Error for BlueprintError {}

/// Path-based screening: filenames that look like state or credentials.
fn forbidden_reason(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with(".sqlite") || lower.ends_with(".db") || lower.contains("chat-history") {
        return Some("state file");
    }
    if lower.contains("secret")
        || lower.contains("credential")
        || lower.ends_with(".pem")
        || lower.contains("token")
    {
        return Some("credential material");
    }
    None
}

/// Payload alphabet for vendor tokens: `[A-Za-z0-9_-]`.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Whether `content` contains `prefix` starting at a word boundary
/// (preceding char absent or non-alphanumeric) and followed by at least
/// `min_payload` consecutive chars accepted by `payload`. Hand-rolled
/// scanning: this package deliberately carries no regex dependency.
fn has_token_shape(
    content: &str,
    prefix: &str,
    min_payload: usize,
    payload: fn(char) -> bool,
) -> bool {
    let mut base = 0;
    while let Some(rel) = content[base..].find(prefix) {
        let start = base + rel;
        let at_boundary = content[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        if at_boundary {
            let after = &content[start + prefix.len()..];
            if after
                .chars()
                .take_while(|&c| payload(c))
                .take(min_payload)
                .count()
                == min_payload
            {
                return true;
            }
        }
        // Every prefix starts with an ASCII char, so `start + 1` stays on a
        // char boundary; advancing by 1 keeps overlapping occurrences visible.
        base = start + 1;
    }
    false
}

/// Content-based screening: credential or state CONTENT hiding under an
/// innocuous filename. Complements `forbidden_reason` (path heuristics);
/// both run on publish and again on import.
fn forbidden_content_reason(content: &str) -> Option<&'static str> {
    // PEM private key blocks: `-----BEGIN <label> PRIVATE KEY-----` with any
    // label (RSA, OPENSSH, EC, or none). The earliest `-----BEGIN ` has the
    // longest suffix, so a single check covers every occurrence.
    if let Some(idx) = content.find("-----BEGIN ") {
        if content[idx..].contains("PRIVATE KEY") {
            return Some("private key material");
        }
    }
    // Vendor token shapes at word boundaries. GitHub and Slack prefixes are
    // distinctive on their own; sk-/AKIA/AIza additionally require a payload
    // run so ordinary hyphenated words ("task-list", "risk-analysis") pass.
    for prefix in ["ghp_", "gho_", "ghs_", "github_pat_", "xoxb-", "xoxp-"] {
        if has_token_shape(content, prefix, 0, is_token_char) {
            return Some("vendor token");
        }
    }
    if has_token_shape(content, "sk-", 20, is_token_char) // OpenAI-style secret key
        || has_token_shape(content, "AKIA", 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit()) // AWS access key id
        || has_token_shape(content, "AIza", 35, is_token_char)
    // Google API key
    {
        return Some("vendor token");
    }
    // SQLite database bytes smuggled as text.
    if content.starts_with("SQLite format 3") {
        return Some("SQLite database content");
    }
    // Explicit marker (test hook).
    if content.contains("FERRITE-BLUEPRINT-FORBIDDEN") {
        return Some("explicit forbidden marker");
    }
    None
}

/// Screen every file by path AND by content; shared by publish and import.
fn screen_files(files: &BTreeMap<String, String>) -> Result<(), BlueprintError> {
    for (path, content) in files {
        if let Some(reason) = forbidden_reason(path).or_else(|| forbidden_content_reason(content)) {
            return Err(BlueprintError::ForbiddenContent {
                path: path.clone(),
                reason: reason.to_string(),
            });
        }
    }
    Ok(())
}

/// The registry: versioned storage with old-version retention.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct BlueprintRegistry {
    /// id -> all published versions, ascending.
    blueprints: BTreeMap<String, Vec<Blueprint>>,
    instances: BTreeMap<String, Instance>,
    next_instance: u64,
}

impl BlueprintRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new version. Every file is screened by path AND by content:
    /// files that look like state or credentials — by name, or by content
    /// shape (private key blocks, vendor tokens, SQLite bytes) — are refused.
    /// The rule is structural, not advisory.
    pub fn publish(
        &mut self,
        id: impl Into<String>,
        title: impl Into<String>,
        author: impl Into<String>,
        files: BTreeMap<String, String>,
        bindings: Vec<BindingRequirement>,
        now: TimestampMs,
    ) -> Result<&Blueprint, BlueprintError> {
        screen_files(&files)?;
        let id = id.into();
        let versions = self.blueprints.entry(id.clone()).or_default();
        let version = versions.last().map(|b| b.version + 1).unwrap_or(1);
        versions.push(Blueprint {
            id: id.clone(),
            version,
            title: title.into(),
            author: author.into(),
            files,
            bindings,
            format: None,
            published_at: now,
        });
        Ok(versions.last().expect("just pushed"))
    }

    /// Latest version of a blueprint.
    pub fn latest(&self, id: &str) -> Result<&Blueprint, BlueprintError> {
        self.blueprints
            .get(id)
            .and_then(|v| v.last())
            .ok_or_else(|| BlueprintError::Unknown(id.to_string()))
    }

    /// A specific retained version.
    pub fn version(&self, id: &str, version: u64) -> Result<&Blueprint, BlueprintError> {
        self.blueprints
            .get(id)
            .ok_or_else(|| BlueprintError::Unknown(id.to_string()))?
            .iter()
            .find(|b| b.version == version)
            .ok_or(BlueprintError::UnknownVersion {
                id: id.to_string(),
                version,
            })
    }

    /// Promote a blueprint version into a deployment "format" (the New Doc
    /// menu). Curation is a deployment decision, recorded on the version.
    pub fn promote_format(
        &mut self,
        id: &str,
        version: u64,
        format: impl Into<String>,
    ) -> Result<(), BlueprintError> {
        let versions = self
            .blueprints
            .get_mut(id)
            .ok_or_else(|| BlueprintError::Unknown(id.to_string()))?;
        let b = versions.iter_mut().find(|b| b.version == version).ok_or(
            BlueprintError::UnknownVersion {
                id: id.to_string(),
                version,
            },
        )?;
        b.format = Some(format.into());
        Ok(())
    }

    /// Instantiate: the recipient wires their OWN grants to every declared
    /// binding. Nothing else transfers — no schedules, no data, no creds.
    pub fn instantiate(
        &mut self,
        id: &str,
        version: u64,
        owner: impl Into<String>,
        wired: BTreeMap<String, String>,
        now: TimestampMs,
    ) -> Result<&Instance, BlueprintError> {
        let bp = self.version(id, version)?;
        // Refuse wiring to undeclared bindings…
        for name in wired.keys() {
            if !bp.bindings.iter().any(|b| &b.name == name) {
                return Err(BlueprintError::UndeclaredBinding(name.clone()));
            }
        }
        // …and refuse instantiation with any declared binding missing.
        for b in &bp.bindings {
            if !wired.contains_key(&b.name) {
                return Err(BlueprintError::MissingBinding(b.name.clone()));
            }
        }
        self.next_instance += 1;
        let iid = format!("inst-{:06}", self.next_instance);
        let inst = Instance {
            id: iid.clone(),
            blueprint_id: id.to_string(),
            blueprint_version: version,
            owner: owner.into(),
            wired,
            created_at: now,
        };
        self.instances.insert(iid.clone(), inst);
        Ok(self.instances.get(&iid).expect("just inserted"))
    }

    pub fn instance(&self, id: &str) -> Option<&Instance> {
        self.instances.get(id)
    }

    /// Formats visible in the deployment's creation menu.
    pub fn formats(&self) -> Vec<&Blueprint> {
        self.blueprints
            .values()
            .flat_map(|v| v.iter())
            .filter(|b| b.format.is_some())
            .collect()
    }
}

/// A size-capped export/import archive (the `.gadget` equivalent). JSON on
/// the wire; the cap is enforced on the encoded bytes both ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ExportArchive {
    pub blueprint: Blueprint,
}

impl ExportArchive {
    pub fn export(blueprint: &Blueprint) -> Result<Vec<u8>, BlueprintError> {
        let bytes = serde_json::to_vec(&ExportArchive {
            blueprint: blueprint.clone(),
        })
        .map_err(|e| BlueprintError::InvalidArchive(e.to_string()))?;
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(BlueprintError::ArchiveTooLarge);
        }
        Ok(bytes)
    }

    pub fn import(bytes: &[u8]) -> Result<Blueprint, BlueprintError> {
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(BlueprintError::ArchiveTooLarge);
        }
        let archive: ExportArchive = serde_json::from_slice(bytes)
            .map_err(|e| BlueprintError::InvalidArchive(e.to_string()))?;
        // Imported files are re-screened, path AND content: an archive is
        // untrusted input.
        screen_files(&archive.blueprint.files)?;
        Ok(archive.blueprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> BTreeMap<String, String> {
        let mut f = BTreeMap::new();
        f.insert("src/main.rs".to_string(), "fn main() {}".to_string());
        f
    }

    fn bindings() -> Vec<BindingRequirement> {
        vec![BindingRequirement {
            name: "github".into(),
            kind: "connector.github".into(),
            annotation: BindingAnnotation {
                friendly_name: "Your GitHub account".into(),
                guidance: "Read access to the repo you want tracked".into(),
                suggested_resource: Some("https://github.com/example-org/example-repo".into()),
            },
        }]
    }

    #[test]
    fn publish_versions_are_retained() {
        let mut reg = BlueprintRegistry::new();
        reg.publish("tracker", "Repo tracker", "alice", files(), bindings(), 10)
            .unwrap();
        reg.publish(
            "tracker",
            "Repo tracker v2",
            "alice",
            files(),
            bindings(),
            20,
        )
        .unwrap();
        assert_eq!(reg.latest("tracker").unwrap().version, 2);
        assert_eq!(reg.version("tracker", 1).unwrap().title, "Repo tracker");
    }

    #[test]
    fn state_and_credentials_are_refused() {
        let mut reg = BlueprintRegistry::new();
        let mut f = files();
        f.insert("data/chat-history.json".into(), "[]".into());
        assert!(matches!(
            reg.publish("x", "t", "a", f, vec![], 1),
            Err(BlueprintError::ForbiddenContent { .. })
        ));
        let mut f = files();
        f.insert("secrets/token.txt".into(), "ghp_abc".into());
        assert!(matches!(
            reg.publish("x", "t", "a", f, vec![], 1),
            Err(BlueprintError::ForbiddenContent { .. })
        ));
    }

    #[test]
    fn private_key_content_is_refused_under_an_innocuous_filename() {
        let mut reg = BlueprintRegistry::new();
        let mut f = files();
        f.insert(
            "src/config.rs".into(),
            "pub const KEY: &str = \"-----BEGIN RSA PRIVATE KEY-----\\nMIIEow\";".into(),
        );
        assert_eq!(
            reg.publish("x", "t", "a", f, vec![], 1).unwrap_err(),
            BlueprintError::ForbiddenContent {
                path: "src/config.rs".into(),
                reason: "private key material".into(),
            }
        );
        // Every PEM label form is caught, including the bare one.
        for label in ["RSA ", "OPENSSH ", "EC ", ""] {
            let header = format!("-----BEGIN {label}PRIVATE KEY-----");
            assert_eq!(
                forbidden_content_reason(&header),
                Some("private key material")
            );
        }
    }

    #[test]
    fn vendor_token_content_is_refused() {
        // A GitHub PAT embedded mid-file under an ordinary filename.
        let mut reg = BlueprintRegistry::new();
        let mut f = files();
        f.insert(
            "src/config.rs".into(),
            "let t = \"ghp_abcdefghijklmnopqrstuvwxyz123456\";".into(),
        );
        assert_eq!(
            reg.publish("x", "t", "a", f, vec![], 1).unwrap_err(),
            BlueprintError::ForbiddenContent {
                path: "src/config.rs".into(),
                reason: "vendor token".into(),
            }
        );
        // An AWS access key id…
        let mut f = files();
        f.insert("notes.md".into(), "root key: AKIAIOSFODNN7EXAMPLE".into());
        assert!(matches!(
            reg.publish("x", "t", "a", f, vec![], 1),
            Err(BlueprintError::ForbiddenContent { .. })
        ));
        // …and an OpenAI-style secret key.
        let mut f = files();
        f.insert(
            "src/llm.rs".into(),
            "client(\"sk-abc123abc123abc123abc123\")".into(),
        );
        assert!(matches!(
            reg.publish("x", "t", "a", f, vec![], 1),
            Err(BlueprintError::ForbiddenContent { .. })
        ));
    }

    #[test]
    fn ordinary_words_sharing_token_letters_are_accepted() {
        // "risk-analysis" contains "sk-" but it is preceded by the
        // alphanumeric 'i' — not a word boundary, so it must NOT be flagged.
        assert_eq!(forbidden_content_reason("risk-analysis"), None);
        assert_eq!(forbidden_content_reason("task-list"), None);
        // A boundary "sk-" still needs a >=20-char payload ("sk-learn" is fine).
        assert_eq!(forbidden_content_reason("use sk-learn here"), None);
        // The word "private" alone is not private key material.
        assert_eq!(forbidden_content_reason("// keep this private"), None);

        let mut reg = BlueprintRegistry::new();
        let mut f = files();
        f.insert(
            "src/planner.rs".into(),
            "// Private helper: the task-list feeds the risk-analysis step.\nfn risk_analysis() {}"
                .into(),
        );
        assert!(reg.publish("ok", "t", "a", f, vec![], 1).is_ok());
    }

    #[test]
    fn content_screening_shapes_and_word_boundaries() {
        // Bare vendor prefixes at a word boundary are enough…
        for tok in ["gho_x", "ghs_y", "github_pat_z", "xoxb-1", "xoxp-2"] {
            assert_eq!(forbidden_content_reason(tok), Some("vendor token"), "{tok}");
        }
        // …and the boundary is "absent or non-alphanumeric": a quote or an
        // underscore before the prefix still counts as a boundary.
        assert_eq!(
            forbidden_content_reason("x=\"ghp_A\""),
            Some("vendor token")
        );
        assert_eq!(forbidden_content_reason("pre_ghp_A"), Some("vendor token"));
        // Alphanumeric-preceded look-alikes are not tokens.
        assert_eq!(forbidden_content_reason("Weighp_value"), None);
        assert_eq!(forbidden_content_reason("xAKIAIOSFODNN7EXAMPLE"), None);
        // AKIA needs a 16-char uppercase-alnum run; AIza needs a 35-char run.
        assert_eq!(forbidden_content_reason("AKIA is a prefix"), None);
        assert_eq!(
            forbidden_content_reason("AKIAIOSFODNN7EXAMPLE"),
            Some("vendor token")
        );
        assert_eq!(forbidden_content_reason("AIza key prefix"), None);
        assert_eq!(
            forbidden_content_reason("AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456"),
            Some("vendor token")
        );
        // SQLite bytes only count when the file STARTS with the magic.
        assert_eq!(
            forbidden_content_reason("SQLite format 3\u{0}data"),
            Some("SQLite database content")
        );
        assert_eq!(forbidden_content_reason("docs about SQLite format 3"), None);
        // Explicit marker line (test hook).
        assert_eq!(
            forbidden_content_reason("ok\nFERRITE-BLUEPRINT-FORBIDDEN\nok"),
            Some("explicit forbidden marker")
        );
    }

    #[test]
    fn instantiation_requires_every_binding_wired_by_recipient() {
        let mut reg = BlueprintRegistry::new();
        reg.publish("tracker", "T", "alice", files(), bindings(), 10)
            .unwrap();
        // Missing binding refused.
        let err = reg
            .instantiate("tracker", 1, "bob", BTreeMap::new(), 20)
            .unwrap_err();
        assert_eq!(err, BlueprintError::MissingBinding("github".into()));
        // Undeclared binding refused.
        let mut wrong = BTreeMap::new();
        wrong.insert("gitlab".to_string(), "grant-1".to_string());
        assert!(matches!(
            reg.instantiate("tracker", 1, "bob", wrong, 20),
            Err(BlueprintError::UndeclaredBinding(_))
        ));
        // Correct wiring succeeds, owned by the recipient.
        let mut wired = BTreeMap::new();
        wired.insert("github".to_string(), "bob-grant-9".to_string());
        let inst_id = reg
            .instantiate("tracker", 1, "bob", wired, 20)
            .unwrap()
            .id
            .clone();
        assert_eq!(reg.instance(&inst_id).unwrap().owner, "bob");
        let bp = reg.version("tracker", 1).unwrap();
        assert!(reg.instance(&inst_id).unwrap().fully_wired(bp));
    }

    #[test]
    fn formats_are_curated_promotions() {
        let mut reg = BlueprintRegistry::new();
        reg.publish("deck", "Slide deck", "org", files(), vec![], 10)
            .unwrap();
        assert!(reg.formats().is_empty());
        reg.promote_format("deck", 1, "New Slides").unwrap();
        assert_eq!(reg.formats().len(), 1);
    }

    #[test]
    fn export_import_roundtrip_and_caps() {
        let mut reg = BlueprintRegistry::new();
        reg.publish("t", "T", "a", files(), bindings(), 10).unwrap();
        let bp = reg.latest("t").unwrap();
        let bytes = ExportArchive::export(bp).unwrap();
        let back = ExportArchive::import(&bytes).unwrap();
        assert_eq!(&back, bp);
        // An import that smuggles state is refused.
        let mut evil = bp.clone();
        evil.files.insert("db/state.sqlite".into(), "binary".into());
        let evil_bytes = serde_json::to_vec(&ExportArchive { blueprint: evil }).unwrap();
        assert!(matches!(
            ExportArchive::import(&evil_bytes),
            Err(BlueprintError::ForbiddenContent { .. })
        ));
    }

    #[test]
    fn import_rescreens_content_not_just_names() {
        let mut reg = BlueprintRegistry::new();
        reg.publish("t", "T", "a", files(), vec![], 10).unwrap();
        let mut evil = reg.latest("t").unwrap().clone();
        evil.files.insert(
            "src/helper.rs".into(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=".into(),
        );
        let bytes = serde_json::to_vec(&ExportArchive { blueprint: evil }).unwrap();
        assert_eq!(
            ExportArchive::import(&bytes).unwrap_err(),
            BlueprintError::ForbiddenContent {
                path: "src/helper.rs".into(),
                reason: "private key material".into(),
            }
        );
    }

    #[test]
    fn oversized_archive_is_refused() {
        let mut reg = BlueprintRegistry::new();
        let mut f = files();
        f.insert("big.rs".into(), "x".repeat(MAX_ARCHIVE_BYTES));
        reg.publish("big", "B", "a", f, vec![], 1).unwrap();
        assert_eq!(
            ExportArchive::export(reg.latest("big").unwrap()).unwrap_err(),
            BlueprintError::ArchiveTooLarge
        );
        let oversize = vec![b'x'; MAX_ARCHIVE_BYTES + 1];
        assert_eq!(
            ExportArchive::import(&oversize).unwrap_err(),
            BlueprintError::ArchiveTooLarge
        );
    }
}
