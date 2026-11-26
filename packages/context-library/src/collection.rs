//! Collections: the unit of organization and visibility in the context
//! library.
//!
//! A collection holds documents and skills. Its `visibility` is `Public`
//! (tenant-wide: every account in the sharing domain reads it) or `Private`
//! (exactly one owning account reads it). A collection may be git-backed —
//! recorded as provenance so teams can review context like code; syncing is
//! the host's job (scoped egress to the git host).
//!
//! The library surface is strictly READ-ONLY for agents: `list`, `read`,
//! and search (see [`crate::context_library::search`]). Publishing and
//! editing are a human/deploy path, exactly like the Cloudflare OS context
//! gatekeeper.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::context_library::skill::{parse_skill, Skill, SkillError};

/// Who can read a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum Visibility {
    /// Tenant-wide: every account in the sharing domain.
    Public,
    /// Exactly the owning account.
    Private,
}

/// One document in a collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Document {
    /// Path-like id within the collection, e.g. `metrics/definitions.md`.
    pub id: String,
    pub title: String,
    pub body: String,
}

/// A collection of documents and skills.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Collection {
    /// Stable collection id, e.g. `engineering-codex`.
    pub id: String,
    pub visibility: Visibility,
    /// The owning account (read authority for Private collections).
    pub owner: String,
    /// Optional git remote this collection mirrors (provenance only).
    pub git_remote: Option<String>,
    documents: BTreeMap<String, Document>,
    skills: BTreeMap<String, Skill>,
}

/// Context library failures. `Skill` is transparent: it displays as the inner
/// [`SkillError`] and exposes it as `source()`.
#[derive(Debug, PartialEq, Eq)]
pub enum CollectionError {
    UnknownCollection(String),
    UnknownDocument(String),
    UnknownSkill(String),
    AccessDenied { collection: String, owner: String },
    Duplicate(String),
    Skill(SkillError),
}

impl std::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCollection(id) => write!(f, "unknown collection {id}"),
            Self::UnknownDocument(id) => write!(f, "unknown document {id}"),
            Self::UnknownSkill(name) => write!(f, "unknown skill {name}"),
            Self::AccessDenied { collection, owner } => {
                write!(
                    f,
                    "access denied: collection {collection} is private to {owner}"
                )
            }
            Self::Duplicate(id) => write!(f, "duplicate id {id}"),
            Self::Skill(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CollectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Skill(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SkillError> for CollectionError {
    fn from(err: SkillError) -> Self {
        Self::Skill(err)
    }
}

impl Collection {
    pub fn new(id: impl Into<String>, visibility: Visibility, owner: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            visibility,
            owner: owner.into(),
            git_remote: None,
            documents: BTreeMap::new(),
            skills: BTreeMap::new(),
        }
    }

    pub fn git_backed(mut self, remote: impl Into<String>) -> Self {
        self.git_remote = Some(remote.into());
        self
    }

    /// Publish (or replace) a document. A human/deploy operation.
    pub fn put_document(&mut self, doc: Document) {
        self.documents.insert(doc.id.clone(), doc);
    }

    /// Publish a skill from `SKILL.md` text; validation is the gate.
    pub fn put_skill(&mut self, skill_md: &str) -> Result<&Skill, CollectionError> {
        let skill = parse_skill(skill_md)?;
        let name = skill.name.clone();
        self.skills.insert(name.clone(), skill);
        Ok(self.skills.get(&name).expect("just inserted"))
    }

    pub fn documents(&self) -> impl Iterator<Item = &Document> {
        self.documents.values()
    }

    pub fn skills(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values()
    }

    pub fn document(&self, id: &str) -> Option<&Document> {
        self.documents.get(id)
    }

    pub fn skill(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    /// Whether `account` may read this collection.
    pub fn readable_by(&self, account: &str) -> bool {
        match self.visibility {
            Visibility::Public => true,
            Visibility::Private => self.owner == account,
        }
    }
}

/// The library: every collection in one tenant's context service.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ContextLibrary {
    collections: BTreeMap<String, Collection>,
}

impl ContextLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_collection(&mut self, c: Collection) -> Result<(), CollectionError> {
        if self.collections.contains_key(&c.id) {
            return Err(CollectionError::Duplicate(c.id));
        }
        self.collections.insert(c.id.clone(), c);
        Ok(())
    }

    pub fn collection_mut(&mut self, id: &str) -> Result<&mut Collection, CollectionError> {
        self.collections
            .get_mut(id)
            .ok_or_else(|| CollectionError::UnknownCollection(id.to_string()))
    }

    /// Collections `account` may read — the agent's whole world.
    pub fn visible_to<'a>(&'a self, account: &'a str) -> impl Iterator<Item = &'a Collection> + 'a {
        self.collections
            .values()
            .filter(move |c| c.readable_by(account))
    }

    /// The library's one read-access check.
    fn readable_collection(
        &self,
        account: &str,
        collection: &str,
    ) -> Result<&Collection, CollectionError> {
        let c = self
            .collections
            .get(collection)
            .ok_or_else(|| CollectionError::UnknownCollection(collection.to_string()))?;
        if !c.readable_by(account) {
            return Err(CollectionError::AccessDenied {
                collection: collection.to_string(),
                owner: c.owner.clone(),
            });
        }
        Ok(c)
    }

    /// Read one document with access control.
    pub fn read_document(
        &self,
        account: &str,
        collection: &str,
        doc_id: &str,
    ) -> Result<&Document, CollectionError> {
        self.readable_collection(account, collection)?
            .document(doc_id)
            .ok_or_else(|| CollectionError::UnknownDocument(doc_id.to_string()))
    }

    /// Read one skill with access control.
    pub fn read_skill(
        &self,
        account: &str,
        collection: &str,
        name: &str,
    ) -> Result<&Skill, CollectionError> {
        self.readable_collection(account, collection)?
            .skill(name)
            .ok_or_else(|| CollectionError::UnknownSkill(name.to_string()))
    }

    /// Every skill `account` can see, ordered by collection id then skill
    /// name. This is the slash-command namespace.
    pub fn skills_visible_to<'a>(&'a self, account: &'a str) -> Vec<(&'a str, &'a Skill)> {
        self.visible_to(account)
            .flat_map(|c| c.skills().map(move |s| (c.id.as_str(), s)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKILL: &str = "---\nname: metric-definitions\ndescription: Canonical metric definitions.\n---\nMAU means…";

    fn library() -> ContextLibrary {
        let mut lib = ContextLibrary::new();
        let mut public = Collection::new("codex", Visibility::Public, "org");
        public.put_document(Document {
            id: "reviews.md".into(),
            title: "Code review standards".into(),
            body: "Review with care.".into(),
        });
        public.put_skill(SKILL).unwrap();
        lib.add_collection(public).unwrap();
        let mut private = Collection::new("alice-notes", Visibility::Private, "alice");
        private.put_document(Document {
            id: "draft.md".into(),
            title: "Draft".into(),
            body: "secret draft".into(),
        });
        lib.add_collection(private).unwrap();
        lib
    }

    #[test]
    fn public_collections_read_by_anyone() {
        let lib = library();
        assert!(lib.read_document("bob", "codex", "reviews.md").is_ok());
        assert!(lib.read_skill("bob", "codex", "metric-definitions").is_ok());
    }

    #[test]
    fn private_collections_read_only_by_owner() {
        let lib = library();
        assert!(lib
            .read_document("alice", "alice-notes", "draft.md")
            .is_ok());
        let err = lib
            .read_document("bob", "alice-notes", "draft.md")
            .unwrap_err();
        assert!(matches!(err, CollectionError::AccessDenied { .. }));
    }

    #[test]
    fn visibility_filters_the_agent_world() {
        let lib = library();
        let bob_sees: Vec<_> = lib.visible_to("bob").map(|c| c.id.as_str()).collect();
        assert_eq!(bob_sees, vec!["codex"]);
        let alice_sees: Vec<_> = lib.visible_to("alice").map(|c| c.id.as_str()).collect();
        assert_eq!(alice_sees, vec!["alice-notes", "codex"]);
    }

    #[test]
    fn invalid_skill_is_refused_at_publish() {
        let mut c = Collection::new("c", Visibility::Public, "org");
        assert!(c.put_skill("no frontmatter").is_err());
    }

    #[test]
    fn duplicate_collection_ids_are_refused() {
        let mut lib = ContextLibrary::new();
        lib.add_collection(Collection::new("c", Visibility::Public, "org"))
            .unwrap();
        assert!(matches!(
            lib.add_collection(Collection::new("c", Visibility::Public, "org")),
            Err(CollectionError::Duplicate(_))
        ));
    }

    #[test]
    fn skills_visible_to_is_the_slash_namespace() {
        let lib = library();
        let skills = lib.skills_visible_to("bob");
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].1.name, "metric-definitions");
    }
}
