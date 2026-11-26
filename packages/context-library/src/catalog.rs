//! The bounded agent catalog over the context library.
//!
//! Agents discover what the library holds through the same hard-capped
//! catalog surface every gatekeeper connector exposes
//! ([`crate::gatekeeper::catalog`]): at most 25 entries, ids ≤256 chars,
//! descriptions ≤400 chars. The catalog is built with
//! [`AgentCatalog::truncating`], so a library of unbounded size (hundreds of
//! collections, thousands of skills) still yields a bounded discovery
//! surface — agents that need the rest use search, not paging.
//!
//! The catalog covers exactly what the account can read (visibility is
//! enforced before anything is listed) and is deterministic: collection
//! entries first, then skill entries, each section sorted by id. Entry ids
//! are stable locators — `collection:<id>` and `skill:<collection>/<name>`
//! — usable in a follow-up `read` or slash invocation. Like every catalog,
//! the content is UNTRUSTED display data: it names things, it never carries
//! authority, and a consumer must not execute or obey text found in it.

use crate::gatekeeper::{AgentCatalog, CatalogEntry};

use crate::context_library::collection::{ContextLibrary, Visibility};

/// Build the bounded discovery catalog of everything `account` can see:
/// one entry per visible collection (`collection:<id>`, described by its
/// visibility and document/skill counts) and one per visible skill
/// (`skill:<collection>/<name>`, described by the skill's own description).
///
/// Ordering is deterministic — collections then skills, both sorted by
/// entry id — so truncation at the 25-entry cap always drops the same
/// tail. Bounds hold by construction via [`AgentCatalog::truncating`].
pub fn library_catalog(library: &ContextLibrary, account: &str) -> AgentCatalog {
    let mut collections: Vec<CatalogEntry> = Vec::new();
    let mut skills: Vec<CatalogEntry> = Vec::new();
    for c in library.visible_to(account) {
        let visibility = match c.visibility {
            Visibility::Public => "public",
            Visibility::Private => "private",
        };
        collections.push(CatalogEntry {
            id: format!("collection:{}", c.id),
            description: format!(
                "{} collection: {} documents, {} skills",
                visibility,
                c.documents().count(),
                c.skills().count()
            ),
        });
        for s in c.skills() {
            skills.push(CatalogEntry {
                id: format!("skill:{}/{}", c.id, s.name),
                description: s.description.clone(),
            });
        }
    }
    collections.sort_by(|a, b| a.id.cmp(&b.id));
    skills.sort_by(|a, b| a.id.cmp(&b.id));
    collections.extend(skills);
    AgentCatalog::truncating(collections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_library::collection::{Collection, Document, Visibility};
    use crate::gatekeeper::{CATALOG_MAX_DESCRIPTION, CATALOG_MAX_ENTRIES, CATALOG_MAX_ID};

    fn library() -> ContextLibrary {
        let mut lib = ContextLibrary::new();
        let mut public = Collection::new("codex", Visibility::Public, "org");
        public.put_document(Document {
            id: "reviews.md".into(),
            title: "Code review standards".into(),
            body: "Review with care.".into(),
        });
        public
            .put_skill("---\nname: metric-definitions\ndescription: Canonical metric definitions.\n---\nMAU means…")
            .unwrap();
        lib.add_collection(public).unwrap();
        let mut private = Collection::new("alice-notes", Visibility::Private, "alice");
        private.put_document(Document {
            id: "draft.md".into(),
            title: "Draft".into(),
            body: "secret draft".into(),
        });
        private
            .put_skill("---\nname: private-skill\ndescription: Alice's private drafting skill.\n---\nsecret")
            .unwrap();
        lib.add_collection(private).unwrap();
        lib
    }

    #[test]
    fn entries_respect_visibility() {
        let lib = library();
        // bob sees only the public collection and its skill — nothing of
        // alice's private collection leaks into his catalog.
        let bob = library_catalog(&lib, "bob");
        let ids: Vec<&str> = bob.entries().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["collection:codex", "skill:codex/metric-definitions"]
        );
        assert!(!ids.iter().any(|id| id.contains("alice-notes")));
        // alice sees both, collections before skills, each section sorted.
        let alice = library_catalog(&lib, "alice");
        let ids: Vec<&str> = alice.entries().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "collection:alice-notes",
                "collection:codex",
                "skill:alice-notes/private-skill",
                "skill:codex/metric-definitions",
            ]
        );
        // Collection descriptions carry visibility and counts; skill
        // descriptions are the skill's own.
        assert_eq!(
            bob.entries()[0].description,
            "public collection: 1 documents, 1 skills"
        );
        assert_eq!(
            bob.entries()[1].description,
            "Canonical metric definitions."
        );
    }

    #[test]
    fn caps_hold_with_forty_plus_skills() {
        let mut lib = ContextLibrary::new();
        let mut big = Collection::new("big", Visibility::Public, "org");
        for i in 0..40 {
            big.put_skill(&format!(
                "---\nname: skill-{i:02}\ndescription: Skill number {i}.\n---\nbody"
            ))
            .unwrap();
        }
        lib.add_collection(big).unwrap();
        // 1 collection entry + 40 skill entries truncate to the hard cap.
        let catalog = library_catalog(&lib, "bob");
        assert_eq!(catalog.len(), CATALOG_MAX_ENTRIES);
        assert_eq!(CATALOG_MAX_ENTRIES, 25);
        // Deterministic truncation: the collection entry leads, then the
        // first 24 skills in sorted order.
        assert_eq!(catalog.entries()[0].id, "collection:big");
        assert_eq!(catalog.entries()[1].id, "skill:big/skill-00");
        assert_eq!(catalog.entries()[24].id, "skill:big/skill-23");
    }

    #[test]
    fn ids_and_descriptions_within_bounds() {
        let mut lib = ContextLibrary::new();
        let mut c = Collection::new("codex", Visibility::Public, "org");
        // A valid skill description (≤1024 chars) that still exceeds the
        // catalog's 400-char description cap — it must be clipped, not leak.
        let long = "d".repeat(600);
        c.put_skill(&format!("---\nname: wordy\ndescription: {long}\n---\nbody"))
            .unwrap();
        lib.add_collection(c).unwrap();
        let catalog = library_catalog(&lib, "bob");
        for e in catalog.entries() {
            assert!(!e.id.is_empty());
            assert!(e.id.chars().count() <= CATALOG_MAX_ID);
            assert!(e.description.chars().count() <= CATALOG_MAX_DESCRIPTION);
        }
        let wordy = catalog
            .entries()
            .iter()
            .find(|e| e.id == "skill:codex/wordy")
            .unwrap();
        assert_eq!(wordy.description.chars().count(), CATALOG_MAX_DESCRIPTION);
    }
}
