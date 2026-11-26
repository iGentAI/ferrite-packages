//! Full-text search over the context library.
//!
//! A small deterministic keyword index: documents and skills are tokenized,
//! queries are ANDed token matches ranked by hit count, and results carry
//! enough locator information (`collection`, `kind`, `id`) for a follow-up
//! `read`. The deployed service swaps this for the `ferrite-search` engine;
//! the interface — search/list/read over visible collections only — is the
//! contract this module locks down, in particular that a query NEVER
//! returns content from a collection the account cannot read.

use ferrite_app::serde::{Deserialize, Serialize};

use crate::context_library::collection::ContextLibrary;

/// What a hit points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct SearchHit {
    pub collection: String,
    /// `document` or `skill`.
    pub kind: String,
    /// Document id or skill name.
    pub id: String,
    pub title: String,
    /// Match strength (token hit count).
    pub score: usize,
}

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect()
}

fn score(haystack: &str, query_tokens: &[String]) -> usize {
    let hay = tokens(haystack);
    let mut total = 0usize;
    for q in query_tokens {
        let hits = hay.iter().filter(|t| *t == q).count();
        if hits == 0 {
            return 0; // AND semantics: every query token must appear
        }
        total += hits;
    }
    total
}

/// The search surface over one library.
pub struct SearchIndex<'a> {
    library: &'a ContextLibrary,
}

impl<'a> SearchIndex<'a> {
    pub fn new(library: &'a ContextLibrary) -> Self {
        Self { library }
    }

    /// Search everything `account` can read. Results are ranked by score
    /// then id for determinism.
    pub fn search(&self, account: &str, query: &str) -> Vec<SearchHit> {
        let q = tokens(query);
        if q.is_empty() {
            return Vec::new();
        }
        let mut hits: Vec<SearchHit> = Vec::new();
        for c in self.library.visible_to(account) {
            for d in c.documents() {
                let s = score(&format!("{} {}", d.title, d.body), &q);
                if s > 0 {
                    hits.push(SearchHit {
                        collection: c.id.clone(),
                        kind: "document".into(),
                        id: d.id.clone(),
                        title: d.title.clone(),
                        score: s,
                    });
                }
            }
            for sk in c.skills() {
                let s = score(&format!("{} {} {}", sk.name, sk.description, sk.body), &q);
                if s > 0 {
                    hits.push(SearchHit {
                        collection: c.id.clone(),
                        kind: "skill".into(),
                        id: sk.name.clone(),
                        title: sk.description.clone(),
                        score: s,
                    });
                }
            }
        }
        hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.cmp(&b.id)));
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_library::collection::{Collection, Document, Visibility};

    fn library() -> ContextLibrary {
        let mut lib = ContextLibrary::new();
        let mut public = Collection::new("codex", Visibility::Public, "org");
        public.put_document(Document {
            id: "reviews.md".into(),
            title: "Code review standards".into(),
            body: "Review code with care. Code review is a conversation.".into(),
        });
        public
            .put_skill("---\nname: review-checklist\ndescription: The review checklist skill.\n---\nCheck tests. Check names.")
            .unwrap();
        lib.add_collection(public).unwrap();
        let mut private = Collection::new("alice-notes", Visibility::Private, "alice");
        private.put_document(Document {
            id: "secret.md".into(),
            title: "Secret plan".into(),
            body: "the secret code review plan".into(),
        });
        lib.add_collection(private).unwrap();
        lib
    }

    #[test]
    fn ranks_by_hit_count() {
        let mut lib = library();
        let mut extra = Collection::new("extra", Visibility::Public, "org");
        extra.put_document(Document {
            id: "a-brief.md".into(),
            title: "Brief".into(),
            body: "One code review.".into(),
        });
        lib.add_collection(extra).unwrap();
        let idx = SearchIndex::new(&lib);
        let hits = idx.search("bob", "code review");
        let ranked: Vec<(&str, usize)> = hits.iter().map(|h| (h.id.as_str(), h.score)).collect();
        assert_eq!(ranked, vec![("reviews.md", 6), ("a-brief.md", 2)]);
    }

    #[test]
    fn and_semantics_require_every_token() {
        let lib = library();
        let idx = SearchIndex::new(&lib);
        assert!(idx.search("bob", "review zebra").is_empty());
    }

    #[test]
    fn results_respect_visibility() {
        let lib = library();
        let idx = SearchIndex::new(&lib);
        // bob cannot see alice's private collection even on a match.
        let bob = idx.search("bob", "secret plan");
        assert!(bob.is_empty());
        let alice = idx.search("alice", "secret plan");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].collection, "alice-notes");
    }

    #[test]
    fn skills_are_searchable() {
        let lib = library();
        let idx = SearchIndex::new(&lib);
        let hits = idx.search("bob", "checklist");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "skill");
        assert_eq!(hits[0].id, "review-checklist");
    }

    #[test]
    fn empty_query_returns_nothing() {
        let lib = library();
        let idx = SearchIndex::new(&lib);
        assert!(idx.search("bob", "  ").is_empty());
    }
}
