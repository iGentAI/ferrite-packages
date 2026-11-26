//! The shared context/skills library (after Cloudflare OS `gatekeeper-context`).
//!
//! Organizational knowledge — metric definitions, review practices, "what
//! good looks like" Codex documents — changes faster than agent deployments.
//! This package makes that knowledge a runtime service instead of a
//! compile-time asset: collections of documents and skills, `public`
//! (tenant-wide) or `private` (per account), delivered to agents through
//! search/list/read, a bounded catalog, and slash-command expansion.
//!
//! A *skill* is any `SKILL.md` with validated YAML frontmatter:
//! `name` (kebab-case, ≤64 chars) and `description` (≤1024 chars). The
//! format is adopted outright — it is compatible with the per-agent
//! `skills/*.md` ferrite already compiles into bundles.
//!
//! The library is strictly READ-ONLY for agents; writes are a human/publish
//! path. Collection access is observer-verified when a shared surface
//! consumes private content (the strategy is the gatekeeper's — this package
//! depends on the `gatekeeper` package for the catalog bounds, the
//! observation authorizer, and the observer registry/verifier types, mounted
//! at `crate::gatekeeper`).
//!
//! This is a **source package**, composed into a consuming app's `src/` tree
//! by `tools/ferrite-pkg`, running under that app's injected authority alone.
//! It is not a crate and not a service.
//!
//! Module map:
//!
//! | Module | Owns |
//! |---|---|
//! | [`collection`] | collections, documents, visibility, the read ACL |
//! | [`skill`] | `SKILL.md` parsing with validated frontmatter |
//! | [`search`] | deterministic AND-keyword search over visible collections |
//! | [`catalog`] | the bounded discovery catalog (gatekeeper caps) |
//! | [`slash`] | `/name args…` expansion with `$ARGUMENT` substitution |
//! | [`observer_access`] | observation records + share-time observer verification |

pub mod catalog;
pub mod collection;
pub mod observer_access;
pub mod search;
pub mod skill;
pub mod slash;

pub use catalog::library_catalog;
pub use collection::{Collection, CollectionError, ContextLibrary, Document, Visibility};
pub use observer_access::{
    library_observer_registry, record_collection_read, LibraryAccessVerifier,
    CONTEXT_COLLECTION_KIND,
};
pub use search::{SearchHit, SearchIndex};
pub use skill::{parse_skill, Skill, SkillError, MAX_DESCRIPTION_LEN, MAX_NAME_LEN};
pub use slash::{expand_slash_command, SlashError};
