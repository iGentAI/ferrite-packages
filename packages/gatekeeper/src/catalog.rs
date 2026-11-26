//! Bounded agent catalogs.
//!
//! A connector returns a small, hard-capped discovery surface so agents can
//! find what is reachable without paging full vendor APIs. The caps are
//! adopted verbatim from the Cloudflare OS gatekeeper contract: at most 25
//! entries, ids capped at 256 chars, descriptions at 400. Catalog content is
//! explicitly UNTRUSTED data — it names things, it never carries authority,
//! and a consumer must not execute or obey text found in it.

use ferrite_app::serde::{Deserialize, Serialize};

use crate::gatekeeper::GatekeeperError;

/// Hard cap on catalog entries.
pub const CATALOG_MAX_ENTRIES: usize = 25;
/// Hard cap on an entry id, in chars.
pub const CATALOG_MAX_ID: usize = 256;
/// Hard cap on an entry description, in chars.
pub const CATALOG_MAX_DESCRIPTION: usize = 400;

/// One discoverable entry: a resource, tool, or collection the caller can
/// reach through this connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct CatalogEntry {
    /// Stable id, e.g. `github.repo:example-org/example-repo`.
    pub id: String,
    /// Human description. Untrusted display text.
    pub description: String,
}

/// A bounded catalog. Construction enforces every cap, so a value of this
/// type is proof the bounds hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AgentCatalog {
    entries: Vec<CatalogEntry>,
}

impl<'de> Deserialize<'de> for AgentCatalog {
    fn deserialize<D: ferrite_app::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(crate = "ferrite_app::serde")]
        struct Wire {
            entries: Vec<CatalogEntry>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.entries).map_err(ferrite_app::serde::de::Error::custom)
    }
}

impl AgentCatalog {
    pub fn new(entries: Vec<CatalogEntry>) -> Result<Self, GatekeeperError> {
        if entries.len() > CATALOG_MAX_ENTRIES {
            return Err(GatekeeperError::CatalogBound(format!(
                "{} entries exceeds the {CATALOG_MAX_ENTRIES}-entry cap",
                entries.len()
            )));
        }
        for e in &entries {
            if e.id.is_empty() || e.id.chars().count() > CATALOG_MAX_ID {
                return Err(GatekeeperError::CatalogBound(format!(
                    "entry id must be 1..={CATALOG_MAX_ID} chars: {:?}",
                    e.id.chars().take(40).collect::<String>()
                )));
            }
            if e.description.chars().count() > CATALOG_MAX_DESCRIPTION {
                return Err(GatekeeperError::CatalogBound(format!(
                    "description for {} exceeds {CATALOG_MAX_DESCRIPTION} chars",
                    e.id
                )));
            }
        }
        Ok(Self { entries })
    }

    /// Build a catalog by truncating instead of refusing: entries beyond the
    /// cap are dropped, over-long fields are clipped at a char boundary.
    /// Use when the source list is vendor data of unbounded size.
    pub fn truncating(entries: Vec<CatalogEntry>) -> Self {
        let entries = entries
            .into_iter()
            .filter(|e| !e.id.is_empty())
            .take(CATALOG_MAX_ENTRIES)
            .map(|mut e| {
                e.id = clip_chars(&e.id, CATALOG_MAX_ID);
                e.description = clip_chars(&e.description, CATALOG_MAX_DESCRIPTION);
                e
            })
            .collect();
        Self { entries }
    }

    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn clip_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, desc: &str) -> CatalogEntry {
        CatalogEntry {
            id: id.into(),
            description: desc.into(),
        }
    }

    #[test]
    fn accepts_bounded_catalog() {
        let c = AgentCatalog::new(vec![entry("a", "first"), entry("b", "second")]).unwrap();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn deserialization_cannot_bypass_entry_and_field_bounds() {
        let entries:Vec<_>=(0..26).map(|i|entry(&format!("a{i}"),"valid")).collect();
        let raw=ferrite_app::serde_json::json!({"entries":entries});
        assert!(ferrite_app::serde_json::from_value::<AgentCatalog>(raw).is_err());
        let raw=ferrite_app::serde_json::json!({"entries":[entry("good",&"x".repeat(401))]});
        assert!(ferrite_app::serde_json::from_value::<AgentCatalog>(raw).is_err());
        let valid=AgentCatalog::new(vec![entry("good","valid")]).unwrap();
        assert!(ferrite_app::serde_json::from_value::<AgentCatalog>(ferrite_app::serde_json::to_value(valid).unwrap()).is_ok());
    }

    #[test]
    fn refuses_too_many_entries() {
        let entries = (0..26).map(|i| entry(&format!("e{i}"), "")).collect();
        assert!(matches!(
            AgentCatalog::new(entries),
            Err(GatekeeperError::CatalogBound(_))
        ));
    }

    #[test]
    fn refuses_oversize_fields() {
        let long_id = "x".repeat(257);
        assert!(AgentCatalog::new(vec![entry(&long_id, "")]).is_err());
        let long_desc = "d".repeat(401);
        assert!(AgentCatalog::new(vec![entry("ok", &long_desc)]).is_err());
        assert!(AgentCatalog::new(vec![entry("", "empty id")]).is_err());
    }

    #[test]
    fn truncating_clips_instead_of_refusing() {
        let entries: Vec<_> = (0..40)
            .map(|i| entry(&format!("e{i}"), &"d".repeat(500)))
            .collect();
        let c = AgentCatalog::truncating(entries);
        assert_eq!(c.len(), CATALOG_MAX_ENTRIES);
        assert!(c.entries()[0].description.chars().count() == CATALOG_MAX_DESCRIPTION);
    }
}
