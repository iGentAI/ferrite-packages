//! The typed tool surface and bounded catalog the Google connector
//! publishes for code-mode agents.
//!
//! The `.d.ts` text is injected into `run_code` snippets when the caller's
//! capability manifest grants the `google` tool family; the catalog is the
//! progressive-discovery surface (hard-capped, untrusted data).

use crate::gatekeeper::catalog::{AgentCatalog, CatalogEntry};
use crate::gatekeeper::typed::{ToolSurface, TypedParam};

/// The connector's session API as a typed TypeScript surface.
pub fn google_tool_surface() -> ToolSurface {
    ToolSurface::new("google")
        .expect("static namespace")
        .type_alias("Document", "{ id: string; body: string }")
        .type_alias(
            "FileMeta",
            "{ id: string; name: string; mimeType: string }",
        )
        .type_alias(
            "AppendReceipt",
            "{ actionId: string; revision: number | null; simulated: boolean }",
        )
        .method(
            "readDocument",
            "Read the current body of an introduced Google Doc (observed read; authorized before data returns).",
            vec![TypedParam::required("docId", "string")],
            "Document",
        )
        .expect("static method")
        .method(
            "listFolder",
            "List files in an introduced Drive folder (observed read; every touched file is recorded as a tracked sub-resource).",
            vec![TypedParam::required("folderId", "string")],
            "FileMeta[]",
        )
        .expect("static method")
        .method(
            "appendToDocument",
            "Submit an append action; returns immediately with a SIMULATED receipt. A human approves later (or auto-approval applies if opted in); revert restores the prior revision.",
            vec![
                TypedParam::required("docId", "string"),
                TypedParam::required("text", "string"),
            ],
            "AppendReceipt",
        )
        .expect("static method")
}

/// The bounded discovery catalog for a session's introduced units.
///
/// Vendor data of unbounded size is clipped, never trusted: the catalog is
/// built with `truncating`, so the hard caps hold whatever the input.
pub fn google_catalog(units: &[String]) -> AgentCatalog {
    let mut entries = vec![CatalogEntry {
        id: "google.tools".into(),
        description: "Typed Google session API: readDocument, listFolder (observed reads), appendToDocument (approvable).".into(),
    }];
    entries.extend(units.iter().map(|u| CatalogEntry {
        id: format!("google.resource:{u}"),
        description: format!("Introduced Google resource {u} (reads observed, writes approvable)."),
    }));
    AgentCatalog::truncating(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatekeeper::catalog::CATALOG_MAX_ENTRIES;

    #[test]
    fn dts_renders_the_session_api() {
        let dts = google_tool_surface().to_dts().expect("static surface validates");
        assert!(dts.contains("declare namespace google {"));
        assert!(dts.contains("function readDocument(docId: string): Promise<Document>;"));
        assert!(dts.contains("function listFolder(folderId: string): Promise<FileMeta[]>;"));
        assert!(dts.contains(
            "function appendToDocument(docId: string, text: string): Promise<AppendReceipt>;"
        ));
        assert!(dts.contains("type FileMeta ="));
    }

    #[test]
    fn catalog_is_bounded_whatever_the_unit_count() {
        let units: Vec<String> = (0..100).map(|i| format!("doc-{i}")).collect();
        let c = google_catalog(&units);
        assert_eq!(c.len(), CATALOG_MAX_ENTRIES);
    }

    #[test]
    fn catalog_names_introduced_units() {
        let c = google_catalog(&["doc-alpha".to_string()]);
        assert!(c
            .entries()
            .iter()
            .any(|e| e.id == "google.resource:doc-alpha"));
    }
}
