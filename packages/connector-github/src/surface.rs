//! The typed tool surface and bounded catalog the GitHub connector
//! publishes for code-mode agents.
//!
//! The `.d.ts` text is injected into `run_code` snippets when the caller's
//! capability manifest grants the `github` tool family; the catalog is the
//! progressive-discovery surface (hard-capped, untrusted data).

use crate::gatekeeper::catalog::{AgentCatalog, CatalogEntry};
use crate::gatekeeper::typed::{ToolSurface, TypedParam};

/// The connector's session API as a typed TypeScript surface.
pub fn github_tool_surface() -> ToolSurface {
    ToolSurface::new("github")
        .expect("static namespace")
        .type_alias(
            "Issue",
            "{ number: number; title: string; body: string; state: 'open' | 'closed' }",
        )
        .type_alias(
            "PullRequest",
            "{ number: number; title: string; body: string; head: string; base: string; state: 'open' | 'closed'; simulated: boolean }",
        )
        .type_alias(
            "SubmittedAction",
            "{ actionId: string; simulated: true }",
        )
        .method(
            "listIssues",
            "List issues on an introduced repository (observed read).",
            vec![TypedParam::required("repo", "string")],
            "Issue[]",
        )
        .expect("static method")
        .method(
            "listPullRequests",
            "List pull requests on an introduced repository (observed read).",
            vec![TypedParam::required("repo", "string")],
            "PullRequest[]",
        )
        .expect("static method")
        .method(
            "openPullRequest",
            "Submit a PR-open action; returns immediately with the SIMULATED PR. A human approves later (or auto-approval applies if opted in).",
            vec![
                TypedParam::required("repo", "string"),
                TypedParam::required("title", "string"),
                TypedParam::optional("body", "string"),
                TypedParam::required("head", "string"),
                TypedParam::required("base", "string"),
            ],
            "PullRequest & SubmittedAction",
        )
        .expect("static method")
        .method(
            "addComment",
            "Submit an issue-comment action (simulated until approved).",
            vec![
                TypedParam::required("repo", "string"),
                TypedParam::required("issue", "number"),
                TypedParam::required("body", "string"),
            ],
            "SubmittedAction",
        )
        .expect("static method")
}

/// The bounded discovery catalog for a session's introduced repos.
///
/// Vendor data of unbounded size is clipped, never trusted: the catalog is
/// built with `truncating`, so the hard caps hold whatever the input.
pub fn github_catalog(repos: &[String]) -> AgentCatalog {
    let mut entries = vec![CatalogEntry {
        id: "github.tools".into(),
        description: "Typed GitHub session API: listIssues, listPullRequests, openPullRequest (approvable), addComment (approvable).".into(),
    }];
    entries.extend(repos.iter().map(|r| CatalogEntry {
        id: format!("github.repo:{r}"),
        description: format!("Introduced repository {r} (reads observed, writes approvable)."),
    }));
    AgentCatalog::truncating(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatekeeper::catalog::CATALOG_MAX_ENTRIES;

    #[test]
    fn dts_renders_the_session_api() {
        let dts = github_tool_surface().to_dts().expect("static surface validates");
        assert!(dts.contains("declare namespace github {"));
        assert!(dts.contains("function listIssues(repo: string): Promise<Issue[]>;"));
        assert!(dts.contains("openPullRequest"));
        assert!(dts.contains("type PullRequest ="));
    }

    #[test]
    fn catalog_is_bounded_whatever_the_repo_count() {
        let repos: Vec<String> = (0..100).map(|i| format!("owner/repo-{i}")).collect();
        let c = github_catalog(&repos);
        assert_eq!(c.len(), CATALOG_MAX_ENTRIES);
    }

    #[test]
    fn catalog_names_introduced_repos() {
        let c = github_catalog(&["example-org/example-repo".to_string()]);
        assert!(c
            .entries()
            .iter()
            .any(|e| e.id == "github.repo:example-org/example-repo"));
    }
}
