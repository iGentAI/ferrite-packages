//! The vendor boundary: everything that actually touches GitHub.
//!
//! The connector core never sees a credential or a socket — it calls a
//! [`GithubBackend`]. The offline gates use [`FixtureBackend`], an in-memory
//! GitHub good enough to prove the governance semantics; a deployed
//! connector app supplies a live backend over its declared egress, holding
//! its token the way the AI gateway holds provider keys.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// An issue as the connector reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Issue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: String, // "open" | "closed"
}

/// A pull request as the connector reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub head: String,
    pub base: String,
    pub state: String, // "open" | "closed"
    /// True when this PR only exists as a simulated (not yet approved) action.
    pub simulated: bool,
}

/// One repository's fixture state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct RepoState {
    pub issues: Vec<Issue>,
    pub pulls: Vec<PullRequest>,
    pub comments: Vec<(u64, String)>, // (issue number, body)
    /// Users with direct read access — the ACL observer verification consults.
    pub readers: Vec<String>,
}

/// The vendor operations the connector needs. Implementations decide how
/// they reach GitHub (fixtures in tests, declared egress in deployment).
pub trait GithubBackend: Send {
    fn list_issues(&self, repo: &str) -> Result<Vec<Issue>, String>;
    fn list_pulls(&self, repo: &str) -> Result<Vec<PullRequest>, String>;
    fn open_pull_request(
        &self,
        repo: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
    ) -> Result<PullRequest, String>;
    fn close_pull_request(&self, repo: &str, number: u64) -> Result<(), String>;
    fn add_comment(&self, repo: &str, issue: u64, body: &str) -> Result<u64, String>;
    fn delete_comment(&self, repo: &str, comment_id: u64) -> Result<(), String>;
    /// Can `user` directly read `repo` with their OWN credentials?
    fn user_can_read(&self, user: &str, repo: &str) -> bool;
}

/// The in-memory backend the offline gates run against.
#[derive(Debug, Default)]
pub struct FixtureBackend {
    repos: Mutex<BTreeMap<String, RepoState>>,
    next_pr: Mutex<u64>,
    next_comment: Mutex<u64>,
}

fn repo_mut<'a>(
    repos: &'a mut BTreeMap<String, RepoState>,
    repo: &str,
) -> Result<&'a mut RepoState, String> {
    repos
        .get_mut(repo)
        .ok_or_else(|| format!("unknown repo {repo}"))
}

impl FixtureBackend {
    pub fn new() -> Self {
        Self {
            repos: Mutex::new(BTreeMap::new()),
            next_pr: Mutex::new(100),
            next_comment: Mutex::new(1000),
        }
    }

    pub fn seed_repo(&self, repo: &str, state: RepoState) {
        self.repos.lock().unwrap().insert(repo.to_string(), state);
    }

    pub fn repo(&self, repo: &str) -> Option<RepoState> {
        self.repos.lock().unwrap().get(repo).cloned()
    }
}

impl GithubBackend for FixtureBackend {
    fn list_issues(&self, repo: &str) -> Result<Vec<Issue>, String> {
        self.repos
            .lock()
            .unwrap()
            .get(repo)
            .map(|r| r.issues.clone())
            .ok_or_else(|| format!("unknown repo {repo}"))
    }

    fn list_pulls(&self, repo: &str) -> Result<Vec<PullRequest>, String> {
        self.repos
            .lock()
            .unwrap()
            .get(repo)
            .map(|r| r.pulls.clone())
            .ok_or_else(|| format!("unknown repo {repo}"))
    }

    fn open_pull_request(
        &self,
        repo: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
    ) -> Result<PullRequest, String> {
        let mut repos = self.repos.lock().unwrap();
        let r = repo_mut(&mut repos, repo)?;
        let mut n = self.next_pr.lock().unwrap();
        *n += 1;
        let pr = PullRequest {
            number: *n,
            title: title.to_string(),
            body: body.to_string(),
            head: head.to_string(),
            base: base.to_string(),
            state: "open".into(),
            simulated: false,
        };
        r.pulls.push(pr.clone());
        Ok(pr)
    }

    fn close_pull_request(&self, repo: &str, number: u64) -> Result<(), String> {
        let mut repos = self.repos.lock().unwrap();
        let pr = repo_mut(&mut repos, repo)?
            .pulls
            .iter_mut()
            .find(|p| p.number == number)
            .ok_or_else(|| format!("unknown PR #{number}"))?;
        pr.state = "closed".into();
        Ok(())
    }

    fn add_comment(&self, repo: &str, issue: u64, body: &str) -> Result<u64, String> {
        let mut repos = self.repos.lock().unwrap();
        let r = repo_mut(&mut repos, repo)?;
        let mut id = self.next_comment.lock().unwrap();
        *id += 1;
        r.comments.push((issue, body.to_string()));
        Ok(*id)
    }

    fn delete_comment(&self, repo: &str, _comment_id: u64) -> Result<(), String> {
        // Fixture keeps comments keyed by issue number; a real backend keys by id.
        repo_mut(&mut self.repos.lock().unwrap(), repo)?;
        Ok(())
    }

    fn user_can_read(&self, user: &str, repo: &str) -> bool {
        self.repos
            .lock()
            .unwrap()
            .get(repo)
            .is_some_and(|r| r.readers.iter().any(|u| u == user))
    }
}
