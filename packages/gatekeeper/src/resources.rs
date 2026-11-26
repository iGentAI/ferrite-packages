//! `SupportedResource` URL-pattern scoping and incremental resource grants.
//!
//! A connector declares the *kinds* of resource it can be scoped to as
//! [`SupportedResource`] entries: a kind id, a human label, and one or more
//! URL patterns that recognise a pasted resource URL (`introduction by URL`).
//! A connection then holds [`ResourceGrant`]s naming specific units — a single
//! repo, a single document — and `ensure_resources` expands a connection's
//! grants incrementally, requesting only what the new resources need.
//!
//! A grant is only as good as the consent behind it. `ensure_resources`
//! records an expansion that needs vendor scopes the connection does not yet
//! hold as *pending*; it becomes a live grant only when the host reports,
//! through [`ResourceGrantSet::grant_consent`], that the human consented to
//! those scopes. A declined or abandoned consent leaves the expansion pending
//! (and the next `ensure_resources` for it asks again), and `is_granted`
//! checks that the scopes a unit needs are actually held.
//!
//! URLs are canonicalised before they are matched (scheme and host folded to
//! lower case, query and fragment dropped, each path segment percent-decoded
//! once) and anything ambiguous — dot segments, encoded slashes, userinfo,
//! an explicit port, backslashes, whitespace — is refused, so the unit a URL
//! is recognised as is the unit it resolves to.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::gatekeeper::oauth::NONCE_TTL_MS;
use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Most grants (live plus pending) one connection may hold.
pub const MAX_RESOURCE_GRANTS: usize = 256;
/// Longest URL [`ResourcePattern::match_url`] considers.
pub const MAX_RESOURCE_URL_LEN: usize = 2_048;
/// Longest unit string a grant may name.
pub const MAX_RESOURCE_UNIT_LEN: usize = 512;
/// How long a pending expansion waits for its consent. A consent that
/// completes later than this (the OAuth nonce lifetime) does not activate it;
/// the resource must be introduced again.
pub const PENDING_GRANT_TTL_MS: u64 = NONCE_TTL_MS;

/// Decode `%XX` escapes once. `None` for a malformed escape or non-UTF-8.
fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = segment.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The canonical form of a pasted resource URL, or `None` when the URL is
/// ambiguous. Scheme and host are lower-cased; the query and fragment are
/// dropped (they never name a unit); each path segment is percent-decoded
/// exactly once. Refused outright: userinfo, an explicit port, a trailing-dot
/// host, backslashes, whitespace or control characters, empty segments,
/// `.`/`..` segments, and segments that decode to a slash or another `%`.
fn canonical_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() || url.len() > MAX_RESOURCE_URL_LEN {
        return None;
    }
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return None;
    }
    let end = url.find(['?', '#']).unwrap_or(url.len());
    let (scheme, rest) = url[..end].split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty()
        || authority.ends_with('.')
        || authority.contains(['@', ':', '%'])
    {
        return None;
    }
    let mut out = format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    );
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Some(out);
    }
    for raw in path[1..].split('/') {
        let seg = percent_decode(raw)?;
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        if seg
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '%') || c.is_control() || c.is_whitespace())
        {
            return None;
        }
        out.push('/');
        out.push_str(&seg);
    }
    Some(out)
}

/// A captured placeholder value must look like an identifier segment: the
/// charset vendor unit ids (repo owners and names, document ids) use.
fn valid_capture(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// A unit named in `ensure_resources` must be printable, bounded text.
fn valid_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAX_RESOURCE_UNIT_LEN
        && !unit.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A URL pattern that recognises one resource unit.
///
/// Patterns are literal segments with `{name}` placeholders capturing one
/// path segment, e.g. `https://github.com/{owner}/{repo}`. A trailing `/*`
/// matches any suffix (used for kinds whose unit is a subtree).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ResourcePattern {
    pub pattern: String,
}

impl ResourcePattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// Match `url` against the pattern; on success return the captured
    /// placeholder values in declaration order. The URL is canonicalised
    /// first (see the module doc); an ambiguous URL matches nothing.
    pub fn match_url(&self, url: &str) -> Option<Vec<(String, String)>> {
        let (pat_no_star, allow_suffix) = match self.pattern.strip_suffix("/*") {
            Some(p) => (p, true),
            None => (self.pattern.as_str(), false),
        };
        let canonical = canonical_url(url)?;
        let url = canonical.as_str();
        let pat_parts: Vec<&str> = pat_no_star.split('/').collect();
        let url_parts: Vec<&str> = url.split('/').collect();
        if allow_suffix {
            // `/*` demands a suffix: at least one segment beyond the pattern.
            if url_parts.len() <= pat_parts.len() {
                return None;
            }
        } else if url_parts.len() != pat_parts.len() {
            return None;
        }
        let mut caps = Vec::new();
        for (p, u) in pat_parts.iter().zip(url_parts.iter()) {
            if let Some(name) = p.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                if !valid_capture(u) {
                    return None;
                }
                caps.push((name.to_string(), (*u).to_string()));
            } else if p != u {
                return None;
            }
        }
        Some(caps)
    }
}

/// A resource kind a connector supports scoping to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct SupportedResource {
    /// Stable kind id, e.g. `github.repo`.
    pub kind: String,
    /// Human label for introduction UI, e.g. `GitHub repository`.
    pub label: String,
    /// URL patterns that recognise a unit of this kind.
    pub patterns: Vec<ResourcePattern>,
    /// Vendor OAuth scopes this kind requires when granted read-only.
    pub read_scopes: Vec<String>,
    /// Additional vendor OAuth scopes required for write.
    pub write_scopes: Vec<String>,
}

impl SupportedResource {
    /// Try to recognise `url` as a unit of this kind. Returns the canonical
    /// unit string (captures joined with `/`).
    pub fn recognise(&self, url: &str) -> Option<String> {
        let caps = self.patterns.iter().find_map(|p| p.match_url(url))?;
        if caps.is_empty() {
            return canonical_url(url);
        }
        Some(
            caps.into_iter()
                .map(|(_, v)| v)
                .collect::<Vec<_>>()
                .join("/"),
        )
    }
}

/// A granted resource unit on a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ResourceGrant {
    pub kind: String,
    pub unit: String,
    pub write: bool,
    pub granted_at: TimestampMs,
    /// Vendor scopes a read of this unit needs (from its kind).
    #[serde(default)]
    pub read_scopes: Vec<String>,
    /// Additional vendor scopes a write needs (from its kind).
    #[serde(default)]
    pub write_scopes: Vec<String>,
}

impl ResourceGrant {
    /// Every scope this grant needs at its current access level.
    fn required_scopes(&self) -> impl Iterator<Item = &String> {
        let write: &[String] = if self.write { &self.write_scopes } else { &[] };
        self.read_scopes.iter().chain(write.iter())
    }

    /// Widen to `newer`'s access level and adopt its scope requirements. Write
    /// access never narrows, and `granted_at` stays the caller's to decide.
    fn absorb(&mut self, newer: ResourceGrant) {
        self.write |= newer.write;
        self.read_scopes = newer.read_scopes;
        self.write_scopes = newer.write_scopes;
    }
}

fn find_grant<'a>(
    grants: &'a mut [ResourceGrant],
    kind: &str,
    unit: &str,
) -> Option<&'a mut ResourceGrant> {
    grants.iter_mut().find(|g| g.kind == kind && g.unit == unit)
}

fn absorb_or_push(grants: &mut Vec<ResourceGrant>, grant: ResourceGrant) {
    match find_grant(grants, &grant.kind, &grant.unit) {
        Some(existing) => existing.absorb(grant),
        None => grants.push(grant),
    }
}

/// A connection's resource grant set, expanded incrementally and only as far
/// as the human has consented.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ResourceGrantSet {
    /// Live grants.
    grants: Vec<ResourceGrant>,
    /// Expansions awaiting consent (new units, or read→write upgrades of a
    /// live grant), stamped with when they were requested.
    #[serde(default)]
    pending: Vec<ResourceGrant>,
    /// The vendor scopes the connection's credential is known to carry,
    /// as reported through [`Self::grant_consent`].
    #[serde(default)]
    consented_scopes: BTreeSet<String>,
    /// The consent flow each pending expansion was shown in, keyed by
    /// `kind\x1funit` ([`Self::begin_consent`]). A consent completes only the
    /// expansions of its own flow: one abandoned earlier stays bound to the
    /// flow that was abandoned and lapses with it, so consenting to a later
    /// introduction never activates it.
    #[serde(default)]
    pending_flows: BTreeMap<String, u64>,
    #[serde(default)]
    next_flow: u64,
}

/// One consent flow begun by [`ResourceGrantSet::begin_consent`]: its id, and
/// the pending expansions it is for, which the consent screen must name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentFlow {
    pub id: u64,
    pub units: Vec<(String, String, bool)>,
}

fn flow_key(kind: &str, unit: &str) -> String {
    format!("{kind}\u{1f}{unit}")
}

impl ResourceGrantSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The live grants.
    pub fn grants(&self) -> &[ResourceGrant] {
        &self.grants
    }

    /// Expansions still waiting for consent.
    pub fn pending(&self) -> &[ResourceGrant] {
        &self.pending
    }

    /// The vendor scopes consented so far.
    pub fn consented_scopes(&self) -> impl Iterator<Item = &String> {
        self.consented_scopes.iter()
    }

    fn covered<'a>(&self, mut scopes: impl Iterator<Item = &'a String>) -> bool {
        scopes.all(|s| self.consented_scopes.contains(s))
    }

    /// True only for a live grant at the asked level whose vendor scopes the
    /// connection actually holds.
    pub fn is_granted(&self, kind: &str, unit: &str, write: bool) -> bool {
        self.grants.iter().any(|g| {
            g.kind == kind
                && g.unit == unit
                && (!write || g.write)
                && self.covered(
                    g.read_scopes
                        .iter()
                        .chain(g.write_scopes.iter().filter(|_| write)),
                )
        })
    }

    fn prune_pending(&mut self, now: TimestampMs) {
        self.pending
            .retain(|p| now.saturating_sub(p.granted_at) <= PENDING_GRANT_TTL_MS);
        let live: BTreeSet<String> =
            self.pending.iter().map(|p| flow_key(&p.kind, &p.unit)).collect();
        self.pending_flows.retain(|key, _| live.contains(key));
    }

    /// Begin a consent flow: every pending expansion not already shown in an
    /// earlier flow is bound to this one and listed, for the consent screen
    /// to name. Only [`Self::grant_consent_for`] with this id activates them.
    pub fn begin_consent(&mut self, now: TimestampMs) -> ConsentFlow {
        self.prune_pending(now);
        self.next_flow = self.next_flow.saturating_add(1);
        let id = self.next_flow;
        let mut units = Vec::new();
        for p in &self.pending {
            let key = flow_key(&p.kind, &p.unit);
            if self.pending_flows.contains_key(&key) {
                continue;
            }
            self.pending_flows.insert(key, id);
            units.push((p.kind.clone(), p.unit.clone(), p.write));
        }
        ConsentFlow { id, units }
    }

    /// The human consented to `scopes` in flow `flow`: the scopes join the
    /// consented set, and the pending expansions bound to that flow whose
    /// scopes are now all held become live grants. Returns how many did.
    pub fn grant_consent_for(&mut self, flow: u64, scopes: &[String], now: TimestampMs) -> usize {
        self.activate(Some(flow), scopes, now)
    }

    fn activate(&mut self, flow: Option<u64>, scopes: &[String], now: TimestampMs) -> usize {
        self.prune_pending(now);
        self.consented_scopes.extend(scopes.iter().cloned());
        let pending = std::mem::take(&mut self.pending);
        let mut activated = 0;
        for p in pending {
            let key = flow_key(&p.kind, &p.unit);
            let bound = self.pending_flows.get(&key).copied();
            if bound != flow || !self.covered(p.required_scopes()) {
                self.pending.push(p);
                continue;
            }
            self.pending_flows.remove(&key);
            activated += 1;
            absorb_or_push(&mut self.grants, p);
        }
        activated
    }

    /// Incremental expansion. Returns the vendor OAuth scopes the requested
    /// resources need that the connection does not yet hold (deduplicated) —
    /// the scopes the consent flow must request.
    ///
    /// An expansion whose scopes are already held takes effect at once. One
    /// that needs new scopes is recorded as *pending* and becomes a grant
    /// only when [`Self::grant_consent`] reports those scopes consented; until
    /// then `is_granted` refuses it and asking again reports the same scopes.
    ///
    /// The whole batch is validated (kind supported, unit well formed, the
    /// [`MAX_RESOURCE_GRANTS`] cap) before anything changes, so a refused
    /// batch leaves the set untouched.
    pub fn ensure_resources(
        &mut self,
        supported: &[SupportedResource],
        wanted: &[(String, String, bool)], // (kind, unit, write)
        now: TimestampMs,
    ) -> Result<Vec<String>, GatekeeperError> {
        self.prune_pending(now);
        // Pass 1: validate everything, and count the units that would be new.
        let mut specs = Vec::with_capacity(wanted.len());
        let mut new_units: BTreeSet<(&str, &str)> = BTreeSet::new();
        for (kind, unit, _) in wanted {
            let spec = supported.iter().find(|s| &s.kind == kind).ok_or_else(|| {
                GatekeeperError::Invalid(format!("unsupported resource kind {kind}"))
            })?;
            if !valid_unit(unit) {
                return Err(GatekeeperError::Invalid(format!(
                    "resource unit {unit:?} is empty, too long, or contains whitespace"
                )));
            }
            let known = self
                .grants
                .iter()
                .chain(self.pending.iter())
                .any(|g| &g.kind == kind && &g.unit == unit);
            if !known {
                new_units.insert((kind.as_str(), unit.as_str()));
            }
            specs.push(spec);
        }
        let held = self.grants.len()
            + self
                .pending
                .iter()
                .filter(|p| !self.grants.iter().any(|g| g.kind == p.kind && g.unit == p.unit))
                .count();
        if held + new_units.len() > MAX_RESOURCE_GRANTS {
            return Err(GatekeeperError::Invalid(format!(
                "a connection holds at most {MAX_RESOURCE_GRANTS} resource grants"
            )));
        }
        // Pass 2: apply. Nothing below can fail.
        let mut needed: BTreeSet<String> = BTreeSet::new();
        for ((kind, unit, write), spec) in wanted.iter().zip(specs) {
            let proposal = ResourceGrant {
                kind: kind.clone(),
                unit: unit.clone(),
                write: *write,
                granted_at: now,
                read_scopes: spec.read_scopes.clone(),
                write_scopes: spec.write_scopes.clone(),
            };
            let missing: Vec<String> = proposal
                .required_scopes()
                .filter(|s| !self.consented_scopes.contains(*s))
                .cloned()
                .collect();
            if missing.is_empty() {
                // Every scope is held: the expansion takes effect now.
                absorb_or_push(&mut self.grants, proposal);
                self.pending.retain(|p| {
                    !(&p.kind == kind && &p.unit == unit && (!p.write || *write))
                });
                if !self.pending.iter().any(|p| &p.kind == kind && &p.unit == unit) {
                    self.pending_flows.remove(&flow_key(kind, unit));
                }
                continue;
            }
            needed.extend(missing);
            let live = self.grants.iter().find(|g| &g.kind == kind && &g.unit == unit);
            if live.is_some_and(|g| g.write || !*write) {
                // Already live at this level; only the consent lapsed. The
                // missing scopes are reported again, nothing is recorded.
                continue;
            }
            match find_grant(&mut self.pending, kind, unit) {
                Some(p) => {
                    p.absorb(proposal);
                    p.granted_at = now;
                }
                None => self.pending.push(proposal),
            }
            // Asked for again: the next consent flow shows it again, and a
            // flow begun before this request no longer completes it.
            self.pending_flows.remove(&flow_key(kind, unit));
        }
        Ok(needed.into_iter().collect())
    }

    /// Record that the human consented to `scopes` outside any begun flow
    /// (the host calls this when the vendor authorization for them
    /// completes). The scopes join the consented set, and the pending
    /// expansions requested within [`PENDING_GRANT_TTL_MS`] that were never
    /// shown in a consent flow, and whose scopes are now all held, become
    /// live grants. An expansion bound to a flow by [`Self::begin_consent`]
    /// is completed only by [`Self::grant_consent_for`] with that flow.
    /// Returns how many expansions took effect.
    pub fn grant_consent(&mut self, scopes: &[String], now: TimestampMs) -> usize {
        self.activate(None, scopes, now)
    }

    /// The credential is gone (disconnect): no scope is held any more, so no
    /// grant admits until consent is recorded again.
    pub fn revoke_consent(&mut self) {
        self.consented_scopes.clear();
        self.pending.clear();
        self.pending_flows.clear();
    }

    /// The human declined the consent: drop every pending expansion.
    /// Returns how many were dropped.
    pub fn abort_pending(&mut self) -> usize {
        let n = self.pending.len();
        self.pending.clear();
        self.pending_flows.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_kind() -> SupportedResource {
        SupportedResource {
            kind: "github.repo".into(),
            label: "GitHub repository".into(),
            patterns: vec![ResourcePattern::new("https://github.com/{owner}/{repo}")],
            read_scopes: vec!["repo:read".into()],
            write_scopes: vec!["repo:write".into()],
        }
    }

    #[test]
    fn recognises_repo_url() {
        assert_eq!(
            repo_kind().recognise("https://github.com/example-org/example-repo"),
            Some("example-org/example-repo".into())
        );
        assert_eq!(repo_kind().recognise("https://github.com/example-org"), None);
        assert_eq!(repo_kind().recognise("https://gitlab.com/a/b"), None);
    }

    #[test]
    fn trailing_star_matches_subtree() {
        let p = ResourcePattern::new("https://docs.google.com/document/d/{id}/*");
        assert!(p
            .match_url("https://docs.google.com/document/d/abc123/edit")
            .is_some());
        assert!(p
            .match_url("https://docs.google.com/document/d/abc123")
            .is_none());
    }

    #[test]
    fn ensure_resources_requests_only_the_delta() {
        let sup = vec![repo_kind()];
        let mut set = ResourceGrantSet::new();
        let scopes = set
            .ensure_resources(&sup, &[("github.repo".into(), "a/b".into(), false)], 1)
            .unwrap();
        assert_eq!(scopes, vec!["repo:read".to_string()]);
        set.grant_consent(&scopes, 2);
        // Same ask again: nothing new.
        let scopes = set
            .ensure_resources(&sup, &[("github.repo".into(), "a/b".into(), false)], 3)
            .unwrap();
        assert!(scopes.is_empty());
        // Write upgrade on the existing unit requests only the write scope.
        let scopes = set
            .ensure_resources(&sup, &[("github.repo".into(), "a/b".into(), true)], 4)
            .unwrap();
        assert_eq!(scopes, vec!["repo:write".to_string()]);
        set.grant_consent(&scopes, 5);
        assert!(set.is_granted("github.repo", "a/b", true));
    }

    #[test]
    fn unsupported_kind_is_refused() {
        let mut set = ResourceGrantSet::new();
        let err = set
            .ensure_resources(&[], &[("nope".into(), "x".into(), false)], 1)
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::Invalid(_)));
    }

    fn doc_kinds() -> Vec<SupportedResource> {
        vec![
            SupportedResource {
                kind: "google.doc".into(),
                label: "Google Doc".into(),
                patterns: vec![
                    ResourcePattern::new("https://docs.google.com/document/d/{id}/*"),
                    ResourcePattern::new("https://docs.google.com/document/d/{id}"),
                ],
                read_scopes: vec!["drive.file:read".into()],
                write_scopes: vec!["drive.file:write".into()],
            },
            SupportedResource {
                kind: "google.drive.folder".into(),
                label: "Google Drive folder".into(),
                patterns: vec![ResourcePattern::new(
                    "https://drive.google.com/drive/folders/{id}",
                )],
                read_scopes: vec!["drive.file:read".into()],
                write_scopes: vec!["drive.file:write".into()],
            },
        ]
    }

    fn recognise(url: &str) -> Option<String> {
        doc_kinds().iter().find_map(|k| k.recognise(url))
    }

    /// F185: a URL is recognised as the unit it resolves to, or not at all.
    #[test]
    fn ambiguous_urls_are_refused_not_misread() {
        // Dot segments would resolve somewhere else in a browser.
        assert_eq!(
            recognise("https://docs.google.com/document/d/SENSITIVE/../DECOY/edit"),
            None
        );
        assert_eq!(
            recognise("https://docs.google.com/document/d/DECOY/../../SENSITIVE/edit"),
            None
        );
        assert_eq!(
            recognise("https://docs.google.com/document/d/abc/%2E%2E/def/edit"),
            None
        );
        // Encoded slashes, userinfo, ports, backslashes and empty segments.
        assert_eq!(
            recognise("https://docs.google.com/document/d/a%2Fb/edit"),
            None
        );
        assert_eq!(
            recognise("https://evil.example@docs.google.com/document/d/abc"),
            None
        );
        assert_eq!(recognise("https://docs.google.com:8443/document/d/abc"), None);
        assert_eq!(recognise("https://docs.google.com/document/d/abc\\x"), None);
        assert_eq!(recognise("https://docs.google.com/document//d/abc"), None);
        assert_eq!(recognise("https://docs.google.com./document/d/abc"), None);
        // Case-folded host and a percent-encoded id resolve to the canonical unit.
        assert_eq!(
            recognise("HTTPS://Docs.Google.COM/document/d/abc%2D1/edit"),
            Some("abc-1".into())
        );
    }

    /// F482: a share link's query or fragment is not part of the unit.
    #[test]
    fn query_and_fragment_do_not_become_the_unit() {
        assert_eq!(
            recognise("https://drive.google.com/drive/folders/FOLDER1?usp=sharing"),
            Some("FOLDER1".into())
        );
        assert_eq!(
            recognise("https://drive.google.com/drive/folders/FOLDER1#top"),
            Some("FOLDER1".into())
        );
        assert_eq!(
            repo_kind().recognise("https://github.com/org/repo?tab=readme"),
            Some("org/repo".into())
        );
    }

    /// F482: the grant set is bounded; the refused batch changes nothing.
    #[test]
    fn grant_set_is_capped() {
        let sup = vec![repo_kind()];
        let mut set = ResourceGrantSet::new();
        set.grant_consent(&["repo:read".into()], 0);
        for i in 0..MAX_RESOURCE_GRANTS {
            set.ensure_resources(&sup, &[("github.repo".into(), format!("o/r{i}"), false)], 1)
                .unwrap();
        }
        assert_eq!(set.grants().len(), MAX_RESOURCE_GRANTS);
        let err = set
            .ensure_resources(&sup, &[("github.repo".into(), "o/one-more".into(), false)], 2)
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::Invalid(_)));
        assert_eq!(set.grants().len(), MAX_RESOURCE_GRANTS);
        // Re-asking for a unit already held is not a new grant.
        assert!(set
            .ensure_resources(&sup, &[("github.repo".into(), "o/r0".into(), false)], 3)
            .is_ok());
    }

    /// F481: a batch with a bad entry applies nothing, not a prefix.
    #[test]
    fn a_refused_batch_leaves_the_set_untouched() {
        let sup = vec![repo_kind()];
        let mut set = ResourceGrantSet::new();
        set.grant_consent(&["repo:read".into()], 0);
        set.ensure_resources(&sup, &[("github.repo".into(), "a/b".into(), false)], 1)
            .unwrap();
        let err = set
            .ensure_resources(
                &sup,
                &[
                    ("github.repo".into(), "c/d".into(), false),
                    ("github.repo".into(), "a/b".into(), true),
                    ("gitlab.repo".into(), "e/f".into(), false),
                ],
                2,
            )
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::Invalid(_)));
        assert_eq!(set.grants().len(), 1);
        assert!(set.pending().is_empty());
        assert!(!set.is_granted("github.repo", "c/d", false));
        assert!(!set.grants()[0].write);
    }

    /// F186: an expansion takes effect only once its scopes are consented; an
    /// abandoned consent is asked for again, and a read-only credential never
    /// admits a write.
    #[test]
    fn grants_wait_for_consent_and_check_the_held_scopes() {
        let sup = doc_kinds();
        let mut set = ResourceGrantSet::new();
        // DocA read: consented.
        let scopes = set
            .ensure_resources(&sup, &[("google.doc".into(), "docA".into(), false)], 1)
            .unwrap();
        assert_eq!(scopes, vec!["drive.file:read".to_string()]);
        assert!(!set.is_granted("google.doc", "docA", false), "not before consent");
        assert_eq!(set.grant_consent(&scopes, 2), 1);
        assert!(set.is_granted("google.doc", "docA", false));

        // DocB write: the consent tab is closed, nothing is recorded as consented.
        let scopes = set
            .ensure_resources(&sup, &[("google.doc".into(), "docB".into(), true)], 3)
            .unwrap();
        assert_eq!(scopes, vec!["drive.file:write".to_string()]);
        assert!(!set.is_granted("google.doc", "docB", true));
        assert!(!set.is_granted("google.doc", "docB", false));
        // Asking again re-raises the consent instead of returning nothing.
        let again = set
            .ensure_resources(&sup, &[("google.doc".into(), "docB".into(), true)], 4)
            .unwrap();
        assert_eq!(again, vec!["drive.file:write".to_string()]);

        // A read-only consent never admits the write.
        set.grant_consent(&["drive.file:read".into()], 5);
        assert!(!set.is_granted("google.doc", "docB", true));

        // A consent that arrives after the pending expansion lapsed does not
        // activate it.
        set.grant_consent(&["drive.file:write".into()], 4 + PENDING_GRANT_TTL_MS + 1);
        assert!(!set.is_granted("google.doc", "docB", true));
        assert!(set.pending().is_empty());

        // Declining drops the pending expansion.
        let mut set2 = ResourceGrantSet::new();
        set2.ensure_resources(&sup, &[("google.doc".into(), "docC".into(), false)], 1)
            .unwrap();
        assert_eq!(set2.abort_pending(), 1);
        set2.grant_consent(&["drive.file:read".into()], 2);
        assert!(!set2.is_granted("google.doc", "docC", false));

        // Disconnect: no held scope, no admission.
        set.revoke_consent();
        assert!(!set.is_granted("google.doc", "docA", false));
    }

    /// The gap: consent was not bound to the flow it was given in, so
    /// consenting to a later introduction that needed the same vendor scope
    /// activated an earlier, abandoned one.
    #[test]
    fn consenting_to_one_flow_does_not_activate_an_abandoned_one() {
        let sup = doc_kinds();
        let mut set = ResourceGrantSet::new();
        let scopes = set
            .ensure_resources(&sup, &[("google.doc".into(), "docB".into(), true)], 1)
            .unwrap();
        let abandoned = set.begin_consent(1);
        assert_eq!(abandoned.units.len(), 1);
        set.ensure_resources(&sup, &[("google.doc".into(), "docScratch".into(), true)], 2)
            .unwrap();
        let flow = set.begin_consent(2);
        assert_eq!(flow.units, vec![("google.doc".into(), "docScratch".into(), true)]);
        assert_eq!(set.grant_consent_for(flow.id, &scopes, 3), 1);
        assert!(set.is_granted("google.doc", "docScratch", true));
        assert!(!set.is_granted("google.doc", "docB", false), "the abandoned flow stays pending");
        // Nor does a consent outside any flow complete a flow-bound expansion.
        set.grant_consent(&scopes, 4);
        assert!(!set.is_granted("google.doc", "docB", false));
        // A later flow does not adopt it either; it lapses with its own flow.
        let later = set.begin_consent(5);
        assert!(later.units.is_empty());
        set.grant_consent_for(later.id, &scopes, 6);
        assert!(!set.is_granted("google.doc", "docB", false));
        set.grant_consent(&scopes, 1 + PENDING_GRANT_TTL_MS + 1);
        assert!(set.pending().is_empty());
    }

    #[test]
    fn a_reconnect_does_not_activate_a_pre_disconnect_expansion() {
        let sup = doc_kinds();
        // A pending expansion does not survive a disconnect.
        let mut set2 = ResourceGrantSet::new();
        set2.ensure_resources(&sup, &[("google.doc".into(), "docC".into(), true)], 1)
            .unwrap();
        set2.revoke_consent();
        assert!(set2.pending().is_empty());
        set2.grant_consent(&["drive.file:read".into(), "drive.file:write".into()], 2);
        assert!(!set2.is_granted("google.doc", "docC", true));
    }
}
