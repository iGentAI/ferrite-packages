//! Sharing mechanics: hashed share keys and the lazy-revocation permission
//! graph.
//!
//! Three adopted patterns:
//!
//! * **Share keys stored only as hashes.** A share link carries a 128-bit
//!   random key; the server stores only its SHA-256 (an HMAC-style secret
//!   digest keyed by a server pepper). The server cannot reconstruct
//!   links, and a database leak exposes nothing usable.
//! * **Lazy revocation via reachability.** The graph records HOW each
//!   party got access — a user edge (`granted_by -> grantee`) or a
//!   share-link edge. Effective access is a fixed point over reachability
//!   from the owner at `open()` time. Revocation severs edges; anyone no
//!   longer reachable loses access at their next open. Cheap, transitive,
//!   previewable, undoable.
//! * **Blast-radius preview** — `preview_revocation` names everyone a cut
//!   would disconnect ("removing Bob also cuts off Carol") before the cut
//!   happens.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::blueprints::roles::Role;
use crate::gatekeeper::sha256::{sha256_concat, to_hex};

/// Sharing failures.
#[derive(Debug, PartialEq, Eq)]
pub enum SharingError {
    UnknownShareKey,
    RevokedShareKey,
    UnknownEdge { from: String, to: String },
}

impl std::fmt::Display for SharingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShareKey => write!(f, "unknown share key"),
            Self::RevokedShareKey => write!(f, "share key revoked"),
            Self::UnknownEdge { from, to } => write!(f, "unknown edge {from} -> {to}"),
        }
    }
}

impl std::error::Error for SharingError {}

/// A share key: the secret material IS the link. Only its hash is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareKey {
    /// 128-bit key, hex-encoded (the link fragment).
    pub secret: String,
}

impl ShareKey {
    /// Mint from caller-supplied entropy (the host provides randomness; this
    /// package stays deterministic for its gates).
    pub fn from_entropy(entropy: [u8; 16]) -> Self {
        Self {
            secret: to_hex(&entropy),
        }
    }

    fn digest(&self, pepper: &[u8]) -> String {
        to_hex(&sha256_concat(&[pepper, self.secret.as_bytes()]))
    }
}

/// Stored share-key records: digest -> (role, revoked).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ShareKeyStore {
    /// Server-side pepper for the digest. Not secret material of the links
    /// themselves; it binds digests to this deployment.
    pepper: Vec<u8>,
    records: BTreeMap<String, (Role, bool)>,
}

impl ShareKeyStore {
    pub fn new(pepper: impl Into<Vec<u8>>) -> Self {
        Self {
            pepper: pepper.into(),
            records: BTreeMap::new(),
        }
    }

    /// Record a minted key. Only the digest is kept.
    pub fn record(&mut self, key: &ShareKey, role: Role) {
        self.records.insert(key.digest(&self.pepper), (role, false));
    }

    /// Redeem a presented key: returns its role when valid.
    pub fn redeem(&self, key: &ShareKey) -> Result<Role, SharingError> {
        match self.records.get(&key.digest(&self.pepper)) {
            None => Err(SharingError::UnknownShareKey),
            Some((_, true)) => Err(SharingError::RevokedShareKey),
            Some((role, false)) => Ok(*role),
        }
    }

    /// Revoke a key by its digest (the server never has the secret again).
    pub fn revoke(&mut self, key: &ShareKey) -> Result<(), SharingError> {
        match self.records.get_mut(&key.digest(&self.pepper)) {
            None => Err(SharingError::UnknownShareKey),
            Some(rec) => {
                rec.1 = true;
                Ok(())
            }
        }
    }

    /// True when no stored record contains secret material (structural
    /// guarantee the gates assert).
    pub fn stores_only_digests(&self, key: &ShareKey) -> bool {
        !self.records.keys().any(|k| k.contains(&key.secret))
    }
}

/// One access edge: `to` has access because `from` granted it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub role: Role,
}

/// What a revocation would disconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct RevocationPreview {
    /// Everyone who would lose access, in deterministic order.
    pub disconnected: Vec<String>,
}

/// The permission graph for one shared surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PermissionGraph {
    owner: String,
    edges: BTreeSet<Edge>,
}

impl PermissionGraph {
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            edges: BTreeSet::new(),
        }
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Record a grant: `from` shares with `to` at `role`.
    pub fn grant(&mut self, from: impl Into<String>, to: impl Into<String>, role: Role) {
        self.edges.insert(Edge {
            from: from.into(),
            to: to.into(),
            role,
        });
    }

    /// Sever one edge (lazy revocation: access disappears at next open).
    pub fn revoke_edge(&mut self, from: &str, to: &str) -> Result<(), SharingError> {
        let before = self.edges.len();
        self.edges.retain(|e| !(e.from == from && e.to == to));
        if self.edges.len() == before {
            return Err(SharingError::UnknownEdge {
                from: from.into(),
                to: to.into(),
            });
        }
        Ok(())
    }

    /// Effective role: a fixed point over reachability from the owner.
    /// The owner always has `Build`. A party reached over multiple paths
    /// gets the strongest role among them; a party not reachable has none.
    pub fn effective_role(&self, who: &str) -> Option<Role> {
        if who == self.owner {
            return Some(Role::Build);
        }
        // BFS from the owner; a grantee's role is capped by the granter's
        // effective role (you cannot pass on more than you hold).
        let mut best: BTreeMap<&str, Role> = BTreeMap::new();
        best.insert(self.owner.as_str(), Role::Build);
        let mut queue: VecDeque<&str> = VecDeque::new();
        queue.push_back(self.owner.as_str());
        while let Some(cur) = queue.pop_front() {
            let cur_role = best[cur];
            for e in self.edges.iter().filter(|e| e.from == cur) {
                let granted = e.role.min(cur_role);
                if best.get(e.to.as_str()).is_none_or(|r| granted > *r) {
                    best.insert(e.to.as_str(), granted);
                    queue.push_back(e.to.as_str());
                }
            }
        }
        best.get(who).copied()
    }

    /// Everyone currently reachable (with access), excluding the owner.
    pub fn reachable(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        queue.push_back(self.owner.as_str());
        seen.insert(self.owner.as_str());
        while let Some(cur) = queue.pop_front() {
            for e in self.edges.iter().filter(|e| e.from == cur) {
                if seen.insert(e.to.as_str()) {
                    out.insert(e.to.clone());
                    queue.push_back(e.to.as_str());
                }
            }
        }
        out
    }

    /// Preview a revocation's blast radius without executing it.
    pub fn preview_revocation(&self, from: &str, to: &str) -> RevocationPreview {
        let mut hypothetical = self.clone();
        let _ = hypothetical.revoke_edge(from, to);
        let before = self.reachable();
        let after = hypothetical.reachable();
        let disconnected = before.difference(&after).cloned().collect();
        RevocationPreview { disconnected }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_keys_store_only_digests() {
        let key = ShareKey::from_entropy([7u8; 16]);
        let mut store = ShareKeyStore::new(b"pepper".to_vec());
        store.record(&key, Role::Use);
        assert!(store.stores_only_digests(&key));
        assert_eq!(store.redeem(&key), Ok(Role::Use));
        // A different key does not redeem.
        let other = ShareKey::from_entropy([8u8; 16]);
        assert_eq!(store.redeem(&other), Err(SharingError::UnknownShareKey));
    }

    #[test]
    fn revoked_keys_stop_redeeming() {
        let key = ShareKey::from_entropy([1u8; 16]);
        let mut store = ShareKeyStore::new(b"p".to_vec());
        store.record(&key, Role::Build);
        store.revoke(&key).unwrap();
        assert_eq!(store.redeem(&key), Err(SharingError::RevokedShareKey));
    }

    #[test]
    fn effective_role_is_reachability_from_owner() {
        let mut g = PermissionGraph::new("alice");
        g.grant("alice", "bob", Role::Build);
        g.grant("bob", "carol", Role::Use);
        assert_eq!(g.effective_role("alice"), Some(Role::Build));
        assert_eq!(g.effective_role("bob"), Some(Role::Build));
        assert_eq!(g.effective_role("carol"), Some(Role::Use));
        assert_eq!(g.effective_role("mallory"), None);
    }

    #[test]
    fn role_is_capped_by_the_granter() {
        let mut g = PermissionGraph::new("alice");
        g.grant("alice", "bob", Role::Use);
        // bob (Use) tries to hand carol Build — capped to Use.
        g.grant("bob", "carol", Role::Build);
        assert_eq!(g.effective_role("carol"), Some(Role::Use));
    }

    #[test]
    fn revocation_is_transitive_and_previewable() {
        let mut g = PermissionGraph::new("alice");
        g.grant("alice", "bob", Role::Build);
        g.grant("bob", "carol", Role::Use);
        g.grant("alice", "dave", Role::Use);
        // Preview first: cutting bob also cuts carol, never dave.
        let preview = g.preview_revocation("alice", "bob");
        assert_eq!(
            preview.disconnected,
            vec!["bob".to_string(), "carol".to_string()]
        );
        // Execute: both lose access lazily (at next effective_role check).
        g.revoke_edge("alice", "bob").unwrap();
        assert_eq!(g.effective_role("bob"), None);
        assert_eq!(g.effective_role("carol"), None);
        assert_eq!(g.effective_role("dave"), Some(Role::Use));
    }

    #[test]
    fn multiple_paths_keep_access_after_one_cut() {
        let mut g = PermissionGraph::new("alice");
        g.grant("alice", "bob", Role::Build);
        g.grant("alice", "carol", Role::Use);
        g.grant("bob", "carol", Role::Build);
        // carol holds Build through bob.
        assert_eq!(g.effective_role("carol"), Some(Role::Build));
        g.revoke_edge("bob", "carol").unwrap();
        // Still reachable via alice, at the weaker role.
        assert_eq!(g.effective_role("carol"), Some(Role::Use));
    }

    #[test]
    fn unknown_edge_revocation_errors() {
        let mut g = PermissionGraph::new("alice");
        assert!(matches!(
            g.revoke_edge("alice", "nobody"),
            Err(SharingError::UnknownEdge { .. })
        ));
    }
}
