//! The connector-owned OAuth flow: nonce-protected callbacks, token
//! ownership, refresh, and expiry/restore events.
//!
//! A connector RUNS the OAuth flow and HOLDS the token; the agent and any
//! consuming app never see it. Three rules, enforced structurally:
//!
//! * **Nonce-protected callbacks.** Every authorization redirect carries a
//!   single-use `state` nonce minted here; a callback presenting an
//!   unknown, reused, or expired nonce is refused. This is the replay
//!   defense the Cloudflare OS gatekeeper contract requires.
//! * **Tokens are held by the connector, stored by digest reference.** The
//!   [`TokenVault`] keeps the secret material in memory for use and exposes
//!   only SHA-256 fingerprints for persistence — the same posture as the AI
//!   gateway's key records ("the store holds a digest, never a usable
//!   key"). The vault is deliberately NOT `Serialize`/`Deserialize`, and its
//!   `Debug` (and [`TokenState`]'s) redact the token values, so neither a
//!   persisted blob nor a diagnostic log can carry a live credential.
//! * **Refresh and expiry are the connector's job.** `token_for` returns a
//!   usable access token only while valid; an expired token with a refresh
//!   token reports `NeedsRefresh` (the host performs the vendor call and
//!   feeds the result back through `complete_refresh`); one without reports
//!   `Expired`, which the UI surfaces as a reconnect prompt.
//!
//! Pending authorizations are bounded: expired nonces are pruned on every
//! begin/complete, and a principal holds at most
//! [`MAX_PENDING_PER_PRINCIPAL`] (the vault at most
//! [`MAX_PENDING_AUTHORIZATIONS`]); beginning another evicts the oldest, so
//! abandoned flows cannot grow the vault without bound.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::gatekeeper::sha256::{sha256, to_hex};
use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Lifetime of a pending authorization nonce (10 minutes).
pub const NONCE_TTL_MS: u64 = 10 * 60 * 1000;
/// Most pending authorizations one principal may hold at once.
pub const MAX_PENDING_PER_PRINCIPAL: usize = 8;
/// Most pending authorizations one vault may hold at once.
pub const MAX_PENDING_AUTHORIZATIONS: usize = 256;

/// How a secret field reads in `Debug` output.
const REDACTED: &str = "<redacted>";

fn hex_digest(data: &[u8]) -> String {
    to_hex(&sha256(data))
}

/// A pending authorization: the nonce we minted and what it is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct PendingAuthorization {
    /// The single-use `state` nonce carried on the redirect.
    pub nonce: String,
    /// The principal connecting their account.
    pub principal: String,
    /// The vendor scopes requested, exactly as `ensure_resources` computed.
    pub scopes: Vec<String>,
    pub created_at: TimestampMs,
}

/// The outcome of asking for a usable access token. `Debug` redacts the
/// token values.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenState {
    /// Usable now.
    Valid { access_token: String },
    /// Expired but refreshable: the host should perform the vendor refresh
    /// call with the returned refresh token and feed the result back.
    NeedsRefresh { refresh_token: String },
    /// Expired with no refresh path: the human must reconnect.
    Expired,
}

impl std::fmt::Debug for TokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid { .. } => f
                .debug_struct("Valid")
                .field("access_token", &format_args!("{REDACTED}"))
                .finish(),
            Self::NeedsRefresh { .. } => f
                .debug_struct("NeedsRefresh")
                .field("refresh_token", &format_args!("{REDACTED}"))
                .finish(),
            Self::Expired => f.write_str("Expired"),
        }
    }
}

/// One connection's token record. Secret material lives only here; the
/// record is never serialized and its `Debug` redacts the tokens.
#[derive(Clone)]
struct TokenRecord {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: TimestampMs,
    /// The vendor scopes consented through this vault's authorizations.
    scopes: BTreeSet<String>,
}

impl TokenRecord {
    fn fingerprint(&self, principal: &str) -> TokenFingerprint {
        TokenFingerprint {
            principal: principal.to_string(),
            access_sha256: hex_digest(self.access_token.as_bytes()),
            expires_at: self.expires_at,
            has_refresh: self.refresh_token.is_some(),
        }
    }
}

impl std::fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRecord")
            .field("access_token", &format_args!("{REDACTED}"))
            .field("has_refresh", &self.refresh_token.is_some())
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// What persistence sees: fingerprints only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct TokenFingerprint {
    pub principal: String,
    /// SHA-256 hex of the access token.
    pub access_sha256: String,
    pub expires_at: TimestampMs,
    pub has_refresh: bool,
}

/// The connector's OAuth state machine: pending nonces + held tokens.
///
/// Not `Serialize`/`Deserialize`: the held tokens must never reach a
/// persisted blob. Persist [`TokenVault::fingerprints`] instead.
#[derive(Default, Clone)]
pub struct TokenVault {
    pending: BTreeMap<String, PendingAuthorization>,
    tokens: BTreeMap<String, TokenRecord>,
    next_nonce: u64,
}

impl std::fmt::Debug for TokenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenVault")
            .field("pending", &self.pending.len())
            .field("tokens", &self.fingerprints())
            .finish()
    }
}

impl TokenVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop pending authorizations whose nonce can no longer complete.
    fn prune_expired(&mut self, now: TimestampMs) {
        self.pending
            .retain(|_, pa| now.saturating_sub(pa.created_at) <= NONCE_TTL_MS);
    }

    /// The oldest pending nonce, optionally for one principal.
    fn oldest_pending(&self, principal: Option<&str>) -> Option<String> {
        self.pending
            .values()
            .filter(|pa| principal.is_none_or(|p| pa.principal == p))
            .min_by(|a, b| (a.created_at, &a.nonce).cmp(&(b.created_at, &b.nonce)))
            .map(|pa| pa.nonce.clone())
    }

    /// Begin an authorization: mint a single-use nonce for the redirect.
    /// `entropy` comes from the host (this package stays deterministic for
    /// its gates); the nonce binds it with a monotonic counter and is
    /// stored server-side, which is what makes replay detectable.
    ///
    /// Expired pendings are pruned first; when the principal (or the vault)
    /// is at its cap, the oldest pending authorization is evicted.
    pub fn begin_authorization(
        &mut self,
        principal: impl Into<String>,
        scopes: Vec<String>,
        entropy: [u8; 16],
        now: TimestampMs,
    ) -> &PendingAuthorization {
        let principal = principal.into();
        self.prune_expired(now);
        while self
            .pending
            .values()
            .filter(|pa| pa.principal == principal)
            .count()
            >= MAX_PENDING_PER_PRINCIPAL
        {
            let Some(oldest) = self.oldest_pending(Some(principal.as_str())) else {
                break;
            };
            self.pending.remove(&oldest);
        }
        while self.pending.len() >= MAX_PENDING_AUTHORIZATIONS {
            let Some(oldest) = self.oldest_pending(None) else {
                break;
            };
            self.pending.remove(&oldest);
        }
        self.next_nonce += 1;
        let mut seed = Vec::with_capacity(24);
        seed.extend_from_slice(&entropy);
        seed.extend_from_slice(&self.next_nonce.to_be_bytes());
        let nonce = hex_digest(&seed);
        let pa = PendingAuthorization {
            nonce: nonce.clone(),
            principal,
            scopes,
            created_at: now,
        };
        self.pending.insert(nonce.clone(), pa);
        self.pending.get(&nonce).expect("just inserted")
    }

    /// Handle the vendor callback. The `state` nonce must be known, unused,
    /// and fresh; it is consumed either way. On success the exchanged
    /// token is held by the vault, owned by the connector, together with
    /// the scopes the nonce was minted for (joined to the scopes already
    /// consented for the principal: the delta semantics of
    /// `ensure_resources` assume incremental authorization).
    pub fn complete_authorization(
        &mut self,
        expected_principal: &str,
        state_nonce: &str,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        expires_at: TimestampMs,
        now: TimestampMs,
    ) -> Result<TokenFingerprint, GatekeeperError> {
        let pa = self.pending.remove(state_nonce);
        self.prune_expired(now);
        let pa = pa.ok_or_else(|| {
            GatekeeperError::Invalid("unknown or already-used OAuth state nonce (replay?)".into())
        })?;
        if now.saturating_sub(pa.created_at) > NONCE_TTL_MS {
            return Err(GatekeeperError::Invalid("OAuth state nonce expired".into()));
        }
        // The callback must be redeemed by the principal that began it: a
        // nonce minted for one principal never stores a token for another.
        if expected_principal.is_empty() || pa.principal != expected_principal {
            return Err(GatekeeperError::Invalid(
                "OAuth state nonce was issued to a different principal".into(),
            ));
        }
        let mut scopes: BTreeSet<String> = pa.scopes.into_iter().collect();
        let mut refresh_token = refresh_token;
        if let Some(previous) = self.tokens.get(&pa.principal) {
            scopes.extend(previous.scopes.iter().cloned());
            // Incremental consent often returns no refresh token: keep the one held,
            // as complete_refresh does, or the session can never be refreshed again.
            if refresh_token.is_none() {
                refresh_token = previous.refresh_token.clone();
            }
        }
        let record = TokenRecord {
            access_token: access_token.into(),
            refresh_token,
            expires_at,
            scopes,
        };
        let fp = record.fingerprint(&pa.principal);
        self.tokens.insert(pa.principal, record);
        Ok(fp)
    }

    /// The vendor scopes consented for `principal`'s held token (sorted;
    /// empty when nothing is held).
    pub fn granted_scopes(&self, principal: &str) -> Vec<String> {
        self.tokens
            .get(principal)
            .map(|rec| rec.scopes.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// How many authorizations are waiting for their callback.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// The usable-token check every vendor call goes through.
    pub fn token_for(
        &self,
        principal: &str,
        now: TimestampMs,
    ) -> Result<TokenState, GatekeeperError> {
        let rec = self.tokens.get(principal).ok_or_else(|| {
            GatekeeperError::Invalid(format!("no connected account for {principal}"))
        })?;
        if now <= rec.expires_at {
            return Ok(TokenState::Valid {
                access_token: rec.access_token.clone(),
            });
        }
        match &rec.refresh_token {
            Some(rt) => Ok(TokenState::NeedsRefresh {
                refresh_token: rt.clone(),
            }),
            None => Ok(TokenState::Expired),
        }
    }

    /// Feed a completed vendor refresh back into the vault.
    pub fn complete_refresh(
        &mut self,
        principal: &str,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        expires_at: TimestampMs,
    ) -> Result<TokenFingerprint, GatekeeperError> {
        let rec = self.tokens.get_mut(principal).ok_or_else(|| {
            GatekeeperError::Invalid(format!("no connected account for {principal}"))
        })?;
        // A refresh needs a refresh token to have been exchanged; a
        // connection that holds none must re-authorize instead.
        if rec.refresh_token.is_none() {
            return Err(GatekeeperError::Invalid(format!(
                "the connection for {principal} holds no refresh token; reconnect instead"
            )));
        }
        rec.access_token = access_token.into();
        if refresh_token.is_some() {
            rec.refresh_token = refresh_token;
        }
        rec.expires_at = expires_at;
        Ok(rec.fingerprint(principal))
    }

    /// Disconnect: drop the held token entirely.
    pub fn disconnect(&mut self, principal: &str) {
        self.tokens.remove(principal);
        // A callback still in flight from before the disconnect must not
        // silently reconnect the account.
        self.pending.retain(|_, pa| pa.principal != principal);
    }

    /// What persistence may see: fingerprints, never secret material.
    pub fn fingerprints(&self) -> Vec<TokenFingerprint> {
        self.tokens
            .iter()
            .map(|(principal, rec)| rec.fingerprint(principal))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_flow_mints_nonce_and_holds_token() {
        let mut v = TokenVault::new();
        let nonce = v
            .begin_authorization("alice", vec!["repo:read".into()], [1u8; 16], 10)
            .nonce
            .clone();
        let fp = v
            .complete_authorization(
                "alice",
                &nonce,
                "gho_secret",
                Some("ghr_refresh".into()),
                100_000,
                20,
            )
            .unwrap();
        assert_eq!(fp.principal, "alice");
        assert!(fp.has_refresh);
        // The fingerprint never contains the token itself.
        assert!(!fp.access_sha256.contains("gho_secret"));
        assert_eq!(
            v.token_for("alice", 50_000).unwrap(),
            TokenState::Valid {
                access_token: "gho_secret".into()
            }
        );
    }

    #[test]
    fn replayed_nonce_is_refused() {
        let mut v = TokenVault::new();
        let nonce = v
            .begin_authorization("alice", vec![], [2u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &nonce, "t", None, 100, 20)
            .unwrap();
        // Same nonce again: replay, refused.
        assert!(v
            .complete_authorization("alice", &nonce, "t2", None, 100, 21)
            .is_err());
        // Unknown nonce: refused.
        assert!(v
            .complete_authorization("alice", "forged", "t3", None, 100, 22)
            .is_err());
    }

    #[test]
    fn stale_nonce_is_refused() {
        let mut v = TokenVault::new();
        let nonce = v
            .begin_authorization("alice", vec![], [3u8; 16], 10)
            .nonce
            .clone();
        let err = v
            .complete_authorization("alice", &nonce, "t", None, 100, 10 + NONCE_TTL_MS + 1)
            .unwrap_err();
        assert!(matches!(err, GatekeeperError::Invalid(_)));
    }

    #[test]
    fn expiry_reports_refresh_path_or_reconnect() {
        let mut v = TokenVault::new();
        let n1 = v
            .begin_authorization("alice", vec![], [4u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &n1, "a1", Some("r1".into()), 1_000, 20)
            .unwrap();
        assert_eq!(
            v.token_for("alice", 2_000).unwrap(),
            TokenState::NeedsRefresh {
                refresh_token: "r1".into()
            }
        );
        v.complete_refresh("alice", "a2", None, 5_000).unwrap();
        assert_eq!(
            v.token_for("alice", 3_000).unwrap(),
            TokenState::Valid {
                access_token: "a2".into()
            }
        );
        // No refresh token and expired -> reconnect.
        let n2 = v
            .begin_authorization("bob", vec![], [5u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("bob", &n2, "b1", None, 1_000, 20)
            .unwrap();
        assert_eq!(v.token_for("bob", 2_000).unwrap(), TokenState::Expired);
    }

    #[test]
    fn persistence_sees_only_digests() {
        let mut v = TokenVault::new();
        let n = v
            .begin_authorization("alice", vec![], [6u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &n, "super-secret-token", None, 100, 20)
            .unwrap();
        let json = ferrite_app::serde_json::to_string(&v.fingerprints()).unwrap();
        assert!(!json.contains("super-secret-token"));
        assert_eq!(v.fingerprints().len(), 1);
    }

    #[test]
    fn disconnect_drops_the_token() {
        let mut v = TokenVault::new();
        let n = v
            .begin_authorization("alice", vec![], [7u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &n, "t", None, 100, 20).unwrap();
        v.disconnect("alice");
        assert!(v.token_for("alice", 50).is_err());
    }

    // Autoref specialization: resolves to `true` only when `T: Serialize`.
    struct Probe<T>(std::marker::PhantomData<T>);
    trait SerializeProbe {
        fn serializable(&self) -> bool {
            true
        }
    }
    impl<T: Serialize> SerializeProbe for Probe<T> {}
    trait FallbackProbe {
        fn serializable(&self) -> bool {
            false
        }
    }
    impl<T> FallbackProbe for &Probe<T> {}

    /// F182: the vault cannot be serialized or Debug-printed with its
    /// secrets, so neither a persisted blob nor a log line carries them.
    #[test]
    fn held_tokens_never_reach_serialization_or_debug() {
        assert!(
            !(&Probe::<TokenVault>(std::marker::PhantomData)).serializable(),
            "TokenVault must not implement Serialize"
        );
        // The fingerprint (what persistence may see) still serializes.
        assert!((&Probe::<TokenFingerprint>(std::marker::PhantomData)).serializable());

        let mut v = TokenVault::new();
        let n = v
            .begin_authorization("alice", vec![], [8u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &n, "live-access-token", Some("live-refresh".into()), 100, 20)
            .unwrap();
        let debug = format!("{v:?}");
        assert!(!debug.contains("live-access-token"), "{debug}");
        assert!(!debug.contains("live-refresh"), "{debug}");
        let state = format!("{:?}", v.token_for("alice", 50).unwrap());
        assert!(!state.contains("live-access-token"), "{state}");
        let state = format!("{:?}", v.token_for("alice", 500).unwrap());
        assert!(!state.contains("live-refresh"), "{state}");
        assert!(state.contains(REDACTED));
    }

    /// F480: abandoned authorizations are pruned and capped.
    #[test]
    fn pending_nonces_are_pruned_and_capped() {
        let mut v = TokenVault::new();
        // Many abandoned flows for one principal: bounded by the per-principal cap.
        for i in 0..100u8 {
            v.begin_authorization("alice", vec![], [i; 16], 10 + u64::from(i));
        }
        assert_eq!(v.pending_count(), MAX_PENDING_PER_PRINCIPAL);
        // The newest nonce still completes.
        let newest = v
            .begin_authorization("alice", vec![], [200u8; 16], 200)
            .nonce
            .clone();
        assert!(v.complete_authorization("alice", &newest, "t", None, 1_000, 201).is_ok());

        // Expired pendings are pruned on the next begin.
        let mut v = TokenVault::new();
        for i in 0..5u8 {
            v.begin_authorization(format!("user-{i}"), vec![], [i; 16], 10);
        }
        assert_eq!(v.pending_count(), 5);
        v.begin_authorization("late", vec![], [9u8; 16], 10 + NONCE_TTL_MS + 1);
        assert_eq!(v.pending_count(), 1);

        // The vault-wide cap holds across principals.
        let mut v = TokenVault::new();
        for i in 0..(MAX_PENDING_AUTHORIZATIONS + 50) {
            let mut entropy = [0u8; 16];
            entropy[..8].copy_from_slice(&(i as u64).to_be_bytes());
            v.begin_authorization(format!("user-{i}"), vec![], entropy, 10);
        }
        assert_eq!(v.pending_count(), MAX_PENDING_AUTHORIZATIONS);
    }

    #[test]
    fn consented_scopes_accumulate_per_principal() {
        let mut v = TokenVault::new();
        let n1 = v
            .begin_authorization("alice", vec!["read".into()], [1u8; 16], 10)
            .nonce
            .clone();
        v.complete_authorization("alice", &n1, "t1", None, 1_000, 11).unwrap();
        let n2 = v
            .begin_authorization("alice", vec!["write".into()], [2u8; 16], 12)
            .nonce
            .clone();
        v.complete_authorization("alice", &n2, "t2", None, 1_000, 13).unwrap();
        assert_eq!(
            v.granted_scopes("alice"),
            vec!["read".to_string(), "write".to_string()]
        );
        v.disconnect("alice");
        assert!(v.granted_scopes("alice").is_empty());
    }

    #[test]
    fn a_callback_is_redeemed_only_by_its_principal_and_disconnect_drops_pending() {
        let mut v = TokenVault::new();
        let mallory = v
            .begin_authorization("mallory", vec![], [8u8; 16], 10)
            .nonce
            .clone();
        // Alice's session redeems mallory's callback: refused, nonce consumed.
        assert!(v.complete_authorization("alice", &mallory, "evil", None, 100, 20).is_err());
        assert!(v.token_for("alice", 30).is_err());
        assert!(v.token_for("mallory", 30).is_err());
        assert!(v.complete_authorization("mallory", &mallory, "t", None, 100, 21).is_err());
        // A pending callback does not survive a disconnect.
        let n = v.begin_authorization("alice", vec![], [9u8; 16], 30).nonce.clone();
        v.disconnect("alice");
        assert_eq!(v.pending_count(), 0);
        assert!(v.complete_authorization("alice", &n, "t", None, 100, 31).is_err());
        assert!(v.token_for("alice", 40).is_err());
    }

    #[test]
    fn refresh_without_a_refresh_token_is_refused() {
        let mut v = TokenVault::new();
        let n = v.begin_authorization("alice", vec![], [10u8; 16], 10).nonce.clone();
        v.complete_authorization("alice", &n, "t", None, 100, 20).unwrap();
        assert!(v.complete_refresh("alice", "minted", None, 10_000).is_err());
        assert_eq!(v.token_for("alice", 200).unwrap(), TokenState::Expired);
    }
}
