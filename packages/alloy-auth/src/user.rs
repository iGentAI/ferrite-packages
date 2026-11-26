//! User records and credential verification.

use ferrite_app::client::StoreClusterClient;
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};

/// The shortest password the package accepts.
///
/// A minimum is a real control, not decoration: PBKDF2 raises the cost of
/// each guess, but nothing rescues a four-character password.
pub const MIN_PASSWORD: usize = 8;

/// The longest password accepted, so a hostile client cannot make the
/// server burn CPU hashing a megabyte.
pub const MAX_PASSWORD: usize = 512;

/// The roles this package recognises, most privileged first.
///
/// The set is CLOSED. `require_writer` denies exactly `viewer`, so a record
/// carrying an unrecognised role — a typo, a role from a newer deployment —
/// would pass every write check by default. Refusing the role at the point
/// of creation is what makes the deny-list safe.
///
/// These three are the only values `create_if_absent` accepts. Note that
/// `"writer"` is NOT among them: [`crate::alloy_auth::Writer`] is an
/// authority LEVEL meaning "not a viewer", which both `admin` and `member`
/// satisfy. Storing a role of `"writer"` is refused.
pub const ROLES: &[&str] = &["admin", "member", "viewer"];

/// The most sign-in attempts one account admits in one
/// [`SIGN_IN_WINDOW_MS`] window.
///
/// PBKDF2 makes each guess expensive, but without a count the number of
/// guesses is bounded only by how long an attacker cares to keep asking.
/// Every attempt is counted, right or wrong, BEFORE the password is checked,
/// so concurrent guesses cannot overrun the bound; a success clears the
/// count, so a busy account (a shared demo login, say) is not starved by its
/// own sign-ins.
pub const MAX_SIGN_IN_ATTEMPTS: u32 = 10;

/// How long a window of sign-in attempts lasts. The window opens at the
/// first attempt after the previous one ended, and its record expires with
/// it, so a locked account opens again without anyone acting.
pub const SIGN_IN_WINDOW_MS: u64 = 15 * 60 * 1_000;

/// How many times reserving an attempt re-reads a counter another request
/// changed first, before it refuses rather than spin.
const SIGN_IN_COUNT_RACES: u32 = 8;

/// The key a user record lives under.
pub fn user_key(id: &str) -> String {
    format!("user/{id}")
}

/// The key the sign-in attempt count for `id` lives under.
///
/// It is the id's DIGEST, so a caller-chosen id of any length or shape
/// names a fixed-size key, and an unknown id is counted exactly like a known
/// one: the limit must not answer differently for an account that does not
/// exist, or it becomes the enumeration oracle `verify` refuses to be.
pub fn sign_in_attempts_key(id: &str) -> String {
    let digest = ferrite_app::crypto::sha256(id.as_bytes());
    format!("signin/{}", crate::crypto::hex_encode(&digest))
}

/// One account's sign-in attempts in the current window, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct SignInAttempts {
    /// Attempts counted in this window, the one being made included.
    attempts: u32,
    /// When the window ends (epoch ms), which is also the record's expiry.
    window_ends_ms: u64,
}

/// One user, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct UserRecord {
    /// The stable user id, which is also what an audit entry records.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The role this user holds (`admin` | `member` | `viewer`).
    pub role: String,
    /// The PBKDF2-SHA256 credential, as `password_hash` encodes it.
    ///
    /// The plaintext never exists outside the login request, and this
    /// string is never returned by any surface.
    pub password: String,
    /// This account INSTANCE: a random value written when the record is
    /// created and copied into every session it opens.
    ///
    /// An id names an account only until the account is deleted; the next
    /// account created under the same id gets a new epoch, so a session
    /// opened for the earlier one no longer resolves
    /// ([`crate::alloy_auth::session::SessionStore::resolve`] compares the
    /// two). A record written before epochs existed reads as the empty
    /// epoch, which matches the sessions written before them.
    #[serde(default)]
    pub epoch: String,
}

/// The entropy in an account epoch: 16 bytes, so two accounts created
/// under one id never share one.
pub const EPOCH_BYTES: usize = 16;

/// The authenticated identity a request carries.
///
/// Constructed by [`crate::alloy_auth::user::UserStore::verify`] and
/// [`crate::alloy_auth::session::SessionStore::resolve`],
/// so a value of this type is evidence that the server verified a
/// credential — an application cannot fabricate one from a header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Actor {
    /// The authenticated user id.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The role.
    pub role: String,
}

impl From<UserRecord> for Actor {
    fn from(user: UserRecord) -> Self {
        Self {
            id: user.id,
            name: user.name,
            role: user.role,
        }
    }
}

impl Actor {
    /// Whether this actor holds the `admin` role.
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    /// Refuse unless this actor holds `role`.
    pub fn require_role(&self, role: &str) -> Result<()> {
        if self.role == role || self.is_admin() {
            Ok(())
        } else {
            Err(AlloyError::Forbidden)
        }
    }

    /// Refuse a read-only actor a write.
    ///
    /// A viewer that can mutate is not a viewer, and this is the single
    /// place every application checks it.
    pub fn require_writer(&self) -> Result<()> {
        if self.role == "viewer" {
            return Err(AlloyError::Forbidden);
        }
        Ok(())
    }
}

/// User records over an injected store handle.
pub struct UserStore {
    store: StoreClusterClient,
}

impl UserStore {
    /// Wrap an injected store client.
    pub fn new(store: StoreClusterClient) -> Self {
        Self { store }
    }

    /// Read one user record.
    pub async fn get(&mut self, id: &str) -> Result<Option<UserRecord>> {
        let Some(raw) = self.store.get(user_key(id).as_bytes()).await? else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&raw).ok())
    }

    /// Create a user if absent. Returns whether this call created it.
    ///
    /// Create-if-absent rather than overwrite: seeding runs on every boot
    /// and on every instance, and resetting a password someone has already
    /// changed would be a silent security regression.
    pub async fn create_if_absent(
        &mut self,
        id: &str,
        name: &str,
        role: &str,
        password: &str,
    ) -> Result<bool> {
        if !ROLES.contains(&role) {
            return Err(AlloyError::internal(format!(
                "'{role}' is not one of the recognised roles ({})",
                ROLES.join(", ")
            )));
        }
        // A credential shorter than `verify` will ever accept is a record
        // that can never be used: the account exists, the password is
        // "right", and every login fails. Refuse it here instead.
        if password.len() < MIN_PASSWORD || password.len() > MAX_PASSWORD {
            return Err(AlloyError::internal(format!(
                "a password must be {MIN_PASSWORD}-{MAX_PASSWORD} bytes"
            )));
        }
        if self.get(id).await?.is_some() {
            return Ok(false);
        }
        let record = UserRecord {
            id: id.to_string(),
            name: name.to_string(),
            role: role.to_string(),
            password: crate::crypto::password_hash(password.as_bytes())
                .map_err(|e| AlloyError::internal(e.to_string()))?,
            epoch: crate::crypto::random_token(EPOCH_BYTES)
                .map_err(|e| AlloyError::internal(e.to_string()))?,
        };
        let encoded =
            serde_json::to_vec(&record).map_err(|e| AlloyError::internal(e.to_string()))?;
        let created = self
            .store
            .put_if_version(user_key(id).as_bytes(), &encoded, None)
            .await?
            .is_ok();
        Ok(created)
    }

    /// Verify a credential, answering the authenticated actor.
    ///
    /// An unknown user and a wrong password produce the SAME error, and the
    /// unknown-user path still performs a hash. Answering faster for an
    /// unknown id would turn this endpoint into an account-enumeration
    /// oracle, which is how an attacker builds the target list before they
    /// ever guess a password.
    pub async fn verify(&mut self, id: &str, password: &str) -> Result<Actor> {
        Ok(self.verify_record(id, password).await?.into())
    }

    /// [`UserStore::verify`], answering the verified record itself, so a
    /// session can be bound to the epoch of the account instance whose
    /// password was checked rather than to one read afterwards.
    async fn verify_record(&mut self, id: &str, password: &str) -> Result<UserRecord> {
        if password.len() < MIN_PASSWORD || password.len() > MAX_PASSWORD {
            return Err(AlloyError::Unauthorized);
        }
        let found = self.get(id).await?;
        let encoded = found
            .as_ref()
            .map(|u| u.password.clone())
            // A decoy with the same scheme and cost as a real record, so the
            // unknown-user path spends the same work as the known one.
            .unwrap_or_else(decoy_credential);
        let ok = crate::crypto::password_verify(password.as_bytes(), &encoded);
        match (ok, found) {
            (true, Some(user)) => Ok(user),
            _ => Err(AlloyError::Unauthorized),
        }
    }

    /// Verify a sign-in attempt, within the per-account attempt limit.
    ///
    /// This is [`UserStore::verify`] behind [`MAX_SIGN_IN_ATTEMPTS`] per
    /// [`SIGN_IN_WINDOW_MS`]: once an account has used its attempts, every
    /// further attempt in the window is refused with
    /// [`AlloyError::TooManyRequests`] carrying the seconds until the window
    /// ends, the right password included, and without the password being
    /// checked. A successful attempt clears the count.
    ///
    /// [`crate::alloy_auth::session::SessionStore::login`] calls this; an
    /// application that signs people in any other way must call it too,
    /// because `verify` alone counts nothing.
    ///
    /// The limit is per account, not per client: an application receives no
    /// client address it could trust. Its cost is that anyone can hold an
    /// account's sign-in shut for one window by spending its attempts; an
    /// unbounded guess rate is the worse failure.
    pub async fn verify_sign_in(&mut self, id: &str, password: &str, now_ms: u64) -> Result<Actor> {
        Ok(self.verify_sign_in_record(id, password, now_ms).await?.into())
    }

    /// [`UserStore::verify_sign_in`], answering the verified record.
    pub(crate) async fn verify_sign_in_record(
        &mut self,
        id: &str,
        password: &str,
        now_ms: u64,
    ) -> Result<UserRecord> {
        self.count_sign_in_attempt(id, now_ms).await?;
        let record = self.verify_record(id, password).await?;
        self.store
            .delete(sign_in_attempts_key(id).as_bytes())
            .await?;
        Ok(record)
    }

    /// Count one sign-in attempt for `id`, or refuse it when the window's
    /// attempts are spent.
    ///
    /// The count is a compare-and-swap on the record's version, so two
    /// concurrent attempts cannot both read the same count and both pass.
    async fn count_sign_in_attempt(&mut self, id: &str, now_ms: u64) -> Result<()> {
        let key = sign_in_attempts_key(id);
        for _ in 0..SIGN_IN_COUNT_RACES {
            let (current, version) = match self.store.get_versioned(key.as_bytes()).await? {
                Some((raw, version)) => (
                    serde_json::from_slice::<SignInAttempts>(&raw)
                        .ok()
                        .filter(|w| now_ms < w.window_ends_ms),
                    Some(version),
                ),
                None => (None, None),
            };
            let window = current.unwrap_or(SignInAttempts {
                attempts: 0,
                window_ends_ms: now_ms.saturating_add(SIGN_IN_WINDOW_MS),
            });
            if window.attempts >= MAX_SIGN_IN_ATTEMPTS {
                return Err(AlloyError::TooManyRequests {
                    retry_after_secs: (window.window_ends_ms - now_ms).div_ceil(1_000).max(1),
                });
            }
            let next = SignInAttempts {
                attempts: window.attempts + 1,
                window_ends_ms: window.window_ends_ms,
            };
            let encoded =
                serde_json::to_vec(&next).map_err(|e| AlloyError::internal(e.to_string()))?;
            if self
                .store
                .put_if_version_expiring(key.as_bytes(), &encoded, version, next.window_ends_ms)
                .await?
                .is_ok()
            {
                return Ok(());
            }
        }
        // Lost every race: this account is being tried faster than the
        // count can be written, which is itself a reason to refuse.
        Err(AlloyError::TooManyRequests { retry_after_secs: 1 })
    }
}

/// The record `verify` checks an unknown user against: a well-formed
/// credential at the cost `password_hash` uses, so that path costs the same
/// as a wrong password for a real user.
fn decoy_credential() -> String {
    format!(
        "pbkdf2-sha256${}${}${}",
        crate::crypto::DEFAULT_PBKDF2_ITERATIONS,
        "0".repeat(32),
        "0".repeat(64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_round_trips_and_a_wrong_password_fails() {
        let encoded = crate::crypto::password_hash(b"correct horse battery").unwrap();
        assert!(crate::crypto::password_verify(
            b"correct horse battery",
            &encoded
        ));
        assert!(!crate::crypto::password_verify(b"wrong", &encoded));
    }

    #[test]
    fn a_stored_credential_is_never_the_plaintext() {
        let encoded = crate::crypto::password_hash(b"correct horse battery").unwrap();
        assert!(!encoded.contains("correct horse battery"));
        assert!(encoded.starts_with("pbkdf2-sha256$"));
        // Two records of the SAME password must differ, or a store dump
        // would reveal which accounts share a password.
        let again = crate::crypto::password_hash(b"correct horse battery").unwrap();
        assert_ne!(encoded, again);
    }

    #[test]
    fn the_decoy_credential_is_a_real_parseable_record() {
        // If the decoy did not parse, `password_verify` would bail out
        // early and the unknown-user path would be measurably faster than
        // the wrong-password path — the exact timing oracle it exists to
        // remove. Its cost must equal the cost of a record `password_hash`
        // writes today.
        let decoy = decoy_credential();
        assert!(!crate::crypto::password_verify(b"anything", &decoy));
        let real = crate::crypto::password_hash(b"correct horse battery").unwrap();
        let cost = |encoded: &str| encoded.split('$').nth(1).and_then(|s| s.parse::<u32>().ok());
        assert!(cost(&real).is_some());
        assert_eq!(cost(&decoy), cost(&real), "the decoy's cost differs from a real record's");
        let mut parts = decoy.split('$');
        assert_eq!(parts.next(), Some("pbkdf2-sha256"));
        parts.next();
        assert_eq!(parts.next().map(|s| s.len()), Some(32));
        assert_eq!(parts.next().map(|s| s.len()), Some(64));
        assert_eq!(parts.next(), None);
    }

    #[test]
    fn a_viewer_may_not_write_and_an_admin_may_do_anything() {
        let viewer = Actor {
            id: "v".into(),
            name: "V".into(),
            role: "viewer".into(),
        };
        let member = Actor {
            id: "m".into(),
            name: "M".into(),
            role: "member".into(),
        };
        let admin = Actor {
            id: "a".into(),
            name: "A".into(),
            role: "admin".into(),
        };
        assert!(viewer.require_writer().is_err());
        assert!(member.require_writer().is_ok());
        assert!(admin.require_writer().is_ok());
        assert!(member.require_role("admin").is_err());
        assert!(admin.require_role("admin").is_ok());
        // An admin passes a member check too: roles nest rather than
        // partition, or every admin would need a second account to work.
        assert!(admin.require_role("member").is_ok());
        assert!(!member.is_admin());
    }

    #[test]
    fn every_recognised_role_has_a_defined_write_verdict() {
        // `require_writer` is a DENY list, so a role outside this set would
        // silently gain write authority. This asserts the set and the
        // verdicts together.
        assert_eq!(ROLES, &["admin", "member", "viewer"]);
        for role in ROLES {
            let actor = Actor {
                id: "u".into(),
                name: "U".into(),
                role: (*role).to_string(),
            };
            assert_eq!(actor.require_writer().is_ok(), *role != "viewer", "{role}");
        }
    }

    #[test]
    fn user_keys_are_namespaced() {
        assert_eq!(user_key("ana"), "user/ana");
    }
}
