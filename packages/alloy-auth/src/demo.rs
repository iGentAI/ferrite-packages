//! Published demo accounts: seeded only on a deployment that opts in, and
//! retired everywhere else.
//!
//! A demo account's password is published (in the app's source and README), so
//! it is a demo convenience, never a credential: a deployment that has not set
//! [`DEMO_ACCOUNTS_SECRET`] must not create the accounts, must remove any left
//! by an earlier build, and must refuse them even if that removal failed.

use ferrite_app::client::StoreClusterClient;
use ferrite_app::{serde_json, AppContext};

use crate::alloy::error::{AlloyError, Result};
use crate::alloy_auth::user::{user_key, UserRecord, UserStore};

/// One demo account: id, display name, role, published password.
pub type DemoAccount = (&'static str, &'static str, &'static str, &'static str);

/// The secret that turns the demo accounts on. Only the value
/// [`DEMO_ACCOUNTS_ENABLED`] does (surrounding whitespace is ignored); unset
/// or anything else leaves them off.
pub const DEMO_ACCOUNTS_SECRET: &str = "demo-accounts";
/// The value of [`DEMO_ACCOUNTS_SECRET`] that turns the demo accounts on.
pub const DEMO_ACCOUNTS_ENABLED: &str = "enabled";

/// What a retired demo account's record is replaced with. It is not a user
/// record, so a session or a login that reads it finds no user, and it
/// expires a millisecond after it is written, leaving the key absent.
const RETIRED_DEMO_ACCOUNT: &[u8] = br#"{"retired":"published demo password"}"#;

/// Whether this deployment asked for the demo accounts.
pub fn demo_accounts_enabled(ctx: &AppContext) -> bool {
    ctx.secret(DEMO_ACCOUNTS_SECRET).is_some_and(|v| v.trim() == DEMO_ACCOUNTS_ENABLED)
}

/// The version of demo account `id`'s record, if that record still accepts
/// the published password; `None` if the account is absent, is not a user
/// record, or holds a password of its own. A store error is passed on, never
/// read as "the password was changed".
pub async fn published_demo_record_version(
    store: &mut StoreClusterClient,
    id: &str,
    published: &str,
) -> Result<Option<u64>> {
    let key = user_key(id);
    let Some((raw, version)) = store.get_versioned(key.as_bytes()).await? else {
        return Ok(None);
    };
    let Ok(record) = serde_json::from_slice::<UserRecord>(&raw) else {
        return Ok(None);
    };
    if !crate::crypto::password_verify(published.as_bytes(), &record.password) {
        return Ok(None);
    }
    Ok(Some(version))
}

/// Retire demo account `id` if its record is still at `version`, the one
/// [`published_demo_record_version`] checked. Answers whether it did.
///
/// The store has no conditional delete, so the record is replaced, by a
/// compare-and-swap on that version, with [`RETIRED_DEMO_ACCOUNT`] carrying
/// an expiry of `now_ms + 1`. An operator who changes the password, or
/// deletes and re-creates the account, after the check changes the version,
/// the swap fails, and their record is kept.
pub async fn retire_demo_record(
    store: &mut StoreClusterClient,
    id: &str,
    version: u64,
    now_ms: u64,
) -> Result<bool> {
    let key = user_key(id);
    let swapped = store
        .put_if_version_expiring(key.as_bytes(), RETIRED_DEMO_ACCOUNT, Some(version), now_ms.saturating_add(1))
        .await?;
    Ok(swapped.is_ok())
}

/// Remove demo account `id` if its stored record still accepts the
/// published password. Answers whether this call removed it.
///
/// The check and the removal concern ONE version of the record, and nothing
/// is ever deleted unconditionally (see [`retire_demo_record`]). A record
/// already being retired is left to expire. A store error fails the seed.
pub async fn retire_published_demo_account(
    store: &mut StoreClusterClient,
    id: &str,
    published: &str,
    now_ms: u64,
) -> Result<bool> {
    match published_demo_record_version(store, id, published).await? {
        Some(version) => retire_demo_record(store, id, version, now_ms).await,
        None => Ok(false),
    }
}

/// Create the demo accounts on a deployment that asked for them; otherwise
/// retire any that still accept their published password.
///
/// `create_if_absent` never overwrites, so a password someone has since
/// changed survives a redeploy. Retiring an account also ends its sessions;
/// an account whose password was changed is left alone, including one changed
/// while this runs (see [`retire_published_demo_account`]).
pub async fn seed_demo_accounts(ctx: &AppContext, accounts: &[DemoAccount]) -> Result<()> {
    if demo_accounts_enabled(ctx) {
        let mut users = UserStore::new(ctx.store("data")?);
        for (id, name, role, password) in accounts {
            users.create_if_absent(id, name, role, password).await?;
        }
    } else {
        let mut store = ctx.store("data")?;
        for (id, _, _, password) in accounts {
            if retire_published_demo_account(&mut store, id, password, ctx.now_ms()).await? {
                ferrite_app::tracing::warn!(
                    account = *id,
                    "removed a demo account that still used its published password"
                );
            }
        }
    }
    Ok(())
}

/// Per-process memory of [`still_published_demo_account`]'s answers, keyed by
/// account and stored password hash (whose salt is unique to each password
/// set), so a PBKDF2 verification runs once per stored password rather than
/// on every request.
static PUBLISHED_DEMO_CHECKS: std::sync::Mutex<Vec<(String, String, bool)>> =
    std::sync::Mutex::new(Vec::new());

/// Whether `id` is a demo account that still accepts its published password
/// on a deployment that did not enable the demo accounts.
///
/// The boot cleanup removes such an account, which ends its sessions. When
/// that cleanup failed (the store was unreachable during the seed), the
/// account and every session opened while it was a demo account survive;
/// login already refuses the published pair, and this makes session
/// resolution refuse those sessions too.
pub async fn still_published_demo_account(
    ctx: &AppContext,
    accounts: &[DemoAccount],
    id: &str,
) -> Result<bool> {
    if demo_accounts_enabled(ctx) {
        return Ok(false);
    }
    let Some((_, _, _, published)) = accounts.iter().find(|(demo_id, ..)| *demo_id == id) else {
        return Ok(false);
    };
    let mut users = UserStore::new(ctx.store("data")?);
    let Some(record) = users.get(id).await? else {
        return Ok(false);
    };
    let remembered = PUBLISHED_DEMO_CHECKS
        .lock()
        .map_err(|_| AlloyError::internal("the demo-account check cache is poisoned"))?
        .iter()
        .find(|(i, hash, _)| i == id && *hash == record.password)
        .map(|(_, _, still)| *still);
    if let Some(still) = remembered {
        return Ok(still);
    }
    let still = crate::crypto::password_verify(published.as_bytes(), &record.password);
    let mut checks = PUBLISHED_DEMO_CHECKS
        .lock()
        .map_err(|_| AlloyError::internal("the demo-account check cache is poisoned"))?;
    checks.retain(|(i, _, _)| i != id);
    checks.push((id.to_string(), record.password, still));
    Ok(still)
}

/// Whether `id`/`password` is one of the published demo credentials.
pub fn is_published_demo_credential(accounts: &[DemoAccount], id: &str, password: &str) -> bool {
    accounts.iter().any(|(i, _, _, p)| {
        *i == id && crate::crypto::constant_time_eq(password.as_bytes(), p.as_bytes())
    })
}
