//! **The activity host**: work that outlives the request that started
//! it.
//!
//! # What an activity is, and why the outbox is not one
//!
//! Alloy already has a mechanism for durable effects: an [`crate::alloy::outbox`]
//! intent is committed inside an action's guarded envelope and performed
//! afterwards, at least once. That covers *fire and forget* — publish this,
//! call that, notify them.
//!
//! An **activity** is the other shape. It is state a user is still holding:
//! a draft being typed, a wizard half filled in, an upload being assembled.
//! Three properties distinguish it from an outbox intent, and each one rules
//! out reusing the outbox:
//!
//! - It is **read back**, repeatedly, by the person who owns it. An outbox
//!   record is written once and consumed by the drain; nothing reads it.
//! - It is **replaced**, not appended. Typing produces a new draft that
//!   supersedes the last one, where an intent is a fact that already
//!   happened and cannot be revised.
//! - It **expires on its own**. Nobody publishes a draft that was abandoned
//!   three weeks ago, and nothing will ever come along to delete it.
//!
//! # The lease, and why expiry is storage's job
//!
//! Every activity carries a deadline, and that deadline is the STORE TTL.
//! The alternative — a status field and a sweeper — has a failure mode this
//! design does not: a sweeper that stops running leaves abandoned state
//! visible forever, and nothing reports it, because from the outside a
//! sweeper that is not running looks exactly like a sweeper with nothing to
//! do. Storage making the key absent needs no janitor and cannot silently
//! stop.
//!
//! Touching an activity EXTENDS its lease. That is what makes "idle for
//! thirty minutes" the thing that expires it, rather than "created thirty
//! minutes ago" — an author who is still typing must not lose their draft
//! merely because they started it a while back.

use ferrite_app::client::StoreClusterClient;
use ferrite_app::serde::de::DeserializeOwned;
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};

/// The key namespace activities live under.
pub const ACTIVITY_PREFIX: &str = "act/";

/// How long an untouched activity survives: thirty minutes.
///
/// Long enough that a distracted author does not lose a draft, short enough
/// that abandoned state does not accumulate for weeks.
pub const DEFAULT_LEASE_MS: u64 = 30 * 60 * 1_000;

/// The longest lease an activity may hold.
///
/// An unbounded lease is a permanent leak with extra steps, so the ceiling
/// is enforced rather than documented.
pub const MAX_LEASE_MS: u64 = 24 * 60 * 60 * 1_000;

/// The key one activity lives under.
///
/// The owner is part of the key, so two people editing the same document
/// hold two activities and neither can read or overwrite the other's.
///
/// Each part is escaped (`%` and `/`), so the key is injective: an owner or
/// subject holding a slash cannot land on another owner's key. A part with
/// neither character is written verbatim, so existing keys do not move.
pub fn activity_key(kind: &str, owner: &str, subject: &str) -> String {
    format!(
        "{ACTIVITY_PREFIX}{}/{}/{}",
        escape_part(kind),
        escape_part(owner),
        escape_part(subject)
    )
}

fn escape_part(part: &str) -> String {
    part.replace('%', "%25").replace('/', "%2F")
}

/// One activity: a payload, its owner, and its deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Activity<T> {
    /// What kind of activity this is, for example `draft`.
    pub kind: String,
    /// Who owns it. Part of the key, and repeated here so a read can check.
    pub owner: String,
    /// What it is about, for example a document id.
    pub subject: String,
    /// The carried state.
    pub payload: T,
    /// When it was created.
    pub created_at_ms: u64,
    /// When it was last touched.
    pub touched_at_ms: u64,
    /// When it expires, which is also the store TTL.
    pub expires_at_ms: u64,
}

impl<T> Activity<T> {
    /// How long this activity has been idle at `now_ms`.
    pub fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.touched_at_ms)
    }

    /// Whether it has expired at `now_ms`.
    ///
    /// Storage enforces this too, but a clock check costs nothing and closes
    /// the window between the deadline passing and the key being reclaimed.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// The activity host, over an injected store handle.
pub struct ActivityHost {
    store: StoreClusterClient,
    lease_ms: u64,
}

impl ActivityHost {
    /// Bind the host with the default lease.
    pub fn new(store: StoreClusterClient) -> Self {
        Self {
            store,
            lease_ms: DEFAULT_LEASE_MS,
        }
    }

    /// Bind with an explicit lease, clamped to [`MAX_LEASE_MS`].
    ///
    /// Clamped rather than refused: a caller asking for a week has made a
    /// judgement about their own workload, and the ceiling is a safety bound
    /// rather than a contract they must satisfy. A zero lease IS refused,
    /// because an activity that expires at the instant it is written is
    /// indistinguishable from a failed write.
    pub fn with_lease(store: StoreClusterClient, lease_ms: u64) -> Result<Self> {
        if lease_ms == 0 {
            return Err(AlloyError::internal(
                "an activity lease of zero would expire the activity at the moment it \
                 was written, which is indistinguishable from a failed write",
            ));
        }
        Ok(Self {
            store,
            lease_ms: lease_ms.min(MAX_LEASE_MS),
        })
    }

    /// The lease this host grants.
    pub fn lease_ms(&self) -> u64 {
        self.lease_ms
    }

    /// Write or replace an activity, extending its lease.
    ///
    /// Replacement is unconditional and that is deliberate: an activity is
    /// owned by ONE actor — the owner is in the key — so there is no second
    /// writer to lose an update to, and a compare-and-swap here would make
    /// an author's own autosave fail against their own previous keystroke.
    pub async fn put<T>(
        &mut self,
        kind: &str,
        owner: &str,
        subject: &str,
        payload: T,
        now_ms: u64,
    ) -> Result<Activity<T>>
    where
        T: Serialize + DeserializeOwned,
    {
        let key = activity_key(kind, owner, subject);
        // A touch EXTENDS the lease, so idleness expires an activity rather
        // than age. An author still typing must not lose a draft merely
        // because they began it half an hour ago.
        let created_at_ms = match self.load_raw(&key).await? {
            Some(existing) => existing,
            None => now_ms,
        };
        let activity = Activity {
            kind: kind.to_string(),
            owner: owner.to_string(),
            subject: subject.to_string(),
            payload,
            created_at_ms,
            touched_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.lease_ms),
        };
        let encoded =
            serde_json::to_vec(&activity).map_err(|e| AlloyError::internal(e.to_string()))?;
        self.store
            .put_expiring(key.as_bytes(), &encoded, activity.expires_at_ms)
            .await?;
        Ok(activity)
    }

    /// Read an activity, or `None` when there is none or it has expired.
    ///
    /// An expired activity reads as ABSENT rather than as an error: from the
    /// caller's point of view a lapsed draft and a draft that was never
    /// started are the same situation, and forcing every reader to
    /// distinguish them would put the expiry rule in every call site.
    pub async fn get<T>(
        &mut self,
        kind: &str,
        owner: &str,
        subject: &str,
        now_ms: u64,
    ) -> Result<Option<Activity<T>>>
    where
        T: Serialize + DeserializeOwned,
    {
        let key = activity_key(kind, owner, subject);
        let Some(raw) = self.store.get(key.as_bytes()).await? else {
            return Ok(None);
        };
        // A payload that no longer decodes — the type changed since it was
        // written — is a miss, not a fault. An activity is never the source
        // of truth, so an unreadable one costs the author their draft and
        // never costs anyone a failed request.
        let Ok(activity) = serde_json::from_slice::<Activity<T>>(&raw) else {
            return Ok(None);
        };
        if activity.is_expired(now_ms) {
            return Ok(None);
        }
        // The owner is in the KEY, so this can only differ if something
        // wrote to the key directly. Refusing is the safe reading.
        if activity.owner != owner || activity.kind != kind || activity.subject != subject {
            return Ok(None);
        }
        Ok(Some(activity))
    }

    /// Drop an activity, whether or not it exists.
    pub async fn clear(&mut self, kind: &str, owner: &str, subject: &str) -> Result<()> {
        let key = activity_key(kind, owner, subject);
        self.store.delete(key.as_bytes()).await?;
        Ok(())
    }

    /// The `created_at_ms` of an existing activity, without decoding its
    /// payload type.
    ///
    /// A touch must preserve the original creation instant, and the caller
    /// may not know the payload type at that point — so this reads the
    /// envelope only.
    async fn load_raw(&mut self, key: &str) -> Result<Option<u64>> {
        let Some(raw) = self.store.get(key.as_bytes()).await? else {
            return Ok(None);
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            return Ok(None);
        };
        Ok(value.get("created_at_ms").and_then(|v| v.as_u64()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_owner_is_part_of_the_key_so_two_authors_cannot_collide() {
        // Two people drafting against ONE document hold two activities.
        // Without the owner in the key the second author's keystroke would
        // overwrite the first author's draft, and neither would be told.
        let a = activity_key("draft", "ana", "d-1");
        let b = activity_key("draft", "raj", "d-1");
        assert_ne!(a, b);
        assert!(a.starts_with(ACTIVITY_PREFIX));
        // …and one author's two subjects are likewise distinct.
        assert_ne!(
            activity_key("draft", "ana", "d-1"),
            activity_key("draft", "ana", "d-2")
        );
        // A different KIND against the same subject is its own activity, so
        // a draft and an upload do not overwrite each other.
        assert_ne!(
            activity_key("draft", "ana", "d-1"),
            activity_key("upload", "ana", "d-1")
        );
    }

    #[test]
    fn a_slash_cannot_move_a_key_across_owners_kinds_or_subjects() {
        // finding_b285f5c78b698bf6
        assert_ne!(
            activity_key("draft", "org", "alice/doc-1"),
            activity_key("draft", "org/alice", "doc-1")
        );
        assert_ne!(activity_key("a/x", "x", "b"), activity_key("a", "x", "x/b"));
        assert_ne!(activity_key("d", "a%2Fb", "s"), activity_key("d", "a/b", "s"));
        // Plain parts keep their historical key.
        assert_eq!(activity_key("draft", "ana", "d-1"), "act/draft/ana/d-1");
    }

    #[test]
    fn an_activity_expires_on_idleness_rather_than_age() {
        let act = Activity {
            kind: "draft".into(),
            owner: "ana".into(),
            subject: "d-1".into(),
            payload: "text",
            created_at_ms: 0,
            touched_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_LEASE_MS,
        };
        // Created long ago, touched recently: still live. An author who has
        // been editing for hours must not lose their draft.
        assert!(!act.is_expired(1_000_000 + DEFAULT_LEASE_MS - 1));
        assert!(act.is_expired(1_000_000 + DEFAULT_LEASE_MS));
        assert_eq!(act.idle_ms(1_060_000), 60_000);
    }

    #[test]
    fn an_idle_time_never_underflows_when_the_clock_steps_backward() {
        let act = Activity {
            kind: "draft".into(),
            owner: "ana".into(),
            subject: "d-1".into(),
            payload: (),
            created_at_ms: 0,
            touched_at_ms: 5_000,
            expires_at_ms: 100_000,
        };
        assert_eq!(act.idle_ms(1_000), 0);
    }

    #[tokio::test]
    async fn a_zero_lease_is_refused_and_an_enormous_one_is_clamped() {
        // These are CONST assertions where they can be: a change violating
        // the bound fails the build rather than waiting for a test run.
        const _: () = assert!(DEFAULT_LEASE_MS > 0);
        const _: () = assert!(DEFAULT_LEASE_MS <= MAX_LEASE_MS);
        const _: () = assert!(MAX_LEASE_MS <= 24 * 60 * 60 * 1_000);

        let env = ferrite_app_test::TestHarness::new()
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        assert!(ActivityHost::with_lease(ctx.store("data").expect("binds"), 0).is_err());
        let host = ActivityHost::with_lease(ctx.store("data").expect("binds"), MAX_LEASE_MS * 100)
            .expect("a large lease is clamped, not refused");
        assert_eq!(host.lease_ms(), MAX_LEASE_MS);
    }

    #[tokio::test]
    async fn touching_extends_the_lease_preserves_created_at_ms_and_drops_undecodable_payloads() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(crate = "ferrite_app::serde")]
        struct Draft {
            body: String,
            base_revision: u32,
        }

        let start = 4_000_000_000_000u64;
        let env = ferrite_app_test::TestHarness::new()
            .manual_clock(start)
            .with_store("data")
            .build()
            .await;
        let ctx = env.context();
        let mut host = ActivityHost::new(ctx.store("data").expect("the store binds"));

        host.put(
            "draft",
            "ana",
            "r-1",
            Draft {
                body: "typing".into(),
                base_revision: 1,
            },
            start,
        )
        .await
        .expect("written");
        let touch = start + DEFAULT_LEASE_MS - 60_000;
        host.put(
            "draft",
            "ana",
            "r-1",
            Draft {
                body: "still typing".into(),
                base_revision: 1,
            },
            touch,
        )
        .await
        .expect("touched");

        let past_original = start + DEFAULT_LEASE_MS + 1_000;
        let read = host
            .get::<Draft>("draft", "ana", "r-1", past_original)
            .await
            .expect("a read succeeds")
            .expect("the draft expired on its age rather than on its idleness");
        assert_eq!(read.payload.body, "still typing");
        assert_eq!(read.created_at_ms, start, "a touch reset the creation time");
        assert_eq!(read.touched_at_ms, touch);

        host.put("draft", "ana", "r-1", "a bare string".to_string(), touch)
            .await
            .expect("written");
        let mistyped = host
            .get::<Draft>("draft", "ana", "r-1", touch)
            .await
            .expect("the read does not fail");
        assert!(mistyped.is_none(), "a mistyped payload must read as absent");
    }
}
