//! The cached loader: what `ctx.cached(..)` actually does.
//!
//! This is where [`crate::alloy::cache`] and [`crate::alloy::tags`] meet the
//! store plane. A read is:
//!
//! 1. **L1** — an in-process hit, validated against tag epochs like any
//!    other. Correctness never depends on it; it only removes a round trip.
//! 2. **L2** — one store read for the envelope, then one bounded APE
//!    `multi_get` to validate its witness.
//! 3. **Miss or dead** — run the loader, write the envelope with the epochs
//!    observed *before* the load, and return.
//!
//! # Why the witness is read before the load, not after
//!
//! If the epochs were read after the loader ran, a tag advanced *during* the
//! load would be recorded as already-observed, and the entry would be born
//! stale with no way to notice. Reading first means a concurrent advance
//! makes the new entry's witness fail on the very next read — the safe
//! direction, costing a recompute rather than serving stale data.
//!
//! # Stale-while-revalidate
//!
//! A stale entry is served immediately and refreshed in the background. The
//! refresh is single-flighted through a store lease key
//! (`put_if_version_expiring` with `expected = None`), which is
//! create-if-absent with a self-releasing TTL: N replicas racing to refresh
//! collapse to one winner, and a crashed holder's lock expires into absence
//! with no janitor to write.

use std::future::Future;

use ferrite_app::client::StoreClusterClient;
use ferrite_app::serde::de::DeserializeOwned;
use ferrite_app::serde::Serialize;
use ferrite_app::serde_json;
use ferrite_app::tracing;

use crate::alloy::cache::{
    cache_key, CacheBody, CacheEnvelope, CacheLife, Freshness, L1Cache, TagWitness, MAX_INLINE_BODY,
};
use crate::alloy::error::{AlloyError, Result};
use crate::alloy::tags::TagStore;

/// How long a single-flight refresh lease is held before it self-releases.
pub const REFRESH_LEASE_MS: u64 = 30_000;

/// How long a cold-fill lease is held before it self-releases.
///
/// Shorter than the refresh lease: nobody is being served while a cold fill
/// is in flight, so a dead holder costs real misses rather than a delayed
/// background refresh, and the key must come back quickly.
pub const FILL_LEASE_MS: u64 = 10_000;

/// The key namespace cold-fill leases live under.
pub const FILL_PREFIX: &str = "fl/";

/// The cold-fill lease key guarding one entry's first write.
pub fn fill_key(entry_key: &str) -> String {
    format!("{FILL_PREFIX}{entry_key}")
}

/// The key namespace refresh leases live under.
pub const LEASE_PREFIX: &str = "rl/";

/// The lease key guarding one entry's refresh.
pub fn lease_key(entry_key: &str) -> String {
    format!("{LEASE_PREFIX}{entry_key}")
}

/// What a cached read did — surfaced so `/__alloy/cache` can report it and so
/// tests can assert the path taken rather than merely the value returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Served from the in-process L1.
    L1Hit,
    /// Served from the store envelope.
    L2Hit,
    /// Served stale; a refresh was started by this caller.
    StaleRefreshed,
    /// Served stale; another caller holds the refresh lease.
    StaleShared,
    /// Served stale because this caller's refresh failed. The stale window
    /// exists precisely so a failing upstream degrades to old data instead
    /// of an error.
    StaleRefreshFailed,
    /// The loader ran.
    Miss,
    /// A cold miss: another caller held the fill lease and had already
    /// written the entry, so this caller served THEIR value without
    /// running the loader a second time.
    MissShared,
    /// The cache was bypassed: the loader ran, and nothing was read or
    /// written. This is draft mode's path — a previewing author must see
    /// the draft on every request AND must not poison the published
    /// entry with it.
    Bypassed,
}

/// The result of a cached read.
#[derive(Debug, Clone)]
pub struct Cached<T> {
    /// The value.
    pub value: T,
    /// Which path produced it.
    pub outcome: CacheOutcome,
}

/// The cached-loader surface over an injected store and the tag table.
pub struct CacheStore {
    store: StoreClusterClient,
    tags: TagStore,
    l1: L1Cache,
    clock: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
}

impl CacheStore {
    /// Bind the cache to the conventional `cache` store and `tags` APE handles.
    pub fn open(ctx: &ferrite_app::AppContext) -> Result<Self> {
        Ok(Self::new(ctx.store("cache")?, TagStore::new(ctx.ape("tags")?)))
    }

    /// Bind the cache to an injected store handle and the tag table.
    pub fn new(store: StoreClusterClient, tags: TagStore) -> Self {
        Self {
            store,
            tags,
            l1: L1Cache::with_defaults(),
            clock: None,
        }
    }

    /// Bind with an explicitly sized L1.
    pub fn with_l1(store: StoreClusterClient, tags: TagStore, l1: L1Cache) -> Self {
        Self { store, tags, l1, clock: None }
    }

    /// Sample the application's injected clock after awaited cache work.
    /// Without this, the `now_ms` argument remains the timestamp for the whole
    /// call, preserving the existing explicit-timestamp API. Supplying a clock
    /// dates a newly loaded entry at its cache publication attempt, not at the
    /// start of a potentially slow load. Tag witnesses still precede the load.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Box::new(clock));
        self
    }

    fn current_ms(&self, fallback: u64) -> u64 {
        self.clock.as_ref().map_or(fallback, |clock| clock())
    }

    /// The L1, for inspection by the dev-tools surface.
    pub fn l1(&self) -> &L1Cache {
        &self.l1
    }

    /// Drop every L1 entry — the fallback when a topic-tail invalidation
    /// cannot be resolved to specific keys.
    pub fn clear_l1(&mut self) {
        self.l1.clear();
    }

    /// Read `fn_id(args)` through the cache, running `load` on a miss.
    ///
    /// `tags` are the invalidation tags this entry depends on; `life` is its
    /// freshness profile; `now_ms` comes from the injected clock.
    pub async fn get<T, F, Fut>(
        &mut self,
        fn_id: &str,
        args: &[u8],
        tags: &[String],
        life: CacheLife,
        now_ms: u64,
        load: F,
    ) -> Result<Cached<T>>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.get_bypassing(fn_id, args, tags, life, now_ms, false, load)
            .await
    }

    /// [`get`](Self::get), with an explicit bypass switch.
    ///
    /// `bypass` is draft mode's path, and it must skip BOTH directions at
    /// once. Skipping only the read would compute the draft and then WRITE
    /// it, so the next published-mode reader of a popular key is served an
    /// unpublished draft from cache — the exact leak draft mode exists to
    /// prevent, created by the mechanism that enables it. Skipping only the
    /// write would serve the previewing author the stale published entry
    /// and never the draft.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_bypassing<T, F, Fut>(
        &mut self,
        fn_id: &str,
        args: &[u8],
        tags: &[String],
        life: CacheLife,
        now_ms: u64,
        bypass: bool,
        load: F,
    ) -> Result<Cached<T>>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if bypass {
            return Ok(Cached {
                value: load().await?,
                outcome: CacheOutcome::Bypassed,
            });
        }
        // A profile whose expiry precedes its stale point silently disables
        // stale-while-revalidate: storage removes the entry before it can
        // ever be served stale, so every read that would have been an
        // instant stale hit becomes a blocking recompute. Nothing downstream
        // can detect that, because a cache miss and a cache that never
        // serves stale look identical from the outside — so it is refused
        // here, at the one place every cached read passes through.
        life.validate()?;

        // Every witness is stored in canonical tag order and compared by
        // position, so the epochs must be read for the canonical list too.
        let tags = TagWitness::canonical_tags(tags);
        let tags = tags.as_slice();

        let key = cache_key(fn_id, args);

        // One epoch read serves the whole request: the L1 check, the L2
        // witness check, and the witness a fresh entry is written with.
        let epochs = self.tags.epochs(tags).await?;

        if let Some(envelope) = self.l1.get(&key) {
            if Self::freshness_for(&envelope, tags, self.current_ms(now_ms), &epochs) == Freshness::Fresh {
                if let Some(value) = Self::decode_body::<T>(&envelope) {
                    return Ok(Cached {
                        value,
                        outcome: CacheOutcome::L1Hit,
                    });
                }
            }
            // Dead, or carrying a body this reader cannot decode: drop it so
            // a later read cannot see it again, then fall through to L2.
            self.l1.remove(&key);
        }

        let stored = self.store.get_versioned(key.as_bytes()).await?;
        if let Some((bytes, version)) = &stored {
            if let Some(envelope) = CacheEnvelope::decode(bytes) {
                // A body this reader cannot decode is a MISS, never a fault:
                // the entry may predate a type change, or its body may live
                // in the blob plane. The cache is never the source of truth,
                // so the honest answer is to recompute rather than fail a
                // request the loader could have served.
                let decoded = Self::decode_body::<T>(&envelope);
                match (Self::freshness_for(&envelope, tags, self.current_ms(now_ms), &epochs), decoded) {
                    (Freshness::Fresh, Some(value)) => {
                        self.l1.put(key.clone(), envelope.clone());
                        return Ok(Cached {
                            value,
                            outcome: CacheOutcome::L2Hit,
                        });
                    }
                    (Freshness::Stale, Some(stale)) => {
                        // Serve the stale body; only the lease winner
                        // recomputes behind it.
                        self.l1.put(key.clone(), envelope.clone());
                        if !self
                            .try_take_lease(lease_key(&key), REFRESH_LEASE_MS, now_ms)
                            .await?
                        {
                            return Ok(Cached {
                                value: stale,
                                outcome: CacheOutcome::StaleShared,
                            });
                        }
                        // The lease is HELD from here on, so every exit below
                        // releases it. Leaving it set would block every later
                        // refresh of this entry for the full lease window —
                        // including after a refresh that failed instantly.
                        let out = match load().await {
                            Ok(fresh) => {
                                // A write failure must not fail the request
                                // either: the fresh value is in hand, and the
                                // entry simply stays stale for another round.
                                let _ = self
                                    .write(
                                        &key,
                                        &fresh,
                                        tags,
                                        &epochs,
                                        life,
                                        now_ms,
                                        Some(*version),
                                    )
                                    .await;
                                Cached {
                                    value: fresh,
                                    outcome: CacheOutcome::StaleRefreshed,
                                }
                            }
                            // Degrading to stale data is the entire purpose of
                            // the stale window. Propagating this error would
                            // turn a survivable upstream failure into a failed
                            // request for every reader of a popular key.
                            Err(_) => Cached {
                                value: stale,
                                outcome: CacheOutcome::StaleRefreshFailed,
                            },
                        };
                        self.release_lease(lease_key(&key)).await;
                        return Ok(out);
                    }
                    _ => {}
                }
            }
        }

        // The cold miss, single-flighted.
        //
        // A stale REFRESH was already single-flighted; a cold miss was not,
        // so N readers arriving on an empty popular key each ran the loader.
        // That is the stampede case: the moment an entry expires — or the
        // first request after a deploy — every concurrent reader hits the
        // origin at once, which is exactly when it can least afford it.
        //
        // The lease is the SAME self-releasing create-if-absent lock the
        // refresh path uses, so a holder that dies mid-load frees the key by
        // expiry rather than wedging it.
        //
        // A loser does NOT block waiting for the winner. Blocking would
        // couple every reader's latency to the slowest loader and turn one
        // failing load into a queue of stalled requests. Instead it re-reads
        // once: if the winner has already written, it serves that value; if
        // not, it runs the loader itself. The worst case is therefore the
        // OLD behaviour — a duplicated load — and never a stalled request.
        //
        // The fill lease is distinct from the refresh lease: an entry can be
        // absent and being filled, or present-but-stale and being refreshed,
        // and those are different states with different holders. One key for
        // both would let a refresh in flight suppress a fill of a DIFFERENT,
        // already-expired entry, which is a hit the cache would never recover.
        let holds_fill = self
            .try_take_lease(fill_key(&key), FILL_LEASE_MS, now_ms)
            .await?;
        if !holds_fill {
            if let Some((bytes, _version)) = self.store.get_versioned(key.as_bytes()).await? {
                if let Some(envelope) = CacheEnvelope::decode(&bytes) {
                    if Self::freshness_for(&envelope, tags, self.current_ms(now_ms), &epochs) != Freshness::Expired {
                        if let Some(value) = Self::decode_body::<T>(&envelope) {
                            self.l1.put(key.clone(), envelope);
                            return Ok(Cached {
                                value,
                                outcome: CacheOutcome::MissShared,
                            });
                        }
                    }
                }
            }
        }

        let loaded = load().await;
        // The lease is released whichever way the load went. Leaving it set
        // after a FAILED load would make every other reader take the
        // re-read path and find nothing, so a broken upstream would look
        // like a cache that had stopped filling.
        if holds_fill {
            self.release_lease(fill_key(&key)).await;
        }
        let value = loaded?;
        let expected = stored.as_ref().map(|(_, v)| *v);
        // The value is in hand, so a failed write costs the NEXT reader a
        // recompute and never costs this one its answer — the same rule the
        // stale-refresh path follows. Propagating it would turn a degraded
        // cache plane (or a value that cannot be serialized) into a failed
        // request the loader had already served.
        if let Err(error) = self
            .write(&key, &value, tags, &epochs, life, now_ms, expected)
            .await
        {
            tracing::warn!(
                target: "alloy::cache",
                fn_id = %fn_id,
                error = %error,
                "writing a freshly loaded cache entry failed; serving the value uncached"
            );
        }
        Ok(Cached {
            value,
            outcome: CacheOutcome::Miss,
        })
    }

    /// Drop one entry from L1 and the store.
    pub async fn invalidate(&mut self, fn_id: &str, args: &[u8]) -> Result<()> {
        let key = cache_key(fn_id, args);
        self.l1.remove(&key);
        self.store.delete(key.as_bytes()).await?;
        Ok(())
    }

    /// The tag table, for an action that must advance epochs.
    pub fn tags_mut(&mut self) -> &mut TagStore {
        &mut self.tags
    }

    /// The store handle, for a loader that reads its own domain state.
    pub fn store_mut(&mut self) -> &mut StoreClusterClient {
        &mut self.store
    }

    /// Decode an envelope body, or `None` when this reader cannot — because
    /// the body lives in the blob plane, or because the stored JSON no longer
    /// matches `T` after a contract change. Both are cache misses, and both
    /// must stay misses: a cache that can fail a request it was only ever
    /// meant to accelerate is worse than no cache.
    fn decode_body<T>(envelope: &CacheEnvelope) -> Option<T>
    where
        T: DeserializeOwned,
    {
        let bytes = envelope.inline_bytes()?;
        serde_json::from_slice(bytes).ok()
    }

    #[allow(clippy::too_many_arguments)]
    async fn write<T>(
        &mut self,
        key: &str,
        value: &T,
        tags: &[String],
        epochs: &[u64],
        life: CacheLife,
        now_ms: u64,
        expected: Option<u64>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let bytes = serde_json::to_vec(value).map_err(|e| AlloyError::internal(e.to_string()))?;
        if bytes.len() > MAX_INLINE_BODY {
            // Oversized bodies belong in blob; caching them inline would
            // push a multi-megabyte value through every envelope read. A
            // smaller entry this one replaces is dropped, or readers keep
            // being served the superseded value (and re-run the load).
            if expected.is_some() {
                self.l1.remove(key);
                self.store.delete(key.as_bytes()).await?;
            }
            return Ok(());
        }
        let witness = TagWitness::new(tags, epochs)?;
        let envelope = CacheEnvelope::new(CacheBody::Inline { bytes }, witness, life, self.current_ms(now_ms));
        let encoded = envelope.encode()?;
        // The TTL is the EXPIRE window, never the stale window: storage makes
        // an expired key absent, so setting it to `stale_at` would delete
        // entries that are still legitimately servable.
        // Another writer filling this key first is not an error: theirs is at
        // least as fresh as ours, and overwriting would discard a newer value.
        let written = self
            .store
            .put_if_version_expiring(key.as_bytes(), &encoded, expected, envelope.expire_at_ms)
            .await?;
        if written.is_ok() {
            self.l1.put(key.to_string(), envelope);
        }
        Ok(())
    }

    /// Release a single-flight lease.
    ///
    /// A failed release is not worth failing an already-served request over:
    /// the lease carries a TTL, so the cost of losing this delete is one
    /// delayed refresh rather than a wedged key.
    async fn release_lease(&mut self, lease: String) {
        let _ = self.store.delete(lease.as_bytes()).await;
    }

    /// Try to take a single-flight lease.
    async fn try_take_lease(&mut self, lease: String, ttl_ms: u64, now_ms: u64) -> Result<bool> {
        let expires = self.current_ms(now_ms).saturating_add(ttl_ms);
        // `expected = None` is create-if-absent, and an EXPIRED lease reads as
        // absent — which is exactly what makes the lock self-releasing when a
        // holder dies mid-refresh.
        let taken = self
            .store
            .put_if_version_expiring(lease.as_bytes(), b"1", None, expires)
            .await?;
        Ok(taken.is_ok())
    }
}

impl CacheStore {
    /// An envelope's freshness for this read's tags: an entry witnessed over a
    /// different tag set (a renamed tag, a per-scope tag) is a miss, never a hit
    /// judged against another tag's epochs.
    fn freshness_for(envelope: &CacheEnvelope, tags: &[String], now_ms: u64, epochs: &[u64]) -> Freshness {
        if envelope.witness.covers(tags) {
            envelope.freshness(now_ms, epochs)
        } else {
            Freshness::Expired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_lease_never_collides_with_the_refresh_lease_it_sits_beside() {
        // An entry can be ABSENT and being filled, or PRESENT-BUT-STALE and
        // being refreshed. Those are different states with different
        // holders, so one key for both would let a refresh in flight
        // suppress the cold fill of an already-expired entry — a miss the
        // cache would never recover, because the filler simply walked away.
        let entry = cache_key("get_drop", b"42");
        let fill = fill_key(&entry);
        let refresh = lease_key(&entry);

        assert_ne!(fill, refresh, "the two leases share a key");
        assert!(fill.starts_with(FILL_PREFIX));
        assert!(refresh.starts_with(LEASE_PREFIX));

        // Neither may look like a cache entry, or a sweep of the cache
        // namespace would take the locks with it.
        assert!(!fill.starts_with("cache/"));
        assert!(!refresh.starts_with("cache/"));

        // …and distinct entries still take distinct fill leases, or one
        // popular key would single-flight the whole cache.
        assert_ne!(
            fill_key(&cache_key("f", b"1")),
            fill_key(&cache_key("f", b"2"))
        );
    }

    #[test]
    fn the_fill_lease_is_bounded_and_shorter_than_a_refresh() {
        // A dead FILL holder is worse than a dead refresh holder: nobody is
        // being served from the entry meanwhile, so the key has to come back
        // quickly. These are const assertions, so a change that violated the
        // bound fails the BUILD rather than waiting for anyone to run this.
        const _: () = assert!(FILL_LEASE_MS > 0);
        const _: () = assert!(FILL_LEASE_MS <= REFRESH_LEASE_MS);
        const _: () = assert!(FILL_LEASE_MS <= 30_000);
    }

    #[test]
    fn distinct_entries_take_distinct_leases() {
        let a = lease_key(&cache_key("f", b"1"));
        let b = lease_key(&cache_key("f", b"2"));
        assert_ne!(a, b);
    }

    #[test]
    fn an_undecodable_body_reads_as_a_miss_rather_than_a_fault() {
        // A blob-backed body: this reader has no bytes to decode, so the
        // loader must run instead of the request failing.
        let blob_backed = CacheEnvelope::new(
            CacheBody::Blob {
                digest: "d".into(),
                len: 10,
            },
            TagWitness::untagged(),
            CacheLife::Minutes,
            0,
        );
        assert!(CacheStore::decode_body::<serde_json::Value>(&blob_backed).is_none());

        // A body written before a contract change no longer matches `T`.
        let mistyped = CacheEnvelope::new(
            CacheBody::Inline {
                bytes: b"\"a string\"".to_vec(),
            },
            TagWitness::untagged(),
            CacheLife::Minutes,
            0,
        );
        assert!(CacheStore::decode_body::<u64>(&mistyped).is_none());
        // …and the same bytes still decode for the type that wrote them.
        assert_eq!(
            CacheStore::decode_body::<String>(&mistyped).as_deref(),
            Some("a string")
        );
    }

    #[test]
    fn the_refresh_lease_is_bounded_so_a_dead_holder_cannot_wedge_a_key() {
        // A lease with no expiry would make one crashed replica stop every
        // future refresh of that entry for the life of the deployment.
        //
        // These are CONST assertions: the bound is a compile-time property
        // of the constant, so a change that violated it would fail the build
        // rather than wait for anyone to run this test. Written as runtime
        // asserts the compiler folds them to `assert!(true)` and they check
        // nothing at all.
        const _: () = assert!(REFRESH_LEASE_MS > 0);
        const _: () = assert!(REFRESH_LEASE_MS <= 60_000);
    }

    /// A cache whose plane handles cannot connect. A bypassed read must still
    /// succeed: touching either handle would fail the test, without opening a
    /// listener that the authoritative remote test sandbox rightly forbids.
    fn cache_without_planes() -> CacheStore {
        use ferrite_app::{AppContext, InjectionPayload, ServiceEntry, WireMember};

        // Built from the SDK's own serde form carrying only the two fields
        // every SDK requires, not as a struct literal and not as the context
        // text carrier. A literal names every field, so it compiles against
        // exactly one SDK: upstream Core's payload carries `edge_issuers`,
        // `instance`, `generation` and `door_service`, the CLI's twin carries
        // `native_replies`, and each refuses the other's. The text carrier is
        // a tagged shape the host owns, and a test that spelled it out would
        // break on every revision of that tag. Every other field defaults.
        // The address type is the SDK's own field type: naming `std::net`
        // here, even in a test, is refused by upstream's code gate, which
        // scans every `src/` file regardless of `#[cfg(test)]`.
        let member: WireMember = serde_json::from_value(serde_json::json!({
            "node_id": "unreachable",
            "client_addr": "127.0.0.1:1",
            "repl_addr": "127.0.0.1:1"
        })).unwrap();
        let unreachable = member.client_addr;
        let service = |kind: &str, group: &str| {
            ServiceEntry::single(kind, group, vec![member.clone()],
                None,
                None,
                None,
            )
        };
        let mut services = std::collections::BTreeMap::new();
        services.insert("cache".to_string(), service("store", "unreachable-store"));
        services.insert("tags".to_string(), service("ape", "unreachable-tags"));
        let fields: serde_json::Map<String, serde_json::Value> = [
            ("conductor_addrs".to_string(), serde_json::to_value(vec![unreachable]).unwrap()),
            ("services".to_string(), serde_json::to_value(&services).unwrap()),
        ]
        .into_iter()
        .collect();
        let payload: InjectionPayload = serde_json::from_value(serde_json::Value::Object(fields))
            .expect("the SDK decodes a payload naming only a conductor seat and its services");
        assert_eq!(payload.services, services, "the inert services survive the decode");
        let ctx = AppContext::new(payload);
        CacheStore::new(
            ctx.store("cache").expect("the inert store handle binds"),
            TagStore::new(ctx.ape("tags").expect("the inert tag handle binds")),
        )
    }

    #[tokio::test]
    async fn a_bypassed_read_always_runs_the_loader_and_never_writes() {
        // Draft mode's contract, both directions at once: the previewing
        // author sees a fresh compute on EVERY request, and the published
        // cache never holds a draft.
        let mut cache = cache_without_planes();
        let mut runs = 0u32;
        for _ in 0..3 {
            let got = cache
                .get_bypassing::<String, _, _>(
                    "get_draft",
                    b"42",
                    &["drops".to_string()],
                    CacheLife::Minutes,
                    0,
                    true,
                    || {
                        runs += 1;
                        async move { Ok("draft body".to_string()) }
                    },
                )
                .await
                .expect("the bypassed read serves");
            assert_eq!(got.value, "draft body");
            assert_eq!(got.outcome, CacheOutcome::Bypassed);
        }
        assert_eq!(runs, 3, "a bypassed read must never be served from cache");

        // The write was skipped too: nothing landed in L1. The inert plane
        // handles above prove the shared store and tag table were untouched.
        let key = cache_key("get_draft", b"42");
        assert!(
            cache.l1.get(&key).is_none(),
            "a bypassed compute reached L1"
        );
    }

    #[tokio::test]
    async fn a_bypassed_read_skips_an_entry_that_is_sitting_right_there() {
        // A published entry exists in L1 and is FRESH; the bypass must ignore
        // it, or the previewing author is served the published body and
        // never the draft.
        let mut cache = cache_without_planes();
        let key = cache_key("get_drop", b"7");
        cache.l1.put(
            key.clone(),
            CacheEnvelope::new(
                CacheBody::Inline {
                    bytes: serde_json::to_vec(&"published".to_string()).unwrap(),
                },
                TagWitness::untagged(),
                CacheLife::Max,
                0,
            ),
        );

        let draft = cache
            .get_bypassing::<String, _, _>(
                "get_drop",
                b"7",
                &[],
                CacheLife::Max,
                0,
                true,
                || async { Ok("draft".to_string()) },
            )
            .await
            .expect("the bypass serves");
        assert_eq!(draft.value, "draft", "the bypass read the cache");
        assert_eq!(draft.outcome, CacheOutcome::Bypassed);

        // …and the published entry survived the preview untouched.
        let after = cache.l1.get(&key).expect("the published entry remains");
        assert_eq!(
            CacheStore::decode_body::<String>(&after).as_deref(),
            Some("published"),
            "the preview poisoned the cache"
        );
    }

    #[tokio::test]
    async fn a_bypassed_loader_failure_propagates() {
        // There is no stale body to degrade to on the bypass path — the
        // cache was never consulted — so the loader's error is the answer.
        let mut cache = cache_without_planes();
        let err = cache
            .get_bypassing::<String, _, _>(
                "get_drop",
                b"7",
                &[],
                CacheLife::Max,
                0,
                true,
                || async { Err(AlloyError::NotFound) },
            )
            .await
            .expect_err("the failure must propagate");
        assert_eq!(err.status(), 404);
    }
}
