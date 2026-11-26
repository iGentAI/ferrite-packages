//! The cache: memoized renders and reads, invalidated by TAG rather
//! than by time alone.
//!
//! Three properties are what make a cache safe to put in front of a
//! database, and all three are bought from platform primitives:
//!
//! 1. **Invalidation is a counter bump, not a scan.** Each tag owns an
//!    atomic counter (`add`); an entry records the generation of every
//!    tag it read. A write bumps the tag, and every entry that read it
//!    is invalid from that instant — without enumerating them. Marking
//!    entries individually would need a scan of unbounded size, and a
//!    scan that is interrupted leaves stale entries served as fresh.
//! 2. **A miss is computed ONCE.** A CAS lease with a TTL elects one
//!    recomputer; everyone else serves the stale value or waits briefly.
//!    Without it, a popular key expiring sends every in-flight request
//!    to the origin at the same instant — the stampede that turns a
//!    cache expiry into an outage.
//! 3. **Expiry is observable, not swept.** TTLs ride the platform's
//!    absolute-instant expiry, so an expired lease is absent by
//!    construction rather than by a cleanup job that might not run.

use std::future::Future;
use std::io;

use ferrite_app::client::StoreClusterClient;
use ferrite_app::{crypto, serde, serde_json};

/// The most tags one entry may carry.
///
/// Every tag costs a read on the hit path, so this is a latency bound as
/// much as a size bound: an entry that wants twenty tags is really
/// asking for a coarser tag.
pub const MAX_TAGS: usize = 8;

/// How long a recomputation lease is held before another caller may take
/// it. Long enough for a slow render, short enough that a crashed holder
/// does not wedge the key.
pub const LEASE_MS: u64 = 10_000;

/// How long a caller that lost the lease waits for the winner's value
/// before computing it itself.
const LOSER_WAIT_MS: u64 = 250;
/// How often it re-checks while waiting.
const LOSER_POLL_MS: u64 = 25;

fn entry_key(key: &str) -> Vec<u8> {
    format!("c:e:{key}").into_bytes()
}

fn lease_key(key: &str) -> Vec<u8> {
    format!("c:l:{key}").into_bytes()
}

fn tag_key(tag: &str) -> Vec<u8> {
    format!("c:t:{tag}").into_bytes()
}

/// How long an entry stays fresh, how long it may be served stale, and
/// what invalidates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheProfile {
    /// Milliseconds an entry is served without recomputation.
    pub ttl_ms: u64,
    /// Milliseconds PAST the TTL an entry may still be served while one
    /// caller recomputes it. `0` disables stale serving.
    pub swr_ms: u64,
    /// Tags that invalidate this entry when bumped.
    pub tags: Vec<String>,
}

impl Default for CacheProfile {
    fn default() -> Self {
        Self {
            ttl_ms: 60_000,
            swr_ms: 300_000,
            tags: Vec::new(),
        }
    }
}

impl CacheProfile {
    /// A profile with `ttl_ms` and no stale window.
    pub fn ttl(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            swr_ms: 0,
            tags: Vec::new(),
        }
    }

    /// Add a tag (silently capped at [`MAX_TAGS`]).
    pub fn tagged(mut self, tag: impl Into<String>) -> Self {
        if self.tags.len() < MAX_TAGS {
            self.tags.push(tag.into());
        }
        self
    }

    /// Set the stale-while-revalidate window.
    pub fn stale_for(mut self, swr_ms: u64) -> Self {
        self.swr_ms = swr_ms;
        self
    }
}

/// Why a value was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Served from cache, within its TTL.
    Fresh,
    /// Served from cache PAST its TTL while it is recomputed.
    Stale,
    /// Computed on this request.
    Miss,
}

impl Freshness {
    /// The `x-rsx-cache` header value.
    pub fn header(&self) -> &'static str {
        match self {
            Freshness::Fresh => "HIT",
            Freshness::Stale => "STALE",
            Freshness::Miss => "MISS",
        }
    }
}

/// A cached value and how it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    /// The bytes.
    pub value: Vec<u8>,
    /// Fresh, stale, or freshly computed.
    pub freshness: Freshness,
    /// The tags this value was stored under.
    pub tags: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(crate = "ferrite_app::serde")]
struct Entry {
    value: Vec<u8>,
    tags: Vec<String>,
    /// The tag generations observed when this value was computed,
    /// parallel to `tags`.
    generations: Vec<i64>,
    created_ms: u64,
    fresh_until_ms: u64,
    expires_ms: u64,
}

/// A held recomputation lease.
///
/// The VERSION is the proof of ownership: releasing is a
/// version-conditional write, so a caller can only ever release the
/// lease it actually acquired.
#[derive(Debug, Clone, Copy)]
struct Lease {
    version: u64,
}

/// The cache, over an application's `cache` store binding.
pub struct Cache {
    store: StoreClusterClient,
    now_ms: u64,
}


/// A value that tells one lease holder's write from another's in a store dump.
///
/// The lease's authority is the CAS VERSION the create returns, never this
/// value, so it needs to be distinct and nothing more. The SDK exports no
/// random function and the code gate refuses every other source, so the bytes
/// come from the one route the SDK has to the operating system's generator:
/// a freshly generated signing key, hashed and dropped.
fn lease_token() -> String {
    let document = crypto::Ed25519SigningKey::generate_pkcs8();
    crypto::hex(&crypto::sha256(&document)[..8])
}

impl Cache {
    /// A cache over `store`, reading time from `now_ms`.
    pub fn new(store: StoreClusterClient, now_ms: u64) -> Self {
        Self { store, now_ms }
    }

    /// The current generation of `tag`.
    ///
    /// `add(_, 0)` both reads and creates: a tag nobody has bumped is
    /// generation 0 rather than an error, so a first read never has to
    /// special-case absence.
    pub async fn generation(&mut self, tag: &str) -> io::Result<i64> {
        let (value, _) = self.store.add(&tag_key(tag), 0).await?;
        Ok(value)
    }

    /// The tag a cached render carries for its own URL.
    ///
    /// Every cached page is tagged with the concrete path it rendered,
    /// so one page can be revalidated without knowing which content
    /// tags it happened to read — and without invalidating its
    /// siblings, which a route-pattern tag would.
    pub fn path_tag(path: &str) -> String {
        format!("route:{path}")
    }

    /// Invalidate the cached render of one URL.
    pub async fn revalidate_path(&mut self, path: &str) -> io::Result<i64> {
        let tag = Self::path_tag(path);
        self.update_tag(&tag).await
    }

    /// Invalidate every entry that read `tag`, atomically and without a
    /// scan.
    pub async fn update_tag(&mut self, tag: &str) -> io::Result<i64> {
        let (value, _) = self.store.add(&tag_key(tag), 1).await?;
        Ok(value)
    }

    /// Invalidate several tags.
    pub async fn update_tags(&mut self, tags: &[String]) -> io::Result<()> {
        for tag in tags {
            self.update_tag(tag).await?;
        }
        Ok(())
    }

    async fn generations(&mut self, tags: &[String]) -> io::Result<Vec<i64>> {
        let mut out = Vec::with_capacity(tags.len());
        for tag in tags {
            out.push(self.generation(tag).await?);
        }
        Ok(out)
    }

    async fn read_entry(&mut self, key: &str) -> io::Result<Option<Entry>> {
        let Some(bytes) = self.store.get(&entry_key(key)).await? else {
            return Ok(None);
        };
        // A malformed entry is a cache problem, never a serving problem:
        // treat it as absent and let it be recomputed.
        Ok(serde_json::from_slice::<Entry>(&bytes).ok())
    }

    /// Read a cached value without computing anything.
    pub async fn peek(&mut self, key: &str) -> io::Result<Option<Cached>> {
        let Some(entry) = self.read_entry(key).await? else {
            return Ok(None);
        };
        let current = self.generations(&entry.tags).await?;
        if current != entry.generations || self.now_ms >= entry.expires_ms {
            return Ok(None);
        }
        let freshness = if self.now_ms < entry.fresh_until_ms {
            Freshness::Fresh
        } else {
            Freshness::Stale
        };
        Ok(Some(Cached {
            value: entry.value,
            freshness,
            tags: entry.tags,
        }))
    }

    /// Drop a cached entry.
    pub async fn forget(&mut self, key: &str) -> io::Result<()> {
        self.store.delete(&entry_key(key)).await?;
        Ok(())
    }

    /// Try to become the one caller that recomputes `key`.
    ///
    /// The lease is a CAS create with a TTL: exactly one caller can win
    /// it, and a holder that dies has it expire out from under it
    /// rather than wedging the key forever.
    async fn acquire_lease(&mut self, key: &str) -> io::Result<Option<Lease>> {
        let token = lease_token();
        let outcome = self
            .store
            .put_if_version_expiring(
                &lease_key(key),
                token.as_bytes(),
                None,
                self.now_ms.saturating_add(LEASE_MS),
            )
            .await?;
        Ok(outcome.ok().map(|version| Lease { version }))
    }

    /// Release a lease ATOMICALLY.
    ///
    /// There is no conditional delete on the store plane, so releasing
    /// is a version-conditional write that collapses the lease's expiry
    /// to the present instant — the key becomes observably absent, and
    /// the CAS means only the holder's version can do it. A
    /// compare-then-delete would look equivalent and is not: between the
    /// read and the delete, the lease can expire and be re-acquired, and
    /// the delete would then remove a SUCCESSOR'S lease and re-open the
    /// stampede this whole mechanism exists to prevent.
    ///
    /// A failed CAS means the lease was already gone (it expired, or the
    /// clock moved past it), which needs no action.
    async fn release_lease(&mut self, key: &str, lease: Lease) -> io::Result<()> {
        let _ = self
            .store
            // An expiry of 0 means "never" on the Store plane: a clock at 0 must still expire it.
            .put_if_version_expiring(&lease_key(key), b"", Some(lease.version), self.now_ms.max(1))
            .await?;
        Ok(())
    }

    async fn write_entry(
        &mut self,
        key: &str,
        value: &[u8],
        profile: &CacheProfile,
        generations: Vec<i64>,
    ) -> io::Result<()> {
        let entry = Entry {
            value: value.to_vec(),
            tags: profile.tags.clone(),
            generations,
            created_ms: self.now_ms,
            fresh_until_ms: self.now_ms.saturating_add(profile.ttl_ms),
            expires_ms: self.now_ms.saturating_add(profile.ttl_ms).saturating_add(profile.swr_ms),
        };
        let bytes = serde_json::to_vec(&entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // The entry carries its own expiry, so a forgotten key reclaims
        // itself instead of accumulating forever.
        self.store
            .put_expiring(&entry_key(key), &bytes, entry.expires_ms)
            .await?;
        Ok(())
    }

    /// Serve `key` from cache, computing it only when necessary.
    ///
    /// A fresh entry is returned as is. A STALE entry is returned
    /// immediately to every caller except the one that wins the
    /// recomputation lease — that caller recomputes and returns the new
    /// value. A missing or invalidated entry is computed by the lease
    /// winner while the others wait briefly for it, and compute it
    /// themselves only if the winner does not produce a value in time.
    /// Correctness never depends on that wait: computing twice is
    /// wasteful, not wrong.
    pub async fn get_or_compute<F, Fut>(
        &mut self,
        key: &str,
        profile: &CacheProfile,
        compute: F,
    ) -> io::Result<Cached>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<Vec<u8>>>,
    {
        if profile.tags.len() > MAX_TAGS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a cache entry may carry at most {MAX_TAGS} tags, got {}",
                    profile.tags.len()
                ),
            ));
        }

        let existing = self.read_entry(key).await?;
        // Ownership of the recomputation lease, tracked SEPARATELY from
        // the decision to compute: a caller that gives up waiting will
        // compute (wasteful, not wrong) but must never release a lease
        // it does not hold.
        let mut lease: Option<Lease> = None;

        if let Some(entry) = &existing {
            let current = self.generations(&entry.tags).await?;
            let valid = current == entry.generations;
            if valid && self.now_ms < entry.fresh_until_ms {
                return Ok(Cached {
                    value: entry.value.clone(),
                    freshness: Freshness::Fresh,
                    tags: entry.tags.clone(),
                });
            }
            // Stale but still servable: only the lease winner pays for
            // the recomputation, everyone else is answered immediately.
            if valid && self.now_ms < entry.expires_ms {
                lease = self.acquire_lease(key).await?;
                if lease.is_none() {
                    return Ok(Cached {
                        value: entry.value.clone(),
                        freshness: Freshness::Stale,
                        tags: entry.tags.clone(),
                    });
                }
            }
        }

        // A miss, or an expired/invalidated entry: elect ONE computer.
        // This applies whether or not a (useless) entry exists — an
        // expired key is exactly when a stampede would form.
        if lease.is_none() {
            lease = self.acquire_lease(key).await?;
            if lease.is_none() {
                for _ in 0..(LOSER_WAIT_MS / LOSER_POLL_MS) {
                    ferrite_app::sleep_ms(LOSER_POLL_MS).await;
                    if let Some(cached) = self.peek(key).await? {
                        return Ok(cached);
                    }
                }
                // The winner is slow or gone. Computing here without the
                // lease is worse than a cache hit and better than
                // failing the request.
            }
        }

        // Generations are read BEFORE computing, so a tag bumped during
        // the computation leaves the new entry immediately invalid
        // rather than pinning a value that predates the write.
        let generations = self.generations(&profile.tags).await?;
        let computed = compute().await;
        // The entry is published BEFORE the lease is released, so a
        // waiter cannot acquire in the gap and recompute what was just
        // produced.
        let outcome = match computed {
            Ok(value) => match self.write_entry(key, &value, profile, generations).await {
                Ok(()) => Ok(value),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        if let Some(held) = lease {
            let _ = self.release_lease(key, held).await;
        }
        let value = outcome?;
        Ok(Cached {
            value,
            freshness: Freshness::Miss,
            tags: profile.tags.clone(),
        })
    }
}
