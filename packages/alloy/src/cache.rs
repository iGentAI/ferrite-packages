//! Cache envelopes, the three freshness windows, and the in-process L1.
//!
//! # Three windows over one hard TTL
//!
//! The store offers a single expiry instant, and it is a hard cliff: the
//! moment it passes the key is absent on every read surface. Next.js's cache
//! model needs three windows — fresh, stale-while-revalidate, and expired —
//! so Alloy maps only the LAST onto the store's TTL and carries the other two
//! as envelope metadata evaluated at read time.
//!
//! That split is deliberate and it is the safe direction: a buggy reader
//! cannot serve an expired entry, because storage has already made it
//! absent, and the sweeper reclaims it with no janitor to write.
//!
//! # The witness
//!
//! An envelope records the tag epochs it observed when it was written. A read
//! re-reads those epochs in one bounded `multi_get` ([`crate::alloy::tags`])
//! and any mismatch means the entry is logically dead — however many entries
//! share that tag. This is what makes invalidation O(1) in entry count.

use std::collections::HashMap;

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};

const SECOND: u64 = 1_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
const YEAR: u64 = 365 * DAY;

/// The seven cache profiles, with Next.js's own windows.
///
/// Each profile names three offsets from the moment of the write: when the
/// entry goes stale (still servable, triggers a refresh), when a scheduled
/// revalidation should fire, and when it expires (hard, enforced by storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "snake_case")]
pub enum CacheLife {
    /// Sub-minute freshness: stale at 1s, revalidate at 1s, expire at 1m.
    Seconds,
    /// The common default for user-visible data.
    Minutes,
    /// Slow-moving content.
    Hours,
    /// Daily content.
    Days,
    /// Weekly content.
    Weeks,
    /// Effectively immutable until explicitly invalidated.
    Max,
    /// An explicit window, in milliseconds from the write.
    Custom {
        /// When the entry becomes stale-but-servable.
        stale_ms: u64,
        /// When a scheduled revalidation should fire.
        revalidate_ms: u64,
        /// When the entry must be gone.
        expire_ms: u64,
    },
}

impl Default for CacheLife {
    fn default() -> Self {
        Self::Minutes
    }
}

impl CacheLife {
    /// Whether this profile's windows are ordered `stale <= expire`.
    ///
    /// Only [`CacheLife::Custom`] can violate it, because the named profiles
    /// are constants checked below. The ordering is not cosmetic: the store
    /// TTL is set from `expire` ALONE, so an entry whose `expire` precedes
    /// its `stale` is made absent by storage before it ever becomes
    /// stale-but-servable. Stale-while-revalidate silently stops existing —
    /// every read that would have been served instantly from a stale body
    /// becomes a blocking recompute, and nothing anywhere reports it.
    ///
    /// `revalidate` is deliberately NOT constrained. It is a scheduling hint
    /// for when a refresh should fire, and firing it before or after the
    /// stale point are both coherent choices.
    pub fn is_ordered(&self) -> bool {
        let (stale, _revalidate, expire) = self.windows();
        stale <= expire
    }

    /// The profile, or an error naming why it cannot be served.
    ///
    /// Construction cannot be refused — `Custom` is a plain enum variant an
    /// author writes directly — so this is the check a caller applies before
    /// handing a profile to the cache.
    pub fn validate(&self) -> Result<()> {
        if self.is_ordered() {
            return Ok(());
        }
        let (stale, revalidate, expire) = self.windows();
        Err(AlloyError::internal(format!(
            "a cache profile expires at {expire}ms but goes stale at {stale}ms \
             (revalidate {revalidate}ms); storage removes the entry at expiry, so a \
             stale window beyond it can never be served"
        )))
    }

    /// `(stale_ms, revalidate_ms, expire_ms)` offsets from the write.
    pub fn windows(&self) -> (u64, u64, u64) {
        match self {
            CacheLife::Seconds => (SECOND, SECOND, MINUTE),
            CacheLife::Minutes => (5 * MINUTE, MINUTE, HOUR),
            CacheLife::Hours => (HOUR, 15 * MINUTE, DAY),
            CacheLife::Days => (DAY, HOUR, WEEK),
            CacheLife::Weeks => (WEEK, DAY, 30 * DAY),
            CacheLife::Max => (YEAR, YEAR, YEAR),
            CacheLife::Custom {
                stale_ms,
                revalidate_ms,
                expire_ms,
            } => (*stale_ms, *revalidate_ms, *expire_ms),
        }
    }

    /// The profile name, as the generated TypeScript spells it.
    pub fn name(&self) -> &'static str {
        match self {
            CacheLife::Seconds => "seconds",
            CacheLife::Minutes => "minutes",
            CacheLife::Hours => "hours",
            CacheLife::Days => "days",
            CacheLife::Weeks => "weeks",
            CacheLife::Max => "max",
            CacheLife::Custom { .. } => "custom",
        }
    }

    /// Compose two profiles: the shortest window wins.
    ///
    /// A route's payload is only as fresh as its least-fresh part, so when a
    /// loader composes several cached calls the effective life is the
    /// tightest of them.
    pub fn shortest(self, other: CacheLife) -> CacheLife {
        let (a_s, a_r, a_e) = self.windows();
        let (b_s, b_r, b_e) = other.windows();
        let tightest = (a_s.min(b_s), a_r.min(b_r), a_e.min(b_e));
        if (a_s, a_r, a_e) == tightest {
            return self;
        }
        if (b_s, b_r, b_e) == tightest {
            return other;
        }
        CacheLife::Custom {
            stale_ms: tightest.0,
            revalidate_ms: tightest.1,
            expire_ms: tightest.2,
        }
    }

    /// Look up one of Next.js's built-in `cacheLife` profiles by name.
    ///
    /// These are NEXT'S numbers, not the enum variants above: the two tables
    /// serve different masters. The variants are this framework's server-side
    /// freshness policy; the named table is the vocabulary an author brings
    /// from `cacheLife("hours")` in upstream code, and it must mean here what
    /// it means there or ported code silently caches on different windows.
    /// The generated TypeScript resolves the same names, so the lookup being
    /// exact on both sides is part of the contract.
    ///
    /// An unknown name is `None` rather than a default: a typo that fell
    /// back to `Minutes` would be a policy nobody chose, applied silently.
    pub fn named(name: &str) -> Option<CacheLife> {
        let (stale_ms, revalidate_ms, expire_ms) = match name {
            "seconds" => (0, SECOND, MINUTE),
            "minutes" => (5 * MINUTE, MINUTE, HOUR),
            "hours" => (5 * MINUTE, HOUR, DAY),
            "days" => (5 * MINUTE, DAY, WEEK),
            "weeks" => (5 * MINUTE, WEEK, 30 * DAY),
            // Upstream spells "never expire" as INFINITE_CACHE. A literal
            // u64::MAX would overflow the saturating adds into a value that
            // reads as "already expired" under some clocks; a quarter of the
            // range is still ~73 million years, which is the same promise
            // with arithmetic headroom.
            "max" => (5 * MINUTE, 30 * DAY, u64::MAX / 4),
            _ => return None,
        };
        Some(CacheLife::Custom {
            stale_ms,
            revalidate_ms,
            expire_ms,
        })
    }

    /// Look up a profile by name through an app-supplied table first.
    ///
    /// A custom entry WINS over a built-in of the same name, because the app
    /// declaring it is the more specific authority — this is how an app both
    /// extends the vocabulary (`"biweekly"`) and re-tunes a standard word
    /// (`"days"` with a longer stale window) without forking the lookup.
    pub fn profiles_with(name: &str, custom: &[(&str, CacheLife)]) -> Option<CacheLife> {
        custom
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, life)| *life)
            .or_else(|| CacheLife::named(name))
    }
}

/// The tag epochs an entry observed when it was written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct TagWitness {
    /// `(tag, epoch)` pairs, sorted by tag so the encoding is canonical.
    pub entries: Vec<(String, u64)>,
}

impl TagWitness {
    /// Build a witness from tags and the epochs read alongside them.
    ///
    /// Both failure modes here are silent cache-correctness bugs, so both are
    /// refused rather than papered over:
    ///
    /// - **Unequal lengths.** Zipping would truncate to the shorter side, and
    ///   the dropped tags would simply not appear in the witness — so
    ///   advancing one of them would never invalidate this entry. It would
    ///   serve stale content until its TTL expired, with nothing to point at.
    /// - **A duplicate tag carrying different epochs.** Sorting by tag alone
    ///   leaves the surviving epoch to the sort's tie-breaking, so the same
    ///   inputs could yield a witness that validates on one run and
    ///   invalidates on the next. A duplicate naming ONE epoch is harmless
    ///   and is collapsed.
    pub fn new(tags: &[String], epochs: &[u64]) -> Result<Self> {
        if tags.len() != epochs.len() {
            return Err(AlloyError::internal(format!(
                "witness built from {} tags and {} epochs",
                tags.len(),
                epochs.len()
            )));
        }
        let mut entries: Vec<(String, u64)> =
            tags.iter().cloned().zip(epochs.iter().copied()).collect();
        // Sort by tag AND epoch so the ordering is total: equal tags with
        // different epochs become adjacent and detectably distinct.
        entries.sort();
        for pair in entries.windows(2) {
            if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
                return Err(AlloyError::internal(format!(
                    "witness names tag '{}' with conflicting epochs {} and {}",
                    pair[0].0, pair[0].1, pair[1].1
                )));
            }
        }
        entries.dedup();
        Ok(Self { entries })
    }

    /// A caller's tag list in the witness's canonical order: sorted, with
    /// duplicates removed. [`is_valid`](Self::is_valid) compares by position,
    /// so the epochs checked against a witness must be read for exactly this
    /// list. Epochs read in the caller's order would pair one tag's recorded
    /// epoch with another tag's current one whenever the caller's list is not
    /// already sorted, and the entry would read as expired on every request.
    pub fn canonical_tags(tags: &[String]) -> Vec<String> {
        let mut canonical = tags.to_vec();
        canonical.sort();
        canonical.dedup();
        canonical
    }

    /// A witness over no tags: an entry that only ever expires on the clock.
    pub fn untagged() -> Self {
        Self::default()
    }

    /// The tags this witness covers, in canonical order.
    pub fn tags(&self) -> Vec<String> {
        self.entries.iter().map(|(t, _)| t.clone()).collect()
    }

    /// Does this witness cover exactly `tags` (canonical order)? Epochs are
    /// compared by position, so a different tag set of the same size must not
    /// be read against them.
    pub fn covers(&self, tags: &[String]) -> bool {
        self.entries.len() == tags.len() && self.entries.iter().zip(tags).all(|((witnessed, _), tag)| witnessed == tag)
    }

    /// Whether `current` (epochs for [`tags`](Self::tags), same order) still
    /// matches what was observed at write time.
    ///
    /// An epoch that moved BACKWARD also fails: it cannot happen through the
    /// advance protocol, so it means the table was reset or rebuilt, and the
    /// safe reading of an entry written against the old table is "dead".
    pub fn is_valid(&self, current: &[u64]) -> bool {
        if current.len() != self.entries.len() {
            return false;
        }
        self.entries
            .iter()
            .zip(current.iter())
            .all(|((_, observed), now)| observed == now)
    }
}

/// Where an entry's body lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", tag = "at", rename_all = "snake_case")]
pub enum CacheBody {
    /// Small bodies ride the envelope itself.
    Inline {
        /// The payload.
        bytes: Vec<u8>,
    },
    /// Large bodies live in the blob plane under their digest; the envelope
    /// carries the pointer. Because the key IS the digest, a re-write is a
    /// no-op and an orphan is garbage rather than corruption.
    Blob {
        /// The hex SHA-256 that is both the blob key and the ETag.
        digest: String,
        /// The body length, so a reader can budget before fetching.
        len: u64,
    },
}

/// The largest body that rides inline rather than through the blob plane.
pub const MAX_INLINE_BODY: usize = 128 * 1024;

/// One cached value with its freshness windows and its witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct CacheEnvelope {
    /// The cached body.
    pub body: CacheBody,
    /// The tag epochs observed at write time.
    pub witness: TagWitness,
    /// When this entry was written (epoch ms).
    pub created_at_ms: u64,
    /// When it becomes stale-but-servable (epoch ms).
    pub stale_at_ms: u64,
    /// When a scheduled revalidation should fire (epoch ms).
    pub revalidate_at_ms: u64,
    /// When it must be gone (epoch ms) — also the store TTL.
    pub expire_at_ms: u64,
    /// The profile that produced these windows.
    pub life: CacheLife,
}

impl CacheEnvelope {
    /// Build an envelope written at `now_ms` under `life`.
    pub fn new(body: CacheBody, witness: TagWitness, life: CacheLife, now_ms: u64) -> Self {
        let (stale, revalidate, expire) = life.windows();
        Self {
            body,
            witness,
            created_at_ms: now_ms,
            stale_at_ms: now_ms.saturating_add(stale),
            revalidate_at_ms: now_ms.saturating_add(revalidate),
            expire_at_ms: now_ms.saturating_add(expire),
            life,
        }
    }

    /// Encode for the store.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AlloyError::internal(e.to_string()))
    }

    /// Decode from the store. A malformed envelope is treated as a miss by
    /// the caller rather than as a fault: the cache is never the source of
    /// truth, so an unreadable entry costs a recompute, not a request.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// This entry's freshness at `now_ms`, given the CURRENT epochs of its
    /// witnessed tags.
    pub fn freshness(&self, now_ms: u64, current_epochs: &[u64]) -> Freshness {
        if !self.witness.is_valid(current_epochs) {
            return Freshness::Expired;
        }
        if now_ms >= self.expire_at_ms {
            return Freshness::Expired;
        }
        if now_ms >= self.stale_at_ms {
            return Freshness::Stale;
        }
        Freshness::Fresh
    }

    /// The inline bytes, when the body did not go to the blob plane.
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            CacheBody::Inline { bytes } => Some(bytes.as_slice()),
            CacheBody::Blob { .. } => None,
        }
    }
}

/// What a read should do with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Serve it.
    Fresh,
    /// Serve it AND refresh in the background.
    Stale,
    /// Do not serve it.
    Expired,
}

/// The key an entry lives under: `cache/{fn}/{arghash}`.
///
/// The argument hash is a SHA-256 over the serialized arguments, so a key is
/// fixed-width regardless of argument size and cannot collide across
/// functions (the function id is a separate path component, not concatenated
/// into the hashed material).
pub fn cache_key(fn_id: &str, args: &[u8]) -> String {
    let hex = ferrite_app::crypto::hex(&ferrite_app::crypto::sha256(args));
    format!("cache/{fn_id}/{hex}")
}

/// One L1 slot.
#[derive(Debug, Clone)]
struct L1Entry {
    envelope: CacheEnvelope,
    bytes: usize,
    tick: u64,
}

/// The in-process first-level cache: a bounded LRU in front of the store.
///
/// A networked store read costs microseconds to a millisecond; an L1 hit
/// costs a hash lookup. But **correctness never depends on L1**: every hit is
/// still validated against the tag epochs by the caller, so a stale L1 entry
/// is caught by the same witness check that catches a stale store entry.
///
/// Nothing in the platform evicts on memory pressure, so this bound is the
/// framework's own and it is enforced on BYTES as well as entries — an
/// entry-count bound alone lets a few large payloads exhaust a hard
/// `memory.max` cgroup and take the instance with them.
#[derive(Debug)]
pub struct L1Cache {
    entries: HashMap<String, L1Entry>,
    max_entries: usize,
    max_bytes: usize,
    used_bytes: usize,
    tick: u64,
    hits: u64,
    misses: u64,
}

impl L1Cache {
    /// A cache bounded by entry count and total body bytes.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            used_bytes: 0,
            tick: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// A cache with the framework defaults: 1024 entries, 32 MiB.
    pub fn with_defaults() -> Self {
        Self::new(1024, 32 * 1024 * 1024)
    }

    /// Look up an entry, refreshing its recency.
    pub fn get(&mut self, key: &str) -> Option<CacheEnvelope> {
        self.tick += 1;
        let tick = self.tick;
        match self.entries.get_mut(key) {
            Some(e) => {
                e.tick = tick;
                self.hits += 1;
                Some(e.envelope.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Insert an entry, evicting by recency until both bounds hold.
    pub fn put(&mut self, key: impl Into<String>, envelope: CacheEnvelope) {
        let key = key.into();
        let bytes = match &envelope.body {
            CacheBody::Inline { bytes } => bytes.len(),
            CacheBody::Blob { .. } => 128,
        };
        // An entry larger than the whole budget is not cacheable in L1; the
        // store still holds it, so this is a locality loss, not a miss.
        if bytes > self.max_bytes {
            self.remove(&key);
            return;
        }
        self.tick += 1;
        self.remove(&key);
        self.entries.insert(
            key,
            L1Entry {
                envelope,
                bytes,
                tick: self.tick,
            },
        );
        self.used_bytes += bytes;
        self.evict_to_fit();
    }

    /// Drop one entry.
    pub fn remove(&mut self, key: &str) {
        if let Some(old) = self.entries.remove(key) {
            self.used_bytes = self.used_bytes.saturating_sub(old.bytes);
        }
    }

    /// Drop every entry (a topic-tail invalidation that cannot be resolved
    /// precisely falls back to this).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.used_bytes = 0;
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes currently accounted for.
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    /// `(hits, misses)` since construction — what `/__alloy/cache` reports.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    fn evict_to_fit(&mut self) {
        while self.entries.len() > self.max_entries || self.used_bytes > self.max_bytes {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.tick)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.remove(&victim);
        }
    }
}

impl Default for L1Cache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_at(now: u64, life: CacheLife, witness: TagWitness) -> CacheEnvelope {
        CacheEnvelope::new(
            CacheBody::Inline {
                bytes: b"payload".to_vec(),
            },
            witness,
            life,
            now,
        )
    }

    #[test]
    fn the_three_windows_are_ordered_and_relative_to_the_write() {
        let e = env_at(1_000, CacheLife::Minutes, TagWitness::default());
        assert_eq!(e.created_at_ms, 1_000);
        assert_eq!(e.stale_at_ms, 301_000);
        assert_eq!(e.revalidate_at_ms, 61_000);
        assert_eq!(e.expire_at_ms, 3_601_000);
    }

    #[test]
    fn freshness_walks_fresh_then_stale_then_expired() {
        let e = env_at(0, CacheLife::Minutes, TagWitness::default());
        assert_eq!(e.freshness(0, &[]), Freshness::Fresh);
        assert_eq!(e.freshness(e.stale_at_ms - 1, &[]), Freshness::Fresh);
        assert_eq!(e.freshness(e.stale_at_ms, &[]), Freshness::Stale);
        assert_eq!(e.freshness(e.expire_at_ms - 1, &[]), Freshness::Stale);
        assert_eq!(e.freshness(e.expire_at_ms, &[]), Freshness::Expired);
    }

    #[test]
    fn a_moved_tag_epoch_kills_an_otherwise_fresh_entry() {
        let tags = vec!["drops".to_string(), "drop-42".to_string()];
        let witness = TagWitness::new(&tags, &[7, 3]).unwrap();
        let e = env_at(0, CacheLife::Max, witness);
        // Same epochs: fresh even far in the future (Max profile).
        assert_eq!(e.freshness(1_000, &[3, 7]), Freshness::Fresh);
        // 'drops' advanced: dead immediately, however fresh the clock says.
        assert_eq!(e.freshness(1_000, &[3, 8]), Freshness::Expired);
    }

    #[test]
    fn epochs_read_in_canonical_tag_order_validate_an_unsorted_callers_entry() {
        // The call sites cache under a family tag and an instance tag, in
        // that order, which is not sorted: "drop-42" < "drops".
        let caller = vec!["drops".to_string(), "drop-42".to_string()];
        let epoch = |tag: &str| if tag == "drops" { 7 } else { 3 };
        let in_caller_order: Vec<u64> = caller.iter().map(|t| epoch(t)).collect();
        let canonical = TagWitness::canonical_tags(&caller);
        assert_eq!(canonical, vec!["drop-42".to_string(), "drops".to_string()]);
        let in_canonical_order: Vec<u64> = canonical.iter().map(|t| epoch(t)).collect();

        let e = env_at(
            0,
            CacheLife::Max,
            TagWitness::new(&canonical, &in_canonical_order).unwrap(),
        );
        // Nothing moved, so the entry is fresh when checked the way the cache
        // store now reads epochs...
        assert_eq!(e.freshness(1_000, &in_canonical_order), Freshness::Fresh);
        // ...and was judged expired, forever, when checked in caller order.
        assert_eq!(e.freshness(1_000, &in_caller_order), Freshness::Expired);

        // A duplicated tag collapses instead of failing the length check.
        let doubled = vec!["b".to_string(), "a".to_string(), "b".to_string()];
        assert_eq!(
            TagWitness::canonical_tags(&doubled),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn a_witness_is_canonical_regardless_of_tag_order() {
        let a = TagWitness::new(&["b".into(), "a".into()], &[2, 1]).unwrap();
        let b = TagWitness::new(&["a".into(), "b".into()], &[1, 2]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.tags(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn a_witness_of_a_different_arity_is_invalid() {
        let w = TagWitness::new(&["a".into()], &[1]).unwrap();
        assert!(!w.is_valid(&[]));
        assert!(!w.is_valid(&[1, 1]));
        assert!(w.is_valid(&[1]));
    }

    #[test]
    fn a_witness_refuses_mismatched_tags_and_epochs() {
        // Truncating here would drop a tag from the witness, so advancing
        // that tag would never invalidate the entry.
        assert!(TagWitness::new(&["a".into(), "b".into()], &[1]).is_err());
        assert!(TagWitness::new(&["a".into()], &[1, 2]).is_err());
        assert!(TagWitness::new(&[], &[1]).is_err());
        assert!(TagWitness::new(&[], &[]).is_ok());
    }

    #[test]
    fn a_witness_refuses_a_tag_named_twice_with_different_epochs() {
        let conflicting = TagWitness::new(&["a".into(), "a".into()], &[1, 2]);
        assert!(
            conflicting.is_err(),
            "a conflicting duplicate must not resolve by sort order"
        );
        // The same tag naming the same epoch is redundant, not ambiguous.
        let benign = TagWitness::new(&["a".into(), "a".into()], &[1, 1]).unwrap();
        assert_eq!(benign.entries.len(), 1);
        assert!(benign.is_valid(&[1]));
    }

    #[test]
    fn envelopes_round_trip_through_their_encoding() {
        let e = env_at(
            5,
            CacheLife::Hours,
            TagWitness::new(&["t".into()], &[9]).unwrap(),
        );
        let bytes = e.encode().unwrap();
        assert_eq!(CacheEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn a_corrupt_envelope_decodes_to_none_rather_than_panicking() {
        assert!(CacheEnvelope::decode(b"not json").is_none());
        assert!(CacheEnvelope::decode(b"{}").is_none());
        assert!(CacheEnvelope::decode(&[]).is_none());
    }

    #[test]
    fn cache_keys_separate_functions_from_arguments() {
        let a = cache_key("get_drop", b"42");
        let b = cache_key("get_drop", b"43");
        let c = cache_key("get_user", b"42");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, cache_key("get_drop", b"42"));
        assert!(a.starts_with("cache/get_drop/"));
        // Fixed width regardless of argument size.
        assert_eq!(
            cache_key("f", &vec![0u8; 1_000_000]).len(),
            cache_key("f", b"").len()
        );
    }

    #[test]
    fn shortest_life_wins_when_profiles_compose() {
        assert_eq!(
            CacheLife::Minutes.shortest(CacheLife::Days),
            CacheLife::Minutes
        );
        assert_eq!(
            CacheLife::Days.shortest(CacheLife::Minutes),
            CacheLife::Minutes
        );
        assert_eq!(
            CacheLife::Max.shortest(CacheLife::Seconds),
            CacheLife::Seconds
        );
    }

    #[test]
    fn the_named_profiles_carry_exactly_nexts_windows() {
        // These are Next's cacheLife numbers, verbatim. An author porting
        // `cacheLife("hours")` must get the SAME windows here that the word
        // means upstream, or ported code caches on a policy nobody wrote.
        const SECOND: u64 = 1_000;
        const MINUTE: u64 = 60 * SECOND;
        const HOUR: u64 = 60 * MINUTE;
        const DAY: u64 = 24 * HOUR;
        const WEEK: u64 = 7 * DAY;
        let expect: &[(&str, (u64, u64, u64))] = &[
            ("seconds", (0, SECOND, MINUTE)),
            ("minutes", (5 * MINUTE, MINUTE, HOUR)),
            ("hours", (5 * MINUTE, HOUR, DAY)),
            ("days", (5 * MINUTE, DAY, WEEK)),
            ("weeks", (5 * MINUTE, WEEK, 30 * DAY)),
            ("max", (5 * MINUTE, 30 * DAY, u64::MAX / 4)),
        ];
        for (name, windows) in expect {
            let life =
                CacheLife::named(name).unwrap_or_else(|| panic!("'{name}' is a built-in profile"));
            assert_eq!(
                life.windows(),
                *windows,
                "'{name}' drifted from Next's table"
            );
            // Every named profile must survive the ordering check the cache
            // applies to every read, or the name would be unusable.
            assert!(life.validate().is_ok(), "'{name}' fails validation");
        }
    }

    #[test]
    fn an_unknown_profile_name_is_none_rather_than_a_default() {
        // A typo that fell back to some default would be a caching policy
        // nobody chose, applied with no symptom. None forces the caller to
        // decide.
        for unknown in ["hour", "Seconds", "MAX", "", "5m"] {
            assert!(
                CacheLife::named(unknown).is_none(),
                "'{unknown}' resolved to a profile"
            );
        }
    }

    #[test]
    fn a_custom_profile_extends_and_overrides_the_built_in_table() {
        let biweekly = CacheLife::Custom {
            stale_ms: 1,
            revalidate_ms: 2,
            expire_ms: 3,
        };
        let retuned_days = CacheLife::Hours;
        let custom: &[(&str, CacheLife)] = &[("biweekly", biweekly), ("days", retuned_days)];

        // An app-declared name is reachable…
        assert_eq!(CacheLife::profiles_with("biweekly", custom), Some(biweekly));
        // …a custom entry WINS over the built-in of the same name…
        assert_eq!(CacheLife::profiles_with("days", custom), Some(retuned_days));
        // …the untouched built-ins still resolve through the same lookup…
        assert_eq!(
            CacheLife::profiles_with("hours", custom),
            CacheLife::named("hours")
        );
        // …and an unknown name is still nobody's default.
        assert!(CacheLife::profiles_with("nope", custom).is_none());
        assert!(CacheLife::profiles_with("biweekly", &[]).is_none());
    }

    #[test]
    fn a_custom_profile_that_expires_before_it_goes_stale_is_refused() {
        // The store TTL comes from `expire` ALONE, so this entry is absent
        // from storage a full minute before it would have become
        // stale-but-servable. The stale window is unreachable, and the
        // failure is invisible: reads still succeed, they are merely never
        // served from the stale path again.
        let inverted = CacheLife::Custom {
            stale_ms: 60_000,
            revalidate_ms: 30_000,
            expire_ms: 1_000,
        };
        assert!(!inverted.is_ordered());
        let err = inverted.validate().expect_err("must be refused");
        assert_eq!(err.status(), 500);

        // The same three numbers in a coherent order are accepted.
        let ordered = CacheLife::Custom {
            stale_ms: 1_000,
            revalidate_ms: 30_000,
            expire_ms: 60_000,
        };
        assert!(ordered.is_ordered());
        assert!(ordered.validate().is_ok());
    }

    #[test]
    fn a_revalidation_hint_may_fall_anywhere_in_the_window() {
        // `revalidate` schedules WHEN a refresh should fire and is not part
        // of the ordering contract: firing before the stale point (refresh
        // eagerly) and after it (refresh lazily) are both coherent, so
        // constraining it would reject profiles that are perfectly sound.
        let eager = CacheLife::Custom {
            stale_ms: 30_000,
            revalidate_ms: 1_000,
            expire_ms: 60_000,
        };
        let lazy = CacheLife::Custom {
            stale_ms: 1_000,
            revalidate_ms: 59_000,
            expire_ms: 60_000,
        };
        assert!(eager.validate().is_ok());
        assert!(lazy.validate().is_ok());
    }

    #[test]
    fn composing_two_ordered_profiles_stays_ordered() {
        // `shortest` takes the minimum of each window INDEPENDENTLY, so in
        // principle it could pair one profile's stale with another's expire
        // and invert them. It cannot: the minimum of two ordered pairs is
        // itself ordered, and this pins that across every named profile
        // combination rather than trusting the argument.
        let profiles = [
            CacheLife::Seconds,
            CacheLife::Minutes,
            CacheLife::Hours,
            CacheLife::Days,
            CacheLife::Weeks,
            CacheLife::Max,
        ];
        for a in profiles {
            for b in profiles {
                let composed = a.shortest(b);
                assert!(
                    composed.is_ordered(),
                    "{} composed with {} inverted its windows",
                    a.name(),
                    b.name()
                );
            }
        }
    }

    #[test]
    fn l1_evicts_the_least_recently_used_entry() {
        let mut c = L1Cache::new(2, 1 << 20);
        c.put("a", env_at(0, CacheLife::Minutes, TagWitness::default()));
        c.put("b", env_at(0, CacheLife::Minutes, TagWitness::default()));
        assert!(c.get("a").is_some()); // 'a' is now the most recent
        c.put("c", env_at(0, CacheLife::Minutes, TagWitness::default()));
        assert!(c.get("b").is_none(), "'b' was least recently used");
        assert!(c.get("a").is_some());
        assert!(c.get("c").is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn l1_is_bounded_by_bytes_as_well_as_entries() {
        let mut c = L1Cache::new(1_000, 4_096);
        for i in 0..100 {
            let big = CacheEnvelope::new(
                CacheBody::Inline {
                    bytes: vec![0u8; 1_000],
                },
                TagWitness::default(),
                CacheLife::Minutes,
                0,
            );
            c.put(format!("k{i}"), big);
        }
        assert!(
            c.used_bytes() <= 4_096,
            "byte bound held: {}",
            c.used_bytes()
        );
        assert!(c.len() <= 5);
    }

    #[test]
    fn an_oversized_entry_is_simply_not_cached_in_l1() {
        let mut c = L1Cache::new(10, 1_000);
        c.put(
            "huge",
            CacheEnvelope::new(
                CacheBody::Inline {
                    bytes: vec![0u8; 10_000],
                },
                TagWitness::default(),
                CacheLife::Minutes,
                0,
            ),
        );
        assert!(c.get("huge").is_none());
        assert_eq!(c.used_bytes(), 0);
    }

    #[test]
    fn overwriting_a_key_does_not_double_count_its_bytes() {
        let mut c = L1Cache::new(10, 1 << 20);
        for _ in 0..10 {
            c.put(
                "k",
                CacheEnvelope::new(
                    CacheBody::Inline {
                        bytes: vec![0u8; 100],
                    },
                    TagWitness::default(),
                    CacheLife::Minutes,
                    0,
                ),
            );
        }
        assert_eq!(c.len(), 1);
        assert_eq!(c.used_bytes(), 100);
    }

    #[test]
    fn a_zero_window_profile_is_legal_and_dead_from_its_write_instant() {
        // `Custom { 0, 0, 0 }` satisfies `stale <= expire`, so it is a LEGAL
        // profile rather than a refused one — and it is immediately dead.
        // That combination is worth pinning precisely because it is not a
        // defect: an author writing it has asked for "never cache this", and
        // the honest answer is an entry that is expired at the moment of the
        // write rather than a validation error.
        let never = CacheLife::Custom {
            stale_ms: 0,
            revalidate_ms: 0,
            expire_ms: 0,
        };
        assert!(never.is_ordered());
        assert!(never.validate().is_ok());
        let e = env_at(1_000, never, TagWitness::default());
        assert_eq!(e.freshness(1_000, &[]), Freshness::Expired);
        // Freshness is a comparison against the READ clock, so an instant
        // before the write reads as fresh. That is not a defect to assert
        // away: `now_ms` comes from the injected clock, the same source the
        // write used, and a reader whose clock has gone BACKWARD past the
        // write instant has a clock problem no cache rule can repair. What
        // matters is that the entry is dead at and after its own expiry,
        // which is the case every real read takes.
        assert_eq!(e.freshness(999, &[]), Freshness::Fresh);
        assert_eq!(e.freshness(1_001, &[]), Freshness::Expired);
    }

    #[test]
    fn clearing_the_l1_resets_its_byte_accounting() {
        // `used_bytes` drives eviction. If `clear` emptied the map without
        // zeroing the counter, the cache would believe it was permanently
        // full: every later insert would evict immediately, the hit rate
        // would collapse to zero, and nothing would report a fault — the
        // cache would simply stop working while looking healthy.
        let mut c = L1Cache::new(10, 1 << 20);
        for i in 0..5 {
            c.put(
                format!("k{i}"),
                CacheEnvelope::new(
                    CacheBody::Inline {
                        bytes: vec![0u8; 1_000],
                    },
                    TagWitness::default(),
                    CacheLife::Minutes,
                    0,
                ),
            );
        }
        assert_eq!(c.used_bytes(), 5_000);
        c.clear();
        assert_eq!(c.len(), 0);
        assert_eq!(
            c.used_bytes(),
            0,
            "cleared entries were still accounted for"
        );

        // The cache is usable again, and still bounded.
        c.put(
            "after",
            env_at(0, CacheLife::Minutes, TagWitness::default()),
        );
        assert!(c.get("after").is_some());
    }

    #[test]
    fn removing_an_absent_key_does_not_corrupt_the_byte_count() {
        // `remove` is called on the miss path (a dead L1 entry is dropped
        // before falling through to L2), so it runs against keys that are
        // not present. A saturating subtraction that ran anyway would drift
        // the counter below the truth and disable eviction.
        let mut c = L1Cache::new(10, 1 << 20);
        c.put("a", env_at(0, CacheLife::Minutes, TagWitness::default()));
        let before = c.used_bytes();
        c.remove("never-inserted");
        assert_eq!(c.used_bytes(), before);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn a_blob_backed_entry_is_accounted_for_without_its_payload() {
        // A blob body is a POINTER: the bytes live in the blob plane, so
        // charging L1 for the full length would evict most of the cache to
        // make room for something it is not holding. It is still charged
        // something, because the envelope itself occupies memory.
        let mut c = L1Cache::new(10, 1 << 20);
        c.put(
            "blob",
            CacheEnvelope::new(
                CacheBody::Blob {
                    digest: "d".repeat(64),
                    len: 10 * 1024 * 1024,
                },
                TagWitness::default(),
                CacheLife::Minutes,
                0,
            ),
        );
        assert!(c.get("blob").is_some());
        assert!(
            c.used_bytes() < 1_024,
            "a 10 MiB blob pointer was charged {} bytes",
            c.used_bytes()
        );
    }

    #[test]
    fn l1_reports_hit_and_miss_counts() {
        let mut c = L1Cache::new(4, 1 << 20);
        c.put("a", env_at(0, CacheLife::Minutes, TagWitness::default()));
        let _ = c.get("a");
        let _ = c.get("b");
        assert_eq!(c.stats(), (1, 1));
    }
}
