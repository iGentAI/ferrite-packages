//! The **tag-epoch table**: cache invalidation that costs the same whether a
//! tag covers one entry or ten million.
//!
//! # The idea
//!
//! Never invalidate entries. Invalidate the *tag*.
//!
//! ```text
//! APE   tagv/@ver      -> u64   the epoch-table version (the single guard key)
//! APE   tagv/{tag}     -> u64   one epoch per tag
//! ```
//!
//! A cache entry records the epochs it observed when it was written (its
//! *witness*). A read re-reads those epochs in one bounded `multi_get`; any
//! mismatch means the entry is logically dead. Advancing a tag is therefore
//! one write, regardless of how many entries carry it.
//!
//! # Why the version key exists
//!
//! `ApeClusterClient::commit_n_if` guards exactly ONE key against one
//! expected value and then writes an entry list atomically. It is not a
//! multi-key compare-and-set, and APE has no increment operation. So bumping
//! N tags atomically is a guarded read-modify-write: read the version, read
//! the tags, and commit the bumped version together with every bumped tag in
//! one envelope guarded on the version. A concurrent advance moves the
//! version, the guard mismatches, and the loser retries against fresh state —
//! so no advance can lose another's tags.
//!
//! The cost is one extra read per advance and a serialization point on the
//! version key. The property that matters survives: **advancing a tag is O(1)
//! in the number of entries carrying it.**

use ferrite_app::client::ApeClusterClient;

use crate::alloy::error::{AlloyError, Result};

/// A generated contract's `tag_is_declared(action, tag)`.
pub type TagDeclared = fn(&str, &str) -> bool;

/// Refuse a tag this action's contract does not declare.
pub fn check_declared<T: AsRef<str>>(is_declared: TagDeclared, action: &str, tags: &[T]) -> Result<()> {
    for tag in tags {
        let tag = tag.as_ref();
        if !is_declared(action, tag) {
            return Err(AlloyError::internal(format!(
                "action '{action}' advanced undeclared tag '{tag}'"
            )));
        }
    }
    Ok(())
}

/// The guard key every advance serializes on.
///
/// It lives OUTSIDE the `tagv/t/` namespace user tags are written to, so no
/// tag name — including the literal `@ver` — can collide with it. A
/// collision would be silent and severe: the colliding tag's epoch and the
/// table version would be the same cell, and an advance naming that tag
/// would place two entries with the same key in one envelope.
pub const VERSION_KEY: &str = "tagv/@ver";

/// The namespace every user tag's epoch lives under.
pub const TAG_PREFIX: &str = "tagv/t/";

/// The most tags one advance may carry.
///
/// An APE envelope holds at most 64 entries and the version guard occupies
/// one of them, so 63 remain for tags.
pub const MAX_TAGS_PER_ADVANCE: usize = 63;

/// How many times a guarded advance retries before reporting a conflict.
const MAX_ADVANCE_ATTEMPTS: u32 = 8;

/// The key an epoch lives under.
///
/// Every user tag is namespaced under [`TAG_PREFIX`], which is disjoint from
/// [`VERSION_KEY`] — so a tag may be named anything at all, `@ver` included,
/// without touching the guard.
pub fn tag_key(tag: &str) -> String {
    format!("{TAG_PREFIX}{tag}")
}

/// Decode an epoch. An absent or malformed value reads as epoch 0, which is
/// the same verdict a witness comparison would reach anyway: a reader that
/// recorded a real epoch sees a mismatch and treats its entry as dead.
pub fn decode_epoch(bytes: Option<&Vec<u8>>) -> u64 {
    bytes
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map_or(0, u64::from_be_bytes)
}

/// Encode an epoch as 8 big-endian bytes, so ordering is byte-comparable.
pub fn encode_epoch(epoch: u64) -> Vec<u8> {
    epoch.to_be_bytes().to_vec()
}

/// The tag-epoch table over an injected APE handle.
pub struct TagStore {
    ape: ApeClusterClient,
}

impl TagStore {
    /// Wrap an injected APE client.
    pub fn new(ape: ApeClusterClient) -> Self {
        Self { ape }
    }

    /// The current epochs for `tags`, in the order given.
    ///
    /// This is the read a cached entry's witness is validated against, so it
    /// is one bounded `multi_get` rather than one read per tag.
    pub async fn epochs(&mut self, tags: &[String]) -> Result<Vec<u64>> {
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        if tags.len() > MAX_TAGS_PER_ADVANCE {
            return Err(AlloyError::bad_request(format!(
                "a witness carries at most {MAX_TAGS_PER_ADVANCE} tags (got {})",
                tags.len()
            )));
        }
        let keys: Vec<String> = tags.iter().map(|t| tag_key(t)).collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
        let got = self.ape.multi_get(&refs).await?;
        Ok(got.iter().map(|v| decode_epoch(v.as_ref())).collect())
    }

    /// Advance every tag in `tags` by one, atomically.
    ///
    /// Returns the new epoch of each tag, in the order given and with one
    /// entry per tag NAMED — a tag named twice is bumped once and reported
    /// twice — so a caller can zip the result against its own list. That is
    /// what an action reply carries back to the client so it can invalidate
    /// exactly the affected queries with no extra round trip.
    ///
    /// `extra` rides the SAME envelope: an action passes its idempotency
    /// marker (and any APE-local effect) here so the effect and the epoch
    /// bumps commit together or not at all. A crash between them would
    /// otherwise leave changed data visible under unchanged epochs — a
    /// silent, unbounded staleness window.
    pub async fn advance_with(
        &mut self,
        tags: &[String],
        extra: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Vec<u64>> {
        if tags.is_empty() && extra.is_empty() {
            return Ok(Vec::new());
        }
        // Deduplicate while preserving the caller's order, so the same tag
        // named twice cannot consume two envelope slots or be bumped twice.
        let mut unique: Vec<String> = Vec::with_capacity(tags.len());
        for t in tags {
            if !unique.contains(t) {
                unique.push(t.clone());
            }
        }
        if unique.len() + extra.len() > MAX_TAGS_PER_ADVANCE {
            return Err(AlloyError::bad_request(format!(
                "one advance commits at most {MAX_TAGS_PER_ADVANCE} entries beside the version guard (got {} tags and {} effect entries)",
                unique.len(),
                extra.len()
            )));
        }

        let tag_keys: Vec<String> = unique.iter().map(|t| tag_key(t)).collect();
        validate_extra_keys(&tag_keys, extra)?;
        for _ in 0..MAX_ADVANCE_ATTEMPTS {
            let version = self.ape.get(VERSION_KEY.as_bytes()).await?;
            let current = if tag_keys.is_empty() {
                Vec::new()
            } else {
                let refs: Vec<&[u8]> = tag_keys.iter().map(|k| k.as_bytes()).collect();
                self.ape.multi_get(&refs).await?
            };

            // One value per key, or nothing is committed: zipping a short
            // read against the keys below would silently bump fewer tags
            // than were asked for while reporting success.
            if current.len() != tag_keys.len() {
                return Err(AlloyError::conflict(format!(
                    "the tag-epoch read returned {} values for {} tags; nothing was advanced",
                    current.len(),
                    tag_keys.len()
                )));
            }
            let next_version = encode_epoch(decode_epoch(version.as_ref()).wrapping_add(1));
            let next_epochs: Vec<u64> = current
                .iter()
                .map(|v| decode_epoch(v.as_ref()).wrapping_add(1))
                .collect();
            let encoded: Vec<Vec<u8>> = next_epochs.iter().map(|e| encode_epoch(*e)).collect();

            let mut entries: Vec<(&[u8], &[u8])> =
                Vec::with_capacity(1 + tag_keys.len() + extra.len());
            entries.push((VERSION_KEY.as_bytes(), next_version.as_slice()));
            for (k, v) in tag_keys.iter().zip(encoded.iter()) {
                entries.push((k.as_bytes(), v.as_slice()));
            }
            for (k, v) in extra {
                entries.push((k.as_slice(), v.as_slice()));
            }

            let committed = self
                .ape
                .commit_n_if(VERSION_KEY.as_bytes(), version.as_deref(), &entries)
                .await?;
            if committed.is_ok() {
                return Ok(in_caller_order(tags, &unique, &next_epochs));
            }
            // Another advance moved the version between the read and the
            // commit. Nothing was written; re-read and retry.
        }
        Err(AlloyError::conflict(
            "the tag-epoch table is under sustained contention; retry the request",
        ))
    }

    /// Advance tags with no additional entries.
    pub async fn advance(&mut self, tags: &[String]) -> Result<Vec<u64>> {
        self.advance_with(tags, &[]).await
    }

    /// Read one tag's epoch.
    pub async fn epoch(&mut self, tag: &str) -> Result<u64> {
        Ok(self
            .epochs(core::slice::from_ref(&tag.to_string()))
            .await?
            .first()
            .copied()
            .unwrap_or(0))
    }

    /// The underlying handle, for an action that must commit its own APE
    /// effect in the same envelope through [`advance_with`](Self::advance_with).
    pub fn ape_mut(&mut self) -> &mut ApeClusterClient {
        &mut self.ape
    }
}

/// Spread the epochs of the deduplicated `unique` tags back over the caller's
/// `tags`, so the result lines up with the list the caller passed, entry for
/// entry. Returning the deduplicated vector instead would pair a repeated
/// tag's second mention with the NEXT tag's epoch and drop the last tag from
/// the client's invalidation set.
fn in_caller_order(tags: &[String], unique: &[String], epochs: &[u64]) -> Vec<u64> {
    tags.iter()
        .filter_map(|t| {
            unique
                .iter()
                .position(|u| u == t)
                .and_then(|i| epochs.get(i).copied())
        })
        .collect()
}

fn validate_extra_keys(tag_keys: &[String], extra: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    let mut seen: Vec<&[u8]> = Vec::with_capacity(1 + tag_keys.len() + extra.len());
    seen.push(VERSION_KEY.as_bytes());
    for k in tag_keys {
        seen.push(k.as_bytes());
    }
    for (k, _) in extra {
        if k.is_empty() {
            return Err(AlloyError::bad_request(
                "an extra advance entry has an empty key",
            ));
        }
        if seen.contains(&k.as_slice()) {
            return Err(AlloyError::bad_request(
                "an extra advance entry collides with the version guard, a tag key, or another extra entry",
            ));
        }
        seen.push(k.as_slice());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_round_trip_through_their_encoding() {
        for e in [0u64, 1, 255, 256, u64::MAX] {
            let bytes = encode_epoch(e);
            assert_eq!(bytes.len(), 8);
            assert_eq!(decode_epoch(Some(&bytes)), e);
        }
    }

    #[test]
    fn an_absent_or_malformed_epoch_reads_as_zero() {
        assert_eq!(decode_epoch(None), 0);
        assert_eq!(decode_epoch(Some(&vec![1, 2, 3])), 0);
        assert_eq!(decode_epoch(Some(&Vec::new())), 0);
    }

    #[test]
    fn epochs_are_byte_comparable_in_order() {
        // Big-endian encoding is what lets a byte comparison order epochs,
        // which a value-guarded CAS relies on.
        assert!(encode_epoch(1) < encode_epoch(2));
        assert!(encode_epoch(255) < encode_epoch(256));
        assert!(encode_epoch(u64::MAX - 1) < encode_epoch(u64::MAX));
    }

    #[test]
    fn tag_keys_are_namespaced() {
        assert_eq!(tag_key("drops"), "tagv/t/drops");
        assert_eq!(tag_key("drop-42"), "tagv/t/drop-42");
    }

    #[test]
    fn no_tag_name_can_collide_with_the_version_guard() {
        // The guard is the serialization point for every advance. If a tag
        // could land on it, advancing that tag would write two entries with
        // the same key into one envelope AND conflate its epoch with the
        // table version. The namespaces are disjoint, so it cannot.
        for hostile in ["@ver", "/@ver", "..%2F@ver", "", "t/@ver"] {
            assert_ne!(
                tag_key(hostile),
                VERSION_KEY,
                "tag '{hostile}' collided with the version guard"
            );
        }
        assert!(!VERSION_KEY.starts_with(TAG_PREFIX));
    }

    #[test]
    fn advanced_epochs_line_up_with_the_callers_list_even_when_a_tag_repeats() {
        // F472: `advance(&["a", "a", "b"])` bumps two tags, but the caller
        // zips the reply against the three names it passed. The second "a"
        // must carry a's epoch and "b" must still be there.
        let tags: Vec<String> = ["a", "a", "b"].iter().map(|t| t.to_string()).collect();
        let unique: Vec<String> = ["a", "b"].iter().map(|t| t.to_string()).collect();
        let got = in_caller_order(&tags, &unique, &[7, 3]);
        assert_eq!(got, vec![7, 7, 3]);
        let paired: Vec<(&String, u64)> = tags.iter().zip(got.iter().copied()).collect();
        assert!(
            paired.contains(&(&"b".to_string(), 3)),
            "b was dropped from the invalidation set"
        );

        // Without repeats the result is the epochs, unchanged.
        assert_eq!(in_caller_order(&unique, &unique, &[7, 3]), vec![7, 3]);
    }

    #[test]
    fn the_envelope_bound_leaves_room_for_the_guard() {
        // An APE envelope holds 64 entries; the guard takes one.
        assert_eq!(MAX_TAGS_PER_ADVANCE, 63);
    }

    #[test]
    fn extra_entries_cannot_collide_with_guard_tags_or_each_other() {
        let tags = vec![tag_key("drops")];
        assert!(validate_extra_keys(&tags, &[(VERSION_KEY.as_bytes().to_vec(), vec![1])]).is_err());
        assert!(validate_extra_keys(&tags, &[(tag_key("drops").into_bytes(), vec![1])]).is_err());
        assert!(
            validate_extra_keys(
                &tags,
                &[
                    (b"row/1".to_vec(), vec![1]),
                    (b"row/1".to_vec(), vec![2]),
                ]
            )
            .is_err()
        );
        assert!(validate_extra_keys(&tags, &[(Vec::new(), vec![1])]).is_err());
        assert!(validate_extra_keys(&tags, &[(b"row/1".to_vec(), vec![1])]).is_ok());
    }
}
