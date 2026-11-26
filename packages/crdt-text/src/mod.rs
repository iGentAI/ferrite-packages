//! crdt-text — a pure-Rust sequence CRDT for collaborative plain-text / Markdown
//! documents, mountable into a constrained Ferrite app under the one-dependency
//! rule (it names no crate of its own; it uses only `ferrite_app::serde` and
//! `ferrite_app::serde_json`, exactly as the plane clients do).
//!
//! ## What it is
//!
//! A Logoot-style ordered-identifier text CRDT. Each character (Unicode scalar)
//! is stamped, at insert time, with a globally unique, densely orderable
//! position identifier [`Id`]. The document is nothing more than a sorted map
//! from [`Id`] to a cell, so convergence is structural: apply the same set of
//! operations in ANY order and you get the same sorted map, hence the same text.
//!
//! Deletes are tombstones — the cell is retained and flagged, never removed —
//! so a delete that is delivered before the insert it refers to still converges
//! (the tombstone is created first; the later insert fills the character without
//! resurrecting it). Re-applying any operation is a no-op.
//!
//! ## Position identifiers
//!
//! An [`Id`] is a `path` of [`Seg`] pairs `(digit, site)` plus a per-replica
//! `counter`. Ordering is lexicographic over the path (comparing `digit` then
//! `site` at each level, with a proper prefix ordering *before* its extensions),
//! and `counter` breaks ties between two ids a single replica minted for the
//! identical gap. [`alloc_between`] mints a fresh id strictly ordered between two
//! neighbours (or the document ends), descending a level whenever the digit/site
//! space between the neighbours is exhausted — the standard dense-identifier
//! allocation. Because the final segment of every minted id carries the minting
//! replica's `site` (and `counter` disambiguates a replica from itself), no two
//! distinct inserts ever collide, so uniqueness — and therefore convergence —
//! holds regardless of how clients interleave.
//!
//! ## What it is NOT
//!
//! It is a text-*sequence* CRDT at Unicode-scalar granularity. It is deliberately
//! NOT wire-compatible with Yjs / Y.js binary updates, nor with any other
//! external CRDT format: the update and snapshot encodings are this crate's own
//! JSON shapes (see [`Update`], [`Doc::to_snapshot`]). A server owning this CRDT
//! merges, validates, compacts, and renders text for the documents THIS package
//! models; it does not interoperate with a Yjs client.

use std::collections::BTreeMap;

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

/// The per-level digit space. Digits live in `0..BASE`; `BASE` itself is the
/// virtual "end of document" upper bound used only while allocating.
pub const BASE: u32 = 1 << 30;

/// One level of a position identifier: an ordered `(digit, site)` pair. `site`
/// is the id of the replica that minted the level, so concurrent inserts that
/// pick the same digit still order deterministically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Seg {
    pub digit: u32,
    pub site: u64,
}

/// A dense, globally unique, totally ordered position identifier for one
/// character. Ordering is `path` (lexicographic, prefix-before-extension) then
/// `counter`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Id {
    pub path: Vec<Seg>,
    pub counter: u64,
}

impl Id {
    /// A well-formed id has a non-empty path and every digit within `0..BASE`.
    /// The server rejects any update carrying an id that fails this check.
    pub fn is_well_formed(&self) -> bool {
        !self.path.is_empty() && self.path.iter().all(|s| s.digit < BASE)
    }
}

/// One collaborative operation. Externally tagged so the JSON is
/// self-describing and cheaply validated (`{"Insert":{...}}` / `{"Delete":{...}}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum Op {
    /// Place `ch` at position `id`.
    Insert { id: Id, ch: char },
    /// Tombstone the character at `id` (retained, flagged not-visible).
    Delete { id: Id },
}

impl Op {
    fn id(&self) -> &Id {
        match self {
            Op::Insert { id, .. } | Op::Delete { id } => id,
        }
    }
}

/// A batch of operations — the unit a client submits and the relay forwards.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Update {
    pub ops: Vec<Op>,
}

impl Update {
    /// Parse and validate an update off the wire. Fails closed on both
    /// malformed JSON and a structurally invalid id.
    pub fn from_slice(bytes: &[u8]) -> Result<Update, CrdtError> {
        let update: Update =
            serde_json::from_slice(bytes).map_err(|e| CrdtError::Malformed(e.to_string()))?;
        update.validate()?;
        Ok(update)
    }

    /// Parse and validate an update already decoded into a JSON value.
    pub fn from_value(value: serde_json::Value) -> Result<Update, CrdtError> {
        let update: Update =
            serde_json::from_value(value).map_err(|e| CrdtError::Malformed(e.to_string()))?;
        update.validate()?;
        Ok(update)
    }

    /// Well-formedness: every operation must carry a well-formed id.
    pub fn validate(&self) -> Result<(), CrdtError> {
        for op in &self.ops {
            if !op.id().is_well_formed() {
                return Err(CrdtError::InvalidId);
            }
        }
        Ok(())
    }
}

/// Why an update was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrdtError {
    /// Bytes did not decode into the update / snapshot shape.
    Malformed(String),
    /// An operation carried an id with an empty path or an out-of-range digit.
    InvalidId,
}

impl core::fmt::Display for CrdtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CrdtError::Malformed(m) => write!(f, "malformed CRDT payload: {m}"),
            CrdtError::InvalidId => f.write_str("operation carries a malformed position id"),
        }
    }
}

impl std::error::Error for CrdtError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Cell {
    /// The character, once an Insert has been seen for this id.
    ch: Option<char>,
    /// A tombstone flag set by Delete; once set it never clears.
    deleted: bool,
}

/// The serialized, compacted document state persisted to Blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct Snapshot {
    /// Format version, so a future change is detectable rather than silent.
    v: u32,
    cells: Vec<SnapCell>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct SnapCell {
    id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ch: Option<char>,
    #[serde(default, skip_serializing_if = "is_false")]
    deleted: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

const SNAPSHOT_VERSION: u32 = 1;

/// A collaborative text document: a sorted map from position id to cell. The
/// map IS the convergence guarantee — two replicas that have seen the same set
/// of operations hold byte-identical maps regardless of delivery order.
#[derive(Clone, Debug, Default)]
pub struct Doc {
    cells: BTreeMap<Id, Cell>,
}

impl Doc {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one operation. Idempotent, and independent of delivery order:
    /// an Insert never overwrites an existing character and never clears a
    /// tombstone; a Delete only ever sets the tombstone.
    pub fn apply(&mut self, op: &Op) {
        match op {
            Op::Insert { id, ch } => {
                self.cells.entry(id.clone()).or_default().ch.get_or_insert(*ch);
            }
            Op::Delete { id } => {
                self.cells.entry(id.clone()).or_default().deleted = true;
            }
        }
    }

    /// Validate then apply a whole update, returning the number of operations
    /// applied. A malformed update is rejected in full — nothing is applied.
    pub fn apply_update(&mut self, update: &Update) -> Result<usize, CrdtError> {
        update.validate()?;
        for op in &update.ops {
            self.apply(op);
        }
        Ok(update.ops.len())
    }

    /// The visible document text, in position order, tombstones excluded.
    pub fn text(&self) -> String {
        self.cells
            .values()
            .filter_map(|c| if c.deleted { None } else { c.ch })
            .collect()
    }

    /// The number of visible characters.
    pub fn len(&self) -> usize {
        self.cells
            .values()
            .filter(|c| !c.deleted && c.ch.is_some())
            .count()
    }

    /// Whether the visible document is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ids of the visible characters, in position order — the coordinate
    /// space a client edits against.
    pub fn visible_ids(&self) -> Vec<Id> {
        self.cells
            .iter()
            .filter(|(_, c)| !c.deleted && c.ch.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Compact the document to its canonical snapshot bytes (JSON). Cells are
    /// emitted in position order, so the bytes are deterministic for a given
    /// logical state.
    pub fn to_snapshot(&self) -> Vec<u8> {
        let snap = Snapshot {
            v: SNAPSHOT_VERSION,
            cells: self
                .cells
                .iter()
                .map(|(id, c)| SnapCell {
                    id: id.clone(),
                    ch: c.ch,
                    deleted: c.deleted,
                })
                .collect(),
        };
        serde_json::to_vec(&snap).unwrap_or_default()
    }

    /// Rehydrate a document from snapshot bytes previously produced by
    /// [`Doc::to_snapshot`].
    pub fn from_snapshot(bytes: &[u8]) -> Result<Doc, CrdtError> {
        let snap: Snapshot =
            serde_json::from_slice(bytes).map_err(|e| CrdtError::Malformed(e.to_string()))?;
        let mut cells = BTreeMap::new();
        for c in snap.cells {
            if !c.id.is_well_formed() {
                return Err(CrdtError::InvalidId);
            }
            cells.insert(
                c.id,
                Cell {
                    ch: c.ch,
                    deleted: c.deleted,
                },
            );
        }
        Ok(Doc { cells })
    }
}

/// Mint a fresh position id strictly ordered between `lo` and `hi` (either of
/// which may be `None`, meaning the start or the end of the document). The
/// minted id is unique to `(site, counter)`: a replica passes its own id as
/// `site` and a strictly increasing `counter`, so two ids it mints for the same
/// gap never coincide, and two replicas never mint the same id.
///
/// `site` must be non-zero; site `0` is reserved as the below-everything
/// sentinel the allocator uses for an exhausted lower bound.
pub fn alloc_between(lo: Option<&Id>, hi: Option<&Id>, site: u64, counter: u64) -> Id {
    let lo_path: &[Seg] = lo.map(|i| i.path.as_slice()).unwrap_or(&[]);
    let path = match hi {
        Some(hi) => alloc_path(lo_path, &hi.path, site),
        None => alloc_path(lo_path, &[], site),
    };
    Id { path, counter }
}

/// Produce a path `p` with `lo < p < hi` under the [`Seg`] lexicographic order,
/// where an empty `hi` is the open end of the document.
fn alloc_path(lo: &[Seg], hi: &[Seg], site: u64) -> Vec<Seg> {
    let mut out: Vec<Seg> = Vec::new();
    let mut depth = 0usize;
    // Once we descend strictly below `lo` at some level, `hi` no longer bounds
    // the deeper levels (any extension of the chosen prefix is already < hi).
    let mut hi_active = true;
    loop {
        let lseg = lo.get(depth).copied();
        let hseg = hi.get(depth).copied().filter(|_| hi_active);
        let lo_digit = lseg.map(|s| s.digit).unwrap_or(0);
        let hi_digit = hseg.map(|s| s.digit).unwrap_or(BASE);

        if lo_digit + 1 < hi_digit {
            // Room between digits: land in the middle with our own site.
            out.push(Seg {
                digit: lo_digit + (hi_digit - lo_digit) / 2,
                site,
            });
            return out;
        }

        // No digit fits between. `site` is a deterministic TIEBREAKER for equal
        // digits, NOT an allocation axis. Minting a segment with a site DERIVED
        // from the neighbours (their midpoint) would produce an id whose final
        // segment does not carry the minting replica's `site`, so two different
        // replicas bisecting the same gap on the same-numbered insert could mint
        // byte-identical ids and collide (one character is then silently lost).
        // Instead, always adopt lo's segment verbatim and descend a level; a
        // fresh digit stamped with the MINTER's `site` is minted at the level
        // where a digit fits (the digit-room branch above), preserving the
        // module-level uniqueness invariant.
        let lo_site = lseg.map(|s| s.site).unwrap_or(0);
        let hi_site = hseg.map(|s| s.site).unwrap_or(u64::MAX);
        out.push(Seg {
            digit: lo_digit,
            site: lo_site,
        });
        // An adjacent digit, or an equal digit with a smaller site, already
        // sorts the chosen prefix strictly below hi, so hi no longer bounds
        // the deeper levels.
        if lo_digit != hi_digit || lo_site < hi_site {
            hi_active = false;
        }
        depth += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test replica: a document plus the monotonic counter it stamps ids with.
    struct Replica {
        doc: Doc,
        site: u64,
        counter: u64,
    }

    impl Replica {
        fn new(site: u64) -> Self {
            Replica {
                doc: Doc::new(),
                site,
                counter: 0,
            }
        }

        /// Insert `ch` at visible index `index`, returning the generated op.
        fn insert(&mut self, index: usize, ch: char) -> Op {
            self.counter += 1;
            let ids = self.doc.visible_ids();
            let lo = if index == 0 { None } else { ids.get(index - 1) };
            let hi = ids.get(index);
            let id = alloc_between(lo, hi, self.site, self.counter);
            let op = Op::Insert { id, ch };
            self.doc.apply(&op);
            op
        }

        /// Type a string left-to-right starting at `index`, collecting the ops.
        fn typed(&mut self, mut index: usize, text: &str) -> Vec<Op> {
            let mut ops = Vec::new();
            for ch in text.chars() {
                ops.push(self.insert(index, ch));
                index += 1;
            }
            ops
        }

        /// Tombstone the character at visible `index`.
        fn delete(&mut self, index: usize) -> Op {
            let id = self.doc.visible_ids()[index].clone();
            let op = Op::Delete { id };
            self.doc.apply(&op);
            op
        }
    }

    /// A tiny deterministic LCG so the convergence proof exercises many
    /// delivery orders without a randomness dependency.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn shuffle<T>(&mut self, v: &mut [T]) {
            for i in (1..v.len()).rev() {
                let j = (self.next() as usize) % (i + 1);
                v.swap(i, j);
            }
        }
    }

    fn doc_from(ops: &[Op]) -> Doc {
        let mut d = Doc::new();
        for op in ops {
            d.apply(op);
        }
        d
    }

    #[test]
    fn alloc_is_always_strictly_between() {
        // Empty document: the first id is well-formed.
        let a = alloc_between(None, None, 1, 1);
        assert!(a.is_well_formed());

        // Repeatedly bisect the SAME gap; every new id stays strictly ordered
        // between its neighbours — the dense-allocation invariant.
        let mut lo = alloc_between(None, None, 1, 1);
        let mut hi = alloc_between(Some(&lo), None, 1, 2);
        assert!(lo < hi);
        for c in 3..200u64 {
            let mid = alloc_between(Some(&lo), Some(&hi), 1, c);
            assert!(
                lo < mid && mid < hi,
                "id must fall strictly between its neighbours"
            );
            assert!(mid.is_well_formed());
            // Alternate which side we keep so the path deepens on both ends.
            if c % 2 == 0 {
                lo = mid;
            } else {
                hi = mid;
            }
        }
    }

    #[test]
    fn single_replica_types_and_deletes() {
        let mut r = Replica::new(1);
        r.typed(0, "hello");
        assert_eq!(r.doc.text(), "hello");
        // Delete the first 'l' (index 2).
        r.delete(2);
        assert_eq!(r.doc.text(), "helo");
        // The tombstone is retained, not removed.
        assert_eq!(r.doc.cells.len(), 5, "tombstoned cell is kept, not dropped");
        assert_eq!(r.doc.len(), 4);
    }

    #[test]
    fn concurrent_inserts_from_n_replicas_converge_in_any_order() {
        // Three replicas start from a shared prefix, then edit concurrently.
        let mut seed = Replica::new(9);
        let base_ops = seed.typed(0, "PLAN: ");

        let mut a = Replica::new(1);
        let mut b = Replica::new(2);
        let mut c = Replica::new(3);
        for r in [&mut a, &mut b, &mut c] {
            for op in &base_ops {
                r.doc.apply(op);
            }
        }

        // Concurrent edits: each replica types at the end, and each also deletes
        // a character from the shared prefix — including a delete of a position
        // no replica has re-typed, exercising tombstones.
        let mut all: Vec<Op> = base_ops.clone();
        all.extend(a.typed(a.doc.len(), "alpha"));
        all.extend(b.typed(b.doc.len(), "bravo"));
        all.extend(c.typed(c.doc.len(), "charlie"));
        all.push(a.delete(0)); // 'P'
        all.push(b.delete(1)); // 'L' (index shifts are local; ids are absolute)

        // Reference: apply in generation order.
        let reference = doc_from(&all);
        let ref_text = reference.text();
        let ref_snapshot = reference.to_snapshot();

        // Every delivery order must produce the identical document.
        let mut orders: Vec<Vec<Op>> = Vec::new();
        orders.push(all.clone());
        let mut rev = all.clone();
        rev.reverse();
        orders.push(rev);
        // Round-robin interleave (as if merged from three streams).
        let mut rr = all.clone();
        rr.sort_by_key(|op| op.id().path.first().map(|s| s.site).unwrap_or(0));
        orders.push(rr);
        // Several pseudo-random shuffles.
        let mut lcg = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..25 {
            let mut o = all.clone();
            lcg.shuffle(&mut o);
            orders.push(o);
        }

        for (i, order) in orders.iter().enumerate() {
            let d = doc_from(order);
            assert_eq!(d.text(), ref_text, "order #{i} diverged in text");
            assert_eq!(
                d.to_snapshot(),
                ref_snapshot,
                "order #{i} diverged in compacted snapshot"
            );
        }

        // Sanity on the merged content. Concurrent inserts at the same position
        // legitimately INTERLEAVE (they order deterministically by site, so the
        // three words are woven together, not kept contiguous) — that is correct
        // sequence-CRDT behaviour. The invariant is that no character is lost or
        // duplicated: the merged multiset is exactly the inserts minus the
        // tombstoned characters. Deleting 'P' then 'L' removes the "PL" prefix.
        let mut expected = "PLAN: ".to_string();
        expected.push_str("alphabravocharlie");
        let mut expected_chars: Vec<char> = expected.chars().collect();
        // Remove one 'P' and one 'L' for the two tombstones.
        expected_chars.remove(expected_chars.iter().position(|&c| c == 'P').unwrap());
        expected_chars.remove(expected_chars.iter().position(|&c| c == 'L').unwrap());
        expected_chars.sort_unstable();
        let mut got_chars: Vec<char> = ref_text.chars().collect();
        got_chars.sort_unstable();
        assert_eq!(
            got_chars, expected_chars,
            "merge lost or duplicated a character"
        );
        // The two deleted prefix characters are gone.
        assert!(!ref_text.contains('P'));
        assert!(!ref_text.contains('L'));
    }

    #[test]
    fn reapply_is_idempotent() {
        let mut r = Replica::new(1);
        let mut ops = r.typed(0, "idempotent");
        ops.push(r.delete(0)); // delete 'i'

        let once = doc_from(&ops);
        // Apply the whole batch a second and third time.
        let mut twice = once.clone();
        for op in &ops {
            twice.apply(op);
        }
        for op in &ops {
            twice.apply(op);
        }
        assert_eq!(twice.text(), once.text());
        assert_eq!(twice.to_snapshot(), once.to_snapshot());
    }

    #[test]
    fn delete_before_insert_still_converges() {
        // A replica generates an insert then a delete of the same character.
        let mut r = Replica::new(1);
        let ins = r.insert(0, 'x');
        let del = r.delete(0);

        // Deliver the delete FIRST, then the insert: the tombstone is created
        // up front and the later insert fills the char without resurrecting it.
        let mut reordered = Doc::new();
        reordered.apply(&del);
        reordered.apply(&ins);
        assert_eq!(reordered.text(), "");

        // In-order delivery agrees.
        let mut in_order = Doc::new();
        in_order.apply(&ins);
        in_order.apply(&del);
        assert_eq!(in_order.text(), reordered.text());
        assert_eq!(in_order.to_snapshot(), reordered.to_snapshot());
    }

    #[test]
    fn concurrent_inserts_at_the_same_position_both_survive_and_converge() {
        // Two replicas insert a different character at the same index of the
        // same starting document, concurrently.
        let mut seed = Replica::new(9);
        let base = seed.typed(0, "AZ");

        let mut a = Replica::new(1);
        let mut b = Replica::new(2);
        for op in &base {
            a.doc.apply(op);
            b.doc.apply(op);
        }
        let op_a = a.insert(1, 'a'); // between A and Z on replica a
        let op_b = b.insert(1, 'b'); // between A and Z on replica b

        let mut all = base.clone();
        all.push(op_a);
        all.push(op_b);

        let forward = doc_from(&all);
        let mut rev = all.clone();
        rev.reverse();
        let backward = doc_from(&rev);

        assert_eq!(forward.text(), backward.text(), "must converge");
        assert_eq!(forward.to_snapshot(), backward.to_snapshot());
        // Both concurrent characters survive, ordered deterministically between A and Z.
        assert_eq!(forward.text(), "AabZ");
    }

    #[test]
    fn site_gap_bisection_stamps_minter_site_not_a_derived_one() {
        // Two replicas each insert the first character into an EMPTY document.
        // First-into-empty lands in digit space, so both ids share the same
        // digit and differ only by site; picking sites 1 and 3 leaves a site
        // gap > 1 between them (the exact shape that used to trigger the buggy
        // site-bisection branch).
        let a = alloc_between(None, None, 1, 1);
        let b = alloc_between(None, None, 3, 1);
        assert_eq!(
            a.path[0].digit, b.path[0].digit,
            "first-into-empty inserts share a digit"
        );
        let (lo, hi) = if a < b {
            (a.clone(), b.clone())
        } else {
            (b.clone(), a.clone())
        };
        assert!(
            lo.path[0].site + 1 < hi.path[0].site,
            "sites 1 and 3 leave a gap > 1"
        );

        // Two DIFFERENT replicas (sites 5 and 7) each place a character in that
        // same gap, with the same local counter. Their ids MUST differ and MUST
        // carry their own minting site — never a derived midpoint site.
        let m5 = alloc_between(Some(&lo), Some(&hi), 5, 1);
        let m7 = alloc_between(Some(&lo), Some(&hi), 7, 1);
        assert!(
            lo < m5 && m5 < hi,
            "m5 falls strictly between the neighbours"
        );
        assert!(
            lo < m7 && m7 < hi,
            "m7 falls strictly between the neighbours"
        );
        assert_ne!(
            m5, m7,
            "two replicas bisecting the same site gap must mint DISTINCT ids"
        );
        assert!(
            m5.path.iter().any(|s| s.site == 5),
            "minted id must carry the minter's site (5), not a derived one"
        );
        assert!(
            m7.path.iter().any(|s| s.site == 7),
            "minted id must carry the minter's site (7), not a derived one"
        );
    }

    #[test]
    fn concurrent_bisection_of_a_site_gap_converges_and_keeps_every_char() {
        // Reconstruct the collision scenario end-to-end through the document.
        // lo/hi model two concurrent first-into-empty inserts a site-gap apart.
        let a = alloc_between(None, None, 1, 1);
        let b = alloc_between(None, None, 3, 1);
        let (lo, hi) = if a < b {
            (a.clone(), b.clone())
        } else {
            (b.clone(), a.clone())
        };

        // Two distinct replicas each insert a distinct character into that gap,
        // concurrently, with the same local counter. Pre-fix these produced the
        // SAME id and one character was lost; post-fix all four survive.
        let id_x = alloc_between(Some(&lo), Some(&hi), 5, 1);
        let id_y = alloc_between(Some(&lo), Some(&hi), 7, 1);
        assert_ne!(id_x, id_y, "concurrent gap inserts must not collide");

        let ops = vec![
            Op::Insert {
                id: lo.clone(),
                ch: '1',
            },
            Op::Insert {
                id: hi.clone(),
                ch: '3',
            },
            Op::Insert { id: id_x, ch: 'x' },
            Op::Insert { id: id_y, ch: 'y' },
        ];

        let forward = doc_from(&ops);
        let mut rev = ops.clone();
        rev.reverse();
        let backward = doc_from(&rev);

        assert_eq!(
            forward.text(),
            backward.text(),
            "delivery order must converge"
        );
        assert_eq!(forward.to_snapshot(), backward.to_snapshot());
        assert_eq!(
            forward.len(),
            4,
            "every concurrent character survives; none collide"
        );
        let mut chars: Vec<char> = forward.text().chars().collect();
        chars.sort_unstable();
        assert_eq!(
            chars,
            vec!['1', '3', 'x', 'y'],
            "no character lost or duplicated"
        );
    }

    #[test]
    fn snapshot_round_trips_including_tombstones() {
        let mut r = Replica::new(1);
        r.typed(0, "snapshot");
        r.delete(0); // tombstone 's'
        let snap = r.doc.to_snapshot();
        let restored = Doc::from_snapshot(&snap).expect("snapshot round-trips");
        assert_eq!(restored.text(), r.doc.text());
        assert_eq!(restored.to_snapshot(), snap);
        // Applying a further update on the restored doc continues to converge.
        let mut r2 = Replica {
            doc: restored,
            site: 5,
            counter: 100,
        };
        r2.typed(r2.doc.len(), "!");
        assert_eq!(r2.doc.text(), "napshot!");
    }

    #[test]
    fn malformed_updates_are_rejected() {
        // Not JSON at all.
        assert!(matches!(
            Update::from_slice(b"not json"),
            Err(CrdtError::Malformed(_))
        ));
        // Well-formed JSON, wrong shape.
        assert!(matches!(
            Update::from_slice(br#"{"ops":[{"Nope":{}}]}"#),
            Err(CrdtError::Malformed(_))
        ));
        // Structurally valid JSON but an empty position path.
        let empty_path = br#"{"ops":[{"Insert":{"id":{"path":[],"counter":1},"ch":"a"}}]}"#;
        assert_eq!(Update::from_slice(empty_path), Err(CrdtError::InvalidId));
        // A digit outside the legal range.
        let bad_digit = format!(
            r#"{{"ops":[{{"Insert":{{"id":{{"path":[{{"digit":{},"site":1}}],"counter":1}},"ch":"a"}}}}]}}"#,
            BASE
        );
        assert_eq!(
            Update::from_slice(bad_digit.as_bytes()),
            Err(CrdtError::InvalidId)
        );
    }

    #[test]
    fn valid_update_round_trips_over_the_wire_and_merges() {
        let mut r = Replica::new(7);
        let update = Update {
            ops: r.typed(0, "wire"),
        };
        let bytes = serde_json::to_vec(&update).unwrap();
        let parsed = Update::from_slice(&bytes).expect("valid update parses");
        let mut server = Doc::new();
        let applied = server.apply_update(&parsed).expect("valid update applies");
        assert_eq!(applied, 4);
        assert_eq!(server.text(), "wire");
    }
}
