//! **Bounded reads and the declared invalidation budget.**
//!
//! Two mechanisms that work the same way: they replace a value a caller
//! can ignore with a value the caller must handle.
//!
//! # Why `(rows, bool)` is the wrong shape
//!
//! `StoreClusterClient::scan_prefix` returns one bounded page and a `more`
//! flag, which is easy to bind to `_more` and drop. That is safe for a list
//! with a known cap and not for an aggregate: a total computed over a truncated
//! set is reported as a confident total, so a header disagrees with the rows
//! beneath it.
//!
//! Nothing in the type distinguished the two. [`Page`] does: a caller either
//! follows the cursor, or calls [`Page::expect_complete`] and NAMES the bound
//! that makes truncation impossible. Both are auditable; `_more` was not.
//!
//! # Why the invalidation budget is declared
//!
//! One guarded advance carries at most [`MAX_TAGS_PER_ADVANCE`] entries
//! beside the version guard, because an APE envelope holds 64. Inventory's
//! cycle-count close can exceed that, and its answer was to truncate the tag
//! list to four family tags once it passed 48 — correct, because a family
//! tag invalidates a superset, but a SILENT widening: nothing recorded that
//! the precise set had been abandoned.
//!
//! [`Invalidation`] makes the widening a declared decision that the plan
//! reports back, so an action's reply can say what it actually invalidated.

use ferrite_app::client::StoreClusterClient;

use crate::alloy::error::{AlloyError, Result};
use crate::alloy::tags::MAX_TAGS_PER_ADVANCE;

/// Whether a read saw its whole set.
///
/// This is a CONTRACT type, not an internal one: a view that aggregates over
/// a truncated set carries the fact to the browser, so the interface can say
/// what it is showing instead of implying a total it never had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// Every row that matches was read.
    Complete,
    /// The read stopped at a ceiling; `cap` rows were returned.
    Truncated {
        /// The ceiling that stopped it.
        cap: usize,
    },
}

impl Completeness {
    /// Whether this read saw everything.
    pub fn is_complete(&self) -> bool {
        matches!(self, Completeness::Complete)
    }

    /// The ceiling, when the read was truncated.
    pub fn cap(&self) -> Option<usize> {
        match self {
            Completeness::Complete => None,
            Completeness::Truncated { cap } => Some(*cap),
        }
    }
}

/// One bounded read, carrying whether it saw everything.
///
/// The variants are deliberately not a struct with a public `truncated`
/// field: a field can be ignored exactly as `_more` was, whereas matching on
/// an enum forces the question to be answered at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page<T> {
    /// Every matching row.
    Complete(Vec<T>),
    /// The ceiling stopped the read.
    Truncated {
        /// What was read.
        rows: Vec<T>,
        /// The ceiling that stopped it.
        cap: usize,
        /// The key to resume after, for a caller that wants the next page.
        resume: Vec<u8>,
    },
}

impl<T> Page<T> {
    /// A complete page.
    pub fn complete(rows: Vec<T>) -> Self {
        Page::Complete(rows)
    }

    /// A page that stopped at `cap`, resumable after `resume`.
    pub fn truncated(rows: Vec<T>, cap: usize, resume: Vec<u8>) -> Self {
        Page::Truncated { rows, cap, resume }
    }

    /// The rows, however the read ended.
    pub fn rows(&self) -> &[T] {
        match self {
            Page::Complete(rows) | Page::Truncated { rows, .. } => rows,
        }
    }

    /// How many rows were read.
    pub fn len(&self) -> usize {
        self.rows().len()
    }

    /// Whether nothing matched.
    pub fn is_empty(&self) -> bool {
        self.rows().is_empty()
    }

    /// This read's completeness, for publication in a view.
    pub fn completeness(&self) -> Completeness {
        match self {
            Page::Complete(_) => Completeness::Complete,
            Page::Truncated { cap, .. } => Completeness::Truncated { cap: *cap },
        }
    }

    /// The cursor to resume after, when the read was truncated.
    pub fn resume(&self) -> Option<&[u8]> {
        match self {
            Page::Complete(_) => None,
            Page::Truncated { resume, .. } => Some(resume.as_slice()),
        }
    }

    /// Take the rows, ACCEPTING a possible truncation.
    ///
    /// Named for what it costs rather than for what it returns: a reader
    /// seeing this at a call site knows an aggregate computed from it may be
    /// partial, which `into_iter()` would not have told them.
    pub fn into_rows_lossy(self) -> Vec<T> {
        match self {
            Page::Complete(rows) | Page::Truncated { rows, .. } => rows,
        }
    }

    /// Take every row, refusing if the read was truncated.
    ///
    /// `why` states the bound that makes completeness safe — "a project list
    /// is capped at 64 by the domain" — so a reviewer can check the claim,
    /// and a later change that breaks it fails loudly rather than quietly
    /// reporting a wrong total.
    pub fn expect_complete(self, why: &str) -> Result<Vec<T>> {
        match self {
            Page::Complete(rows) => Ok(rows),
            Page::Truncated { cap, .. } => Err(AlloyError::internal(format!(
                "a read expected to be complete was truncated at {cap} rows ({why})"
            ))),
        }
    }

    /// Map the rows, preserving completeness.
    pub fn map<U, F: FnMut(T) -> U>(self, f: F) -> Page<U> {
        match self {
            Page::Complete(rows) => Page::Complete(rows.into_iter().map(f).collect()),
            Page::Truncated { rows, cap, resume } => Page::Truncated {
                rows: rows.into_iter().map(f).collect(),
                cap,
                resume,
            },
        }
    }
}

/// Read every row under `prefix`, following the scan cursor to `ceiling`.
///
/// `scan_prefix` returns ONE page and a `more` flag, so the easy call reads a
/// single page and silently drops the rest.
///
/// The ceiling is a real bound rather than an assumption about the data: a
/// set that outgrows it comes back [`Page::Truncated`] carrying its resume
/// key, so the caller can page on or publish the truncation. It never
/// FAILS, because a growing collection is not an error — reporting a
/// partial answer as though it were total is.
pub async fn scan_all(
    store: &mut StoreClusterClient,
    prefix: &[u8],
    page: u32,
    ceiling: usize,
) -> Result<Page<(Vec<u8>, Vec<u8>, u64)>> {
    let mut rows: Vec<(Vec<u8>, Vec<u8>, u64)> = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let (batch, more) = store.scan_prefix(prefix, cursor.as_deref(), page).await?;
        let last = batch.last().map(|(k, _, _)| k.clone());
        rows.extend(batch);
        if exceeds_ceiling(rows.len(), ceiling, more && last.is_some()) {
            return Ok(truncate_at_ceiling(rows, ceiling, cursor));
        }
        match last {
            // `more` is only meaningful with a key to resume from: an empty
            // page cannot advance the cursor, so stopping here is what
            // prevents an infinite loop on a truncated read.
            Some(key) if more => cursor = Some(key),
            _ => return Ok(Page::complete(rows)),
        }
    }
}

/// Whether a scan holding `held` rows must report truncation at `ceiling`.
///
/// Exactly `ceiling` rows with nothing left in the store is a COMPLETE
/// answer: a collection that reaches its legal cap has not outgrown it.
/// Only rows actually dropped, or rows still unread, make it a truncation.
fn exceeds_ceiling(held: usize, ceiling: usize, more: bool) -> bool {
    held > ceiling || (held == ceiling && more)
}

/// Cut `rows` to `ceiling` and name the key to resume after.
///
/// The resume key is the last row that SURVIVES the cut, never the last row
/// fetched: a ceiling that falls inside a batch drops the tail of that batch,
/// and a cursor past those rows would make a caller that pages on skip them
/// — the very silent loss [`Page`] exists to rule out. With nothing kept
/// (`ceiling == 0`) the scan resumes where it started, from `start`.
fn truncate_at_ceiling<V>(
    mut rows: Vec<(Vec<u8>, V, u64)>,
    ceiling: usize,
    start: Option<Vec<u8>>,
) -> Page<(Vec<u8>, V, u64)> {
    rows.truncate(ceiling);
    let resume = match rows.last() {
        Some((key, _, _)) => key.clone(),
        None => start.unwrap_or_default(),
    };
    Page::truncated(rows, ceiling, resume)
}

/// What one action will invalidate, planned against the envelope budget.
///
/// An advance commits at most [`MAX_TAGS_PER_ADVANCE`] entries beside the
/// version guard. An action that also writes a marker, its own APE entries
/// and its outbox records spends from the same budget, so the tag set is not
/// free, and discovering that at runtime means a silent truncation.
#[derive(Debug, Clone, Default)]
pub struct Invalidation {
    families: Vec<String>,
    instances: Vec<String>,
    widen_to: Vec<String>,
    reserved: usize,
}

/// The outcome of planning an invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidationPlan {
    /// The tags to advance.
    pub tags: Vec<String>,
    /// Whether the precise instance set was abandoned for its families.
    pub widened: bool,
}

impl InvalidationPlan {
    /// The tags this plan advances.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
}

impl Invalidation {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve envelope entries for everything that is NOT a tag: the
    /// marker, the action's own APE writes, its outbox records and index.
    ///
    /// Without this the planner would happily fill the envelope with tags
    /// and leave no room for the marker that makes the action replay-safe.
    pub fn reserving(mut self, entries: usize) -> Self {
        self.reserved = entries;
        self
    }

    /// Add a family tag, which is always kept.
    pub fn family(mut self, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        if !self.families.contains(&tag) {
            self.families.push(tag);
        }
        self
    }

    /// Add instance tags, which are the ones a widening drops.
    pub fn instances<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for tag in tags {
            let tag = tag.into();
            if !self.instances.contains(&tag) && !self.families.contains(&tag) {
                self.instances.push(tag);
            }
        }
        self
    }

    /// Declare the families to fall back on when the instance set will not
    /// fit. Naming this is what turns a silent truncation into a decision.
    ///
    /// Every name here must ALSO be declared with [`family`](Self::family).
    /// A widening drops the precise instance tags, so its targets are the
    /// only thing still invalidating those entries — and a name that is not
    /// a real family of this action invalidates nothing at all. Accepting
    /// an arbitrary string would let `widen_to(["stok"])` plan successfully
    /// and leave every stale entry live, which is precisely the silent
    /// failure this type exists to remove.
    pub fn widen_to<I, S>(mut self, families: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for tag in families {
            let tag = tag.into();
            if !self.widen_to.contains(&tag) {
                self.widen_to.push(tag);
            }
        }
        self
    }

    /// The budget available to tags after the reservation.
    pub fn budget(&self) -> usize {
        MAX_TAGS_PER_ADVANCE.saturating_sub(self.reserved)
    }

    /// Plan the advance.
    ///
    /// Precise when it fits; widened when it does not and a fallback was
    /// declared; an ERROR when it does not fit and none was — because
    /// truncating on the author's behalf is exactly the silent behaviour
    /// this type exists to remove.
    pub fn plan(&self) -> Result<InvalidationPlan> {
        let budget = self.budget();
        let mut precise: Vec<String> = self.families.clone();
        for tag in &self.instances {
            if !precise.contains(tag) {
                precise.push(tag.clone());
            }
        }
        if precise.len() <= budget {
            return Ok(InvalidationPlan {
                tags: precise,
                widened: false,
            });
        }
        if self.widen_to.is_empty() {
            return Err(AlloyError::internal(format!(
                "this action would advance {} tags, which exceeds the {budget} available \
                 beside the version guard and its {} reserved entries; declare widen_to(..) \
                 to state which families cover them",
                precise.len(),
                self.reserved
            )));
        }
        // A widening target that is not a declared family of this action
        // invalidates nothing: the instance tags it replaces are dropped,
        // and the name itself was never advanced by anything. Refusing here
        // turns a typo into a build-visible error instead of stale reads.
        for target in &self.widen_to {
            if !self.families.contains(target) {
                return Err(AlloyError::internal(format!(
                    "widen_to names '{target}', which is not a declared family of this \
                     action; a widening must fall back on families the action actually \
                     advances, or it invalidates nothing"
                )));
            }
        }
        // Widening drops the instance tags; every declared family stays.
        let mut widened: Vec<String> = self.families.clone();
        for target in &self.widen_to {
            if !widened.contains(target) {
                widened.push(target.clone());
            }
        }
        if widened.len() > budget {
            return Err(AlloyError::internal(format!(
                "even the widened family set is {} tags against a budget of {budget}",
                widened.len()
            )));
        }
        Ok(InvalidationPlan {
            tags: widened,
            widened: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_page_yields_its_rows() {
        let p = Page::complete(vec![1, 2, 3]);
        assert!(p.completeness().is_complete());
        assert_eq!(p.len(), 3);
        assert_eq!(p.resume(), None);
        assert_eq!(
            p.expect_complete("bounded by the domain").unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn a_truncated_page_refuses_to_pass_as_complete() {
        // This is the whole point: the campaign's aggregates were computed
        // over truncated sets and reported as totals. Here that is an error
        // naming the bound, not a confident wrong number.
        let p = Page::truncated(vec![1, 2], 2, b"k2".to_vec());
        assert_eq!(p.completeness(), Completeness::Truncated { cap: 2 });
        assert_eq!(p.resume(), Some(b"k2".as_slice()));
        let err = p
            .expect_complete("a project list is capped at 64")
            .unwrap_err();
        // An internal error DIGESTS its cause rather than forwarding it, so
        // the assertion is on the verdict, not on the prose: the read is
        // refused with a 500 instead of passing off partial rows as a total.
        assert_eq!(err.status(), 500);
        assert!(!err.problem_json().to_string().contains("capped at 64"));
    }

    #[test]
    fn mapping_preserves_the_truncation_verdict() {
        // A projection must not launder a truncated read into a complete one.
        let p = Page::truncated(vec![1, 2], 2, b"k".to_vec()).map(|n| n * 10);
        assert_eq!(p.rows(), &[10, 20]);
        assert_eq!(p.completeness(), Completeness::Truncated { cap: 2 });
        let c = Page::complete(vec![1]).map(|n| n + 1);
        assert!(c.completeness().is_complete());
    }

    #[test]
    fn a_small_tag_set_is_advanced_precisely() {
        let plan = Invalidation::new()
            .family("stock")
            .instances(["sku-A", "sku-B"])
            .plan()
            .unwrap();
        assert!(!plan.widened);
        assert_eq!(plan.tags, vec!["stock", "sku-A", "sku-B"]);
    }

    #[test]
    fn an_oversized_set_widens_only_when_a_fallback_was_declared() {
        // Inventory's cycle-count close: hundreds of SKUs, one envelope.
        let many: Vec<String> = (0..200).map(|i| format!("sku-{i}")).collect();
        let declared = Invalidation::new()
            .family("stock")
            .instances(many.clone())
            .widen_to(["stock"])
            .plan()
            .unwrap();
        assert!(declared.widened, "the plan must report that it widened");
        assert_eq!(declared.tags, vec!["stock"]);

        // Without a declared fallback this is a build-time-visible error,
        // never a silent truncation to whatever happened to fit.
        let undeclared = Invalidation::new().family("stock").instances(many).plan();
        assert!(undeclared.is_err());
    }

    #[test]
    fn the_budget_leaves_room_for_the_actions_own_entries() {
        // An action spends envelope entries on its marker, its APE writes and
        // its outbox records. Tags may not consume the whole envelope.
        let plan = Invalidation::new().reserving(60).family("a").family("b");
        assert_eq!(plan.budget(), MAX_TAGS_PER_ADVANCE - 60);
        assert!(plan.plan().is_ok());

        let over = Invalidation::new()
            .reserving(62)
            .family("a")
            .family("b")
            .plan();
        assert!(over.is_err(), "the reservation must bound the tag set");
    }

    #[test]
    fn duplicate_tags_never_consume_two_entries() {
        let plan = Invalidation::new()
            .family("stock")
            .instances(["sku-A", "sku-A", "stock"])
            .plan()
            .unwrap();
        assert_eq!(plan.tags, vec!["stock", "sku-A"]);
    }

    #[test]
    fn a_widened_plan_that_still_does_not_fit_is_refused() {
        // Widening is not a magic escape: if the families themselves exceed
        // the envelope, that is a design error and must surface as one.
        let families: Vec<String> = (0..70).map(|i| format!("f{i}")).collect();
        let mut plan = Invalidation::new().instances((0..200).map(|i| format!("i{i}")));
        for f in &families {
            plan = plan.family(f.clone());
        }
        assert!(plan.widen_to(families).plan().is_err());
    }

    #[test]
    fn a_widening_target_must_be_a_family_this_action_advances() {
        // The failure this prevents is silent: the instance tags are
        // dropped, and a misspelled family advances nothing, so every
        // entry that should have died stays live and fresh.
        let many: Vec<String> = (0..200).map(|i| format!("sku-{i}")).collect();
        let typo = Invalidation::new()
            .family("stock")
            .instances(many.clone())
            .widen_to(["stok"])
            .plan();
        assert!(
            typo.is_err(),
            "a misspelled widening target must be refused"
        );

        // …and the correctly-named one still plans.
        let good = Invalidation::new()
            .family("stock")
            .instances(many)
            .widen_to(["stock"])
            .plan()
            .unwrap();
        assert!(good.widened);
        assert_eq!(good.tags, vec!["stock"]);
    }

    fn row(key: &str) -> (Vec<u8>, Vec<u8>, u64) {
        (key.as_bytes().to_vec(), Vec::new(), 1)
    }

    #[test]
    fn a_set_exactly_at_the_ceiling_is_complete() {
        // finding_79a0a1d822244ecc: the store holding exactly `ceiling` rows
        // and reporting no more is a complete read, not a truncation.
        assert!(!exceeds_ceiling(4, 4, false));
        assert!(!exceeds_ceiling(0, 0, false));
        assert!(exceeds_ceiling(4, 4, true));
        assert!(exceeds_ceiling(5, 4, false));
        assert!(!exceeds_ceiling(3, 4, true));
    }

    #[test]
    fn a_truncated_scan_resumes_after_the_last_row_it_kept() {
        // F470: the ceiling fell inside a batch of five. Rows d and e were
        // dropped, so a caller paging on from the resume key must see them;
        // a cursor naming e (the last row FETCHED) would skip both.
        let fetched: Vec<_> = ["a", "b", "c", "d", "e"].into_iter().map(row).collect();
        let page = truncate_at_ceiling(fetched, 3, None);
        assert_eq!(page.len(), 3);
        assert_eq!(page.completeness().cap(), Some(3));
        assert_eq!(page.resume(), Some(b"c".as_slice()));
        assert_eq!(page.rows()[2].0, b"c".to_vec());

        // Nothing kept: resume where this batch started, never past it.
        let fetched: Vec<_> = ["m", "n"].into_iter().map(row).collect();
        let page = truncate_at_ceiling(fetched, 0, Some(b"l".to_vec()));
        assert!(page.is_empty());
        assert_eq!(page.resume(), Some(b"l".as_slice()));
    }
}
