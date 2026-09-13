//! Shared bounded scalar-anchor value table for `yaml-rust2` `MarkedEventReceiver`-based
//! parsers (`deps-dart`, `deps-gitlab-ci`).
//!
//! Each receiver builds an `anchor id -> scalar text` map during its single event-stream
//! pass so a later `Event::Alias` can resolve back to the anchor's text.
//!
//! # What is generic vs. what stays per-crate
//!
//! [`ScalarAnchorTable`] owns exactly the table mechanics duplicated across both crates before
//! this module existed: `yaml-rust2`'s anchor-id-`0` sentinel (no anchor), the optional
//! char-length/entry-count bounds ([`AnchorLimits`]), and the `HashMap<usize, (String, M)>`
//! store itself. Alias-resolution *policy* — which frame role a table hit resolves into,
//! key-position vs. value-position handling, what a table miss means for the caller — stays in
//! each crate's own receiver, threaded through the table's generic `meta: M` the same way
//! [`crate::yaml_walk::FrameStack`] threads a `payload: P`.
//!
//! # Examples
//!
//! ```
//! use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
//!
//! let mut table: ScalarAnchorTable = ScalarAnchorTable::new(AnchorLimits::UNBOUNDED);
//! table.record(1, "v1.2.3", ());
//! assert_eq!(table.get(1), Some(("v1.2.3", &())));
//! assert_eq!(table.get(2), None);
//! ```

use std::collections::HashMap;

/// Bounds on how much a [`ScalarAnchorTable`] will record, to cap memory use against a
/// pathological or malicious document — `None` skips the corresponding check entirely.
///
/// Fields are private; [`AnchorLimits::UNBOUNDED`] and [`AnchorLimits::bounded`] are the only
/// way to construct one, so a value never drifts out of one of those two shapes after
/// construction.
///
/// # Examples
///
/// ```
/// use deps_core::yaml_anchor::AnchorLimits;
///
/// assert_ne!(AnchorLimits::bounded(512, 256), AnchorLimits::UNBOUNDED);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorLimits {
    /// Maximum character count (`str::chars().count()`) of one anchored scalar's text that
    /// will be recorded. `None` skips the check entirely, so an unbounded table pays no
    /// per-anchored-scalar `chars()` walk.
    max_value_chars: Option<usize>,
    /// Maximum number of distinct anchor ids the table will hold. `None` skips the check.
    max_entries: Option<usize>,
}

impl AnchorLimits {
    /// No bounds at all — every anchored scalar is recorded regardless of length or table
    /// size. Still implicitly bounded upstream by a document-wide expansion-size gate (e.g.
    /// `deps_core::check_yaml_expansion`), so an unbounded table remains safe.
    pub const UNBOUNDED: Self = Self {
        max_value_chars: None,
        max_entries: None,
    };

    /// Bounds the table to at most `max_entries` distinct anchor ids, each with recorded text
    /// no longer than `max_value_chars` characters.
    #[must_use]
    pub const fn bounded(max_value_chars: usize, max_entries: usize) -> Self {
        Self {
            max_value_chars: Some(max_value_chars),
            max_entries: Some(max_entries),
        }
    }
}

/// A bounded `anchor id -> (scalar text, per-crate metadata)` table, built during one
/// `yaml-rust2` event-stream pass and looked up on a later `Event::Alias`.
///
/// `M` carries whatever a driving crate's own alias-resolution policy needs alongside the
/// text (e.g. `deps-dart` keeps the scalar's style/tag to re-check null-ness at the alias
/// site) — defaults to `()` when nothing beyond the text itself is needed.
///
/// # Examples
///
/// ```
/// use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
///
/// let mut table: ScalarAnchorTable<u8> = ScalarAnchorTable::new(AnchorLimits::bounded(32, 2));
/// table.record(1, "short", 7);
/// table.record(1, "overwritten", 9); // overwriting an existing id is always allowed
/// assert_eq!(table.get(1), Some(("overwritten", &9)));
/// ```
#[derive(Debug)]
pub struct ScalarAnchorTable<M = ()> {
    entries: HashMap<usize, (String, M)>,
    limits: AnchorLimits,
}

impl<M> ScalarAnchorTable<M> {
    /// Creates an empty table bounded by `limits`.
    #[must_use]
    pub fn new(limits: AnchorLimits) -> Self {
        Self {
            entries: HashMap::new(),
            limits,
        }
    }

    /// Records `anchor_id`'s scalar `text` and `meta`, unless `anchor_id` is `0`
    /// (`yaml-rust2`'s "no anchor" sentinel — anchor ids otherwise start at 1).
    ///
    /// Also a no-op if `text` exceeds the limits' `max_value_chars`, or the table is already
    /// at the limits' `max_entries` and `anchor_id` is not already present.
    /// Recording an id already in the table always overwrites it, even at capacity — in
    /// practice unreachable for ids sourced from `yaml-rust2`, which assigns them
    /// monotonically and never reuses one within a document, but preserved (and tested) for
    /// exact behavior parity with the pre-extraction per-crate implementations.
    ///
    /// `meta` is evaluated eagerly by the caller before this call, like any other argument —
    /// a caller that only wants the cost paid for an actually-anchored scalar (`anchor_id !=
    /// 0`) should guard the call at its own call site rather than rely on this method to skip
    /// constructing `meta`.
    pub fn record(&mut self, anchor_id: usize, text: &str, meta: M) {
        if anchor_id == 0 {
            return;
        }
        if let Some(max_chars) = self.limits.max_value_chars
            && text.chars().take(max_chars.saturating_add(1)).count() > max_chars
        {
            return;
        }
        if let Some(max_entries) = self.limits.max_entries
            && self.entries.len() >= max_entries
            && !self.entries.contains_key(&anchor_id)
        {
            return;
        }
        self.entries.insert(anchor_id, (text.to_string(), meta));
    }

    /// Looks up `anchor_id`'s recorded text and metadata, if it was recorded.
    #[must_use]
    pub fn get(&self, anchor_id: usize) -> Option<(&str, &M)> {
        self.entries
            .get(&anchor_id)
            .map(|(text, meta)| (text.as_str(), meta))
    }
}

#[cfg(test)]
mod tests {
    use super::{AnchorLimits, ScalarAnchorTable};

    #[test]
    fn test_anchor_id_zero_is_a_no_op() {
        let mut table: ScalarAnchorTable = ScalarAnchorTable::new(AnchorLimits::UNBOUNDED);
        table.record(0, "ignored", ());
        assert_eq!(table.get(0), None);
    }

    #[test]
    fn test_char_count_at_boundary_is_recorded_over_boundary_is_skipped() {
        let mut table: ScalarAnchorTable = ScalarAnchorTable::new(AnchorLimits::bounded(4, 10));
        table.record(1, "abcd", ()); // == 4 chars, recorded
        table.record(2, "abcde", ()); // == 5 chars, skipped
        assert_eq!(table.get(1), Some(("abcd", &())));
        assert_eq!(table.get(2), None);
    }

    #[test]
    fn test_entry_cap_skips_new_id_but_allows_overwriting_existing_id() {
        let mut table: ScalarAnchorTable = ScalarAnchorTable::new(AnchorLimits::bounded(64, 1));
        table.record(1, "first", ());
        table.record(2, "second", ()); // table already at cap, new id skipped
        assert_eq!(table.get(2), None);
        table.record(1, "overwritten", ()); // overwriting existing id at capacity is allowed
        assert_eq!(table.get(1), Some(("overwritten", &())));
    }

    #[test]
    fn test_unbounded_limits_record_past_both_bounds() {
        let mut table: ScalarAnchorTable = ScalarAnchorTable::new(AnchorLimits::UNBOUNDED);
        let long = "v".repeat(10_000);
        for id in 1..=1000usize {
            table.record(id, &long, ());
        }
        assert_eq!(table.get(1).map(|(text, ())| text.len()), Some(10_000));
        assert_eq!(table.get(1000).map(|(text, ())| text.len()), Some(10_000));
    }
}
