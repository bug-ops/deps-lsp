//! Set of claimed byte spans with logarithmic containment lookup.
//!
//! Regex-based manifest parsers (`deps-swift`, `deps-gradle`) try several overlapping
//! patterns against the same text and must skip a later match already claimed by an earlier
//! pattern. A `Vec` scan per match is quadratic on a single attacker-controlled long line;
//! [`MatchedSpans`] keeps only the non-dominated spans, so both insert and lookup are
//! `O(log k)`.

use std::collections::BTreeMap;
use std::ops::Range;

/// Claimed byte spans, queried by containment.
///
/// Internally a staircase: spans are keyed by start and only spans that are not contained in
/// another are retained, so `end` is strictly increasing with `start` and the single span with
/// the greatest `start <= query.start` has the greatest reachable `end`.
///
/// # Examples
///
/// ```
/// use deps_core::MatchedSpans;
///
/// let mut spans = MatchedSpans::default();
/// spans.insert(10..20);
/// assert!(spans.contains(&(12..18)));
/// assert!(spans.contains(&(10..20)));
/// assert!(!spans.contains(&(5..15)));
/// assert!(!spans.contains(&(15..25)));
///
/// assert!(spans.insert_point(40));
/// assert!(spans.contains_point(40));
/// assert!(!spans.contains_point(41));
/// ```
#[derive(Debug, Default, Clone)]
pub struct MatchedSpans {
    ends_by_start: BTreeMap<usize, usize>,
}

impl MatchedSpans {
    /// Returns `true` if `range` is non-empty and lies entirely within one previously
    /// inserted span.
    #[must_use]
    pub fn contains(&self, range: &Range<usize>) -> bool {
        !range.is_empty()
            && self
                .ends_by_start
                .range(..=range.start)
                .next_back()
                .is_some_and(|(_, &end)| range.end <= end)
    }

    /// Returns `true` if a span starting exactly at `start` was inserted via
    /// [`insert_point`](Self::insert_point).
    #[must_use]
    pub fn contains_point(&self, start: usize) -> bool {
        self.contains(&(start..start + 1))
    }

    /// Claims `span`, returning `false` (and changing nothing) if `span` is empty or already
    /// contained in a claimed span.
    pub fn insert(&mut self, span: Range<usize>) -> bool {
        if span.is_empty() || self.contains(&span) {
            return false;
        }
        while let Some((&start, &end)) = self.ends_by_start.range(span.start..).next() {
            if end > span.end {
                break;
            }
            self.ends_by_start.remove(&start);
        }
        self.ends_by_start.insert(span.start, span.end);
        true
    }

    /// Claims the single offset `start` for exact-start lookups via
    /// [`contains_point`](Self::contains_point); returns `false` if it was already claimed.
    pub fn insert_point(&mut self, start: usize) -> bool {
        self.insert(start..start + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_contains_nothing() {
        assert!(!MatchedSpans::default().contains(&(0..1)));
    }

    #[test]
    fn nested_and_overlapping_spans() {
        let mut spans = MatchedSpans::default();
        spans.insert(10..20);
        spans.insert(12..15);
        spans.insert(18..30);
        assert!(spans.contains(&(12..15)));
        assert!(spans.contains(&(19..30)));
        assert!(!spans.contains(&(15..25)));
        assert!(!spans.contains(&(10..30)));
        assert!(!spans.contains(&(9..12)));
        assert!(!spans.contains(&(30..31)));
    }

    #[test]
    fn wider_span_replaces_dominated_ones() {
        let mut spans = MatchedSpans::default();
        spans.insert(5..8);
        spans.insert(10..12);
        spans.insert(0..20);
        assert!(spans.contains(&(10..12)));
        assert_eq!(spans.ends_by_start.len(), 1);
    }

    #[test]
    fn same_start_longer_span_wins() {
        let mut spans = MatchedSpans::default();
        spans.insert(3..5);
        spans.insert(3..9);
        assert!(spans.contains(&(3..9)));
    }

    #[test]
    fn unit_spans_match_exact_start_only() {
        let mut spans = MatchedSpans::default();
        spans.insert(7..8);
        assert!(spans.contains(&(7..8)));
        assert!(!spans.contains(&(8..9)));
        assert!(!spans.contains(&(6..7)));
    }

    #[test]
    fn empty_spans_are_ignored() {
        let mut spans = MatchedSpans::default();
        assert!(!spans.insert(4..4));
        assert!(!spans.contains(&(4..4)));
        spans.insert(0..10);
        assert!(!spans.contains(&(5..5)));
    }

    #[test]
    fn adjacent_spans_are_not_merged() {
        let mut spans = MatchedSpans::default();
        spans.insert(0..5);
        spans.insert(5..10);
        assert!(!spans.contains(&(3..8)));
        assert!(spans.contains(&(0..5)));
        assert!(spans.contains(&(5..10)));
    }

    #[test]
    fn inserting_a_covered_span_is_a_no_op() {
        let mut spans = MatchedSpans::default();
        assert!(spans.insert(0..10));
        assert!(!spans.insert(2..4));
        assert!(!spans.insert(0..10));
        assert_eq!(spans.ends_by_start.len(), 1);
    }

    #[test]
    fn point_helpers_are_exact_start() {
        let mut spans = MatchedSpans::default();
        assert!(spans.insert_point(7));
        assert!(!spans.insert_point(7));
        assert!(spans.contains_point(7));
        assert!(!spans.contains_point(6));
        assert!(!spans.contains_point(8));
    }

    #[test]
    fn agrees_with_naive_containment() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % bound as u64).unwrap()
        };
        let mut spans = MatchedSpans::default();
        let mut naive: Vec<Range<usize>> = Vec::new();
        for _ in 0..3000 {
            let start = next(200);
            let range = start..start + 1 + next(40);
            let expected = naive
                .iter()
                .any(|s| s.start <= range.start && range.end <= s.end);
            assert_eq!(spans.contains(&range), expected, "{range:?}");
            spans.insert(range.clone());
            naive.push(range);
        }
    }

    #[test]
    fn duplicate_partial_overlap_and_dominated_then_enclosing() {
        let mut spans = MatchedSpans::default();
        spans.insert(3..7);
        spans.insert(3..7);
        assert!(spans.contains(&(3..7)));
        assert!(!spans.contains(&(0..7)));
        spans.insert(20..24);
        spans.insert(10..30);
        assert!(spans.contains(&(12..29)));
        assert!(!spans.contains(&(9..12)));
    }

    #[test]
    fn large_disjoint_flood_stays_fast() {
        let mut spans = MatchedSpans::default();
        let start = std::time::Instant::now();
        for i in 0..300_000 {
            spans.insert(i * 2..i * 2 + 1);
        }
        for i in 0..300_000 {
            assert!(spans.contains(&(i * 2..i * 2 + 1)));
            assert!(!spans.contains(&(i * 2 + 1..i * 2 + 2)));
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(spans.ends_by_start.len(), 300_000);
    }
}
