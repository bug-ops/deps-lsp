//! Bounded-`DashMap` capacity policies shared across this crate's caches.
//!
//! Every eviction policy that governs a plain, per-entry-timestamped `DashMap<K, V>` memo
//! lives here, named, so a new cache in this crate reaches for an existing policy instead of
//! growing a near-duplicate (`github::ReleaseDatesCache` and `deps_dev`'s two memos each used
//! to carry their own copy of [`evict_expired_then_oldest`]'s body, and `osv::OsvClient`'s two
//! caches shared one local copy of [`evict_oldest_batch`]'s, before this module existed).
//! Ecosystem crates cannot reach `pub(crate)` items here; `deps-github-actions`,
//! `deps-gitlab-ci`, and `deps-npm` each still carry their own near-duplicate eviction helper,
//! tracked as a deferred follow-up rather than folded into this pass.
//!
//! [`crate::lockfile::LockFileCache`]'s eviction and [`crate::cache::HttpCache`]'s
//! byte-accounted eviction are deliberately **not** here:
//! - `LockFileCache` has no per-entry TTL, so [`evict_expired_then_oldest`]'s sweep half does
//!   not apply to it; its eviction logs a `warn!` naming the victim key, which a generic helper
//!   would have to thread through as another closure parameter; and its capacity is
//!   per-instance (`with_capacity`), not a shared const, so there is no knob here to unify.
//! - `HttpCache` tracks cumulative retained bytes (`total_bytes: AtomicUsize`) alongside entry
//!   count — state a plain `DashMap<K, V>` capacity policy has no field for — so folding it in
//!   would either lose that accounting or force every other caller to carry an unused field.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Percentage of a cache's capacity evicted when it is full, by [`evict_oldest_batch`] and by
/// [`crate::cache::HttpCache::evict_entries`] (which computes its own byte-budget analog of
/// this same fraction).
pub(crate) const CACHE_EVICTION_PERCENTAGE: usize = 10;

/// Evicts entries from `map` when it is already at `max_entries`, ahead of an insert that
/// would otherwise grow it further: first every entry expired against its own TTL, then —
/// only if that freed nothing — the single oldest entry by `fetched_at`.
pub(crate) fn evict_expired_then_oldest<K, V>(
    map: &DashMap<K, V>,
    max_entries: usize,
    fetched_at: impl Fn(&V) -> Instant,
    ttl: impl Fn(&V) -> Duration,
) where
    K: Eq + std::hash::Hash + Clone,
{
    if map.len() < max_entries {
        return;
    }
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(fetched_at(v)) < ttl(v));
    if map.len() >= max_entries
        && let Some(oldest) = map
            .iter()
            .min_by_key(|e| fetched_at(e.value()))
            .map(|e| e.key().clone())
    {
        map.remove(&oldest);
    }
}

/// Evicts the oldest `1/CACHE_EVICTION_PERCENTAGE` (see [`CACHE_EVICTION_PERCENTAGE`]) of
/// `max_entries` — i.e. of the cache's capacity, not necessarily of `map.len()` — by
/// `fetched_at`.
///
/// Caller must only invoke this when `map` is already at `max_entries`: unlike
/// [`evict_expired_then_oldest`], this does not check `map.len()` itself, so calling it
/// unconditionally on a map far below capacity can evict entries needlessly.
pub(crate) fn evict_oldest_batch<K, V>(
    map: &DashMap<K, V>,
    max_entries: usize,
    fetched_at: impl Fn(&V) -> Instant,
) where
    K: Eq + std::hash::Hash + Clone + Ord,
{
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let target_removals = (max_entries / CACHE_EVICTION_PERCENTAGE).max(1);
    let mut oldest: BinaryHeap<Reverse<(Instant, K)>> = map
        .iter()
        .map(|entry| Reverse((fetched_at(entry.value()), entry.key().clone())))
        .collect();

    for _ in 0..target_removals {
        let Some(Reverse((_, key))) = oldest.pop() else {
            break;
        };
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::{CACHE_EVICTION_PERCENTAGE, evict_oldest_batch};
    use dashmap::DashMap;
    use std::time::{Duration, Instant};

    struct Entry {
        fetched_at: Instant,
    }

    fn map_with_ages(count: usize) -> DashMap<usize, Entry> {
        let map = DashMap::new();
        let base = Instant::now();
        for i in 0..count {
            map.insert(
                i,
                Entry {
                    // Higher key => more recently fetched, so key `0` is oldest.
                    fetched_at: base + Duration::from_secs(i as u64),
                },
            );
        }
        map
    }

    #[test]
    fn removes_exactly_the_target_count() {
        let map = map_with_ages(100);
        evict_oldest_batch(&map, 100, |e| e.fetched_at);
        assert_eq!(map.len(), 90);
    }

    #[test]
    fn removes_oldest_entries_and_keeps_newest() {
        let map = map_with_ages(100);
        let target_removals = (100 / CACHE_EVICTION_PERCENTAGE).max(1);
        evict_oldest_batch(&map, 100, |e| e.fetched_at);

        for key in 0..target_removals {
            assert!(!map.contains_key(&key), "expected key {key} to be evicted");
        }
        for key in target_removals..100 {
            assert!(map.contains_key(&key), "expected key {key} to survive");
        }
    }

    #[test]
    fn floors_target_removals_at_one_below_percentage_threshold() {
        let map = map_with_ages(5);
        evict_oldest_batch(&map, 5, |e| e.fetched_at);
        assert_eq!(map.len(), 5 - 1);
        assert!(!map.contains_key(&0));
    }

    #[test]
    fn empties_without_panicking_when_smaller_than_target() {
        let map = map_with_ages(3);
        // max_entries is much larger than the map itself, so the target removal count
        // (max_entries / CACHE_EVICTION_PERCENTAGE) exceeds map.len().
        evict_oldest_batch(&map, 1000, |e| e.fetched_at);
        assert!(map.is_empty());
    }

    #[test]
    fn no_op_on_empty_map() {
        let map: DashMap<usize, Entry> = DashMap::new();
        evict_oldest_batch(&map, 1000, |e| e.fetched_at);
        assert!(map.is_empty());
    }

    #[test]
    fn removes_one_when_max_entries_equals_percentage() {
        let map = map_with_ages(CACHE_EVICTION_PERCENTAGE);
        evict_oldest_batch(&map, CACHE_EVICTION_PERCENTAGE, |e| e.fetched_at);
        assert_eq!(map.len(), CACHE_EVICTION_PERCENTAGE - 1);
        assert!(!map.contains_key(&0));
    }

    /// Exercises the `K: Ord` bound's only reason to exist: breaking a tie between two entries
    /// with the *same* `fetched_at`. Uses `String` keys (not `usize`) so key order cannot be
    /// mistaken for insertion order.
    #[test]
    fn ties_on_fetched_at_break_by_key_order() {
        let map: DashMap<String, Entry> = DashMap::new();
        let same_instant = Instant::now();
        map.insert(
            "b".to_string(),
            Entry {
                fetched_at: same_instant,
            },
        );
        map.insert(
            "a".to_string(),
            Entry {
                fetched_at: same_instant,
            },
        );

        evict_oldest_batch(&map, CACHE_EVICTION_PERCENTAGE, |e| e.fetched_at);

        assert!(
            !map.contains_key("a"),
            "the lexicographically smaller key breaks the tie"
        );
        assert!(map.contains_key("b"));
    }
}
