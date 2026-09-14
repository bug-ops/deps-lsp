//! Bounded-`DashMap` capacity policies shared across this crate's caches and, since this
//! module is `pub`, across ecosystem crates too.
//!
//! Every eviction policy that governs a plain, per-entry-timestamped `DashMap<K, V>` memo
//! lives here, named, so a new cache reaches for an existing policy instead of growing a
//! near-duplicate (`github::ReleaseDatesCache` and `deps_dev`'s two memos each used to carry
//! their own copy of [`crate::cache_policy::evict_expired_then_oldest`]'s body;
//! `osv::OsvClient`'s two caches shared one local copy of
//! [`crate::cache_policy::evict_oldest_batch`]'s; and `deps-github-actions`,
//! `deps-gitlab-ci`, and `deps-npm` each carried their own near-duplicate of
//! [`crate::cache_policy::evict_arbitrary_if_full`]/
//! [`crate::cache_policy::evict_expired_then_clear_all`]'s bodies, before this module
//! existed).
//!
//! [`crate::lockfile::LockFileCache`]'s eviction and [`crate::cache::HttpCache`]'s
//! byte-accounted eviction are deliberately **not** here:
//! - `LockFileCache` has no per-entry TTL, so
//!   [`crate::cache_policy::evict_expired_then_oldest`]'s sweep half does not apply to it;
//!   its eviction logs a `warn!` naming the victim key, which a generic helper
//!   would have to thread through as another closure parameter; and its capacity is
//!   per-instance (`with_capacity`), not a shared const, so there is no knob here to unify.
//! - `HttpCache` tracks cumulative retained bytes (`total_bytes: AtomicUsize`) alongside entry
//!   count — state a plain `DashMap<K, V>` capacity policy has no field for — so folding it in
//!   would either lose that accounting or force every other caller to carry an unused field.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Percentage of a cache's capacity evicted when it is full, by [`evict_oldest_batch`] and by
/// `crate::cache::HttpCache::evict_entries` (which computes its own byte-budget analog of
/// this same fraction).
pub const CACHE_EVICTION_PERCENTAGE: usize = 10;

/// Evicts entries from `map` when it is already at `max_entries`, ahead of an insert that
/// would otherwise grow it further.
///
/// First every entry expired against its own TTL, then — only if that freed nothing — the
/// single oldest entry by `fetched_at`.
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use deps_core::cache_policy::evict_expired_then_oldest;
/// use std::time::{Duration, Instant};
///
/// let map: DashMap<u32, Instant> = DashMap::new();
/// let now = Instant::now();
/// map.insert(1, now); // oldest
/// map.insert(2, now + Duration::from_secs(1));
///
/// // Neither entry is TTL-expired, so the single oldest one is evicted instead.
/// evict_expired_then_oldest(&map, 2, |fetched_at| *fetched_at, |_| Duration::from_secs(60));
///
/// assert!(!map.contains_key(&1));
/// assert!(map.contains_key(&2));
/// ```
pub fn evict_expired_then_oldest<K, V>(
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
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use deps_core::cache_policy::{CACHE_EVICTION_PERCENTAGE, evict_oldest_batch};
/// use std::time::{Duration, Instant};
///
/// let map: DashMap<u32, Instant> = DashMap::new();
/// let now = Instant::now();
/// for key in 0..CACHE_EVICTION_PERCENTAGE as u32 {
///     map.insert(key, now + Duration::from_secs(u64::from(key)));
/// }
///
/// // At capacity, 1/CACHE_EVICTION_PERCENTAGE of max_entries is evicted: here, just the
/// // single oldest entry (key `0`).
/// evict_oldest_batch(&map, CACHE_EVICTION_PERCENTAGE, |fetched_at| *fetched_at);
///
/// assert!(!map.contains_key(&0));
/// assert_eq!(map.len(), CACHE_EVICTION_PERCENTAGE - 1);
/// ```
pub fn evict_oldest_batch<K, V>(
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

/// Evicts a single arbitrary entry from `map` when it is already at `max_entries`, ahead of
/// an insert that would otherwise grow it further.
///
/// The victim is the single oldest-inserted entry, approximated by removing an arbitrary
/// entry: suited to a map with no per-entry timestamp (e.g. a tag/SHA cross-reference), where
/// a repeated fetch simply repopulates whichever entry was dropped. Reach for
/// [`evict_expired_then_oldest`] or [`evict_expired_then_clear_all`] instead when entries do
/// carry a `fetched_at`. The O(n) scan runs only on an insert that finds the map full.
///
/// **Must not be used for an in-flight coalescing lock map** (e.g. a
/// `DashMap<K, Arc<Mutex<()>>>` tracking requests currently in flight): removing an arbitrary
/// entry there can evict one whose lock is still held by another waiter, silently defeating
/// coalescing under exactly the load it targets. That case needs a policy that only evicts an
/// entry whose `Arc::strong_count()` is `1` — see `deps_github_actions::registry`'s
/// `evict_in_flight_if_full` for that pattern.
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use deps_core::cache_policy::evict_arbitrary_if_full;
///
/// let map: DashMap<u32, &str> = DashMap::new();
/// map.insert(1, "a");
/// map.insert(2, "b");
/// evict_arbitrary_if_full(&map, 2);
/// assert_eq!(map.len(), 1);
/// ```
pub fn evict_arbitrary_if_full<K, V>(map: &DashMap<K, V>, max_entries: usize)
where
    K: Eq + std::hash::Hash + Clone,
{
    if map.len() < max_entries {
        return;
    }
    // The victim key is resolved in its own `let` binding, fully dropping the iterator (and
    // whatever shard guard it holds) before `remove` runs — folding this into a single
    // `if let Some(key) = map.iter()....` risks the iterator's temporary being scope-extended
    // across the `remove` call (Rust's `if let` temporary-lifetime-extension rule), which can
    // deadlock against `DashMap`'s internal per-shard locking.
    let victim = map.iter().next().map(|e| e.key().clone());
    if let Some(key) = victim {
        map.remove(&key);
    }
}

/// Drops every entry in `map` expired against its own TTL; if that alone did not bring `map`
/// back under `max_entries`, clears the whole map.
///
/// Caller must only invoke this when `map` is already at `max_entries`: unlike
/// [`evict_expired_then_oldest`], this does not check `map.len()` itself before running the
/// TTL sweep, so calling it unconditionally on a map far below capacity discards expired
/// entries needlessly (though never live ones, since the sweep only ever removes entries
/// whose own TTL has elapsed).
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use deps_core::cache_policy::evict_expired_then_clear_all;
/// use std::time::{Duration, Instant};
///
/// let map: DashMap<u32, Instant> = DashMap::new();
/// map.insert(1, Instant::now());
/// evict_expired_then_clear_all(&map, 2, |fetched_at| *fetched_at, Duration::from_secs(60));
/// assert_eq!(map.len(), 1);
/// ```
pub fn evict_expired_then_clear_all<K, V>(
    map: &DashMap<K, V>,
    max_entries: usize,
    fetched_at: impl Fn(&V) -> Instant,
    ttl: Duration,
) where
    K: Eq + std::hash::Hash,
{
    let now = Instant::now();
    map.retain(|_, v| now.saturating_duration_since(fetched_at(v)) < ttl);
    if map.len() >= max_entries {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_EVICTION_PERCENTAGE, evict_arbitrary_if_full, evict_expired_then_clear_all,
        evict_oldest_batch,
    };
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

    // --- evict_arbitrary_if_full ---

    #[test]
    fn evict_arbitrary_if_full_removes_exactly_one_at_capacity() {
        let map: DashMap<u32, &str> = DashMap::new();
        map.insert(1, "a");
        map.insert(2, "b");
        evict_arbitrary_if_full(&map, 2);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn evict_arbitrary_if_full_below_capacity_is_a_no_op() {
        let map: DashMap<u32, &str> = DashMap::new();
        map.insert(1, "a");
        evict_arbitrary_if_full(&map, 2);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn evict_arbitrary_if_full_empty_map_is_a_no_op() {
        let map: DashMap<u32, &str> = DashMap::new();
        evict_arbitrary_if_full(&map, 2);
        assert!(map.is_empty());
    }

    // --- evict_expired_then_clear_all ---

    #[test]
    fn evict_expired_then_clear_all_drops_only_expired_entries() {
        let map: DashMap<&str, Instant> = DashMap::new();
        map.insert(
            "expired",
            Instant::now().checked_sub(Duration::from_secs(61)).unwrap(),
        );
        map.insert("fresh", Instant::now());

        evict_expired_then_clear_all(&map, 256, |v| *v, Duration::from_secs(60));

        assert!(!map.contains_key("expired"));
        assert!(map.contains_key("fresh"));
    }

    #[test]
    fn evict_expired_then_clear_all_clears_all_when_still_at_capacity_after_ttl_sweep() {
        let map: DashMap<usize, Instant> = DashMap::new();
        let max_entries = 8;
        for i in 0..max_entries {
            map.insert(i, Instant::now());
        }

        evict_expired_then_clear_all(&map, max_entries, |v| *v, Duration::from_secs(60));

        assert!(map.is_empty());
    }
}
