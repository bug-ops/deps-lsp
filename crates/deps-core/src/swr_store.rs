//! A bounded stale-while-revalidate store shared by the git-evidence stores and Swift's
//! repository-identity memo.
//!
//! Reads keep serving an entry past its TTL and report it [`Freshness::Stale`], so the caller
//! can schedule a refresh without ever dropping a known answer. Capacity and idle eviction are
//! O(log n): recency lives in an ordered tick index instead of a scan of every entry.
//!
//! Recency order uses an internal tick counter, never a caller-supplied [`Instant`]. Idle
//! eviction compares the caller's `now` with each entry's last read and pops from the oldest
//! tick until it reaches an entry that is not idle. With a non-monotonic `now` across threads
//! this can leave an idle entry behind a younger one until a later write; it is evicted then.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::mem;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Whether a read value is still within its TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The value is younger than the TTL, or the store has no TTL.
    Fresh,
    /// The TTL has passed; the value is served while a refresh is scheduled.
    Stale,
}

/// Which operations make an entry the most recently used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recency {
    /// Reads and writes both refresh recency.
    ReadsAndWrites,
    /// Only reads (and the first insert of a key) refresh recency; rewriting a value does not.
    ReadsOnly,
}

/// How a [`SwrStore`] bounds and ages its entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwrPolicy {
    /// Most entries kept; the least recently used are evicted first.
    pub capacity: NonZeroUsize,
    /// Age at which an entry turns [`Freshness::Stale`]; `None` never expires.
    pub ttl: Option<Duration>,
    /// Time without a read after which an entry is evicted; `None` keeps idle entries.
    pub idle: Option<Duration>,
    /// What counts as use for eviction order.
    pub recency: Recency,
}

/// A value read from a [`SwrStore`] and its freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwrRead<V> {
    /// The stored value.
    pub value: V,
    /// Whether it is within the TTL.
    pub freshness: Freshness,
}

/// The outcome of [`SwrStore::upsert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upserted<V> {
    /// The key was absent.
    Inserted,
    /// The key held `previous`, which the new value replaced.
    Replaced {
        /// The value that was there.
        previous: V,
    },
}

/// The outcome of [`SwrStore::refresh_or_insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refreshed {
    /// The key held a value, which was kept and had its TTL restarted.
    Kept,
    /// The key was absent and the fallback value was inserted.
    Inserted,
}

#[derive(Debug)]
struct Slot<V> {
    value: V,
    refreshed_at: Instant,
    last_read: Instant,
    tick: u64,
}

#[derive(Debug)]
struct Inner<K, V> {
    entries: HashMap<K, Slot<V>>,
    order: BTreeMap<u64, K>,
    next_tick: u64,
}

impl<K: Hash + Eq + Clone, V> Inner<K, V> {
    fn take_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick += 1;
        tick
    }

    fn insert_new(&mut self, key: K, value: V, now: Instant) {
        let tick = self.take_tick();
        self.order.insert(tick, key.clone());
        self.entries.insert(
            key,
            Slot {
                value,
                refreshed_at: now,
                last_read: now,
                tick,
            },
        );
    }

    fn touch(&mut self, key: &K, now: Instant) {
        let tick = self.take_tick();
        if let Some(slot) = self.entries.get_mut(key) {
            self.order.remove(&slot.tick);
            slot.tick = tick;
            slot.last_read = now;
            self.order.insert(tick, key.clone());
        }
    }

    fn oldest(&self) -> Option<&Slot<V>> {
        let (_, key) = self.order.first_key_value()?;
        self.entries.get(key)
    }

    fn evict_oldest(&mut self) {
        if let Some((_, key)) = self.order.pop_first() {
            self.entries.remove(&key);
        }
    }

    fn evict(&mut self, policy: &SwrPolicy, now: Instant) {
        if let Some(idle) = policy.idle {
            while self
                .oldest()
                .is_some_and(|slot| now.saturating_duration_since(slot.last_read) > idle)
            {
                self.evict_oldest();
            }
        }
        while self.entries.len() > policy.capacity.get() {
            self.evict_oldest();
        }
    }
}

/// A bounded map with TTL staleness, idle eviction and least-recently-used capacity eviction.
///
/// Every operation takes one short lock, never held across an `.await`; a poisoned lock is
/// recovered, since no operation leaves the maps half-updated.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroUsize;
/// use std::time::{Duration, Instant};
/// use deps_core::swr_store::{Freshness, Recency, SwrPolicy, SwrStore, Upserted};
///
/// let store = SwrStore::new(SwrPolicy {
///     capacity: NonZeroUsize::new(2).unwrap(),
///     ttl: Some(Duration::from_secs(60)),
///     idle: None,
///     recency: Recency::ReadsAndWrites,
/// });
/// let now = Instant::now();
/// assert_eq!(store.upsert("a", 1, now), Upserted::Inserted);
/// let later = now + Duration::from_secs(61);
/// assert_eq!(store.get(&"a", later).unwrap().freshness, Freshness::Stale);
/// assert_eq!(store.get_fresh(&"a", later), None);
/// ```
#[derive(Debug)]
pub struct SwrStore<K, V> {
    policy: SwrPolicy,
    inner: Mutex<Inner<K, V>>,
}

impl<K: Hash + Eq + Clone, V: Clone> SwrStore<K, V> {
    /// An empty store governed by `policy`.
    #[must_use]
    pub fn new(policy: SwrPolicy) -> Self {
        Self {
            policy,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                order: BTreeMap::new(),
                next_tick: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<K, V>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn freshness_of(&self, slot: &Slot<V>, now: Instant) -> Freshness {
        match self.policy.ttl {
            Some(ttl) if now.saturating_duration_since(slot.refreshed_at) >= ttl => {
                Freshness::Stale
            }
            Some(_) | None => Freshness::Fresh,
        }
    }

    /// The value for `key` and its freshness, marking it read at `now`.
    #[must_use]
    pub fn get(&self, key: &K, now: Instant) -> Option<SwrRead<V>> {
        let mut inner = self.lock();
        let slot = inner.entries.get(key)?;
        let read = SwrRead {
            value: slot.value.clone(),
            freshness: self.freshness_of(slot, now),
        };
        inner.touch(key, now);
        Some(read)
    }

    /// The value for `key` only while it is fresh. A stale or absent entry is `None` and a stale
    /// one is not marked read, so asking to refresh it does not keep it alive.
    #[must_use]
    pub fn get_fresh(&self, key: &K, now: Instant) -> Option<V> {
        let mut inner = self.lock();
        let slot = inner.entries.get(key)?;
        if self.freshness_of(slot, now) == Freshness::Stale {
            return None;
        }
        let value = slot.value.clone();
        inner.touch(key, now);
        Some(value)
    }

    /// Stores `value` under `key` as a fresh entry, then evicts beyond the policy.
    pub fn upsert(&self, key: K, value: V, now: Instant) -> Upserted<V> {
        let mut inner = self.lock();
        let outcome = match inner.entries.get_mut(&key) {
            Some(slot) => {
                slot.refreshed_at = now;
                let previous = mem::replace(&mut slot.value, value);
                if self.policy.recency == Recency::ReadsAndWrites {
                    inner.touch(&key, now);
                }
                Upserted::Replaced { previous }
            }
            None => {
                inner.insert_new(key, value, now);
                Upserted::Inserted
            }
        };
        inner.evict(&self.policy, now);
        outcome
    }

    /// Restarts the TTL of the value held for `key`, or inserts `if_absent` when there is none,
    /// then evicts beyond the policy. A known value is never replaced.
    pub fn refresh_or_insert(&self, key: K, if_absent: V, now: Instant) -> Refreshed {
        let mut inner = self.lock();
        let outcome = match inner.entries.get_mut(&key) {
            Some(slot) => {
                slot.refreshed_at = now;
                if self.policy.recency == Recency::ReadsAndWrites {
                    inner.touch(&key, now);
                }
                Refreshed::Kept
            }
            None => {
                inner.insert_new(key, if_absent, now);
                Refreshed::Inserted
            }
        };
        inner.evict(&self.policy, now);
        outcome
    }

    /// Calls `visit` for every entry, in no particular order, without marking any as read.
    ///
    /// `visit` runs under the store's lock: re-entering the store from it deadlocks.
    pub fn scan(&self, mut visit: impl FnMut(&K, &V)) {
        for (key, slot) in &self.lock().entries {
            visit(key, &slot.value);
        }
    }

    /// Number of stored entries, stale ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether no entry is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const TTL: Duration = Duration::from_secs(60);

    fn policy(capacity: usize, recency: Recency) -> SwrPolicy {
        SwrPolicy {
            capacity: NonZeroUsize::new(capacity).unwrap(),
            ttl: Some(TTL),
            idle: None,
            recency,
        }
    }

    fn store(capacity: usize, recency: Recency) -> SwrStore<u32, u32> {
        SwrStore::new(policy(capacity, recency))
    }

    fn after(now: Instant, secs: u64) -> Instant {
        now + Duration::from_secs(secs)
    }

    #[test]
    fn a_read_past_the_ttl_is_stale_but_still_served() {
        let s = store(4, Recency::ReadsAndWrites);
        let now = Instant::now();
        s.upsert(1, 10, now);

        let fresh = s.get(&1, after(now, 59)).unwrap();
        assert_eq!(fresh.freshness, Freshness::Fresh);
        let stale = s.get(&1, after(now, 60)).unwrap();
        assert_eq!((stale.value, stale.freshness), (10, Freshness::Stale));
    }

    #[test]
    fn get_fresh_on_a_stale_entry_is_none_and_does_not_touch() {
        let s = store(2, Recency::ReadsOnly);
        let now = Instant::now();
        s.upsert(1, 10, now);
        s.upsert(2, 20, now);
        assert_eq!(s.get_fresh(&1, after(now, 61)), None);

        s.upsert(3, 30, after(now, 62));
        assert_eq!(
            s.get(&1, after(now, 62)),
            None,
            "key 1 was still the oldest"
        );
        assert!(s.get(&2, after(now, 62)).is_some());
    }

    #[test]
    fn writes_touch_only_under_reads_and_writes() {
        for (recency, evicted) in [(Recency::ReadsAndWrites, 2), (Recency::ReadsOnly, 1)] {
            let s = store(2, recency);
            let now = Instant::now();
            s.upsert(1, 10, now);
            s.upsert(2, 20, now);
            s.upsert(1, 11, now);
            s.upsert(3, 30, now);
            assert_eq!(s.get(&evicted, now), None, "{recency:?}");
            assert_eq!(s.len(), 2);
        }
    }

    #[test]
    fn upsert_reports_the_replaced_value() {
        let s = store(2, Recency::ReadsAndWrites);
        let now = Instant::now();
        assert_eq!(s.upsert(1, 10, now), Upserted::Inserted);
        assert_eq!(s.upsert(1, 11, now), Upserted::Replaced { previous: 10 });
    }

    #[test]
    fn refresh_or_insert_keeps_a_known_value_and_restarts_its_ttl() {
        let s = store(2, Recency::ReadsOnly);
        let now = Instant::now();
        assert_eq!(s.refresh_or_insert(1, 0, now), Refreshed::Inserted);
        s.upsert(1, 10, now);
        assert_eq!(s.refresh_or_insert(1, 0, after(now, 61)), Refreshed::Kept);
        let read = s.get(&1, after(now, 62)).unwrap();
        assert_eq!((read.value, read.freshness), (10, Freshness::Fresh));
    }

    #[test]
    fn entries_unread_past_the_idle_window_are_evicted_by_the_next_write() {
        let s = SwrStore::new(SwrPolicy {
            idle: Some(Duration::from_secs(100)),
            ..policy(8, Recency::ReadsOnly)
        });
        let now = Instant::now();
        s.upsert(1, 10, now);
        s.upsert(2, 20, now);
        assert!(s.get(&2, after(now, 100)).is_some());

        s.upsert(3, 30, after(now, 101));
        assert_eq!(s.get(&1, after(now, 101)), None);
        assert!(s.get(&2, after(now, 101)).is_some());
    }

    #[test]
    fn scan_visits_every_entry_without_touching() {
        let s = store(2, Recency::ReadsOnly);
        let now = Instant::now();
        s.upsert(1, 10, now);
        s.upsert(2, 20, now);
        let mut seen = Vec::new();
        s.scan(|key, value| seen.push((*key, *value)));
        seen.sort_unstable();
        assert_eq!(seen, [(1, 10), (2, 20)]);

        s.upsert(3, 30, now);
        assert_eq!(s.get(&1, now), None, "scan did not refresh key 1");
    }

    fn keys(s: &SwrStore<u32, u32>) -> Vec<u32> {
        let mut keys = Vec::new();
        s.scan(|key, _| keys.push(*key));
        keys.sort_unstable();
        keys
    }

    #[test]
    fn capacity_eviction_removes_exactly_the_least_recently_used_keys() {
        for (recency, survivors) in [
            (Recency::ReadsAndWrites, [1, 2, 5, 6]),
            (Recency::ReadsOnly, [1, 4, 5, 6]),
        ] {
            let s = store(4, recency);
            let now = Instant::now();
            for key in 1..=4 {
                s.upsert(key, key, now);
            }
            drop(s.get(&1, now));
            s.upsert(2, 20, now);
            s.upsert(5, 5, now);
            s.upsert(6, 6, now);
            assert_eq!(keys(&s), survivors, "{recency:?}");
        }
    }

    #[test]
    fn without_ttl_or_idle_nothing_goes_stale_or_idle() {
        let s = SwrStore::new(SwrPolicy {
            ttl: None,
            idle: None,
            ..policy(4, Recency::ReadsOnly)
        });
        let now = Instant::now();
        s.upsert(1, 10, now);
        let far = after(now, 60 * 60 * 24 * 365);
        s.upsert(2, 20, far);
        let read = s.get(&1, far).unwrap();
        assert_eq!((read.value, read.freshness), (10, Freshness::Fresh));
        assert_eq!(s.get_fresh(&1, far), Some(10));
        assert_eq!(keys(&s), [1, 2]);
    }

    #[test]
    fn with_ttl_and_idle_an_entry_is_stale_before_it_is_idle_and_a_read_resets_idle() {
        let s = SwrStore::new(SwrPolicy {
            ttl: Some(Duration::from_secs(60)),
            idle: Some(Duration::from_secs(100)),
            ..policy(4, Recency::ReadsOnly)
        });
        let now = Instant::now();
        s.upsert(1, 10, now);
        let stale = s.get(&1, after(now, 61)).unwrap();
        assert_eq!(stale.freshness, Freshness::Stale);

        s.upsert(2, 20, after(now, 150));
        assert_eq!(keys(&s), [1, 2], "the read at 61 restarted the idle window");
        s.upsert(3, 30, after(now, 162));
        assert_eq!(keys(&s), [2, 3], "idle for more than 100 s after that read");
    }

    #[test]
    fn recency_follows_access_order_not_the_callers_instants() {
        for (first, second, third) in [(100, 0, 50), (7, 7, 7)] {
            let s = store(2, Recency::ReadsAndWrites);
            let start = Instant::now();
            s.upsert(1, 1, after(start, first));
            s.upsert(2, 2, after(start, second));
            s.upsert(3, 3, after(start, third));
            assert_eq!(
                keys(&s),
                [2, 3],
                "key 1 was accessed first ({first}, {second}, {third})"
            );

            drop(s.get(&2, start));
            s.upsert(4, 4, after(start, 1000));
            assert_eq!(keys(&s), [2, 4], "key 3 is now the least recently used");
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Get(u8),
        GetFresh(u8),
        Upsert(u8),
        Refresh(u8),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..12u8).prop_map(Op::Get),
            (0..12u8).prop_map(Op::GetFresh),
            (0..12u8).prop_map(Op::Upsert),
            (0..12u8).prop_map(Op::Refresh),
        ]
    }

    proptest! {
        #[test]
        fn the_tick_index_and_the_entries_stay_in_sync(
            ops in proptest::collection::vec(op(), 0..200),
            reads_and_writes in any::<bool>(),
        ) {
            let recency = if reads_and_writes { Recency::ReadsAndWrites } else { Recency::ReadsOnly };
            let s: SwrStore<u8, u8> = SwrStore::new(SwrPolicy {
                idle: Some(Duration::from_secs(5)),
                ..policy(4, recency)
            });
            let start = Instant::now();
            for (step, op) in ops.into_iter().enumerate() {
                let now = after(start, u64::try_from(step).unwrap());
                match op {
                    Op::Get(k) => drop(s.get(&k, now)),
                    Op::GetFresh(k) => drop(s.get_fresh(&k, now)),
                    Op::Upsert(k) => { s.upsert(k, k, now); }
                    Op::Refresh(k) => { s.refresh_or_insert(k, k, now); }
                }
                let inner = s.lock();
                prop_assert_eq!(inner.entries.len(), inner.order.len());
                prop_assert!(inner.entries.len() <= 4);
                for (tick, key) in &inner.order {
                    prop_assert_eq!(inner.entries.get(key).map(|slot| slot.tick), Some(*tick));
                }
            }
        }
    }
}
