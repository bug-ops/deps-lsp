//! Generic TTL-memoized, optionally in-flight-coalesced storage for a deps.dev call outcome.
//!
//! [`CallOutcome`] replaces the `(value, ttl, completeness)` tuple every `deps_dev` memo used to
//! carry independently — deriving the TTL from the outcome via [`TtlPolicy`] instead of storing
//! it alongside makes a mismatched pairing (e.g. the success TTL paired with an incomplete
//! result) unrepresentable. [`TtlMemo`] is the plain, uncoalesced storage layer every memo in
//! this client uses; [`CoalescedMemo`] layers `coalesce`'s in-flight join on top of it for the
//! three memos where a losing concurrent caller must await the winner's result rather than
//! re-fetching (issue #1454).

use std::future::Future;
use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::watch;

use super::FetchCompleteness;
use crate::cache_policy::evict_expired_then_oldest;

/// The outcome of one deps.dev call evaluation, carrying its own completeness rather than a
/// completeness flag stored alongside a plain value.
///
/// Both variants carry a payload: a partial result is a real, legitimate outcome for some
/// evaluations (e.g. [`super::DepsDevClient::fetch`]'s `Degraded(Some(signal))` when the version
/// call succeeds but the project call fails), not merely a placeholder for "nothing" — a
/// payload-less `Degraded` variant would be unable to represent that case.
#[derive(Debug, Clone)]
pub(super) enum CallOutcome<V> {
    /// Every call this evaluation needed returned a definitive answer.
    Definitive(V),
    /// At least one call failed, timed out, or returned unparseable data.
    Degraded(V),
}

impl<V> CallOutcome<V> {
    /// The [`FetchCompleteness`] this outcome corresponds to.
    pub(super) const fn completeness(&self) -> FetchCompleteness {
        match self {
            Self::Definitive(_) => FetchCompleteness::Complete,
            Self::Degraded(_) => FetchCompleteness::Incomplete,
        }
    }

    /// Discards the completeness, keeping only the value.
    pub(super) fn into_value(self) -> V {
        match self {
            Self::Definitive(value) | Self::Degraded(value) => value,
        }
    }

    /// Splits this outcome into a caller-facing `(value, completeness)` pair — the shape every
    /// public method on [`super::DepsDevClient`] returning a completeness marker exposes.
    pub(super) fn into_parts(self) -> (V, FetchCompleteness) {
        let completeness = self.completeness();
        (self.into_value(), completeness)
    }

    /// Builds an outcome from an already-known `completeness`, for a call site that combines two
    /// sub-results (e.g. a version call's provenance plus a separately-resolved project score)
    /// rather than reporting one call's own pass/fail directly.
    pub(super) const fn with_completeness(value: V, completeness: FetchCompleteness) -> Self {
        match completeness {
            FetchCompleteness::Complete => Self::Definitive(value),
            FetchCompleteness::Incomplete => Self::Degraded(value),
        }
    }
}

/// The TTL a [`TtlMemo`] applies to a [`CallOutcome::Definitive`] vs. a [`CallOutcome::Degraded`]
/// entry — the two `Duration` constants every deps.dev/GOSSIP memo used to plumb through
/// independently, now bound together with the outcome kind they apply to.
#[derive(Debug, Clone, Copy)]
pub(super) struct TtlPolicy {
    definitive: Duration,
    degraded: Duration,
}

impl TtlPolicy {
    /// Builds a policy from its two TTLs.
    pub(super) const fn new(definitive: Duration, degraded: Duration) -> Self {
        Self {
            definitive,
            degraded,
        }
    }

    /// The TTL `outcome`'s own kind maps to.
    pub(super) const fn ttl_for<V>(&self, outcome: &CallOutcome<V>) -> Duration {
        match outcome {
            CallOutcome::Definitive(_) => self.definitive,
            CallOutcome::Degraded(_) => self.degraded,
        }
    }
}

/// [`TtlPolicy`] for every plain deps.dev call (trust signal, project score, similarity,
/// popularity) — matches [`super::DEPS_DEV_SUCCESS_TTL`]/[`super::DEPS_DEV_ERROR_TTL`]'s
/// long-standing values.
pub(super) const DEPS_DEV_TTLS: TtlPolicy =
    TtlPolicy::new(super::DEPS_DEV_SUCCESS_TTL, super::DEPS_DEV_ERROR_TTL);

/// [`TtlPolicy`] for GOSSIP calls — matches
/// [`super::GOSSIP_SUCCESS_TTL`]/[`super::GOSSIP_ERROR_TTL`]'s long-standing values.
pub(super) const GOSSIP_TTLS: TtlPolicy =
    TtlPolicy::new(super::GOSSIP_SUCCESS_TTL, super::GOSSIP_ERROR_TTL);

/// Entry-count bound every [`TtlMemo`] enforces, mirroring `github::MAX_RELEASE_DATES_MEMO_ENTRIES`'s
/// reasoning: comfortably above the distinct-package count of any realistic workspace.
const MAX_MEMO_ENTRIES: usize = super::MAX_MEMO_ENTRIES;

/// One stored [`TtlMemo`] entry: when it was written, and the outcome it holds.
struct MemoSlot<V> {
    fetched_at: Instant,
    outcome: CallOutcome<V>,
}

/// Plain, uncoalesced TTL memo over `K -> CallOutcome<V>` — the storage layer shared by every
/// memo in [`super::DepsDevClient`], coalesced ([`CoalescedMemo`]) or not.
pub(super) struct TtlMemo<K, V> {
    entries: DashMap<K, MemoSlot<V>>,
    policy: TtlPolicy,
}

impl<K, V> TtlMemo<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Creates an empty memo governed by `policy`.
    pub(super) fn new(policy: TtlPolicy) -> Self {
        Self {
            entries: DashMap::new(),
            policy,
        }
    }

    /// Returns `key`'s outcome if an entry exists and is still within its own TTL.
    pub(super) fn get_fresh(&self, key: &K) -> Option<CallOutcome<V>> {
        let entry = self.entries.get(key)?;
        (entry.fetched_at.elapsed() < self.policy.ttl_for(&entry.outcome))
            .then(|| entry.outcome.clone())
    }

    /// Stores `outcome` under `key`, evicting first ([`evict_expired_then_oldest`]) when this is
    /// a new key and the memo is already at [`MAX_MEMO_ENTRIES`].
    pub(super) fn insert(&self, key: K, outcome: CallOutcome<V>) {
        if !self.entries.contains_key(&key) {
            evict_expired_then_oldest(
                &self.entries,
                MAX_MEMO_ENTRIES,
                |s| s.fetched_at,
                |s| self.policy.ttl_for(&s.outcome),
            );
        }
        self.entries.insert(
            key,
            MemoSlot {
                fetched_at: Instant::now(),
                outcome,
            },
        );
    }

    /// Evicts `key`'s entry, if any — used to force a re-fetch ahead of its natural TTL
    /// expiry (e.g. [`super::DepsDevClient::force_refresh_gossip_findings`]).
    pub(super) fn remove(&self, key: &K) {
        self.entries.remove(key);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn ttl_of(&self, key: &K) -> Option<Duration> {
        self.entries
            .get(key)
            .map(|e| self.policy.ttl_for(&e.outcome))
    }
}

/// A [`coalesce`] watch-channel payload: "leader hasn't finished yet" vs. "leader finished with
/// `T`". A dedicated enum rather than `Option<T>` (clippy `option_option`): every current
/// [`CoalescedMemo`] instantiates `T` as `CallOutcome<Option<_>>`, which would otherwise nest as
/// `Option<Option<_>>`.
#[derive(Debug, Clone)]
pub(super) enum Slot<T> {
    /// The leader's `fetch` has not completed (or panicked) yet.
    Pending,
    /// The leader's `fetch` completed with this value.
    Ready(T),
}

/// Releases an in-flight claim on drop — including on panic — so a claim can never leak and
/// permanently block later calls for the same key.
struct InFlightGuard<'a, K: Hash + Eq, W> {
    map: &'a DashMap<K, W>,
    key: K,
}

impl<K: Hash + Eq, W> Drop for InFlightGuard<'_, K, W> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// Either claims `key` as the leader (installing a fresh, `Pending` channel) or joins as a
/// follower of whichever channel the current leader already installed — a plain, synchronous
/// function so the returned [`Entry`] guard is dropped before [`coalesce`] ever reaches an
/// `.await` (this workspace's `clippy.toml` denies holding one across an await point on
/// principle, regardless of whether a given case is provably safe).
fn claim_or_follow<K, T>(
    in_flight: &DashMap<K, watch::Receiver<Slot<T>>>,
    key: K,
) -> Result<watch::Sender<Slot<T>>, watch::Receiver<Slot<T>>>
where
    K: Hash + Eq,
{
    match in_flight.entry(key) {
        Entry::Occupied(occupied) => Err(occupied.get().clone()),
        Entry::Vacant(vacant) => {
            let (tx, rx) = watch::channel(Slot::Pending);
            vacant.insert(rx);
            Ok(tx)
        }
    }
}

/// Bounds how many times [`coalesce`] takes over as a new leader after the previous one was
/// cancelled before sending (issue #1455 critic S2), so a leader that keeps getting cancelled (or
/// keeps panicking deterministically) cannot loop forever — the last attempt's caller either
/// produces a real value or lets a genuine panic propagate to its own task, and every caller that
/// loses that final round gets `None` back.
const MAX_COALESCE_TAKEOVER_ATTEMPTS: u8 = 2;

/// Coalesces concurrent callers for the same in-flight `key`: the first caller (the leader) runs
/// `fetch` and broadcasts its result to every other concurrent caller for the same key (the
/// followers) via a [`watch`] channel, instead of a follower returning a default value
/// immediately (issue #1454).
///
/// A follower whose leader is cancelled — it panics, or the task calling `coalesce` is
/// `AbortHandle::abort()`-ed by something outside this function — takes over as the new leader
/// and calls `fetch` itself instead of silently giving up (issue #1455 critic S2). Bounded by
/// [`MAX_COALESCE_TAKEOVER_ATTEMPTS`]; `in_flight`'s entry for `key` is removed on every path
/// (including a panic or abort), via [`InFlightGuard`]'s `Drop` impl.
///
/// Returns `None` when every takeover attempt was exhausted without ever resolving a real
/// outcome — the caller ([`CoalescedMemo::get_or_fetch`]) maps that explicitly to a degraded
/// fallback rather than relying on a `Default` value to silently mean failure.
async fn coalesce<K, T, F, Fut>(
    in_flight: &DashMap<K, watch::Receiver<Slot<T>>>,
    key: K,
    fetch: F,
) -> Option<T>
where
    K: Hash + Eq + Clone + Send + Sync,
    T: Clone + Send + Sync,
    F: Fn() -> Fut + Send,
    Fut: Future<Output = T> + Send,
{
    for attempt in 0..=MAX_COALESCE_TAKEOVER_ATTEMPTS {
        match claim_or_follow(in_flight, key.clone()) {
            Ok(tx) => {
                let _guard = InFlightGuard {
                    map: in_flight,
                    key,
                };
                let value = fetch().await;
                let _ = tx.send(Slot::Ready(value.clone()));
                return Some(value);
            }
            Err(mut rx) => loop {
                let slot = rx.borrow_and_update().clone();
                if let Slot::Ready(value) = slot {
                    return Some(value);
                }
                if rx.changed().await.is_err() {
                    tracing::debug!(
                        attempt,
                        "coalesce: in-flight leader was cancelled before completing; taking \
                         over as leader"
                    );
                    break;
                }
            },
        }
    }

    tracing::debug!(
        "coalesce: gave up after {} leader-takeover attempts; giving up",
        MAX_COALESCE_TAKEOVER_ATTEMPTS + 1
    );
    None
}

/// A [`TtlMemo`] with in-flight join for concurrent misses on the same key (issue #1454) — the
/// storage shape for the three deps.dev memos where a losing concurrent caller must await the
/// winner's result rather than degrading immediately: the trust-signal (project) memo, the
/// similarity memo, and the popularity memo. Deliberately **not** used for the plain `projects`
/// memo or the version-scoped GOSSIP memo — coalescing those would change their existing,
/// intentionally uncoalesced behavior.
pub(super) struct CoalescedMemo<K, V> {
    memo: TtlMemo<K, V>,
    in_flight: DashMap<K, watch::Receiver<Slot<CallOutcome<V>>>>,
}

impl<K, V> CoalescedMemo<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Default + Send + Sync,
{
    /// Creates an empty, empty-in-flight memo governed by `policy`.
    pub(super) fn new(policy: TtlPolicy) -> Self {
        Self {
            memo: TtlMemo::new(policy),
            in_flight: DashMap::new(),
        }
    }

    /// Returns `key`'s memoized outcome if still fresh; otherwise runs `fetch` — coalesced with
    /// any other concurrent caller for the same `key` — stores its outcome, and returns it.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Internal to deps_dev; not part of the crate's public API.
    /// let outcome = memo.get_or_fetch(key, || async { CallOutcome::Definitive(42) }).await;
    /// ```
    pub(super) async fn get_or_fetch<F, Fut>(&self, key: K, fetch: F) -> CallOutcome<V>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = CallOutcome<V>> + Send,
    {
        if let Some(outcome) = self.memo.get_fresh(&key) {
            return outcome;
        }

        coalesce(&self.in_flight, key.clone(), || async {
            // Re-check the memo now that this call has actually won the leader claim (issue
            // #1455 critic M1): a leader that finished and wrote the memo between the check
            // above and this call's claim attempt would otherwise cost a wholly avoidable
            // duplicate fetch.
            if let Some(outcome) = self.memo.get_fresh(&key) {
                return outcome;
            }
            let outcome = fetch().await;
            self.memo.insert(key.clone(), outcome.clone());
            outcome
        })
        .await
        .unwrap_or_else(|| CallOutcome::Degraded(V::default()))
    }

    #[cfg(test)]
    pub(super) const fn memo(&self) -> &TtlMemo<K, V> {
        &self.memo
    }

    #[cfg(test)]
    pub(super) fn in_flight_contains(&self, key: &K) -> bool {
        self.in_flight.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesce_leader_panic_lets_follower_take_over_and_recover_real_value() {
        let map: Arc<DashMap<u32, watch::Receiver<Slot<u32>>>> = Arc::new(DashMap::new());

        let leader_map = Arc::clone(&map);
        let leader = tokio::spawn(async move {
            coalesce(&leader_map, 1u32, || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                panic!("leader fetch panics");
                #[allow(unreachable_code)]
                0u32
            })
            .await
        });

        // Give the leader time to claim the in-flight entry before the follower starts.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let follower = coalesce(&map, 1u32, || async { 99u32 }).await;

        assert!(
            leader.await.is_err(),
            "the leader's own task must observe the panic"
        );
        assert_eq!(
            follower,
            Some(99),
            "a follower whose leader panicked must take over and recover the real value from \
             its own fetch, never deadlock, panic itself, or silently give up"
        );
        assert!(
            !map.contains_key(&1u32),
            "the in-flight entry must be cleaned up after the leader panic and the follower's \
             own successful takeover"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesce_aborted_leader_lets_follower_take_over_and_recover_real_value() {
        let map: Arc<DashMap<u32, watch::Receiver<Slot<u32>>>> = Arc::new(DashMap::new());

        let leader_map = Arc::clone(&map);
        let leader = tokio::spawn(async move {
            coalesce(&leader_map, 1u32, || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                0u32
            })
            .await
        });
        // Give the leader time to claim the in-flight entry.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let follower_map = Arc::clone(&map);
        let follower =
            tokio::spawn(async move { coalesce(&follower_map, 1u32, || async { 7u32 }).await });
        // Give the follower time to join (see the Occupied entry and start waiting on
        // `changed()`) before the leader is cancelled out from under it.
        tokio::time::sleep(Duration::from_millis(10)).await;

        leader.abort();

        let follower_result = follower.await.expect("follower task must not panic");
        assert_eq!(
            follower_result,
            Some(7),
            "a follower whose leader was aborted (not panicked) must take over and recover the \
             real value from its own fetch, not silently give up"
        );
        assert!(
            !map.contains_key(&1u32),
            "the in-flight entry must be cleaned up after the leader's abort and the \
             follower's own successful takeover"
        );
    }

    #[tokio::test]
    async fn get_or_fetch_memo_hit_skips_fetch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let memo: CoalescedMemo<u32, u32> = CoalescedMemo::new(TtlPolicy::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let calls = Arc::new(AtomicUsize::new(0));

        let call_a = Arc::clone(&calls);
        let first = memo
            .get_or_fetch(1u32, || {
                let call_a = Arc::clone(&call_a);
                async move {
                    call_a.fetch_add(1, Ordering::SeqCst);
                    CallOutcome::Definitive(42u32)
                }
            })
            .await;
        assert_eq!(first.into_value(), 42);

        let call_b = Arc::clone(&calls);
        let second = memo
            .get_or_fetch(1u32, || {
                let call_b = Arc::clone(&call_b);
                async move {
                    call_b.fetch_add(1, Ordering::SeqCst);
                    CallOutcome::Definitive(0u32)
                }
            })
            .await;
        assert_eq!(
            second.into_value(),
            42,
            "the memo hit must serve the cached value"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh memo hit must never call fetch again"
        );
    }

    #[tokio::test]
    async fn get_or_fetch_degraded_expires_on_the_shorter_degraded_ttl() {
        let memo: CoalescedMemo<u32, u32> = CoalescedMemo::new(TtlPolicy::new(
            Duration::from_secs(60),
            Duration::from_millis(20),
        ));

        let outcome = memo
            .get_or_fetch(1u32, || async { CallOutcome::Degraded(0u32) })
            .await;
        assert!(matches!(outcome, CallOutcome::Degraded(0)));
        assert!(memo.memo().get_fresh(&1u32).is_some());

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            memo.memo().get_fresh(&1u32).is_none(),
            "a Degraded entry must expire on the shorter degraded TTL, not the definitive one"
        );
    }

    #[tokio::test]
    async fn get_or_fetch_exhaustion_returns_degraded_default() {
        let in_flight: DashMap<u32, watch::Receiver<Slot<CallOutcome<u32>>>> = DashMap::new();
        // Pre-occupies the in-flight slot with a channel whose sender is already dropped, so
        // every `claim_or_follow` call joins as a follower whose `changed()` immediately errors
        // — exhausting every takeover attempt without ever producing a real outcome.
        let (tx, rx) = watch::channel(Slot::<CallOutcome<u32>>::Pending);
        drop(tx);
        in_flight.insert(1u32, rx);

        let memo = CoalescedMemo::<u32, u32> {
            memo: TtlMemo::new(TtlPolicy::new(
                Duration::from_secs(60),
                Duration::from_secs(60),
            )),
            in_flight,
        };

        let outcome = memo
            .get_or_fetch(1u32, || async { CallOutcome::Definitive(0u32) })
            .await;
        assert!(
            matches!(outcome, CallOutcome::Degraded(0)),
            "exhaustion must degrade to CallOutcome::Degraded(V::default()), never panic or hang"
        );
    }
}
