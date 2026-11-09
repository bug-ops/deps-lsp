//! The memo of repository-URL identity lookups and its detached per-URL single-flight (spec 088).
//!
//! Reads are stale-while-revalidate: a read returns the last known answer even when it is older
//! than [`IDENTITY_TTL`], and staleness only schedules a background refresh. A refresh that
//! returns the same answer, or [`IdentityLookup::Failed`], changes nothing, so an expired entry
//! can never flip a dependency's parsed form to source control and back (NFR-003).
//!
//! A lookup runs in its own spawned task, so aborting the debounced change task that awaits it
//! drops only the waiter: the answer still lands in the memo and the next keystroke does not
//! send the request again (FR-011).

use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use deps_core::swr_store::{Recency, Refreshed, SwrPolicy, SwrStore, Upserted};
use deps_core::{FlightHandle, RefreshEvents, RefreshSender, SingleFlight};
use futures::FutureExt;

use crate::package_location::RegistryIdentityBuf;
use crate::scm::{CaseFoldedScmUrl, IdentityLookup, MemoKey, RegistryIndexUrl};

pub(crate) use deps_core::swr_store::Freshness;

/// How long an answer is served without scheduling a refresh.
pub(crate) const IDENTITY_TTL: Duration = Duration::from_hours(1);

/// How long an unread entry is kept.
pub(crate) const IDLE_EVICTION: Duration = Duration::from_hours(24);

/// Most entries held; the least recently read are evicted first.
pub(crate) const MEMO_CAPACITY: usize = 4096;

/// Slack a waiter allows a lookup beyond its own timeout, for the task to record its answer.
const WAIT_GRACE: Duration = Duration::from_secs(1);

/// How long to wait for a lookup that is cut off after `timeout`.
pub(crate) fn wait_budget(timeout: Duration) -> Duration {
    timeout + WAIT_GRACE
}

/// A memoized answer and how old it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoRead {
    pub answer: IdentityLookup,
    pub freshness: Freshness,
}

/// Repository-URL identity answers shared by every Swift document of a registry.
#[derive(Debug)]
pub(crate) struct ScmIdentityMemo {
    entries: SwrStore<MemoKey, IdentityLookup>,
    inflight: SingleFlight<MemoKey>,
    generation: AtomicU64,
    events: RefreshSender,
}

impl Default for ScmIdentityMemo {
    fn default() -> Self {
        Self {
            entries: SwrStore::new(SwrPolicy {
                capacity: NonZeroUsize::new(MEMO_CAPACITY).unwrap_or(NonZeroUsize::MIN),
                ttl: Some(IDENTITY_TTL),
                idle: Some(IDLE_EVICTION),
                recency: Recency::ReadsOnly,
            }),
            inflight: SingleFlight::default(),
            generation: AtomicU64::new(0),
            events: RefreshSender::new(),
        }
    }
}

impl ScmIdentityMemo {
    /// Receives `ReparseOpenDocuments` whenever a recorded answer changes.
    pub(crate) fn subscribe(&self) -> RefreshEvents {
        self.events.subscribe()
    }

    /// The count of answer changes so far.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The memoized answer for `key`, marking it read at `now`.
    pub(crate) fn get(&self, key: &MemoKey, now: Instant) -> Option<MemoRead> {
        let read = self.entries.get(key, now)?;
        Some(MemoRead {
            answer: read.value,
            freshness: read.freshness,
        })
    }

    /// The unique identity `registry` gave each repository, keyed by the repository URL in
    /// lowercase (a lock file may spell a repository's case differently from the manifest).
    ///
    /// A lowercase spelling that two entries map to different identities is left out.
    pub(crate) fn unique_by_lowercase_repository(
        &self,
        registry: &RegistryIndexUrl,
    ) -> HashMap<CaseFoldedScmUrl, RegistryIdentityBuf> {
        let mut found: HashMap<CaseFoldedScmUrl, Option<RegistryIdentityBuf>> = HashMap::new();
        self.entries.scan(|key, answer| {
            let IdentityLookup::Unique(identity) = answer else {
                return;
            };
            if key.registry() != registry {
                return;
            }
            found
                .entry(CaseFoldedScmUrl::from(key.repository()))
                .and_modify(|seen| {
                    if seen.as_ref() != Some(identity) {
                        *seen = None;
                    }
                })
                .or_insert_with(|| Some(identity.clone()));
        });
        found
            .into_iter()
            .filter_map(|(url, identity)| Some((url, identity?)))
            .collect()
    }

    /// Stores the outcome of one lookup of `key` at `now`; returns whether the generation
    /// advanced.
    ///
    /// [`IdentityLookup::Failed`] never replaces a known answer, and an unchanged answer only
    /// restarts its TTL. The generation advances, announcing
    /// `RefreshEvent::ReparseOpenDocuments` after the store's lock is released, only when the
    /// unique identity the key resolves to changes (appears, disappears or differs): every other
    /// answer leaves every dependency on the form it already has.
    pub(crate) fn record(&self, key: &MemoKey, answer: IdentityLookup, now: Instant) -> bool {
        let moved = if answer == IdentityLookup::Failed {
            match self.entries.refresh_or_insert(key.clone(), answer, now) {
                Refreshed::Kept | Refreshed::Inserted => false,
            }
        } else {
            let incoming = unique_identity(&answer).cloned();
            match self.entries.upsert(key.clone(), answer, now) {
                Upserted::Inserted => incoming.is_some(),
                Upserted::Replaced { previous } => unique_identity(&previous) != incoming.as_ref(),
            }
        };
        if moved {
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            self.events
                .send_reparse_open_documents(generation, key.repository().to_parse_input());
        }
        moved
    }

    /// Runs `lookup` for `key` in a detached task, or joins the one already in flight.
    ///
    /// The task records its answer in the memo whether or not anyone still waits for it. It is
    /// cut off after `timeout`, and a panicking lookup, like one cut off, records
    /// [`IdentityLookup::Failed`]. The caller bounds how many lookups run at once.
    pub(crate) fn start(
        self: &Arc<Self>,
        key: &MemoKey,
        timeout: Duration,
        lookup: impl Future<Output = IdentityLookup> + Send + 'static,
    ) -> FlightHandle {
        let memo = Arc::clone(self);
        let recorded = key.clone();
        self.inflight.start_or_join(key.clone(), async move {
            // The flight also catches a panic, but only to report it to waiters; this task
            // records its answer even when nobody waits, so it must negatively cache the panic.
            let answer = match AssertUnwindSafe(tokio::time::timeout(timeout, lookup))
                .catch_unwind()
                .await
            {
                Ok(Ok(answer)) => answer,
                Ok(Err(_elapsed)) => IdentityLookup::Failed,
                Err(_panic) => {
                    tracing::error!("repository identity lookup panicked");
                    IdentityLookup::Failed
                }
            };
            memo.record(&recorded, answer, Instant::now());
        })
    }
}

fn unique_identity(answer: &IdentityLookup) -> Option<&RegistryIdentityBuf> {
    match answer {
        IdentityLookup::Unique(identity) => Some(identity),
        IdentityLookup::Ambiguous
        | IdentityLookup::NotRegistered
        | IdentityLookup::Rejected
        | IdentityLookup::Failed => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SwiftRegistryUrl;
    use crate::package_location::RegistryIdentityBuf;
    use crate::scm::ScmLookupUrl;
    use deps_core::{FlightEnd, RefreshEvent};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn url(path: &str) -> ScmLookupUrl {
        ScmLookupUrl::parse(&format!("https://github.com/{path}")).unwrap()
    }

    fn registry(base: &str) -> SwiftRegistryUrl {
        SwiftRegistryUrl::for_test(base, deps_core::net_policy::RegistryTrust::Trusted)
    }

    fn k(path: &str) -> MemoKey {
        MemoKey::new(&registry("https://registry.example/api"), &url(path))
    }

    fn unique(id: &str) -> IdentityLookup {
        IdentityLookup::Unique(RegistryIdentityBuf::parse(id).unwrap())
    }

    fn later(now: Instant, by: Duration) -> Instant {
        now.checked_add(by).unwrap()
    }

    #[test]
    fn test_miss_then_fresh_then_stale_read() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        assert!(memo.get(&key, now).is_none());

        memo.record(&key, unique("apple.swift-nio"), now);
        let fresh = memo.get(&key, now).unwrap();
        assert_eq!(fresh.freshness, Freshness::Fresh);

        let stale = memo.get(&key, later(now, IDENTITY_TTL)).unwrap();
        assert_eq!(stale.freshness, Freshness::Stale);
        assert_eq!(stale.answer, unique("apple.swift-nio"));
    }

    #[test]
    fn test_failed_never_overwrites_a_known_answer() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        memo.record(&key, unique("apple.swift-nio"), now);

        assert!(!memo.record(&key, IdentityLookup::Failed, later(now, IDENTITY_TTL)));
        let read = memo.get(&key, later(now, IDENTITY_TTL)).unwrap();
        assert_eq!(read.answer, unique("apple.swift-nio"));
        assert_eq!(read.freshness, Freshness::Fresh);
        assert_eq!(memo.generation(), 1);
    }

    #[test]
    fn test_failed_is_stored_when_nothing_is_known_and_replaced_by_a_real_answer() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        assert!(
            !memo.record(&key, IdentityLookup::Failed, now),
            "no dependency changes form"
        );
        assert_eq!(memo.get(&key, now).unwrap().answer, IdentityLookup::Failed);
        assert!(memo.record(&key, unique("apple.swift-nio"), now));
        assert_eq!(memo.generation(), 1);
    }

    #[test]
    fn test_answers_that_leave_every_dependency_on_source_control_never_advance_the_generation() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        for answer in [
            IdentityLookup::NotRegistered,
            IdentityLookup::Ambiguous,
            IdentityLookup::Rejected,
            IdentityLookup::Failed,
            IdentityLookup::NotRegistered,
        ] {
            assert!(!memo.record(&key, answer, now));
        }
        assert_eq!(memo.generation(), 0);
    }

    #[test]
    fn test_a_changed_or_withdrawn_unique_identity_advances_the_generation() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        assert!(memo.record(&key, unique("apple.swift-nio"), now));
        assert!(memo.record(&key, unique("other.swift-nio"), now));
        assert!(memo.record(&key, IdentityLookup::Ambiguous, now));
        assert_eq!(memo.generation(), 3);
    }

    #[test]
    fn test_one_repository_is_memoized_per_registry() {
        let memo = ScmIdentityMemo::default();
        let scm = url("apple/swift-nio");
        let a = MemoKey::new(&registry("https://a.example/api"), &scm);
        let b = MemoKey::new(&registry("https://b.example/api"), &scm);
        let now = Instant::now();

        memo.record(&a, unique("apple.swift-nio"), now);

        assert!(memo.get(&a, now).is_some());
        assert!(
            memo.get(&b, now).is_none(),
            "another registry never reuses the first one's identity"
        );
    }

    #[test]
    fn test_generation_advances_only_on_an_answer_change() {
        let memo = ScmIdentityMemo::default();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        assert!(memo.record(&key, unique("apple.swift-nio"), now));
        assert!(!memo.record(&key, unique("apple.swift-nio"), now));
        assert_eq!(memo.generation(), 1);
        assert!(memo.record(&key, IdentityLookup::NotRegistered, now));
        assert_eq!(memo.generation(), 2);
    }

    #[test]
    fn test_answer_change_announces_a_reparse_event_with_its_generation() {
        let memo = ScmIdentityMemo::default();
        let mut events = memo.subscribe();
        let key = k("apple/swift-nio");
        let now = Instant::now();
        memo.record(&key, unique("apple.swift-nio"), now);
        memo.record(&key, unique("apple.swift-nio"), now);
        assert_eq!(
            events.try_recv().unwrap(),
            RefreshEvent::ReparseOpenDocuments {
                generation: 1,
                input: key.repository().to_parse_input(),
            }
        );
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn test_unread_entries_are_evicted_after_the_idle_window_and_reads_keep_them() {
        let memo = ScmIdentityMemo::default();
        let kept = k("apple/kept");
        let idle = k("apple/idle");
        let now = Instant::now();
        memo.record(&kept, IdentityLookup::NotRegistered, now);
        memo.record(&idle, IdentityLookup::NotRegistered, now);

        let almost = later(now, IDLE_EVICTION);
        assert!(memo.get(&kept, almost).is_some());

        let probe = k("apple/probe");
        memo.record(
            &probe,
            IdentityLookup::NotRegistered,
            later(almost, Duration::from_secs(1)),
        );
        assert!(memo.get(&kept, almost).is_some());
        assert!(memo.get(&idle, almost).is_none());
    }

    #[test]
    fn test_capacity_evicts_the_least_recently_read_entry() {
        let memo = ScmIdentityMemo::default();
        let now = Instant::now();
        for i in 0..MEMO_CAPACITY {
            let at = later(now, Duration::from_millis(u64::try_from(i).unwrap()));
            memo.record(&k(&format!("o/r{i}")), IdentityLookup::NotRegistered, at);
        }
        let newest = later(now, Duration::from_secs(10));
        memo.record(&k("o/newest"), IdentityLookup::NotRegistered, newest);

        assert!(memo.get(&k("o/r0"), newest).is_none());
        assert!(memo.get(&k("o/r1"), newest).is_some());
        assert!(memo.get(&k("o/newest"), newest).is_some());
    }

    #[tokio::test]
    async fn test_concurrent_starts_share_one_request() {
        let memo = Arc::new(ScmIdentityMemo::default());
        let key = k("apple/swift-nio");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let counter = Arc::clone(&sent);
        let first = memo.start(&key, TIMEOUT, async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            release_rx.await.unwrap();
            unique("apple.swift-nio")
        });
        let second = memo.start(&key, TIMEOUT, async { IdentityLookup::Failed });
        assert!(first.issued());
        assert!(!second.issued());

        release_tx.send(()).unwrap();
        assert_eq!(first.wait(wait_budget(TIMEOUT)).await, FlightEnd::Completed);
        assert_eq!(
            second.wait(wait_budget(TIMEOUT)).await,
            FlightEnd::Completed
        );
        assert_eq!(sent.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            memo.get(&key, Instant::now()).unwrap().answer,
            unique("apple.swift-nio")
        );
    }

    #[tokio::test]
    async fn test_aborting_the_waiter_does_not_cancel_the_lookup() {
        let memo = Arc::new(ScmIdentityMemo::default());
        let key = k("apple/swift-nio");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = memo.start(&key, TIMEOUT, async move {
            release_rx.await.unwrap();
            unique("apple.swift-nio")
        });
        let waiter = tokio::spawn(handle.wait(wait_budget(TIMEOUT)));
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        release_tx.send(()).unwrap();
        let rejoin = memo.start(&key, TIMEOUT, async { IdentityLookup::Failed });
        assert!(!rejoin.issued());
        assert_eq!(
            rejoin.wait(wait_budget(TIMEOUT)).await,
            FlightEnd::Completed
        );
        assert_eq!(
            memo.get(&key, Instant::now()).unwrap().answer,
            unique("apple.swift-nio")
        );
    }

    #[tokio::test]
    async fn test_a_finished_lookup_clears_the_in_flight_marker() {
        let memo = Arc::new(ScmIdentityMemo::default());
        let key = k("apple/swift-nio");
        let first = memo.start(&key, TIMEOUT, async { IdentityLookup::NotRegistered });
        assert_eq!(first.wait(wait_budget(TIMEOUT)).await, FlightEnd::Completed);
        let second = memo.start(&key, TIMEOUT, async { IdentityLookup::NotRegistered });
        assert!(second.issued());
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_lookup_past_the_timeout_records_failed() {
        let memo = Arc::new(ScmIdentityMemo::default());
        let key = k("apple/swift-nio");
        let handle = memo.start(&key, TIMEOUT, std::future::pending());
        assert_eq!(
            handle.wait(wait_budget(TIMEOUT) * 2).await,
            FlightEnd::Completed
        );
        assert_eq!(
            memo.get(&key, Instant::now()).unwrap().answer,
            IdentityLookup::Failed
        );
    }

    #[tokio::test]
    async fn test_a_panicking_lookup_records_failed_even_when_nobody_waits() {
        let memo = Arc::new(ScmIdentityMemo::default());
        let key = k("apple/swift-nio");
        let handle = memo.start(&key, TIMEOUT, async { panic!("lookup failed") });
        assert_eq!(
            handle.wait(wait_budget(TIMEOUT)).await,
            FlightEnd::Completed
        );
        assert_eq!(
            memo.get(&key, Instant::now()).unwrap().answer,
            IdentityLookup::Failed
        );
    }
}
