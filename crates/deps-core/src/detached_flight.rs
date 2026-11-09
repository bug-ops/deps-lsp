//! Single-flight for work that outlives its caller.
//!
//! [`SingleFlight::start_or_join`] runs a future in its own spawned task, or joins the task
//! already running for the same key. The returned [`FlightHandle`] only waits: aborting the
//! waiter drops the handle and leaves the task running, so its result still lands wherever the
//! work stores it. The task owns the claim, so it is released when the work finishes, panics, or
//! the runtime shuts down and drops the task; only then are waiters woken. Nothing outside the
//! task can abort it, because its `JoinHandle` is dropped. A panic is caught inside the task,
//! logged inside the caller's span, and reported to waiters as [`FlightEnd::Abandoned`], never
//! as completion.
//!
//! The in-flight map is an implementation detail: no map type appears in this module's public
//! signatures.

use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use tracing::Instrument;

use crate::single_flight::{FlightMap, Follower, OwnedClaim, claim_or_follow_owned};

/// Deduplicates detached background work per key.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use deps_core::{FlightEnd, SingleFlight};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let flights = SingleFlight::<&str>::default();
/// let (release, gate) = tokio::sync::oneshot::channel::<()>();
///
/// let first = flights.start_or_join("key", async move { gate.await.unwrap() });
/// let second = flights.start_or_join("key", async {});
/// assert!(first.issued());
/// assert!(!second.issued());
///
/// release.send(()).unwrap();
/// assert_eq!(first.wait(Duration::from_secs(5)).await, FlightEnd::Completed);
/// assert_eq!(second.wait(Duration::from_secs(5)).await, FlightEnd::Completed);
/// # }
/// ```
pub struct SingleFlight<K>(Arc<FlightMap<K, ()>>);

impl<K: Hash + Eq> fmt::Debug for SingleFlight<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleFlight")
            .field("in_flight", &self.0.len())
            .finish()
    }
}

impl<K: Hash + Eq> Default for SingleFlight<K> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> SingleFlight<K> {
    /// Spawns `work` as the leader for `key`, or joins the leader already running.
    ///
    /// A joining call drops `work` unrun. The task owns the claim, so a panic or a runtime
    /// shutdown releases it and wakes every waiter.
    ///
    /// Must be called within a tokio runtime.
    pub fn start_or_join(
        &self,
        key: K,
        work: impl Future<Output = ()> + Send + 'static,
    ) -> FlightHandle {
        match claim_or_follow_owned(&self.0, key) {
            OwnedClaim::Follower(follower) => FlightHandle {
                follower,
                issued: false,
            },
            OwnedClaim::Leader(leader) => {
                let follower = leader.follower();
                tokio::spawn(
                    async move {
                        if AssertUnwindSafe(work).catch_unwind().await.is_err() {
                            tracing::error!("detached single-flight work panicked");
                            return;
                        }
                        leader.publish(());
                    }
                    .instrument(tracing::Span::current()),
                );
                FlightHandle {
                    follower,
                    issued: true,
                }
            }
        }
    }
}

/// A started or joined flight that can be awaited.
#[derive(Debug)]
pub struct FlightHandle {
    follower: Follower<()>,
    issued: bool,
}

impl FlightHandle {
    /// Whether this call started the work, as opposed to joining a flight already running.
    #[must_use]
    pub const fn issued(&self) -> bool {
        self.issued
    }

    /// Waits up to `budget` for the flight to end and reports how it ended.
    ///
    /// The work keeps running when the budget runs out.
    pub async fn wait(self, budget: Duration) -> FlightEnd {
        match tokio::time::timeout(budget, self.follower.wait()).await {
            Ok(Some(())) => FlightEnd::Completed,
            Ok(None) => FlightEnd::Abandoned,
            Err(_elapsed) => FlightEnd::TimedOut,
        }
    }
}

/// How a flight ended from a waiter's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightEnd {
    /// The work ran to completion.
    Completed,
    /// The leader panicked, or a runtime shutdown dropped it, before finishing. A panic is
    /// logged at `error` level inside the caller's span.
    Abandoned,
    /// The budget ran out while the work was still running.
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BUDGET: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_second_call_for_the_same_key_joins_and_never_runs_its_work() {
        let flights = SingleFlight::default();
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let runs = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&runs);
        let first = flights.start_or_join("k", async move {
            counter.fetch_add(1, Ordering::SeqCst);
            gate.await.unwrap();
        });
        let counter = Arc::clone(&runs);
        let second = flights.start_or_join("k", async move {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        assert!(first.issued());
        assert!(!second.issued());

        release.send(()).unwrap();
        assert_eq!(first.wait(BUDGET).await, FlightEnd::Completed);
        assert_eq!(second.wait(BUDGET).await, FlightEnd::Completed);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_finished_flight_frees_the_key() {
        let flights = SingleFlight::default();
        let end = flights.start_or_join("k", async {}).wait(BUDGET).await;
        assert_eq!(end, FlightEnd::Completed);
        assert!(flights.start_or_join("k", async {}).issued());
    }

    #[tokio::test]
    async fn a_panicking_leader_is_abandoned_not_completed_and_frees_the_key() {
        let flights = SingleFlight::default();
        let handle = flights.start_or_join("k", async { panic!("leader failed") });
        assert_eq!(handle.wait(BUDGET).await, FlightEnd::Abandoned);
        assert!(flights.start_or_join("k", async {}).issued());
    }

    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn a_panicking_leader_is_logged_inside_the_callers_span() {
        let flights = SingleFlight::default();
        let output = crate::test_util::capture_tracing_output_async(async {
            let span = tracing::info_span!("request", document = "doc-1984");
            let handle =
                span.in_scope(|| flights.start_or_join("k", async { panic!("leader failed") }));
            assert_eq!(handle.wait(BUDGET).await, FlightEnd::Abandoned);
        })
        .await;
        assert!(
            output.contains("detached single-flight work panicked"),
            "{output}"
        );
        assert!(output.contains("doc-1984"), "{output}");
    }

    #[tokio::test]
    async fn a_waiter_that_gives_up_leaves_the_work_running() {
        let flights = SingleFlight::default();
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = flights.start_or_join("k", async move {
            gate.await.unwrap();
            done_tx.send(()).unwrap();
        });
        let waiter = tokio::spawn(handle.wait(BUDGET));
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        release.send(()).unwrap();
        done_rx.await.unwrap();
    }

    #[test]
    fn dropping_the_runtime_releases_the_claim_and_wakes_waiters() {
        let build = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
        };
        let flights = SingleFlight::default();
        let runtime = build();
        let handle = runtime.block_on(async { flights.start_or_join("k", std::future::pending()) });
        assert!(handle.issued());

        drop(runtime);

        assert!(
            flights.0.is_empty(),
            "the dropped leader released the claim"
        );
        assert_eq!(
            build().block_on(handle.wait(BUDGET)),
            FlightEnd::Abandoned,
            "waiters see the flight end"
        );
    }

    #[tokio::test]
    async fn waiting_past_the_budget_reports_timed_out() {
        let flights = SingleFlight::default();
        let handle = flights.start_or_join("k", std::future::pending());
        assert_eq!(
            handle.wait(Duration::from_millis(20)).await,
            FlightEnd::TimedOut
        );
    }

    #[tokio::test]
    async fn waiters_wake_only_after_the_key_is_free() {
        let flights = SingleFlight::default();
        let handle = flights.start_or_join("k", async {});
        assert_eq!(handle.wait(BUDGET).await, FlightEnd::Completed);
        assert!(flights.0.is_empty());
    }
}
