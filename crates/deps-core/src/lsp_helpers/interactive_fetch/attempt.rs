//! One polled registry attempt: its deadline, what it tells the breaker, and what it writes to
//! the memo.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use super::breaker::{Admission, ProbeId};
use super::key::InteractiveFetchKey;
use super::memo::RecordState;
use super::{InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList};
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;

/// Margin below the budget within which an answer may be a stale-serve or a race against the
/// 10 s connect timeout rather than proof the endpoint is responsive.
pub(super) const MARGIN: Duration = Duration::from_secs(1);

/// Whether an attempt started with enough of the request's budget for its failure to say
/// anything about the registry.
///
/// A request promoted to leader after its predecessor was cancelled inherits the deadline it
/// entered with, so it may poll with a sliver of the budget left. Such an attempt elapsing
/// proves nothing, and memoizing it would suppress a package for 30 s on a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptBudget {
    /// At least half of [`REGISTRY_FETCH_BUDGET`] remained: an error or elapse is a real failure.
    Full,
    /// Less than half remained: an error or elapse is inconclusive and writes no failure.
    Truncated,
}

impl AttemptBudget {
    pub(super) fn of(remaining: Duration) -> Self {
        if remaining >= REGISTRY_FETCH_BUDGET / 2 {
            Self::Full
        } else {
            Self::Truncated
        }
    }
}

/// How a polled attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptEnd {
    Live,
    Err,
    Elapsed,
    /// The awaiting future was dropped, for instance by `$/cancelRequest`.
    Cancelled,
}

/// What an attempt says about the endpoint's responsiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptEvidence {
    Answered,
    Slow,
    Inconclusive,
}

/// Evidence from an attempt that ended as `end` after `waited` against a budget of `budget`.
///
/// A fast `Live` or `Err` shows the endpoint is responsive. A `Live` near the budget is
/// inconclusive: the HTTP cache serves stale data after a failed revalidation, so it may come
/// from a dead host. Giving up at or beyond half the budget is slow; giving up earlier (a
/// promoted request with little budget left, an early cancel) says nothing.
pub(super) fn evidence(end: AttemptEnd, waited: Duration, budget: Duration) -> AttemptEvidence {
    let responsive = waited < budget.saturating_sub(MARGIN);
    match end {
        AttemptEnd::Live if responsive => AttemptEvidence::Answered,
        AttemptEnd::Live => AttemptEvidence::Inconclusive,
        AttemptEnd::Err if responsive => AttemptEvidence::Answered,
        AttemptEnd::Err => AttemptEvidence::Slow,
        AttemptEnd::Elapsed | AttemptEnd::Cancelled if waited >= budget / 2 => {
            AttemptEvidence::Slow
        }
        AttemptEnd::Elapsed | AttemptEnd::Cancelled => AttemptEvidence::Inconclusive,
    }
}

/// Reports an attempt's evidence to the breaker exactly once.
///
/// Finishing it reports the real end. Dropping it unfinished means the awaiting future was
/// cancelled, which reports [`AttemptEnd::Cancelled`] — a hover that waited most of the budget
/// before the editor gave up is evidence the endpoint is slow.
struct AttemptGuard<'a> {
    gate: &'a InteractiveFetchGate,
    key: &'a InteractiveFetchKey,
    generation: u64,
    started: Instant,
    probe: Option<ProbeId>,
    settled: bool,
}

impl AttemptGuard<'_> {
    fn finish(mut self, end: AttemptEnd) {
        self.settled = true;
        self.report(end);
    }

    fn report(&self, end: AttemptEnd) {
        let waited = Instant::now().saturating_duration_since(self.started);
        let evidence = evidence(end, waited, REGISTRY_FETCH_BUDGET);
        if self.gate.generation() != self.generation {
            return;
        }
        self.gate.breaker.report(
            &self.key.endpoint,
            &self.key.package,
            evidence,
            self.probe,
            super::now(),
        );
        // Re-checked after the write, as for the memo: an invalidation in between would
        // otherwise leave this endpoint's stale evidence behind.
        if self.gate.generation() != self.generation {
            self.gate.breaker.forget(&self.key.endpoint);
        }
    }
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.report(AttemptEnd::Cancelled);
        }
    }
}

/// Awaits `fetch` until `deadline`, mapping an error to [`NoLiveList::Failed`] and an elapse to
/// [`NoLiveList::Unverified`].
pub(super) async fn bounded_await_until<T, E>(
    fetch: impl Future<Output = Result<T, E>>,
    deadline: Instant,
    request: &InteractiveFetchRequest<'_>,
) -> (InteractiveFetch<T>, AttemptEnd) {
    let budget = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout_at(deadline, fetch).await {
        Ok(Ok(value)) => (InteractiveFetch::Live(value), AttemptEnd::Live),
        Ok(Err(_)) => (
            InteractiveFetch::Degraded(NoLiveList::Failed),
            AttemptEnd::Err,
        ),
        Err(_) => {
            tracing::warn!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                timeout_secs = budget.as_secs(),
                "primary registry version fetch timed out"
            );
            (
                InteractiveFetch::Degraded(NoLiveList::Unverified),
                AttemptEnd::Elapsed,
            )
        }
    }
}

/// How [`InteractiveFetchGate::attempt`] ended.
pub(super) enum Attempted<T> {
    Polled(InteractiveFetch<T>),
    /// The endpoint's breaker is open: nothing was polled and nothing was written.
    Refused,
}

impl InteractiveFetchGate {
    /// Polls `fetch` until `deadline`, tells the endpoint breaker what happened, and records
    /// the outcome in the memo.
    ///
    /// Only an attempt that began with a [`AttemptBudget::Full`] budget writes a failure; a
    /// truncated one leaves the memo alone. Success records follow the same rules at any budget.
    pub(super) async fn attempt<T, E>(
        &self,
        fetch: impl Future<Output = Result<T, E>>,
        deadline: Instant,
        key: &InteractiveFetchKey,
        request: &InteractiveFetchRequest<'_>,
        background_failure_known: bool,
        generation: u64,
    ) -> Attempted<T> {
        let probe = match self.admit(&key.endpoint, request.context) {
            Admission::Refused => {
                super::log_skipped(request, "registry endpoint circuit open");
                return Attempted::Refused;
            }
            Admission::Probe(probe) => Some(probe),
            Admission::Proceed => None,
        };
        let started = Instant::now();
        let budget = AttemptBudget::of(deadline.saturating_duration_since(started));
        let guard = AttemptGuard {
            gate: self,
            key,
            generation,
            started,
            probe,
            settled: false,
        };
        let (result, end) = bounded_await_until(fetch, deadline, request).await;
        guard.finish(end);
        let result = match result {
            // The background fetch still reports this package as failing, so a stale seeded
            // record must not flip to fail-open after one TTL.
            InteractiveFetch::Degraded(NoLiveList::Failed) if background_failure_known => {
                InteractiveFetch::Degraded(NoLiveList::Unverified)
            }
            other => other,
        };
        match (&result, background_failure_known, budget) {
            (InteractiveFetch::Degraded(_), _, AttemptBudget::Full) => {
                self.record(key, RecordState::InteractiveFailed, generation);
            }
            (InteractiveFetch::Degraded(_), _, AttemptBudget::Truncated) => {}
            (InteractiveFetch::Live(_), true, _) => {
                self.record(key, RecordState::InteractiveSucceeded, generation);
            }
            // Nothing a success record could override, so it must not occupy the capped memo.
            (InteractiveFetch::Live(_), false, _) => {
                self.memo.remove(key);
            }
        }
        Attempted::Polled(result)
    }
}
