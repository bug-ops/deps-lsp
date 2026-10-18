//! One polled registry attempt: its deadline, its budget class, and what it writes to the memo.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use super::key::InteractiveFetchKey;
use super::memo::RecordState;
use super::{InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList};
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;

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

/// Awaits `fetch` until `deadline`, mapping an error to [`NoLiveList::Failed`] and an elapse to
/// [`NoLiveList::Unverified`].
pub(super) async fn bounded_await_until<T, E>(
    fetch: impl Future<Output = Result<T, E>>,
    deadline: Instant,
    request: &InteractiveFetchRequest<'_>,
) -> InteractiveFetch<T> {
    let budget = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout_at(deadline, fetch).await {
        Ok(Ok(value)) => InteractiveFetch::Live(value),
        Ok(Err(_)) => InteractiveFetch::Degraded(NoLiveList::Failed),
        Err(_) => {
            tracing::warn!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                timeout_secs = budget.as_secs(),
                "primary registry version fetch timed out"
            );
            InteractiveFetch::Degraded(NoLiveList::Unverified)
        }
    }
}

impl InteractiveFetchGate {
    /// Polls `fetch` until `deadline` and records the outcome in the memo.
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
    ) -> InteractiveFetch<T> {
        let budget = AttemptBudget::of(deadline.saturating_duration_since(Instant::now()));
        let result = match bounded_await_until(fetch, deadline, request).await {
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
        result
    }
}
