//! One polled registry attempt: its deadline, what it tells the breaker, and what it writes to
//! the memo.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::breaker::{Admission, ProbeId};
use super::key::{BreakerEvidence, LookupKey, LookupKind};
use super::memo::RecordState;
use super::{InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList};
use crate::ErrorOrigin;

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
    /// At least half of the kind's budget remained: an error or elapse is a real failure.
    Full,
    /// Less than half remained: an error or elapse is inconclusive and writes no failure.
    Truncated,
}

impl AttemptBudget {
    pub(super) fn of(remaining: Duration, budget: Duration) -> Self {
        if remaining >= budget / 2 {
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
    Err(ErrorOrigin),
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
/// A fast `Live` or endpoint-attributed `Err` shows the endpoint is responsive. A `Live` near
/// the budget is inconclusive: the HTTP cache serves stale data after a failed revalidation, so
/// it may come from a dead host. Giving up at or beyond half the budget is slow, whether by
/// elapse, cancel, or an unattributed error such as a late DNS failure; giving up earlier
/// (a promoted request with little budget left, an early cancel, a fast local failure) says
/// nothing.
pub(super) fn evidence(end: AttemptEnd, waited: Duration, budget: Duration) -> AttemptEvidence {
    let responsive = waited < budget.saturating_sub(MARGIN);
    match end {
        AttemptEnd::Live if responsive => AttemptEvidence::Answered,
        AttemptEnd::Live => AttemptEvidence::Inconclusive,
        AttemptEnd::Err(ErrorOrigin::Endpoint) if responsive => AttemptEvidence::Answered,
        AttemptEnd::Err(ErrorOrigin::Endpoint) => AttemptEvidence::Slow,
        AttemptEnd::Err(ErrorOrigin::Unattributed)
        | AttemptEnd::Elapsed
        | AttemptEnd::Cancelled
            if waited >= budget / 2 =>
        {
            AttemptEvidence::Slow
        }
        AttemptEnd::Err(ErrorOrigin::Unattributed)
        | AttemptEnd::Elapsed
        | AttemptEnd::Cancelled => AttemptEvidence::Inconclusive,
    }
}

/// Reports an attempt's evidence to the breaker exactly once.
///
/// Finishing it reports the real end. Dropping it unfinished means the awaiting future was
/// cancelled, which reports [`AttemptEnd::Cancelled`] — a hover that waited most of the budget
/// before the editor gave up is evidence the endpoint is slow.
struct AttemptGuard<'a> {
    gate: &'a InteractiveFetchGate,
    lookup: &'a Arc<LookupKey>,
    generation: u64,
    started: Instant,
    probe: Option<ProbeId>,
    settled: bool,
    counts: BreakerEvidence,
}

impl AttemptGuard<'_> {
    fn finish(mut self, end: AttemptEnd) {
        self.settled = true;
        self.report(end);
    }

    fn report(&self, end: AttemptEnd) {
        match self.counts {
            BreakerEvidence::Counts => {}
            BreakerEvidence::Ignored => return,
        }
        let waited = Instant::now().saturating_duration_since(self.started);
        let evidence = evidence(end, waited, self.lookup.kind().budget());
        if self.gate.generation() != self.generation {
            return;
        }
        let endpoint = self.lookup.route.endpoint();
        self.gate.breaker.report(
            &endpoint,
            &self.lookup.package,
            evidence,
            self.probe,
            super::now(),
        );
        // Re-checked after the write, as for the memo: an invalidation in between would
        // otherwise leave this endpoint's stale evidence behind.
        if self.gate.generation() != self.generation {
            self.gate.breaker.forget(&endpoint);
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

/// An error an interactive await may log, exposing only a URL- and credential-free cause.
///
/// `Display` and `Debug` of a registry error can embed the raw request URL, so a lookup never
/// logs them; it logs this coarse classification instead.
///
/// # Examples
///
/// ```
/// use deps_core::DepsError;
/// use deps_core::lsp_helpers::InteractiveFetchError;
///
/// let error = DepsError::CacheError("poisoned lock".into());
/// assert_eq!(error.log_cause(), (None, "cache"));
/// assert_eq!(InteractiveFetchError::origin(&error), deps_core::ErrorOrigin::Unattributed);
/// ```
pub trait InteractiveFetchError {
    /// The HTTP status when there is one, plus a short stable cause label.
    fn log_cause(&self) -> (Option<u16>, &'static str);

    /// Whether the failure is evidence about the registry endpoint, which decides if a fast
    /// failure vouches for it (see [`ErrorOrigin`]).
    fn origin(&self) -> ErrorOrigin;
}

impl InteractiveFetchError for crate::DepsError {
    fn log_cause(&self) -> (Option<u16>, &'static str) {
        self.safe_tracing_summary()
    }

    fn origin(&self) -> ErrorOrigin {
        Self::origin(self)
    }
}

/// For test lookups that carry no error detail.
#[cfg(test)]
impl InteractiveFetchError for () {
    fn log_cause(&self) -> (Option<u16>, &'static str) {
        (None, "unspecified")
    }

    fn origin(&self) -> ErrorOrigin {
        ErrorOrigin::Endpoint
    }
}

/// Awaits `fetch` until `deadline`, mapping an error to [`NoLiveList::Failed`] and an elapse to
/// [`NoLiveList::Unverified`].
pub(super) async fn bounded_await_until<T, E: InteractiveFetchError>(
    fetch: impl Future<Output = Result<T, E>>,
    deadline: Instant,
    request: &InteractiveFetchRequest<'_>,
    kind: LookupKind,
) -> (InteractiveFetch<T>, AttemptEnd) {
    match tokio::time::timeout_at(deadline, fetch).await {
        Ok(Ok(value)) => (InteractiveFetch::Live(value), AttemptEnd::Live),
        Ok(Err(error)) => {
            let (status, cause) = error.log_cause();
            tracing::debug!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                lookup = kind.as_str(),
                ?status,
                cause,
                "interactive registry lookup failed"
            );
            (
                InteractiveFetch::Degraded(NoLiveList::Failed),
                AttemptEnd::Err(error.origin()),
            )
        }
        Err(_) => {
            tracing::warn!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                lookup = kind.as_str(),
                timeout_secs = kind.budget().as_secs(),
                "interactive registry lookup timed out"
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
    /// The attempt ran; `budget` says whether a failure of it proves anything.
    Polled(InteractiveFetch<T>, AttemptBudget),
    /// The endpoint's breaker is open: nothing was polled and nothing was written.
    Refused,
}

impl InteractiveFetchGate {
    /// Polls `fetch` until `deadline`, tells the endpoint breaker what happened, and records
    /// the outcome in the memo.
    ///
    /// Only an attempt that began with a [`AttemptBudget::Full`] budget writes a failure; a
    /// truncated one leaves the memo alone. Success records follow the same rules at any budget.
    pub(super) async fn attempt<T, E: InteractiveFetchError>(
        &self,
        fetch: impl Future<Output = Result<T, E>>,
        deadline: Instant,
        lookup: &Arc<LookupKey>,
        request: &InteractiveFetchRequest<'_>,
        background_failure_known: bool,
        generation: u64,
    ) -> Attempted<T> {
        let counts = lookup.kind().breaker_evidence();
        let probe = match self.admit(&lookup.route.endpoint(), request.context, counts) {
            Admission::Refused => {
                super::log_skipped(request, "registry endpoint circuit open");
                return Attempted::Refused;
            }
            Admission::Probe(probe) => Some(probe),
            Admission::Proceed => None,
        };
        let started = Instant::now();
        let budget = AttemptBudget::of(
            deadline.saturating_duration_since(started),
            lookup.kind().budget(),
        );
        let guard = AttemptGuard {
            gate: self,
            lookup,
            generation,
            started,
            probe,
            settled: false,
            counts,
        };
        let (result, end) = bounded_await_until(fetch, deadline, request, lookup.kind()).await;
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
                self.record(lookup, RecordState::InteractiveFailed, generation);
            }
            (InteractiveFetch::Degraded(_), _, AttemptBudget::Truncated) => {}
            (InteractiveFetch::Live(_), true, _) => {
                self.record(lookup, RecordState::InteractiveSucceeded, generation);
            }
            // Nothing a success record could override, so it must not occupy the capped memo.
            (InteractiveFetch::Live(_), false, _) => self.forget_record(lookup),
        }
        Attempted::Polled(result, budget)
    }
}
