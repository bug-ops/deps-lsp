//! One polled registry attempt: its deadline, what it tells the breaker, and what it writes to
//! the memo.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::breaker::{Admission, ProbeId};
use super::key::{BreakerEvidence, EndpointKey, LookupKey, LookupKind};
use super::memo::RecordState;
use super::{InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList};
use crate::ErrorOrigin;
use crate::endpoint_contact::{AttemptContact, Contact, ResponseSeen};

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

/// Evidence from an attempt that ended as `end` after `waited` against a budget of `budget`,
/// given what it did on the wire (`contact`).
///
/// A response is required to vouch for an endpoint, and a stalled request to accuse it:
///
/// - A `Live` result, or an endpoint-attributed `Err`, within the budget minus a margin is
///   [`AttemptEvidence::Answered`] only if a response arrived. One served from a memo, a fresh
///   cache entry or a local error never touched the endpoint. A `Live` near the budget is
///   inconclusive: the HTTP cache serves stale data after a failed revalidation, so it may come
///   from a dead host.
/// - An ending after a request was outstanding for at least half the budget, by elapse, cancel
///   or any error, is [`AttemptEvidence::Slow`]. The stall is busy time since the last response,
///   so a chain whose first hop answers fast and whose second hangs is slow, a request that
///   fails after a long wait still counts, and a paginating fetch that keeps receiving
///   responses is not slow. An attempt that received no response of its own also counts the
///   time another task's request on the same endpoint was outstanding during its wait (see
///   [`AttemptContact::observe`]), so a lookup coalesced onto a background fetch's request
///   accuses the endpoint just as one that sent it would.
/// - Everything else is [`AttemptEvidence::Inconclusive`]: a promoted request with little
///   budget left, an early cancel, a fast local failure, a lookup that waited on another task's
///   lock or single-flight with no request outstanding behind it, and an attempt whose
///   concurrent requests were partially answered (a response clears the busy time even if a
///   sibling still hangs).
pub(super) fn evidence(
    end: AttemptEnd,
    contact: Contact,
    waited: Duration,
    budget: Duration,
) -> AttemptEvidence {
    let responsive = waited < budget.saturating_sub(MARGIN);
    let answered = contact.response == ResponseSeen::Yes;
    let stalled = contact.stall >= budget / 2;
    match end {
        AttemptEnd::Live if responsive && answered => AttemptEvidence::Answered,
        AttemptEnd::Live => AttemptEvidence::Inconclusive,
        AttemptEnd::Err(_) | AttemptEnd::Elapsed | AttemptEnd::Cancelled if stalled => {
            AttemptEvidence::Slow
        }
        AttemptEnd::Err(ErrorOrigin::Endpoint) if responsive && answered => {
            AttemptEvidence::Answered
        }
        AttemptEnd::Err(_) | AttemptEnd::Elapsed | AttemptEnd::Cancelled => {
            AttemptEvidence::Inconclusive
        }
    }
}

/// The wire view of an attempt: it joins its endpoint's shared ledger only when its evidence
/// counts and the endpoint is resolved. A decoration never writes shared state, since its
/// host may differ from the base fetch's.
fn attempt_contact(counts: BreakerEvidence, endpoint: EndpointKey) -> AttemptContact {
    match (counts, endpoint) {
        (
            BreakerEvidence::Counts,
            EndpointKey::Resolved {
                ecosystem,
                endpoint,
            },
        ) => AttemptContact::on_endpoint(ecosystem, endpoint),
        (BreakerEvidence::Counts, EndpointKey::Scoped { .. }) | (BreakerEvidence::Ignored, _) => {
            AttemptContact::own_only()
        }
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
    contact: AttemptContact,
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
        let now = Instant::now();
        let waited = now.saturating_duration_since(self.started);
        let (contact, view) = self.contact.observe(now);
        let evidence = evidence(end, contact, waited, self.lookup.kind().budget());
        tracing::debug!(
            ?evidence,
            view = view.as_str(),
            stall_ms = u64::try_from(contact.stall.as_millis()).unwrap_or(u64::MAX),
            lookup = self.lookup.kind().as_str(),
            "interactive attempt breaker evidence"
        );
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
/// let error = DepsError::RecentlyFailed;
/// assert_eq!(error.log_cause(), (None, "recently-failed"));
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
        let endpoint = lookup.route.endpoint();
        let probe = match self.admit(&endpoint, request.context, counts) {
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
            contact: attempt_contact(counts, endpoint),
        };
        let scoped = guard.contact.scope(fetch);
        let (result, end) = bounded_await_until(scoped, deadline, request, lookup.kind()).await;
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
