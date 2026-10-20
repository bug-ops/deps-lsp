//! Single-flight for interactive version-list awaits (FR-007).
//!
//! Concurrent hovers and code actions for one package would each poll their own registry
//! request. The first becomes the leader and polls; the rest follow its shared list. Followers
//! hold a dispatch permit like any other waiter, so sharing never frees a slot for more
//! registry work than the cap allows.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;

use tokio::time::Instant;

use super::attempt::{AttemptBudget, Attempted, InteractiveFetchError};
use super::key::{LookupKey, LookupKind};
use super::memo::Decision;
use super::{
    InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList, SharedVersions,
    log_skipped, now,
};
use crate::freshness::FreshnessSettings;
use crate::single_flight::{Claim, Follower, claim_or_follow};

/// Whether a version list carries publish-time enrichment.
///
/// An enriched list is a superset of a bare one for every reader that only inspects versions,
/// so a bare request may follow an enriched flight but never the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ListShape {
    Bare,
    Enriched,
}

impl ListShape {
    pub(super) const fn of(freshness: FreshnessSettings) -> Self {
        match freshness {
            FreshnessSettings::Disabled => Self::Bare,
            FreshnessSettings::Enabled { .. } => Self::Enriched,
        }
    }
}

/// Identity of one flight. The generation keeps an await that straddles
/// [`InteractiveFetchGate::invalidate_all`] from pairing with requests made after it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct FlightKey {
    key: Arc<LookupKey>,
    shape: ListShape,
    generation: u64,
}

impl FlightKey {
    pub(super) const fn new(key: Arc<LookupKey>, shape: ListShape, generation: u64) -> Self {
        Self {
            key,
            shape,
            generation,
        }
    }

    fn with_shape(&self, shape: ListShape) -> Self {
        Self {
            key: Arc::clone(&self.key),
            shape,
            generation: self.generation,
        }
    }
}

/// What a leader hands its followers.
#[derive(Clone)]
pub(super) enum FlightResult {
    Live(SharedVersions),
    /// The leader got no live list. A follower reports it as unverified: only the request that
    /// received a registry error itself may fail open (the memo replay rule, OQ-5).
    Failed,
}

impl std::fmt::Debug for FlightResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live(list) => f.debug_tuple("Live").field(&list.len()).finish(),
            Self::Failed => f.write_str("Failed"),
        }
    }
}

impl FlightResult {
    fn of(result: &InteractiveFetch<SharedVersions>) -> Self {
        match result {
            InteractiveFetch::Live(list) => Self::Live(Arc::clone(list)),
            InteractiveFetch::Degraded(_) => Self::Failed,
        }
    }

    fn into_fetch(self) -> InteractiveFetch<SharedVersions> {
        match self {
            Self::Live(list) => InteractiveFetch::Live(list),
            Self::Failed => InteractiveFetch::Degraded(NoLiveList::Unverified),
        }
    }
}

/// Why a follower stopped waiting.
enum Followed {
    Result(FlightResult),
    /// The leader was cancelled before answering.
    LeaderGone,
    /// This request's own deadline passed first.
    DeadlineElapsed,
}

impl InteractiveFetchGate {
    /// Number of flights currently registered.
    #[cfg(test)]
    pub(super) fn in_flight_len(&self) -> usize {
        self.version_flights.len()
    }

    /// Claims the flight for `flight`, or returns a follower of one this request may follow.
    fn claim_or_follow(&self, flight: &FlightKey) -> Claim<'_, FlightKey, FlightResult> {
        if flight.shape == ListShape::Bare
            && let Some(enriched) = self
                .version_flights
                .get(&flight.with_shape(ListShape::Enriched))
                .map(|entry| entry.clone())
        {
            return Claim::Follower(Follower::from(enriched));
        }
        claim_or_follow(&self.version_flights, flight.clone())
    }
}

async fn follow(follower: Follower<FlightResult>, deadline: Instant) -> Followed {
    match tokio::time::timeout_at(deadline, follower.wait()).await {
        Ok(Some(result)) => Followed::Result(result),
        Ok(None) => Followed::LeaderGone,
        Err(_) => Followed::DeadlineElapsed,
    }
}

/// Awaits a version list for `request`, sharing one registry poll between concurrent callers.
///
/// `fetch` is polled at most once, and only if this request becomes the leader.
pub(super) async fn await_shared<E: InteractiveFetchError>(
    gate: &InteractiveFetchGate,
    lookup: Arc<LookupKey>,
    fetch: impl Future<Output = Result<SharedVersions, E>>,
    request: &InteractiveFetchRequest<'_>,
    shape: ListShape,
) -> InteractiveFetch<SharedVersions> {
    let admitted = match gate.admit_request(&lookup, request) {
        Ok(admitted) => admitted,
        Err(kind) => return InteractiveFetch::Degraded(kind),
    };
    let (generation, background_failure_known) =
        (admitted.generation, admitted.background_failure_known);

    let deadline = Instant::now() + LookupKind::VersionList.budget();
    let flight = FlightKey::new(Arc::clone(&lookup), shape, generation);
    let mut fetch = pin!(fetch);
    loop {
        match gate.claim_or_follow(&flight) {
            Claim::Follower(follower) => match follow(follower, deadline).await {
                Followed::Result(result) => return result.into_fetch(),
                Followed::LeaderGone => {}
                Followed::DeadlineElapsed => {
                    log_skipped(request, "deadline elapsed following another request");
                    return InteractiveFetch::Degraded(NoLiveList::Unverified);
                }
            },
            Claim::Leader(leader) => {
                match lead(
                    gate,
                    fetch.as_mut(),
                    deadline,
                    &lookup,
                    request,
                    background_failure_known,
                    generation,
                )
                .await
                {
                    Led::Answered(result) => {
                        leader.publish(FlightResult::of(&result));
                        return result;
                    }
                    // Dropping the claim unanswered makes each follower take over with its
                    // own deadline: an open breaker refuses every hover among them without a
                    // poll, and a failure that proved nothing is not theirs to adopt.
                    Led::Unanswered(result) => return result,
                }
            }
        }
    }
}

/// What a leader ended with.
enum Led {
    Answered(InteractiveFetch<SharedVersions>),
    /// The leader's own result is not an answer for followers: the endpoint's breaker refused
    /// the poll, or the attempt began with too little budget for its failure to mean anything.
    Unanswered(InteractiveFetch<SharedVersions>),
}

async fn lead<E: InteractiveFetchError>(
    gate: &InteractiveFetchGate,
    fetch: impl Future<Output = Result<SharedVersions, E>>,
    deadline: Instant,
    lookup: &Arc<LookupKey>,
    request: &InteractiveFetchRequest<'_>,
    background_failure_known: bool,
    generation: u64,
) -> Led {
    // A leader that finished between this request's first decision and its claim may have
    // written a record; polling again would be a wholly avoidable duplicate.
    if let Decision::Degrade(kind, reason) =
        gate.decide(lookup, background_failure_known, generation, now())
    {
        log_skipped(request, reason.as_str());
        return Led::Answered(InteractiveFetch::Degraded(kind));
    }
    if Instant::now() >= deadline {
        log_skipped(request, "deadline elapsed before the lookup could start");
        return Led::Unanswered(InteractiveFetch::Degraded(NoLiveList::Unverified));
    }
    match gate
        .attempt(
            fetch,
            deadline,
            lookup,
            request,
            background_failure_known,
            generation,
        )
        .await
    {
        Attempted::Polled(result @ InteractiveFetch::Degraded(_), AttemptBudget::Truncated) => {
            Led::Unanswered(result)
        }
        Attempted::Polled(result, AttemptBudget::Full | AttemptBudget::Truncated) => {
            Led::Answered(result)
        }
        Attempted::Refused => Led::Unanswered(InteractiveFetch::Degraded(NoLiveList::Unverified)),
    }
}
