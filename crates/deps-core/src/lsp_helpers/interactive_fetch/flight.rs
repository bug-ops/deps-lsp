//! Single-flight for interactive version-list awaits (FR-007).
//!
//! Concurrent hovers and code actions for one package would each poll their own registry
//! request. The first becomes the leader and polls; the rest follow its shared list. Followers
//! hold a dispatch permit like any other waiter, so sharing never frees a slot for more
//! registry work than the cap allows.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;

use tokio::sync::watch;
use tokio::time::Instant;

use super::attempt::Attempted;
use super::key::InteractiveFetchKey;
use super::memo::Decision;
use super::{
    InteractiveFetch, InteractiveFetchGate, InteractiveFetchRequest, NoLiveList, SharedVersions,
    log_skipped, now,
};
use crate::freshness::FreshnessSettings;
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;
use crate::single_flight::{InFlightGuard, Slot, claim_or_follow};

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
    key: InteractiveFetchKey,
    shape: ListShape,
    generation: u64,
}

impl FlightKey {
    pub(super) const fn new(key: InteractiveFetchKey, shape: ListShape, generation: u64) -> Self {
        Self {
            key,
            shape,
            generation,
        }
    }

    fn with_shape(&self, shape: ListShape) -> Self {
        Self {
            key: self.key.clone(),
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

type FlightReceiver = watch::Receiver<Slot<FlightResult>>;

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

    /// Claims the flight for `flight`, or returns the receiver of one this request may follow.
    fn claim_or_follow(
        &self,
        flight: &FlightKey,
    ) -> Result<watch::Sender<Slot<FlightResult>>, FlightReceiver> {
        if flight.shape == ListShape::Bare
            && let Some(enriched) = self
                .version_flights
                .get(&flight.with_shape(ListShape::Enriched))
                .map(|entry| entry.clone())
        {
            return Err(enriched);
        }
        claim_or_follow(&self.version_flights, flight.clone())
    }
}

async fn follow(mut receiver: FlightReceiver, deadline: Instant) -> Followed {
    let wait = async {
        loop {
            let slot = receiver.borrow_and_update().clone();
            if let Slot::Ready(result) = slot {
                return Some(result);
            }
            if receiver.changed().await.is_err() {
                return None;
            }
        }
    };
    match tokio::time::timeout_at(deadline, wait).await {
        Ok(Some(result)) => Followed::Result(result),
        Ok(None) => Followed::LeaderGone,
        Err(_) => Followed::DeadlineElapsed,
    }
}

/// Awaits a version list for `request`, sharing one registry poll between concurrent callers.
///
/// `fetch` is polled at most once, and only if this request becomes the leader.
pub(super) async fn await_shared<E>(
    gate: &InteractiveFetchGate,
    key: InteractiveFetchKey,
    fetch: impl Future<Output = Result<SharedVersions, E>>,
    request: &InteractiveFetchRequest<'_>,
    shape: ListShape,
) -> InteractiveFetch<SharedVersions> {
    // Read before the outcomes so an invalidation racing this request discards its writes.
    let generation = gate.generation();
    let background_failure_known = request.background_failure_known();
    if let Decision::Degrade(kind, reason) =
        gate.decide(&key, background_failure_known, generation, now())
    {
        log_skipped(request, reason.as_str());
        return InteractiveFetch::Degraded(kind);
    }
    let Ok(_permit) = gate.permits.try_acquire() else {
        log_skipped(request, "interactive fetch concurrency cap reached");
        return InteractiveFetch::Degraded(NoLiveList::Unverified);
    };

    let deadline = Instant::now() + REGISTRY_FETCH_BUDGET;
    let flight = FlightKey::new(key.clone(), shape, generation);
    let mut fetch = pin!(fetch);
    loop {
        match gate.claim_or_follow(&flight) {
            Err(receiver) => match follow(receiver, deadline).await {
                Followed::Result(result) => return result.into_fetch(),
                Followed::LeaderGone => {}
                Followed::DeadlineElapsed => {
                    log_skipped(request, "deadline elapsed following another request");
                    return InteractiveFetch::Degraded(NoLiveList::Unverified);
                }
            },
            Ok(sender) => {
                // Declared after `sender`, so the claim is released before followers wake.
                let _claim = InFlightGuard::new(&gate.version_flights, flight.clone());
                match lead(
                    gate,
                    fetch.as_mut(),
                    deadline,
                    &key,
                    request,
                    background_failure_known,
                    generation,
                )
                .await
                {
                    Led::Answered(result) => {
                        sender.send_replace(Slot::Ready(FlightResult::of(&result)));
                        return result;
                    }
                    // Dropping the claim unanswered makes each follower take over, and the
                    // open breaker refuses every hover among them without a poll.
                    Led::Refused => return InteractiveFetch::Degraded(NoLiveList::Unverified),
                }
            }
        }
    }
}

/// What a leader ended with.
enum Led {
    Answered(InteractiveFetch<SharedVersions>),
    /// The endpoint's breaker refused the poll.
    Refused,
}

async fn lead<E>(
    gate: &InteractiveFetchGate,
    fetch: impl Future<Output = Result<SharedVersions, E>>,
    deadline: Instant,
    key: &InteractiveFetchKey,
    request: &InteractiveFetchRequest<'_>,
    background_failure_known: bool,
    generation: u64,
) -> Led {
    // A leader that finished between this request's first decision and its claim may have
    // written a record; polling again would be a wholly avoidable duplicate.
    if let Decision::Degrade(kind, reason) =
        gate.decide(key, background_failure_known, generation, now())
    {
        log_skipped(request, reason.as_str());
        return Led::Answered(InteractiveFetch::Degraded(kind));
    }
    if Instant::now() >= deadline {
        log_skipped(request, "deadline elapsed before the lookup could start");
        return Led::Answered(InteractiveFetch::Degraded(NoLiveList::Unverified));
    }
    match gate
        .attempt(
            fetch,
            deadline,
            key,
            request,
            background_failure_known,
            generation,
        )
        .await
    {
        Attempted::Polled(result) => Led::Answered(result),
        Attempted::Refused => Led::Refused,
    }
}
