//! Per-attempt record of whether a registry request was sent and answered.
//!
//! The interactive fetch gate asks an attempt's HTTP layer, not its caller's error value, what
//! happened on the wire: a lookup answered from a memo, a cache hit or a local error never
//! touches the endpoint, so it must not vouch for it, and a lookup that waited on another task
//! never sent a request of its own, so it must not accuse it.
//!
//! [`ContactLedger::scope`] installs a ledger for one polled attempt. The HTTP send sites call
//! [`note_request`] after their local guards and before DNS preflight (so a hung lookup counts
//! as outstanding) and hold the returned [`RequestNote`] until the send ends:
//! [`RequestNote::answered`] once any status line arrives, a plain drop on error or
//! cancellation. [`note_request`] is a no-op outside a scope.
//!
//! The ledger measures busy time: the time at least one request was outstanding since the last
//! response. A request that fails after a long wait still counts as stalled, while a fast
//! transport error followed by idle time does not accumulate anything.

use std::future::Future;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

tokio::task_local! {
    static CONTACT: Arc<ContactLedger>;
}

/// Whether any response arrived during an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseSeen {
    Yes,
    No,
}

/// What an attempt observed on the wire when it was snapshotted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contact {
    pub(crate) response: ResponseSeen,
    /// How long at least one request has been outstanding since the last response; zero when
    /// none has been.
    pub(crate) stall: Duration,
}

impl Contact {
    /// No request sent, nothing answered: the attempt never reached the network.
    #[cfg(test)]
    pub(crate) const UNTOUCHED: Self = Self {
        response: ResponseSeen::No,
        stall: Duration::ZERO,
    };
}

/// Whether any request is outstanding, and since when.
#[derive(Debug, Clone, Copy)]
enum Busy {
    Idle,
    Open {
        since: Instant,
        outstanding: NonZeroU32,
    },
}

impl Busy {
    fn opened(self, now: Instant) -> Self {
        match self {
            Self::Idle => Self::Open {
                since: now,
                outstanding: NonZeroU32::MIN,
            },
            Self::Open { since, outstanding } => Self::Open {
                since,
                outstanding: outstanding.saturating_add(1),
            },
        }
    }

    /// One request ended; `restart` maps the interval start when others remain outstanding.
    fn closed_one(self, restart: impl FnOnce(Instant) -> Instant) -> Self {
        match self {
            Self::Idle => Self::Idle,
            Self::Open { since, outstanding } => {
                NonZeroU32::new(outstanding.get() - 1).map_or(Self::Idle, |outstanding| {
                    Self::Open {
                        since: restart(since),
                        outstanding,
                    }
                })
            }
        }
    }
}

#[derive(Debug)]
struct WireState {
    responded: ResponseSeen,
    busy_closed: Duration,
    busy: Busy,
}

impl WireState {
    fn busy_time(&self, now: Instant) -> Duration {
        match self.busy {
            Busy::Idle => self.busy_closed,
            Busy::Open { since, .. } => self.busy_closed + now.saturating_duration_since(since),
        }
    }

    fn answered(&mut self, now: Instant) {
        self.responded = ResponseSeen::Yes;
        self.busy_closed = Duration::ZERO;
        self.busy = self.busy.closed_one(|_| now);
    }

    fn abandoned(&mut self, now: Instant) {
        if let Busy::Open { since, outstanding } = self.busy
            && outstanding == NonZeroU32::MIN
        {
            self.busy_closed += now.saturating_duration_since(since);
        }
        self.busy = self.busy.closed_one(|since| since);
    }
}

/// Wire-level contact of one attempt.
///
/// A response resets the busy time even if a concurrent request of the same attempt is still
/// outstanding (a `join!` of two endpoints, a paging batch), so a partially answering endpoint
/// reads as unstalled and its attempt as inconclusive rather than slow.
#[derive(Debug)]
pub(crate) struct ContactLedger {
    state: Mutex<WireState>,
}

impl ContactLedger {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WireState {
                responded: ResponseSeen::No,
                busy_closed: Duration::ZERO,
                busy: Busy::Idle,
            }),
        })
    }

    /// Runs `fetch` with this ledger installed for [`note_request`].
    pub(crate) async fn scope<F: Future>(self: &Arc<Self>, fetch: F) -> F::Output {
        CONTACT.scope(Arc::clone(self), fetch).await
    }

    /// No await is held under the lock; a poisoned lock still holds consistent state because
    /// every update is a plain field assignment.
    fn lock(&self) -> MutexGuard<'_, WireState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the ledger as of `now`.
    pub(crate) fn snapshot(&self, now: Instant) -> Contact {
        let state = self.lock();
        Contact {
            response: state.responded,
            stall: state.busy_time(now),
        }
    }
}

/// One request that left (or is about to leave) over the wire.
///
/// Hold it across the send. [`Self::answered`] records the response; dropping it unanswered
/// (error, cancellation, a timeout dropping the future) closes the request without vouching
/// for the endpoint. It owns its ledger, so it needs no task-local scope when it ends.
#[must_use = "the note must be held across the send so the request counts as outstanding"]
#[derive(Debug)]
pub(crate) struct RequestNote {
    ledger: Option<Arc<ContactLedger>>,
}

impl RequestNote {
    /// Records that a response (any status) arrived.
    pub(crate) fn answered(mut self) {
        if let Some(ledger) = self.ledger.take() {
            ledger.lock().answered(Instant::now());
        }
    }
}

impl Drop for RequestNote {
    fn drop(&mut self) {
        if let Some(ledger) = self.ledger.take() {
            ledger.lock().abandoned(Instant::now());
        }
    }
}

/// Records that a request is about to leave; a no-op outside a scope.
pub(crate) fn note_request() -> RequestNote {
    // `try_with` fails outside a scope, where recording is deliberately a no-op.
    let ledger = CONTACT.try_with(Arc::clone).ok();
    if let Some(ledger) = &ledger {
        let mut state = ledger.lock();
        state.busy = state.busy.opened(Instant::now());
    }
    RequestNote { ledger }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn hooks_outside_a_scope_do_nothing() {
        note_request().answered();
        drop(note_request());
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_ledger_is_untouched() {
        let ledger = ContactLedger::new();
        assert_eq!(ledger.snapshot(Instant::now()), Contact::UNTOUCHED);
    }

    #[tokio::test(start_paused = true)]
    async fn an_outstanding_request_stalls_until_answered() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let note = note_request();
                tokio::time::sleep(Duration::from_secs(4)).await;
                let stalled = ledger.snapshot(Instant::now());
                assert_eq!(stalled.response, ResponseSeen::No);
                assert_eq!(stalled.stall, Duration::from_secs(4));

                note.answered();
                let answered = ledger.snapshot(Instant::now());
                assert_eq!(answered.response, ResponseSeen::Yes);
                assert_eq!(answered.stall, Duration::ZERO);
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_stall_restarts_at_the_next_request_after_a_response() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let first = note_request();
                tokio::time::sleep(Duration::from_millis(100)).await;
                first.answered();
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _second = note_request();
                tokio::time::sleep(Duration::from_secs(2)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.response, ResponseSeen::Yes);
                assert_eq!(contact.stall, Duration::from_secs(2));
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_request_keeps_the_oldest_busy_start() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let _first = note_request();
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _second = note_request();
                tokio::time::sleep(Duration::from_secs(1)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.stall, Duration::from_secs(3));
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_failed_request_still_counts_as_stalled() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let note = note_request();
                tokio::time::sleep(Duration::from_secs(6)).await;
                drop(note);
                tokio::time::sleep(Duration::from_secs(30)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.response, ResponseSeen::No);
                assert_eq!(contact.stall, Duration::from_secs(6));
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_error_followed_by_idle_time_accumulates_nothing() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                drop(note_request());
                tokio::time::sleep(Duration::from_secs(60)).await;

                assert_eq!(ledger.snapshot(Instant::now()).stall, Duration::ZERO);
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_while_another_request_is_outstanding_restarts_the_stall() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let slow = note_request();
                let fast = note_request();
                tokio::time::sleep(Duration::from_secs(4)).await;
                fast.answered();
                tokio::time::sleep(Duration::from_secs(1)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.response, ResponseSeen::Yes);
                assert_eq!(contact.stall, Duration::from_secs(1));

                drop(slow);
                assert_eq!(
                    ledger.snapshot(Instant::now()).stall,
                    Duration::from_secs(1)
                );
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn busy_time_pauses_while_idle_between_requests() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                let first = note_request();
                tokio::time::sleep(Duration::from_secs(2)).await;
                drop(first);
                tokio::time::sleep(Duration::from_secs(10)).await;
                let _second = note_request();
                tokio::time::sleep(Duration::from_secs(3)).await;

                assert_eq!(
                    ledger.snapshot(Instant::now()).stall,
                    Duration::from_secs(5)
                );
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_note_ending_outside_its_scope_still_updates_its_ledger() {
        let ledger = ContactLedger::new();
        let note = ledger.scope(async { note_request() }).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(note);

        assert_eq!(
            ledger.snapshot(Instant::now()).stall,
            Duration::from_secs(3)
        );
    }
}
