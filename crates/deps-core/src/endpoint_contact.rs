//! Per-attempt record of whether a registry request was sent and answered.
//!
//! The interactive fetch gate asks an attempt's HTTP layer, not its caller's error value, what
//! happened on the wire: a lookup answered from a memo, a cache hit or a local error never
//! touches the endpoint, so it must not vouch for it, and a lookup that waited on another task
//! never sent a request of its own, so it must not accuse it.
//!
//! [`ContactLedger::scope`] installs a ledger for one polled attempt. The HTTP send sites call
//! [`note_request`] after their local guards and before DNS preflight (so a hung lookup counts
//! as pending) and [`note_response`] once any status line arrives. Both are no-ops outside a
//! scope.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Sentinel for "no request is pending".
const NO_PENDING: u64 = u64::MAX;

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
    /// How long the oldest request since the last response has been outstanding, or `None` when
    /// no request is outstanding.
    pub(crate) stall: Option<Duration>,
}

impl Contact {
    /// No request sent, nothing answered: the attempt never reached the network.
    #[cfg(test)]
    pub(crate) const UNTOUCHED: Self = Self {
        response: ResponseSeen::No,
        stall: None,
    };
}

/// Wire-level contact of one attempt.
///
/// A response clears the pending request even if a concurrent request of the same attempt is
/// still outstanding (a `join!` of two endpoints, a paging batch), so a partially answering
/// endpoint reads as unstalled and its attempt as inconclusive rather than slow.
#[derive(Debug)]
pub(crate) struct ContactLedger {
    origin: Instant,
    responded: AtomicBool,
    pending_since: AtomicU64,
}

impl ContactLedger {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            responded: AtomicBool::new(false),
            pending_since: AtomicU64::new(NO_PENDING),
        })
    }

    /// Runs `fetch` with this ledger installed for [`note_request`] and [`note_response`].
    pub(crate) async fn scope<F: Future>(self: &Arc<Self>, fetch: F) -> F::Output {
        CONTACT.scope(Arc::clone(self), fetch).await
    }

    fn nanos_since_origin(&self, now: Instant) -> u64 {
        let nanos = now.saturating_duration_since(self.origin).as_nanos();
        // A pending timestamp of `NO_PENDING` itself would read as "none"; clamp below it.
        u64::try_from(nanos).map_or(NO_PENDING - 1, |n| n.min(NO_PENDING - 1))
    }

    fn request(&self, now: Instant) {
        // Failing means a request is already pending; its older timestamp is the one to keep.
        let _ = self.pending_since.compare_exchange(
            NO_PENDING,
            self.nanos_since_origin(now),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn response(&self) {
        self.responded.store(true, Ordering::Release);
        self.pending_since.store(NO_PENDING, Ordering::Release);
    }

    /// Reads the ledger as of `now`.
    pub(crate) fn snapshot(&self, now: Instant) -> Contact {
        let response = if self.responded.load(Ordering::Acquire) {
            ResponseSeen::Yes
        } else {
            ResponseSeen::No
        };
        let pending = self.pending_since.load(Ordering::Acquire);
        let stall = (pending != NO_PENDING).then(|| {
            now.saturating_duration_since(self.origin)
                .saturating_sub(Duration::from_nanos(pending))
        });
        Contact { response, stall }
    }
}

/// Records that a request is about to leave, unless one is already outstanding.
pub(crate) fn note_request() {
    // `try_with` fails outside a scope, where recording is deliberately a no-op.
    let _ = CONTACT.try_with(|ledger| ledger.request(Instant::now()));
}

/// Records that a response (any status) arrived.
pub(crate) fn note_response() {
    // `try_with` fails outside a scope, where recording is deliberately a no-op.
    let _ = CONTACT.try_with(|ledger| ledger.response());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn hooks_outside_a_scope_do_nothing() {
        note_request();
        note_response();
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_ledger_is_untouched() {
        let ledger = ContactLedger::new();
        assert_eq!(ledger.snapshot(Instant::now()), Contact::UNTOUCHED);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pending_request_stalls_until_answered() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                note_request();
                tokio::time::sleep(Duration::from_secs(4)).await;
                let stalled = ledger.snapshot(Instant::now());
                assert_eq!(stalled.response, ResponseSeen::No);
                assert_eq!(stalled.stall, Some(Duration::from_secs(4)));

                note_response();
                let answered = ledger.snapshot(Instant::now());
                assert_eq!(answered.response, ResponseSeen::Yes);
                assert_eq!(answered.stall, None);
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_stall_restarts_at_the_next_request_after_a_response() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                note_request();
                tokio::time::sleep(Duration::from_millis(100)).await;
                note_response();
                tokio::time::sleep(Duration::from_secs(3)).await;
                note_request();
                tokio::time::sleep(Duration::from_secs(2)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.response, ResponseSeen::Yes);
                assert_eq!(contact.stall, Some(Duration::from_secs(2)));
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_request_keeps_the_oldest_pending_time() {
        let ledger = ContactLedger::new();
        ledger
            .scope(async {
                note_request();
                tokio::time::sleep(Duration::from_secs(2)).await;
                note_request();
                tokio::time::sleep(Duration::from_secs(1)).await;

                let contact = ledger.snapshot(Instant::now());
                assert_eq!(contact.stall, Some(Duration::from_secs(3)));
            })
            .await;
    }
}
