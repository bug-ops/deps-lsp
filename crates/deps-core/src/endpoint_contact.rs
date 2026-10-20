//! Per-attempt record of whether a registry request was sent and answered.
//!
//! The interactive fetch gate asks an attempt's HTTP layer, not its caller's error value, what
//! happened on the wire: a lookup answered from a memo, a cache hit or a local error never
//! touches the endpoint, so it must not vouch for it, and a lookup that waited on another task
//! never sent a request of its own, so it must not accuse it.
//!
//! [`AttemptContact::scope`] installs a ledger for one polled attempt. The HTTP send sites call
//! [`note_request`] after their local guards and before DNS preflight (so a hung lookup counts
//! as outstanding) and hold the returned [`RequestNote`] until the send ends:
//! [`RequestNote::answered`] once any status line arrives, a plain drop on error or
//! cancellation. [`note_request`] is a no-op outside a scope.
//!
//! The ledger measures busy time: the time at least one request was outstanding since the last
//! response. A request that fails after a long wait still counts as stalled, while a fast
//! transport error followed by idle time does not accumulate anything.
//!
//! An attempt that coalesces onto a request another task put on the wire (a `OnceCell`, a
//! per-key lock) sends nothing of its own. Orchestration code tags the task that does send with
//! [`observe_ecosystem`] and [`observe_endpoint`], so its requests also feed a ledger shared by
//! every task of the same `(ecosystem, endpoint)`; an attempt that never saw a response of its
//! own reads that ledger over its own wait.

use std::future::Future;
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::time::Instant;

use crate::{EcosystemId, EndpointFingerprint, RegistryEndpoint};

tokio::task_local! {
    static CONTACT: ContactScope;
    static ECOSYSTEM: EcosystemId;
}

/// Which ledgers a request sent in the current task feeds.
#[derive(Debug, Clone)]
enum ContactScope {
    /// An interactive attempt that cannot name its endpoint, or does not count for it.
    Attempt { own: Arc<ContactLedger> },
    /// An interactive attempt on a resolved endpoint: its requests also feed the shared ledger.
    AttemptOnEndpoint {
        own: Arc<ContactLedger>,
        shared: Arc<ContactLedger>,
    },
    /// Orchestration code fetching from a resolved endpoint on its own.
    Fetch { shared: Arc<ContactLedger> },
}

impl ContactScope {
    fn ledgers(&self) -> (Option<&Arc<ContactLedger>>, Option<&Arc<ContactLedger>>) {
        match self {
            Self::Attempt { own } => (Some(own), None),
            Self::AttemptOnEndpoint { own, shared } => (Some(own), Some(shared)),
            Self::Fetch { shared } => (None, Some(shared)),
        }
    }
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

/// A reading of a ledger's busy time, comparable with an earlier reading of the same ledger.
#[derive(Debug, Clone, Copy)]
struct WireMark {
    epoch: u64,
    busy: Duration,
}

impl WireMark {
    /// Busy time between `start` and this reading. After a response the busy time restarted
    /// from zero, so it already lies inside the window.
    fn stall_since(self, start: Self) -> Duration {
        if self.epoch == start.epoch {
            self.busy.saturating_sub(start.busy)
        } else {
            self.busy
        }
    }
}

#[derive(Debug)]
struct WireState {
    responded: ResponseSeen,
    epoch: u64,
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
        self.epoch = self.epoch.saturating_add(1);
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

/// Wire-level contact of one attempt, or of one endpoint when shared.
///
/// A response resets the busy time even if a concurrent request is still outstanding (a
/// `join!` of two endpoints, a paging batch), so a partially answering endpoint reads as
/// unstalled and its attempt as inconclusive rather than slow.
#[derive(Debug)]
pub(crate) struct ContactLedger {
    state: Mutex<WireState>,
}

impl ContactLedger {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WireState {
                responded: ResponseSeen::No,
                epoch: 0,
                busy_closed: Duration::ZERO,
                busy: Busy::Idle,
            }),
        })
    }

    /// Runs `fetch` with this ledger as the only one its requests feed.
    #[cfg(test)]
    pub(crate) async fn scope<F: Future>(self: &Arc<Self>, fetch: F) -> F::Output {
        let scope = ContactScope::Attempt {
            own: Arc::clone(self),
        };
        CONTACT.scope(scope, fetch).await
    }

    fn opened(&self, now: Instant) {
        let mut state = self.lock();
        state.busy = state.busy.opened(now);
    }

    fn answered(&self, now: Instant) {
        self.lock().answered(now);
    }

    fn abandoned(&self, now: Instant) {
        self.lock().abandoned(now);
    }

    fn mark(&self, now: Instant) -> WireMark {
        let state = self.lock();
        WireMark {
            epoch: state.epoch,
            busy: state.busy_time(now),
        }
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
/// for the endpoint. It owns its (at most two) ledgers, so it needs no task-local scope when it
/// ends.
#[must_use = "the note must be held across the send so the request counts as outstanding"]
#[derive(Debug, Default)]
pub(crate) struct RequestNote {
    own: Option<Arc<ContactLedger>>,
    shared: Option<Arc<ContactLedger>>,
}

impl RequestNote {
    /// Records that a response (any status) arrived.
    pub(crate) fn answered(mut self) {
        let now = Instant::now();
        for ledger in [self.own.take(), self.shared.take()].into_iter().flatten() {
            ledger.answered(now);
        }
    }
}

impl Drop for RequestNote {
    fn drop(&mut self) {
        let now = Instant::now();
        for ledger in [self.own.take(), self.shared.take()].into_iter().flatten() {
            ledger.abandoned(now);
        }
    }
}

/// Records that a request is about to leave; a no-op outside a scope.
pub(crate) fn note_request() -> RequestNote {
    // `try_with` fails outside a scope, where recording is deliberately a no-op.
    CONTACT
        .try_with(|scope| {
            let now = Instant::now();
            let (own, shared) = scope.ledgers();
            for ledger in own.into_iter().chain(shared) {
                ledger.opened(now);
            }
            RequestNote {
                own: own.cloned(),
                shared: shared.cloned(),
            }
        })
        .unwrap_or_default()
}

/// Past this many registered endpoints, dead entries are pruned before the next insert.
const PRUNE_ABOVE: usize = 64;

/// Ledgers shared by every task of one `(ecosystem, endpoint)`.
///
/// Entries are weak: a ledger lives while some fetch or attempt holds it, so the map cannot
/// grow with the endpoints a long session has touched.
#[derive(Debug, Default)]
struct SharedLedgers(DashMap<(EcosystemId, EndpointFingerprint), Weak<ContactLedger>>);

impl SharedLedgers {
    fn acquire(&self, ecosystem: EcosystemId, endpoint: EndpointFingerprint) -> Arc<ContactLedger> {
        if self.0.len() > PRUNE_ABOVE {
            self.0.retain(|_, ledger| ledger.strong_count() > 0);
        }
        match self.0.entry((ecosystem, endpoint)) {
            Entry::Occupied(mut slot) => slot.get().upgrade().unwrap_or_else(|| {
                let ledger = ContactLedger::new();
                slot.insert(Arc::downgrade(&ledger));
                ledger
            }),
            Entry::Vacant(slot) => {
                let ledger = ContactLedger::new();
                slot.insert(Arc::downgrade(&ledger));
                ledger
            }
        }
    }
}

// Process-global: tests that share it must use a host/ecosystem pair no other test uses.
static SHARED: LazyLock<SharedLedgers> = LazyLock::new(SharedLedgers::default);

/// Which of an attempt's two views of the wire decided its stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StallView {
    /// The attempt's own requests.
    Own,
    /// Requests of other tasks on the same endpoint during the attempt's wait.
    Shared,
}

impl StallView {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Shared => "shared",
        }
    }
}

#[derive(Debug)]
struct SharedWindow {
    ledger: Arc<ContactLedger>,
    start: WireMark,
}

/// The wire contact of one interactive attempt: its own ledger, plus a window onto the
/// endpoint's shared ledger when the attempt can name one.
#[derive(Debug)]
pub(crate) struct AttemptContact {
    own: Arc<ContactLedger>,
    shared: Option<SharedWindow>,
}

impl AttemptContact {
    /// An attempt whose requests, and only those, are its evidence.
    pub(crate) fn own_only() -> Self {
        Self {
            own: ContactLedger::new(),
            shared: None,
        }
    }

    /// An attempt on a resolved endpoint: its requests also feed the endpoint's shared ledger,
    /// and requests other tasks have outstanding there during its wait are evidence too.
    pub(crate) fn on_endpoint(ecosystem: EcosystemId, endpoint: EndpointFingerprint) -> Self {
        let ledger = SHARED.acquire(ecosystem, endpoint);
        let start = ledger.mark(Instant::now());
        Self {
            own: ContactLedger::new(),
            shared: Some(SharedWindow { ledger, start }),
        }
    }

    /// Runs `fetch` with this attempt's ledgers installed for [`note_request`].
    pub(crate) async fn scope<F: Future>(&self, fetch: F) -> F::Output {
        let own = Arc::clone(&self.own);
        let scope = match &self.shared {
            Some(window) => ContactScope::AttemptOnEndpoint {
                own,
                shared: Arc::clone(&window.ledger),
            },
            None => ContactScope::Attempt { own },
        };
        CONTACT.scope(scope, fetch).await
    }

    /// What the attempt saw as of `now`.
    ///
    /// An attempt that received a response itself is judged by its own requests alone: it was
    /// served by the endpoint, whatever other tasks are waiting on. One that received none
    /// takes the longer of its own stall and the shared one, so a request another task put on
    /// the wire counts exactly as far as it was outstanding during this attempt's own wait.
    pub(crate) fn observe(&self, now: Instant) -> (Contact, StallView) {
        let own = self.own.snapshot(now);
        match (&self.shared, own.response) {
            (Some(window), ResponseSeen::No) => {
                let shared = window.ledger.mark(now).stall_since(window.start);
                if shared > own.stall {
                    (
                        Contact {
                            stall: shared,
                            ..own
                        },
                        StallView::Shared,
                    )
                } else {
                    (own, StallView::Own)
                }
            }
            (Some(_), ResponseSeen::Yes) | (None, _) => (own, StallView::Own),
        }
    }
}

/// Runs `fetch` with `ecosystem` recorded, so that [`observe_endpoint`] inside it knows which
/// ecosystem's breaker evidence its requests belong to.
///
/// For orchestration code that fetches on behalf of an ecosystem (the background fetch, the
/// completion dispatch), not for ecosystem crates: a crate's coalescing layer needs no hook of
/// its own.
///
/// # Examples
///
/// ```
/// use deps_core::{EcosystemId, observe_ecosystem};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let answer = observe_ecosystem(EcosystemId::NuGet, async { 42 }).await;
/// assert_eq!(answer, 42);
/// # }
/// ```
pub async fn observe_ecosystem<F: Future>(ecosystem: EcosystemId, fetch: F) -> F::Output {
    ECOSYSTEM.scope(ecosystem, fetch).await
}

/// Runs `fetch` so that its HTTP requests feed the breaker evidence of `endpoint`, under the
/// ecosystem set by an enclosing [`observe_ecosystem`].
///
/// An interactive lookup that waits on this fetch's request (a shared `OnceCell`, a per-key
/// lock) sends nothing itself; this lets the interactive fetch gate see that the request is
/// outstanding. For orchestration code, not for ecosystem crates.
///
/// It runs `fetch` unchanged when there is no enclosing [`observe_ecosystem`], when `endpoint`
/// is [`RegistryEndpoint::Unresolved`], or when the task is already inside an interactive
/// attempt (whose own accounting must not be shadowed).
///
/// # Examples
///
/// ```
/// use deps_core::{EcosystemId, EgressTier, RegistryEndpoint, observe_ecosystem, observe_endpoint};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let endpoint = RegistryEndpoint::from_base_str("https://api.nuget.org/v3/", EgressTier::Baseline);
/// let answer = observe_ecosystem(
///     EcosystemId::NuGet,
///     observe_endpoint(endpoint, async { 42 }),
/// )
/// .await;
/// assert_eq!(answer, 42);
/// # }
/// ```
pub async fn observe_endpoint<F: Future>(endpoint: RegistryEndpoint, fetch: F) -> F::Output {
    match fetch_scope(endpoint) {
        Some(scope) => CONTACT.scope(scope, fetch).await,
        None => fetch.await,
    }
}

fn fetch_scope(endpoint: RegistryEndpoint) -> Option<ContactScope> {
    if CONTACT.try_with(|_| ()).is_ok() {
        return None;
    }
    let RegistryEndpoint::Resolved(fingerprint) = endpoint else {
        return None;
    };
    let ecosystem = ECOSYSTEM.try_with(|ecosystem| *ecosystem).ok()?;
    Some(ContactScope::Fetch {
        shared: SHARED.acquire(ecosystem, fingerprint),
    })
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

    fn fingerprint(base: &str) -> EndpointFingerprint {
        let RegistryEndpoint::Resolved(fingerprint) =
            RegistryEndpoint::from_base_str(base, crate::EgressTier::Baseline)
        else {
            panic!("test base URL must resolve");
        };
        fingerprint
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    async fn sleep(n: u64) {
        tokio::time::sleep(secs(n)).await;
    }

    /// Spawns a task that holds one never-answered request on `base` for `hold` seconds.
    fn spawn_holder(ecosystem: EcosystemId, base: &str, hold: u64) -> tokio::task::JoinHandle<()> {
        let endpoint = RegistryEndpoint::from_base_str(base, crate::EgressTier::Baseline);
        tokio::spawn(observe_ecosystem(
            ecosystem,
            observe_endpoint(endpoint, async move {
                let _note = note_request();
                sleep(hold).await;
            }),
        ))
    }

    #[test]
    fn window_arithmetic_subtracts_within_an_epoch_and_restarts_across_epochs() {
        let start = WireMark {
            epoch: 3,
            busy: secs(4),
        };
        let same = WireMark {
            epoch: 3,
            busy: secs(9),
        };
        let later = WireMark {
            epoch: 4,
            busy: secs(2),
        };
        assert_eq!(same.stall_since(start), secs(5));
        assert_eq!(later.stall_since(start), secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_reads_the_request_another_task_has_outstanding() {
        let base = "https://waiter.example/";
        let holder = spawn_holder(EcosystemId::NuGet, base, 60);
        tokio::task::yield_now().await;
        sleep(1).await;

        let waiter = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));
        sleep(5).await;

        let (contact, view) = waiter.observe(Instant::now());
        assert_eq!(contact.response, ResponseSeen::No);
        assert_eq!(contact.stall, secs(5));
        assert_eq!(view, StallView::Shared);
        assert_eq!(waiter.own.snapshot(Instant::now()), Contact::UNTOUCHED);
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_joining_a_long_outstanding_request_counts_only_its_own_wait() {
        let base = "https://late-join.example/";
        let holder = spawn_holder(EcosystemId::GithubActions, base, 300);
        tokio::task::yield_now().await;
        sleep(59).await;

        let waiter = AttemptContact::on_endpoint(EcosystemId::GithubActions, fingerprint(base));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (contact, _) = waiter.observe(Instant::now());
        assert_eq!(contact.stall, Duration::from_millis(100));
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_takeover_keeps_the_busy_time_continuous() {
        let base = "https://takeover.example/";
        let holder = spawn_holder(EcosystemId::NuGet, base, 5);
        tokio::task::yield_now().await;
        sleep(1).await;

        let attempt = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));
        attempt
            .scope(async {
                holder.await.unwrap();
                let _own = note_request();
                sleep(1).await;
            })
            .await;

        let (contact, view) = attempt.observe(Instant::now());
        assert_eq!(contact.stall, secs(5));
        assert_eq!(view, StallView::Shared);
        assert_eq!(attempt.own.snapshot(Instant::now()).stall, secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_with_its_own_response_ignores_the_shared_view() {
        let base = "https://own-response.example/";
        let holder = spawn_holder(EcosystemId::NuGet, base, 60);
        tokio::task::yield_now().await;

        let attempt = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));
        attempt
            .scope(async {
                note_request().answered();
            })
            .await;
        sleep(8).await;

        let (contact, view) = attempt.observe(Instant::now());
        assert_eq!(contact.response, ResponseSeen::Yes);
        assert_eq!(view, StallView::Own);
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_paging_holder_never_looks_stalled_to_a_waiter() {
        let base = "https://paging.example/";
        let endpoint = RegistryEndpoint::from_base_str(base, crate::EgressTier::Baseline);
        let holder = tokio::spawn(observe_ecosystem(
            EcosystemId::GithubActions,
            observe_endpoint(endpoint, async {
                for _ in 0..12 {
                    let note = note_request();
                    sleep(1).await;
                    note.answered();
                }
            }),
        ));
        tokio::task::yield_now().await;
        let waiter = AttemptContact::on_endpoint(EcosystemId::GithubActions, fingerprint(base));
        sleep(11).await;

        let (contact, _) = waiter.observe(Instant::now());
        assert!(contact.stall < secs(5), "stall was {:?}", contact.stall);
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_same_endpoint_under_another_ecosystem_is_isolated() {
        let base = "https://isolated.example/";
        let holder = spawn_holder(EcosystemId::Maven, base, 60);
        tokio::task::yield_now().await;

        let gradle = AttemptContact::on_endpoint(EcosystemId::Gradle, fingerprint(base));
        sleep(8).await;

        assert_eq!(gradle.observe(Instant::now()).0, Contact::UNTOUCHED);
        holder.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_own_only_attempt_never_writes_shared_state() {
        let base = "https://decoration.example/";
        let watcher = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));
        let decoration = AttemptContact::own_only();
        decoration
            .scope(async {
                let _note = note_request();
                sleep(7).await;
            })
            .await;

        assert_eq!(watcher.observe(Instant::now()).0, Contact::UNTOUCHED);
    }

    #[tokio::test(start_paused = true)]
    async fn observe_endpoint_does_not_shadow_an_enclosing_attempt() {
        let base = "https://no-shadow.example/";
        let endpoint = RegistryEndpoint::from_base_str(base, crate::EgressTier::Baseline);
        let watcher = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));
        let attempt = AttemptContact::own_only();
        observe_ecosystem(
            EcosystemId::NuGet,
            attempt.scope(observe_endpoint(endpoint, async {
                let _note = note_request();
                sleep(4).await;
            })),
        )
        .await;

        assert_eq!(attempt.own.snapshot(Instant::now()).stall, secs(4));
        assert_eq!(watcher.observe(Instant::now()).0, Contact::UNTOUCHED);
    }

    #[tokio::test(start_paused = true)]
    async fn observe_endpoint_without_an_ecosystem_or_a_resolved_endpoint_is_a_no_op() {
        let base = "https://no-op.example/";
        let endpoint = RegistryEndpoint::from_base_str(base, crate::EgressTier::Baseline);
        let watcher = AttemptContact::on_endpoint(EcosystemId::NuGet, fingerprint(base));

        observe_endpoint(endpoint, async {
            let _note = note_request();
            sleep(4).await;
        })
        .await;
        observe_ecosystem(
            EcosystemId::NuGet,
            observe_endpoint(RegistryEndpoint::Unresolved, async {
                let _note = note_request();
                sleep(4).await;
            }),
        )
        .await;

        assert_eq!(watcher.observe(Instant::now()).0, Contact::UNTOUCHED);
    }

    #[test]
    fn dead_shared_ledgers_are_pruned_past_the_threshold() {
        let ledgers = SharedLedgers::default();
        for index in 0..=PRUNE_ABOVE {
            let fingerprint = fingerprint(&format!("https://prune-{index}.example/"));
            drop(ledgers.acquire(EcosystemId::Cargo, fingerprint));
        }
        assert!(ledgers.0.len() > PRUNE_ABOVE);

        let live = ledgers.acquire(
            EcosystemId::Cargo,
            fingerprint("https://prune-live.example/"),
        );
        assert_eq!(ledgers.0.len(), 1);
        drop(live);
    }

    #[test]
    fn a_live_shared_ledger_is_reused_and_a_dead_one_replaced() {
        let ledgers = SharedLedgers::default();
        let key = fingerprint("https://reuse.example/");
        let first = ledgers.acquire(EcosystemId::Npm, key);
        assert!(Arc::ptr_eq(&first, &ledgers.acquire(EcosystemId::Npm, key)));
        drop(first);
        let replaced = ledgers.acquire(EcosystemId::Npm, key);
        assert_eq!(Arc::strong_count(&replaced), 1);
    }
}
