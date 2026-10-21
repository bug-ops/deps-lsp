//! Local, process-lifetime rate-limit short-circuiting shared across ecosystem crates.
//!
//! Extracted from `deps-github-actions` and `deps-gitlab-ci` (#1205), which had
//! independently implemented the identical mechanism.

use crate::error::RateLimitEvidence;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Default cooldown, in seconds, a [`RateLimitGate`] keeps short-circuiting further requests
/// after a rate-limit/auth-rejection trip, before allowing another live request.
///
/// Extracted from `deps-github-actions` and `deps-gitlab-ci`'s identical
/// `RATE_LIMIT_COOLDOWN_SECS` constants (#1480 item 8) — long enough to meaningfully stop
/// hammering a workspace with many unique packages, short enough to recover without a
/// restart.
pub const DEFAULT_COOLDOWN_SECS: u64 = 300;

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Locally short-circuits further requests for a fixed cooldown once an upstream has
/// rate-limited (or auth-rejected) this client.
///
/// A *mechanism*, not a policy: the gate holds no notion of scope. The caller decides
/// whether one gate covers a whole process (`deps-github-actions`: one GitHub API, one
/// gate) or one host each (`deps-gitlab-ci`, spec §9.3) by choosing where it stores it.
///
/// Both load and store use [`Ordering::Relaxed`]: a stale read costs at most one extra
/// doomed request (if a trip is not yet visible) or one extra short-circuit (if a clear
/// is not yet visible) — never a correctness violation, so no stronger ordering is needed.
///
/// # Examples
///
/// ```
/// use deps_core::rate_limit::RateLimitGate;
///
/// let gate = RateLimitGate::new(300);
/// assert!(!gate.is_tripped());
/// gate.trip();
/// assert!(gate.is_tripped());
/// ```
#[derive(Debug)]
pub struct RateLimitGate {
    /// Unix-epoch seconds at which the gate clears; `0` means "not tripped".
    reset_at: AtomicU64,
    cooldown_secs: u64,
    /// Whether the trip currently in effect was backed by confirmed evidence rather than an
    /// inferred guess (#1295 critic S3) — meaningless while [`Self::is_tripped`] is `false`.
    /// Sees its own `Ordering::Relaxed` store *before* `reset_at`'s on [`Self::trip_verified`]/
    /// [`Self::trip`], so a reader that observes `is_tripped() == true` on the same thread that
    /// tripped it has always also observed the right `verified` value for that trip — the two
    /// stores can still reorder across threads (this gate's whole contract already tolerates a
    /// stale read costing at most one extra doomed request, never a correctness violation).
    verified: AtomicBool,
}

impl RateLimitGate {
    /// Creates an untripped gate whose [`Self::trip`]/[`Self::trip_verified`] blocks further
    /// requests for `cooldown_secs`.
    #[must_use]
    pub const fn new(cooldown_secs: u64) -> Self {
        Self {
            reset_at: AtomicU64::new(0),
            cooldown_secs,
            verified: AtomicBool::new(false),
        }
    }

    /// Whether a request should be short-circuited right now.
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        let reset_at = self.reset_at.load(Ordering::Relaxed);
        reset_at != 0 && now_epoch_secs() < reset_at
    }

    /// Whether the trip currently in effect was tripped via [`Self::trip_verified`] rather
    /// than the plain [`Self::trip`] (#1295 critic S3). Meaningless when [`Self::is_tripped`]
    /// is `false` — a caller short-circuiting on a tripped gate should build its error to match
    /// this, instead of always reporting an unverified guess for every call within the
    /// cooldown window regardless of how the *first* call actually confirmed it.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.verified.load(Ordering::Relaxed)
    }

    /// [`Self::verified`], projected onto [`RateLimitEvidence`] — lets a caller building the
    /// error for an already-tripped gate write `some_rate_limit_error(gate.evidence())` instead
    /// of re-deriving the `if gate.verified() { .. } else { .. }` branch at every call site
    /// (#1480 item 8: this replaces `GithubActionsRegistry::rate_limited_error`'s and
    /// `GitlabCiRegistry::fetch_route`'s identical hand-rolled versions of this projection).
    /// Meaningless when [`Self::is_tripped`] is `false`, exactly like [`Self::verified`] itself.
    #[must_use]
    pub fn evidence(&self) -> RateLimitEvidence {
        if self.verified() {
            RateLimitEvidence::Confirmed
        } else {
            RateLimitEvidence::Inferred
        }
    }

    /// Trips the gate until `now + cooldown_secs`, recording that this trip was *not* backed
    /// by confirmed evidence (see [`Self::verified`]).
    pub fn trip(&self) {
        self.trip_with(false);
    }

    /// Like [`Self::trip`], but records that this trip *was* backed by confirmed evidence —
    /// [`Self::verified`] then returns `true` for as long as this trip stays in effect.
    pub fn trip_verified(&self) {
        self.trip_with(true);
    }

    fn trip_with(&self, verified: bool) {
        self.verified.store(verified, Ordering::Relaxed);
        self.reset_at
            .store(now_epoch_secs() + self.cooldown_secs, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn trip_until_epoch_secs(&self, reset_at: u64) {
        self.reset_at.store(reset_at, Ordering::Relaxed);
    }
}

/// Which rate-limit response-header family a [`QuotaMeter`] reads.
///
/// GitHub and GitLab report the same two facts under different names, so a meter is bound to
/// one family at construction instead of sniffing both on every response.
///
/// # Examples
///
/// ```
/// use deps_core::rate_limit::QuotaHeaders;
///
/// assert_eq!(QuotaHeaders::GitHub.remaining_header(), "x-ratelimit-remaining");
/// assert_eq!(QuotaHeaders::GitLab.reset_header(), "ratelimit-reset");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaHeaders {
    /// `X-RateLimit-Remaining` / `X-RateLimit-Reset`.
    GitHub,
    /// `RateLimit-Remaining` / `RateLimit-Reset`.
    GitLab,
}

impl QuotaHeaders {
    /// The lowercase name of the header carrying the remaining request count.
    #[must_use]
    pub const fn remaining_header(self) -> &'static str {
        match self {
            Self::GitHub => "x-ratelimit-remaining",
            Self::GitLab => "ratelimit-remaining",
        }
    }

    /// The lowercase name of the header carrying the window reset as Unix epoch seconds.
    #[must_use]
    pub const fn reset_header(self) -> &'static str {
        match self {
            Self::GitHub => "x-ratelimit-reset",
            Self::GitLab => "ratelimit-reset",
        }
    }
}

/// How far ahead of the local clock a reading's `reset_epoch` may lie before the reading is
/// ignored.
///
/// Forge windows last an hour. A reading from a misbehaving host that claims a reset far in the
/// future would otherwise win every comparison by its larger `reset_epoch` and pin the meter
/// (and with it every probe) for good.
const MAX_RESET_HORIZON_SECS: u64 = 2 * 3600;

/// One observed rate-limit reading of a forge host.
///
/// `reset_epoch` is a server-clock value compared with the local clock; skew only shifts how
/// long a reading stays valid, and the [`TokenBucket`] still governs probes, so no skew guard
/// is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaReading {
    /// Requests the server reported as left in the current window.
    pub remaining: u32,
    /// Unix epoch seconds at which the window resets.
    pub reset_epoch: u64,
    /// When this process received the response.
    pub observed: Instant,
}

impl QuotaReading {
    const fn is_expired_at(&self, now_epoch: u64) -> bool {
        now_epoch >= self.reset_epoch
    }
}

/// The newest rate-limit reading of one forge host, fed only by live network responses.
///
/// The fetch layer records into it through
/// [`RequestAuth::with_quota_meter`](crate::cache::RequestAuth::with_quota_meter) at the moment a
/// response is received. A cache entry, a fresh-cache hit or a replayed header never reaches it
/// (`CachedResponse` carries no quota), so a stale `remaining` cannot overwrite a newer one.
///
/// A newer reading replaces the held one: a larger `reset_epoch` wins, an equal `reset_epoch`
/// keeps the smaller `remaining` and the later `observed`, a smaller `reset_epoch` is discarded.
/// Once `now >= reset_epoch` the held reading counts as absent.
///
/// # Examples
///
/// ```
/// use deps_core::rate_limit::{QuotaHeaders, QuotaMeter};
///
/// let meter = QuotaMeter::new(QuotaHeaders::GitHub);
/// assert!(meter.current().is_none());
/// ```
#[derive(Debug)]
pub struct QuotaMeter {
    headers: QuotaHeaders,
    reading: Mutex<Option<QuotaReading>>,
}

impl QuotaMeter {
    /// Creates a meter with no reading that parses `headers`.
    #[must_use]
    pub const fn new(headers: QuotaHeaders) -> Self {
        Self {
            headers,
            reading: Mutex::new(None),
        }
    }

    /// The reading a probe should honour, or `None` when none was observed yet or the window
    /// it described has ended.
    #[must_use]
    pub fn current(&self) -> Option<QuotaReading> {
        self.current_at(now_epoch_secs())
    }

    fn current_at(&self, now_epoch: u64) -> Option<QuotaReading> {
        (*self.reading.lock().unwrap_or_else(PoisonError::into_inner))
            .filter(|reading| !reading.is_expired_at(now_epoch))
    }

    /// Records the rate-limit headers of a response that was just received over the network.
    ///
    /// A response lacking either header (a self-hosted GitLab without `RateLimit-*`) records
    /// nothing, leaving probes governed by the bucket and the gate alone.
    pub(crate) fn observe_headers(&self, headers: &reqwest::header::HeaderMap) {
        let number = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
        };
        let (Some(remaining), Some(reset_epoch)) = (
            number(self.headers.remaining_header()),
            number(self.headers.reset_header()),
        ) else {
            return;
        };
        self.observe_live(QuotaReading {
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            reset_epoch,
            observed: Instant::now(),
        });
    }

    pub(crate) fn observe_live(&self, new: QuotaReading) {
        self.observe_at(new, now_epoch_secs());
    }

    fn observe_at(&self, new: QuotaReading, now_epoch: u64) {
        if new.reset_epoch > now_epoch.saturating_add(MAX_RESET_HORIZON_SECS) {
            tracing::debug!("ignoring a rate-limit reading whose window ends implausibly far away");
            return;
        }
        let mut held = self.reading.lock().unwrap_or_else(PoisonError::into_inner);
        *held = match *held {
            Some(old) if !old.is_expired_at(now_epoch) => Some(merge_readings(old, new)),
            _ => Some(new),
        };
    }

    /// Records `reading` as if a live response had carried it.
    #[cfg(any(test, feature = "test-util"))]
    pub fn observe_for_test(&self, reading: QuotaReading) {
        self.observe_live(reading);
    }
}

fn merge_readings(old: QuotaReading, new: QuotaReading) -> QuotaReading {
    match new.reset_epoch.cmp(&old.reset_epoch) {
        std::cmp::Ordering::Greater => new,
        std::cmp::Ordering::Less => old,
        std::cmp::Ordering::Equal => QuotaReading {
            remaining: old.remaining.min(new.remaining),
            reset_epoch: old.reset_epoch,
            observed: old.observed.max(new.observed),
        },
    }
}

/// A refilling allowance of requests, spent one at a time and never refunded.
///
/// Starts full. Refill is continuous and computed lazily on the next draw.
///
/// # Examples
///
/// ```
/// use deps_core::rate_limit::TokenBucket;
///
/// let bucket = TokenBucket::new(2, 0);
/// assert!(bucket.try_take());
/// assert!(bucket.try_take());
/// assert!(!bucket.try_take());
/// ```
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    refill_per_hour: u32,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    refilled_at: Instant,
}

impl TokenBucket {
    /// Creates a full bucket holding `capacity` tokens that regains `refill_per_hour` per hour.
    #[must_use]
    pub fn new(capacity: u32, refill_per_hour: u32) -> Self {
        Self {
            capacity,
            refill_per_hour,
            state: Mutex::new(BucketState {
                tokens: f64::from(capacity),
                refilled_at: Instant::now(),
            }),
        }
    }

    /// Takes one token, returning `false` when the bucket is empty.
    #[must_use]
    pub fn try_take(&self) -> bool {
        self.try_take_at(Instant::now())
    }

    fn try_take_at(&self, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = now.saturating_duration_since(state.refilled_at);
        let regained = elapsed.as_secs_f64() * f64::from(self.refill_per_hour) / 3600.0;
        state.tokens = (state.tokens + regained).min(f64::from(self.capacity));
        state.refilled_at = now.max(state.refilled_at);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Whether the forge host a [`ProbeAllowance`] guards is queried with a token, which selects
/// its reserve, capacity and refill rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCredential {
    /// No token: 60 requests/hour shared with the tag-index fetches, so probes stay tiny
    /// (reserve 20, capacity 4, refill 6/h).
    Anonymous,
    /// A token for the host (reserve 500, capacity 32, refill 600/h).
    Token,
}

impl ProbeCredential {
    const fn reserve(self) -> u32 {
        match self {
            Self::Anonymous => 20,
            Self::Token => 500,
        }
    }

    const fn capacity(self) -> u32 {
        match self {
            Self::Anonymous => 4,
            Self::Token => 32,
        }
    }

    const fn refill_per_hour(self) -> u32 {
        match self {
            Self::Anonymous => 6,
            Self::Token => 600,
        }
    }
}

/// Proof that one probe request was allowed.
///
/// Never refunded, so a probe that fails still counts against the budget.
#[derive(Debug)]
#[must_use = "a permit is drawn from the budget; issue the probe it pays for"]
pub struct ProbePermit(());

/// The process-wide budget of optional background probe requests against one forge host.
///
/// A permit is denied while the host's [`RateLimitGate`] is tripped, while the live
/// [`QuotaMeter`] reading is at or below the reserve left for tag-index fetches, or while the
/// [`TokenBucket`] is empty. With no live reading (none yet, expired, or a host without
/// `RateLimit-*` headers) the bucket and the gate alone govern. A probe never trips the gate;
/// a tripped gate only denies probes.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use deps_core::rate_limit::{
///     DEFAULT_COOLDOWN_SECS, ProbeAllowance, ProbeCredential, QuotaHeaders, QuotaMeter,
///     RateLimitGate,
/// };
///
/// let allowance = ProbeAllowance::new(
///     ProbeCredential::Anonymous,
///     Arc::new(QuotaMeter::new(QuotaHeaders::GitHub)),
///     Arc::new(RateLimitGate::new(DEFAULT_COOLDOWN_SECS)),
/// );
/// let granted = (0..10).filter(|_| allowance.try_acquire().is_some()).count();
/// assert_eq!(granted, 4);
/// ```
#[derive(Debug)]
pub struct ProbeAllowance {
    bucket: TokenBucket,
    meter: Arc<QuotaMeter>,
    gate: Arc<RateLimitGate>,
    reserve: u32,
}

impl ProbeAllowance {
    /// Creates an allowance with `credential`'s reserve, capacity and refill rate.
    #[must_use]
    pub fn new(
        credential: ProbeCredential,
        meter: Arc<QuotaMeter>,
        gate: Arc<RateLimitGate>,
    ) -> Self {
        Self {
            bucket: TokenBucket::new(credential.capacity(), credential.refill_per_hour()),
            meter,
            gate,
            reserve: credential.reserve(),
        }
    }

    /// Draws one permit, or `None` when the gate, the quota reserve or the bucket denies it.
    pub fn try_acquire(&self) -> Option<ProbePermit> {
        if self.gate.is_tripped() {
            return None;
        }
        if self
            .meter
            .current()
            .is_some_and(|reading| reading.remaining <= self.reserve)
        {
            return None;
        }
        self.bucket.try_take().then_some(ProbePermit(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const NOW: u64 = 1_000;

    fn reading(remaining: u32, reset_epoch: u64) -> QuotaReading {
        QuotaReading {
            remaining,
            reset_epoch,
            observed: Instant::now(),
        }
    }

    fn meter() -> QuotaMeter {
        QuotaMeter::new(QuotaHeaders::GitHub)
    }

    #[test]
    fn meter_larger_reset_epoch_replaces_held_reading() {
        let m = meter();
        m.observe_at(reading(3, NOW + 100), NOW);
        m.observe_at(reading(55, NOW + 200), NOW);
        assert_eq!(m.current_at(NOW).unwrap().remaining, 55);
    }

    #[test]
    fn meter_equal_reset_epoch_keeps_minimum_remaining() {
        let m = meter();
        m.observe_at(reading(3, NOW + 100), NOW);
        m.observe_at(reading(55, NOW + 100), NOW);
        assert_eq!(m.current_at(NOW).unwrap().remaining, 3);
    }

    /// SC-004: an older window's `remaining = 55` arriving after a live `remaining = 3` of a
    /// newer window must not raise the held value.
    #[test]
    fn meter_smaller_reset_epoch_is_discarded() {
        let m = meter();
        m.observe_at(reading(3, NOW + 200), NOW);
        m.observe_at(reading(55, NOW + 100), NOW);
        assert_eq!(m.current_at(NOW).unwrap().remaining, 3);
    }

    #[test]
    fn meter_expired_reading_counts_as_absent_and_is_replaced() {
        let m = meter();
        m.observe_at(reading(3, NOW + 10), NOW);
        assert!(m.current_at(NOW + 10).is_none());
        m.observe_at(reading(55, NOW + 5), NOW + 10);
        assert_eq!(m.reading.lock().unwrap().unwrap().remaining, 55);
    }

    #[test]
    fn meter_parses_only_its_own_header_family() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("ratelimit-remaining", "7".parse().unwrap());
        headers.insert(
            "ratelimit-reset",
            (now_epoch_secs() + 60).to_string().parse().unwrap(),
        );
        let github = meter();
        github.observe_headers(&headers);
        assert!(github.current().is_none());
        let gitlab = QuotaMeter::new(QuotaHeaders::GitLab);
        gitlab.observe_headers(&headers);
        assert_eq!(gitlab.current().unwrap().remaining, 7);
    }

    /// A host claiming a far-future reset must not pin the meter.
    #[test]
    fn meter_ignores_readings_with_an_implausible_reset() {
        let m = meter();
        m.observe_at(reading(0, NOW + MAX_RESET_HORIZON_SECS + 1), NOW);
        m.observe_at(reading(0, u64::MAX), NOW);
        assert!(m.reading.lock().unwrap().is_none());
        m.observe_at(reading(7, NOW + MAX_RESET_HORIZON_SECS), NOW);
        assert_eq!(m.current_at(NOW).unwrap().remaining, 7);
    }

    #[test]
    fn a_pinned_far_future_reading_cannot_displace_a_sane_one() {
        let m = meter();
        m.observe_at(reading(3, NOW + 100), NOW);
        m.observe_at(reading(900, u64::MAX), NOW);
        assert_eq!(m.current_at(NOW).unwrap().remaining, 3);
    }

    #[test]
    fn meter_ignores_response_without_both_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "7".parse().unwrap());
        let m = meter();
        m.observe_headers(&headers);
        assert!(m.reading.lock().unwrap().is_none());
    }

    #[test]
    fn bucket_refills_lazily_up_to_capacity() {
        let bucket = TokenBucket::new(2, 3600);
        let start = Instant::now();
        assert!(bucket.try_take_at(start));
        assert!(bucket.try_take_at(start));
        assert!(!bucket.try_take_at(start));
        assert!(bucket.try_take_at(start + Duration::from_secs(1)));
        let later = start + Duration::from_secs(3600);
        assert!(bucket.try_take_at(later));
        assert!(bucket.try_take_at(later));
        assert!(!bucket.try_take_at(later));
    }

    fn allowance(
        credential: ProbeCredential,
    ) -> (ProbeAllowance, Arc<QuotaMeter>, Arc<RateLimitGate>) {
        let meter = Arc::new(meter());
        let gate = Arc::new(RateLimitGate::new(DEFAULT_COOLDOWN_SECS));
        (
            ProbeAllowance::new(credential, Arc::clone(&meter), Arc::clone(&gate)),
            meter,
            gate,
        )
    }

    #[test]
    fn allowance_denied_while_gate_tripped() {
        let (allowance, _, gate) = allowance(ProbeCredential::Token);
        gate.trip();
        assert!(allowance.try_acquire().is_none());
    }

    #[test]
    fn allowance_denied_at_or_below_reserve_but_allowed_above() {
        let (allowance, meter, _) = allowance(ProbeCredential::Anonymous);
        let reset = now_epoch_secs() + 3600;
        meter.observe_for_test(reading(20, reset));
        assert!(allowance.try_acquire().is_none());
        meter.observe_for_test(reading(21, reset + 1));
        assert!(allowance.try_acquire().is_some());
    }

    #[test]
    fn allowance_without_reading_is_governed_by_bucket_alone() {
        let (allowance, _, _) = allowance(ProbeCredential::Anonymous);
        assert_eq!(
            (0..10)
                .filter(|_| allowance.try_acquire().is_some())
                .count(),
            4
        );
    }

    #[test]
    fn token_parameters_are_larger_than_anonymous() {
        let (allowance, _, _) = allowance(ProbeCredential::Token);
        assert_eq!(
            (0..100)
                .filter(|_| allowance.try_acquire().is_some())
                .count(),
            32
        );
    }

    #[test]
    fn test_rate_limit_gate_starts_untripped() {
        let gate = RateLimitGate::new(300);
        assert!(!gate.is_tripped());
    }

    #[test]
    fn test_rate_limit_gate_trips_and_stays_tripped_within_cooldown() {
        let gate = RateLimitGate::new(300);
        gate.trip();
        assert!(gate.is_tripped());
    }

    #[test]
    fn test_rate_limit_gate_clears_after_reset_time_passes() {
        let gate = RateLimitGate::new(300);
        gate.trip_until_epoch_secs(1); // far in the past
        assert!(!gate.is_tripped());
    }

    #[test]
    fn test_rate_limit_gate_starts_unverified() {
        let gate = RateLimitGate::new(300);
        assert!(!gate.verified());
    }

    #[test]
    fn test_rate_limit_gate_trip_is_unverified() {
        let gate = RateLimitGate::new(300);
        gate.trip();
        assert!(gate.is_tripped());
        assert!(!gate.verified());
    }

    #[test]
    fn test_rate_limit_gate_trip_verified_is_verified() {
        let gate = RateLimitGate::new(300);
        gate.trip_verified();
        assert!(gate.is_tripped());
        assert!(gate.verified());
    }

    /// #1295 critic S3: a later plain `trip()` (e.g. a subsequent unverified 403) must not
    /// leave a stale `verified: true` from an earlier confirmed trip — each trip call
    /// overwrites the flag for the whole cooldown window it starts.
    #[test]
    fn test_rate_limit_gate_trip_after_trip_verified_clears_verified_flag() {
        let gate = RateLimitGate::new(300);
        gate.trip_verified();
        assert!(gate.verified());
        gate.trip();
        assert!(!gate.verified());
    }
}
