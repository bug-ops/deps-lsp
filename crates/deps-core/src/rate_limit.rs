//! Local, process-lifetime rate-limit short-circuiting shared across ecosystem crates.
//!
//! Extracted from `deps-github-actions` and `deps-gitlab-ci` (#1205), which had
//! independently implemented the identical mechanism.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[cfg(test)]
mod tests {
    use super::*;

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
