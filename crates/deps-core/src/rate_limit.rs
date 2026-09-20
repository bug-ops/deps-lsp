//! Local, process-lifetime rate-limit short-circuiting shared across ecosystem crates.
//!
//! Extracted from `deps-github-actions` and `deps-gitlab-ci` (#1205), which had
//! independently implemented the identical mechanism.

use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl RateLimitGate {
    /// Creates an untripped gate whose [`Self::trip`] blocks further requests for
    /// `cooldown_secs`.
    #[must_use]
    pub const fn new(cooldown_secs: u64) -> Self {
        Self {
            reset_at: AtomicU64::new(0),
            cooldown_secs,
        }
    }

    /// Whether a request should be short-circuited right now.
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        let reset_at = self.reset_at.load(Ordering::Relaxed);
        reset_at != 0 && now_epoch_secs() < reset_at
    }

    /// Trips the gate until `now + cooldown_secs`.
    pub fn trip(&self) {
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
}
