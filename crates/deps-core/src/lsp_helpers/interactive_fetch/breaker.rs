//! Per-endpoint circuit breaker for interactive registry awaits (OQ-7).
//!
//! The per-package failure memo makes the second request for one package instant, but a
//! manifest of N distinct packages against a dead registry still pays N full awaits. The
//! breaker watches how an endpoint answers and, once it looks dead, refuses hover awaits to
//! it for [`BREAKER_OPEN_DURATION`] without polling.
//!
//! It tracks responsiveness, not correctness: a fast response from the endpoint (an HTTP
//! status, an oversized or undecodable API body, a registry's own not-found) counts as an
//! answer, while an error with no response behind it says nothing about it: a fast transport
//! error, or one raised locally (policy, cache, configuration, a parse error, a locally decided
//! not-found). A request outstanding for half the budget counts as slow. A single slow package
//! never opens it (the package may just be big); two *distinct* slow packages with no answer
//! from the endpoint in the meantime do.
//!
//! The key is the network path [`Registry::endpoint_for`](crate::Registry::endpoint_for)
//! reports, shared across manifests and dependency sources, or the manifest and source when
//! the registry reports none.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::attempt::{AttemptEvidence, MARGIN};
use super::key::{BreakerEvidence, EndpointKey, MAX_LOOKUP_BUDGET};
use super::memo::INTERACTIVE_FAILURE_TTL;
use super::{FetchContext, InteractiveFetchGate};
use crate::NormalizedName;
use crate::cache_policy::evict_oldest_batch_where;

/// How long an opened breaker refuses requests before letting one probe through.
pub(super) const BREAKER_OPEN_DURATION: Duration = INTERACTIVE_FAILURE_TTL;

/// How long an answer vouches for the endpoint, and how long a slow package stays suspect.
const EVIDENCE_TTL: Duration = INTERACTIVE_FAILURE_TTL;

/// How long a half-open probe may hold the breaker: the longest lookup budget plus a margin.
/// A probe older than this is presumed lost (its holder was dropped without reporting), and the
/// next enforced request takes over.
pub(super) const PROBE_LEASE: Duration = MAX_LOOKUP_BUDGET.saturating_add(MARGIN);

/// An answer re-written no more often than this while the endpoint is already known good, so a
/// sweep of fast answers does not take a write lock per package.
const ANSWER_REFRESH: Duration = Duration::from_secs(5);

/// Hard cap on tracked endpoints.
pub(super) const BREAKER_CAP: usize = 256;

/// Identity of the one request allowed through a half-open breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProbeId(u64);

/// A package whose attempt was slow while the endpoint had not recently answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Suspect {
    pub(super) package: NormalizedName,
    pub(super) at: Instant,
}

/// What the breaker believes about one endpoint. A missing entry is
/// `Closed { last_answered: None, suspect: None }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EndpointHealth {
    Closed {
        last_answered: Option<Instant>,
        suspect: Option<Suspect>,
    },
    Open {
        until: Instant,
    },
    HalfOpen {
        probe: ProbeId,
        /// When the probe was leased, so a lost probe cannot hold the breaker forever.
        since: Instant,
    },
}

/// What the breaker decides for one enforced request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Proceed,
    Refuse,
    /// The request may poll as the single half-open probe.
    TakeProbe,
}

/// The verdict on an enforced request for an endpoint with `health` (`None` when untracked).
///
/// Pure, so `admit` can compute it under a read lock and recompute it on the current value
/// under the write lock before acting on `TakeProbe`.
pub(super) fn verdict(
    health: Option<&EndpointHealth>,
    counts: BreakerEvidence,
    now: Instant,
) -> Verdict {
    // An ignored-evidence lookup cannot settle a probe, so it never takes one.
    let probe_or_refuse = match counts {
        BreakerEvidence::Counts => Verdict::TakeProbe,
        BreakerEvidence::Ignored => Verdict::Refuse,
    };
    match health {
        None | Some(EndpointHealth::Closed { .. }) => Verdict::Proceed,
        Some(EndpointHealth::Open { until }) if now < *until => Verdict::Refuse,
        Some(EndpointHealth::Open { .. }) => probe_or_refuse,
        Some(EndpointHealth::HalfOpen { since, .. })
            if now.saturating_duration_since(*since) < PROBE_LEASE =>
        {
            Verdict::Refuse
        }
        Some(EndpointHealth::HalfOpen { .. }) => probe_or_refuse,
    }
}

impl EndpointHealth {
    const UNKNOWN: Self = Self::Closed {
        last_answered: None,
        suspect: None,
    };

    /// The state after `evidence` from `package`'s attempt, which held `probe` if it was the
    /// half-open probe.
    pub(super) fn after(
        &self,
        evidence: AttemptEvidence,
        package: &NormalizedName,
        probe: Option<ProbeId>,
        now: Instant,
    ) -> Self {
        match evidence {
            AttemptEvidence::Answered => Self::Closed {
                last_answered: Some(now),
                suspect: None,
            },
            AttemptEvidence::Slow => self.after_slow(package, probe, now),
            AttemptEvidence::Inconclusive => match self {
                Self::HalfOpen { probe: leased, .. } if Some(*leased) == probe => {
                    Self::Open { until: now }
                }
                Self::Closed { .. } | Self::Open { .. } | Self::HalfOpen { .. } => self.clone(),
            },
        }
    }

    fn after_slow(&self, package: &NormalizedName, probe: Option<ProbeId>, now: Instant) -> Self {
        match self {
            Self::HalfOpen { probe: leased, .. } if Some(*leased) == probe => Self::Open {
                until: now + BREAKER_OPEN_DURATION,
            },
            Self::Open { .. } | Self::HalfOpen { .. } => self.clone(),
            Self::Closed {
                last_answered,
                suspect,
            } => {
                let recently_answered = last_answered
                    .is_some_and(|at| now.saturating_duration_since(at) < EVIDENCE_TTL);
                if recently_answered {
                    return self.clone();
                }
                let corroborated = suspect.as_ref().is_some_and(|suspect| {
                    suspect.package != *package
                        && now.saturating_duration_since(suspect.at) < EVIDENCE_TTL
                });
                if corroborated {
                    Self::Open {
                        until: now + BREAKER_OPEN_DURATION,
                    }
                } else {
                    Self::Closed {
                        last_answered: *last_answered,
                        suspect: Some(Suspect {
                            package: package.clone(),
                            at: now,
                        }),
                    }
                }
            }
        }
    }
}

/// Whether a refusal applies to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BreakerAdmission {
    /// The breaker may refuse this request or hand it the half-open probe.
    Enforce,
    /// The request always proceeds but still reports what it observes.
    ObserveOnly,
}

impl BreakerAdmission {
    /// Hover is the sweep the breaker exists to speed up. A false open would drop the fix
    /// actions of a whole manifest for 30 s, and an unverified fix must not fail open, so code
    /// actions only observe.
    pub(super) const fn of(context: FetchContext) -> Self {
        match context {
            FetchContext::Hover => Self::Enforce,
            FetchContext::CodeAction => Self::ObserveOnly,
        }
    }
}

/// The breaker's verdict on one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    Proceed,
    /// Proceed as the single half-open probe.
    Probe(ProbeId),
    Refused,
}

#[derive(Debug)]
struct EndpointState {
    health: EndpointHealth,
    touched: Instant,
}

/// Health of every endpoint the gate has watched.
#[derive(Debug, Default)]
pub(super) struct EndpointBreaker {
    endpoints: DashMap<EndpointKey, EndpointState>,
    next_probe: AtomicU64,
}

impl EndpointBreaker {
    /// Decides whether a request for `endpoint` may poll. An open breaker whose time has run
    /// out hands the first enforced request the probe and refuses the rest until it settles.
    ///
    /// The common case (a closed or untracked endpoint) takes a read lock only.
    pub(super) fn admit(
        &self,
        endpoint: &EndpointKey,
        admission: BreakerAdmission,
        counts: BreakerEvidence,
        now: Instant,
    ) -> Admission {
        match admission {
            BreakerAdmission::ObserveOnly => return Admission::Proceed,
            BreakerAdmission::Enforce => {}
        }
        let optimistic = {
            let state = self.endpoints.get(endpoint);
            verdict(state.as_deref().map(|state| &state.health), counts, now)
        };
        match optimistic {
            Verdict::Proceed => Admission::Proceed,
            Verdict::Refuse => Admission::Refused,
            Verdict::TakeProbe => self.take_probe(endpoint, counts, now),
        }
    }

    /// Re-decides under the write lock, so two requests racing for the probe cannot both get it.
    pub(super) fn take_probe(
        &self,
        endpoint: &EndpointKey,
        counts: BreakerEvidence,
        now: Instant,
    ) -> Admission {
        let Some(mut state) = self.endpoints.get_mut(endpoint) else {
            return Admission::Proceed;
        };
        match verdict(Some(&state.health), counts, now) {
            Verdict::Proceed => Admission::Proceed,
            Verdict::Refuse => Admission::Refused,
            Verdict::TakeProbe => {
                let probe = ProbeId(self.next_probe.fetch_add(1, Ordering::Relaxed));
                *state = EndpointState {
                    health: EndpointHealth::HalfOpen { probe, since: now },
                    touched: now,
                };
                Admission::Probe(probe)
            }
        }
    }

    /// Folds one attempt's `evidence` into `endpoint`'s health.
    ///
    /// A report that cannot change anything returns after a read lock. Otherwise the new health
    /// is always computed from the value found under the write lock, never from the one the
    /// read pass saw: a concurrent writer may have changed it in between.
    pub(super) fn report(
        &self,
        endpoint: &EndpointKey,
        package: &NormalizedName,
        evidence: AttemptEvidence,
        probe: Option<ProbeId>,
        now: Instant,
    ) {
        self.report_between(endpoint, package, evidence, probe, now, || {});
    }

    /// [`Self::report`] with a hook that runs after the read pass and before the write pass,
    /// where a concurrent writer can interleave; tests use it to stage that interleaving.
    pub(super) fn report_between(
        &self,
        endpoint: &EndpointKey,
        package: &NormalizedName,
        evidence: AttemptEvidence,
        probe: Option<ProbeId>,
        now: Instant,
        between_passes: impl FnOnce(),
    ) {
        if probe.is_none() && self.is_noop(endpoint, package, evidence, now) {
            return;
        }
        between_passes();
        if !self.endpoints.contains_key(endpoint) && !self.make_room(now) {
            return;
        }
        match self.endpoints.entry(*endpoint) {
            Entry::Occupied(mut entry) => {
                let health = entry.get().health.after(evidence, package, probe, now);
                *entry.get_mut() = EndpointState {
                    health,
                    touched: now,
                };
            }
            Entry::Vacant(entry) => {
                entry.insert(EndpointState {
                    health: EndpointHealth::UNKNOWN.after(evidence, package, probe, now),
                    touched: now,
                });
            }
        }
    }

    fn is_noop(
        &self,
        endpoint: &EndpointKey,
        package: &NormalizedName,
        evidence: AttemptEvidence,
        now: Instant,
    ) -> bool {
        let state = self.endpoints.get(endpoint);
        let Some(state) = state.as_deref() else {
            return false;
        };
        let refreshed_recently = matches!(
            (&state.health, evidence),
            (
                EndpointHealth::Closed {
                    last_answered: Some(at),
                    suspect: None,
                },
                AttemptEvidence::Answered,
            ) if now.saturating_duration_since(*at) < ANSWER_REFRESH
        );
        refreshed_recently || state.health.after(evidence, package, None, now) == state.health
    }

    /// Makes room for one more endpoint, returning whether there is any.
    ///
    /// Stale entries go first, then the oldest `Closed` ones in a batch. An unexpired `Open` or
    /// `HalfOpen` entry is never evicted: forgetting it would make a dead endpoint cost two more
    /// slow awaits. When every slot holds one, the new endpoint is simply not tracked, which is
    /// the same as `Closed` with no evidence.
    fn make_room(&self, now: Instant) -> bool {
        if self.endpoints.len() < BREAKER_CAP {
            return true;
        }
        self.endpoints
            .retain(|_, state| now.saturating_duration_since(state.touched) < EVIDENCE_TTL);
        if self.endpoints.len() < BREAKER_CAP {
            return true;
        }
        evict_oldest_batch_where(
            &self.endpoints,
            BREAKER_CAP,
            |state| state.touched,
            |state| matches!(state.health, EndpointHealth::Closed { .. }),
        );
        self.endpoints.len() < BREAKER_CAP
    }

    pub(super) fn forget(&self, endpoint: &EndpointKey) {
        self.endpoints.remove(endpoint);
    }

    pub(super) fn clear(&self) {
        self.endpoints.clear();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[cfg(test)]
    pub(super) fn health(&self, endpoint: &EndpointKey) -> Option<EndpointHealth> {
        self.endpoints
            .get(endpoint)
            .map(|state| state.health.clone())
    }
}

impl InteractiveFetchGate {
    /// Asks the breaker whether `endpoint` may be polled for a request in `context`.
    pub(super) fn admit(
        &self,
        endpoint: &EndpointKey,
        context: FetchContext,
        counts: BreakerEvidence,
    ) -> Admission {
        self.breaker.admit(
            endpoint,
            BreakerAdmission::of(context),
            counts,
            super::now(),
        )
    }
}
