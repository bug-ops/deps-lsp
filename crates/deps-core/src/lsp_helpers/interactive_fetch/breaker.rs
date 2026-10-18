//! Per-endpoint circuit breaker for interactive registry awaits (OQ-7).
//!
//! The per-package failure memo makes the second request for one package instant, but a
//! manifest of N distinct packages against a dead registry still pays N full awaits. The
//! breaker watches how an endpoint answers and, once it looks dead, refuses hover awaits to
//! it for [`BREAKER_OPEN_DURATION`] without polling.
//!
//! It tracks responsiveness, not correctness: a fast 404 or error counts as an answer. A
//! single slow package never opens it (the package may just be big); two *distinct* slow
//! packages with no answer from the endpoint in the meantime do.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::attempt::AttemptEvidence;
use super::key::EndpointKey;
use super::memo::INTERACTIVE_FAILURE_TTL;
use super::{FetchContext, InteractiveFetchGate};
use crate::PackageName;
use crate::cache_policy::evict_expired_then_oldest_at;

/// How long an opened breaker refuses requests before letting one probe through.
pub(super) const BREAKER_OPEN_DURATION: Duration = INTERACTIVE_FAILURE_TTL;

/// How long an answer vouches for the endpoint, and how long a slow package stays suspect.
const EVIDENCE_TTL: Duration = INTERACTIVE_FAILURE_TTL;

/// Hard cap on tracked endpoints.
pub(super) const BREAKER_CAP: usize = 256;

/// Identity of the one request allowed through a half-open breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProbeId(u64);

/// A package whose attempt was slow while the endpoint had not recently answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Suspect {
    pub(super) package: PackageName,
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
    },
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
        package: &PackageName,
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
                Self::HalfOpen { probe: leased } if Some(*leased) == probe => {
                    Self::Open { until: now }
                }
                Self::Closed { .. } | Self::Open { .. } | Self::HalfOpen { .. } => self.clone(),
            },
        }
    }

    fn after_slow(&self, package: &PackageName, probe: Option<ProbeId>, now: Instant) -> Self {
        match self {
            Self::HalfOpen { probe: leased } if Some(*leased) == probe => Self::Open {
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
// TODO(critic): key the breaker by resolved host once Registry exposes it (npm scopes, GOPRIVATE, extra-index-url, multi-feed NuGet)
#[derive(Debug, Default)]
pub(super) struct EndpointBreaker {
    endpoints: DashMap<EndpointKey, EndpointState>,
    next_probe: AtomicU64,
}

impl EndpointBreaker {
    /// Decides whether a request for `endpoint` may poll. An open breaker whose time has run
    /// out hands the first enforced request the probe and refuses the rest until it settles.
    pub(super) fn admit(
        &self,
        endpoint: &EndpointKey,
        admission: BreakerAdmission,
        now: Instant,
    ) -> Admission {
        match admission {
            BreakerAdmission::ObserveOnly => return Admission::Proceed,
            BreakerAdmission::Enforce => {}
        }
        let Entry::Occupied(mut entry) = self.endpoints.entry(endpoint.clone()) else {
            return Admission::Proceed;
        };
        match entry.get().health {
            EndpointHealth::Closed { .. } => Admission::Proceed,
            EndpointHealth::Open { until } if now < until => Admission::Refused,
            EndpointHealth::Open { .. } => {
                let probe = ProbeId(self.next_probe.fetch_add(1, Ordering::Relaxed));
                *entry.get_mut() = EndpointState {
                    health: EndpointHealth::HalfOpen { probe },
                    touched: now,
                };
                Admission::Probe(probe)
            }
            EndpointHealth::HalfOpen { .. } => Admission::Refused,
        }
    }

    /// Folds one attempt's `evidence` into `endpoint`'s health.
    pub(super) fn report(
        &self,
        endpoint: &EndpointKey,
        package: &PackageName,
        evidence: AttemptEvidence,
        probe: Option<ProbeId>,
        now: Instant,
    ) {
        if !self.endpoints.contains_key(endpoint) {
            evict_expired_then_oldest_at(
                &self.endpoints,
                BREAKER_CAP,
                now,
                |state| state.touched,
                |_| EVIDENCE_TTL,
            );
        }
        match self.endpoints.entry(endpoint.clone()) {
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
    pub(super) fn admit(&self, endpoint: &EndpointKey, context: FetchContext) -> Admission {
        self.breaker
            .admit(endpoint, BreakerAdmission::of(context), super::now())
    }
}
