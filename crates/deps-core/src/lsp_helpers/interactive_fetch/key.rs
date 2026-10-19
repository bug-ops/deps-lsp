//! Identity of one interactive lookup, shared by the failure memo, the in-flight map and the
//! endpoint breaker.

use std::time::Duration;

use super::AuxiliaryLookup;
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;
use crate::registry_endpoint::keyed_hash64;
use crate::{DependencySource, EcosystemId, EndpointFingerprint, PackageName};

/// Budget of an [`AuxiliaryLookup`]: each is an optional enrichment or fallback of a response
/// that already has its basic card, so they get half the version list's.
const AUXILIARY_FETCH_BUDGET: Duration = Duration::from_secs(5);

/// The longest budget any lookup kind gets.
pub(super) const MAX_LOOKUP_BUDGET: Duration = REGISTRY_FETCH_BUDGET;

const _: () = assert!(AUXILIARY_FETCH_BUDGET.as_millis() <= MAX_LOOKUP_BUDGET.as_millis());

/// What a lookup tells the endpoint breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BreakerEvidence {
    /// Its answers and its slowness both count.
    Counts,
    /// It neither opens nor closes the breaker (and never takes the half-open probe).
    Ignored,
}

/// Whether the background fetch's recorded failure for a package applies to a lookup kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackgroundSeed {
    /// The background fetch fetched the same thing, so its failure seeds the memo.
    Applies,
    /// The lookup is not what the background fetch did; its failure says nothing about it.
    Ignored,
}

/// Whether a lookup kind takes a dispatch permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PermitPolicy {
    Required,
    /// The lookup continues a request that already passed the cap.
    Exempt,
}

/// How a lookup kind reads and writes the failure memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MemoPolicy {
    /// Another kind's interactive failure that also short-circuits this kind. The relation is
    /// directional: a stalled version list means its pin resolution would stall too, never the
    /// reverse.
    pub(super) honors: Option<LookupKind>,
}

/// Which kind of lookup a request is, so the failure memo, the budget and the breaker
/// treat a package's version list and its auxiliary lookups separately. Each kind owns the
/// memo slot of its own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum LookupKind {
    VersionList,
    Auxiliary(AuxiliaryLookup),
}

impl LookupKind {
    pub(super) const fn budget(self) -> Duration {
        match self {
            Self::VersionList => REGISTRY_FETCH_BUDGET,
            Self::Auxiliary(
                AuxiliaryLookup::Decoration
                | AuxiliaryLookup::PinResolution
                | AuxiliaryLookup::LatestFallback,
            ) => AUXILIARY_FETCH_BUDGET,
        }
    }

    pub(super) const fn breaker_evidence(self) -> BreakerEvidence {
        match self {
            Self::VersionList
            | Self::Auxiliary(AuxiliaryLookup::PinResolution | AuxiliaryLookup::LatestFallback) => {
                BreakerEvidence::Counts
            }
            // A decoration may be served by a different host than the base fetch (a NuGet
            // registration hive), so its pace says nothing about the endpoint's.
            Self::Auxiliary(AuxiliaryLookup::Decoration) => BreakerEvidence::Ignored,
        }
    }

    pub(super) const fn background_seed(self) -> BackgroundSeed {
        match self {
            Self::VersionList
            | Self::Auxiliary(AuxiliaryLookup::Decoration | AuxiliaryLookup::PinResolution) => {
                BackgroundSeed::Applies
            }
            Self::Auxiliary(AuxiliaryLookup::LatestFallback) => BackgroundSeed::Ignored,
        }
    }

    pub(super) const fn permit_policy(self) -> PermitPolicy {
        match self {
            Self::VersionList
            | Self::Auxiliary(AuxiliaryLookup::Decoration | AuxiliaryLookup::PinResolution) => {
                PermitPolicy::Required
            }
            Self::Auxiliary(AuxiliaryLookup::LatestFallback) => PermitPolicy::Exempt,
        }
    }

    pub(super) const fn memo_policy(self) -> MemoPolicy {
        match self {
            Self::Auxiliary(AuxiliaryLookup::PinResolution) => MemoPolicy {
                honors: Some(Self::VersionList),
            },
            Self::VersionList
            | Self::Auxiliary(AuxiliaryLookup::Decoration | AuxiliaryLookup::LatestFallback) => {
                MemoPolicy { honors: None }
            }
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::VersionList => "version list",
            Self::Auxiliary(AuxiliaryLookup::Decoration) => "decoration",
            Self::Auxiliary(AuxiliaryLookup::PinResolution) => "pin resolution",
            Self::Auxiliary(AuxiliaryLookup::LatestFallback) => "latest fallback",
        }
    }
}

/// Keyed hash of a [`DependencySource`], so the memo key distinguishes registries without
/// storing their (possibly credential-bearing) URLs (FR-004, FR-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct SourceFingerprint(u64);

impl SourceFingerprint {
    pub(super) fn of(source: &DependencySource) -> Self {
        Self(keyed_hash64(source))
    }
}

/// Keyed hash of the manifest URL the request is served for (see
/// [`InteractiveFetchRequest::new`](super::InteractiveFetchRequest::new)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct ManifestFingerprint(u64);

impl ManifestFingerprint {
    pub(super) fn of(manifest: &url::Url) -> Self {
        Self(keyed_hash64(manifest))
    }
}

/// What scopes a route: the resolved network path when the registry can name it, else the
/// manifest, whose per-project configuration `deps-core` cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum RouteScope {
    Endpoint(EndpointFingerprint),
    Manifest(ManifestFingerprint),
}

/// Where a lookup goes: the part of a [`LookupKey`] that is shared by every package fetched
/// through the same route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct RouteKey {
    pub(super) ecosystem: EcosystemId,
    pub(super) source: SourceFingerprint,
    pub(super) scope: RouteScope,
}

impl RouteKey {
    /// The breaker key: shared across manifests and sources when the network path is resolved,
    /// scoped to the manifest and source otherwise.
    pub(super) const fn endpoint(self) -> EndpointKey {
        match self.scope {
            RouteScope::Endpoint(endpoint) => EndpointKey::Resolved {
                ecosystem: self.ecosystem,
                endpoint,
            },
            RouteScope::Manifest(manifest) => EndpointKey::Scoped {
                ecosystem: self.ecosystem,
                manifest,
                source: self.source,
            },
        }
    }
}

/// Identity of an endpoint in the breaker. `ecosystem` stays in the key: two ecosystems that
/// reach the same URL (Maven and Gradle) have independent evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum EndpointKey {
    Resolved {
        ecosystem: EcosystemId,
        endpoint: EndpointFingerprint,
    },
    Scoped {
        ecosystem: EcosystemId,
        manifest: ManifestFingerprint,
        source: SourceFingerprint,
    },
}

/// Identity of one memoized lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct LookupKey {
    pub(super) route: RouteKey,
    pub(super) package: PackageName,
    pub(super) slot: LookupKind,
}

impl LookupKey {
    /// The kind of lookup this key's slot belongs to.
    pub(super) const fn kind(&self) -> LookupKind {
        self.slot
    }

    /// The same package on the same route, in another kind's slot.
    pub(super) fn in_slot(&self, slot: LookupKind) -> Self {
        Self {
            route: self.route,
            package: self.package.clone(),
            slot,
        }
    }
}
