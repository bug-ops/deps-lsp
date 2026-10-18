//! Identity of one interactive lookup, shared by the failure memo and the in-flight map.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use std::time::Duration;

use super::AuxiliaryLookup;
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;
use crate::{DependencySource, EcosystemId, PackageName};

/// Budget of an [`AuxiliaryLookup`]: both are optional enrichments of a response that already
/// has its basic card, so they get half the version list's.
const AUXILIARY_FETCH_BUDGET: Duration = Duration::from_secs(5);

/// What a lookup tells the endpoint breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BreakerEvidence {
    /// Its answers and its slowness both count.
    Counts,
    /// It neither opens nor closes the breaker (and never takes the half-open probe).
    Ignored,
}

/// Which kind of lookup a request is, so the failure memo, the budget and the breaker
/// treat a package's version list and its auxiliary lookups separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum LookupKind {
    VersionList,
    Auxiliary(AuxiliaryLookup),
}

impl LookupKind {
    pub(super) const fn budget(self) -> Duration {
        match self {
            Self::VersionList => REGISTRY_FETCH_BUDGET,
            Self::Auxiliary(AuxiliaryLookup::Decoration | AuxiliaryLookup::PinResolution) => {
                AUXILIARY_FETCH_BUDGET
            }
        }
    }

    pub(super) const fn breaker_evidence(self) -> BreakerEvidence {
        match self {
            Self::VersionList | Self::Auxiliary(AuxiliaryLookup::PinResolution) => {
                BreakerEvidence::Counts
            }
            // A decoration may be served by a different host than the base fetch (a NuGet
            // registration hive), so its pace says nothing about the endpoint's.
            Self::Auxiliary(AuxiliaryLookup::Decoration) => BreakerEvidence::Ignored,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::VersionList => "version list",
            Self::Auxiliary(AuxiliaryLookup::Decoration) => "decoration",
            Self::Auxiliary(AuxiliaryLookup::PinResolution) => "pin resolution",
        }
    }
}

/// Hash of a [`DependencySource`], so the memo key distinguishes registries without storing
/// their (possibly credential-bearing) URLs (FR-004, FR-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct SourceFingerprint(u64);

impl SourceFingerprint {
    pub(super) fn of(source: &DependencySource) -> Self {
        Self(hash64(source))
    }
}

/// Hash of the manifest URL the request is served for (see
/// [`InteractiveFetchRequest::new`](super::InteractiveFetchRequest::new)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ManifestFingerprint(u64);

impl ManifestFingerprint {
    pub(super) fn of(manifest: &url::Url) -> Self {
        Self(hash64(manifest))
    }
}

fn hash64(value: &impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// The registry endpoint a lookup resolves against, as far as `deps-core` can tell: the
/// manifest (per-project `.npmrc` or source replacement) and the dependency source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EndpointKey {
    pub(super) ecosystem: EcosystemId,
    pub(super) manifest: ManifestFingerprint,
    pub(super) source: SourceFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct InteractiveFetchKey {
    pub(super) endpoint: EndpointKey,
    pub(super) package: PackageName,
    pub(super) kind: LookupKind,
}
