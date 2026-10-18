//! Identity of one interactive lookup, shared by the failure memo and the in-flight map.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::{DependencySource, EcosystemId, PackageName};

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
}
