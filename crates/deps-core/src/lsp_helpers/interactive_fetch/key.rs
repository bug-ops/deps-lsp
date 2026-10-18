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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct InteractiveFetchKey {
    pub(super) ecosystem: EcosystemId,
    pub(super) package: PackageName,
    pub(super) manifest: ManifestFingerprint,
    pub(super) source: SourceFingerprint,
}
