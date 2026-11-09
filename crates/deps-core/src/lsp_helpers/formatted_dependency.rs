//! A dependency paired with the formatter that reads it.
//!
//! Type-erased consumers (the `deps-lsp` document pipeline, `deps-engine`, `deps-cli`) hold a
//! document as a [`ParsedManifest`](crate::ecosystem::ParsedManifest) and see its dependencies
//! only as [`FormattedDependency`] values. A value of that trait can only be built by
//! [`BoundDependency`], whose type parameter ties the dependency to its own formatter's
//! [`DependencyFormatter::Dep`], so an erased consumer can never ask a formatter about a
//! dependency of another ecosystem.

use std::collections::HashMap;

use super::{
    DependencyFormatter, DependencyGate, EcosystemFormatter, LatestVerdict, OsvNameAvailability,
    PublicContent,
};
use crate::edit::{PlannedUpdate, VulnFixSkip};
use crate::lsp_helpers::{InUseVersions, LockSelectionMemo};
use crate::osv::{
    CandidateStatusMap, LatestStatusMap, LockResolution, OsvPackageName, StructuralSkipReason,
    VulnKeys,
};
use crate::position::Range;
use crate::{
    ConcreteVersion, Dependency, EcosystemId, NormalizedName, PackageKey, VersionReq,
    lsp_helpers::RequirementStatus,
    lsp_helpers::{CandidateTagSource, CommitRewrite},
};

/// A dependency together with its ecosystem's formatter, behind one dyn-compatible interface.
///
/// The methods are exactly the per-dependency questions erased consumers ask; each answer comes
/// from the formatter that was bound to the dependency at construction. Visitors receive
/// `&dyn FormattedDependency` only for the duration of a callback
/// ([`ParsedManifest::for_each_formatted_dependency`](crate::ecosystem::ParsedManifest::for_each_formatted_dependency));
/// only [`Self::dependency`], which borrows from the document, may outlive it.
pub trait FormattedDependency<'a>: Send + Sync {
    /// The dependency itself, borrowed from the document.
    fn dependency(&self) -> &'a dyn Dependency;

    /// The dependency-free view of the bound formatter.
    fn formatter(&self) -> &'a dyn EcosystemFormatter;

    /// See [`DependencyFormatter::public_content`].
    fn public_content(&self) -> Option<PublicContent<'a>>;

    /// See [`DependencyFormatter::osv_name_availability`].
    fn osv_name_availability(&self) -> OsvNameAvailability;

    /// See [`DependencyFormatter::osv_package_name`].
    fn osv_package_name(&self) -> Option<OsvPackageName>;

    /// See [`DependencyFormatter::candidate_tag_source`].
    fn candidate_tag_source(&self) -> CandidateTagSource;

    /// See [`DependencyFormatter::manifest_requirement_is_resolved_version`].
    fn manifest_requirement_is_resolved_version(&self) -> bool;

    /// See [`DependencyFormatter::lock_resolution`].
    fn lock_resolution(&self) -> LockResolution;

    /// See [`DependencyFormatter::commit_rewrite_for`].
    fn commit_rewrite_for(&self, version: &ConcreteVersion) -> CommitRewrite;

    /// See [`DependencyGate::requirement_status_for`].
    fn requirement_status_for(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus;

    /// See [`crate::osv::non_public_skip_reason`].
    fn non_public_skip_reason(&self) -> StructuralSkipReason;

    /// See [`crate::lsp_helpers::resolve_in_use_version`].
    fn resolve_in_use_version(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
    ) -> Option<ConcreteVersion>;

    /// See [`crate::lsp_helpers::resolve_in_use_versions`].
    fn resolve_in_use_versions(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
    ) -> Option<InUseVersions>;

    /// Like [`Self::resolve_in_use_versions`], reusing `memo` across the dependencies of one
    /// pass so repeated `(name, requirement)` lock selections are computed once.
    fn resolve_in_use_versions_memoized(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
        memo: &mut LockSelectionMemo,
    ) -> Option<InUseVersions>;

    /// See [`crate::lsp_helpers::has_unqueryable_resolved_pin`].
    fn has_unqueryable_resolved_pin(&self, ecosystem: EcosystemId) -> bool;

    /// See [`crate::edit::replacement_text`].
    fn replacement_text(&self, version: &ConcreteVersion, current: &str) -> Option<String>;

    /// See [`crate::edit::floor_safe_replacement_text`].
    fn floor_safe_replacement_text(
        &self,
        version: &ConcreteVersion,
        current: &str,
    ) -> Option<String>;

    /// See [`crate::edit::plan_verified_fix`].
    ///
    /// # Errors
    ///
    /// Returns the [`VulnFixSkip`] reason the fix cannot be planned.
    fn plan_verified_fix(
        &self,
        version_range: Range,
        current: &str,
        version_native: &str,
    ) -> Result<PlannedUpdate, VulnFixSkip>;

    /// See [`crate::lsp_helpers::latest_verdict`].
    fn latest_verdict(
        &self,
        latest_status: Option<&LatestStatusMap>,
        keys: Option<&VulnKeys>,
        key: &PackageKey,
        displayed_latest: &str,
    ) -> LatestVerdict;

    /// See [`crate::lsp_helpers::candidate_verdict`].
    fn candidate_verdict(
        &self,
        candidate_status: Option<&CandidateStatusMap>,
        keys: Option<&VulnKeys>,
        key: &PackageKey,
        version: &str,
    ) -> LatestVerdict;
}

/// The only [`FormattedDependency`]: a formatter and a dependency of exactly its
/// [`DependencyFormatter::Dep`] type.
///
/// Typed code builds one with [`Self::new`] to call a helper that is shared with erased
/// consumers.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{BoundDependency, FormattedDependency};
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// let formatter = StubFormatter::DEFAULT;
/// let dep = StubDependency::new("serde");
/// let bound = BoundDependency::new(&formatter, &dep);
/// assert_eq!(bound.dependency().name().as_str(), "serde");
/// ```
#[derive(Debug)]
pub struct BoundDependency<'a, F: DependencyFormatter> {
    formatter: &'a F,
    dep: &'a F::Dep,
}

impl<'a, F: DependencyFormatter> BoundDependency<'a, F> {
    /// Pairs `dep` with the `formatter` that reads it.
    #[must_use]
    pub const fn new(formatter: &'a F, dep: &'a F::Dep) -> Self {
        Self { formatter, dep }
    }
}

impl<F: DependencyFormatter> Clone for BoundDependency<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: DependencyFormatter> Copy for BoundDependency<'_, F> {}

impl<'a, F: DependencyFormatter> FormattedDependency<'a> for BoundDependency<'a, F> {
    fn dependency(&self) -> &'a dyn Dependency {
        self.dep
    }

    fn formatter(&self) -> &'a dyn EcosystemFormatter {
        self.formatter
    }

    fn public_content(&self) -> Option<PublicContent<'a>> {
        self.formatter.public_content(self.dep)
    }

    fn osv_name_availability(&self) -> OsvNameAvailability {
        self.formatter.osv_name_availability(self.dep)
    }

    fn osv_package_name(&self) -> Option<OsvPackageName> {
        self.formatter.osv_package_name(self.dep)
    }

    fn candidate_tag_source(&self) -> CandidateTagSource {
        self.formatter.candidate_tag_source(self.dep)
    }

    fn manifest_requirement_is_resolved_version(&self) -> bool {
        self.formatter
            .manifest_requirement_is_resolved_version(self.dep)
    }

    fn lock_resolution(&self) -> LockResolution {
        self.formatter.lock_resolution(self.dep)
    }

    fn commit_rewrite_for(&self, version: &ConcreteVersion) -> CommitRewrite {
        self.formatter.commit_rewrite_for(self.dep, version)
    }

    fn requirement_status_for(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        self.formatter
            .requirement_status_for(self.dep, requirement, latest)
    }

    fn non_public_skip_reason(&self) -> StructuralSkipReason {
        crate::osv::non_public_skip_reason(self.dep, self.formatter)
    }

    fn resolve_in_use_version(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
    ) -> Option<ConcreteVersion> {
        crate::lsp_helpers::resolve_in_use_version(
            self.dep,
            key,
            resolved_versions,
            resolved_version_candidates,
            self.formatter,
            ecosystem,
        )
    }

    fn resolve_in_use_versions(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
    ) -> Option<InUseVersions> {
        crate::lsp_helpers::resolve_in_use_versions(
            self.dep,
            key,
            resolved_versions,
            resolved_version_candidates,
            self.formatter,
            ecosystem,
        )
    }

    fn resolve_in_use_versions_memoized(
        &self,
        key: &PackageKey,
        resolved_versions: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_version_candidates: Option<&HashMap<NormalizedName, Vec<ConcreteVersion>>>,
        ecosystem: EcosystemId,
        memo: &mut LockSelectionMemo,
    ) -> Option<InUseVersions> {
        crate::lsp_helpers::resolve_in_use_versions_memoized(
            self.dep,
            key,
            resolved_versions,
            resolved_version_candidates,
            self.formatter,
            ecosystem,
            memo,
        )
    }

    fn has_unqueryable_resolved_pin(&self, ecosystem: EcosystemId) -> bool {
        crate::lsp_helpers::has_unqueryable_resolved_pin(self.dep, self.formatter, ecosystem)
    }

    fn replacement_text(&self, version: &ConcreteVersion, current: &str) -> Option<String> {
        crate::edit::replacement_text(self.formatter, self.dep, version, current)
    }

    fn floor_safe_replacement_text(
        &self,
        version: &ConcreteVersion,
        current: &str,
    ) -> Option<String> {
        crate::edit::floor_safe_replacement_text(self.formatter, self.dep, version, current)
    }

    fn plan_verified_fix(
        &self,
        version_range: Range,
        current: &str,
        version_native: &str,
    ) -> Result<PlannedUpdate, VulnFixSkip> {
        crate::edit::plan_verified_fix(
            self.dep,
            version_range,
            current,
            version_native,
            self.formatter,
        )
    }

    fn latest_verdict(
        &self,
        latest_status: Option<&LatestStatusMap>,
        keys: Option<&VulnKeys>,
        key: &PackageKey,
        displayed_latest: &str,
    ) -> LatestVerdict {
        super::latest_verdict(
            latest_status,
            self.dep,
            keys,
            key,
            displayed_latest,
            self.formatter,
        )
    }

    fn candidate_verdict(
        &self,
        candidate_status: Option<&CandidateStatusMap>,
        keys: Option<&VulnKeys>,
        key: &PackageKey,
        version: &str,
    ) -> LatestVerdict {
        super::candidate_verdict(
            candidate_status,
            self.dep,
            keys,
            key,
            version,
            self.formatter,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::{MOCK_FORMATTER, MockDep, dep_at};
    use crate::test_util::StubFormatter;

    #[test]
    fn bound_dependency_exposes_its_dependency_and_formatter() {
        let dep = dep_at("serde");
        let bound = BoundDependency::new(&MOCK_FORMATTER, &dep);

        assert_eq!(bound.dependency().name().as_str(), "serde");
        assert_eq!(
            bound
                .formatter()
                .package_url(&crate::PackageName::new("serde")),
            "https://example.com/serde"
        );
        assert_eq!(
            bound.public_content().map(|c| c.name.as_str().to_owned()),
            Some("serde".to_owned())
        );
    }

    #[test]
    fn bound_dependency_forwards_formatter_overrides() {
        const GO: StubFormatter<MockDep> = StubFormatter::new()
            .with_manifest_requirement_as_resolved_version()
            .for_dependency();
        let dep = dep_at("serde");

        assert!(
            !BoundDependency::new(&MOCK_FORMATTER, &dep).manifest_requirement_is_resolved_version()
        );
        assert!(BoundDependency::new(&GO, &dep).manifest_requirement_is_resolved_version());
    }

    #[test]
    fn bound_dependency_is_usable_as_a_trait_object() {
        let dep = dep_at("serde");
        let bound = BoundDependency::new(&MOCK_FORMATTER, &dep);
        let erased: &dyn FormattedDependency<'_> = &bound;

        assert_eq!(erased.lock_resolution(), LockResolution::Expected);
        assert_eq!(
            erased.requirement_status_for(&VersionReq::new("^1.0"), &ConcreteVersion::new("1.5.0")),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn replacement_text_forwards_and_declines_placeholders() {
        let dep = dep_at("serde");
        let bound = BoundDependency::new(&MOCK_FORMATTER, &dep);
        let version = ConcreteVersion::new("1.2.3");

        assert_eq!(
            bound.replacement_text(&version, "1.0.0"),
            Some("\"1.2.3\"".to_owned())
        );
        assert_eq!(bound.replacement_text(&version, "${serde.version}"), None);
    }
}
