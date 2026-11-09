#![expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 never approach truncation range; this \
              whole module is #[cfg(test)]-gated fixture support"
)]

//! Shared test fixtures (mock formatters, dependencies, registries) reused across
//! this module's per-feature test suites.

use super::*;
use crate::{
    ConcreteVersion, Dependency, InvalidPackageName, PackageName, ParseResult, TypedParseResult,
    VersionReq,
};

pub(crate) fn pkg(s: &str) -> PackageName {
    PackageName::new(s)
}

pub(crate) const MOCK_FORMATTER: crate::test_util::StubFormatter<MockDep> =
    crate::test_util::StubFormatter::new()
        .with_quoted_text_edit()
        .for_dependency();

/// Formatter stub that always reports `Unresolved`, mirroring `MavenFormatter` /
/// `GradleFormatter`'s override for `${property}` / `$var` requirements.
pub(crate) struct MockUnresolvedFormatter;

impl PackageNaming for MockUnresolvedFormatter {}

impl PackageRendering for MockUnresolvedFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for MockUnresolvedFormatter {
    fn classify_requirement_status(
        &self,
        _requirement: BoundedVersionReq<'_>,
        _latest: &ConcreteVersion,
    ) -> RequirementStatus {
        RequirementStatus::Unresolved
    }
}

impl DiagnosticMessages for MockUnresolvedFormatter {}

impl DiagnosticPolicy for MockUnresolvedFormatter {}

impl SourcePolicy for MockUnresolvedFormatter {}

impl OsvNaming for MockUnresolvedFormatter {}

/// A formatter whose [`BuildMetadataPolicy`] is `Significant`, standing in for Dart/pub.
pub(crate) struct MockBuildAwareFormatter;

impl PackageNaming for MockBuildAwareFormatter {}

impl PackageRendering for MockBuildAwareFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for MockBuildAwareFormatter {
    fn build_metadata_policy(&self) -> BuildMetadataPolicy {
        BuildMetadataPolicy::Significant
    }
}

impl DiagnosticMessages for MockBuildAwareFormatter {}

impl DiagnosticPolicy for MockBuildAwareFormatter {}

impl SourcePolicy for MockBuildAwareFormatter {}

impl OsvNaming for MockBuildAwareFormatter {}

/// A formatter whose `validate_package_name` always rejects, for exercising
/// the "Invalid package name" diagnostic path independently of "Unknown package".
pub(crate) struct RejectingFormatter;

impl PackageNaming for RejectingFormatter {
    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Err(InvalidPackageName::new("name is rejected for testing"))
    }
}

impl PackageRendering for RejectingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for RejectingFormatter {}

impl DiagnosticMessages for RejectingFormatter {}

impl DiagnosticPolicy for RejectingFormatter {}

impl SourcePolicy for RejectingFormatter {}

impl OsvNaming for RejectingFormatter {}

pub(crate) struct MockParseResult {
    pub(crate) deps: Vec<MockDep>,
    pub(crate) uri: url::Url,
}

impl ParseResult for MockParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        self.deps.iter().map(|d| d as &dyn Dependency).collect()
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &url::Url {
        &self.uri
    }
}

impl TypedParseResult for MockParseResult {
    type Dep = MockDep;
    fn own_dependencies(&self) -> &[MockDep] {
        &self.deps
    }
}

/// A [`ParseResult`] over heterogeneous [`Dependency`] impls — for tests that mix a
/// [`MockDep`] with a [`MockSyntheticRangeDep`] in one document, which [`MockParseResult`]'s
/// homogeneous `Vec<MockDep>` can't express.
pub(crate) struct MockMixedParseResult {
    pub(crate) deps: Vec<Box<dyn Dependency>>,
    pub(crate) uri: url::Url,
}

impl ParseResult for MockMixedParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        self.deps.iter().map(AsRef::as_ref).collect()
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &url::Url {
        &self.uri
    }
}

impl TypedParseResult for MockMixedParseResult {
    type Dep = Box<dyn Dependency>;
    fn own_dependencies(&self) -> &[Box<dyn Dependency>] {
        &self.deps
    }
}

/// Lets a heterogeneous document be its own typed dependency: every method, including the
/// provided ones, forwards to the boxed dependency.
impl Dependency for Box<dyn Dependency> {
    fn name(&self) -> &PackageName {
        self.as_ref().name()
    }
    fn name_range(&self) -> crate::position::Range {
        self.as_ref().name_range()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        self.as_ref().version_requirement()
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        self.as_ref().version_range()
    }
    fn source(&self) -> crate::parser::DependencySource {
        self.as_ref().source()
    }
    fn features(&self) -> &[String] {
        self.as_ref().features()
    }
    fn features_range(&self) -> Option<crate::position::Range> {
        self.as_ref().features_range()
    }
    fn markers(&self) -> Option<&str> {
        self.as_ref().markers()
    }
    fn markers_range(&self) -> Option<crate::position::Range> {
        self.as_ref().markers_range()
    }
    fn version_literal(&self) -> Option<&str> {
        self.as_ref().version_literal()
    }
    fn name_range_is_synthetic(&self) -> bool {
        self.as_ref().name_range_is_synthetic()
    }
}

pub(crate) struct MockDep {
    pub(crate) name: PackageName,
    pub(crate) version_req: VersionReq,
    pub(crate) version_range: crate::position::Range,
    pub(crate) name_range: crate::position::Range,
}

impl Dependency for MockDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> crate::position::Range {
        self.name_range
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        Some(&self.version_req)
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        Some(self.version_range)
    }
    fn source(&self) -> crate::parser::DependencySource {
        crate::parser::DependencySource::Registry
    }
}

/// A [`MockDep`] reporting a caller-chosen [`crate::parser::DependencySource`].
pub(crate) struct MockSourcedDep {
    pub(crate) inner: MockDep,
    pub(crate) source: crate::parser::DependencySource,
}

impl Dependency for MockSourcedDep {
    fn name(&self) -> &PackageName {
        self.inner.name()
    }
    fn name_range(&self) -> crate::position::Range {
        self.inner.name_range()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        self.inner.version_requirement()
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        self.inner.version_range()
    }
    fn source(&self) -> crate::parser::DependencySource {
        self.source.clone()
    }
}

/// A dependency whose `name_range()` is a synthetic placeholder
/// (`Dependency::name_range_is_synthetic() == true`) and `version_range()` is always `None` —
/// mirrors a `deps-dart` container-anchor-alias-resolved dependency (issue #905) for testing
/// that `name_range()`-keyed lookups and position-based hover/diagnostic anchoring correctly
/// skip it rather than treat `name_range()` as real. A separate, additive type rather than a
/// new field on [`MockDep`] (used at many pre-existing call sites across this crate's tests)
/// specifically so adding it touches none of them.
pub(crate) struct MockSyntheticRangeDep {
    pub(crate) name: PackageName,
}

impl Dependency for MockSyntheticRangeDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> crate::position::Range {
        crate::position::Range::default()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        None
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        None
    }
    fn source(&self) -> crate::parser::DependencySource {
        crate::parser::DependencySource::Registry
    }
    fn name_range_is_synthetic(&self) -> bool {
        true
    }
}

/// A dependency with a real `name_range()` and a real, non-default `version_range()`, but no
/// `version_requirement()` at all — mirrors Maven's `<version></version>` (#1161): the
/// zero-width `version_range()` exists purely so completion can locate the dependency at that
/// position, with no requirement text behind it. Used to test that hover/inlay-hints/
/// diagnostics anchoring correctly treat this exactly like `version_range() == None` (#1161 M1
/// critic follow-up), rather than treating a non-`None` `version_range()` alone as "there is
/// real version content here."
pub(crate) struct MockNoRequirementDep {
    pub(crate) name: PackageName,
    pub(crate) name_range: crate::position::Range,
    pub(crate) version_range: crate::position::Range,
}

impl Dependency for MockNoRequirementDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> crate::position::Range {
        self.name_range
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        None
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        Some(self.version_range)
    }
    fn source(&self) -> crate::parser::DependencySource {
        crate::parser::DependencySource::Registry
    }
}

pub(crate) struct MockMarkedDep {
    pub(crate) name: PackageName,
    pub(crate) name_range: crate::position::Range,
    pub(crate) markers: Option<String>,
}

impl Dependency for MockMarkedDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> crate::position::Range {
        self.name_range
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        None
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        None
    }
    fn source(&self) -> crate::parser::DependencySource {
        crate::parser::DependencySource::Registry
    }
    fn markers(&self) -> Option<&str> {
        self.markers.as_deref()
    }
}

pub(crate) struct MockMarkedParseResult {
    pub(crate) dep: MockMarkedDep,
    pub(crate) uri: url::Url,
}

impl ParseResult for MockMarkedParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        vec![&self.dep]
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &url::Url {
        &self.uri
    }
}

pub(crate) fn sample_advisory(
    id: &str,
    severity: crate::osv::VulnSeverity,
) -> std::sync::Arc<crate::osv::Advisory> {
    std::sync::Arc::new(
        crate::osv::Advisory::new(id.to_string(), "2023-01-01T00:00:00Z".to_string(), severity)
            .expect("valid osv id")
            .with_summary("Something went wrong".to_string())
            .with_aliases(vec!["CVE-2020-0001".to_string()])
            .with_fixed_versions(vec![
                crate::osv::OsvVersion::new("1.2.0"),
                crate::osv::OsvVersion::new("1.5.0"),
            ]),
    )
}

pub(crate) fn dep_at(name: &str) -> MockDep {
    MockDep {
        name: PackageName::new(name),
        version_req: VersionReq::new("1.0.0"),
        version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
        name_range: Range::new(Position::new(0, 0), Position::new(0, name.len() as u32)),
    }
}

/// Wraps a [`MockDep`] to report a non-`Registry` [`crate::parser::DependencySource`],
/// without touching every other `MockDep` literal in this test module.
pub(crate) struct NonRegistryDep(
    pub(crate) MockDep,
    pub(crate) crate::parser::DependencySource,
);

impl Dependency for NonRegistryDep {
    fn name(&self) -> &PackageName {
        self.0.name()
    }
    fn name_range(&self) -> crate::position::Range {
        self.0.name_range()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        self.0.version_requirement()
    }
    fn version_range(&self) -> Option<crate::position::Range> {
        self.0.version_range()
    }
    fn source(&self) -> crate::parser::DependencySource {
        self.1.clone()
    }
}

/// `ParseResult` holding exactly one dependency of any concrete `Dependency`
/// type, so single-dependency tests aren't forced to use `MockDep`/`MockParseResult`.
pub(crate) struct SingleDepParseResult<D> {
    pub(crate) dep: D,
    pub(crate) uri: url::Url,
}

impl<D: Dependency + 'static> ParseResult for SingleDepParseResult<D> {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        vec![&self.dep]
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &url::Url {
        &self.uri
    }
}

impl<D: Dependency + 'static> TypedParseResult for SingleDepParseResult<D> {
    type Dep = D;
    fn own_dependencies(&self) -> &[D] {
        std::slice::from_ref(&self.dep)
    }
}

/// Formatter whose `compile_bounded_requirement` does exact-string matching, so
/// `requirement_is_unsatisfiable` can actually return `true` in a test
/// (unlike the default `MOCK_FORMATTER`, whose `compile_bounded_requirement`
/// default always returns `None`).
pub(crate) struct ExactMatchFormatter;

pub(crate) struct ExactMatcher(pub(crate) String);
impl RequirementMatcher for ExactMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        Some(version.as_str() == self.0)
    }

    fn strict_prerelease_exclusion(&self) -> bool {
        false
    }
}

impl PackageNaming for ExactMatchFormatter {}

impl PackageRendering for ExactMatchFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for ExactMatchFormatter {
    fn compile_bounded_requirement(
        &self,
        requirement: BoundedVersionReq<'_>,
    ) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
    }
}

impl DiagnosticMessages for ExactMatchFormatter {}

impl DiagnosticPolicy for ExactMatchFormatter {}

impl SourcePolicy for ExactMatchFormatter {}

impl OsvNaming for ExactMatchFormatter {}

/// Mirrors `deps-cargo`/`deps-swift`'s real formatter shape (delegates to the shared
/// [`compile_semver_requirement`], whose matcher opts into `strict_prerelease_exclusion`)
/// without depending on those crates. Shared by `matching_prerelease_would_satisfy_tests` and
/// the `generate_diagnostics_from_cache` end-to-end coverage below (#299).
pub(crate) struct StrictSemverFormatter;
impl PackageNaming for StrictSemverFormatter {}

impl PackageRendering for StrictSemverFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        name.as_str().to_string()
    }
}

impl RequirementResolution for StrictSemverFormatter {
    fn compile_bounded_requirement(
        &self,
        requirement: BoundedVersionReq<'_>,
    ) -> Option<Box<dyn RequirementMatcher>> {
        let requirement = requirement.get();
        compile_semver_requirement(requirement)
    }
}

impl DiagnosticMessages for StrictSemverFormatter {}

impl DiagnosticPolicy for StrictSemverFormatter {}

impl SourcePolicy for StrictSemverFormatter {}

impl OsvNaming for StrictSemverFormatter {}

impl TypedParseResult for MockMarkedParseResult {
    type Dep = MockMarkedDep;
    fn own_dependencies(&self) -> &[MockMarkedDep] {
        std::slice::from_ref(&self.dep)
    }
}

macro_rules! mock_dependency_formatter {
    ($($ty:ty),+ $(,)?) => {
        $(impl DependencyFormatter for $ty {
            type Dep = MockDep;
        })+
    };
}

mock_dependency_formatter!(
    MockUnresolvedFormatter,
    MockBuildAwareFormatter,
    RejectingFormatter,
    ExactMatchFormatter,
    StrictSemverFormatter,
);

/// [`ExactMatchFormatter`] paired with [`NonRegistryDep`].
pub(crate) struct NonRegistryExactFormatter;

impl PackageNaming for NonRegistryExactFormatter {}

impl PackageRendering for NonRegistryExactFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for NonRegistryExactFormatter {
    fn compile_bounded_requirement(
        &self,
        requirement: BoundedVersionReq<'_>,
    ) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
    }
}

impl DiagnosticMessages for NonRegistryExactFormatter {}

impl DiagnosticPolicy for NonRegistryExactFormatter {}

impl SourcePolicy for NonRegistryExactFormatter {}

impl OsvNaming for NonRegistryExactFormatter {}

impl DependencyFormatter for NonRegistryExactFormatter {
    type Dep = NonRegistryDep;
}

/// [`RejectingFormatter`] paired with [`NonRegistryDep`].
pub(crate) struct NonRegistryRejectingFormatter;

impl PackageNaming for NonRegistryRejectingFormatter {
    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Err(InvalidPackageName::new("name is rejected for testing"))
    }
}

impl PackageRendering for NonRegistryRejectingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for NonRegistryRejectingFormatter {}

impl DiagnosticMessages for NonRegistryRejectingFormatter {}

impl DiagnosticPolicy for NonRegistryRejectingFormatter {}

impl SourcePolicy for NonRegistryRejectingFormatter {}

impl OsvNaming for NonRegistryRejectingFormatter {}

impl DependencyFormatter for NonRegistryRejectingFormatter {
    type Dep = NonRegistryDep;
}
