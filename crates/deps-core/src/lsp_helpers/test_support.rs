#![expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 never approach truncation range; this \
              whole module is #[cfg(test)]-gated fixture support"
)]

//! Shared test fixtures (mock formatters, dependencies, registries) reused across
//! this module's per-feature test suites.

use super::*;
use crate::{
    ConcreteVersion, Dependency, InvalidPackageName, PackageName, ParseResult, VersionReq,
};
#[cfg(feature = "lsp-responses")]
use crate::{PublishTime, RemovalStatus};
use std::any::Any;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind};

pub(crate) fn pkg(s: &str) -> PackageName {
    PackageName::new(s)
}

pub(crate) const MOCK_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::new().with_quoted_text_edit();

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
    fn requirement_status(
        &self,
        _requirement: &VersionReq,
        _latest: &ConcreteVersion,
    ) -> RequirementStatus {
        RequirementStatus::Unresolved
    }
}

impl DiagnosticMessages for MockUnresolvedFormatter {}

impl DiagnosticPolicy for MockUnresolvedFormatter {}

impl SourcePolicy for MockUnresolvedFormatter {}

impl OsvNaming for MockUnresolvedFormatter {}

/// Formatter stub mirroring `GoFormatter`'s override: reports the manifest
/// version-requirement line (go.mod's `require`) as itself the resolved
/// version, since it is already the exact MVS-selected version (#235).
#[cfg(feature = "lsp-responses")]
pub(crate) const MOCK_GO_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::new()
        .with_package_url_prefix("https://pkg.go.dev/")
        .with_manifest_requirement_as_resolved_version();

/// Formatter stub mirroring `deps-cargo`'s `CargoFormatter`: widens
/// `can_resolve_source` to accept `AlternateRegistry` (any private/internal
/// index, not just a crates.io mirror), while leaving
/// `source_is_public_registry_content` at its default (`Registry` only) —
/// exercises the M2/critic-C2 regression class, where a source can be
/// resolvable without its content being safe to treat as a public
/// registry's (e.g. for the deps.dev trust-signal gate, which must use the
/// latter, never the former).
#[cfg(feature = "lsp-responses")]
pub(crate) const MOCK_WIDENED_RESOLVE_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::new().with_alternate_registry_resolution();

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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "lsp-responses")]
pub(crate) struct MockRegistry;

#[cfg(feature = "lsp-responses")]
impl crate::Registry for MockRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `get_versions` always errs, for exercising a fetch-failure code
/// path (e.g. `generate_hover`'s degrade-to-basic-card behavior on a failed fetch).
#[cfg(feature = "lsp-responses")]
pub(crate) struct ErrorRegistry;

#[cfg(feature = "lsp-responses")]
impl crate::Registry for ErrorRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            Err(crate::error::DepsError::CacheError(
                "mock registry error".to_string(),
            ))
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `get_versions` sleeps past a caller-supplied delay before
/// resolving, for exercising a caller's `tokio::time::timeout` wrap around the fetch
/// (e.g. `REGISTRY_FETCH_BUDGET`, #1204). Pair with `#[tokio::test(start_paused =
/// true)]` so the delay elapses without a real wall-clock wait.
///
/// Resolves with a non-empty, non-yanked version list, not `Vec::new()`: an empty list
/// renders identically to a properly timed-out fetch (no `**Latest**` line, `None` for
/// yank checks either way), so a caller whose timeout wrap silently stopped applying
/// would still pass an assertion built only against an empty result — a real version
/// entry makes that regression visible (surfaces as a `**Latest**` line in hover, or an
/// unfiltered fix action in code actions) instead of accidentally passing.
#[cfg(feature = "lsp-responses")]
pub(crate) struct SlowRegistry {
    pub(crate) delay: std::time::Duration,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for SlowRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(vec![Box::new(TestVersion {
                version: ConcreteVersion::new("9.9.9"),
                yanked: false,
            }) as Box<dyn crate::Version>])
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    // Without this override, `select_latest_matching` falls back to the trait default
    // (always `None`, registry.rs), so `generate_hover`'s `live_latest_idx` would stay
    // `None` regardless of whether `get_versions` actually timed out — silently
    // reintroducing the same non-discriminating-test bug this struct's `get_versions`
    // fix above was meant to close.
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn crate::Version>],
        _req: &crate::VersionReq,
    ) -> Option<usize> {
        versions.iter().position(|v| v.is_stable())
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `get_versions` always errs with `PackageNotFound`, for
/// exercising a "package genuinely doesn't exist" code path — distinct from
/// [`ErrorRegistry`], whose `CacheError` stands in for a transient/unanswerable
/// failure instead.
#[cfg(feature = "lsp-responses")]
pub(crate) struct NotFoundRegistry;

#[cfg(feature = "lsp-responses")]
impl crate::Registry for NotFoundRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            Err(crate::error::DepsError::PackageNotFound {
                package: name.as_str().into(),
                registry: "mock",
            })
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A version with a configurable yanked flag and publish time, used for the
/// "Recent versions" hover freshness tests below.
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockVersionWithAge {
    pub(crate) version: ConcreteVersion,
    pub(crate) yanked: bool,
    pub(crate) published_at: Option<PublishTime>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Version for MockVersionWithAge {
    fn version_string(&self) -> &ConcreteVersion {
        &self.version
    }

    fn removal_status(&self) -> crate::RemovalStatus {
        crate::RemovalStatus::from_yanked(self.yanked)
    }

    fn published_at(&self) -> Option<PublishTime> {
        self.published_at
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "lsp-responses")]
pub(crate) struct TestVersion {
    pub(crate) version: ConcreteVersion,
    pub(crate) yanked: bool,
}

#[cfg(feature = "lsp-responses")]
impl crate::Version for TestVersion {
    fn version_string(&self) -> &ConcreteVersion {
        &self.version
    }

    fn removal_status(&self) -> crate::RemovalStatus {
        crate::RemovalStatus::from_yanked(self.yanked)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `get_versions` returns a fixed, caller-supplied version list —
/// used to exercise hover's "Recent versions" rendering, which `MockRegistry`
/// above (always empty) cannot.
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockRegistryWithVersions {
    pub(crate) versions: Vec<MockVersionWithAge>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for MockRegistryWithVersions {
    fn get_versions<'a>(
        &'a self,
        _name: &'a crate::PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let versions = self
            .versions
            .iter()
            .map(|v| {
                Box::new(MockVersionWithAge {
                    version: v.version.clone(),
                    yanked: v.yanked,
                    published_at: v.published_at,
                }) as Box<dyn crate::Version>
            })
            .collect();
        Box::pin(async move { Ok(versions) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a crate::PackageName,
        _req: &'a crate::VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    /// Newest entry that is neither yanked nor a prerelease — same predicate hover used
    /// to derive `live_latest_idx` before it was routed through this trait method
    /// (#347/#348 S1). A deprecated-but-installable entry is a legitimate "latest" here,
    /// matching most ecosystems (Cargo, PyPI, ...) which have no ranking preference for
    /// non-deprecated over deprecated; see `MockRegistryPreferringUnflagged` below for the
    /// npm-shaped ranking preference.
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn crate::Version>],
        _req: &crate::VersionReq,
    ) -> Option<usize> {
        versions.iter().position(|v| v.is_stable())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A version carrying an SPDX `license` list (issue #204), used by hover tests that
/// exercise `push_license_hover_section`'s native-version-list path without touching
/// every existing [`MockVersionWithAge`] call site.
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockVersionWithLicense {
    pub(crate) version: ConcreteVersion,
    pub(crate) license: Vec<String>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Version for MockVersionWithLicense {
    fn version_string(&self) -> &ConcreteVersion {
        &self.version
    }

    fn license(&self) -> &[String] {
        &self.license
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Registry stub serving [`MockVersionWithLicense`] entries — the license-hover
/// counterpart of [`MockRegistryWithVersions`].
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockRegistryWithLicensedVersions {
    pub(crate) versions: Vec<MockVersionWithLicense>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for MockRegistryWithLicensedVersions {
    fn get_versions<'a>(
        &'a self,
        _name: &'a crate::PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let versions = self
            .versions
            .iter()
            .map(|v| {
                Box::new(MockVersionWithLicense {
                    version: v.version.clone(),
                    license: v.license.clone(),
                }) as Box<dyn crate::Version>
            })
            .collect();
        Box::pin(async move { Ok(versions) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a crate::PackageName,
        _req: &'a crate::VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn crate::Version>],
        _req: &crate::VersionReq,
    ) -> Option<usize> {
        versions.iter().position(|v| v.is_stable())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A version carrying an explicit [`RemovalStatus`], used where a test needs
/// `AdvisoryDeprecated` specifically — `MockVersionWithAge`'s `bool` field can only
/// express `Available`/`Yanked` via [`RemovalStatus::from_yanked`].
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockVersionWithStatus {
    pub(crate) version: ConcreteVersion,
    pub(crate) status: RemovalStatus,
}

#[cfg(feature = "lsp-responses")]
impl crate::Version for MockVersionWithStatus {
    fn version_string(&self) -> &ConcreteVersion {
        &self.version
    }

    fn removal_status(&self) -> RemovalStatus {
        self.status
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `select_latest_matching` mirrors the shared 3-rung existence
/// ladder ([`crate::select_latest_for_existence`]) used by Cargo/PyPI/Dart/npm/Deno under
/// a wildcard requirement, rather than `MockRegistryWithVersions`'s generic `is_stable()`
/// scan. Exists for the hover/cache-agreement regression test (#347/#348 S1, #364): hover
/// must resolve "latest" through this same ranking, not an independent `is_stable()`-based
/// pick that disagrees with it — including rung 3 (newest overall, unconditionally), which
/// is what lets an all-yanked/all-prerelease package still resolve a "latest" instead of
/// `None`.
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockRegistryPreferringUnflagged {
    pub(crate) versions: Vec<MockVersionWithStatus>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for MockRegistryPreferringUnflagged {
    fn get_versions<'a>(
        &'a self,
        _name: &'a crate::PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let versions = self
            .versions
            .iter()
            .map(|v| {
                Box::new(MockVersionWithStatus {
                    version: v.version.clone(),
                    status: v.status,
                }) as Box<dyn crate::Version>
            })
            .collect();
        Box::pin(async move { Ok(versions) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a crate::PackageName,
        _req: &'a crate::VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn crate::Version>],
        _req: &crate::VersionReq,
    ) -> Option<usize> {
        crate::select_latest_for_existence(versions, |v| v.as_ref())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `select_latest_matching` always returns `None` — mirroring Go's
/// list-based ladder, which is deliberately excluded from the shared 3-rung existence
/// ladder (#364/#372) since `/@v/list` has no real per-version retraction data — paired
/// with a `get_latest_matching` that DOES resolve, mirroring Go's `/@latest` endpoint
/// answering from a more complete source than the list. Exists for the hover
/// list-based-pick-failed fallback regression test (#373). `get_latest_matching_calls`
/// counts invocations so a test can assert the fallback is NOT reached on the happy
/// path (a list-based pick that already succeeds), guarding against a future regression
/// that would make every hover pay for a second network round trip.
#[cfg(feature = "lsp-responses")]
pub(crate) struct MockRegistryListFailsLatestFallbackSucceeds {
    pub(crate) versions: Vec<MockVersionWithAge>,
    pub(crate) fallback_latest: MockVersionWithAge,
    /// `select_latest_matching`'s return value — `None` reproduces the Go
    /// list-based-pick-failure this mock exists for; `Some(idx)` lets a test exercise the
    /// happy path (list pick succeeds) through this same mock, to assert the fallback is
    /// NOT reached.
    pub(crate) list_pick_index: Option<usize>,
    pub(crate) get_latest_matching_calls: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for MockRegistryListFailsLatestFallbackSucceeds {
    fn get_versions<'a>(
        &'a self,
        _name: &'a crate::PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let versions = self
            .versions
            .iter()
            .map(|v| {
                Box::new(MockVersionWithAge {
                    version: v.version.clone(),
                    yanked: v.yanked,
                    published_at: v.published_at,
                }) as Box<dyn crate::Version>
            })
            .collect();
        Box::pin(async move { Ok(versions) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a crate::PackageName,
        _req: &'a crate::VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        self.get_latest_matching_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fallback = MockVersionWithAge {
            version: self.fallback_latest.version.clone(),
            yanked: self.fallback_latest.yanked,
            published_at: self.fallback_latest.published_at,
        };
        Box::pin(async move { Ok(Some(Box::new(fallback) as Box<dyn crate::Version>)) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn select_latest_matching(
        &self,
        _versions: &[Box<dyn crate::Version>],
        _req: &crate::VersionReq,
    ) -> Option<usize> {
        self.list_pick_index
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry returning a fixed, caller-supplied version list — used to
/// exercise the yank check and display-item dedup in
/// [`generate_code_actions`].
#[cfg(feature = "lsp-responses")]
pub(crate) struct FixedVersionRegistry {
    pub(crate) versions: Vec<(&'static str, bool)>,
}

#[cfg(feature = "lsp-responses")]
impl crate::Registry for FixedVersionRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        let versions: Vec<Box<dyn crate::Version>> = self
            .versions
            .iter()
            .map(|(version, yanked)| {
                Box::new(TestVersion {
                    version: (*version).into(),
                    yanked: *yanked,
                }) as Box<dyn crate::Version>
            })
            .collect();
        Box::pin(async move { Ok(versions) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    // Mirrors the real 3-rung existence ladder every ecosystem's own `select_latest_matching`
    // delegates to (`crate::select_latest_for_existence`), rather than the trait default
    // (always `None`) — `generate_code_actions`'s `(latest)`/`is_preferred` REFACTOR-action
    // pick is now sourced from this call (#952), same as hover's `live_latest_idx`.
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn crate::Version>],
        _req: &VersionReq,
    ) -> Option<usize> {
        crate::select_latest_for_existence(versions, |v| v.as_ref())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Builds a single-dependency parse result for the freshness hover tests, cursor
/// positioned on the dependency name.
#[cfg(feature = "lsp-responses")]
pub(crate) fn freshness_test_parse_result(name: &str) -> MockParseResult {
    MockParseResult {
        deps: vec![MockDep {
            name: name.into(),
            version_req: "1.0.0".into(),
            version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, name.len() as u32)),
        }],
        uri: crate::test_util::test_uri("/test/Cargo.toml"),
    }
}

/// A formatter whose `format_version_for_text_edit` is the identity —
/// unlike [`MOCK_FORMATTER`], which wraps the version in quotes and would
/// otherwise confound the N1 no-op-edit guard's own test.
#[cfg(feature = "lsp-responses")]
pub(crate) const IDENTITY_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::DEFAULT;

/// A formatter mimicking `deps-dart`'s non-identity
/// `format_version_for_text_edit` (wraps the version in a caret
/// constraint) — used to prove the N1 guard compares the *formatted*
/// text actually written, not the bare version (critic S3).
#[cfg(feature = "lsp-responses")]
pub(crate) struct CaretWrappingFormatter;

#[cfg(feature = "lsp-responses")]
impl PackageNaming for CaretWrappingFormatter {}

#[cfg(feature = "lsp-responses")]
impl PackageRendering for CaretWrappingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        format!("^{version}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

#[cfg(feature = "lsp-responses")]
impl RequirementResolution for CaretWrappingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticMessages for CaretWrappingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticPolicy for CaretWrappingFormatter {}

#[cfg(feature = "lsp-responses")]
impl SourcePolicy for CaretWrappingFormatter {}

#[cfg(feature = "lsp-responses")]
impl OsvNaming for CaretWrappingFormatter {}

/// A formatter mimicking `deps-pypi`'s non-identity
/// `format_version_replacing` override (preserves an `==` pin instead of
/// falling back to `format_version_for_text_edit`) — used to prove the
/// vulnerability-fix action's `TextEdit` goes through the override, not
/// the default delegation (critic S3).
#[cfg(feature = "lsp-responses")]
pub(crate) struct PinPreservingFormatter;

#[cfg(feature = "lsp-responses")]
impl PackageNaming for PinPreservingFormatter {}

#[cfg(feature = "lsp-responses")]
impl PackageRendering for PinPreservingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        format!(">={version}")
    }

    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        if current.starts_with("==") {
            format!("=={version}")
        } else {
            self.format_version_for_text_edit(version)
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

#[cfg(feature = "lsp-responses")]
impl RequirementResolution for PinPreservingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticMessages for PinPreservingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticPolicy for PinPreservingFormatter {}

#[cfg(feature = "lsp-responses")]
impl SourcePolicy for PinPreservingFormatter {}

#[cfg(feature = "lsp-responses")]
impl OsvNaming for PinPreservingFormatter {}

/// Builds a `pkg = "<version_req>"`-shaped fixture: a dependency whose
/// `version_range` slices `content` to exactly `version_req` (so the
/// literal-span guard in `generate_code_actions` never rejects it).
#[cfg(feature = "lsp-responses")]
pub(crate) fn vulnerable_dep(
    version_req: &str,
) -> (MockDep, tower_lsp_server::ls_types::Range, String) {
    use tower_lsp_server::ls_types::{Position, Range};

    let content = format!("pkg = \"{version_req}\"");
    let start = 7u32; // len(`pkg = "`)
    let end = start + version_req.chars().count() as u32;
    let version_range = Range::new(Position::new(0, start), Position::new(0, end));
    (
        MockDep {
            name: pkg("pkg"),
            version_req: VersionReq::new(version_req),
            version_range: version_range.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 3)).into(),
        },
        version_range,
        content,
    )
}

#[cfg(feature = "lsp-responses")]
pub(crate) fn quickfix_titles(actions: &[CodeAction]) -> Vec<&str> {
    actions
        .iter()
        .filter(|a| a.kind == Some(CodeActionKind::QUICKFIX))
        .map(|a| a.title.as_str())
        .collect()
}

#[cfg(feature = "lsp-responses")]
pub(crate) fn refactor_titles(actions: &[CodeAction]) -> Vec<&str> {
    actions
        .iter()
        .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
        .map(|a| a.title.as_str())
        .collect()
}

/// A formatter whose formatted edit text differs from the bare version only in
/// whitespace (a trailing space) — used to prove the REFACTOR-loop no-op guard
/// compares whitespace-insensitively rather than by raw string equality.
#[cfg(feature = "lsp-responses")]
pub(crate) struct TrailingSpaceFormatter;

#[cfg(feature = "lsp-responses")]
impl PackageNaming for TrailingSpaceFormatter {}

#[cfg(feature = "lsp-responses")]
impl PackageRendering for TrailingSpaceFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        format!("{version} ")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

#[cfg(feature = "lsp-responses")]
impl RequirementResolution for TrailingSpaceFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticMessages for TrailingSpaceFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticPolicy for TrailingSpaceFormatter {}

#[cfg(feature = "lsp-responses")]
impl SourcePolicy for TrailingSpaceFormatter {}

#[cfg(feature = "lsp-responses")]
impl OsvNaming for TrailingSpaceFormatter {}

/// A formatter that truncates every version to `==<major>.<minor>`, mirroring
/// `deps-pypi`'s `truncate_release_to_match` collapsing several distinct
/// registry versions (or a registry version and an OSV fix version) to the
/// same rewritten text — used to prove issue #242's two dedup gaps: an item
/// matching the fix action's text under a different raw version, and two
/// items matching each other's text.
#[cfg(feature = "lsp-responses")]
pub(crate) struct TruncatingFormatter;

#[cfg(feature = "lsp-responses")]
impl PackageNaming for TruncatingFormatter {}

#[cfg(feature = "lsp-responses")]
impl PackageRendering for TruncatingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.to_string()
    }

    fn format_version_replacing(&self, version: &ConcreteVersion, _current: &str) -> String {
        let mut parts = version.as_str().split('.');
        let major = parts.next().unwrap_or("0");
        let minor = parts.next().unwrap_or("0");
        format!("=={major}.{minor}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

#[cfg(feature = "lsp-responses")]
impl RequirementResolution for TruncatingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticMessages for TruncatingFormatter {}

#[cfg(feature = "lsp-responses")]
impl DiagnosticPolicy for TruncatingFormatter {}

#[cfg(feature = "lsp-responses")]
impl SourcePolicy for TruncatingFormatter {}

#[cfg(feature = "lsp-responses")]
impl OsvNaming for TruncatingFormatter {}

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
    fn as_any(&self) -> &dyn Any {
        self
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
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Formatter whose `compile_requirement` does exact-string matching, so
/// `requirement_is_unsatisfiable` can actually return `true` in a test
/// (unlike the default `MOCK_FORMATTER`, whose `compile_requirement`
/// default always returns `None`).
pub(crate) struct ExactMatchFormatter;

pub(crate) struct ExactMatcher(pub(crate) String);
impl RequirementMatcher for ExactMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        Some(version.as_str() == self.0)
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
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
    }
}

impl DiagnosticMessages for ExactMatchFormatter {}

impl DiagnosticPolicy for ExactMatchFormatter {}

impl SourcePolicy for ExactMatchFormatter {}

impl OsvNaming for ExactMatchFormatter {}

pub(crate) struct RealSemverMatcher(pub(crate) semver::VersionReq);
impl RequirementMatcher for RealSemverMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        version
            .as_str()
            .parse::<semver::Version>()
            .ok()
            .map(|v| self.0.matches(&v))
    }
}

/// Mirrors `deps-cargo`/`deps-swift`'s real formatter shape (`semver::VersionReq`
/// compilation, opted into `strict_semver_prerelease_exclusion`) without depending on
/// those crates. Shared by `matching_prerelease_would_satisfy_tests` and the
/// `generate_diagnostics_from_cache` end-to-end coverage below (#299).
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
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(RealSemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }
}

impl DiagnosticMessages for StrictSemverFormatter {}

impl DiagnosticPolicy for StrictSemverFormatter {
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }
}

impl SourcePolicy for StrictSemverFormatter {}

impl OsvNaming for StrictSemverFormatter {}
