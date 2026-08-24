//! Shared test fixtures (mock formatters, dependencies, registries) reused across
//! this module's per-feature test suites.

use super::*;
use crate::{PackageName, ParseResult, PublishTime, RemovalStatus, VersionReq};
use std::any::Any;
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind};

pub(crate) fn pkg(s: &str) -> PackageName {
    PackageName::new(s)
}

pub(crate) struct MockFormatter;

impl EcosystemFormatter for MockFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        format!("\"{}\"", version)
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name)
    }
}

/// Formatter stub that always reports `Unresolved`, mirroring `MavenFormatter` /
/// `GradleFormatter`'s override for `${property}` / `$var` requirements.
pub(crate) struct MockUnresolvedFormatter;

impl EcosystemFormatter for MockUnresolvedFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name)
    }

    fn requirement_status(&self, _requirement: &VersionReq, _latest: &str) -> RequirementStatus {
        RequirementStatus::Unresolved
    }
}

/// Formatter stub mirroring `GoFormatter`'s override: reports the manifest
/// version-requirement line (go.mod's `require`) as itself the resolved
/// version, since it is already the exact MVS-selected version (#235).
pub(crate) struct MockGoFormatter;

impl EcosystemFormatter for MockGoFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://pkg.go.dev/{}", name)
    }

    fn manifest_requirement_is_resolved_version(&self, _dep: &dyn Dependency) -> bool {
        true
    }
}

/// A formatter whose `validate_package_name` always rejects, for exercising
/// the "Invalid package name" diagnostic path independently of "Unknown package".
pub(crate) struct RejectingFormatter;

impl EcosystemFormatter for RejectingFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name)
    }

    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Err(InvalidPackageName::new("name is rejected for testing"))
    }
}

pub(crate) struct MockParseResult {
    pub(crate) deps: Vec<MockDep>,
    pub(crate) uri: Uri,
}

impl ParseResult for MockParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        self.deps.iter().map(|d| d as &dyn Dependency).collect()
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &Uri {
        &self.uri
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) struct MockDep {
    pub(crate) name: PackageName,
    pub(crate) version_req: VersionReq,
    pub(crate) version_range: Range,
    pub(crate) name_range: Range,
}

impl Dependency for MockDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> Range {
        self.name_range
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        Some(&self.version_req)
    }
    fn version_range(&self) -> Option<Range> {
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
    pub(crate) name_range: Range,
    pub(crate) markers: Option<String>,
}

impl Dependency for MockMarkedDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> Range {
        self.name_range
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        None
    }
    fn version_range(&self) -> Option<Range> {
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
    pub(crate) uri: Uri,
}

impl ParseResult for MockMarkedParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        vec![&self.dep]
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &Uri {
        &self.uri
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) struct MockRegistry;

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

    fn search<'a>(
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

/// A registry whose `get_versions` always errs, for exercising
/// `generate_diagnostics`'s `Err` arm.
pub(crate) struct ErrorRegistry;

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

    fn search<'a>(
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
/// exercising `generate_diagnostics`'s "Unknown package" branch (#267 C1) —
/// distinct from [`ErrorRegistry`], whose `CacheError` must instead produce
/// the "Registry lookup failed" message.
pub(crate) struct NotFoundRegistry;

impl crate::Registry for NotFoundRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            Err(crate::error::DepsError::PackageNotFound {
                package: name.to_string(),
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

    fn search<'a>(
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

/// A registry whose `get_versions` succeeds with a newer stable version and
/// whose `get_latest_matching` returns a non-yanked current version, for
/// exercising `generate_diagnostics`'s outdated-severity wiring.
pub(crate) struct OutdatedRegistry;

impl crate::Registry for OutdatedRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            Ok(vec![Box::new(MockVersionWithAge {
                version: "2.0.0".to_string(),
                yanked: false,
                published_at: None,
            }) as Box<dyn crate::Version>])
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
    ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
    {
        Box::pin(async move {
            Ok(Some(Box::new(MockVersionWithAge {
                version: "1.0.0".to_string(),
                yanked: false,
                published_at: None,
            }) as Box<dyn crate::Version>))
        })
    }

    fn search<'a>(
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
pub(crate) struct MockVersionWithAge {
    pub(crate) version: String,
    pub(crate) yanked: bool,
    pub(crate) published_at: Option<PublishTime>,
}

impl crate::Version for MockVersionWithAge {
    fn version_string(&self) -> &str {
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

pub(crate) struct TestVersion {
    pub(crate) version: String,
    pub(crate) yanked: bool,
}

impl crate::Version for TestVersion {
    fn version_string(&self) -> &str {
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
pub(crate) struct MockRegistryWithVersions {
    pub(crate) versions: Vec<MockVersionWithAge>,
}

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

    fn search<'a>(
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

/// A version carrying an explicit [`RemovalStatus`], used where a test needs
/// `AdvisoryDeprecated` specifically — `MockVersionWithAge`'s `bool` field can only
/// express `Available`/`Yanked` via [`RemovalStatus::from_yanked`].
pub(crate) struct MockVersionWithStatus {
    pub(crate) version: String,
    pub(crate) status: RemovalStatus,
}

impl crate::Version for MockVersionWithStatus {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn removal_status(&self) -> RemovalStatus {
        self.status
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry whose `select_latest_matching` mirrors npm's #338 NFR-002 ranking
/// preference — rung 1: newest entry that is neither flagged nor a prerelease; rung 2:
/// newest entry that isn't hard-yanked — rather than `MockRegistryWithVersions`'s
/// generic `is_stable()` scan. Exists for the hover/cache-agreement regression test
/// (#347/#348 S1): hover must resolve "latest" through this same ranking, not an
/// independent `is_stable()`-based pick that disagrees with it.
pub(crate) struct MockRegistryPreferringUnflagged {
    pub(crate) versions: Vec<MockVersionWithStatus>,
}

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

    fn search<'a>(
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
        versions
            .iter()
            .position(|v| !v.removal_status().is_flagged() && !v.is_prerelease())
            .or_else(|| {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution())
            })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A registry returning a fixed, caller-supplied version list — used to
/// exercise the yank check and display-item dedup in
/// [`generate_code_actions`].
pub(crate) struct FixedVersionRegistry {
    pub(crate) versions: Vec<(&'static str, bool)>,
}

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
                    version: (*version).to_string(),
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

    fn search<'a>(
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

/// Builds a single-dependency parse result for the freshness hover tests, cursor
/// positioned on the dependency name.
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
/// unlike [`MockFormatter`], which wraps the version in quotes and would
/// otherwise confound the N1 no-op-edit guard's own test.
pub(crate) struct IdentityFormatter;

impl EcosystemFormatter for IdentityFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{name}")
    }
}

/// A formatter mimicking `deps-dart`'s non-identity
/// `format_version_for_text_edit` (wraps the version in a caret
/// constraint) — used to prove the N1 guard compares the *formatted*
/// text actually written, not the bare version (critic S3).
pub(crate) struct CaretWrappingFormatter;

impl EcosystemFormatter for CaretWrappingFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        format!("^{version}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{name}")
    }
}

/// A formatter mimicking `deps-pypi`'s non-identity
/// `format_version_replacing` override (preserves an `==` pin instead of
/// falling back to `format_version_for_text_edit`) — used to prove the
/// vulnerability-fix action's `TextEdit` goes through the override, not
/// the default delegation (critic S3).
pub(crate) struct PinPreservingFormatter;

impl EcosystemFormatter for PinPreservingFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        format!(">={version}")
    }

    fn format_version_replacing(&self, version: &str, current: &str) -> String {
        if current.starts_with("==") {
            format!("=={version}")
        } else {
            self.format_version_for_text_edit(version)
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{name}")
    }
}

/// Builds a `pkg = "<version_req>"`-shaped fixture: a dependency whose
/// `version_range` slices `content` to exactly `version_req` (so the
/// literal-span guard in `generate_code_actions` never rejects it).
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
            version_range,
            name_range: Range::new(Position::new(0, 0), Position::new(0, 3)),
        },
        version_range,
        content,
    )
}

pub(crate) fn quickfix_titles(actions: &[CodeAction]) -> Vec<&str> {
    actions
        .iter()
        .filter(|a| a.kind == Some(CodeActionKind::QUICKFIX))
        .map(|a| a.title.as_str())
        .collect()
}

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
pub(crate) struct TrailingSpaceFormatter;

impl EcosystemFormatter for TrailingSpaceFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        format!("{version} ")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{name}")
    }
}

/// A formatter that truncates every version to `==<major>.<minor>`, mirroring
/// `deps-pypi`'s `truncate_release_to_match` collapsing several distinct
/// registry versions (or a registry version and an OSV fix version) to the
/// same rewritten text — used to prove issue #242's two dedup gaps: an item
/// matching the fix action's text under a different raw version, and two
/// items matching each other's text.
pub(crate) struct TruncatingFormatter;

impl EcosystemFormatter for TruncatingFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn format_version_replacing(&self, version: &str, _current: &str) -> String {
        let mut parts = version.split('.');
        let major = parts.next().unwrap_or("0");
        let minor = parts.next().unwrap_or("0");
        format!("=={major}.{minor}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{name}")
    }
}

pub(crate) fn sample_advisory(
    id: &str,
    severity: crate::osv::VulnSeverity,
) -> std::sync::Arc<crate::osv::Advisory> {
    std::sync::Arc::new(crate::osv::Advisory {
        id: id.to_string(),
        modified: "2023-01-01T00:00:00Z".to_string(),
        summary: Some("Something went wrong".to_string()),
        aliases: vec!["CVE-2020-0001".to_string()],
        severity,
        cvss_vector: None,
        fixed_versions: vec!["1.2.0".to_string(), "1.5.0".to_string()],
        url: format!("https://osv.dev/vulnerability/{id}"),
    })
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
    fn name_range(&self) -> Range {
        self.0.name_range()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        self.0.version_requirement()
    }
    fn version_range(&self) -> Option<Range> {
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
    pub(crate) uri: Uri,
}

impl<D: Dependency + 'static> ParseResult for SingleDepParseResult<D> {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        vec![&self.dep]
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &Uri {
        &self.uri
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Formatter whose `compile_requirement` does exact-string matching, so
/// `requirement_is_unsatisfiable` can actually return `true` in a test
/// (unlike the default `MockFormatter`, whose `compile_requirement`
/// default always returns `None`).
pub(crate) struct ExactMatchFormatter;

pub(crate) struct ExactMatcher(pub(crate) String);
impl RequirementMatcher for ExactMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        Some(version == self.0)
    }
}

impl EcosystemFormatter for ExactMatchFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }
    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name)
    }
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
    }
}

pub(crate) struct RealSemverMatcher(pub(crate) semver::VersionReq);
impl RequirementMatcher for RealSemverMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        version
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
impl EcosystemFormatter for StrictSemverFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }
    fn package_url(&self, name: &PackageName) -> String {
        name.to_string()
    }
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(RealSemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }
}
