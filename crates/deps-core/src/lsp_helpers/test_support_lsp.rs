#![expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 never approach truncation range; this \
              whole module is #[cfg(test)]-gated fixture support"
)]

//! LSP-only test fixtures reused across this module's `lsp-responses`-gated test suites —
//! the counterpart of [`super::test_support`] for fixtures that only make sense once the
//! `Registry`/`Version` trait objects and `tower_lsp_server` completion/code-action types are
//! in scope. Gated once at its `mod test_support_lsp;` declaration in `lsp_helpers/mod.rs`.

use super::test_support::{MockDep, MockParseResult, pkg};
use super::*;
use crate::{ConcreteVersion, PackageName, PublishTime, RemovalStatus, VersionReq};
use std::any::Any;
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind};

/// Formatter stub mirroring `GoFormatter`'s override: reports the manifest
/// version-requirement line (go.mod's `require`) as itself the resolved
/// version, since it is already the exact MVS-selected version (#235).
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
pub(crate) const MOCK_WIDENED_RESOLVE_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::new().with_alternate_registry_resolution();

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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &'a crate::SelectionContext,
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
pub(crate) struct SlowRegistry {
    pub(crate) delay: std::time::Duration,
}

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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
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
pub(crate) struct NotFoundRegistry;

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
        _selection_context: &'a crate::SelectionContext,
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
pub(crate) struct MockVersionWithAge {
    pub(crate) version: ConcreteVersion,
    pub(crate) yanked: bool,
    pub(crate) published_at: Option<PublishTime>,
}

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

pub(crate) struct TestVersion {
    pub(crate) version: ConcreteVersion,
    pub(crate) yanked: bool,
}

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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
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
pub(crate) struct MockVersionWithLicense {
    pub(crate) version: ConcreteVersion,
    pub(crate) license: Vec<String>,
}

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
pub(crate) struct MockRegistryWithLicensedVersions {
    pub(crate) versions: Vec<MockVersionWithLicense>,
}

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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
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
    pub(crate) version: ConcreteVersion,
    pub(crate) status: RemovalStatus,
}

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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
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
        _selection_context: &'a crate::SelectionContext,
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
        _selection_context: &crate::SelectionContext,
    ) -> Option<usize> {
        crate::select_latest_for_existence(versions, |v| v.as_ref())
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
/// unlike [`super::test_support::MOCK_FORMATTER`], which wraps the version in quotes and
/// would otherwise confound the N1 no-op-edit guard's own test.
pub(crate) const IDENTITY_FORMATTER: crate::test_util::StubFormatter =
    crate::test_util::StubFormatter::DEFAULT;

/// A formatter mimicking `deps-dart`'s non-identity
/// `format_version_for_text_edit` (wraps the version in a caret
/// constraint) — used to prove the N1 guard compares the *formatted*
/// text actually written, not the bare version (critic S3).
pub(crate) struct CaretWrappingFormatter;

impl PackageNaming for CaretWrappingFormatter {}

impl PackageRendering for CaretWrappingFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        format!("^{version}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for CaretWrappingFormatter {}

impl DiagnosticMessages for CaretWrappingFormatter {}

impl DiagnosticPolicy for CaretWrappingFormatter {}

impl SourcePolicy for CaretWrappingFormatter {}

impl OsvNaming for CaretWrappingFormatter {}

/// A formatter mimicking `deps-pypi`'s non-identity
/// `format_version_replacing` override (preserves an `==` pin instead of
/// falling back to `format_version_for_text_edit`) — used to prove the
/// vulnerability-fix action's `TextEdit` goes through the override, not
/// the default delegation (critic S3).
pub(crate) struct PinPreservingFormatter;

impl PackageNaming for PinPreservingFormatter {}

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

impl RequirementResolution for PinPreservingFormatter {}

impl DiagnosticMessages for PinPreservingFormatter {}

impl DiagnosticPolicy for PinPreservingFormatter {}

impl SourcePolicy for PinPreservingFormatter {}

impl OsvNaming for PinPreservingFormatter {}

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
            version_range: version_range.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 3)).into(),
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

impl PackageNaming for TrailingSpaceFormatter {}

impl PackageRendering for TrailingSpaceFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        format!("{version} ")
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("https://example.com/{}", name.as_str())
    }
}

impl RequirementResolution for TrailingSpaceFormatter {}

impl DiagnosticMessages for TrailingSpaceFormatter {}

impl DiagnosticPolicy for TrailingSpaceFormatter {}

impl SourcePolicy for TrailingSpaceFormatter {}

impl OsvNaming for TrailingSpaceFormatter {}

/// A formatter that truncates every version to `==<major>.<minor>`, mirroring
/// `deps-pypi`'s `truncate_release_to_match` collapsing several distinct
/// registry versions (or a registry version and an OSV fix version) to the
/// same rewritten text — used to prove issue #242's two dedup gaps: an item
/// matching the fix action's text under a different raw version, and two
/// items matching each other's text.
pub(crate) struct TruncatingFormatter;

impl PackageNaming for TruncatingFormatter {}

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

impl RequirementResolution for TruncatingFormatter {}

impl DiagnosticMessages for TruncatingFormatter {}

impl DiagnosticPolicy for TruncatingFormatter {}

impl SourcePolicy for TruncatingFormatter {}

impl OsvNaming for TruncatingFormatter {}
