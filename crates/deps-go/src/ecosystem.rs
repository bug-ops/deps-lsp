//! Go modules ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Go projects,
//! providing LSP functionality for `go.mod` files.

use std::any::Any;
#[cfg(feature = "lsp-responses")]
use std::future::Future;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Range};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::config::GoParseContext;
use crate::formatter::GoFormatter;
use crate::registry::GoRegistry;

/// Go modules ecosystem implementation.
///
/// Provides LSP functionality for go.mod files, including:
/// - Dependency parsing with position tracking
/// - Version information from proxy.golang.org
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown packages
pub struct GoEcosystem {
    registry: Arc<GoRegistry>,
    formatter: GoFormatter,
    /// The reachability policy and `$GOENV` memoization cache (spec 034) every
    /// `parse_manifest` call threads through to [`crate::parser::parse_go_mod_with_context`].
    /// Defaulted by [`Self::new`]; set explicitly by [`Self::with_context`] so
    /// `deps_engine::setup::register_ecosystems` can share one process-wide policy handle with
    /// `ServerState` (mirrors `deps_npm::ecosystem::NpmEcosystem`'s identical `context`
    /// field).
    context: GoParseContext,
}

impl GoEcosystem {
    /// Creates a new Go ecosystem with the given HTTP cache, using a fresh, default
    /// [`GoParseContext`] — an all-`PublicOnly`-policy, empty-cache context private to this
    /// ecosystem instance. Production use goes through [`Self::with_context`] instead.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self::with_context(Arc::new(GoRegistry::new(cache)), GoParseContext::default())
    }

    /// Creates a new Go ecosystem sharing `ctx`'s reachability policy and `$GOENV`
    /// memoization cache, around an existing [`GoRegistry`] instance — the production
    /// constructor, used by `deps_engine::setup::register_ecosystems` so `initialize`/
    /// `workspace/didChangeConfiguration` can update the same `Arc<RegistryAccessPolicy>`
    /// every parse reads.
    #[must_use]
    pub fn with_context(registry: Arc<GoRegistry>, ctx: GoParseContext) -> Self {
        Self {
            registry,
            formatter: GoFormatter,
            context: ctx,
        }
    }

    /// Completes package names.
    ///
    /// Go doesn't have a centralized search API like crates.io or npm.
    /// Users typically know the full module path (e.g., github.com/gin-gonic/gin).
    /// This implementation returns empty results for now.
    ///
    /// Future enhancements could include:
    /// - Popular packages database
    /// - Local workspace module paths
    /// - Integration with go.sum for recently used modules
    #[cfg(feature = "lsp-responses")]
    fn complete_package_names(&self, _prefix: &str) -> impl Future<Output = Vec<CompletionItem>> {
        std::future::ready(vec![])
    }

    /// Completes feature flags for a specific package.
    ///
    /// Go modules don't have a feature flag system like Cargo.
    /// Returns empty results.
    #[cfg(feature = "lsp-responses")]
    fn complete_features(
        &self,
        _package_name: &deps_core::PackageName,
        _prefix: &str,
    ) -> impl Future<Output = Vec<CompletionItem>> {
        std::future::ready(vec![])
    }
}

impl deps_core::ecosystem::private::Sealed for GoEcosystem {}

impl Ecosystem for GoEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Go
    }

    fn display_name(&self) -> &'static str {
        "Go Modules"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["go.mod"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["go.sum"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Url,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_go_mod_with_context(content, uri, &self.context)?;
            // Registers every `$GOENV`-resolved `GOPROXY`/`GOPRIVATE`-bypass chain this parse
            // found (spec 034) into the shared router — the only point where a per-document
            // `$GOENV` resolution and the long-lived `GoRegistry` this ecosystem shares across
            // every document ever meet. See `GoParseResult::resolved_chains`.
            for chain in &result.resolved_chains {
                GoRegistry::register_alternate(&self.registry, chain);
            }
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::GoSumParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    #[cfg(feature = "lsp-responses")]
    fn complete_package_name<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        prefix: String,
        _range: Range,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move { self.complete_package_names(&prefix).await.into() })
    }

    #[cfg(feature = "lsp-responses")]
    fn complete_feature<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move { self.complete_features(&package_name, &prefix).await.into() })
    }

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: deps_core::position::Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        Some(extract_prefix(line, position.character))
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("{} {latest}", name.as_str()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Checks if `line_number` of `content` is inside a go.mod `require` directive.
///
/// Handles both the single-line form (`require module version`) and the
/// parenthesized block form (`require (` ... `)`), for `deps-lsp`'s raw-text fallback
/// completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    let mut in_require_block = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim();
        let is_block_start = trimmed
            .strip_prefix("require")
            .is_some_and(|rest| rest.trim_start().starts_with('('));

        if is_block_start {
            in_require_block = true;
        } else if in_require_block && trimmed.starts_with(')') {
            in_require_block = false;
        }

        if i == line_number {
            return in_require_block || is_block_start || trimmed.starts_with("require ");
        }
    }

    false
}

/// Extracts the fallback-completion prefix on `line` up to `character` — a bare
/// module path, with no manifest-syntax wrapper to strip.
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GoDependency, GoDirective};
    #[cfg(feature = "lsp-responses")]
    use deps_core::parser::DependencySource;
    use deps_core::position::{Position as DomainPosition, Range as DomainRange};
    use deps_core::{Dependency, VersionData};
    #[cfg(feature = "lsp-responses")]
    use deps_core::{EcosystemConfig, PackageVersions};

    #[cfg(feature = "lsp-responses")]
    deps_core::complete_versions_test_shim!(GoEcosystem);
    use std::collections::HashMap;
    #[cfg(feature = "lsp-responses")]
    use tower_lsp_server::ls_types::{InlayHintLabel, Position};

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    /// Mock dependency for testing
    fn mock_dependency(name: &str, version: Option<&str>, line: u32) -> GoDependency {
        GoDependency {
            module_path: name.into(),
            module_path_range: DomainRange::new(
                DomainPosition::new(line, 0),
                DomainPosition::new(line, name.len() as u32),
            ),
            version: version.map(Into::into),
            version_range: version.map(|_| {
                DomainRange::new(DomainPosition::new(line, 0), DomainPosition::new(line, 10))
            }),
            directive: GoDirective::Require,
            indirect: false,
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<GoDependency>,
        uri: Url,
    }

    /// A dependency on `line`, with a `version_range` there so position-based lookup
    /// (issue #593) can find it — mirrors `mock_dependency`, but with an explicit `source`.
    #[cfg(feature = "lsp-responses")]
    fn dep_with_source(name: &str, source: DependencySource, line: u32) -> GoDependency {
        GoDependency {
            module_path: pkg(name),
            module_path_range: DomainRange::new(
                DomainPosition::new(line, 0),
                DomainPosition::new(line, 0),
            ),
            version: None,
            version_range: Some(DomainRange::new(
                DomainPosition::new(line, 0),
                DomainPosition::new(line, 10),
            )),
            directive: GoDirective::Require,
            indirect: false,
            source,
        }
    }

    impl deps_core::ParseResult for MockParseResult {
        fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
            self.dependencies
                .iter()
                .map(|d| d as &dyn deps_core::Dependency)
                .collect()
        }

        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }

        fn uri(&self) -> &Url {
            &self.uri
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_ecosystem_manifest_filenames/
    // test_ecosystem_lockfile_filenames/test_as_any family. test_registry_returns_trait_object
    // stays hand-written below: it also asserts the concrete `GoRegistry` downcast, stronger
    // than the macro's plain smoke check.
    deps_core::ecosystem_conformance! {
        mod go_ecosystem_conformance;
        build: GoEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: GoEcosystem;
        id: "go";
        display_name: "Go Modules";
        manifest_filenames: &["go.mod"];
        lockfile_filenames: &["go.sum"];
        non_registry_fixture: "go.mod" => "module example.com/myapp\n\nrequire github.com/acme/secretmod v1.0.0\n\nreplace github.com/acme/secretmod => ./local/secretmod\n";
    }

    // #794: no `completion_guard_conformance!` for this crate — `complete_package_names`
    // above unconditionally returns `vec![]` (Go has no centralized module-search API, so
    // users type the full module path), never calling `registry.search` or
    // `is_valid_completion_prefix_len` at all. The macro's fixture asserts a valid-length
    // prefix against an always-has-a-result registry comes back non-empty, which cannot
    // hold for a completion path that is unconditionally empty by design — mirrors
    // `deps_github_actions`/`deps_gitlab_ci`'s identical N/A for the same reason (no
    // package-name search endpoint).

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `Ecosystem::
    // version_operator_chars`'s trait-default doc comment (`go.mod` has no operator
    // syntax, so this crate never overrides it), so an edit to one without the other
    // fails loudly instead of silently degrading completion. Calls through the real
    // `version_operator_chars()` method (not a bare `&[]` literal) so a future override
    // in this crate is caught by this test instead of silently diverging from it.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod go_operator_chars_conformance;
        ecosystem: "go";
        operator_chars: GoEcosystem::new(Arc::new(deps_core::HttpCache::new())).version_operator_chars();
        required: &[];
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_inlay_hints_up_to_date() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "github.com/gin-gonic/gin".into(),
            PackageVersions::latest_only("v1.9.1"),
        );

        let config = EcosystemConfig::default();

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("github.com/gin-gonic/gin".into(), "v1.9.1".into());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅ v1.9.1"),
            _ => panic!("Expected String label"),
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_inlay_hints_needs_update() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.0"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "github.com/gin-gonic/gin".into(),
            PackageVersions::latest_only("v1.9.1"),
        );

        let config = EcosystemConfig::default();

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "❌ v1.9.1"),
            _ => panic!("Expected String label"),
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_inlay_hints_hide_up_to_date() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "github.com/gin-gonic/gin".into(),
            PackageVersions::latest_only("v1.9.1"),
        );

        let config = EcosystemConfig::default().with_show_up_to_date_hints(false);

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("github.com/gin-gonic/gin".into(), "v1.9.1".into());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 0);
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_inlay_hints_no_version_range() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let mut dep = mock_dependency("github.com/gin-gonic/gin", Some("v1.9.1"), 5);
        dep.version_range = None;

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "github.com/gin-gonic/gin".into(),
            PackageVersions::latest_only("v1.9.1"),
        );

        let config = EcosystemConfig::default();

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 0);
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let results = ecosystem.complete_package_names("github").await;
        assert!(results.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let dep = mock_dependency("github.com/gin-gonic/gin", Some("v1.9"), 0);
        let position = dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "v1.9",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("v1.9")));
    }

    /// #1034: backed by a mockito server (rather than a live `proxy.golang.org` request) so
    /// the `is_empty()` assertion is driven by a deliberately-failing mocked 404 response,
    /// not by whatever the live network happens to do — an offline run was previously
    /// vacuously green here, masking a real regression in error handling. Only `/@v/list` is
    /// mocked: `complete_versions` routes through `Registry::get_versions_with` → the
    /// inherent `get_versions`, which never requests `/@latest` (that endpoint belongs to
    /// `get_latest_matching`, a different call path).
    ///
    /// `assert_async` (impl-critic S1) proves the mock was actually hit, not just that some
    /// error occurred — `completions` has no `Result` to match a specific error variant on
    /// (it always degrades a fetch error to an empty `Vec`), so this is the strongest signal
    /// available that the empty result came from the intended mocked 404 rather than an
    /// unrelated failure (e.g. mockito's own `501` for an unmatched request, which would
    /// satisfy a bare `is_empty()` just as well).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/github.com/nonexistent/package12345/@v/list")
            .with_status(404)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = Arc::new(GoRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            server.url(),
        ));
        let ecosystem = GoEcosystem::with_context(registry, GoParseContext::default());

        let dep = mock_dependency("github.com/nonexistent/package12345", Some("v1.0"), 0);
        let position = dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "v1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;

        list_mock.assert_async().await;
        assert!(results.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_features_always_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let results = ecosystem
            .complete_features(&pkg("github.com/gin-gonic/gin"), "")
            .await;
        assert!(results.is_empty());
    }

    /// #1066: was `assert!(results.len() <= 20)` against a live registry — a tautology given
    /// the actual display cap (`MAX_COMPLETION_VERSIONS`, `deps-core`) is 5, not 20, so it
    /// passed vacuously (even for 0 results) and could never catch a cap regression. Mocks 8
    /// matching versions and asserts the count is exactly the real cap.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_capped_at_max_completion_versions() {
        let mut server = mockito::Server::new_async().await;
        let versions_body = (0..8)
            .map(|i| format!("v1.0.{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mock = server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body(versions_body)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = Arc::new(GoRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            server.url(),
        ));
        let ecosystem = GoEcosystem::with_context(registry, GoParseContext::default());

        // Test that we respect the display cap, not just some loose upper bound.
        let dep = mock_dependency("github.com/gin-gonic/gin", Some("v1.0"), 0);
        let position = dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "v",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert_eq!(results.len(), 5);
    }

    /// #1034: backed by a mockito server (rather than a live `proxy.golang.org` request) so
    /// this is deterministic and fast — the sibling `test_generate_diagnostics_basic`
    /// documents why the live-network shape is otherwise `#[ignore]`d.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_hover_on_module_path() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.0\nv1.9.1\nv1.10.0\n")
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = Arc::new(GoRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            server.url(),
        ));
        let ecosystem = GoEcosystem::with_context(registry, GoParseContext::default());

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let position = Position::new(5, 5);
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = ecosystem
            .generate_hover(
                &parse_result,
                position,
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::FreshnessSettings::default(),
            )
            .await;

        // Returns hover with package URL and the mock-derived latest version (impl-critic
        // M1: without this, the assertions never depended on the mocked response at all).
        assert!(hover.is_some());
        let hover_content = hover.unwrap();
        let markdown = format!("{:?}", hover_content.contents);
        assert!(markdown.contains("pkg.go.dev"));
        assert!(
            markdown.contains("**Latest**: `v1.10.0`"),
            "expected the mocked /@v/list's highest version to render as Latest: {markdown}"
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_hover_outside_dependency() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let position = Position::new(0, 0);
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = ecosystem
            .generate_hover(
                &parse_result,
                position,
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(hover.is_none());
    }

    /// #1014: backed by a mockito server (rather than a live `proxy.golang.org` request)
    /// so this exercises the same `generate_code_actions` / REFACTOR-action-building code
    /// path deterministically, without network flakiness (the sibling
    /// `test_generate_diagnostics_basic` documents why that live-network shape is
    /// otherwise `#[ignore]`d). `DependencySource::Registry` (the default from
    /// `mock_dependency`) routes through `GoRegistry`'s `Public` tier, so
    /// `with_public_base_for_test` — not the `WorkspaceDeclared`-tier `with_base` the
    /// alternate-registry tests above use — is the matching mock entry point.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_code_actions_on_module() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.0\nv1.9.1\nv1.10.0\n")
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = Arc::new(GoRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            server.url(),
        ));
        let ecosystem = GoEcosystem::with_context(registry, GoParseContext::default());

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.0"),
                5,
            )],
            uri: uri.clone(),
        };

        let position = Position::new(5, 5);
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        // `version_range` on line 5 spans columns 0..10; content must slice to
        // exactly the declared requirement text there for the `literal_span_matches`
        // guard in `generate_code_actions` to accept the edit.
        let content = "\n\n\n\n\nv1.9.0    \n";

        let actions = ecosystem
            .generate_code_actions(
                &parse_result,
                position,
                &uri,
                VersionData::new(&cached_versions, &resolved_versions),
                content,
            )
            .await;

        let ls_uri: tower_lsp_server::ls_types::Uri = uri.as_str().parse().unwrap();

        // Actions are registry-derived "update to version" REFACTOR edits, one per
        // candidate version; exactly one is marked preferred (the highest matching).
        assert!(
            actions.iter().any(|action| {
                action
                    .edit
                    .as_ref()
                    .and_then(|edit| edit.changes.as_ref())
                    .and_then(|changes| changes.get(&ls_uri))
                    .is_some_and(|edits| edits.iter().any(|e| e.new_text.contains("v1.10.0")))
            }),
            "expected an action whose edit updates the dependency to v1.10.0, got: {actions:?}"
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| action.is_preferred == Some(true))
                .count(),
            1,
            "expected exactly one preferred action, got: {actions:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires network access to proxy.golang.org"]
    async fn test_generate_diagnostics_basic() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ecosystem.generate_diagnostics(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                parse_result.uri(),
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
            ),
        )
        .await;

        assert!(result.is_ok(), "Diagnostic generation timed out");
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_package_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = r"module example.com/myapp

go 1.21

require github.com/
";

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![],
            uri,
        };

        let position = Position::new(4, 19);

        let completions = ecosystem
            .generate_completions(
                &parse_result,
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(completions.items.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_outside_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = r"module example.com/myapp

go 1.21
";

        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = MockParseResult {
            dependencies: vec![],
            uri,
        };

        let position = Position::new(0, 0);

        let completions = ecosystem
            .generate_completions(
                &parse_result,
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(completions.items.is_empty());
    }

    /// #1195 M4 regression: `VERSION_OPERATOR_CHARS` is empty for Go — `go.mod` requires a
    /// bare exact semver with no comparator syntax at all, so nothing about the version
    /// prefix's *shape* ever protected a `Version` position from `deps-lsp`'s raw-text
    /// fallback before this PR; only `CompletionOrigin::Version` does now. Runs through the
    /// real parser and the real `generate_completions` dispatch (not a synthetic
    /// `ParseResult`), with a mocked 404 so the empty result is deterministic;
    /// `list_mock.assert_async()` proves the `Version` context was actually reached rather
    /// than resolving to `None`/`Unresolved`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_empty_result_stamps_version_origin() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/github.com/nonexistent/package12345/@v/list")
            .with_status(404)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = Arc::new(GoRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            server.url(),
        ));
        let ecosystem = GoEcosystem::with_context(registry, GoParseContext::default());

        let content = "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/nonexistent/package12345 v1.2.3\n";
        let uri = deps_core::test_util::test_uri("/test/go.mod");
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "fixture must parse to exactly one dependency: {content}"
        );

        let version_range = parse_result.dependencies()[0].version_range().unwrap();
        let position: Position = version_range.start.into();

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        list_mock.assert_async().await;
        assert!(completions.items.is_empty());
        assert_eq!(
            completions.origin,
            deps_core::completion::CompletionOrigin::Version,
            "go.mod has no comparator syntax at all — CompletionOrigin::Version is the only \
             thing that can stop deps-lsp's fallback from leaking the raw module-path+version \
             text into a package-name search here"
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = r"module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
";

        let uri = deps_core::test_util::test_uri("/test/go.mod");

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert_eq!(parse_result.dependencies().len(), 1);
        assert_eq!(
            parse_result.dependencies()[0].name(),
            "github.com/gin-gonic/gin"
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = "";
        let uri = deps_core::test_util::test_uri("/test/go.mod");

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert_eq!(parse_result.dependencies().len(), 0);
    }

    #[test]
    fn test_registry_returns_trait_object() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let registry = ecosystem.registry();
        assert!(registry.as_any().is::<GoRegistry>());
    }

    #[test]
    fn test_lockfile_provider_exists() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        assert!(ecosystem.lockfile_provider().is_some());
    }

    #[test]
    fn test_mock_dependency_indirect() {
        let mut dep = mock_dependency("github.com/example/pkg", Some("v1.0.0"), 10);
        dep.indirect = true;

        assert!(dep.indirect);
        assert_eq!(dep.name(), "github.com/example/pkg");
    }

    // --- issue #593: completion routes by cursor position, not by resolved DependencySource name ---

    /// Two dependencies sharing one `PackageName` but resolving to different sources no
    /// longer collapse into the old name-based "offer nothing for either" result (spec 034
    /// F1's `CompletionSource::Ambiguous`) — cursor position now identifies exactly one
    /// dependency, so each occurrence routes independently through its own source.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_same_name_different_sources_routes_by_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let registry_dep = dep_with_source("git.mycorp.example/pkg", DependencySource::Registry, 0);
        let alternate_dep = dep_with_source(
            "git.mycorp.example/pkg",
            DependencySource::AlternateRegistry {
                index: "go-private:never-registered".to_string(),
                mirrors_crates_io: false,
            },
            1,
        );
        let alternate_position = alternate_dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![registry_dep, alternate_dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };

        // The alternate occurrence resolves deterministically without network: its index was
        // never registered, so the fetch fails closed with `PackageNotFound` before any HTTP
        // call — proving its own source, not the co-occurring `Registry`-sourced entry, drove
        // the routing.
        let results = ecosystem
            .complete_versions(
                &parse_result,
                alternate_position,
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "unregistered alternate index must offer no completions"
        );
    }

    /// An `AlternateRegistry` source whose index has no registered client offers no
    /// completions — never a fall back to `proxy.golang.org` (the core of F1).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_unregistered_alternate_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let dep = dep_with_source(
            "git.mycorp.example/internal/auth",
            DependencySource::AlternateRegistry {
                index: "never-registered".to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// F1 end-to-end: a registered alternate client's version completion routes there,
    /// proving completion actually consults the resolved `$GOENV` chain instead of always
    /// querying the public root.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_routes_to_registered_alternate_client() {
        use crate::config::{GoProxyChain, GoProxyHop, GoProxyUrl};
        use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};

        let mut alt_server = mockito::Server::new_async().await;
        alt_server
            .mock("GET", "/git.mycorp.example/internal/auth/@v/list")
            .with_status(200)
            .with_body("v1.0.0\nv1.5.0\n")
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let registry = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let ecosystem = GoEcosystem::with_context(Arc::clone(&registry), GoParseContext::default());

        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::All);
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![GoProxyHop::Url(
                GoProxyUrl::new(&alt_server.url(), &policy).unwrap(),
            )],
            ..Default::default()
        };
        GoRegistry::register_alternate(&registry, &chain);

        let dep = dep_with_source(
            "git.mycorp.example/internal/auth",
            DependencySource::AlternateRegistry {
                index: "go-proxy:test".to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start.into();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
    }

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_dependencies_section`'s `require (...)` block scan compose correctly
    /// through the real trait method on realistic multi-line `go.mod` content.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let content = "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/g";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position.into()),
            Some("github.com/gin-gonic/g")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_single_line() {
        let content = "module example.com/myapp\n\nrequire github.com/gin-gonic/gin v1.9.1\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 0));
    }

    #[test]
    fn test_is_in_dependencies_section_block() {
        let content =
            "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(is_in_dependencies_section(content, 3));
        assert!(!is_in_dependencies_section(content, 4));
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        struct MockMetadata {
            name: deps_core::PackageName,
            latest_version: deps_core::ConcreteVersion,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                &self.latest_version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
        let meta = MockMetadata {
            name: pkg("github.com/stretchr/testify"),
            latest_version: "v1.9.0".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("github.com/stretchr/testify v1.9.0".to_string())
        );
    }
}
