//! Go modules ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Go projects,
//! providing LSP functionality for `go.mod` files.

use std::any::Any;
use std::future::Future;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter, parser::DependencySource,
};

use crate::config::GoParseContext;
use crate::formatter::GoFormatter;
use crate::registry::GoRegistry;

/// The source(s) a `CompletionContext::Version`'s bare `package_name` joins back to within a
/// manifest's already-parsed dependencies (spec 034 F1).
enum CompletionSource {
    /// No dependency in the manifest has this exact name yet — most commonly because the
    /// user is still typing a brand-new dependency line. Callers fall back to the
    /// pre-existing public-registry-only behavior, unchanged.
    NotInManifest,
    /// Every occurrence of this name in the manifest agrees on one resolved source.
    Resolved(DependencySource),
    /// Two or more occurrences of this name resolve to different sources — callers must
    /// offer no completions at all rather than picking one arbitrarily.
    Ambiguous,
}

/// Joins `package_name` back to `parse_result.dependencies()` by name (spec 034 F1).
///
/// Mirrors `deps_npm::ecosystem`/`deps_pypi::ecosystem`'s identical helper — the resolved
/// `$GOENV` source is already attached to each dependency by `parser::parse_go_mod_with_context`,
/// so this is purely a name join, no `$GOENV` re-resolution.
fn resolve_completion_source(
    parse_result: &dyn ParseResultTrait,
    package_name: &deps_core::PackageName,
) -> CompletionSource {
    let mut sources = parse_result
        .dependencies()
        .into_iter()
        .filter(|d| d.name() == package_name)
        .map(deps_core::Dependency::source);

    let Some(first) = sources.next() else {
        return CompletionSource::NotInManifest;
    };
    if sources.all(|s| s == first) {
        CompletionSource::Resolved(first)
    } else {
        tracing::warn!(
            package = %package_name,
            "ambiguous dependency source for version completion; offering none"
        );
        CompletionSource::Ambiguous
    }
}

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
    /// `crate::lib::register_ecosystems` can share one process-wide policy handle with
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
    /// constructor, used by `crate::lib::register_ecosystems` so `initialize`/
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
    fn complete_package_names(&self, _prefix: &str) -> impl Future<Output = Vec<CompletionItem>> {
        // Go modules don't have a centralized search API
        // Users typically know the full module path
        std::future::ready(vec![])
    }

    /// Completes version requirements for `package_name`, routed by the source that name
    /// resolves to in `parse_result` (spec 034 F1). An ambiguous, unresolved, or
    /// unregistered-alternate source offers no completions rather than risking a private
    /// module path lookup against `proxy.golang.org` — the same leak class `GOPRIVATE`/`GOPROXY`
    /// close for hover/diagnostics/code-actions.
    async fn complete_versions(
        &self,
        parse_result: &dyn ParseResultTrait,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        match resolve_completion_source(parse_result, package_name) {
            CompletionSource::Ambiguous => vec![],
            CompletionSource::NotInManifest
            | CompletionSource::Resolved(DependencySource::Registry) => {
                deps_core::completion::complete_versions_generic(
                    self.registry.as_ref(),
                    package_name,
                    prefix,
                    &[],
                    freshness,
                )
                .await
            }
            CompletionSource::Resolved(DependencySource::AlternateRegistry { index, .. }) => {
                match self.registry.alternate_client(&index) {
                    Some(client) => {
                        deps_core::completion::complete_versions_generic(
                            client.as_ref(),
                            package_name,
                            prefix,
                            &[],
                            freshness,
                        )
                        .await
                    }
                    None => vec![],
                }
            }
            CompletionSource::Resolved(_) => vec![],
        }
    }

    /// Completes feature flags for a specific package.
    ///
    /// Go modules don't have a feature flag system like Cargo.
    /// Returns empty results.
    fn complete_features(
        &self,
        _package_name: &deps_core::PackageName,
        _prefix: &str,
    ) -> impl Future<Output = Vec<CompletionItem>> {
        // Go modules don't have feature flags
        std::future::ready(vec![])
    }
}

impl deps_core::ecosystem::private::Sealed for GoEcosystem {}

impl Ecosystem for GoEcosystem {
    fn id(&self) -> &'static str {
        "go"
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
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_go_mod_with_context(content, uri, &self.context)?;
            // Registers every `$GOENV`-resolved `GOPROXY`/`GOPRIVATE`-bypass chain this parse
            // found (spec 034) into the shared router — the only point where a per-document
            // `$GOENV` resolution and the long-lived `GoRegistry` this ecosystem shares across
            // every document ever meet. See `GoParseResult::resolved_chains`.
            for chain in &result.resolved_chains {
                GoRegistry::register_chain(&self.registry, chain);
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

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix, .. } => {
                    self.complete_package_names(&prefix).await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => {
                    self.complete_versions(parse_result, &package_name, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature {
                    package_name,
                    prefix,
                } => self.complete_features(&package_name, &prefix).await,
                CompletionContext::None => vec![],
            }
            .into()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GoDependency, GoDirective};
    use deps_core::{Dependency, EcosystemConfig, PackageVersions, VersionData};
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{InlayHintLabel, Position, Range};

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    /// Mock dependency for testing
    fn mock_dependency(name: &str, version: Option<&str>, line: u32) -> GoDependency {
        GoDependency {
            module_path: name.into(),
            module_path_range: Range::new(
                Position::new(line, 0),
                Position::new(line, name.len() as u32),
            ),
            version: version.map(Into::into),
            version_range: version
                .map(|_| Range::new(Position::new(line, 0), Position::new(line, 10))),
            directive: GoDirective::Require,
            indirect: false,
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<GoDependency>,
        uri: Uri,
    }

    /// A `MockParseResult` with no dependencies — `resolve_completion_source` reports
    /// `NotInManifest` for any name against it, so `complete_versions` falls back to its
    /// pre-existing public-registry-only behavior (F1: this is the mechanical,
    /// behavior-preserving fixture change forced on every pre-existing `complete_versions`
    /// test below).
    fn empty_parse_result() -> MockParseResult {
        MockParseResult {
            dependencies: vec![],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        }
    }

    fn dep_with_source(name: &str, source: DependencySource) -> GoDependency {
        GoDependency {
            module_path: pkg(name),
            module_path_range: Range::default(),
            version: None,
            version_range: None,
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

        fn uri(&self) -> &Uri {
            &self.uri
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "go");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "Go Modules");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["go.mod"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["go.sum"]);
    }

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

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version
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

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

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

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
            show_up_to_date_hints: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version - but show_up_to_date_hints is false
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

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 0);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Verify we can downcast
        let any = ecosystem.as_any();
        assert!(any.is::<GoEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Go doesn't have package search, should always return empty
        let results = ecosystem.complete_package_names("github").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("github.com/gin-gonic/gin"),
                "v1.9",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("v1.9")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("github.com/nonexistent/package12345"),
                "v1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_features_always_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Go doesn't have features, should always return empty
        let results = ecosystem
            .complete_features(&pkg("github.com/gin-gonic/gin"), "")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_limit_20() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("github.com/gin-gonic/gin"),
                "v",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    async fn test_generate_hover_on_module_path() {
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

        // Returns hover with package URL
        assert!(hover.is_some());
        let hover_content = hover.unwrap();
        let markdown = format!("{:?}", hover_content.contents);
        assert!(markdown.contains("pkg.go.dev"));
    }

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

    #[tokio::test]
    async fn test_generate_code_actions_on_module() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

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

        // Returns actions (open documentation link)
        assert!(!actions.is_empty());
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

        // Use timeout to prevent hanging
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

        // Should complete within timeout
        assert!(result.is_ok(), "Diagnostic generation timed out");
    }

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

        // Go doesn't support package search, should be empty
        assert!(completions.items.is_empty());
    }

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

    // --- spec 034 F1: completion routes by resolved DependencySource ---

    #[test]
    fn test_resolve_completion_source_not_in_manifest() {
        let parse_result = empty_parse_result();
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("github.com/gin-gonic/gin")),
            CompletionSource::NotInManifest
        ));
    }

    #[test]
    fn test_resolve_completion_source_resolved() {
        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "github.com/gin-gonic/gin",
                DependencySource::Registry,
            )],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("github.com/gin-gonic/gin")),
            CompletionSource::Resolved(DependencySource::Registry)
        ));
    }

    /// Two occurrences of the same name resolving to different sources must not pick either
    /// arbitrarily.
    #[test]
    fn test_resolve_completion_source_ambiguous() {
        let parse_result = MockParseResult {
            dependencies: vec![
                dep_with_source("git.mycorp.example/pkg", DependencySource::Registry),
                dep_with_source(
                    "git.mycorp.example/pkg",
                    DependencySource::AlternateRegistry {
                        index: "go-private:direct".to_string(),
                        mirrors_crates_io: false,
                    },
                ),
            ],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("git.mycorp.example/pkg")),
            CompletionSource::Ambiguous
        ));
    }

    #[tokio::test]
    async fn test_complete_versions_ambiguous_source_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let parse_result = MockParseResult {
            dependencies: vec![
                dep_with_source("git.mycorp.example/pkg", DependencySource::Registry),
                dep_with_source(
                    "git.mycorp.example/pkg",
                    DependencySource::AlternateRegistry {
                        index: "go-private:direct".to_string(),
                        mirrors_crates_io: false,
                    },
                ),
            ],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("git.mycorp.example/pkg"),
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// An `AlternateRegistry` source whose index has no registered client offers no
    /// completions — never a fall back to `proxy.golang.org` (the core of F1).
    #[tokio::test]
    async fn test_complete_versions_unregistered_alternate_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);
        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "git.mycorp.example/internal/auth",
                DependencySource::AlternateRegistry {
                    index: "never-registered".to_string(),
                    mirrors_crates_io: false,
                },
            )],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("git.mycorp.example/internal/auth"),
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// F1 end-to-end: a registered alternate client's version completion routes there,
    /// proving completion actually consults the resolved `$GOENV` chain instead of always
    /// querying the public root.
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
        GoRegistry::register_chain(&registry, &chain);

        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "git.mycorp.example/internal/auth",
                DependencySource::AlternateRegistry {
                    index: "go-proxy:test".to_string(),
                    mirrors_crates_io: false,
                },
            )],
            uri: deps_core::test_util::test_uri("/test/go.mod"),
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("git.mycorp.example/internal/auth"),
                "v1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
    }
}
