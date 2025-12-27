//! Go modules ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Go projects,
//! providing LSP functionality for `go.mod` files.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers,
};

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
}

impl GoEcosystem {
    /// Creates a new Go ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(GoRegistry::new(cache)),
            formatter: GoFormatter,
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
    async fn complete_package_names(&self, _prefix: &str) -> Vec<CompletionItem> {
        // Go modules don't have a centralized search API
        // Users typically know the full module path
        vec![]
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
        )
        .await
    }

    /// Completes feature flags for a specific package.
    ///
    /// Go modules don't have a feature flag system like Cargo.
    /// Returns empty results.
    async fn complete_features(&self, _package_name: &str, _prefix: &str) -> Vec<CompletionItem> {
        // Go modules don't have feature flags
        vec![]
    }
}

#[async_trait]
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

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_go_mod(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::GoSumParser))
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        loading_state: deps_core::LoadingState,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        lsp_helpers::generate_inlay_hints(
            parse_result,
            cached_versions,
            resolved_versions,
            loading_state,
            config,
            &self.formatter,
        )
    }

    async fn generate_hover(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
    ) -> Option<Hover> {
        lsp_helpers::generate_hover(
            parse_result,
            position,
            cached_versions,
            resolved_versions,
            self.registry.as_ref(),
            &self.formatter,
        )
        .await
    }

    async fn generate_code_actions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        _cached_versions: &HashMap<String, String>,
        uri: &Uri,
    ) -> Vec<CodeAction> {
        lsp_helpers::generate_code_actions(
            parse_result,
            position,
            uri,
            self.registry.as_ref(),
            &self.formatter,
        )
        .await
    }

    async fn generate_diagnostics(
        &self,
        parse_result: &dyn ParseResultTrait,
        _cached_versions: &HashMap<String, String>,
        _uri: &Uri,
    ) -> Vec<Diagnostic> {
        lsp_helpers::generate_diagnostics(parse_result, self.registry.as_ref(), &self.formatter)
            .await
    }

    async fn generate_completions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        content: &str,
    ) -> Vec<CompletionItem> {
        use deps_core::completion::{CompletionContext, detect_completion_context};

        let context = detect_completion_context(parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix } => self.complete_package_names(&prefix).await,
            CompletionContext::Version {
                package_name,
                prefix,
            } => self.complete_versions(&package_name, &prefix).await,
            CompletionContext::Feature {
                package_name,
                prefix,
            } => self.complete_features(&package_name, &prefix).await,
            CompletionContext::None => vec![],
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GoDependency, GoDirective};
    use deps_core::Dependency;
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{InlayHintLabel, Position, Range};

    /// Mock dependency for testing
    fn mock_dependency(name: &str, version: Option<&str>, line: u32) -> GoDependency {
        GoDependency {
            module_path: name.to_string(),
            module_path_range: Range::new(
                Position::new(line, 0),
                Position::new(line, name.len() as u32),
            ),
            version: version.map(String::from),
            version_range: version
                .map(|_| Range::new(Position::new(line, 0), Position::new(line, 10))),
            directive: GoDirective::Require,
            indirect: false,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<GoDependency>,
        uri: Uri,
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

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_needs_update() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.0"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![dep],
            uri,
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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
            .complete_versions("github.com/gin-gonic/gin", "v1.9")
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
            .complete_versions("github.com/nonexistent/package12345", "v1.0")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_features_always_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        // Go doesn't have features, should always return empty
        let results = ecosystem
            .complete_features("github.com/gin-gonic/gin", "")
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
            .complete_versions("github.com/gin-gonic/gin", "v")
            .await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    async fn test_generate_hover_on_module_path() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
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
                &cached_versions,
                &resolved_versions,
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

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
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
                &cached_versions,
                &resolved_versions,
            )
            .await;

        assert!(hover.is_none());
    }

    #[tokio::test]
    async fn test_generate_code_actions_on_module() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
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

        let actions = ecosystem
            .generate_code_actions(&parse_result, position, &cached_versions, &uri)
            .await;

        // Returns actions (open documentation link)
        assert!(!actions.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires network access to proxy.golang.org"]
    async fn test_generate_diagnostics_basic() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency(
                "github.com/gin-gonic/gin",
                Some("v1.9.1"),
                5,
            )],
            uri,
        };

        let cached_versions = HashMap::new();

        // Use timeout to prevent hanging
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ecosystem.generate_diagnostics(&parse_result, &cached_versions, parse_result.uri()),
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

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![],
            uri,
        };

        let position = Position::new(4, 19);

        let completions = ecosystem
            .generate_completions(&parse_result, position, content)
            .await;

        // Go doesn't support package search, should be empty
        assert!(completions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_outside_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = r"module example.com/myapp

go 1.21
";

        let uri = Uri::from_file_path("/test/go.mod").unwrap();
        let parse_result = MockParseResult {
            dependencies: vec![],
            uri,
        };

        let position = Position::new(0, 0);

        let completions = ecosystem
            .generate_completions(&parse_result, position, content)
            .await;

        assert!(completions.is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GoEcosystem::new(cache);

        let content = r"module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
";

        let uri = Uri::from_file_path("/test/go.mod").unwrap();

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
        let uri = Uri::from_file_path("/test/go.mod").unwrap();

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
        assert_eq!(
            registry.package_url("github.com/gin-gonic/gin"),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );
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
}
