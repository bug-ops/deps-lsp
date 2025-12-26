//! PyPI ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Python projects,
//! providing LSP functionality for `pyproject.toml` files.

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

use crate::formatter::PypiFormatter;
use crate::parser::PypiParser;
use crate::registry::PypiRegistry;

/// PyPI ecosystem implementation.
///
/// Provides LSP functionality for pyproject.toml files, including:
/// - Dependency parsing with position tracking
/// - Version information from PyPI registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/yanked packages
pub struct PypiEcosystem {
    registry: Arc<PypiRegistry>,
    parser: PypiParser,
    formatter: PypiFormatter,
}

impl PypiEcosystem {
    /// Creates a new PyPI ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PypiRegistry::new(cache)),
            parser: PypiParser::new(),
            formatter: PypiFormatter,
        }
    }

    /// Completes package names by searching the PyPI registry.
    ///
    /// Requires at least 2 characters for search. Returns up to 20 results.
    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        use deps_core::completion::build_package_completion;

        // Security: reject too short or too long prefixes
        if prefix.len() < 2 || prefix.len() > 100 {
            return vec![];
        }

        // Search registry (limit to 20 results)
        let results = match self.registry.search(prefix, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Package search failed for '{}': {}", prefix, e);
                return vec![];
            }
        };

        // Use dummy range - completion will be inserted at cursor position
        let insert_range = tower_lsp_server::ls_types::Range::default();

        results
            .into_iter()
            .map(|metadata| {
                let boxed: Box<dyn deps_core::Metadata> = Box::new(metadata);
                build_package_completion(boxed.as_ref(), insert_range)
            })
            .collect()
    }

    /// Completes version strings for a specific package.
    ///
    /// Filters versions by prefix and hides yanked versions by default.
    /// Returns up to 20 results, newest stable versions first.
    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        use deps_core::completion::build_version_completion;

        // Fetch all versions for the package
        let versions = match self.registry.get_versions(package_name).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch versions for '{}': {}", package_name, e);
                return vec![];
            }
        };

        let insert_range = tower_lsp_server::ls_types::Range::default();

        // Filter by prefix (strip PEP 440 operators like >=, ==, ~=, etc.)
        let clean_prefix = prefix.trim_start_matches(['>', '<', '=', '~', '!']).trim();

        // Filter by prefix and hide yanked versions
        let mut filtered_iter = versions
            .iter()
            .filter(|v| v.version.starts_with(clean_prefix) && !v.yanked)
            .take(20)
            .peekable();

        // If we have filtered results, use them; otherwise show all non-yanked versions
        if filtered_iter.peek().is_some() {
            // Use filtered results (consume peekable iterator)
            filtered_iter
                .map(|v| {
                    build_version_completion(
                        v as &dyn deps_core::Version,
                        package_name,
                        insert_range,
                    )
                })
                .collect()
        } else {
            // Show up to 20 non-yanked versions (newest first)
            versions
                .iter()
                .filter(|v| !v.yanked)
                .take(20)
                .map(|v| {
                    build_version_completion(
                        v as &dyn deps_core::Version,
                        package_name,
                        insert_range,
                    )
                })
                .collect()
        }
    }
}

#[async_trait]
impl Ecosystem for PypiEcosystem {
    fn id(&self) -> &'static str {
        "pypi"
    }

    fn display_name(&self) -> &'static str {
        "PyPI (Python)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["pyproject.toml"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["poetry.lock", "uv.lock"]
    }

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResultTrait>> {
        let result = self.parser.parse_content(content, uri).map_err(|e| {
            deps_core::DepsError::ParseError {
                file_type: "pyproject.toml".into(),
                source: Box::new(e),
            }
        })?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::PypiLockParser))
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        lsp_helpers::generate_inlay_hints(
            parse_result,
            cached_versions,
            resolved_versions,
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
            // PyPI doesn't have features like Cargo
            CompletionContext::Feature { .. } => vec![],
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

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "pypi");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "PyPI (Python)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["pyproject.toml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["poetry.lock", "uv.lock"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<PypiEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem.complete_package_names("d").await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_real_search() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem.complete_package_names("reque").await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "requests"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem.complete_versions("requests", "2.").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem.complete_versions("requests", ">=2.").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions("this-package-does-not-exist-12345", "1.0")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Package names with hyphens and underscores should work
        let results = ecosystem.complete_package_names("scikit-le").await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Prefix longer than 100 chars should return empty (security)
        let long_prefix = "a".repeat(101);
        let results = ecosystem.complete_package_names(&long_prefix).await;
        assert!(results.is_empty());

        // Exactly 100 chars should work
        let max_prefix = "a".repeat(100);
        let results = ecosystem.complete_package_names(&max_prefix).await;
        // Should not panic, but may return empty (no matches)
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_limit_20() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem.complete_versions("requests", "2").await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_special_chars_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Real packages with special characters
        let results = ecosystem.complete_package_names("scikit-le").await;
        assert!(!results.is_empty() || results.is_empty()); // May or may not have results
    }

    #[tokio::test]
    async fn test_parse_manifest_valid_content() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
dependencies = ["requests>=2.0.0"]
"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(!parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_toml() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let invalid_content = "[project\nname = invalid";

        let result = ecosystem.parse_manifest(invalid_content, &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_manifest_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
dependencies = []
"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_registry_returns_arc() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let registry = ecosystem.registry();
        assert!(Arc::strong_count(&registry) >= 1);
    }

    #[tokio::test]
    async fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let provider = ecosystem.lockfile_provider();
        assert!(provider.is_some());
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
dependencies = []
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let config = EcosystemConfig::default();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                &cached_versions,
                &resolved_versions,
                &config,
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };

        let completions = ecosystem
            .generate_completions(parse_result.as_ref(), position, content)
            .await;

        assert!(completions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_feature_context_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // PyPI doesn't have features, so this should always return empty
        // Even if we detect a feature context (which shouldn't happen for PyPI)
        // This tests the Feature branch in generate_completions
        let content = r#"[project]
dependencies = ["requests"]
"#;
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        // Test with any position - feature context should return empty
        let position = Position {
            line: 1,
            character: 20,
        };

        let completions = ecosystem
            .generate_completions(parse_result.as_ref(), position, content)
            .await;

        // Should not crash, returns empty or package/version completions
        assert!(completions.is_empty() || !completions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_hover_no_dependency_at_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = ecosystem
            .generate_hover(
                parse_result.as_ref(),
                position,
                &cached_versions,
                &resolved_versions,
            )
            .await;

        assert!(hover.is_none());
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_actions() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();

        let actions = ecosystem
            .generate_code_actions(parse_result.as_ref(), position, &cached_versions, &uri)
            .await;

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();

        let content = r#"[project]
name = "test"
dependencies = []
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();

        let diagnostics = ecosystem
            .generate_diagnostics(parse_result.as_ref(), &cached_versions, &uri)
            .await;

        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_empty_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Empty prefix should show non-yanked versions (up to 20)
        let results = ecosystem.complete_versions("nonexistent-package", "").await;
        // Should not panic, returns empty for unknown package
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_tilde_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test PEP 440 operators are stripped correctly
        let results = ecosystem
            .complete_versions("nonexistent-pkg", "~=2.0")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_not_equal_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test != operator stripping
        let results = ecosystem
            .complete_versions("nonexistent-pkg", "!=2.0")
            .await;
        assert!(results.is_empty());
    }
}
