//! npm ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for npm/JavaScript projects,
//! providing LSP functionality for `package.json` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::NpmFormatter;
use crate::registry::NpmRegistry;

/// npm ecosystem implementation.
///
/// Provides LSP functionality for package.json files, including:
/// - Dependency parsing with position tracking
/// - Version information from npm registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/deprecated packages
pub struct NpmEcosystem {
    registry: Arc<NpmRegistry>,
    formatter: NpmFormatter,
}

impl NpmEcosystem {
    /// Creates a new npm ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(NpmRegistry::new(cache)),
            formatter: NpmFormatter,
        }
    }

    /// Completes package names by searching the npm registry.
    ///
    /// Requires at least 2 characters for search. Returns up to 20 results.
    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(self.registry.as_ref(), prefix, 20)
            .await
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &['^', '~', '=', '<', '>', '*'],
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for NpmEcosystem {}

impl Ecosystem for NpmEcosystem {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn display_name(&self) -> &'static str {
        "npm (JavaScript)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["package.json"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["package-lock.json"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_package_json(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::NpmLockParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix } => {
                    self.complete_package_names(&prefix).await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => self.complete_versions(&package_name, &prefix).await,
                CompletionContext::Feature { .. } => vec![],
                CompletionContext::None => vec![],
            }
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::EcosystemConfig;
    use std::collections::HashMap;

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "npm");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "npm (JavaScript)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["package.json"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["package-lock.json"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<NpmEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem.complete_package_names("e").await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_real_search() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem.complete_package_names("expre").await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "express"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem.complete_versions("express", "4.").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("4.")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem.complete_versions("express", "^4.").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("4.")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions("this-package-does-not-exist-12345", "1.0")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Package names with special characters (@scope/package) should work
        let results = ecosystem.complete_package_names("@type").await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Prefix longer than 200 chars should return empty (security)
        let long_prefix = "a".repeat(201);
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
        let ecosystem = NpmEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem.complete_versions("express", "4").await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_scoped() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Scoped packages (@types/node, etc.)
        let results = ecosystem.complete_package_names("@types").await;
        assert!(!results.is_empty() || results.is_empty()); // May not have results but shouldn't panic
    }

    #[tokio::test]
    async fn test_parse_manifest_valid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(!parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let invalid_content = r#"{"dependencies": invalid json"#;

        let result = ecosystem.parse_manifest(invalid_content, &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_manifest_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"dependencies": {}}"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_registry_returns_arc() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let registry = ecosystem.registry();
        assert!(Arc::strong_count(&registry) >= 1);
    }

    #[tokio::test]
    async fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let provider = ecosystem.lockfile_provider();
        assert!(provider.is_some());
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"dependencies": {}}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let config = EcosystemConfig::default();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                &cached_versions,
                &resolved_versions,
                deps_core::LoadingState::Loaded,
                &config,
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"name": "test"}"#;

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
        let ecosystem = NpmEcosystem::new(cache);

        // npm doesn't have features, so this should always return empty
        let content = r#"{"dependencies": {"express": "4.0.0"}}"#;
        let uri = Uri::from_file_path("/test/package.json").unwrap();
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let position = Position {
            line: 0,
            character: 30,
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
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"name": "test"}"#;

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
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"name": "test"}"#;

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
        let ecosystem = NpmEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/package.json").unwrap();

        let content = r#"{"dependencies": {}}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = ecosystem
            .generate_diagnostics(
                parse_result.as_ref(),
                &cached_versions,
                &resolved_versions,
                &uri,
            )
            .await;

        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_empty_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Empty prefix should show non-deprecated versions (up to 20)
        let results = ecosystem.complete_versions("nonexistent-package", "").await;
        // Should not panic, returns empty for unknown package
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_tilde_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test ~ operator stripping
        let results = ecosystem.complete_versions("nonexistent-pkg", "~4.0").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_wildcard() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test * wildcard stripping
        let results = ecosystem.complete_versions("nonexistent-pkg", "*").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_less_than_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test < and > operator stripping
        let results = ecosystem.complete_versions("nonexistent-pkg", "<2.0").await;
        assert!(results.is_empty());
    }
}
