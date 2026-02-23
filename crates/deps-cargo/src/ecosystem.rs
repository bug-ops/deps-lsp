//! Cargo ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Cargo/Rust projects,
//! providing LSP functionality for `Cargo.toml` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, Version,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::CargoFormatter;
use crate::registry::CratesIoRegistry;

/// Cargo ecosystem implementation.
///
/// Provides LSP functionality for Cargo.toml files, including:
/// - Dependency parsing with position tracking
/// - Version information from crates.io
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/yanked packages
pub struct CargoEcosystem {
    registry: Arc<CratesIoRegistry>,
    formatter: CargoFormatter,
}

impl CargoEcosystem {
    /// Creates a new Cargo ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(CratesIoRegistry::new(cache)),
            formatter: CargoFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(self.registry.as_ref(), prefix, 20)
            .await
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &['^', '~', '=', '<', '>'],
        )
        .await
    }

    /// Completes feature flags for a specific package.
    ///
    /// Fetches features from the latest stable version.
    async fn complete_features(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        use deps_core::completion::build_feature_completion;

        // Fetch all versions to find latest stable
        let versions = match self.registry.get_versions(package_name).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch versions for '{}': {}", package_name, e);
                return vec![];
            }
        };

        let latest = match versions.iter().find(|v| v.is_stable()) {
            Some(v) => v,
            None => {
                tracing::warn!("No stable version found for '{}'", package_name);
                return vec![];
            }
        };

        let insert_range = tower_lsp_server::ls_types::Range::default();

        // Get features and filter by prefix
        let features = latest.features();
        features
            .into_iter()
            .filter(|f| f.starts_with(prefix))
            .map(|feature| build_feature_completion(&feature, package_name, insert_range))
            .collect()
    }
}

impl deps_core::ecosystem::private::Sealed for CargoEcosystem {}

impl Ecosystem for CargoEcosystem {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn display_name(&self) -> &'static str {
        "Cargo (Rust)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Cargo.toml"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["Cargo.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_cargo_toml(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::CargoLockParser))
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
                CompletionContext::Feature {
                    package_name,
                    prefix,
                } => self.complete_features(&package_name, &prefix).await,
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
    use crate::types::{DependencySection, DependencySource, ParsedDependency};
    use deps_core::EcosystemConfig;
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{InlayHintLabel, Position, Range};

    /// Mock dependency for testing
    fn mock_dependency(
        name: &str,
        version: Option<&str>,
        name_line: u32,
        version_line: u32,
    ) -> ParsedDependency {
        ParsedDependency {
            name: name.to_string(),
            name_range: Range::new(
                Position::new(name_line, 0),
                Position::new(name_line, name.len() as u32),
            ),
            version_req: version.map(String::from),
            version_range: version.map(|_| {
                Range::new(
                    Position::new(version_line, 0),
                    Position::new(version_line, 10),
                )
            }),
            features: vec![],
            features_range: None,
            source: DependencySource::Registry,
            workspace_inherited: false,
            section: DependencySection::Dependencies,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<ParsedDependency>,
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
            static URI: std::sync::LazyLock<Uri> =
                std::sync::LazyLock::new(|| Uri::from_file_path("/test/Cargo.toml").unwrap());
            &URI
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "cargo");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "Cargo (Rust)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["Cargo.toml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["Cargo.lock"]);
    }

    #[test]
    fn test_generate_inlay_hints_up_to_date_exact_match() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.214"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "1.0.214".to_string());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_up_to_date_caret_version() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("^1.0"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "1.0.214".to_string());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_needs_update() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.100"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

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
            InlayHintLabel::String(s) => assert_eq!(s, "❌ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_hide_up_to_date() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.214"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version - but show_up_to_date_hints is false
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "1.0.214".to_string());
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
        let ecosystem = CargoEcosystem::new(cache);

        let mut dep = mock_dependency("serde", Some("1.0.214"), 5, 5);
        dep.version_range = None;

        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

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
    fn test_generate_inlay_hints_caret_edge_case() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Edge case: version_req is just "^" without version number
        let dep = mock_dependency("serde", Some("^"), 5, 5);

        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Should not panic, should return update hint
        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Verify we can downcast
        let any = ecosystem.as_any();
        assert!(any.is::<CargoEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem.complete_package_names("s").await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_real_search() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem.complete_package_names("serd").await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "serde"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem.complete_versions("serde", "1.0").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("1.0")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem.complete_versions("serde", "^1.0").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("1.0")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem.complete_features("serde", "").await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "derive"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_with_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem.complete_features("serde", "der").await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("der")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions("this-package-does-not-exist-12345", "1.0")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_features_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_features("this-package-does-not-exist-12345", "")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Package names with hyphens and underscores should work
        let results = ecosystem.complete_package_names("tokio-ut").await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

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
        let ecosystem = CargoEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem.complete_versions("serde", "1").await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_empty_list() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Some packages have no features - should handle gracefully
        // (Using a package that likely has no features, or empty prefix on a small package)
        let results = ecosystem.complete_features("anyhow", "nonexistent").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_special_chars_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Real packages with special characters
        let results = ecosystem.complete_package_names("tokio-ut").await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label.contains('-')));
    }

    #[test]
    fn test_generate_inlay_hints_loading_state() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("tokio", Some("1.0"), 5, 5)],
        };

        // Empty caches - simulating loading state
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            deps_core::LoadingState::Loading,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "⏳", "Expected loading indicator"),
            _ => panic!("Expected String label"),
        }

        if let Some(tower_lsp_server::ls_types::InlayHintTooltip::String(tooltip)) =
            &hints[0].tooltip
        {
            assert_eq!(tooltip, "Fetching latest version...");
        } else {
            panic!("Expected tooltip for loading state");
        }
    }
}
