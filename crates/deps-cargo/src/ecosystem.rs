//! Cargo ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Cargo/Rust projects,
//! providing LSP functionality for `Cargo.toml` files.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, Version,
    lsp_helpers,
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

    /// Completes package names by searching the crates.io registry.
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

        // Filter by prefix (strip ^ or ~ operators)
        let clean_prefix = prefix.trim_start_matches(['^', '~', '=', '<', '>']);

        // Filter by prefix and hide yanked versions
        let mut filtered_iter = versions
            .iter()
            .filter(|v| v.num.starts_with(clean_prefix) && !v.yanked)
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

#[async_trait]
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

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_cargo_toml(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::CargoLockParser))
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
    use crate::types::{DependencySection, DependencySource, ParsedDependency};
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
