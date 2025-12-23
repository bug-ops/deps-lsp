//! Cargo ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Cargo/Rust projects,
//! providing LSP functionality for `Cargo.toml` files.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Url,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers,
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

    async fn parse_manifest(&self, content: &str, uri: &Url) -> Result<Box<dyn ParseResultTrait>> {
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
        uri: &Url,
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
        _uri: &Url,
    ) -> Vec<Diagnostic> {
        lsp_helpers::generate_diagnostics(parse_result, self.registry.as_ref(), &self.formatter)
            .await
    }

    async fn generate_completions(
        &self,
        _parse_result: &dyn ParseResultTrait,
        _position: Position,
        _content: &str,
    ) -> Vec<CompletionItem> {
        vec![]
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
    use tower_lsp::lsp_types::{InlayHintLabel, Position, Range};

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

        fn uri(&self) -> &Url {
            static URI: once_cell::sync::Lazy<Url> =
                once_cell::sync::Lazy::new(|| Url::parse("file:///test/Cargo.toml").unwrap());
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
    fn test_generate_inlay_hints_up_to_date_exact_match() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.214"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✓"),
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
            show_up_to_date_hints: true,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✓"),
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
            show_up_to_date_hints: true,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "↑ 1.0.214"),
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
            show_up_to_date_hints: false,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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
            show_up_to_date_hints: true,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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
            show_up_to_date_hints: true,
            up_to_date_text: "✓".to_string(),
            needs_update_text: "↑ {}".to_string(),
        };

        // Should not panic, should return update hint
        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
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
}
