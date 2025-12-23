//! Cargo ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Cargo/Rust projects,
//! providing LSP functionality for `Cargo.toml` files.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CompletionItem, Diagnostic, DiagnosticSeverity, Hover,
    HoverContents, InlayHint, InlayHintKind, InlayHintLabel, MarkupContent, MarkupKind, Position,
    TextEdit, Url, WorkspaceEdit,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, Version,
};

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
}

impl CargoEcosystem {
    /// Creates a new Cargo ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(CratesIoRegistry::new(cache)),
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

    async fn parse_manifest(
        &self,
        content: &str,
        uri: &Url,
    ) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_cargo_toml(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        let mut hints = Vec::new();

        for dep in parse_result.dependencies() {
            let Some(version_range) = dep.version_range() else {
                continue;
            };

            let Some(latest_version) = cached_versions.get(dep.name()) else {
                continue;
            };

            let version_req = dep.version_requirement().unwrap_or("");
            let is_latest = latest_version == version_req
                || (version_req.starts_with('^')
                    && version_req.len() > 1
                    && latest_version.starts_with(
                        version_req[1..].split('.').next().unwrap_or(""),
                    ));

            let label_text = if is_latest {
                if config.show_up_to_date_hints {
                    config.up_to_date_text.clone()
                } else {
                    continue;
                }
            } else {
                config.needs_update_text.replace("{}", latest_version)
            };

            hints.push(InlayHint {
                position: version_range.end,
                label: InlayHintLabel::String(label_text),
                kind: Some(InlayHintKind::TYPE),
                padding_left: Some(true),
                padding_right: None,
                text_edits: None,
                tooltip: None,
                data: None,
            });
        }

        hints
    }

    async fn generate_hover(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        cached_versions: &HashMap<String, String>,
    ) -> Option<Hover> {
        let dep = parse_result
            .dependencies()
            .into_iter()
            .find(|d| ranges_overlap(d.name_range(), position))?;

        let versions = self.registry.get_versions(dep.name()).await.ok()?;

        let url = self.registry.package_url(dep.name());
        let mut markdown = format!("# [{}]({})\n\n", dep.name(), url);

        if let Some(version_req) = dep.version_requirement() {
            markdown.push_str(&format!("**Current**: `{}`\n\n", version_req));
        }

        if let Some(latest) = cached_versions.get(dep.name()) {
            markdown.push_str(&format!("**Latest**: `{}`\n\n", latest));
        }

        markdown.push_str("**Recent versions**:\n");
        for (i, version) in versions.iter().take(8).enumerate() {
            if i == 0 {
                markdown.push_str(&format!("- {} *(latest)*\n", version.version_string()));
            } else if version.is_yanked() {
                markdown.push_str(&format!("- {} *(yanked)*\n", version.version_string()));
            } else {
                markdown.push_str(&format!("- {}\n", version.version_string()));
            }
        }

        Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: markdown,
            }),
            range: Some(dep.name_range()),
        })
    }

    async fn generate_code_actions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        _cached_versions: &HashMap<String, String>,
        uri: &Url,
    ) -> Vec<CodeAction> {
        let mut actions = Vec::new();

        let Some(dep) = parse_result
            .dependencies()
            .into_iter()
            .find(|d| {
                d.version_range()
                    .is_some_and(|r| ranges_overlap(r, position))
            })
        else {
            return actions;
        };

        let version_range = dep.version_range().unwrap();

        let Ok(versions) = self.registry.get_versions(dep.name()).await else {
            return actions;
        };

        for (i, version) in versions
            .iter()
            .filter(|v| !v.is_yanked())
            .take(5)
            .enumerate()
        {
            let new_text = format!("\"{}\"", version.version_string());

            let mut edits = HashMap::new();
            edits.insert(
                uri.clone(),
                vec![TextEdit {
                    range: version_range,
                    new_text,
                }],
            );

            let title = if i == 0 {
                format!("Update {} to {} (latest)", dep.name(), version.version_string())
            } else {
                format!("Update {} to {}", dep.name(), version.version_string())
            };

            actions.push(CodeAction {
                title,
                kind: Some(CodeActionKind::QUICKFIX),
                edit: Some(WorkspaceEdit {
                    changes: Some(edits),
                    ..Default::default()
                }),
                is_preferred: Some(i == 0),
                ..Default::default()
            });
        }

        actions
    }

    async fn generate_diagnostics(
        &self,
        parse_result: &dyn ParseResultTrait,
        _cached_versions: &HashMap<String, String>,
        _uri: &Url,
    ) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        for dep in parse_result.dependencies() {
            let versions = match self.registry.get_versions(dep.name()).await {
                Ok(v) => v,
                Err(_) => {
                    diagnostics.push(Diagnostic {
                        range: dep.name_range(),
                        severity: Some(DiagnosticSeverity::WARNING),
                        message: format!("Unknown package '{}'", dep.name()),
                        source: Some("deps-lsp".into()),
                        ..Default::default()
                    });
                    continue;
                }
            };

            let Some(version_req) = dep.version_requirement() else {
                continue;
            };
            let Some(version_range) = dep.version_range() else {
                continue;
            };

            let matching = self
                .registry
                .get_latest_matching(dep.name(), version_req)
                .await
                .ok()
                .flatten();

            if let Some(current) = matching {
                if current.is_yanked() {
                    diagnostics.push(Diagnostic {
                        range: version_range,
                        severity: Some(DiagnosticSeverity::WARNING),
                        message: "This version has been yanked".into(),
                        source: Some("deps-lsp".into()),
                        ..Default::default()
                    });
                }

                let latest = versions.iter().find(|v| !v.is_yanked());
                if let Some(latest) = latest
                    && latest.version_string() != current.version_string()
                {
                    diagnostics.push(Diagnostic {
                        range: version_range,
                        severity: Some(DiagnosticSeverity::HINT),
                        message: format!("Newer version available: {}", latest.version_string()),
                        source: Some("deps-lsp".into()),
                        ..Default::default()
                    });
                }
            }
        }

        diagnostics
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

fn ranges_overlap(range: tower_lsp::lsp_types::Range, position: Position) -> bool {
    !(range.end.line < position.line
        || (range.end.line == position.line && range.end.character < position.character)
        || position.line < range.start.line
        || (position.line == range.start.line && position.character < range.start.character))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DependencySection, DependencySource, ParsedDependency};
    use std::collections::HashMap;
    use tower_lsp::lsp_types::{Position, Range};

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
            static URI: once_cell::sync::Lazy<Url> = once_cell::sync::Lazy::new(|| {
                Url::parse("file:///test/Cargo.toml").unwrap()
            });
            &URI
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_ranges_overlap_inside() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_start_boundary() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 10);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_end_boundary() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        // The implementation includes the end position as overlapping
        let position = Position::new(5, 20);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 25);
        assert!(!ranges_overlap(range, position));
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

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            &cached_versions,
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
