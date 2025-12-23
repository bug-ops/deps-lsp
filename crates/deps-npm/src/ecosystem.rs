//! npm ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for npm/JavaScript projects,
//! providing LSP functionality for `package.json` files.

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
}

impl NpmEcosystem {
    /// Creates a new npm ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(NpmRegistry::new(cache)),
        }
    }
}

#[async_trait]
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

    async fn parse_manifest(&self, content: &str, uri: &Url) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_package_json(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::NpmLockParser))
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        let mut hints = Vec::new();

        for dep in parse_result.dependencies() {
            let Some(version_range) = dep.version_range() else {
                continue;
            };

            let latest_version = cached_versions.get(dep.name());
            let resolved_version = resolved_versions.get(dep.name());

            // Determine if dependency is up-to-date
            let (is_up_to_date, display_version) = match (resolved_version, latest_version) {
                // Have both: compare resolved with latest
                (Some(resolved), Some(latest)) => {
                    let is_same = resolved == latest
                        || is_same_major_minor(resolved, latest);
                    (is_same, Some(latest.as_str()))
                }
                // Only latest: fall back to comparing requirement with latest
                (None, Some(latest)) => {
                    let version_req = dep.version_requirement().unwrap_or("");
                    // Strip caret/tilde prefix if present for comparison
                    let req_normalized = version_req
                        .strip_prefix('^')
                        .or_else(|| version_req.strip_prefix('~'))
                        .unwrap_or(version_req);
                    // Check if it's a partial version (1 or 2 parts) vs full version (3+ parts)
                    let req_parts: Vec<&str> = req_normalized.split('.').collect();
                    let is_partial_version = req_parts.len() <= 2;
                    let is_match = latest == version_req
                        || (is_partial_version && is_same_major_minor(req_normalized, latest))
                        || (is_partial_version && latest.starts_with(req_normalized));
                    (is_match, Some(latest.as_str()))
                }
                // Only resolved: show as up-to-date with resolved version
                (Some(resolved), None) => (true, Some(resolved.as_str())),
                // Neither: skip this dependency
                (None, None) => continue,
            };

            let label_text = if is_up_to_date {
                if config.show_up_to_date_hints {
                    if let Some(resolved) = resolved_version {
                        format!("{} {}", config.up_to_date_text, resolved)
                    } else {
                        config.up_to_date_text.clone()
                    }
                } else {
                    continue;
                }
            } else {
                let version = display_version.unwrap_or("unknown");
                config.needs_update_text.replace("{}", version)
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
        resolved_versions: &HashMap<String, String>,
    ) -> Option<Hover> {
        let dep = parse_result
            .dependencies()
            .into_iter()
            .find(|d| {
                let on_name = ranges_overlap(d.name_range(), position);
                let on_version = d.version_range().is_some_and(|r| ranges_overlap(r, position));
                on_name || on_version
            })?;

        let versions = self.registry.get_versions(dep.name()).await.ok()?;

        let url = crate::registry::package_url(dep.name());
        let mut markdown = format!("# [{}]({})\n\n", dep.name(), url);

        // Show resolved version from lock file if available, otherwise show manifest requirement
        if let Some(resolved) = resolved_versions.get(dep.name()) {
            markdown.push_str(&format!("**Current**: `{}`\n\n", resolved));
        } else if let Some(version_req) = dep.version_requirement() {
            markdown.push_str(&format!("**Requirement**: `{}`\n\n", version_req));
        }

        if let Some(latest) = cached_versions.get(dep.name()) {
            markdown.push_str(&format!("**Latest**: `{}`\n\n", latest));
        }

        markdown.push_str("**Recent versions**:\n");
        for (i, version) in versions.iter().take(8).enumerate() {
            if i == 0 {
                markdown.push_str(&format!("- {} *(latest)*\n", version.version_string()));
            } else if version.is_yanked() {
                markdown.push_str(&format!("- {} *(deprecated)*\n", version.version_string()));
            } else {
                markdown.push_str(&format!("- {}\n", version.version_string()));
            }
        }

        markdown.push_str("\n---\n⌨️ **Press `Cmd+.` to update version**");

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

        let Some(dep) = parse_result.dependencies().into_iter().find(|d| {
            d.version_range()
                .is_some_and(|r| ranges_overlap(r, position))
        }) else {
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
                format!(
                    "Update {} to {} (latest)",
                    dep.name(),
                    version.version_string()
                )
            } else {
                format!("Update {} to {}", dep.name(), version.version_string())
            };

            actions.push(CodeAction {
                title,
                kind: Some(CodeActionKind::REFACTOR),
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
                        message: "This version is deprecated".into(),
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

/// Checks if two version strings have the same major and minor version.
fn is_same_major_minor(v1: &str, v2: &str) -> bool {
    let parts1: Vec<&str> = v1.split('.').collect();
    let parts2: Vec<&str> = v2.split('.').collect();

    if parts1.len() >= 2 && parts2.len() >= 2 {
        parts1[0] == parts2[0] && parts1[1] == parts2[1]
    } else if !parts1.is_empty() && !parts2.is_empty() {
        parts1[0] == parts2[0]
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_ranges_overlap_inside() {
        let range = tower_lsp::lsp_types::Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_before() {
        let range = tower_lsp::lsp_types::Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<NpmEcosystem>());
    }
}
