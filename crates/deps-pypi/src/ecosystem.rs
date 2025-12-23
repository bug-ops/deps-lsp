//! PyPI ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Python projects,
//! providing LSP functionality for `pyproject.toml` files.

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
}

impl PypiEcosystem {
    /// Creates a new PyPI ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PypiRegistry::new(cache)),
            parser: PypiParser::new(),
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

    async fn parse_manifest(&self, content: &str, uri: &Url) -> Result<Box<dyn ParseResultTrait>> {
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
        let mut hints = Vec::new();

        for dep in parse_result.dependencies() {
            let Some(version_range) = dep.version_range() else {
                continue;
            };

            // Normalize package name for lookup (PyPI names are case-insensitive, - == _)
            let normalized_name = normalize_pypi_name(dep.name());
            let latest_version = cached_versions
                .get(&normalized_name)
                .or_else(|| cached_versions.get(dep.name()));
            let resolved_version = resolved_versions
                .get(&normalized_name)
                .or_else(|| resolved_versions.get(dep.name()));

            // Determine if dependency is up-to-date
            let (is_up_to_date, display_version) = match (resolved_version, latest_version) {
                // Have both: compare resolved with latest
                (Some(resolved), Some(latest)) => {
                    let is_same = resolved == latest
                        || is_same_major_minor(resolved, latest);
                    (is_same, Some(latest.as_str()))
                }
                // Only latest: fall back to checking if latest satisfies requirement
                (None, Some(latest)) => {
                    let version_req = dep.version_requirement().unwrap_or("");
                    let is_match = version_satisfies_pep440(latest, version_req);
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

        // Normalize package name for lookup (PyPI names are case-insensitive, - == _)
        let normalized_name = normalize_pypi_name(dep.name());

        // Show resolved version from lock file if available, otherwise show manifest requirement
        let resolved = resolved_versions
            .get(&normalized_name)
            .or_else(|| resolved_versions.get(dep.name()));
        if let Some(resolved_ver) = resolved {
            markdown.push_str(&format!("**Current**: `{}`\n\n", resolved_ver));
        } else if let Some(version_req) = dep.version_requirement() {
            markdown.push_str(&format!("**Requirement**: `{}`\n\n", version_req));
        }

        let latest = cached_versions
            .get(&normalized_name)
            .or_else(|| cached_versions.get(dep.name()));
        if let Some(latest_ver) = latest {
            markdown.push_str(&format!("**Latest**: `{}`\n\n", latest_ver));
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

        // Find dependency where cursor is anywhere on the dependency line
        // (from start of name to end of version, or just on name line if no version)
        let Some(dep) = parse_result.dependencies().into_iter().find(|d| {
            let name_range = d.name_range();
            // Check if cursor is on the same line as the dependency
            if position.line != name_range.start.line {
                return false;
            }
            // Create extended range: from start of name to end of version (or end of name)
            let end_char = d
                .version_range()
                .map(|r| r.end.character)
                .unwrap_or(name_range.end.character);
            // Add some padding for quotes and surrounding characters
            let start_char = name_range.start.character.saturating_sub(2);
            let end_char = end_char.saturating_add(2);
            let in_range = position.character >= start_char && position.character <= end_char;
            tracing::debug!(
                "code_action check: dep={}, pos={}:{}, range={}..{}, in_range={}",
                d.name(),
                position.line,
                position.character,
                start_char,
                end_char,
                in_range
            );
            in_range
        }) else {
            tracing::debug!(
                "code_action: no dependency found at position {}:{}",
                position.line,
                position.character
            );
            return actions;
        };

        let Some(version_range) = dep.version_range() else {
            tracing::debug!("code_action: dependency {} has no version_range", dep.name());
            return actions;
        };

        let Ok(versions) = self.registry.get_versions(dep.name()).await else {
            return actions;
        };

        for (i, version) in versions
            .iter()
            .filter(|v| !v.is_yanked())
            .take(5)
            .enumerate()
        {
            // Calculate next major version with overflow protection
            let next_major = version
                .version_string()
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .and_then(|v| v.checked_add(1))
                .unwrap_or(1);

            // version_range does NOT include quotes (unlike Cargo), so new_text shouldn't either
            let new_text = format!(">={},<{}", version.version_string(), next_major);

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

/// Normalizes a PyPI package name for comparison.
/// PyPI names are case-insensitive and treat hyphens and underscores as equivalent.
fn normalize_pypi_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
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

/// Checks if a version satisfies a PEP 440 specifier using pep440_rs.
fn version_satisfies_pep440(version: &str, specifier: &str) -> bool {
    use pep440_rs::{Version, VersionSpecifiers};
    use std::str::FromStr;

    let ver = match Version::from_str(version) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let specs = match VersionSpecifiers::from_str(specifier) {
        Ok(s) => s,
        Err(_) => return false,
    };

    specs.contains(&ver)
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
        let ecosystem = PypiEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<PypiEcosystem>());
    }
}
