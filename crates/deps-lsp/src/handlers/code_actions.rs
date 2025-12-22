//! Code actions handler implementation.
//!
//! Provides quick fixes for dependency issues:
//! - "Update to latest version" for outdated dependencies
//! - "Add missing feature" for feature suggestions

use crate::document::{Ecosystem, ServerState, UnifiedDependency};

/// Maximum number of version update options to offer in code actions.
const MAX_CODE_ACTION_VERSIONS: usize = 5;
use deps_cargo::{CratesIoRegistry, DependencySource};
use deps_npm::NpmRegistry;
use deps_pypi::{PypiDependencySource, PypiRegistry};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Range, TextEdit, Url,
    WorkspaceEdit,
};

/// Handles code action requests.
///
/// Returns available quick fixes for the selected range.
/// Gracefully degrades by returning empty vec on errors.
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let range = params.range;

    tracing::info!(
        "code_action request: uri={}, range={}:{}-{}:{}",
        uri,
        range.start.line,
        range.start.character,
        range.end.line,
        range.end.character
    );

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for code actions: {}", uri);
            return vec![];
        }
    };

    tracing::info!(
        "found document with {} dependencies, ecosystem={:?}",
        doc.dependencies.len(),
        doc.ecosystem
    );

    let ecosystem = doc.ecosystem;

    // Collect dependencies that overlap with the cursor range
    let deps_to_check: Vec<(String, Range)> = doc
        .dependencies
        .iter()
        .filter_map(|dep| {
            let (name, version_range, is_registry) = match dep {
                UnifiedDependency::Cargo(cargo_dep) => (
                    cargo_dep.name.clone(),
                    cargo_dep.version_range?,
                    matches!(cargo_dep.source, DependencySource::Registry),
                ),
                UnifiedDependency::Npm(npm_dep) => {
                    (npm_dep.name.clone(), npm_dep.version_range?, true)
                }
                UnifiedDependency::Pypi(pypi_dep) => (
                    pypi_dep.name.clone(),
                    pypi_dep.version_range?,
                    matches!(pypi_dep.source, PypiDependencySource::PyPI),
                ),
            };

            if is_registry && ranges_overlap(version_range, range) {
                Some((name, version_range))
            } else {
                None
            }
        })
        .collect();

    drop(doc);

    match ecosystem {
        Ecosystem::Cargo => handle_cargo_code_actions(state, uri, deps_to_check).await,
        Ecosystem::Npm => handle_npm_code_actions(state, uri, deps_to_check).await,
        Ecosystem::Pypi => handle_pypi_code_actions(state, uri, deps_to_check).await,
    }
}

async fn handle_cargo_code_actions(
    state: Arc<ServerState>,
    uri: &Url,
    deps: Vec<(String, Range)>,
) -> Vec<CodeActionOrCommand> {
    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let futures: Vec<_> = deps
        .iter()
        .map(|(name, version_range)| {
            let name = name.clone();
            let version_range = *version_range;
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, version_range, versions)
            }
        })
        .collect();

    let results = join_all(futures).await;

    let mut actions = Vec::new();
    for (name, version_range, versions_result) in results {
        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch versions for {}: {}", name, e);
                continue;
            }
        };

        // Offer multiple version options (non-yanked, up to MAX_CODE_ACTION_VERSIONS)
        for (i, version) in versions
            .iter()
            .filter(|v| !v.yanked)
            .take(MAX_CODE_ACTION_VERSIONS)
            .enumerate()
        {
            let mut edits = HashMap::new();
            edits.insert(
                uri.clone(),
                vec![TextEdit {
                    range: version_range,
                    new_text: format!("\"{}\"", version.num),
                }],
            );

            let title = if i == 0 {
                format!("Update {} to {} (latest)", name, version.num)
            } else {
                format!("Update {} to {}", name, version.num)
            };

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title,
                kind: Some(CodeActionKind::QUICKFIX),
                edit: Some(WorkspaceEdit {
                    changes: Some(edits),
                    ..Default::default()
                }),
                is_preferred: Some(i == 0),
                ..Default::default()
            }));
        }
    }

    actions
}

async fn handle_npm_code_actions(
    state: Arc<ServerState>,
    uri: &Url,
    deps: Vec<(String, Range)>,
) -> Vec<CodeActionOrCommand> {
    let registry = NpmRegistry::new(Arc::clone(&state.cache));

    let futures: Vec<_> = deps
        .iter()
        .map(|(name, version_range)| {
            let name = name.clone();
            let version_range = *version_range;
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, version_range, versions)
            }
        })
        .collect();

    let results = join_all(futures).await;

    let mut actions = Vec::new();
    for (name, version_range, versions_result) in results {
        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch npm versions for {}: {}", name, e);
                continue;
            }
        };

        // Offer multiple version options (non-deprecated, up to MAX_CODE_ACTION_VERSIONS)
        for (i, version) in versions
            .iter()
            .filter(|v| !v.deprecated)
            .take(MAX_CODE_ACTION_VERSIONS)
            .enumerate()
        {
            let mut edits = HashMap::new();
            edits.insert(
                uri.clone(),
                vec![TextEdit {
                    range: version_range,
                    new_text: format!("\"{}\"", version.version),
                }],
            );

            let title = if i == 0 {
                format!("Update {} to {} (latest)", name, version.version)
            } else {
                format!("Update {} to {}", name, version.version)
            };

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title,
                kind: Some(CodeActionKind::QUICKFIX),
                edit: Some(WorkspaceEdit {
                    changes: Some(edits),
                    ..Default::default()
                }),
                is_preferred: Some(i == 0),
                ..Default::default()
            }));
        }
    }

    actions
}

async fn handle_pypi_code_actions(
    state: Arc<ServerState>,
    uri: &Url,
    deps: Vec<(String, Range)>,
) -> Vec<CodeActionOrCommand> {
    let registry = PypiRegistry::new(Arc::clone(&state.cache));

    // Get document to access dependency details for format detection
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for PyPI code actions: {}", uri);
            return vec![];
        }
    };

    let futures: Vec<_> = deps
        .iter()
        .map(|(name, version_range)| {
            let name = name.clone();
            let version_range = *version_range;
            let registry = registry.clone();

            // Find the dependency to get section info
            let dep = doc.dependencies.iter().find_map(|d| {
                if let UnifiedDependency::Pypi(pypi_dep) = d
                    && pypi_dep.name == name
                    && pypi_dep.version_range == Some(version_range)
                {
                    return Some(pypi_dep.clone());
                }
                None
            });

            async move {
                let versions = registry.get_versions(&name).await;
                (name, version_range, dep, versions)
            }
        })
        .collect();

    drop(doc);
    let results = join_all(futures).await;

    let mut actions = Vec::new();
    for (name, version_range, dep_opt, versions_result) in results {
        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch PyPI versions for {}: {}", name, e);
                continue;
            }
        };

        let dep = match dep_opt {
            Some(d) => d,
            None => {
                tracing::warn!("Could not find dependency {} for code action", name);
                continue;
            }
        };

        // Offer multiple version options (non-yanked, up to MAX_CODE_ACTION_VERSIONS)
        for (i, version) in versions
            .iter()
            .filter(|v| !v.yanked)
            .take(MAX_CODE_ACTION_VERSIONS)
            .enumerate()
        {
            // Format the new version text based on the dependency section
            // PEP 621 uses array format: ["package>=version"]
            // Poetry uses table format: package = "^version" or { version = "^version" }
            let new_text = match &dep.section {
                deps_pypi::PypiDependencySection::Dependencies
                | deps_pypi::PypiDependencySection::OptionalDependencies { .. }
                | deps_pypi::PypiDependencySection::DependencyGroup { .. } => {
                    // PEP 621/735 format - replace just the version specifier part
                    format!(">={}", version.version)
                }
                deps_pypi::PypiDependencySection::PoetryDependencies
                | deps_pypi::PypiDependencySection::PoetryGroup { .. } => {
                    // Poetry format - quoted version with caret
                    format!("\"^{}\"", version.version)
                }
            };

            let mut edits = HashMap::new();
            edits.insert(
                uri.clone(),
                vec![TextEdit {
                    range: version_range,
                    new_text,
                }],
            );

            let title = if i == 0 {
                format!("Update {} to {} (latest)", name, version.version)
            } else {
                format!("Update {} to {}", name, version.version)
            };

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title,
                kind: Some(CodeActionKind::QUICKFIX),
                edit: Some(WorkspaceEdit {
                    changes: Some(edits),
                    ..Default::default()
                }),
                is_preferred: Some(i == 0),
                ..Default::default()
            }));
        }
    }

    actions
}

/// Checks if two ranges overlap.
fn ranges_overlap(a: Range, b: Range) -> bool {
    !(a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character < b.start.character)
        || b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character < a.start.character))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Position;

    #[test]
    fn test_ranges_overlap() {
        let range1 = Range::new(Position::new(1, 5), Position::new(1, 10));
        let range2 = Range::new(Position::new(1, 7), Position::new(1, 12));
        assert!(ranges_overlap(range1, range2));

        let range3 = Range::new(Position::new(1, 0), Position::new(1, 4));
        assert!(!ranges_overlap(range1, range3));
    }

    #[test]
    fn test_ranges_overlap_same_range() {
        let range = Range::new(Position::new(1, 5), Position::new(1, 10));
        assert!(ranges_overlap(range, range));
    }

    #[test]
    fn test_ranges_overlap_adjacent() {
        let range1 = Range::new(Position::new(1, 5), Position::new(1, 10));
        let range2 = Range::new(Position::new(1, 10), Position::new(1, 15));
        assert!(ranges_overlap(range1, range2));
    }

    #[test]
    fn test_ranges_overlap_different_lines() {
        let range1 = Range::new(Position::new(1, 5), Position::new(1, 10));
        let range2 = Range::new(Position::new(2, 0), Position::new(2, 5));
        assert!(!ranges_overlap(range1, range2));
    }

    #[test]
    fn test_ranges_overlap_multiline() {
        let range1 = Range::new(Position::new(1, 5), Position::new(3, 10));
        let range2 = Range::new(Position::new(2, 0), Position::new(4, 5));
        assert!(ranges_overlap(range1, range2));
    }

    #[test]
    fn test_ranges_overlap_contained() {
        let outer = Range::new(Position::new(1, 0), Position::new(1, 20));
        let inner = Range::new(Position::new(1, 5), Position::new(1, 10));
        assert!(ranges_overlap(outer, inner));
        assert!(ranges_overlap(inner, outer));
    }

    #[test]
    fn test_ranges_overlap_edge_case_same_position() {
        let range1 = Range::new(Position::new(1, 5), Position::new(1, 10));
        let range2 = Range::new(Position::new(1, 5), Position::new(1, 5));
        assert!(ranges_overlap(range1, range2));
    }

    #[test]
    fn test_ranges_overlap_before() {
        let range1 = Range::new(Position::new(2, 0), Position::new(2, 10));
        let range2 = Range::new(Position::new(1, 0), Position::new(1, 10));
        assert!(!ranges_overlap(range1, range2));
    }

    #[test]
    fn test_ranges_overlap_after() {
        let range1 = Range::new(Position::new(1, 0), Position::new(1, 10));
        let range2 = Range::new(Position::new(2, 0), Position::new(2, 10));
        assert!(!ranges_overlap(range1, range2));
    }
}
