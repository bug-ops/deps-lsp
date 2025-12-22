//! Code actions handler implementation.
//!
//! Provides quick fixes for dependency issues:
//! - "Update to latest version" for outdated dependencies
//! - "Add missing feature" for feature suggestions

use crate::document::{Ecosystem, ServerState, UnifiedDependency};
use deps_cargo::{CratesIoRegistry, DependencySource, ParsedDependency};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Range, TextEdit,
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

    // TODO: Add npm support in code actions
    if doc.ecosystem != Ecosystem::Cargo {
        tracing::debug!("Code actions not yet implemented for {:?}", doc.ecosystem);
        return vec![];
    }

    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let cargo_deps: Vec<&ParsedDependency> = doc
        .dependencies
        .iter()
        .filter_map(|dep| {
            if let UnifiedDependency::Cargo(cargo_dep) = dep {
                if matches!(cargo_dep.source, DependencySource::Registry) {
                    if let Some(version_range) = cargo_dep.version_range {
                        if ranges_overlap(version_range, range) {
                            return Some(cargo_dep);
                        }
                    }
                }
            }
            None
        })
        .collect();

    let futures: Vec<_> = cargo_deps
        .iter()
        .map(|dep| {
            let name = dep.name.clone();
            let version_range = dep.version_range.unwrap();
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
                tracing::error!("Failed to fetch versions for {}: {}", name, e);
                continue;
            }
        };

        let latest = match versions.iter().find(|v| !v.yanked) {
            Some(v) => v,
            None => continue,
        };

        let mut edits = HashMap::new();
        edits.insert(
            uri.clone(),
            vec![TextEdit {
                range: version_range,
                new_text: format!("\"{}\"", latest.num),
            }],
        );

        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Update {} to {}", name, latest.num),
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            ..Default::default()
        }));
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
}
