//! Code actions handler implementation.
//!
//! Provides quick fixes for dependency issues:
//! - "Update to latest version" for outdated dependencies
//! - "Add missing feature" for feature suggestions

use crate::cargo::registry::CratesIoRegistry;
use crate::cargo::types::DependencySource;
use crate::document::ServerState;
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

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for code actions: {}", uri);
            return vec![];
        }
    };

    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let deps_in_range: Vec<_> = doc
        .dependencies
        .iter()
        .filter(|dep| {
            matches!(dep.source, DependencySource::Registry)
                && dep
                    .version_range
                    .map(|r| ranges_overlap(r, range))
                    .unwrap_or(false)
        })
        .collect();

    let futures: Vec<_> = deps_in_range
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

        let edit = TextEdit {
            range: version_range,
            new_text: format!(r#""{}""#, latest.num),
        };

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), vec![edit]);

        actions.push(CodeActionOrCommand::CodeAction(CodeAction {
            title: format!("Update to latest version ({})", latest.num),
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }),
            ..Default::default()
        }));
    }

    actions
}

/// Checks if two ranges overlap.
fn ranges_overlap(a: Range, b: Range) -> bool {
    !(a.end.line < b.start.line || b.end.line < a.start.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Position;

    #[test]
    fn test_ranges_overlap() {
        let r1 = Range::new(Position::new(1, 0), Position::new(1, 10));
        let r2 = Range::new(Position::new(1, 5), Position::new(1, 15));
        assert!(ranges_overlap(r1, r2));

        let r3 = Range::new(Position::new(1, 0), Position::new(1, 10));
        let r4 = Range::new(Position::new(2, 0), Position::new(2, 10));
        assert!(!ranges_overlap(r3, r4));
    }

    #[test]
    fn test_ranges_overlap_same_line() {
        let r1 = Range::new(Position::new(1, 0), Position::new(1, 10));
        let r2 = Range::new(Position::new(1, 10), Position::new(1, 20));
        assert!(ranges_overlap(r1, r2));
    }
}
