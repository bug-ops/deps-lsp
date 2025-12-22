//! Code actions handler implementation.
//!
//! Provides quick fixes for dependency issues:
//! - "Update to latest version" for outdated dependencies
//! - "Add missing feature" for feature suggestions

use crate::document::{Ecosystem, ServerState};
use crate::handlers::{CargoHandlerImpl, NpmHandlerImpl, PyPiHandlerImpl};
use deps_core::EcosystemHandler;
use std::sync::Arc;
use tower_lsp::lsp_types::{CodeActionOrCommand, CodeActionParams};

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
    let dependencies = doc.dependencies.clone();
    drop(doc);

    match ecosystem {
        Ecosystem::Cargo => {
            let handler = CargoHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_code_actions(&handler, &dependencies, uri, range).await
        }
        Ecosystem::Npm => {
            let handler = NpmHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_code_actions(&handler, &dependencies, uri, range).await
        }
        Ecosystem::Pypi => {
            let handler = PyPiHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_code_actions(&handler, &dependencies, uri, range).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::{Position, Range};

    /// Helper function for tests - checks if two ranges overlap.
    fn ranges_overlap(a: Range, b: Range) -> bool {
        !(a.end.line < b.start.line
            || (a.end.line == b.start.line && a.end.character < b.start.character)
            || b.end.line < a.start.line
            || (b.end.line == a.start.line && b.end.character < a.start.character))
    }

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
