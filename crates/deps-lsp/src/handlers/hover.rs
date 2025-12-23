//! Hover handler implementation.
//!
//! Provides rich hover documentation when the cursor is over a dependency
//! name or version string. Shows crate metadata, latest version, features,
//! and links to documentation/repository.

use crate::document::{Ecosystem, ServerState};
use crate::handlers::{CargoHandlerImpl, NpmHandlerImpl, PyPiHandlerImpl};
use deps_core::{EcosystemHandler, generate_hover};
use std::sync::Arc;
use tower_lsp::lsp_types::{Hover, HoverParams, Position, Range};

/// Handles hover requests.
///
/// Returns documentation for the dependency at the cursor position.
/// Degrades gracefully by returning None if no dependency is found or
/// if fetching version information fails.
///
/// # Examples
///
/// Hovering over "serde" in `serde = "1.0"` shows:
/// ```markdown
/// # serde
///
/// **Current**: `1.0`
/// **Latest**: `1.0.214`
///
/// **Features**:
/// - `derive`
/// - `std`
/// - `alloc`
/// ...
/// ```
pub async fn handle_hover(state: Arc<ServerState>, params: HoverParams) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    let doc = state.get_document(uri)?;

    let dep = doc.dependencies.iter().find(|d| {
        position_in_range(position, d.name_range())
            || d.version_range()
                .is_some_and(|r| position_in_range(position, r))
    })?;

    if !dep.is_registry() {
        return None;
    }

    let ecosystem = doc.ecosystem;
    let dep = dep.clone();
    // Get resolved version from lock file if available
    let resolved_version = doc.resolved_versions.get(dep.name()).cloned();
    drop(doc);

    match ecosystem {
        Ecosystem::Cargo => {
            let handler = CargoHandlerImpl::new(Arc::clone(&state.cache));
            generate_hover(&handler, &dep, resolved_version.as_deref()).await
        }
        Ecosystem::Npm => {
            let handler = NpmHandlerImpl::new(Arc::clone(&state.cache));
            generate_hover(&handler, &dep, resolved_version.as_deref()).await
        }
        Ecosystem::Pypi => {
            let handler = PyPiHandlerImpl::new(Arc::clone(&state.cache));
            generate_hover(&handler, &dep, resolved_version.as_deref()).await
        }
    }
}

/// Checks if a position is within a range.
fn position_in_range(pos: Position, range: Range) -> bool {
    (pos.line > range.start.line
        || (pos.line == range.start.line && pos.character >= range.start.character))
        && (pos.line < range.end.line
            || (pos.line == range.end.line && pos.character <= range.end.character))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Position;

    #[test]
    fn test_position_in_range() {
        let range = Range::new(Position::new(1, 5), Position::new(1, 10));

        assert!(position_in_range(Position::new(1, 5), range));
        assert!(position_in_range(Position::new(1, 7), range));
        assert!(position_in_range(Position::new(1, 10), range));

        assert!(!position_in_range(Position::new(1, 4), range));
        assert!(!position_in_range(Position::new(1, 11), range));
        assert!(!position_in_range(Position::new(0, 5), range));
        assert!(!position_in_range(Position::new(2, 5), range));
    }

    #[test]
    fn test_position_in_multiline_range() {
        let range = Range::new(Position::new(1, 5), Position::new(3, 10));

        assert!(position_in_range(Position::new(1, 5), range));
        assert!(position_in_range(Position::new(2, 0), range));
        assert!(position_in_range(Position::new(3, 10), range));

        assert!(!position_in_range(Position::new(1, 4), range));
        assert!(!position_in_range(Position::new(3, 11), range));
    }
}
