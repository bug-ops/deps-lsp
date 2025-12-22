//! Hover handler implementation.
//!
//! Provides rich hover documentation when the cursor is over a dependency
//! name or version string. Shows crate metadata, latest version, features,
//! and links to documentation/repository.

use crate::document::{Ecosystem, ServerState, UnifiedDependency};
use deps_cargo::{CratesIoRegistry, crate_url};
use deps_npm::{NpmRegistry, package_url};
use deps_pypi::PypiRegistry;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    Hover, HoverContents, HoverParams, MarkupContent, MarkupKind, Position, Range,
};

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
    drop(doc);

    match ecosystem {
        Ecosystem::Cargo => handle_cargo_hover(state, uri, position, &dep).await,
        Ecosystem::Npm => handle_npm_hover(state, uri, position, &dep).await,
        Ecosystem::Pypi => handle_pypi_hover(state, uri, position, &dep).await,
    }
}

async fn handle_cargo_hover(
    state: Arc<ServerState>,
    _uri: &tower_lsp::lsp_types::Url,
    _position: Position,
    dep: &UnifiedDependency,
) -> Option<Hover> {
    let UnifiedDependency::Cargo(cargo_dep) = dep else {
        return None;
    };

    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));
    let versions = registry.get_versions(&cargo_dep.name).await.ok()?;
    let latest = versions.first()?;

    let url = crate_url(&cargo_dep.name);
    let mut markdown = format!("# [{}]({})\n\n", cargo_dep.name, url);

    if let Some(current) = &cargo_dep.version_req {
        markdown.push_str(&format!("**Current**: `{}`\n\n", current));
    }

    if latest.yanked {
        markdown.push_str("⚠️ **Warning**: This version has been yanked\n\n");
    }

    // Show version list
    markdown.push_str("**Versions** *(use Cmd+. to update)*:\n");
    for (i, version) in versions.iter().take(8).enumerate() {
        if i == 0 {
            // Latest version with docs.rs link
            let docs_url = format!("https://docs.rs/{}/{}", cargo_dep.name, version.num);
            markdown.push_str(&format!("- {} [(docs)]({})\n", version.num, docs_url));
        } else {
            markdown.push_str(&format!("- {}\n", version.num));
        }
    }
    if versions.len() > 8 {
        markdown.push_str(&format!("- *...and {} more*\n", versions.len() - 8));
    }

    // Show features if available
    if !latest.features.is_empty() {
        markdown.push_str("\n**Features**:\n");
        for feature in latest.features.keys().take(10) {
            markdown.push_str(&format!("- `{}`\n", feature));
        }
        if latest.features.len() > 10 {
            markdown.push_str(&format!("- *...and {} more*\n", latest.features.len() - 10));
        }
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(cargo_dep.name_range),
    })
}

async fn handle_npm_hover(
    state: Arc<ServerState>,
    _uri: &tower_lsp::lsp_types::Url,
    _position: Position,
    dep: &UnifiedDependency,
) -> Option<Hover> {
    let UnifiedDependency::Npm(npm_dep) = dep else {
        return None;
    };

    let registry = NpmRegistry::new(Arc::clone(&state.cache));
    let versions = registry.get_versions(&npm_dep.name).await.ok()?;
    let latest = versions.first()?;

    let url = package_url(&npm_dep.name);
    let mut markdown = format!("# [{}]({})\n\n", npm_dep.name, url);

    if let Some(current) = &npm_dep.version_req {
        markdown.push_str(&format!("**Current**: `{}`\n\n", current));
    }

    if latest.deprecated {
        markdown.push_str("⚠️ **Warning**: This package is deprecated\n\n");
    }

    // Show version list
    markdown.push_str("**Versions** *(use Cmd+. to update)*:\n");
    for (i, version) in versions.iter().take(8).enumerate() {
        if i == 0 {
            markdown.push_str(&format!("- {} *(latest)*\n", version.version));
        } else {
            markdown.push_str(&format!("- {}\n", version.version));
        }
    }
    if versions.len() > 8 {
        markdown.push_str(&format!("- *...and {} more*\n", versions.len() - 8));
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(npm_dep.name_range),
    })
}

async fn handle_pypi_hover(
    state: Arc<ServerState>,
    _uri: &tower_lsp::lsp_types::Url,
    _position: Position,
    dep: &UnifiedDependency,
) -> Option<Hover> {
    let UnifiedDependency::Pypi(pypi_dep) = dep else {
        return None;
    };

    let registry = PypiRegistry::new(Arc::clone(&state.cache));
    let versions = registry.get_versions(&pypi_dep.name).await.ok()?;
    let latest = versions.first()?;

    let url = format!("https://pypi.org/project/{}/", pypi_dep.name);
    let mut markdown = format!("# [{}]({})\n\n", pypi_dep.name, url);

    if let Some(current) = &pypi_dep.version_req {
        markdown.push_str(&format!("**Current**: `{}`\n\n", current));
    }

    if latest.yanked {
        markdown.push_str("⚠️ **Warning**: This version has been yanked\n\n");
    }

    // Show version list
    markdown.push_str("**Versions** *(use Cmd+. to update)*:\n");
    for (i, version) in versions.iter().take(8).enumerate() {
        if i == 0 {
            markdown.push_str(&format!("- {} *(latest)*\n", version.version));
        } else {
            markdown.push_str(&format!("- {}\n", version.version));
        }
    }
    if versions.len() > 8 {
        markdown.push_str(&format!("- *...and {} more*\n", versions.len() - 8));
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(pypi_dep.name_range),
    })
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
