//! Completion handler implementation.
//!
//! Provides intelligent completions for:
//! - Package names (from crates.io search)
//! - Version strings (from sparse index)
//! - Feature flags (from crate metadata)
//!
//! TODO: Add npm-specific completion logic for package.json

use crate::document::ServerState;
use deps_cargo::CratesIoRegistry;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionParams, CompletionResponse, Documentation,
    Position,
};

/// Handles completion requests.
///
/// Determines the completion context (package name, version, or feature)
/// and returns appropriate suggestions.
pub async fn handle_completion(
    state: Arc<ServerState>,
    params: CompletionParams,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    let doc = state.get_document(uri)?;
    let context = determine_completion_context(&doc.content, position)?;
    drop(doc);

    match context {
        CompletionContext::PackageName { prefix } => complete_package_names(state, &prefix).await,
        CompletionContext::Version { dep_name } => complete_versions(state, &dep_name).await,
        CompletionContext::Feature { dep_name } => complete_features(state, &dep_name).await,
    }
}

/// Context for completion request.
#[derive(Debug, Clone)]
enum CompletionContext {
    PackageName { prefix: String },
    Version { dep_name: String },
    Feature { dep_name: String },
}

/// Determines what kind of completion is needed based on cursor position.
fn determine_completion_context(content: &str, position: Position) -> Option<CompletionContext> {
    let line = content.lines().nth(position.line as usize)?;
    let before_cursor = &line[..(position.character as usize).min(line.len())];

    if before_cursor.contains('=') && before_cursor.ends_with('"') {
        let dep_name = before_cursor
            .split('=')
            .next()?
            .trim()
            .trim_start_matches('[')
            .trim();

        if before_cursor.contains("features") {
            return Some(CompletionContext::Feature {
                dep_name: dep_name.to_string(),
            });
        }

        return Some(CompletionContext::Version {
            dep_name: dep_name.to_string(),
        });
    }

    if before_cursor
        .trim()
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Some(CompletionContext::PackageName {
            prefix: before_cursor.trim().to_string(),
        });
    }

    None
}

/// Completes package names from crates.io search.
async fn complete_package_names(
    state: Arc<ServerState>,
    prefix: &str,
) -> Option<CompletionResponse> {
    if prefix.len() < 2 {
        return None;
    }

    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));
    let crates = registry.search(prefix, 20).await.ok()?;

    let items: Vec<CompletionItem> = crates
        .into_iter()
        .map(|c| CompletionItem {
            label: c.name.clone(),
            kind: Some(CompletionItemKind::MODULE),
            detail: Some(format!("v{}", c.max_version)),
            documentation: c.description.map(Documentation::String),
            insert_text: Some(format!(r#"{} = "{}""#, c.name, c.max_version)),
            ..Default::default()
        })
        .collect();

    Some(CompletionResponse::Array(items))
}

/// Completes version strings for a specific dependency.
async fn complete_versions(state: Arc<ServerState>, dep_name: &str) -> Option<CompletionResponse> {
    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));
    let versions = registry.get_versions(dep_name).await.ok()?;

    let items: Vec<CompletionItem> = versions
        .into_iter()
        .filter(|v| !v.yanked)
        .take(20)
        .map(|v| CompletionItem {
            label: v.num.clone(),
            kind: Some(CompletionItemKind::VALUE),
            detail: Some("version".into()),
            insert_text: Some(v.num.clone()),
            ..Default::default()
        })
        .collect();

    Some(CompletionResponse::Array(items))
}

/// Completes feature flags for a specific dependency.
async fn complete_features(state: Arc<ServerState>, dep_name: &str) -> Option<CompletionResponse> {
    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let versions = registry.get_versions(dep_name).await.ok()?;
    let latest = versions.first()?;

    let items: Vec<CompletionItem> = latest
        .features
        .keys()
        .map(|f| CompletionItem {
            label: f.clone(),
            kind: Some(CompletionItemKind::PROPERTY),
            detail: Some("feature".into()),
            insert_text: Some(format!(r#""{}""#, f)),
            ..Default::default()
        })
        .collect();

    Some(CompletionResponse::Array(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_completion_context_version() {
        let content = r#"serde = ""#;
        let position = Position::new(0, 9);
        let context = determine_completion_context(content, position);
        assert!(matches!(context, Some(CompletionContext::Version { .. })));
    }

    #[test]
    fn test_determine_completion_context_package_name() {
        let content = "serd";
        let position = Position::new(0, 4);
        let context = determine_completion_context(content, position);
        assert!(matches!(
            context,
            Some(CompletionContext::PackageName { .. })
        ));
    }

    #[test]
    fn test_determine_completion_context_feature() {
        let content = r#"serde = { version = "1.0", features = [""#;
        let position = Position::new(0, 40);
        let context = determine_completion_context(content, position);
        assert!(matches!(context, Some(CompletionContext::Feature { .. })));
    }

    #[test]
    fn test_determine_completion_context_no_match() {
        let content = r#"# comment"#;
        let position = Position::new(0, 5);
        let context = determine_completion_context(content, position);
        assert!(context.is_none());
    }

    #[test]
    fn test_determine_completion_context_version_with_spaces() {
        let content = r#"  serde  =  ""#;
        let position = Position::new(0, 13);
        let context = determine_completion_context(content, position);
        assert!(matches!(context, Some(CompletionContext::Version { .. })));
    }

    #[test]
    fn test_determine_completion_context_short_prefix() {
        let content = "s";
        let position = Position::new(0, 1);
        let context = determine_completion_context(content, position);
        if let Some(CompletionContext::PackageName { prefix }) = context {
            assert_eq!(prefix, "s");
        } else {
            panic!("Expected PackageName context");
        }
    }

    #[test]
    fn test_determine_completion_context_hyphenated_name() {
        let content = "tokio-util";
        let position = Position::new(0, 10);
        let context = determine_completion_context(content, position);
        assert!(matches!(
            context,
            Some(CompletionContext::PackageName { .. })
        ));
    }

    #[test]
    fn test_determine_completion_context_underscored_name() {
        let content = "tower_lsp";
        let position = Position::new(0, 9);
        let context = determine_completion_context(content, position);
        assert!(matches!(
            context,
            Some(CompletionContext::PackageName { .. })
        ));
    }

    #[test]
    fn test_determine_completion_context_multiline_version() {
        let content = "[dependencies]\nserde = \"";
        let position = Position::new(1, 9);
        let context = determine_completion_context(content, position);
        assert!(matches!(context, Some(CompletionContext::Version { .. })));
    }

    #[test]
    fn test_determine_completion_context_table_syntax() {
        let content = r#"[dependencies.serde]
version = ""#;
        let position = Position::new(1, 11);
        let context = determine_completion_context(content, position);
        assert!(matches!(context, Some(CompletionContext::Version { .. })));
    }
}
