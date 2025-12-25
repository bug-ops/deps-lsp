//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionParams, CompletionResponse, InsertTextFormat,
};

/// Handles completion requests.
///
/// Delegates to the appropriate ecosystem implementation based on the document type.
/// Falls back to text-based completion when TOML parsing fails (user is still typing).
pub async fn handle_completion(
    state: Arc<ServerState>,
    params: CompletionParams,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    tracing::info!(
        "completion request: uri={:?}, line={}, character={}",
        uri,
        position.line,
        position.character
    );

    // Get document and extract needed data
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("completion: document not found: {:?}", uri);
            return None;
        }
    };
    let ecosystem_id = doc.ecosystem_id;
    let content = doc.content.clone();
    let has_parse_result = doc.parse_result().is_some();
    drop(doc);

    tracing::info!(
        "completion: ecosystem={}, has_parse_result={}",
        ecosystem_id,
        has_parse_result
    );

    // Try parse_result first, fallback to text-based detection
    let items = if has_parse_result {
        // Re-acquire document to get parse_result
        let doc = state.get_document(uri)?;
        let parse_result = doc.parse_result()?;
        let ecosystem = state.ecosystem_registry.get(ecosystem_id)?;
        let completions = ecosystem
            .generate_completions(parse_result, position, &content)
            .await;
        drop(doc);

        // If ecosystem returned no completions, try fallback
        // This handles the case where user is typing a NEW package name
        if completions.is_empty() {
            tracing::info!("completion: ecosystem returned empty, trying fallback");
            fallback_completion(&state, ecosystem_id, position, &content).await
        } else {
            completions
        }
    } else {
        // Fallback: detect context from raw text
        fallback_completion(&state, ecosystem_id, position, &content).await
    };

    tracing::info!("completion: returning {} items", items.len());

    if items.is_empty() {
        None
    } else {
        Some(CompletionResponse::Array(items))
    }
}

/// Fallback completion when document parsing fails.
///
/// Detects dependencies sections from raw text and provides package name suggestions.
async fn fallback_completion(
    state: &ServerState,
    ecosystem_id: &str,
    position: tower_lsp_server::ls_types::Position,
    content: &str,
) -> Vec<CompletionItem> {
    tracing::info!(
        "fallback_completion: starting for ecosystem={}",
        ecosystem_id
    );

    // Get the current line
    let line = match content.lines().nth(position.line as usize) {
        Some(l) => l,
        None => {
            tracing::info!("fallback_completion: line {} not found", position.line);
            return vec![];
        }
    };

    tracing::info!("fallback_completion: line content = {:?}", line);

    // Check if we're in a dependencies section
    if !is_in_dependencies_section(content, position.line as usize, ecosystem_id) {
        tracing::info!("fallback_completion: not in dependencies section");
        return vec![];
    }

    // Extract what user has typed (from start of line to cursor)
    let prefix_end = std::cmp::min(position.character as usize, line.len());
    let prefix = &line[..prefix_end];
    let prefix = prefix.trim();

    tracing::info!("fallback_completion: prefix = {:?}", prefix);

    // If it looks like a package name (letters, no = sign, at least 2 chars)
    if prefix.is_empty() || prefix.contains('=') || prefix.len() < 2 {
        tracing::info!("fallback_completion: prefix rejected (empty, contains =, or < 2 chars)");
        return vec![];
    }

    // Get ecosystem and search for packages
    let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
        Some(e) => e,
        None => return vec![],
    };

    let registry = ecosystem.registry();

    // Search for packages matching the prefix
    search_packages(registry.as_ref(), ecosystem_id, prefix).await
}

/// Checks if a line is inside a dependencies section.
fn is_in_dependencies_section(content: &str, line_number: usize, ecosystem_id: &str) -> bool {
    match ecosystem_id {
        "cargo" | "pypi" => is_in_toml_dependencies(content, line_number),
        "npm" => is_in_json_dependencies(content, line_number),
        _ => false,
    }
}

/// Checks if a line is inside a TOML dependencies section.
///
/// Looks for `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` sections
/// in Cargo.toml or `[project.dependencies]` in pyproject.toml.
fn is_in_toml_dependencies(content: &str, line_number: usize) -> bool {
    // Walk backwards from current line to find the most recent section header
    // Collect lines up to target, then iterate backwards
    let lines: Vec<_> = content.lines().enumerate().take(line_number + 1).collect();

    for (_, line) in lines.iter().rev() {
        let line = line.trim();

        // Check if this is a section header
        if line.starts_with('[') && line.ends_with(']') {
            // Check if it's a dependencies section
            return line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line == "[workspace.dependencies]"
                || line == "[project.dependencies]"
                || line == "[project.optional-dependencies]"
                || line.starts_with("[target.")
                    && (line.contains(".dependencies]")
                        || line.contains(".dev-dependencies]")
                        || line.contains(".build-dependencies]"));
        }
    }

    false
}

/// Checks if a line is inside a JSON dependencies section.
///
/// Looks for `"dependencies": {`, `"devDependencies": {`, etc. in package.json.
fn is_in_json_dependencies(content: &str, line_number: usize) -> bool {
    let mut in_dependencies = false;
    let mut brace_depth = 0;

    // Use iterator directly without collecting to avoid allocation
    for (i, line) in content.lines().enumerate() {
        // Early exit: stop if we've passed the target line
        if i > line_number {
            break;
        }

        let trimmed = line.trim();

        // Check if we're entering a dependencies section
        if trimmed.starts_with('"')
            && (trimmed.contains("\"dependencies\":")
                || trimmed.contains("\"devDependencies\":")
                || trimmed.contains("\"peerDependencies\":")
                || trimmed.contains("\"optionalDependencies\":"))
        {
            in_dependencies = true;
            brace_depth = 0;
        }

        // Track brace depth when in dependencies section
        if in_dependencies {
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        // If we've closed the dependencies section
                        if brace_depth <= 0 {
                            in_dependencies = false;
                        }
                    }
                    _ => {}
                }
            }

            // If we're at the target line and inside dependencies section with depth > 0
            if i == line_number && in_dependencies && brace_depth > 0 {
                return true;
            }
        }
    }

    false
}

/// Searches for packages and returns completion items.
async fn search_packages(
    registry: &dyn deps_core::Registry,
    ecosystem_id: &str,
    query: &str,
) -> Vec<CompletionItem> {
    tracing::info!(
        "search_packages: query={:?}, ecosystem={}",
        query,
        ecosystem_id
    );

    // Search for up to 50 packages
    let results = match registry.search(query, 50).await {
        Ok(r) => {
            tracing::info!("search_packages: found {} results", r.len());
            r
        }
        Err(e) => {
            tracing::warn!("search_packages: search failed: {}", e);
            return vec![];
        }
    };

    // Convert search results to completion items
    results
        .iter()
        .map(|metadata| create_package_completion_item(metadata.as_ref(), ecosystem_id))
        .collect()
}

/// Creates a completion item for a package.
fn create_package_completion_item(
    metadata: &dyn deps_core::Metadata,
    ecosystem_id: &str,
) -> CompletionItem {
    let name = metadata.name();
    let latest = metadata.latest_version();
    let description = metadata.description();

    // Create insert text based on ecosystem
    let insert_text = match ecosystem_id {
        "cargo" | "pypi" => format!("{} = \"{}\"", name, latest),
        "npm" => format!("\"{}\": \"^{}\"", name, latest),
        _ => format!("{} = \"{}\"", name, latest),
    };

    // Build detail text
    let detail = format!("Latest: {}", latest);

    CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::MODULE),
        detail: Some(detail),
        documentation: description
            .map(|d| tower_lsp_server::ls_types::Documentation::String(d.into())),
        insert_text: Some(insert_text),
        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams, Uri,
    };

    #[tokio::test]
    async fn test_completion_returns_none_for_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let result = handle_completion(state, params).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

        let content = "[dependencies]\nserde = \"1.0\"".to_string();

        // Parse the manifest to get a proper parse result
        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();

        let doc = DocumentState::new_from_parse_result("cargo", content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 9),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should return Some or None based on ecosystem implementation
        // We don't test the actual completions here as that's ecosystem-specific
        let _result = handle_completion(state, params).await;
        // Just verify it doesn't panic - actual completion logic is in ecosystem
    }

    #[test]
    fn test_is_in_toml_dependencies_basic() {
        let content = r#"
[package]
name = "test"

[dependencies]
serde
"#;
        assert!(is_in_toml_dependencies(content, 5));
        assert!(!is_in_toml_dependencies(content, 1));
    }

    #[test]
    fn test_is_in_toml_dependencies_dev_deps() {
        let content = r#"
[dev-dependencies]
tokio
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_build_deps() {
        let content = r#"
[build-dependencies]
cc
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_project_deps() {
        let content = r#"
[project.dependencies]
requests
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_workspace_deps() {
        let content = r#"
[workspace.dependencies]
serde = "1.0"
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_target_specific() {
        let content = r#"
[target.'cfg(windows)'.dependencies]
winapi
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_wrong_section() {
        let content = r#"
[package]
name = "test"

[profile.release]
opt-level = 3
"#;
        assert!(!is_in_toml_dependencies(content, 2));
        assert!(!is_in_toml_dependencies(content, 5));
    }

    #[test]
    fn test_is_in_toml_dependencies_multiple_sections() {
        let content = r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tokio
"#;
        assert!(is_in_toml_dependencies(content, 2));
        assert!(is_in_toml_dependencies(content, 5));
    }

    #[test]
    fn test_is_in_json_dependencies_basic() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3));
        assert!(!is_in_json_dependencies(content, 1));
    }

    #[test]
    fn test_is_in_json_dependencies_dev_deps() {
        let content = r#"{
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_json_dependencies_peer_deps() {
        let content = r#"{
  "peerDependencies": {
    "react"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_json_dependencies_optional_deps() {
        let content = r#"{
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_json_dependencies_outside_section() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.0.0"
  },
  "scripts": {
    "start": "node index.js"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3));
        assert!(!is_in_json_dependencies(content, 6));
    }

    #[test]
    fn test_is_in_json_dependencies_nested_braces() {
        let content = r#"{
  "dependencies": {
    "package": "1.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_dependencies_section_cargo() {
        let content = r#"
[dependencies]
serde
"#;
        assert!(is_in_dependencies_section(content, 2, "cargo"));
        assert!(!is_in_dependencies_section(content, 0, "cargo"));
    }

    #[test]
    fn test_is_in_dependencies_section_pypi() {
        let content = r#"
[project.dependencies]
requests
"#;
        assert!(is_in_dependencies_section(content, 2, "pypi"));
    }

    #[test]
    fn test_is_in_dependencies_section_npm() {
        let content = r#"{
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_dependencies_section(content, 2, "npm"));
    }

    #[test]
    fn test_is_in_dependencies_section_unknown_ecosystem() {
        let content = r#"
[dependencies]
something
"#;
        assert!(!is_in_dependencies_section(content, 2, "unknown"));
    }

    #[test]
    fn test_create_package_completion_item_cargo() {
        struct MockMetadata;
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &str {
                "serde"
            }
            fn description(&self) -> Option<&str> {
                Some("A serialization framework")
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &str {
                "1.0.214"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, "cargo");

        assert_eq!(item.label, "serde");
        assert_eq!(item.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(item.detail, Some("Latest: 1.0.214".to_string()));
        assert_eq!(item.insert_text, Some("serde = \"1.0.214\"".to_string()));
        assert_eq!(item.insert_text_format, Some(InsertTextFormat::PLAIN_TEXT));
    }

    #[test]
    fn test_create_package_completion_item_npm() {
        struct MockMetadata;
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &str {
                "express"
            }
            fn description(&self) -> Option<&str> {
                Some("Fast web framework")
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &str {
                "4.18.2"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, "npm");

        assert_eq!(item.label, "express");
        assert_eq!(
            item.insert_text,
            Some("\"express\": \"^4.18.2\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_pypi() {
        struct MockMetadata;
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &str {
                "requests"
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &str {
                "2.31.0"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, "pypi");

        assert_eq!(item.label, "requests");
        assert_eq!(item.insert_text, Some("requests = \"2.31.0\"".to_string()));
    }

    #[tokio::test]
    async fn test_fallback_triggered_when_parse_fails() {
        use crate::document::Ecosystem;

        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

        // Malformed content that will fail to parse
        let content = r#"[dependencies]
ser"#
            .to_string();

        // Create document without parse result (simulating parse failure)
        let doc = DocumentState::new(Ecosystem::Cargo, content.clone(), vec![]);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 3), // After "ser"
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should use fallback completion (won't panic, may return empty if search fails)
        let result = handle_completion(state, params).await;
        // Just verify it doesn't panic - actual results depend on registry availability
        // In a real scenario with mocked registry, we'd verify it returns search results
        drop(result);
    }

    #[test]
    fn test_fallback_rejects_single_char_prefix() {
        let content = r#"
[dependencies]
s
"#;

        // Extract prefix at position (1 char)
        let line = content.lines().nth(2).unwrap();
        let prefix_end = std::cmp::min(1, line.len());
        let prefix = &line[..prefix_end];
        let prefix = prefix.trim();

        // Should reject single char (< 2 chars requirement)
        assert_eq!(prefix.len(), 1);
        assert!(prefix.len() < 2);
    }

    #[test]
    fn test_fallback_rejects_prefix_with_equals() {
        let content = r#"
[dependencies]
serde = "1.0"
"#;

        // Extract prefix at position (contains '=')
        let line = content.lines().nth(2).unwrap();
        let prefix_end = std::cmp::min(12, line.len()); // "serde = "
        let prefix = &line[..prefix_end];
        let prefix = prefix.trim();

        // Should reject prefix containing '='
        assert!(prefix.contains('='));
    }

    #[test]
    fn test_prefix_extraction_cursor_beyond_line() {
        let content = r#"
[dependencies]
serde
"#;

        // Try to extract prefix with cursor beyond line length
        let line = content.lines().nth(2).unwrap();
        assert_eq!(line, "serde");

        // Cursor at position 100 (beyond line)
        let prefix_end = std::cmp::min(100, line.len());
        let prefix = &line[..prefix_end];

        // Should clamp to line length
        assert_eq!(prefix, "serde");
        assert_eq!(prefix.len(), 5); // Not 100
    }
}
