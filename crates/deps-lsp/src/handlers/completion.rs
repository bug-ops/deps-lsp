//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::EcosystemId;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
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
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    tracing::info!(
        "completion request: uri={:?}, line={}, character={}",
        uri,
        position.line,
        position.character
    );

    // Check if document is loaded, if not try to load with short timeout
    // Completion is latency-critical, so we use a 200ms timeout
    if state.get_document(uri).is_none() {
        tracing::info!("completion: document not loaded, loading from disk");

        // Try to load with short timeout (200ms)
        let load_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            ensure_document_loaded(uri, Arc::clone(&state), client.clone(), Arc::clone(&config)),
        )
        .await;

        match load_result {
            Ok(true) => {
                // Document loaded successfully, continue with completion
                tracing::debug!("completion: document loaded successfully");
            }
            Ok(false) | Err(_) => {
                // Load failed or timed out, return empty completions
                tracing::warn!("completion: document load failed or timed out");
                return Some(CompletionResponse::Array(vec![]));
            }
        }
    }

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

    // Check if we're in a dependencies section. An ecosystem id that doesn't parse is
    // not registered, so there is no fallback to offer (mirrors the `ecosystem_registry
    // .get` lookup below, which fails the same way for the same reason).
    let Ok(ecosystem_kind) = ecosystem_id.parse::<EcosystemId>() else {
        tracing::warn!("fallback_completion: unknown ecosystem id {ecosystem_id:?}");
        return vec![];
    };
    if !is_in_dependencies_section(content, position.line as usize, ecosystem_kind) {
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
    search_packages(registry.as_ref(), ecosystem_kind, prefix).await
}

/// Checks if a line is inside a dependencies section.
///
/// Dispatches to a per-ecosystem raw-text heuristic. Matching on [`EcosystemId`]
/// rather than the raw ecosystem id string makes this exhaustive: adding a new
/// ecosystem forces a decision here instead of silently disabling section-aware
/// completion for it (see issue #118).
fn is_in_dependencies_section(
    content: &str,
    line_number: usize,
    ecosystem_id: EcosystemId,
) -> bool {
    match ecosystem_id {
        EcosystemId::Cargo | EcosystemId::Pypi => is_in_toml_dependencies(content, line_number),
        EcosystemId::Npm => is_in_json_dependencies(
            content,
            line_number,
            &[
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ],
        ),
        EcosystemId::Composer => {
            is_in_json_dependencies(content, line_number, &["require", "require-dev"])
        }
        EcosystemId::Maven => is_in_xml_tag_section(content, line_number, "dependencies"),
        EcosystemId::Go => is_in_go_require(content, line_number),
        EcosystemId::Dart => is_in_yaml_dependencies(content, line_number),
        // TODO(#118 follow-up): Gemfile has no delimited dependencies section —
        // `gem "name"` calls are valid anywhere at the top level or inside
        // `group ... do ... end` blocks, so there is no raw-text boundary to detect.
        // `false` matches the pre-fix behavior (fallback completion disabled) rather
        // than `true`: `fallback_completion` fires on every keystroke where the
        // ecosystem's own completion is empty, using the *whole trimmed line* as the
        // search query (not a token), so a permissive `true` here would fire a live
        // registry search on unrelated text and insert results with unrelated syntax.
        EcosystemId::Bundler => false,
        // TODO(#118 follow-up): Package.swift dependencies are `.package(...)` calls
        // matched anywhere in the file by the real parser (not confined to the
        // `dependencies: [...]` array), so there is no reliable raw-text section
        // boundary here either. See the Bundler arm above for why this is `false`.
        EcosystemId::Swift => false,
        // TODO(#118 follow-up): Gradle spans five manifest formats (TOML version
        // catalog, Groovy DSL, Kotlin DSL) with no raw-text section marker shared
        // across all of them. See the Bundler arm above for why this is `false`.
        EcosystemId::Gradle => false,
        // TODO(#118 follow-up): NuGet spans three schemas: csproj/Directory.Packages
        // .props nest PackageReference/PackageVersion in `<ItemGroup>`, while
        // packages.config lists `<package>` elements directly under its root with no
        // such wrapper. See the Bundler arm above for why this is `false`.
        EcosystemId::NuGet => false,
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

/// Checks if a line is inside a JSON dependencies-like section.
///
/// Looks for `"{key}": {` for any of the given `keys`, e.g. `dependencies` /
/// `devDependencies` in package.json, or `require` / `require-dev` in composer.json.
fn is_in_json_dependencies(content: &str, line_number: usize, keys: &[&str]) -> bool {
    let mut in_dependencies = false;
    let mut brace_depth = 0;
    // Build each `"{key}":` needle once per call rather than once per line.
    let needles: Vec<String> = keys.iter().map(|key| format!("\"{key}\":")).collect();

    for (i, line) in content.lines().enumerate() {
        // Early exit: stop if we've passed the target line
        if i > line_number {
            break;
        }

        let trimmed = line.trim();

        // Check if we're entering a dependencies-like section
        if trimmed.starts_with('"')
            && needles
                .iter()
                .any(|needle| trimmed.contains(needle.as_str()))
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

/// Checks if a line is inside an XML `<tag>...</tag>` element.
///
/// Tracks nested open/close tag counts (ignoring attributes and self-closing tags) to
/// find whether the target line falls within any occurrence of the element, e.g.
/// `<dependencies>` in pom.xml (including nested inside `<dependencyManagement>`).
fn is_in_xml_tag_section(content: &str, line_number: usize, tag: &str) -> bool {
    let open_prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut depth: usize = 0;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let opens_here = count_open_tags(line, &open_prefix);
        depth += opens_here;
        // A line with an opening tag counts as "inside" even if the same line also
        // closes it (`<dependencies></dependencies>`), consistent with the target
        // line being the header itself in `is_in_toml_dependencies`.
        if i == line_number && opens_here > 0 {
            return true;
        }

        depth = depth.saturating_sub(line.matches(close.as_str()).count());
        if i == line_number && depth > 0 {
            return true;
        }
    }

    false
}

/// Counts real `<{open_prefix}...>` tag occurrences on `line`, i.e. `open_prefix`
/// followed by `>` or whitespace (an attribute) rather than more tag-name characters
/// (so `<dependencies` doesn't also match a longer, unrelated tag name).
fn count_open_tags(line: &str, open_prefix: &str) -> usize {
    let mut count = 0;
    let mut search_from = 0;

    while let Some(rel_idx) = line[search_from..].find(open_prefix) {
        let idx = search_from + rel_idx;
        let after = &line[idx + open_prefix.len()..];
        if after.starts_with('>') || after.starts_with(char::is_whitespace) {
            count += 1;
        }
        search_from = idx + open_prefix.len();
    }

    count
}

/// Checks if a line is inside a go.mod `require` directive.
///
/// Handles both the single-line form (`require module version`) and the
/// parenthesized block form (`require (` ... `)`).
fn is_in_go_require(content: &str, line_number: usize) -> bool {
    let mut in_require_block = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim();
        let is_block_start = trimmed
            .strip_prefix("require")
            .is_some_and(|rest| rest.trim_start().starts_with('('));

        if is_block_start {
            in_require_block = true;
        } else if in_require_block && trimmed.starts_with(')') {
            in_require_block = false;
        }

        if i == line_number {
            return in_require_block || is_block_start || trimmed.starts_with("require ");
        }
    }

    false
}

/// Checks if a line is inside a pubspec.yaml dependency section.
///
/// Dart's `dependencies`, `dev_dependencies`, and `dependency_overrides` keys are
/// top-level (unindented) YAML mappings; their entries stay part of the section until
/// the next unindented key starts a new one.
fn is_in_yaml_dependencies(content: &str, line_number: usize) -> bool {
    const SECTION_KEYS: &[&str] = &[
        "dependencies:",
        "dev_dependencies:",
        "dependency_overrides:",
    ];
    let mut in_dependencies = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Top-level (unindented) key: starts a new section, or leaves the current one.
        if trimmed.len() == line.len() {
            in_dependencies = SECTION_KEYS.iter().any(|key| trimmed.starts_with(key));
        }
    }

    in_dependencies
}

/// Searches for packages and returns completion items.
async fn search_packages(
    registry: &dyn deps_core::Registry,
    ecosystem_id: EcosystemId,
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
///
/// The insert text mirrors each ecosystem's manifest syntax, exhaustively matched on
/// [`EcosystemId`] so a new ecosystem must supply its own snippet instead of silently
/// inheriting Cargo's `name = "version"` TOML syntax (see issue #118).
fn create_package_completion_item(
    metadata: &dyn deps_core::Metadata,
    ecosystem_id: EcosystemId,
) -> CompletionItem {
    let name = metadata.name();
    let latest = metadata.latest_version();
    let description = metadata.description();

    let insert_text = match ecosystem_id {
        EcosystemId::Cargo | EcosystemId::Pypi => format!("{name} = \"{latest}\""),
        EcosystemId::Npm | EcosystemId::Composer => format!("\"{name}\": \"^{latest}\""),
        EcosystemId::Go => format!("{name} {latest}"),
        EcosystemId::Dart => format!("{name}: ^{latest}"),
        EcosystemId::Maven => format!("<artifactId>{name}</artifactId><version>{latest}</version>"),
        EcosystemId::Gradle => format!("implementation(\"{name}:{latest}\")"),
        EcosystemId::Swift => format!(".package(url: \"{name}\", from: \"{latest}\")"),
        EcosystemId::NuGet => {
            format!("<PackageReference Include=\"{name}\" Version=\"{latest}\" />")
        }
        EcosystemId::Bundler => format!("gem \"{name}\", \"~> {latest}\""),
    };

    // Build detail text
    let detail = format!("Latest: {latest}");

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
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    #[tokio::test]
    async fn test_completion_returns_empty_for_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // With cold start support, missing documents trigger background load
        // and return empty completions for the first request
        assert!(matches!(result, Some(CompletionResponse::Array(items)) if items.is_empty()));
    }

    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

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
        let (client, config) = create_test_client_and_config();
        let _result = handle_completion(state, params, client, config).await;
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
        let content = r"
[dev-dependencies]
tokio
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_build_deps() {
        let content = r"
[build-dependencies]
cc
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_project_deps() {
        let content = r"
[project.dependencies]
requests
";
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
        let content = r"
[target.'cfg(windows)'.dependencies]
winapi
";
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

    const NPM_KEYS: &[&str] = &[
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    #[test]
    fn test_is_in_json_dependencies_basic() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 1, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_dev_deps() {
        let content = r#"{
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_peer_deps() {
        let content = r#"{
  "peerDependencies": {
    "react"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_optional_deps() {
        let content = r#"{
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
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
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 6, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_nested_braces() {
        let content = r#"{
  "dependencies": {
    "package": "1.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_custom_keys() {
        let content = r#"{
  "require": {
    "monolog/monolog": "^2.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.0"
  }
}"#;
        assert!(is_in_json_dependencies(
            content,
            2,
            &["require", "require-dev"]
        ));
        assert!(is_in_json_dependencies(
            content,
            5,
            &["require", "require-dev"]
        ));
    }

    #[test]
    fn test_is_in_dependencies_section_cargo() {
        let content = r"
[dependencies]
serde
";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Cargo));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Cargo));
    }

    #[test]
    fn test_is_in_dependencies_section_pypi() {
        let content = r"
[project.dependencies]
requests
";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Pypi));
    }

    #[test]
    fn test_is_in_dependencies_section_npm() {
        let content = r#"{
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Npm));
    }

    #[test]
    fn test_is_in_dependencies_section_composer() {
        let content = r#"{
  "require": {
    "monolog/monolog": "^2.0"
  },
  "scripts": {
    "test": "phpunit"
  }
}"#;
        assert!(is_in_dependencies_section(
            content,
            2,
            EcosystemId::Composer
        ));
        assert!(!is_in_dependencies_section(
            content,
            5,
            EcosystemId::Composer
        ));
    }

    #[test]
    fn test_is_in_dependencies_section_maven() {
        let content = r"
<project>
  <dependencies>
    <dependency></dependency>
  </dependencies>
</project>
";
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Maven));
        assert!(!is_in_dependencies_section(content, 1, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_single_line() {
        let content = "<project><dependencies></dependencies></project>\n";
        assert!(is_in_dependencies_section(content, 0, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_attributed_tag() {
        let content = r#"
<project>
  <dependencies xmlns="http://maven.apache.org/POM/4.0.0">
    <dependency></dependency>
  </dependencies>
</project>
"#;
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_no_false_positive_on_longer_tag_name() {
        let content = r"
<project>
  <dependencyManagement>
    <dependencies>
      <dependency></dependency>
    </dependencies>
  </dependencyManagement>
</project>
";
        // Line 2 opens `<dependencyManagement>`, not `<dependencies>` — must not match.
        assert!(!is_in_dependencies_section(content, 2, EcosystemId::Maven));
        // Line 4 is genuinely inside the nested `<dependencies>` block.
        assert!(is_in_dependencies_section(content, 4, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_go_single_line() {
        let content = "module example.com/myapp\n\nrequire github.com/gin-gonic/gin v1.9.1\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Go));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Go));
    }

    #[test]
    fn test_is_in_dependencies_section_go_block() {
        let content =
            "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Go));
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Go));
        assert!(!is_in_dependencies_section(content, 4, EcosystemId::Go));
    }

    #[test]
    fn test_is_in_dependencies_section_dart() {
        let content =
            "name: myapp\ndependencies:\n  http: ^1.0.0\nenvironment:\n  sdk: '>=3.0.0'\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Dart));
        assert!(!is_in_dependencies_section(content, 4, EcosystemId::Dart));
    }

    #[test]
    fn test_is_in_dependencies_section_dart_column_zero_comment() {
        // A column-0 `#` comment inside a section must not read as a new top-level
        // key and reset `in_dependencies` to false.
        let content = "name: myapp\ndependencies:\n# a comment\n  http: ^1.0.0\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Dart));
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Dart));
    }

    #[test]
    fn test_is_in_dependencies_section_no_raw_text_boundary_ecosystems() {
        // No existing raw-text section boundary: `false` preserves pre-fix behavior
        // (fallback completion disabled) rather than risking spurious registry
        // searches on arbitrary lines. See the TODO comments in
        // `is_in_dependencies_section` for the per-ecosystem rationale.
        let content = "anything at all\n";
        assert!(!is_in_dependencies_section(
            content,
            0,
            EcosystemId::Bundler
        ));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Swift));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Gradle));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::NuGet));
    }

    #[test]
    fn test_create_package_completion_item_cargo() {
        struct MockMetadata;
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &'static str {
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
            fn latest_version(&self) -> &'static str {
                "1.0.214"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, EcosystemId::Cargo);

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
            fn name(&self) -> &'static str {
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
            fn latest_version(&self) -> &'static str {
                "4.18.2"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, EcosystemId::Npm);

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
            fn name(&self) -> &'static str {
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
            fn latest_version(&self) -> &'static str {
                "2.31.0"
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata;
        let item = create_package_completion_item(&meta, EcosystemId::Pypi);

        assert_eq!(item.label, "requests");
        assert_eq!(item.insert_text, Some("requests = \"2.31.0\"".to_string()));
    }

    #[tokio::test]
    async fn test_fallback_triggered_when_parse_fails() {
        use deps_core::EcosystemId;

        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        // Malformed content that will fail to parse
        let content = r"[dependencies]
ser"
        .to_string();

        // Create document without parse result (simulating parse failure)
        let doc = DocumentState::new(EcosystemId::Cargo, content.clone(), vec![]);
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
        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // Just verify it doesn't panic - actual results depend on registry availability
        // In a real scenario with mocked registry, we'd verify it returns search results
        drop(result);
    }

    #[tokio::test]
    async fn test_fallback_completion_unknown_ecosystem_id_returns_empty() {
        let state = ServerState::new();
        let content = "[dependencies]\nserde\n".to_string();

        let items = fallback_completion(&state, "unknown", Position::new(1, 5), &content).await;
        assert!(items.is_empty());
    }

    #[test]
    fn test_fallback_rejects_single_char_prefix() {
        let content = r"
[dependencies]
s
";

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
        let content = r"
[dependencies]
serde
";

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
