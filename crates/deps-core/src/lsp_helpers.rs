//! Shared LSP response builders.

use std::collections::HashMap;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, Diagnostic, DiagnosticSeverity, Hover, HoverContents, InlayHint,
    InlayHintKind, InlayHintLabel, InlayHintTooltip, MarkupContent, MarkupKind, Position, Range,
    TextEdit, Uri, WorkspaceEdit,
};

use crate::{Dependency, EcosystemConfig, ParseResult, Registry};

/// Checks if a position overlaps with a range (inclusive start, exclusive end).
pub fn ranges_overlap(range: Range, position: Position) -> bool {
    !(range.end.line < position.line
        || (range.end.line == position.line && range.end.character <= position.character)
        || position.line < range.start.line
        || (position.line == range.start.line && position.character < range.start.character))
}

/// Checks if two version strings have the same major and minor version.
pub fn is_same_major_minor(v1: &str, v2: &str) -> bool {
    if v1.is_empty() || v2.is_empty() {
        return false;
    }

    let mut parts1 = v1.split('.');
    let mut parts2 = v2.split('.');

    if parts1.next() != parts2.next() {
        return false;
    }

    match (parts1.next(), parts2.next()) {
        (Some(m1), Some(m2)) => m1 == m2,
        _ => true,
    }
}

/// Ecosystem-specific formatting and comparison logic.
pub trait EcosystemFormatter: Send + Sync {
    /// Normalize package name for lookup (default: identity).
    fn normalize_package_name(&self, name: &str) -> String {
        name.to_string()
    }

    /// Format version string for code action text edit.
    fn format_version_for_code_action(&self, version: &str) -> String;

    /// Check if a version satisfies a requirement string.
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // Handle caret (^) - allows changes that don't modify left-most non-zero
        // ^2.0 allows 2.x.x, ^0.2 allows 0.2.x, ^0.0.3 allows only 0.0.3
        if let Some(req) = requirement.strip_prefix('^') {
            let req_parts: Vec<&str> = req.split('.').collect();
            let ver_parts: Vec<&str> = version.split('.').collect();

            // Must have same major version
            if req_parts.first() != ver_parts.first() {
                return false;
            }

            // For ^X.Y where X > 0, any X.*.* is allowed
            if req_parts.first().is_some_and(|m| *m != "0") {
                return true;
            }

            // For ^0.Y, must have same minor
            if req_parts.len() >= 2 && ver_parts.len() >= 2 {
                return req_parts[1] == ver_parts[1];
            }

            return true;
        }

        // Handle tilde (~) - allows patch-level changes
        // ~2.0 allows 2.0.x, ~2.0.1 allows 2.0.x where x >= 1
        if let Some(req) = requirement.strip_prefix('~') {
            return is_same_major_minor(req, version);
        }

        // Plain version or partial version
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;

        version == requirement
            || (is_partial_version && is_same_major_minor(requirement, version))
            || (is_partial_version && version.starts_with(requirement))
    }

    /// Get package URL for hover markdown.
    fn package_url(&self, name: &str) -> String;

    /// Message for yanked/deprecated versions in diagnostics.
    fn yanked_message(&self) -> &'static str {
        "This version has been yanked"
    }

    /// Label for yanked versions in hover.
    fn yanked_label(&self) -> &'static str {
        "*(yanked)*"
    }

    /// Detect if cursor position is on a dependency for code actions.
    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        dep.version_range()
            .is_some_and(|r| ranges_overlap(r, position))
    }
}

pub fn generate_inlay_hints(
    parse_result: &dyn ParseResult,
    cached_versions: &HashMap<String, String>,
    resolved_versions: &HashMap<String, String>,
    loading_state: crate::LoadingState,
    config: &EcosystemConfig,
    formatter: &dyn EcosystemFormatter,
) -> Vec<InlayHint> {
    let deps = parse_result.dependencies();
    let mut hints = Vec::with_capacity(deps.len());

    for dep in deps {
        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let normalized_name = formatter.normalize_package_name(dep.name());
        let latest_version = cached_versions
            .get(&normalized_name)
            .or_else(|| cached_versions.get(dep.name()));
        let resolved_version = resolved_versions
            .get(&normalized_name)
            .or_else(|| resolved_versions.get(dep.name()));

        // Show loading hint if loading and no cached version
        if loading_state == crate::LoadingState::Loading
            && config.show_loading_hints
            && latest_version.is_none()
        {
            hints.push(InlayHint {
                position: version_range.end,
                label: InlayHintLabel::String(config.loading_text.clone()),
                kind: Some(InlayHintKind::TYPE),
                tooltip: Some(InlayHintTooltip::String(
                    "Fetching latest version...".to_string(),
                )),
                padding_left: Some(true),
                padding_right: None,
                text_edits: None,
                data: None,
            });
            continue;
        }

        let Some(latest) = latest_version else {
            if let Some(resolved) = resolved_version
                && config.show_up_to_date_hints
            {
                hints.push(InlayHint {
                    position: version_range.end,
                    label: InlayHintLabel::String(format!(
                        "{} {}",
                        config.up_to_date_text, resolved
                    )),
                    kind: Some(InlayHintKind::TYPE),
                    padding_left: Some(true),
                    padding_right: None,
                    text_edits: None,
                    tooltip: None,
                    data: None,
                });
            }
            continue;
        };

        // Two-tier check for up-to-date status:
        // 1. If lock file has the dep, check if resolved == latest
        // 2. If NOT in lock file, check if version requirement is satisfied by latest
        let is_up_to_date = if let Some(resolved) = resolved_version {
            resolved.as_str() == latest.as_str()
        } else {
            let version_req = dep.version_requirement().unwrap_or("");
            formatter.version_satisfies_requirement(latest, version_req)
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
            config.needs_update_text.replace("{}", latest)
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

pub async fn generate_hover<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    cached_versions: &HashMap<String, String>,
    resolved_versions: &HashMap<String, String>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Option<Hover> {
    use std::fmt::Write;

    let dep = parse_result.dependencies().into_iter().find(|d| {
        let on_name = ranges_overlap(d.name_range(), position);
        let on_version = d
            .version_range()
            .is_some_and(|r| ranges_overlap(r, position));
        on_name || on_version
    })?;

    let versions = registry.get_versions(dep.name()).await.ok()?;

    let url = formatter.package_url(dep.name());

    // Pre-allocate with estimated capacity to reduce allocations
    let mut markdown = String::with_capacity(512);
    write!(&mut markdown, "# [{}]({})\n\n", dep.name(), url).unwrap();

    let normalized_name = formatter.normalize_package_name(dep.name());

    let resolved = resolved_versions
        .get(&normalized_name)
        .or_else(|| resolved_versions.get(dep.name()));
    if let Some(resolved_ver) = resolved {
        write!(&mut markdown, "**Current**: `{}`\n\n", resolved_ver).unwrap();
    } else if let Some(version_req) = dep.version_requirement() {
        write!(&mut markdown, "**Requirement**: `{}`\n\n", version_req).unwrap();
    }

    let latest = cached_versions
        .get(&normalized_name)
        .or_else(|| cached_versions.get(dep.name()));
    if let Some(latest_ver) = latest {
        write!(&mut markdown, "**Latest**: `{}`\n\n", latest_ver).unwrap();
    }

    markdown.push_str("**Recent versions**:\n");
    for (i, version) in versions.iter().take(8).enumerate() {
        if i == 0 {
            writeln!(&mut markdown, "- {} *(latest)*", version.version_string()).unwrap();
        } else if version.is_yanked() {
            writeln!(
                &mut markdown,
                "- {} {}",
                version.version_string(),
                formatter.yanked_label()
            )
            .unwrap();
        } else {
            writeln!(&mut markdown, "- {}", version.version_string()).unwrap();
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

pub async fn generate_code_actions<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    uri: &Uri,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Vec<CodeAction> {
    use crate::completion::prepare_version_display_items;

    let deps = parse_result.dependencies();
    let mut actions = Vec::with_capacity(deps.len().min(5));

    let Some(dep) = deps
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position))
    else {
        return actions;
    };

    let Some(version_range) = dep.version_range() else {
        return actions;
    };

    let Ok(versions) = registry.get_versions(dep.name()).await else {
        return actions;
    };

    let display_items = prepare_version_display_items(&versions, dep.name());

    for item in display_items {
        let new_text = formatter.format_version_for_code_action(&item.version);

        let mut edits = HashMap::new();
        edits.insert(
            uri.clone(),
            vec![TextEdit {
                range: version_range,
                new_text,
            }],
        );

        actions.push(CodeAction {
            title: item.label,
            kind: Some(CodeActionKind::REFACTOR),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            is_preferred: Some(item.is_latest),
            ..Default::default()
        });
    }

    actions
}

/// Generates diagnostics using cached versions (no network calls).
///
/// Uses pre-fetched version information from the lifecycle's parallel fetch.
/// This avoids making additional network requests during diagnostic generation.
///
/// # Arguments
///
/// * `parse_result` - Parsed dependencies from manifest
/// * `cached_versions` - Latest versions from registry (name -> latest version)
/// * `resolved_versions` - Resolved versions from lock file (name -> installed version)
/// * `formatter` - Ecosystem-specific formatting and comparison logic
pub fn generate_diagnostics_from_cache(
    parse_result: &dyn ParseResult,
    cached_versions: &HashMap<String, String>,
    resolved_versions: &HashMap<String, String>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        let normalized_name = formatter.normalize_package_name(dep.name());
        let latest_version = cached_versions
            .get(&normalized_name)
            .or_else(|| cached_versions.get(dep.name()));

        let Some(latest) = latest_version else {
            // Skip "unknown" diagnostic if package exists in lock file
            // (registry fetch may have failed due to rate limiting)
            let in_lockfile = resolved_versions.contains_key(&normalized_name)
                || resolved_versions.contains_key(dep.name());
            if !in_lockfile {
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(DiagnosticSeverity::WARNING),
                    message: format!("Unknown package '{}'", dep.name()),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
            continue;
        };

        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let version_req = dep.version_requirement().unwrap_or("");
        let requirement_allows_latest =
            formatter.version_satisfies_requirement(latest, version_req);

        if !requirement_allows_latest {
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(DiagnosticSeverity::HINT),
                message: format!("Newer version available: {}", latest),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
        }
    }

    diagnostics
}

/// Generates diagnostics by fetching from registry (makes network calls).
///
/// **Warning**: This function makes network requests for each dependency.
/// Prefer `generate_diagnostics_from_cache` when cached versions are available.
#[allow(dead_code)]
pub async fn generate_diagnostics<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        let versions = match registry.get_versions(dep.name()).await {
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

        let matching = registry
            .get_latest_matching(dep.name(), version_req)
            .await
            .ok()
            .flatten();

        if let Some(current) = matching {
            if current.is_yanked() {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(DiagnosticSeverity::WARNING),
                    message: formatter.yanked_message().into(),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }

            let latest = crate::registry::find_latest_stable(&versions);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges_overlap_inside() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_at_start() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 10);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_at_end() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 20);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 25);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_different_line_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(4, 15);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_different_line_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(6, 15);
        assert!(!ranges_overlap(range, position));
    }

    #[test]
    fn test_ranges_overlap_multiline() {
        let range = Range::new(Position::new(5, 10), Position::new(7, 5));
        let position = Position::new(6, 0);
        assert!(ranges_overlap(range, position));
    }

    #[test]
    fn test_is_same_major_minor_full_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.9"));
    }

    #[test]
    fn test_is_same_major_minor_exact_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_major_only_match() {
        assert!(is_same_major_minor("1", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_minor() {
        assert!(!is_same_major_minor("1.2.3", "1.3.0"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_major() {
        assert!(!is_same_major_minor("1.2.3", "2.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_empty_strings() {
        assert!(!is_same_major_minor("", ""));
        assert!(!is_same_major_minor("1.2.3", ""));
        assert!(!is_same_major_minor("", "1.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_partial_versions() {
        assert!(is_same_major_minor("1.2", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1.2"));
    }

    struct MockFormatter;

    impl EcosystemFormatter for MockFormatter {
        fn format_version_for_code_action(&self, version: &str) -> String {
            format!("\"{}\"", version)
        }

        fn package_url(&self, name: &str) -> String {
            format!("https://example.com/{}", name)
        }
    }

    #[test]
    fn test_ecosystem_formatter_defaults() {
        let formatter = MockFormatter;
        assert_eq!(formatter.normalize_package_name("test-pkg"), "test-pkg");
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_ecosystem_formatter_version_satisfies() {
        let formatter = MockFormatter;

        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));

        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));

        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
    }

    #[test]
    fn test_ecosystem_formatter_custom_normalize() {
        struct PyPIFormatter;

        impl EcosystemFormatter for PyPIFormatter {
            fn normalize_package_name(&self, name: &str) -> String {
                name.to_lowercase().replace('-', "_")
            }

            fn format_version_for_code_action(&self, version: &str) -> String {
                format!(
                    ">={},<{}",
                    version,
                    version.split('.').next().unwrap_or("0")
                )
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://pypi.org/project/{}", name)
            }
        }

        let formatter = PyPIFormatter;
        assert_eq!(
            formatter.normalize_package_name("Test-Package"),
            "test_package"
        );
        assert_eq!(
            formatter.format_version_for_code_action("1.2.3"),
            ">=1.2.3,<1"
        );
        assert_eq!(
            formatter.package_url("requests"),
            "https://pypi.org/project/requests"
        );
    }

    #[test]
    fn test_inlay_hint_exact_version_shows_update_needed() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".to_string(),
                version_req: "=2.0.12".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "2.0.12".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "❌ 2.1.1");
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_caret_version_up_to_date() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".to_string(),
                version_req: "^2.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "2.1.1".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_loading_hint_shows_when_no_cached_version() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".to_string(),
                version_req: "1.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "⏳", "Expected loading hint");
            }
            _ => panic!("Expected string label"),
        }

        if let Some(InlayHintTooltip::String(tooltip)) = &hints[0].tooltip {
            assert_eq!(tooltip, "Fetching latest version...");
        } else {
            panic!("Expected tooltip");
        }
    }

    #[test]
    fn test_loading_hint_disabled_when_config_false() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: false,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".to_string(),
                version_req: "1.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(
            hints.len(),
            0,
            "Expected no hints when loading hints disabled"
        );
    }

    #[test]
    fn test_caret_version_0x_edge_cases() {
        let formatter = MockFormatter;

        // ^0.2 should only allow 0.2.x
        assert!(formatter.version_satisfies_requirement("0.2.0", "^0.2"));
        assert!(formatter.version_satisfies_requirement("0.2.5", "^0.2"));
        assert!(formatter.version_satisfies_requirement("0.2.99", "^0.2"));

        // ^0.2 should NOT allow 0.3.x or 0.1.x
        assert!(!formatter.version_satisfies_requirement("0.3.0", "^0.2"));
        assert!(!formatter.version_satisfies_requirement("0.1.0", "^0.2"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "^0.2"));

        // ^0.0.3 should only allow 0.0.3 (left-most non-zero is patch)
        assert!(formatter.version_satisfies_requirement("0.0.3", "^0.0.3"));
        assert!(formatter.version_satisfies_requirement("0.0.3", "^0.0"));

        // ^0 should only allow 0.x.y (major is 0)
        assert!(formatter.version_satisfies_requirement("0.0.0", "^0"));
        assert!(formatter.version_satisfies_requirement("0.5.0", "^0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "^0"));
    }

    #[test]
    fn test_caret_version_non_zero_major() {
        let formatter = MockFormatter;

        // ^1.2 allows any 1.x.x
        assert!(formatter.version_satisfies_requirement("1.0.0", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.0", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.9.9", "^1.2"));

        // ^1.2 should NOT allow 2.x.x
        assert!(!formatter.version_satisfies_requirement("2.0.0", "^1.2"));
        assert!(!formatter.version_satisfies_requirement("0.9.0", "^1.2"));
    }

    #[test]
    fn test_loading_hint_not_shown_when_cached_version_exists() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".to_string(),
                version_req: "1.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "1.0.214".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(
                    text, "✅ 1.0.214",
                    "Expected up-to-date hint, not loading hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_generate_diagnostics_from_cache_unknown_package() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "unknown-pkg".to_string(),
                version_req: "1.0.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &formatter,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("unknown-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_outdated_version() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".to_string(),
                version_req: "1.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.0.0".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &formatter,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
        assert!(diagnostics[0].message.contains("Newer version available"));
        assert!(diagnostics[0].message.contains("2.0.0"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_up_to_date() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".to_string(),
                version_req: "^1.0".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &formatter,
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for up-to-date dependency"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_multiple_deps() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "serde".to_string(),
                    version_req: "^1.0".to_string(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                },
                MockDep {
                    name: "tokio".to_string(),
                    version_req: "1.0".to_string(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: Range::new(Position::new(1, 0), Position::new(1, 5)),
                },
                MockDep {
                    name: "unknown".to_string(),
                    version_req: "1.0".to_string(),
                    version_range: Range::new(Position::new(2, 10), Position::new(2, 20)),
                    name_range: Range::new(Position::new(2, 0), Position::new(2, 7)),
                },
            ],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());
        cached_versions.insert("tokio".to_string(), "2.0.0".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            &formatter,
        );

        assert_eq!(diagnostics.len(), 2);

        let has_outdated = diagnostics
            .iter()
            .any(|d| d.message.contains("Newer version"));
        let has_unknown = diagnostics
            .iter()
            .any(|d| d.message.contains("Unknown package"));

        assert!(has_outdated, "Expected outdated version diagnostic");
        assert!(has_unknown, "Expected unknown package diagnostic");
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_but_satisfies_requirement() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".to_string(),
                version_req: "0.5".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".to_string(), "0.5.1".to_string());

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint for satisfied requirement, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_and_outdated() {
        use std::any::Any;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        struct MockParseResult {
            deps: Vec<MockDep>,
            uri: Uri,
        }

        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockDep {
            name: String,
            version_req: String,
            version_range: Range,
            name_range: Range,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &str {
                &self.name
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".to_string(),
                version_req: "0.4".to_string(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: Uri::from_file_path("/test/Cargo.toml").unwrap(),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".to_string(), "0.5.1".to_string());

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            &cached_versions,
            &resolved_versions,
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("❌"),
                    "Expected needs-update hint for unsatisfied requirement, got: {}",
                    text
                );
                assert!(text.contains("0.5.1"), "Expected latest version in hint");
            }
            _ => panic!("Expected string label"),
        }
    }
}
