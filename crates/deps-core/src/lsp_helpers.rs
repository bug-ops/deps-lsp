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
        let req_normalized = requirement
            .strip_prefix('^')
            .or_else(|| requirement.strip_prefix('~'))
            .unwrap_or(requirement);

        let req_parts: Vec<&str> = req_normalized.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;

        version == requirement
            || (is_partial_version && is_same_major_minor(req_normalized, version))
            || (is_partial_version && version.starts_with(req_normalized))
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

        let (is_up_to_date, display_version) = match (resolved_version, latest_version) {
            (Some(resolved), Some(latest)) => {
                // Always compare against absolute latest, not just major.minor match
                // This ensures exact versions like =2.0.12 show ❌ when 2.1.1 is available
                let is_same = resolved == latest;
                (is_same, Some(latest.as_str()))
            }
            (None, Some(latest)) => {
                let version_req = dep.version_requirement().unwrap_or("");
                // When no resolved version, check if requirement would match latest
                let is_match = formatter.version_satisfies_requirement(latest, version_req);
                (is_match, Some(latest.as_str()))
            }
            (Some(resolved), None) => (true, Some(resolved.as_str())),
            (None, None) => continue,
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
            let version = display_version.unwrap_or("unknown");
            config.needs_update_text.replace("{}", version)
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

    for (i, version) in versions
        .iter()
        .filter(|v| !v.is_yanked())
        .take(5)
        .enumerate()
    {
        let new_text = formatter.format_version_for_code_action(version.version_string());

        let mut edits = HashMap::new();
        edits.insert(
            uri.clone(),
            vec![TextEdit {
                range: version_range,
                new_text,
            }],
        );

        let title = if i == 0 {
            format!(
                "Update {} to {} (latest)",
                dep.name(),
                version.version_string()
            )
        } else {
            format!("Update {} to {}", dep.name(), version.version_string())
        };

        actions.push(CodeAction {
            title,
            kind: Some(CodeActionKind::REFACTOR),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            is_preferred: Some(i == 0),
            ..Default::default()
        });
    }

    actions
}

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
                assert_eq!(
                    text, "✅",
                    "Expected up-to-date hint, not loading hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }
}
