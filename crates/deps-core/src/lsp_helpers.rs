//! Shared LSP response builders.

use std::collections::HashMap;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, Diagnostic, DiagnosticSeverity, Hover, HoverContents, InlayHint,
    InlayHintKind, InlayHintLabel, InlayHintTooltip, MarkupContent, MarkupKind, Position, Range,
    TextEdit, Uri, WorkspaceEdit,
};

use crate::{Dependency, EcosystemConfig, ParseResult, Registry, VersionReq};

/// Bundles the two per-package version maps (`cached`, `resolved`) that LSP handlers pass
/// together everywhere.
///
/// Grouping them prevents accidentally swapping the two `&HashMap<String, String>`
/// arguments at a call site, since the compiler can no longer typecheck them positionally.
///
/// # Examples
///
/// ```
/// use deps_core::VersionData;
/// use std::collections::HashMap;
///
/// let mut cached = HashMap::new();
/// cached.insert("serde".to_string(), "1.0.214".to_string());
///
/// let mut resolved = HashMap::new();
/// resolved.insert("serde".to_string(), "1.0.200".to_string());
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached.get("serde"), Some(&"1.0.214".to_string()));
/// assert_eq!(versions.resolved.get("serde"), Some(&"1.0.200".to_string()));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest versions known from the registry, keyed by package name.
    pub cached: &'a HashMap<String, String>,
    /// Versions actually resolved in the lock file, keyed by package name.
    pub resolved: &'a HashMap<String, String>,
}

impl<'a> VersionData<'a> {
    /// Creates a new `VersionData` from the cached and resolved version maps.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved);
    /// assert!(versions.cached.is_empty());
    /// ```
    pub fn new(cached: &'a HashMap<String, String>, resolved: &'a HashMap<String, String>) -> Self {
        Self { cached, resolved }
    }
}

/// Checks whether a cursor position falls within an LSP range (inclusive on both ends).
pub fn position_in_range(pos: Position, range: Range) -> bool {
    if pos.line < range.start.line || pos.line > range.end.line {
        return false;
    }
    if pos.line == range.start.line && pos.character < range.start.character {
        return false;
    }
    if pos.line == range.end.line && pos.character > range.end.character {
        return false;
    }
    true
}

/// Converts byte offsets in source text to LSP `Position` values.
///
/// Precomputes line-start byte offsets once, then maps any byte offset to a
/// `(line, character)` position. Characters are counted as UTF-16 code units
/// as required by the LSP specification.
pub struct LineOffsetTable {
    line_starts: Vec<usize>,
}

impl LineOffsetTable {
    /// Builds the table for `content`.
    pub fn new(content: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Converts a byte offset into an LSP `Position`.
    pub fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let offset = offset.min(content.len());
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts[line];
        let character = content[line_start..offset]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();
        Position::new(line as u32, character)
    }
}

/// Escapes Markdown syntax characters so untrusted text cannot break out of the
/// Markdown structure it is embedded in.
///
/// Applied to manifest-controlled text (dependency names) before it is written into
/// hover markdown link labels, and to registry-controlled completion metadata
/// (package name/version, description, repository/documentation URLs) before it is
/// written into completion-item link labels and link destinations. Every ASCII
/// punctuation character is backslash-escaped (CommonMark's full escapable set — not
/// just brackets/parens, which would still leave e.g. `<https://evil.example>`
/// autolinks live), and control characters (including newlines) are replaced with a
/// space so the text cannot terminate the single-line block it is embedded in and
/// splice in new content.
///
/// Backslash-escaping is valid in link destinations as well as regular text, so this
/// also neutralizes `)`/`]` breakout attempts in a `[label](destination)` URL. It does
/// *not* block dangerous URI schemes (e.g. `javascript:`) in a destination — that is a
/// separate concern from breaking out of the surrounding Markdown structure.
///
/// Backslash-escaping does *not* work inside inline code spans (CommonMark §6.1) —
/// use [`markdown_code_span`] for text embedded in `` `...` `` instead.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::escape_markdown;
///
/// assert_eq!(escape_markdown("pkg](evil)[pkg"), r"pkg\]\(evil\)\[pkg");
/// assert_eq!(escape_markdown("a\nb"), "a b");
/// ```
pub fn escape_markdown(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            escaped.push(' ');
            continue;
        }
        if c.is_ascii_punctuation() {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Wraps `content` in a Markdown inline code span (backticks included) that safely
/// contains arbitrary untrusted text, regardless of embedded backticks.
///
/// Backslash-escaping does not work inside code spans (CommonMark §6.1), so instead
/// this fences with one more backtick than the longest run found in `content`, and
/// pads with a single space on each side when `content` starts or ends with a
/// backtick or space (required by CommonMark to keep the fence unambiguous). Control
/// characters (including newlines) are replaced with a space first, since the raw
/// hover string is otherwise free to merge into an adjacent Markdown block.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::markdown_code_span;
///
/// assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
/// assert_eq!(markdown_code_span("a`b"), "``a`b``");
/// ```
pub fn markdown_code_span(content: &str) -> String {
    let sanitized: String = content
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    let max_backtick_run = sanitized
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(max_backtick_run + 1);

    if sanitized.is_empty() {
        format!("{fence} {fence}")
    } else if sanitized.starts_with(['`', ' ']) || sanitized.ends_with(['`', ' ']) {
        format!("{fence} {sanitized} {fence}")
    } else {
        format!("{fence}{sanitized}{fence}")
    }
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
    fn format_version_for_text_edit(&self, version: &str) -> String;

    /// Check if a version satisfies a requirement string.
    ///
    /// General constraint check (e.g. for completion/candidate filtering) — not the
    /// "is this dependency up to date" hook. That is `is_requirement_up_to_date` below,
    /// which has its own default and its own override points; an ecosystem whose bare
    /// requirement is a floor rather than an auto-following range (see `deps-nuget`)
    /// overrides that method, not this one.
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

    /// Whether an unresolved dependency (no lock-file version) should be reported as
    /// up to date against `latest`, given its declared `requirement`.
    ///
    /// Default: `latest` satisfies `requirement` — correct for range-based ecosystems
    /// (Cargo's `^1.2`, npm's `~1.2`, ...) where the declared requirement already
    /// expresses forward compatibility, so a `latest` it accepts is not "newer" in any
    /// actionable sense. Ecosystems where a bare requirement is a minimum floor rather
    /// than an auto-following range (NuGet's bare `Version="1.0.0"`) must override this,
    /// since "does the floor accept `latest`" and "is the pin already `latest`" are
    /// different questions there.
    fn is_requirement_up_to_date(&self, requirement: &str, latest: &str) -> bool {
        self.version_satisfies_requirement(latest, requirement)
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
            .is_some_and(|r| position_in_range(position, r))
    }
}

pub fn generate_inlay_hints(
    parse_result: &dyn ParseResult,
    versions: VersionData<'_>,
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

        let normalized_name = formatter.normalize_package_name(dep.name().as_str());
        let latest_version = versions
            .cached
            .get(&normalized_name)
            .or_else(|| versions.cached.get(dep.name().as_str()));
        let resolved_version = versions
            .resolved
            .get(&normalized_name)
            .or_else(|| versions.resolved.get(dep.name().as_str()));

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
            let version_req = dep.version_requirement().map_or("", VersionReq::as_str);
            formatter.is_requirement_up_to_date(version_req, latest)
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
    versions: VersionData<'_>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Option<Hover> {
    use std::fmt::Write;

    let dep = parse_result.dependencies().into_iter().find(|d| {
        let on_name = position_in_range(position, d.name_range());
        let on_version = d
            .version_range()
            .is_some_and(|r| position_in_range(position, r));
        on_name || on_version
    })?;

    let available_versions = registry.get_versions(dep.name().as_str()).await.ok()?;

    let url = formatter.package_url(dep.name().as_str());

    // Pre-allocate with estimated capacity to reduce allocations
    let mut markdown = String::with_capacity(512);
    write!(
        &mut markdown,
        "# [{}]({})\n\n",
        escape_markdown(dep.name().as_str()),
        url
    )
    .unwrap();

    let normalized_name = formatter.normalize_package_name(dep.name().as_str());

    let resolved = versions
        .resolved
        .get(&normalized_name)
        .or_else(|| versions.resolved.get(dep.name().as_str()));
    if let Some(resolved_ver) = resolved {
        write!(
            &mut markdown,
            "**Current**: {}\n\n",
            markdown_code_span(resolved_ver)
        )
        .unwrap();
    } else if let Some(version_req) = dep.version_requirement() {
        write!(
            &mut markdown,
            "**Requirement**: {}\n\n",
            markdown_code_span(version_req.as_str())
        )
        .unwrap();
    }

    if let Some(marker_expr) = dep.markers() {
        write!(
            &mut markdown,
            "**Active when**: {}\n\n",
            markdown_code_span(marker_expr)
        )
        .unwrap();
    }

    let latest = versions
        .cached
        .get(&normalized_name)
        .or_else(|| versions.cached.get(dep.name().as_str()));
    if let Some(latest_ver) = latest {
        write!(
            &mut markdown,
            "**Latest**: {}\n\n",
            markdown_code_span(latest_ver)
        )
        .unwrap();
    }

    markdown.push_str("**Recent versions**:\n");
    for (i, version) in available_versions.iter().take(8).enumerate() {
        let version_span = markdown_code_span(version.version_string());
        if i == 0 {
            writeln!(&mut markdown, "- {version_span} *(latest)*").unwrap();
        } else if version.is_yanked() {
            writeln!(
                &mut markdown,
                "- {} {}",
                version_span,
                formatter.yanked_label()
            )
            .unwrap();
        } else {
            writeln!(&mut markdown, "- {version_span}").unwrap();
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

    let Ok(versions) = registry.get_versions(dep.name().as_str()).await else {
        return actions;
    };

    let display_items = prepare_version_display_items(&versions, dep.name().as_str());

    for item in display_items {
        let new_text = formatter.format_version_for_text_edit(&item.version);

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
/// * `versions` - Latest (registry) and resolved (lock file) version maps, keyed by package name
/// * `formatter` - Ecosystem-specific formatting and comparison logic
pub fn generate_diagnostics_from_cache(
    parse_result: &dyn ParseResult,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        let normalized_name = formatter.normalize_package_name(dep.name().as_str());
        let latest_version = versions
            .cached
            .get(&normalized_name)
            .or_else(|| versions.cached.get(dep.name().as_str()));

        let Some(latest) = latest_version else {
            // Skip "unknown" diagnostic if package exists in lock file
            // (registry fetch may have failed due to rate limiting)
            let in_lockfile = versions.resolved.contains_key(&normalized_name)
                || versions.resolved.contains_key(dep.name().as_str());
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

        let version_req = dep.version_requirement().map_or("", VersionReq::as_str);
        let is_up_to_date = formatter.is_requirement_up_to_date(version_req, latest);

        if !is_up_to_date {
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
/// Prefer `generate_diagnostics_from_cache` when cached versions are available. Not called
/// anywhere in this workspace (`deps-lsp` always has cached versions by the time
/// diagnostics run) — kept as public API for external callers of `deps-core` as a library,
/// re-exported as `deps_core::lsp_generate_diagnostics`.
pub async fn generate_diagnostics<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        let versions = match registry.get_versions(dep.name().as_str()).await {
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
            .get_latest_matching(dep.name().as_str(), version_req.as_str())
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
                && !formatter
                    .is_requirement_up_to_date(version_req.as_str(), latest.version_string())
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
    use crate::PackageName;
    use std::any::Any;

    #[test]
    fn test_position_in_range_inside() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_start() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 10);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_end() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 20);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 25);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(4, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(6, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_multiline() {
        let range = Range::new(Position::new(5, 10), Position::new(7, 5));
        let position = Position::new(6, 0);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_escape_markdown_link_breakout_payload() {
        let payload = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";
        let escaped = escape_markdown(payload);
        assert_eq!(
            escaped,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
        assert!(!escaped.contains("]("));
    }

    #[test]
    fn test_escape_markdown_backslash_and_backtick() {
        assert_eq!(escape_markdown(r"a\b`c"), r"a\\b\`c");
    }

    #[test]
    fn test_escape_markdown_autolink_angle_brackets() {
        // `<...>` around a bare URL is a CommonMark autolink; `<`/`>` must be escaped
        // so it cannot render as a live link independent of the `[]`/`()` escaping.
        let escaped = escape_markdown("pkg <https://evil.example>");
        assert_eq!(escaped, r"pkg \<https\:\/\/evil\.example\>");
        assert!(!escaped.contains('<') || escaped.contains(r"\<"));
    }

    #[test]
    fn test_escape_markdown_control_chars_become_spaces() {
        assert_eq!(escape_markdown("a\nb"), "a b");
        assert_eq!(escape_markdown("a\r\nb"), "a  b");
        assert_eq!(escape_markdown("a\tb"), "a b");
        assert_eq!(escape_markdown("a\0b"), "a b");
    }

    #[test]
    fn test_escape_markdown_newline_cannot_break_out_of_heading() {
        // A raw newline used to terminate the ATX heading line early, letting the
        // rest of the name (potentially another "# [...](...)" sequence) render as
        // separate, unescaped Markdown blocks.
        let escaped = escape_markdown("react\n# [fake](https://evil.example)");
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn test_escape_markdown_hyphenated_name_round_trips_visually() {
        // Escaping a hyphen (ASCII punctuation) is visually inert on render — CommonMark
        // renders `\-` as a literal `-` — so common package names are unaffected in
        // practice even though the raw Markdown source now escapes them.
        assert_eq!(escape_markdown("tokio-util"), r"tokio\-util");
    }

    #[test]
    fn test_markdown_code_span_plain_content() {
        assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
    }

    #[test]
    fn test_markdown_code_span_widens_fence_for_embedded_backticks() {
        assert_eq!(markdown_code_span("a`b"), "``a`b``");
        assert_eq!(markdown_code_span("``double``"), "``` ``double`` ```");
    }

    #[test]
    fn test_markdown_code_span_pads_when_content_starts_or_ends_with_backtick() {
        let span = markdown_code_span("`leading");
        assert!(span.starts_with("`` `"));
    }

    #[test]
    fn test_markdown_code_span_replaces_control_chars() {
        let span = markdown_code_span("1.0\n[evil](https://evil.example)");
        assert!(!span.contains('\n'));
    }

    #[test]
    fn test_markdown_code_span_empty_content() {
        assert_eq!(markdown_code_span(""), "` `");
    }

    #[test]
    fn test_markdown_code_span_backtick_payload_cannot_break_span() {
        // A payload attempting to close the code span early and splice in a live
        // link must not succeed regardless of backtick count in the content.
        let payload = "1.0` <https://evil.example>` more";
        let span = markdown_code_span(payload);
        // The fence must be strictly longer than any backtick run in the (sanitized)
        // content, so no substring of `span` after the opening fence can act as a
        // closing fence before the real one.
        let opening_fence_len = span.chars().take_while(|&c| c == '`').count();
        let inner = &span[opening_fence_len..span.len() - opening_fence_len];
        assert!(
            !inner.contains(&"`".repeat(opening_fence_len)),
            "content contains a run of backticks as long as the fence: {span}"
        );
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
        fn format_version_for_text_edit(&self, version: &str) -> String {
            format!("\"{}\"", version)
        }

        fn package_url(&self, name: &str) -> String {
            format!("https://example.com/{}", name)
        }
    }

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
        name: PackageName,
        version_req: VersionReq,
        version_range: Range,
        name_range: Range,
    }

    impl Dependency for MockDep {
        fn name(&self) -> &PackageName {
            &self.name
        }
        fn name_range(&self) -> Range {
            self.name_range
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
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

            fn format_version_for_text_edit(&self, version: &str) -> String {
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
            formatter.format_version_for_text_edit("1.2.3"),
            ">=1.2.3,<1"
        );
        assert_eq!(
            formatter.package_url("requests"),
            "https://pypi.org/project/requests"
        );
    }

    struct MockMarkedDep {
        name: PackageName,
        name_range: Range,
        markers: Option<String>,
    }

    impl Dependency for MockMarkedDep {
        fn name(&self) -> &PackageName {
            &self.name
        }
        fn name_range(&self) -> Range {
            self.name_range
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
            None
        }
        fn version_range(&self) -> Option<Range> {
            None
        }
        fn source(&self) -> crate::parser::DependencySource {
            crate::parser::DependencySource::Registry
        }
        fn markers(&self) -> Option<&str> {
            self.markers.as_deref()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockMarkedParseResult {
        dep: MockMarkedDep,
        uri: Uri,
    }

    impl ParseResult for MockMarkedParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            vec![&self.dep]
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

    struct MockRegistry;

    impl crate::Registry for MockRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a str,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a str,
            _req: &'a str,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(None) })
        }

        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn package_url(&self, _name: &str) -> String {
            String::new()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_generate_hover_surfaces_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some("python_full_version >= '3.9'".to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Active when**: `python_full_version >= '3.9'`")
        );
    }

    #[tokio::test]
    async fn test_generate_hover_omits_active_when_without_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "requests".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                markers: None,
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Active when"));
    }

    #[tokio::test]
    async fn test_generate_hover_escapes_malicious_dependency_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let malicious_name = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label (between the H1's "# [" and the "](") must be the fully
        // escaped name, with no raw "](" sequence that could close the label early
        // and splice in an attacker-controlled markdown link.
        let header_line = content
            .value
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(
            label,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_newline_in_name_cannot_forge_new_heading() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Combines S1 (newline breaks out of the ATX heading line) with an
        // autolink payload that needs no brackets/parens at all.
        let malicious_name = "react\n# [fake](https://evil.example) <https://evil.example>";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label must be the exact single-line escaped name: no raw
        // newline breaking the ATX heading, and the autolink's `<`/`>` escaped so
        // it cannot render as a live link independent of the `[]`/`()` escaping.
        let header_line = content
            .value
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(label, escape_markdown(malicious_name));
        assert!(!label.contains('\n'));
        assert!(label.contains(r"\<https"));
    }

    #[tokio::test]
    async fn test_generate_hover_marker_with_parens_renders_unescaped() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Regression guard (M4): a legitimate PEP 508 marker with parentheses must
        // render as-is inside its code span, not with visible `\(`/`\)` escapes —
        // backslash-escaping does not apply inside code spans.
        let marker = "python_version >= \"3.8\" and (sys_platform == \"linux\")";
        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some(marker.to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains(&format!("**Active when**: `{marker}`"))
        );
    }

    #[test]
    fn test_inlay_hint_exact_version_shows_update_needed() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "2.0.12".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "2.1.1".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".to_string(), "1.0.214".to_string());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "unknown-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("unknown-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_outdated_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "2.0.0".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
        assert!(diagnostics[0].message.contains("Newer version available"));
        assert!(diagnostics[0].message.contains("2.0.0"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_up_to_date() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for up-to-date dependency"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_multiple_deps() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "serde".into(),
                    version_req: "^1.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                },
                MockDep {
                    name: "tokio".into(),
                    version_req: "1.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: Range::new(Position::new(1, 0), Position::new(1, 5)),
                },
                MockDep {
                    name: "unknown".into(),
                    version_req: "1.0".into(),
                    version_range: Range::new(Position::new(2, 10), Position::new(2, 20)),
                    name_range: Range::new(Position::new(2, 0), Position::new(2, 7)),
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".to_string(), "1.0.214".to_string());
        cached_versions.insert("tokio".to_string(), "2.0.0".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".to_string(), "0.5.1".to_string());

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.4".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".to_string(), "0.5.1".to_string());

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
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
