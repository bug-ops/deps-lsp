//! Shared LSP response builders.

use std::collections::HashMap;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, CodeDescription, CodeLens, Command, Diagnostic, DiagnosticSeverity,
    Hover, HoverContents, InlayHint, InlayHintKind, InlayHintLabel, InlayHintTooltip,
    MarkupContent, MarkupKind, NumberOrString, Position, Range, TextEdit, Uri, WorkspaceEdit,
};

use crate::osv::{ADVISORY_DISPLAY_CAP, ScanOutcome, VulnerabilityMap, diagnostic_severity_for};
use crate::{
    Dependency, EcosystemConfig, InvalidPackageName, PackageName, ParseResult, Registry, VersionReq,
};

/// Bundles the two per-package version maps (`cached`, `resolved`) that LSP handlers pass
/// together everywhere.
///
/// Grouping them prevents accidentally swapping the two `&HashMap<PackageName, String>`
/// arguments at a call site, since the compiler can no longer typecheck them positionally.
///
/// # Examples
///
/// ```
/// use deps_core::{PackageName, VersionData};
/// use std::collections::HashMap;
///
/// let mut cached = HashMap::new();
/// cached.insert(PackageName::new("serde"), "1.0.214".to_string());
///
/// let mut resolved = HashMap::new();
/// resolved.insert(PackageName::new("serde"), "1.0.200".to_string());
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached.get("serde"), Some(&"1.0.214".to_string()));
/// assert_eq!(versions.resolved.get("serde"), Some(&"1.0.200".to_string()));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest versions known from the registry, keyed by package name.
    pub cached: &'a HashMap<PackageName, String>,
    /// Versions actually resolved in the lock file, keyed by package name.
    pub resolved: &'a HashMap<PackageName, String>,
    /// OSV scan results, keyed by normalized package name. `None` when no
    /// scan has run yet (e.g. the feature is disabled) — distinct from an
    /// empty map, which would mean "scanned, nothing found".
    pub vulnerabilities: Option<&'a VulnerabilityMap>,
}

impl<'a> VersionData<'a> {
    /// Creates a new `VersionData` from the cached and resolved version maps.
    ///
    /// `vulnerabilities` starts `None`; chain [`Self::with_vulnerabilities`]
    /// to attach a scan result.
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
    /// assert!(versions.vulnerabilities.is_none());
    /// ```
    pub fn new(
        cached: &'a HashMap<PackageName, String>,
        resolved: &'a HashMap<PackageName, String>,
    ) -> Self {
        Self {
            cached,
            resolved,
            vulnerabilities: None,
        }
    }

    /// Attaches an OSV scan result to this `VersionData`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::VulnerabilityMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let vulns = VulnerabilityMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulns);
    /// assert!(versions.vulnerabilities.is_some());
    /// ```
    #[must_use]
    pub fn with_vulnerabilities(mut self, vulnerabilities: &'a VulnerabilityMap) -> Self {
        self.vulnerabilities = Some(vulnerabilities);
        self
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

    /// Converts an LSP `Position` back into a byte offset — the inverse of
    /// [`byte_offset_to_position`](Self::byte_offset_to_position). Out-of-range lines or
    /// UTF-16 characters clamp to `content.len()` rather than panicking, matching the
    /// forward conversion's `.min(content.len())` guard.
    pub fn position_to_byte_offset(&self, content: &str, position: Position) -> usize {
        let Some(&line_start) = self.line_starts.get(position.line as usize) else {
            return content.len();
        };
        let line_end = self
            .line_starts
            .get(position.line as usize + 1)
            .copied()
            .unwrap_or(content.len());
        let line = &content[line_start..line_end];
        crate::completion::utf16_to_byte_offset(line, position.character)
            .map_or(line_end, |offset| line_start + offset)
            .min(content.len())
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

/// Result of checking whether a dependency's declared requirement is already satisfied by
/// the latest known version.
///
/// Diagnostics and inlay hints read this result differently: diagnostics only need to know
/// whether it is safe to skip the "Newer version available" warning, so both `UpToDate` and
/// `Unresolved` suppress it. Inlay hints additionally need to distinguish `Unresolved` from
/// `UpToDate`, since an unresolved requirement (e.g. a dangling Gradle version-catalog
/// `version.ref` alias, or an unexpanded Maven `${property}`) must not render an "up to
/// date" badge that was never actually verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementStatus {
    /// The latest version satisfies the declared requirement.
    UpToDate,
    /// The latest version does not satisfy the declared requirement — a newer version is
    /// available.
    Outdated,
    /// The requirement could not be resolved to a concrete constraint, so no comparison
    /// could be made.
    Unresolved,
}

/// Ecosystem-specific formatting and comparison logic.
pub trait EcosystemFormatter: Send + Sync {
    /// Normalize package name for lookup (default: identity).
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.to_string()
    }

    /// Lints `name` against ecosystem-specific naming rules.
    ///
    /// Default: permissive, always `Ok(())`. This is a diagnostic lint, not a
    /// construction-time gate — [`PackageName::new`](crate::PackageName::new)
    /// stays infallible regardless of what this returns. Override only to warn
    /// on names an ecosystem's own tooling would never accept; err on the side
    /// of accepting anything ambiguous, since a false positive here is a
    /// warning on a manifest the user's actual package manager treats as fine.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] carrying the reason `name` fails this
    /// ecosystem's naming rules. The default implementation never errs.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::lsp_helpers::EcosystemFormatter;
    ///
    /// struct PermissiveFormatter;
    ///
    /// impl EcosystemFormatter for PermissiveFormatter {
    ///     fn format_version_for_text_edit(&self, version: &str) -> String {
    ///         version.to_string()
    ///     }
    ///
    ///     fn package_url(&self, name: &PackageName) -> String {
    ///         format!("https://example.com/{name}")
    ///     }
    /// }
    ///
    /// // The default is permissive: any name, including one that would fail an
    /// // ecosystem-specific override, is accepted.
    /// assert!(PermissiveFormatter.validate_package_name("../not/a/real/rule").is_ok());
    /// ```
    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Ok(())
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
    fn is_requirement_up_to_date(&self, requirement: &VersionReq, latest: &str) -> bool {
        self.version_satisfies_requirement(latest, requirement.as_str())
    }

    /// Whether `requirement` could not be resolved to a concrete version constraint (e.g. an
    /// unexpanded property/variable placeholder rather than a real version or range).
    ///
    /// Default: always resolvable. Ecosystems whose requirement syntax can contain
    /// unresolved placeholders (Maven's `${property}`, Gradle's `$var`/`${var}`) override
    /// this single predicate; both `version_satisfies_requirement`'s "treat as satisfied"
    /// short-circuit and `requirement_status`'s `Unresolved` variant are derived from it, so
    /// the two can't drift out of sync with each other.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::EcosystemFormatter;
    /// use deps_core::{PackageName, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl EcosystemFormatter for DefaultFormatter {
    ///     fn format_version_for_text_edit(&self, version: &str) -> String {
    ///         version.to_string()
    ///     }
    ///     fn package_url(&self, name: &PackageName) -> String {
    ///         name.to_string()
    ///     }
    /// }
    ///
    /// assert!(!DefaultFormatter.requirement_is_unresolved(&VersionReq::new("^1.2")));
    /// ```
    fn requirement_is_unresolved(&self, _requirement: &VersionReq) -> bool {
        false
    }

    /// Tri-state variant of `is_requirement_up_to_date` that distinguishes "confirmed up to
    /// date" from "could not be resolved, so we don't know."
    ///
    /// Default: `Unresolved` when `requirement_is_unresolved` says so, otherwise maps the
    /// boolean result of `is_requirement_up_to_date` to `UpToDate`/`Outdated`. Callers
    /// needing the distinction — inlay hints, in particular — use this instead of
    /// `is_requirement_up_to_date` so they can tell "verified up to date" apart from
    /// "resolution failed."
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{EcosystemFormatter, RequirementStatus};
    /// use deps_core::{PackageName, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl EcosystemFormatter for DefaultFormatter {
    ///     fn format_version_for_text_edit(&self, version: &str) -> String {
    ///         version.to_string()
    ///     }
    ///     fn package_url(&self, name: &PackageName) -> String {
    ///         name.to_string()
    ///     }
    /// }
    ///
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), "1.5.0"),
    ///     RequirementStatus::UpToDate
    /// );
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), "2.0.0"),
    ///     RequirementStatus::Outdated
    /// );
    /// ```
    fn requirement_status(&self, requirement: &VersionReq, latest: &str) -> RequirementStatus {
        if self.requirement_is_unresolved(requirement) {
            return RequirementStatus::Unresolved;
        }
        if self.is_requirement_up_to_date(requirement, latest) {
            RequirementStatus::UpToDate
        } else {
            RequirementStatus::Outdated
        }
    }

    /// Get package URL for hover markdown.
    fn package_url(&self, name: &PackageName) -> String;

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

    /// OSV.dev's canonical spelling for `dep`'s package name, or `None` if
    /// this dependency cannot be mapped (e.g. a non-GitHub Swift package).
    ///
    /// Deliberately **not** routed through [`Self::normalize_package_name`]:
    /// that method produces this project's internal lookup key, while this
    /// one produces the name sent on the wire to OSV. They coincide for most
    /// ecosystems and diverge for NuGet (case-preserving; normalizing would
    /// lowercase it and zero out results), Composer (OSV wants lowercase,
    /// overridden in `deps-composer`), and Swift (prefixed to
    /// `github.com/{owner}/{repo}`, overridden in `deps-swift`). Takes
    /// `&dyn Dependency` rather than `&str` because the Swift override needs
    /// to downcast to inspect the dependency's source URL host — see
    /// `architecture.md` §2.
    ///
    /// The default implementation is the identity: OSV is case-sensitive in
    /// every ecosystem this project supports except PyPI, and for Cargo, npm,
    /// Go, Maven, Gradle, Dart, Bundler, NuGet, and PyPI the manifest's raw
    /// name already matches OSV's canonical spelling.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        Some(dep.name().to_string())
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

        let normalized_name = formatter.normalize_package_name(dep.name());
        let latest_version = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()));
        let resolved_version = versions
            .resolved
            .get(normalized_name.as_str())
            .or_else(|| versions.resolved.get(dep.name()));

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
        // 2. If NOT in lock file, check the version requirement against latest
        let status = if let Some(resolved) = resolved_version {
            if resolved.as_str() == latest.as_str() {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            }
        } else {
            match dep.version_requirement() {
                Some(version_req) => formatter.requirement_status(version_req, latest),
                // No declared requirement at all (e.g. a dangling alias/reference the
                // parser couldn't resolve to any string) — nothing was verified.
                None => RequirementStatus::Unresolved,
            }
        };

        let label_text = match status {
            RequirementStatus::UpToDate => {
                if config.show_up_to_date_hints {
                    if let Some(resolved) = resolved_version {
                        format!("{} {}", config.up_to_date_text, resolved)
                    } else {
                        config.up_to_date_text.clone()
                    }
                } else {
                    continue;
                }
            }
            RequirementStatus::Outdated => config.needs_update_text.replace("{}", latest),
            // Resolution failed (e.g. dangling alias/unexpanded variable) — neither
            // "up to date" nor "outdated" was actually verified, so show nothing.
            RequirementStatus::Unresolved => continue,
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

    let available_versions = registry.get_versions(dep.name()).await.ok()?;

    let url = formatter.package_url(dep.name());

    // Pre-allocate with estimated capacity to reduce allocations
    let mut markdown = String::with_capacity(512);
    write!(
        &mut markdown,
        "# [{}]({})\n\n",
        escape_markdown(dep.name().as_str()),
        url
    )
    .unwrap();

    let normalized_name = formatter.normalize_package_name(dep.name());

    let resolved = versions
        .resolved
        .get(normalized_name.as_str())
        .or_else(|| versions.resolved.get(dep.name()));
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
        .get(normalized_name.as_str())
        .or_else(|| versions.cached.get(dep.name()));
    if let Some(latest_ver) = latest {
        write!(
            &mut markdown,
            "**Latest**: {}\n\n",
            markdown_code_span(latest_ver)
        )
        .unwrap();
    }

    let vuln_outcome = versions.vulnerabilities.and_then(|m| {
        m.get(&normalized_name)
            .or_else(|| m.get(dep.name().as_str()))
    });
    push_vulnerability_hover_section(&mut markdown, vuln_outcome);

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

// TODO(critic): FR-006 (upgrade code actions for vulnerable dependencies) is
// deferred to a follow-up PR — this is the one helper that does not take
// `VersionData`, so wiring it up requires an `Ecosystem` trait signature
// change that no crate currently overrides. See architecture.md §7/§10 Q3.
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
        let normalized_name = formatter.normalize_package_name(dep.name());

        // Emitted before either early-`continue` below (registry outage,
        // no version range) so a registry failure never suppresses an OSV
        // finding — the two are independent data sources (FR-007/US-004).
        if let Some(vulnerabilities) = versions.vulnerabilities
            && let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities
                .get(&normalized_name)
                .or_else(|| vulnerabilities.get(dep.name().as_str()))
        {
            push_vulnerability_diagnostics(&mut diagnostics, dep, dv);
        }

        let latest_version = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()));

        let Some(latest) = latest_version else {
            // Skip "unknown" diagnostic if package exists in lock file
            // (registry fetch may have failed due to rate limiting)
            let in_lockfile = versions.resolved.contains_key(normalized_name.as_str())
                || versions.resolved.contains_key(dep.name());
            if !in_lockfile {
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => format!("Invalid package name '{}': {reason}", dep.name()),
                    Ok(()) => format!("Unknown package '{}'", dep.name()),
                };
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(DiagnosticSeverity::WARNING),
                    message,
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
            continue;
        };

        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let status = match dep.version_requirement() {
            Some(version_req) => formatter.requirement_status(version_req, latest),
            // No declared requirement at all (e.g. a dangling alias/reference the parser
            // couldn't resolve to any string) — nothing was verified.
            None => RequirementStatus::Unresolved,
        };

        if status == RequirementStatus::Outdated {
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

/// Slices `content` over an LSP `Range` using a pre-built `LineOffsetTable`, returning
/// `""` for an inverted or out-of-bounds range instead of panicking.
///
/// `table` is document-invariant — callers iterating over multiple dependencies in the
/// same document must build it once and reuse it, rather than rebuilding it (an O(n)
/// scan of `content`) per dependency.
fn slice_for_range<'a>(content: &'a str, table: &LineOffsetTable, range: Range) -> &'a str {
    let start = table.position_to_byte_offset(content, range.start);
    let end = table.position_to_byte_offset(content, range.end);
    if start > end {
        return "";
    }
    content.get(start..end).unwrap_or("")
}

/// Checks whether `slice` — `content` sliced over a dependency's `version_range` — still
/// holds the literal version text declared by `requirement`.
///
/// Whitespace is stripped from both sides before comparison, since pep508's normalized
/// requirement string can diverge from the original source spacing (PyPI's `>=1.7,<2.0`
/// renders as `>=1.7, <2.0`) while `version_range` still spans the un-normalized source.
///
/// The second branch accepts `slice` wrapped in brackets matching `requirement` — the
/// exact inverse of NuGet's parser wrapping a bare source version as `format!("[{v}]")`
/// (`crates/deps-nuget/src/parser.rs`). This is deliberately **not** a symmetric bracket
/// strip: NuGet's `Version="1.0.0"` produces requirement `[1.0.0]` over a bare-literal
/// span, so a *symmetric* strip (stripping one bracket pair from both operands) would
/// compare `1.0.0` against `1.0.0` — coincidentally correct there, but the same strip
/// applied to `Version="[1.0.0]"` (requirement `[[1.0.0]]`, a spelling
/// `crates/deps-nuget/src/formatter.rs` explicitly supports) leaves `[1.0.0]` vs
/// `1.0.0` and **falsely rejects** an editable dependency. Wrapping only the slice side
/// handles both spellings without that false reject.
fn literal_span_matches(slice: &str, requirement: &str) -> bool {
    let norm_slice: String = slice.chars().filter(|c| !c.is_whitespace()).collect();
    let norm_req: String = requirement.chars().filter(|c| !c.is_whitespace()).collect();
    norm_slice == norm_req || format!("[{norm_slice}]") == norm_req
}

/// Manifest edits bringing every safely-editable outdated dependency to `latest`.
///
/// A dependency is included when all of the following hold:
/// - it declares a `version_range` (a span to rewrite exists);
/// - a `latest` version is known in `versions.cached` (normalized name first, then raw —
///   mirroring [`generate_diagnostics_from_cache`]);
/// - `formatter.is_requirement_up_to_date` reports the declared requirement as *not*
///   satisfying `latest` — the same predicate diagnostics use, so on a fixture where the
///   guard below is a no-op, `collect_update_all_edits(..).len()` equals the number of
///   `generate_diagnostics_from_cache` "Newer version available" diagnostics;
/// - the **literal-span guard** (`literal_span_matches`): `content` sliced over
///   `version_range` must still be (up to whitespace and NuGet's bracket wrap) the
///   declared requirement text. Several ecosystems point `version_range` at something
///   that is not a version literal — a Maven `${property}` reference, a Gradle DSL
///   variable or version-catalog alias, or (for every Swift dependency form) the
///   lower-bound literal of a synthesized comparator range — and rewriting those spans
///   would corrupt the manifest instead of fixing it. A dependency that fails the guard
///   is skipped entirely: neither counted nor edited.
///
/// Accepted edits are sorted by start position; a later edit whose start falls before the
/// previous edit's end (an overlap — a `WorkspaceEdit` protocol violation) is dropped with
/// a `tracing::warn!`. No current parser produces overlapping `version_range`s, so this is
/// a guard against future parser changes, not an expected code path.
///
/// `content` is the manifest source, needed for the literal-span guard above — the same
/// parameter [`Ecosystem::generate_completions`](crate::Ecosystem::generate_completions)
/// already threads through for a similar reason.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{collect_update_all_edits, EcosystemFormatter, VersionData};
/// use deps_core::{Dependency, ParseResult, PackageName, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use tower_lsp_server::ls_types::{Position, Range, Uri};
///
/// struct MockFormatter;
/// impl EcosystemFormatter for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{name}")
///     }
/// }
///
/// struct MockDep {
///     name: PackageName,
///     version_req: VersionReq,
///     version_range: Range,
///     name_range: Range,
/// }
/// impl Dependency for MockDep {
///     fn name(&self) -> &PackageName { &self.name }
///     fn name_range(&self) -> Range { self.name_range }
///     fn version_requirement(&self) -> Option<&VersionReq> { Some(&self.version_req) }
///     fn version_range(&self) -> Option<Range> { Some(self.version_range) }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// struct MockParseResult { deps: Vec<MockDep>, uri: Uri }
/// impl ParseResult for MockParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> { None }
///     fn uri(&self) -> &Uri { &self.uri }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// let content = r#"serde = "1.0.0""#;
/// let parse_result = MockParseResult {
///     deps: vec![MockDep {
///         name: PackageName::new("serde"),
///         version_req: VersionReq::new("1.0.0"),
///         version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///         name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
///     }],
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
/// };
///
/// let mut cached = HashMap::new();
/// cached.insert("serde".into(), "1.2.0".to_string());
/// let resolved = HashMap::new();
///
/// let edits = collect_update_all_edits(
///     &parse_result,
///     content,
///     VersionData::new(&cached, &resolved),
///     &MockFormatter,
/// );
///
/// assert_eq!(edits.len(), 1);
/// assert_eq!(edits[0].new_text, "1.2.0");
/// ```
pub fn collect_update_all_edits(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<TextEdit> {
    let deps = parse_result.dependencies();
    let mut edits: Vec<TextEdit> = Vec::with_capacity(deps.len());
    // Built once and reused for every dependency below — content is fixed for the
    // whole call, so re-scanning it per dependency would be O(n²) in dependency count.
    let line_offsets = LineOffsetTable::new(content);

    for dep in deps {
        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let normalized_name = formatter.normalize_package_name(dep.name());
        let Some(latest) = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()))
        else {
            continue;
        };

        let Some(version_req) = dep.version_requirement() else {
            continue;
        };
        if version_req.as_str().is_empty() {
            // Defense-in-depth: an empty requirement would trivially satisfy the guard
            // below (both sides normalize to ""), so without this, a future formatter
            // whose `is_requirement_up_to_date` doesn't treat "" as up to date could
            // emit an edit anchored on a span that was never a version literal.
            continue;
        }
        if formatter.is_requirement_up_to_date(version_req, latest) {
            continue;
        }

        let slice = slice_for_range(content, &line_offsets, version_range);
        if !literal_span_matches(slice, version_req.as_str()) {
            continue;
        }

        edits.push(TextEdit {
            range: version_range,
            new_text: formatter.format_version_for_text_edit(latest),
        });
    }

    edits.sort_by_key(|edit| (edit.range.start.line, edit.range.start.character));

    let mut non_overlapping: Vec<TextEdit> = Vec::with_capacity(edits.len());
    for edit in edits {
        let overlaps_prev = non_overlapping.last().is_some_and(|prev: &TextEdit| {
            (edit.range.start.line, edit.range.start.character)
                < (prev.range.end.line, prev.range.end.character)
        });
        if overlaps_prev {
            tracing::warn!(
                range = ?edit.range,
                "collect_update_all_edits: dropping overlapping TextEdit"
            );
            continue;
        }
        non_overlapping.push(edit);
    }

    non_overlapping
}

/// Zero or one lens for the document, bound to `command_id`.
///
/// Delegates to [`collect_update_all_edits`] for the count in the lens title — the same
/// call the command handler makes to produce the edits it applies, so `title N == edits
/// applied` holds by construction rather than by two implementations agreeing. Returns no
/// lens when there is nothing to update: a permanent line-0 annotation on every
/// up-to-date manifest would be noise.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{generate_code_lenses, EcosystemFormatter, VersionData};
/// use deps_core::{PackageName, ParseResult};
/// use std::collections::HashMap;
///
/// struct MockFormatter;
/// impl EcosystemFormatter for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{name}")
///     }
/// }
///
/// // An empty parse result yields no outdated dependencies, so no lens is generated.
/// # struct EmptyParseResult { uri: tower_lsp_server::ls_types::Uri }
/// # impl deps_core::ParseResult for EmptyParseResult {
/// #     fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> { vec![] }
/// #     fn workspace_root(&self) -> Option<&std::path::Path> { None }
/// #     fn uri(&self) -> &tower_lsp_server::ls_types::Uri { &self.uri }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// let parse_result = EmptyParseResult { uri: deps_core::test_util::test_uri("/test/Cargo.toml") };
/// let cached = HashMap::new();
/// let resolved = HashMap::new();
///
/// let lenses = generate_code_lenses(
///     &parse_result,
///     "",
///     VersionData::new(&cached, &resolved),
///     &MockFormatter,
///     parse_result.uri(),
///     "deps-lsp.updateAllOutdated",
/// );
///
/// assert!(lenses.is_empty());
/// ```
pub fn generate_code_lenses(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
    uri: &Uri,
    command_id: &str,
) -> Vec<CodeLens> {
    let edits = collect_update_all_edits(parse_result, content, versions, formatter);
    if edits.is_empty() {
        return Vec::new();
    }

    let count = edits.len();
    let title = if count == 1 {
        "Update 1 outdated dependency".to_string()
    } else {
        format!("Update {count} outdated dependencies")
    };

    vec![CodeLens {
        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        command: Some(Command {
            title,
            command: command_id.to_string(),
            arguments: Some(vec![serde_json::json!({ "uri": uri })]),
        }),
        data: None,
    }]
}

/// Pushes one [`Diagnostic`] per advisory (each with its own severity, code,
/// and clickable `code_description`), capped at
/// [`ADVISORY_DISPLAY_CAP`] plus a trailing "+N more advisories" entry.
///
/// `N` is derived from `dv.total_known` — the batch result's reported count —
/// never from `dv.advisories.len()`, since invariant 3 (`architecture.md` §8)
/// caps the record *fetch* independently of the render cap.
fn push_vulnerability_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    dep: &dyn Dependency,
    dv: &crate::osv::DependencyVulnerabilities,
) {
    let range = dep.version_range().unwrap_or_else(|| dep.name_range());

    let shown = dv.advisories.iter().take(ADVISORY_DISPLAY_CAP);
    let mut shown_count = 0usize;
    for advisory in shown {
        shown_count += 1;
        let code_description = advisory
            .url
            .parse::<Uri>()
            .ok()
            .map(|href| CodeDescription { href });

        diagnostics.push(Diagnostic {
            range,
            severity: Some(diagnostic_severity_for(advisory.severity)),
            message: format!(
                "{}: {}",
                advisory.id,
                advisory
                    .summary
                    .as_deref()
                    .unwrap_or("(no summary provided)")
            ),
            code: Some(NumberOrString::String(advisory.id.clone())),
            code_description,
            source: Some("deps-lsp".into()),
            ..Default::default()
        });
    }

    let remaining = dv.total_known.saturating_sub(shown_count);
    if remaining > 0 {
        diagnostics.push(Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::INFORMATION),
            message: format!("+{remaining} more advisories"),
            source: Some("deps-lsp".into()),
            ..Default::default()
        });
    }
}

/// Lowercase display label for a [`crate::osv::VulnSeverity`], used only in hover text.
const fn severity_label(severity: crate::osv::VulnSeverity) -> &'static str {
    match severity {
        crate::osv::VulnSeverity::Critical => "critical",
        crate::osv::VulnSeverity::High => "high",
        crate::osv::VulnSeverity::Medium => "medium",
        crate::osv::VulnSeverity::Low => "low",
        crate::osv::VulnSeverity::Unknown => "unknown severity",
    }
}

/// Appends the hover "Security advisories" section, gated strictly on the
/// scan outcome — never on map absence.
///
/// `Vulnerable` gets the advisories list, `Clean` may state the affirmative
/// "no known vulnerabilities", and `Skipped` (or no scan at all) says
/// **nothing**: saying "clean" about a dependency that was never queried is
/// worse than saying nothing at all (`architecture.md` §8 invariant 0).
fn push_vulnerability_hover_section(markdown: &mut String, outcome: Option<&ScanOutcome>) {
    use std::fmt::Write;

    match outcome {
        Some(ScanOutcome::Vulnerable(dv)) => {
            markdown.push_str("### Security advisories\n\n");

            let shown = dv.advisories.iter().take(ADVISORY_DISPLAY_CAP);
            for advisory in shown {
                writeln!(
                    markdown,
                    "- **[{}]({})** — {}",
                    escape_markdown(&advisory.id),
                    advisory.url,
                    severity_label(advisory.severity)
                )
                .unwrap();
                writeln!(
                    markdown,
                    "  {}",
                    escape_markdown(
                        advisory
                            .summary
                            .as_deref()
                            .unwrap_or("(no summary provided)")
                    )
                )
                .unwrap();

                let mut details = Vec::with_capacity(2);
                if let Some(fixed) = advisory.fixed_versions.last() {
                    details.push(format!("Fixed in: {}", markdown_code_span(fixed)));
                }
                if !advisory.aliases.is_empty() {
                    details.push(format!(
                        "Aliases: {}",
                        escape_markdown(&advisory.aliases.join(", "))
                    ));
                }
                if !details.is_empty() {
                    writeln!(markdown, "  {}", details.join(" \u{b7} ")).unwrap();
                }
            }

            let shown_count = dv.advisories.len().min(ADVISORY_DISPLAY_CAP);
            let remaining = dv.total_known.saturating_sub(shown_count);
            if remaining > 0 {
                writeln!(markdown, "- *(+{remaining} more advisories)*").unwrap();
            }

            if let crate::osv::UpgradeStatus::CandidateVulnerable { version, .. } =
                &dv.upgrade_status
            {
                writeln!(
                    markdown,
                    "\n\u{26a0}\u{fe0f} Latest version {} is also affected.",
                    markdown_code_span(version)
                )
                .unwrap();
            }

            markdown.push('\n');
        }
        Some(ScanOutcome::Clean) => {
            markdown.push_str("**No known vulnerabilities** (OSV.dev)\n\n");
        }
        Some(ScanOutcome::Skipped(_)) | None => {}
    }
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
        let versions = match registry.get_versions(dep.name()).await {
            Ok(v) => v,
            Err(_) => {
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => format!("Invalid package name '{}': {reason}", dep.name()),
                    Ok(()) => format!("Unknown package '{}'", dep.name()),
                };
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(DiagnosticSeverity::WARNING),
                    message,
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
                && formatter.requirement_status(version_req, latest.version_string())
                    == RequirementStatus::Outdated
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
    use crate::{PackageName, VersionReq};
    use std::any::Any;

    fn pkg(s: &str) -> PackageName {
        PackageName::new(s)
    }

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

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name)
        }
    }

    /// Formatter stub that always reports `Unresolved`, mirroring `MavenFormatter` /
    /// `GradleFormatter`'s override for `${property}` / `$var` requirements.
    struct MockUnresolvedFormatter;

    impl EcosystemFormatter for MockUnresolvedFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name)
        }

        fn requirement_status(
            &self,
            _requirement: &VersionReq,
            _latest: &str,
        ) -> RequirementStatus {
            RequirementStatus::Unresolved
        }
    }

    /// A formatter whose `validate_package_name` always rejects, for exercising
    /// the "Invalid package name" diagnostic path independently of "Unknown package".
    struct RejectingFormatter;

    impl EcosystemFormatter for RejectingFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name)
        }

        fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
            Err(InvalidPackageName::new("name is rejected for testing"))
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
        assert_eq!(
            formatter.normalize_package_name(&pkg("test-pkg")),
            "test-pkg"
        );
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
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.as_str().to_lowercase().replace('-', "_")
            }

            fn format_version_for_text_edit(&self, version: &str) -> String {
                format!(
                    ">={},<{}",
                    version,
                    version.split('.').next().unwrap_or("0")
                )
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pypi.org/project/{}", name)
            }
        }

        let formatter = PyPIFormatter;
        assert_eq!(
            formatter.normalize_package_name(&pkg("Test-Package")),
            "test_package"
        );
        assert_eq!(
            formatter.format_version_for_text_edit("1.2.3"),
            ">=1.2.3,<1"
        );
        assert_eq!(
            formatter.package_url(&pkg("requests")),
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
            _name: &'a PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a PackageName,
            _req: &'a VersionReq,
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

        fn package_url(&self, _name: &PackageName) -> String {
            String::new()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A registry whose `get_versions` always errs, for exercising
    /// `generate_diagnostics`'s `Err` arm.
    struct ErrorRegistry;

    impl crate::Registry for ErrorRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move {
                Err(crate::error::DepsError::CacheError(
                    "mock registry error".to_string(),
                ))
            })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a PackageName,
            _req: &'a VersionReq,
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

        fn package_url(&self, _name: &PackageName) -> String {
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
        cached_versions.insert("serde".into(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.0.12".to_string());

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
        cached_versions.insert("serde".into(), "2.1.1".to_string());

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.1.1".to_string());

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
        cached_versions.insert("serde".into(), "1.0.214".to_string());

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.0.214".to_string());

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
    fn test_generate_diagnostics_from_cache_invalid_package_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A formatter that rejects every name must produce exactly one
        // "Invalid package name" diagnostic per unresolved dependency, never
        // both that and "Unknown package".
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
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
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
        assert!(!diagnostics[0].message.contains("Unknown package"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_invalid_package_name() {
        use tower_lsp_server::ls_types::{Position, Range};

        // Network variant: a registry lookup failure combined with a rejected
        // name must produce "Invalid package name", not "Unknown package".
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let diagnostics = generate_diagnostics(&parse_result, &ErrorRegistry, &formatter).await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
        assert!(!diagnostics[0].message.contains("Unknown package"));
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
        cached_versions.insert("serde".into(), "2.0.0".to_string());

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
        cached_versions.insert("serde".into(), "1.0.214".to_string());

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
        cached_versions.insert("serde".into(), "1.0.214".to_string());
        cached_versions.insert("tokio".into(), "2.0.0".to_string());

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
        cached_versions.insert("criterion".into(), "0.5.1".to_string());

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
        cached_versions.insert("criterion".into(), "0.5.1".to_string());

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

    #[test]
    fn test_generate_diagnostics_from_cache_unresolved_emits_no_diagnostic() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockUnresolvedFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "spring-boot-starter".into(),
                version_req: "$missing".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("spring-boot-starter".into(), "3.2.0".to_string());

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for an unresolved requirement, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_inlay_hint_unresolved_requirement_emits_no_hint() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "spring-boot-starter".into(),
                version_req: "$missing".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("spring-boot-starter".into(), "3.2.0".to_string());

        // Not in lock file, so status is derived from `requirement_status` on the
        // formatter (which the caller sets to `Unresolved`) rather than a resolved-vs-latest
        // comparison.
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &MockUnresolvedFormatter,
        );

        assert!(
            hints.is_empty(),
            "Expected no inlay hint at all for an unresolved requirement (not even 'up to date'), got: {hints:?}"
        );
    }

    mod update_all_edits_tests {
        use super::*;
        use tower_lsp_server::ls_types::{Position, Range};

        struct UaeDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            version_range: Option<Range>,
        }

        impl Dependency for UaeDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct UaeParseResult {
            deps: Vec<UaeDep>,
            uri: Uri,
        }

        impl ParseResult for UaeParseResult {
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

        fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Range {
            Range::new(Position::new(sl, sc), Position::new(el, ec))
        }

        fn dep(name: &str, req: Option<&str>, vr: Option<Range>) -> UaeDep {
            UaeDep {
                name: PackageName::new(name),
                version_req: req.map(VersionReq::new),
                version_range: vr,
            }
        }

        fn parse_result(deps: Vec<UaeDep>) -> UaeParseResult {
            UaeParseResult {
                deps,
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            }
        }

        /// A formatter whose `is_requirement_up_to_date` ignores range semantics and
        /// always reports "not up to date" — mirrors NuGet's bare-requirement-is-a-floor
        /// override (`crates/deps-nuget/src/formatter.rs`), used to prove the override
        /// point is actually consulted rather than the trait default.
        struct FloorFormatter;

        impl EcosystemFormatter for FloorFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn is_requirement_up_to_date(&self, _requirement: &VersionReq, _latest: &str) -> bool {
                false
            }
        }

        #[test]
        fn test_zero_outdated_returns_empty_edits_and_no_lens() {
            let content = r#"serde = "1.0.0""#;
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.0.0".to_string());
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            assert!(edits.is_empty());

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert!(lenses.is_empty());
        }

        #[test]
        fn test_n_outdated_produces_n_edits_with_expected_range_and_text() {
            let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\n";
            let pr = parse_result(vec![
                dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14))),
                dep("tokio", Some("1.0.0"), Some(range(1, 9, 1, 14))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.2.0".to_string());
            cached.insert("tokio".into(), "1.3.0".to_string());
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            assert_eq!(edits.len(), 2);
            assert_eq!(edits[0].range, range(0, 9, 0, 14));
            assert_eq!(
                edits[0].new_text,
                MockFormatter.format_version_for_text_edit("1.2.0")
            );
            assert_eq!(edits[1].range, range(1, 9, 1, 14));
            assert_eq!(
                edits[1].new_text,
                MockFormatter.format_version_for_text_edit("1.3.0")
            );

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert_eq!(lenses.len(), 1);
            let command = lenses[0].command.as_ref().expect("lens has a command");
            assert_eq!(command.title, "Update 2 outdated dependencies");
            assert_eq!(command.command, "deps-lsp.updateAllOutdated");
        }

        #[test]
        fn test_singular_title_for_one_outdated_dependency() {
            let content = r#"serde = "1.0.0""#;
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.2.0".to_string());
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert_eq!(lenses.len(), 1);
            assert_eq!(
                lenses[0].command.as_ref().unwrap().title,
                "Update 1 outdated dependency"
            );
        }

        #[test]
        fn test_missing_version_range_is_skipped() {
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), None)]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.2.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_empty_version_requirement_is_skipped() {
            // Defense-in-depth (H2): an empty requirement would trivially satisfy
            // `literal_span_matches` if the guard were reached (both sides normalize to
            // "") and the span text would then be discarded and overwritten outright —
            // this must never reach the guard in the first place.
            let content = "pkg = \"\"\n";
            let pr = parse_result(vec![dep("pkg", Some(""), Some(range(0, 6, 0, 6)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), "1.0.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "an empty version requirement must never produce an edit"
            );
        }

        #[test]
        fn test_dependency_absent_from_cache_is_skipped() {
            let content = "git-dep = \"1.0.0\"\n";
            let pr = parse_result(vec![dep(
                "git-dep",
                Some("1.0.0"),
                Some(range(0, 11, 0, 16)),
            )]);
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_requirement_already_accepts_latest_is_not_counted() {
            // "^1.0" already accepts "1.2.0" per the default `is_requirement_up_to_date`,
            // so no edit is produced even though `latest` differs from the source text.
            let content = "serde = \"^1.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("^1.0"), Some(range(0, 9, 0, 13)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.2.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_formatter_is_requirement_up_to_date_override_is_honored() {
            // With the trait default, "1.0.0" satisfying "1.0.0" would be up to date.
            // `FloorFormatter` overrides the hook to always report outdated, proving
            // `collect_update_all_edits` calls through the formatter, not the default.
            let content = r#"pkg = "1.0.0""#;
            let pr = parse_result(vec![dep("pkg", Some("1.0.0"), Some(range(0, 7, 0, 12)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), "1.0.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &FloorFormatter,
            );
            assert_eq!(edits.len(), 1);
        }

        #[test]
        fn test_guard_rejects_span_that_is_not_the_requirement() {
            // Simulates the Maven `${property}` class: version_range spans a reference,
            // version_requirement is the already-resolved value.
            let content = "<version>${slf4j.version}</version>";
            let pr = parse_result(vec![dep(
                "slf4j-api",
                Some("2.0.16"),
                Some(range(0, 9, 0, 25)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("slf4j-api".into(), "2.1.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "a version_range spanning a property reference must not be edited"
            );
        }

        #[test]
        fn test_guard_accepts_whitespace_only_difference() {
            // PyPI's pep508 round-trip: `version_requirement()` is normalized to
            // ">=1.7, <2.0" while `version_range` still spans the un-normalized source.
            let content = "pkg>=1.7,<2.0";
            let pr = parse_result(vec![dep(
                "pkg",
                Some(">=1.7, <2.0"),
                Some(range(0, 3, 0, 13)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), "3.0.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(edits.len(), 1, "whitespace-only divergence must not skip");
        }

        #[test]
        fn test_guard_accepts_nuget_bracket_wrap() {
            // NuGet wraps a bare source version as the requirement: source "1.0.0" ->
            // requirement "[1.0.0]". The guard's bracket branch is the exact inverse.
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="1.0.0" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[1.0.0]"),
                Some(range(0, 53, 0, 58)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("Newtonsoft.Json".into(), "13.0.3".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "NuGet's bracket-wrapped requirement must be kept"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_already_bracketed_source() {
            // The real reason the guard wraps only the slice, not both operands: NuGet's
            // parser wraps *unconditionally* — a source that is already bracketed,
            // `Version="[1.0.0]"`, still yields a double-wrapped requirement `[[1.0.0]]`
            // (`crates/deps-nuget/src/parser.rs`). A symmetric strip would compare
            // `[1.0.0]` against `1.0.0` here and falsely reject an editable dependency;
            // the asymmetric wrap-the-slice rule handles it correctly.
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0.0]" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0.0]]"),
                Some(range(0, 53, 0, 60)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("Newtonsoft.Json".into(), "13.0.3".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "an already-bracketed NuGet source must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_open_ended_lower_bound_spelling() {
            // Another double-bracket NuGet spelling from §4.4's table: source
            // "[1.0.0,]" (open-ended lower bound) wraps to requirement "[[1.0.0,]]".
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0.0,]" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0.0,]]"),
                Some(range(0, 53, 0, 61)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("Newtonsoft.Json".into(), "13.0.3".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "the open-ended-lower-bound NuGet spelling must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_exclusive_upper_bound_spelling() {
            // Third double-bracket NuGet spelling from §4.4's table: source
            // "[1.0,2.0)" (exclusive upper bound) wraps to requirement "[[1.0,2.0)]".
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0,2.0)" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0,2.0)]"),
                Some(range(0, 53, 0, 62)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("Newtonsoft.Json".into(), "13.0.3".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "the exclusive-upper-bound NuGet spelling must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_rejects_bracketed_interval_against_unbracketed_requirement() {
            // Regression guard for the OLD (broken) symmetric-strip rule: stripping
            // brackets from *both* operands would wrongly match a Maven-style bracketed
            // interval span `[1.0,2.0]` against an unbracketed requirement `1.0,2.0`.
            // The corrected asymmetric rule only wraps the *slice*, so
            // `format!("[{slice}]")` produces `[[1.0,2.0]]`, which does not equal
            // `1.0,2.0` either — the dependency must be skipped.
            let content = "<version>[1.0,2.0]</version>";
            let pr = parse_result(vec![dep(
                "interval-dep",
                Some("1.0,2.0"),
                Some(range(0, 9, 0, 18)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("interval-dep".into(), "3.0.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "a bracketed interval span must not match an unbracketed requirement"
            );
        }

        #[test]
        fn test_invariant_edit_count_matches_diagnostic_count_when_guard_is_noop() {
            // On a fixture where every span already equals its requirement (the guard is
            // a no-op), the edit count must equal the diagnostic count — same predicate.
            let content = "serde = \"1.0.0\"\ntokio = \"^1.5\"\nunknown = \"1.0.0\"\n";
            let pr = parse_result(vec![
                dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14))),
                dep("tokio", Some("^1.5"), Some(range(1, 9, 1, 13))),
                dep("unknown", Some("1.0.0"), Some(range(2, 11, 2, 16))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), "2.0.0".to_string());
            cached.insert("tokio".into(), "1.9.0".to_string());
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            let diagnostics = generate_diagnostics_from_cache(&pr, versions, &MockFormatter);
            let newer_version_diagnostics = diagnostics
                .iter()
                .filter(|d| d.message.contains("Newer version available"))
                .count();

            assert_eq!(edits.len(), newer_version_diagnostics);
            assert_eq!(edits.len(), 1);
        }

        #[test]
        fn test_overlapping_edits_are_dropped_keeping_the_first() {
            let content = "aaaa = \"1.0.0\"\n";
            // Two dependencies whose declared version_range identically overlaps —
            // synthesizes the protocol-violation case the sort+assert guard exists for.
            let pr = parse_result(vec![
                dep("aaaa", Some("1.0.0"), Some(range(0, 8, 0, 13))),
                dep("aaaa-dup", Some("1.0.0"), Some(range(0, 8, 0, 13))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("aaaa".into(), "2.0.0".to_string());
            cached.insert("aaaa-dup".into(), "3.0.0".to_string());
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(edits.len(), 1, "the overlapping later edit must be dropped");
        }
    }

    fn sample_advisory(
        id: &str,
        severity: crate::osv::VulnSeverity,
    ) -> std::sync::Arc<crate::osv::Advisory> {
        std::sync::Arc::new(crate::osv::Advisory {
            id: id.to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: Some("Something went wrong".to_string()),
            aliases: vec!["CVE-2020-0001".to_string()],
            severity,
            cvss_vector: None,
            fixed_versions: vec!["1.2.0".to_string(), "1.5.0".to_string()],
            url: format!("https://osv.dev/vulnerability/{id}"),
        })
    }

    fn dep_at(name: &str) -> MockDep {
        MockDep {
            name: PackageName::new(name),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, name.len() as u32)),
        }
    }

    #[test]
    fn test_generate_diagnostics_vulnerable_dependency_emits_advisory_diagnostic_even_without_registry_data()
     {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("vulnerable-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        // Registry data is entirely absent (as if the registry fetch failed),
        // which must never suppress the OSV finding.
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "vulnerable-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
        );

        let vuln_diag = diagnostics
            .iter()
            .find(|d| d.message.contains("RUSTSEC-2020-0071"))
            .expect("vulnerability diagnostic must be emitted even without registry data");
        assert_eq!(vuln_diag.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            vuln_diag.code,
            Some(NumberOrString::String("RUSTSEC-2020-0071".to_string()))
        );
    }

    #[test]
    fn test_generate_diagnostics_advisory_cap_emits_more_count_from_total_known() {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("noisy-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let advisories: Vec<_> = (0..ADVISORY_DISPLAY_CAP)
            .map(|i| sample_advisory(&format!("ADV-{i}"), VulnSeverity::Low))
            .collect();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "noisy-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories,
                total_known: 40,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
        );

        let more_diag = diagnostics
            .iter()
            .find(|d| d.message.contains("more advisories"))
            .expect("expected a trailing +N more advisories diagnostic");
        assert!(
            more_diag.message.contains("+35"),
            "got: {}",
            more_diag.message
        );
    }

    #[test]
    fn test_generate_diagnostics_skipped_outcome_emits_no_vulnerability_diagnostic() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("git-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert("git-pkg".into(), "1.0.0".to_string());
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "git-pkg".to_string(),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
        );

        assert!(
            diagnostics.iter().all(|d| d.code.is_none()),
            "a Skipped outcome must never render an advisory diagnostic"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_clean_outcome_states_no_known_vulnerabilities() {
        use crate::osv::{ScanOutcome, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("clean-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert("clean-pkg".to_string(), ScanOutcome::Clean);

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_skipped_outcome_says_nothing_about_vulnerabilities() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("path-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "path-pkg".to_string(),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Security advisories"));
        assert!(!content.value.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_vulnerable_outcome_shows_advisories_and_more_count() {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("bad-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "bad-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Critical)],
                total_known: 3,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "2.0.0".to_string(),
                    advisory_ids: vec!["RUSTSEC-2020-0071".to_string()],
                },
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("Security advisories"));
        assert!(content.value.contains("RUSTSEC-2020-0071"));
        assert!(content.value.contains("Fixed in"));
        assert!(
            content.value.contains("1.5.0"),
            "must show highest fixed version"
        );
        assert!(content.value.contains("+2 more advisories"));
        assert!(content.value.contains("also affected"));
    }
}
