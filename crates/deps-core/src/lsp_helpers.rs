//! Shared LSP response builders.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, CodeDescription, CodeLens, Command, Diagnostic, DiagnosticSeverity,
    Hover, HoverContents, InlayHint, InlayHintKind, InlayHintLabel, InlayHintTooltip,
    MarkupContent, MarkupKind, NumberOrString, Position, Range, TextEdit, Uri, WorkspaceEdit,
};

use crate::osv::{ADVISORY_DISPLAY_CAP, ScanOutcome, VulnerabilityMap, diagnostic_severity_for};
use crate::{
    Dependency, EcosystemConfig, InvalidPackageName, PackageName, ParseResult, PublishTime,
    Registry, Version, VersionReq, format_relative_age,
};

/// Maximum number of recent versions hover's "Recent versions" section renders.
///
/// Also the walk target for registries (NuGet, npm) that must fetch publish times for
/// only the versions actually rendered, rather than the entire version history.
pub const HOVER_RECENT_VERSIONS: usize = 8;

/// Registry version data for one package, fetched together in a single round trip.
///
/// `latest` and `available` are deliberately asymmetric — this is load-bearing, not an
/// oversight:
/// - `latest` comes from this ecosystem's own `Registry::select_latest_matching(.., "*")`
///   pick, which excludes yanked (and, for semver/node-semver `*`, prerelease) versions —
///   the same value `get_latest_matching` returned before this type existed.
/// - `available` is the **unfiltered** `get_versions` output: every published version,
///   newest-first, yanked and prerelease entries included.
///
/// The unsatisfiable-requirement check (see `crate::lsp_helpers::requirement_is_unsatisfiable`)
/// scans `available` and deliberately does not filter it: a requirement that only matches a
/// yanked or prerelease version is still satisfied, so filtering `available` the same way
/// `latest` is filtered would produce false "no published version satisfies" warnings.
///
/// `yanked` is the subset of `available` (same version-string encoding) that the registry
/// reported as yanked/deprecated. It exists because `Registry::get_latest_matching` — the
/// call that used to populate this cache — filters yanked entries out by contract on every
/// current registry implementation, so a per-version yanked flag threaded through *that*
/// call would always read `false` (see #233). `available` now comes from the unfiltered
/// `get_versions` instead, which does observe yanked entries, so `yanked` is derived from
/// that same fetch rather than discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersions {
    /// Latest usable version for this package.
    pub latest: String,
    /// Every published version, newest-first, unfiltered.
    pub available: Arc<[String]>,
    /// Subset of `available` reported as yanked/deprecated by the registry.
    pub yanked: Arc<[String]>,
}

impl PackageVersions {
    /// Builds a `PackageVersions` from only the "latest" version string, with `available`
    /// populated as the single-element list `[latest]`.
    ///
    /// **Test-only in intent.** The one-element `available` this produces is a real, if
    /// small, version list — it is not "empty/unknown", so `requirement_is_unsatisfiable`
    /// will evaluate a requirement against it. Do **not** use this for a lock-file-only
    /// population path that has no real version list to offer (use
    /// [`latest_without_list`](Self::latest_without_list) there instead, which leaves
    /// `available` genuinely empty) — that exact substitution is the false-positive N5 was
    /// written to prevent: it would let the unsatisfiable-requirement check produce a
    /// verdict against a fabricated one-entry list before any registry fetch has run. Real
    /// registry fetches always populate `available` from the full `get_versions` result
    /// instead of using either constructor.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageVersions;
    ///
    /// let versions = PackageVersions::latest_only("1.0.214");
    /// assert_eq!(versions.latest, "1.0.214");
    /// assert_eq!(&*versions.available, &["1.0.214".to_string()]);
    /// ```
    pub fn latest_only(latest: impl Into<String>) -> Self {
        let latest = latest.into();
        let available = Arc::from(vec![latest.clone()]);
        Self {
            latest,
            available,
            yanked: Arc::from(Vec::new()),
        }
    }

    /// Builds a `PackageVersions` with no version list — used where only the "latest" value
    /// is known and probing further would be misleading, notably the lock-file population
    /// path (`crates/deps-lsp/src/document/lifecycle.rs`), which must not populate a
    /// plausible-looking one-element `available` list before any registry fetch has run: the
    /// unsatisfiable-requirement check treats an empty `available` as "still loading, skip".
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageVersions;
    ///
    /// let versions = PackageVersions::latest_without_list("1.0.195");
    /// assert_eq!(versions.latest, "1.0.195");
    /// assert!(versions.available.is_empty());
    /// ```
    pub fn latest_without_list(latest: impl Into<String>) -> Self {
        Self {
            latest: latest.into(),
            available: Arc::from(Vec::new()),
            yanked: Arc::from(Vec::new()),
        }
    }
}

/// Bundles the two per-package version maps (`cached`, `resolved`) that LSP handlers pass
/// together everywhere.
///
/// Grouping them prevents accidentally swapping the two map arguments at a call site, since
/// the compiler can no longer typecheck them positionally.
///
/// # Examples
///
/// ```
/// use deps_core::{PackageName, PackageVersions, VersionData};
/// use std::collections::HashMap;
///
/// let mut cached = HashMap::new();
/// cached.insert(PackageName::new("serde"), PackageVersions::latest_only("1.0.214"));
///
/// let mut resolved = HashMap::new();
/// resolved.insert(PackageName::new("serde"), "1.0.200".to_string());
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached.get("serde").map(|v| v.latest.as_str()), Some("1.0.214"));
/// assert_eq!(versions.resolved.get("serde"), Some(&"1.0.200".to_string()));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest known versions and full version lists from the registry, keyed by package name.
    pub cached: &'a HashMap<PackageName, PackageVersions>,
    /// Versions actually resolved in the lock file, keyed by package name.
    pub resolved: &'a HashMap<PackageName, String>,
    /// OSV scan results, keyed by normalized package name. `None` when no
    /// scan has run yet (e.g. the feature is disabled) — distinct from an
    /// empty map, which would mean "scanned, nothing found".
    pub vulnerabilities: Option<&'a VulnerabilityMap>,
    /// Yanked-version findings, keyed by normalized package name -> the
    /// version string found yanked (the in-use version, or `latest` when
    /// only `latest` itself is yanked — see `deps-lsp`'s lifecycle probe).
    /// `None` when no yanked check has run yet — distinct from an empty map,
    /// which would mean "checked, nothing yanked".
    pub yanked: Option<&'a HashMap<String, String>>,
    /// Packages whose registry fetch errored or timed out during the most
    /// recent lifecycle fetch, keyed by normalized package name. Lets
    /// [`generate_diagnostics_from_cache`] distinguish "the registry was
    /// asked and said this package doesn't exist" from "the registry
    /// couldn't be asked" (#267) — a `cached` miss alone conflates both into
    /// a misleading "Unknown package" diagnostic. `None` when no fetch has
    /// run yet, same convention as [`Self::yanked`].
    pub fetch_failed: Option<&'a HashSet<String>>,
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
        cached: &'a HashMap<PackageName, PackageVersions>,
        resolved: &'a HashMap<PackageName, String>,
    ) -> Self {
        Self {
            cached,
            resolved,
            vulnerabilities: None,
            yanked: None,
            fetch_failed: None,
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

    /// Attaches yanked-version findings to this `VersionData`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let yanked = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_yanked(&yanked);
    /// assert!(versions.yanked.is_some());
    /// ```
    #[must_use]
    pub fn with_yanked(mut self, yanked: &'a HashMap<String, String>) -> Self {
        self.yanked = Some(yanked);
        self
    }

    /// Attaches the set of packages whose registry fetch failed (error or timeout)
    /// during the most recent lifecycle fetch.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::{HashMap, HashSet};
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let fetch_failed = HashSet::new();
    /// let versions = VersionData::new(&cached, &resolved).with_fetch_failed(&fetch_failed);
    /// assert!(versions.fetch_failed.is_some());
    /// ```
    #[must_use]
    pub fn with_fetch_failed(mut self, fetch_failed: &'a HashSet<String>) -> Self {
        self.fetch_failed = Some(fetch_failed);
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

    /// Absolute byte offset where `line` (0-indexed) starts, or `None` if
    /// `line` is out of range.
    ///
    /// Prefer this over re-deriving a line's start via cursor arithmetic
    /// (`cursor += line.len() + 1`): `str::lines()` strips a trailing `\r`,
    /// so that approach under-counts by one byte per CRLF line and corrupts
    /// every subsequent offset in the file. This table is built by scanning
    /// `char_indices()` for `\n` (see [`new`](Self::new)), which counts the
    /// `\r`, so it stays correct for LF, CRLF and mixed line endings alike.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let table = LineOffsetTable::new("a\r\nb\r\nc");
    /// assert_eq!(table.line_start(0), Some(0));
    /// assert_eq!(table.line_start(1), Some(3));
    /// assert_eq!(table.line_start(2), Some(6));
    /// assert_eq!(table.line_start(3), None);
    /// ```
    pub fn line_start(&self, line: usize) -> Option<usize> {
        self.line_starts.get(line).copied()
    }

    /// Converts a byte offset into an LSP `Position`.
    pub fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let offset = offset.min(content.len());
        // `offset` is not always a toml-span offset (boundary-safe by
        // construction) — the requirements.txt line parser derives offsets
        // via hand-rolled byte arithmetic, which can land inside a
        // multi-byte character (e.g. a non-ASCII comment or marker string
        // combined with an off-by-a-byte cut). Clamp down to the nearest
        // char boundary rather than panicking on the slice below.
        let mut offset = offset;
        while offset > 0 && !content.is_char_boundary(offset) {
            offset -= 1;
        }
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

/// A `requirement` compiled by one ecosystem, ready to test candidate versions against.
///
/// Produced by [`EcosystemFormatter::compile_requirement`]. Kept as a separate object
/// (rather than a single "does any version match" function) so the requirement is parsed
/// once per dependency, and so the scanning loop — including the empty-list guard, the
/// early-exit on first match, and the "skip an unparseable candidate" rule — lives once in
/// [`requirement_is_unsatisfiable`] instead of being reimplemented by all eleven ecosystems.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::RequirementMatcher;
///
/// struct ExactMatch(String);
///
/// impl RequirementMatcher for ExactMatch {
///     fn matches(&self, version: &str) -> Option<bool> {
///         Some(version == self.0)
///     }
/// }
///
/// let matcher = ExactMatch("1.0.0".to_string());
/// assert_eq!(matcher.matches("1.0.0"), Some(true));
/// assert_eq!(matcher.matches("2.0.0"), Some(false));
/// ```
pub trait RequirementMatcher: Send + Sync {
    /// Tests one candidate version string against the compiled requirement.
    ///
    /// `Some(true)` / `Some(false)`: this candidate provably does / does not satisfy the
    /// requirement. `None`: this candidate *string* could not be parsed by this ecosystem's
    /// version format (e.g. a PyPI legacy release identifier, a Maven timestamped snapshot
    /// qualifier) — the caller skips it and keeps scanning the rest of the list. Never
    /// return `None` to mean "the requirement itself is unusable"; that is
    /// [`EcosystemFormatter::compile_requirement`]'s job, via returning `None` from that
    /// method instead of constructing a matcher at all.
    fn matches(&self, version: &str) -> Option<bool>;
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

    /// Format `version` as a replacement for the existing requirement text
    /// `current`, preserving `current`'s operator/pin style where the
    /// ecosystem supports more than one.
    ///
    /// Default: ignores `current`, delegating to
    /// [`format_version_for_text_edit`](Self::format_version_for_text_edit).
    /// Override when a bare `format_version_for_text_edit` replacement would
    /// silently change the requirement's semantics — e.g. PyPI's `==1.0.1`
    /// pin becoming `>=1.0.1,<2` on "update version" would defeat the point
    /// of pinning.
    fn format_version_replacing(&self, version: &str, _current: &str) -> String {
        self.format_version_for_text_edit(version)
    }

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

    /// Compiles `requirement` into a matcher for precise membership testing against a list
    /// of candidate version strings, or `None` when this ecosystem cannot parse or cannot
    /// model this requirement form — in which case no unsatisfiable-requirement diagnostic
    /// is produced for it.
    ///
    /// Distinct from `version_satisfies_requirement`, which answers the looser "treat as up
    /// to date" question and is deliberately permissive (see that method's docs). This one
    /// gates a WARNING diagnostic claiming "no published version satisfies this
    /// requirement", so it must never guess: an ecosystem that has not opted in by
    /// overriding this method emits no such diagnostic at all, rather than one derived from
    /// a loose heuristic.
    ///
    /// `None` has two distinct causes, both correct to suppress the diagnostic for: the
    /// requirement string fails to parse under this ecosystem's own comparator (`deps-cargo`,
    /// `deps-npm`, `deps-pypi`, `deps-swift` — `.ok()` on a fallible parse), or the
    /// requirement parses fine but names a version-space region the fetched `available` list
    /// structurally cannot contain regardless — a Go pseudo-version, a Composer
    /// dev-branch/`@dev` flag, a RubyGems exact pin indistinguishable from one that matches
    /// only a yanked release, a malformed Maven/Gradle/NuGet range. Scanning either case would
    /// always decide `Some(false)` for every candidate, producing a false "no published
    /// version satisfies" verdict instead of correctly suppressing the check. Implementors of
    /// the second (predicate-guard) shape should use
    /// [`compile_requirement_unless`], which
    /// centralizes this contract instead of re-deriving it per ecosystem. `deps-dart` is the
    /// only ecosystem with neither cause: every requirement string is a valid Dart constraint
    /// by construction, so its override is always `Some`.
    ///
    /// Default: `None` — an ecosystem that has not opted in emits no unsatisfiable-requirement
    /// diagnostics.
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
    /// assert!(
    ///     DefaultFormatter
    ///         .compile_requirement(&VersionReq::new("^1.2"))
    ///         .is_none()
    /// );
    /// ```
    fn compile_requirement(
        &self,
        _requirement: &VersionReq,
    ) -> Option<Box<dyn RequirementMatcher>> {
        None
    }

    /// Whether this ecosystem's registry can silently omit a *published* version from
    /// `available` in a way indistinguishable from "never published" — and, if so, whether
    /// `requirement` names a version-space region that specific omission could explain, given
    /// the versions actually observed in `available`.
    ///
    /// Called by [`requirement_is_unsatisfiable`] before compiling `requirement`; returning
    /// `true` suppresses the "no published version satisfies this requirement" diagnostic for
    /// this dependency, the same as [`Self::compile_requirement`] returning `None` — but,
    /// unlike that method, this one sees `available` and can therefore narrow the suppression
    /// instead of disabling it for every requirement of a given shape.
    ///
    /// Default `false` — no ecosystem has this problem unless it opts in. `deps-bundler`
    /// overrides it (see `BundlerFormatter::requirement_is_undecidable_given_available` and
    /// its helper for the RubyGems-specific rationale and heuristic).
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
    /// assert!(!DefaultFormatter.requirement_is_undecidable_given_available(
    ///     &VersionReq::new("1.6.13"),
    ///     &["1.6.9".to_string(), "1.6.14".to_string()],
    /// ));
    /// ```
    fn requirement_is_undecidable_given_available(
        &self,
        _requirement: &VersionReq,
        _available: &[String],
    ) -> bool {
        false
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

    /// Whether the "requirement satisfiable only by a yanked version" diagnostic
    /// (`crate::lsp_helpers::requirement_matches_only_yanked`) should evaluate `requirement`
    /// at all for this ecosystem.
    ///
    /// Default `true` — no restriction, every requirement shape is checked. Override to
    /// `false` for a requirement shape where this ecosystem's `Version::is_yanked()` is not
    /// a genuine per-version signal. `NpmFormatter` and `ComposerFormatter` restrict this to
    /// exact-pin requirements: npm's yanked flag is sourced from `deprecated`
    /// (`NpmVersion::deprecated`), and Composer's from `abandoned`
    /// (`ComposerVersion::abandoned`) — both are commonly package-wide (a live-verified
    /// npm package had 126/126 versions marked deprecated), so evaluating a range
    /// requirement against them would flag every dependency on a deprecated/abandoned
    /// package under this diagnostic's wording, conflating it with package-level
    /// deprecation — a distinct, separately-planned diagnostic (issue #205). Restricting to
    /// an exact pin keeps this diagnostic scoped to #247's actual scenario: "you are pinned
    /// to this one specific version, and it has been yanked."
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
    /// assert!(DefaultFormatter.yanked_diagnostic_applies_to(&VersionReq::new("^1.2")));
    /// ```
    fn yanked_diagnostic_applies_to(&self, _requirement: &VersionReq) -> bool {
        true
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

    /// Converts a version string as it appears in an OSV advisory record
    /// (e.g. [`crate::osv::Advisory::fixed_versions`]) into this ecosystem's
    /// own version namespace, as used in manifests and by the registry.
    ///
    /// Default: identity — correct for ecosystems whose OSV records carry
    /// the native version string verbatim. Override when OSV's namespace
    /// diverges from the native one (Go module versions carry a `v` prefix
    /// that OSV's SEMVER ranges never use).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::lsp_helpers::EcosystemFormatter;
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
    /// assert_eq!(DefaultFormatter.osv_version_to_native("1.2.3"), "1.2.3");
    /// ```
    fn osv_version_to_native(&self, version: &str) -> String {
        version.to_string()
    }

    /// Rewrites a native-ecosystem version string into the spelling OSV.dev's
    /// SEMVER range matching expects.
    ///
    /// Deliberately the inverse of [`Self::osv_package_name`] rather than a
    /// field on [`crate::osv::ScanTarget`] itself: the caller (`deps-lsp`'s
    /// scan-target builder) has only the native version string at hand, so
    /// each ecosystem's formatter is the natural place to own the transform.
    /// The default implementation is the identity: OSV accepts every
    /// supported ecosystem's native version spelling unchanged except Go,
    /// whose module versions carry a mandatory `v` prefix
    /// (`golang.org/x/mod/module` convention) that OSV's SEMVER matcher
    /// rejects — overridden in `deps-go` to strip it.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::lsp_helpers::EcosystemFormatter;
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
    /// assert_eq!(DefaultFormatter.osv_version("1.2.3"), "1.2.3");
    /// ```
    fn osv_version(&self, version: &str) -> String {
        version.to_string()
    }

    /// Whether `dep`'s manifest version-requirement line is itself the exact
    /// version already selected — never a range.
    ///
    /// True only for a Go `require`-directive dependency: `go.mod`'s
    /// `require` line already holds the module version selected by Go's
    /// MVS, unlike Cargo/npm where the manifest holds a range and the lock
    /// file holds the pin. When true, hover and inlay hints prefer
    /// [`Dependency::version_requirement`] over the lock-file-derived entry
    /// in [`VersionData::resolved`], because `go.sum` is a checksum ledger
    /// that `go get`/`go build` only ever append to (only `go mod tidy`
    /// prunes it) — a stale, no-longer-selected higher version can remain
    /// recorded there after a downgrade and, since go.sum is written sorted
    /// ascending by semver, always sorts last and wins naive
    /// last-occurrence-wins parsing (overridden in `deps-go`; see `#235`).
    ///
    /// Takes `dep` (precedent: [`Self::osv_package_name`]) because Go's
    /// `exclude`/`replace` directives are also surfaced as dependencies
    /// whose `version_requirement()` is *not* an in-use version (the
    /// excluded version, or the replaced-from version) — the `deps-go`
    /// override inspects the directive kind and returns `true` only for
    /// `require`.
    fn manifest_requirement_is_resolved_version(&self, dep: &dyn Dependency) -> bool {
        let _ = dep;
        false
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
            .or_else(|| versions.cached.get(dep.name()))
            .map(|v| v.latest.as_str());
        let resolved_version: Option<&str> =
            if formatter.manifest_requirement_is_resolved_version(dep) {
                dep.version_requirement().map(VersionReq::as_str)
            } else {
                versions
                    .resolved
                    .get(normalized_name.as_str())
                    .or_else(|| versions.resolved.get(dep.name()))
                    .map(String::as_str)
            };

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
            if resolved == latest {
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

/// Formats the relative-age suffix for one "Recent versions" hover entry.
///
/// Returns an empty string when the registry doesn't expose a publish timestamp for
/// `version` (`published_at()` is `None`), so the entry renders exactly as it did
/// before this feature existed (graceful degradation, US-003).
///
/// `now` is taken as an explicit parameter rather than read internally so every entry
/// in the same "Recent versions" list is aged against one consistent instant.
fn version_age_suffix(version: &dyn Version, now: PublishTime) -> String {
    version
        .published_at()
        .map(|published| format!(" — {}", format_relative_age(published.age_secs_from(now))))
        .unwrap_or_default()
}

pub async fn generate_hover<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    versions: VersionData<'_>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    freshness: crate::freshness::FreshnessSettings,
) -> Option<Hover> {
    use std::fmt::Write;

    let dep = parse_result.dependencies().into_iter().find(|d| {
        let on_name = position_in_range(position, d.name_range());
        let on_version = d
            .version_range()
            .is_some_and(|r| position_in_range(position, r));
        on_name || on_version
    })?;

    // A non-resolvable source (e.g. `CustomRegistry`, Git, Path) doesn't resolve
    // against `registry` at all — fetching by name here would silently check an
    // unrelated or coincidentally-named public-registry package (#248), so hover
    // must skip the registry lookup and every section built from it entirely.
    let resolvable = dep.source().is_version_resolvable();

    let available_versions = if resolvable {
        Some(
            registry
                .get_versions_with(dep.name(), freshness)
                .await
                .ok()?,
        )
    } else {
        None
    };

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

    let resolved: Option<&str> = if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement().map(VersionReq::as_str)
    } else {
        versions
            .resolved
            .get(normalized_name.as_str())
            .or_else(|| versions.resolved.get(dep.name()))
            .map(String::as_str)
    };
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

    let latest = resolvable
        .then(|| {
            versions
                .cached
                .get(normalized_name.as_str())
                .or_else(|| versions.cached.get(dep.name()))
                .map(|v| v.latest.as_str())
        })
        .flatten();
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

    if let Some(available_versions) = &available_versions {
        markdown.push_str("**Recent versions**:\n");
        let now = PublishTime::now();
        for (i, version) in available_versions
            .iter()
            .take(HOVER_RECENT_VERSIONS)
            .enumerate()
        {
            let version_span = markdown_code_span(version.version_string());
            let age_suffix = if freshness.enabled {
                version_age_suffix(version.as_ref(), now)
            } else {
                String::new()
            };
            if i == 0 {
                writeln!(&mut markdown, "- {version_span} *(latest)*{age_suffix}").unwrap();
            } else if version.is_yanked() {
                writeln!(
                    &mut markdown,
                    "- {} {}{}",
                    version_span,
                    formatter.yanked_label(),
                    age_suffix
                )
                .unwrap();
            } else {
                writeln!(&mut markdown, "- {version_span}{age_suffix}").unwrap();
            }
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

/// The vulnerability-fix quickfix built by [`build_vulnerability_fix_action`],
/// bundled with the native-namespace version it targets so callers can dedup
/// display items and check the registry's yank flag against it without
/// re-parsing the action's title.
struct VulnerabilityFixAction {
    /// `fix.version`, converted to this ecosystem's namespace via
    /// [`EcosystemFormatter::osv_version_to_native`].
    version_native: String,
    /// The formatted edit text this action's own `TextEdit` writes — the exact
    /// value `action.edit` carries, kept alongside it so callers (the REFACTOR-loop
    /// dedup in [`generate_code_actions`]) can compare against it without
    /// recomputing `format_version_replacing` and risking the copy silently
    /// drifting from the actual edit if that computation ever changes.
    new_text: String,
    action: CodeAction,
}

/// Builds the "fix vulnerability" quickfix for `dep`, if OSV data
/// recommends one.
///
/// Registry-independent by construction (FR-007, mirroring the rule already
/// enforced in [`generate_diagnostics_from_cache`]): computed entirely from
/// `versions.vulnerabilities` and `version_req` (the caller's already-fetched
/// `dep.version_requirement()`), never from a registry fetch. Callers must
/// still reconcile the result against a successful registry fetch when one
/// is available — see the yank check in [`generate_code_actions`].
fn build_vulnerability_fix_action(
    dep: &dyn Dependency,
    uri: &Uri,
    version_range: Range,
    versions: VersionData<'_>,
    version_req: &str,
    formatter: &dyn EcosystemFormatter,
) -> Option<VulnerabilityFixAction> {
    let normalized_name = formatter.normalize_package_name(dep.name());
    let outcome = versions.vulnerabilities.and_then(|m| {
        m.get(&normalized_name)
            .or_else(|| m.get(dep.name().as_str()))
    })?;
    let ScanOutcome::Vulnerable(dv) = outcome else {
        return None;
    };
    let fix = dv.recommended_fix()?;
    let version_native = formatter.osv_version_to_native(&fix.version);
    // Computed before the N1 guard below against the *same* formatting the
    // plain "update version" action uses (`format_version_replacing`), not
    // the bare version: several ecosystems wrap or expand it (`deps-dart`'s
    // `^`-prefix, a range), and `deps-pypi` rewrites it in place to preserve
    // the manifest's existing pin style (`==1.0.1` -> `==1.0.2`) — the guard
    // must compare the text that would actually be written.
    let new_text = formatter.format_version_replacing(&version_native, version_req);

    // N1: skip a no-op edit — the manifest already declares exactly the text
    // this action would write, so applying it would rewrite the text to
    // itself. Whitespace-insensitive, mirroring `literal_span_matches`:
    // `version_req` can be a normalized requirement string with spacing the
    // declared text and the freshly-formatted text don't agree on (e.g.
    // pep508's `>=1.7, <2.0` vs. a formatter's `>=1.7,<2.0`), which would
    // otherwise let a whitespace-only edit slip past this guard.
    if strip_whitespace(version_req) == strip_whitespace(&new_text) {
        return None;
    }

    // S3: the scan target may have been the lockfile-resolved version, not
    // the declared requirement — rewriting the manifest alone would then not
    // clear the diagnostic until the lockfile is regenerated. Say so in the
    // title rather than silently overclaiming.
    let lockfile_hit = versions
        .resolved
        .get(normalized_name.as_str())
        .or_else(|| versions.resolved.get(dep.name()))
        .is_some();

    // Names only the first (worst-severity, per `recommended_fix`'s sort)
    // advisory id and summarizes the rest — `recommended_fix` can return an
    // unbounded number of ids (up to `ADVISORY_DISPLAY_CAP`), and a title
    // listing every one of them would overflow an editor's code-action menu.
    let (first_id, rest_ids) = fix.advisory_ids.split_first()?;
    let fixes = if rest_ids.is_empty() {
        first_id.clone()
    } else {
        format!("{first_id} +{} more", rest_ids.len())
    };
    let title = if lockfile_hit {
        format!("Update to {version_native} (fixes {fixes}; update lockfile to apply)")
    } else {
        format!("Update to {version_native} (fixes {fixes})")
    };

    let mut edits = HashMap::new();
    edits.insert(
        uri.clone(),
        vec![TextEdit {
            range: version_range,
            new_text: new_text.clone(),
        }],
    );

    Some(VulnerabilityFixAction {
        version_native,
        new_text,
        action: CodeAction {
            title,
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            is_preferred: Some(true),
            // Stashes the resolved advisory ids so the `deps-lsp` handler can
            // bind this action to the matching client-supplied diagnostics
            // (`CodeActionContext::diagnostics`) without deps-core needing to
            // know about LSP request context — cleared by the handler once
            // consumed.
            data: Some(serde_json::json!({ "advisory_ids": fix.advisory_ids })),
            ..Default::default()
        },
    })
}

/// Generates the code actions offered for the dependency at `position`.
///
/// Finds the dependency whose declared version `position` falls on
/// (`formatter.is_position_on_dependency`). Returns an empty `Vec`
/// immediately if no dependency is at `position`, it has no `version_range`
/// to edit, it has no declared (or an empty) `version_requirement`, or the
/// **literal-span guard** rejects it — `content` sliced over `version_range`
/// no longer holds the literal requirement text (see `literal_span_matches`,
/// e.g. a Maven `${property}` reference, a Gradle DSL variable/alias, or a
/// synthesized comparator's lower bound). Writing a `TextEdit` at that range
/// would corrupt the manifest instead of fixing it, so this mirrors the
/// guard `collect_update_all_edits` already applies on the bulk-edit path,
/// and gates *both* kinds of action below since either could write there.
///
/// Otherwise returns up to two kinds of action, in this order:
///
/// 1. At most one `QUICKFIX` "fix vulnerability" action, if `versions`
///    carries an OSV scan result flagging this dependency and
///    [`crate::osv::DependencyVulnerabilities::recommended_fix`] has a
///    claimable target (see the private `build_vulnerability_fix_action` helper
///    just above). This action
///    is computed entirely from `versions` and the dependency's declared
///    requirement, deliberately *before* the `registry.get_versions` call
///    below — a registry outage must never hide a known-vulnerable
///    dependency's fix (FR-007), so this action is still returned even when
///    the registry fetch that produces the plain list below fails. When the
///    fetch does succeed, a fix target the registry reports as yanked is
///    dropped rather than offered.
/// 2. Up to five plain `REFACTOR` "update to `<version>`" actions, one per
///    non-yanked version [`crate::completion::prepare_version_display_items`]
///    selects from the registry response, and demoting `is_preferred` to
///    `None` on all of them when a fix action is present, since only one
///    preferred action is meaningful per response. Each action's edit text
///    comes from [`EcosystemFormatter::format_version_replacing`], which
///    preserves the manifest's existing pin/operator style where an
///    ecosystem overrides it (e.g. PyPI's `==1.0.1` stays `==1.0.2` rather
///    than expanding to a `>=,<` range). Every entry's formatted edit text is
///    checked against a running set seeded with the declared requirement and
///    the fix action's own formatted text (whitespace-insensitive); an entry
///    is skipped, and never added to the set, when its text is already
///    present. This is the common case, not a rare edge case:
///    [`crate::completion::prepare_version_display_items`] lists the top 5
///    non-yanked registry versions newest-first, so whenever the declared
///    version is already within 5 releases of latest, it is itself one of
///    the display items being offered as an "update". The same set also
///    catches two display items whose formatted text coincides — e.g. an
///    ecosystem formatter that truncates precision (PyPI's
///    `truncate_release_to_match`) can map several distinct registry
///    versions to the same rewritten text — and a display item matching the
///    fix action's target even when their *raw* versions differ (formatting
///    can normalize two distinct inputs to the same text). Textual (not
///    semantic) equality is deliberate: `formatter.is_requirement_up_to_date`
///    answers "does `latest` already satisfy this requirement", which is
///    true for e.g. `is_requirement_up_to_date("^1.0", "1.2.0")` and would
///    wrongly suppress every explicit-bump action for a range-style
///    requirement; it also can't detect a pinned no-op like `==1.0.0` ->
///    `==1.0.0`, since it never compares the formatted edit text at all.
///
/// Returns an empty `Vec` also when (no fix action applies and) the registry
/// fetch fails.
///
/// No `# Examples` here: exercising this meaningfully needs a `Registry`
/// impl plus `ParseResult`/`Dependency` mocks, which live as private test
/// fixtures in this module's own `#[cfg(test)]` block rather than as public
/// API — see the `generate_code_actions_*` tests there for realistic calls.
// TODO(#206-followup): unsatisfiable quick-fix needs context.diagnostics + latest
// threaded into generate_code_actions.
pub async fn generate_code_actions<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    uri: &Uri,
    versions: VersionData<'_>,
    content: &str,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Vec<CodeAction> {
    use crate::completion::prepare_version_display_items;

    let deps = parse_result.dependencies();
    let mut actions = Vec::with_capacity(deps.len().min(5) + 1);

    let Some(dep) = deps
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position))
    else {
        return actions;
    };

    let Some(version_range) = dep.version_range() else {
        return actions;
    };

    let Some(version_req) = dep.version_requirement() else {
        return actions;
    };
    if version_req.as_str().is_empty() {
        // Defense-in-depth, mirroring `collect_update_all_edits`: an empty
        // requirement would trivially satisfy the guard below.
        return actions;
    }

    let line_offsets = LineOffsetTable::new(content);
    let slice = slice_for_range(content, &line_offsets, version_range);
    if !literal_span_matches(slice, version_req.as_str()) {
        // `version_range` no longer slices to the declared requirement text
        // (e.g. a Maven `${property}`, a Gradle DSL variable/alias, or a
        // synthesized comparator's lower bound) — writing a TextEdit there
        // would corrupt the manifest instead of fixing it. Mirrors the guard
        // `collect_update_all_edits` already applies on the bulk-edit path.
        return actions;
    }

    // Built before the registry fetch below so a registry outage never
    // suppresses an OSV-derived fix (FR-007).
    let fix = build_vulnerability_fix_action(
        dep,
        uri,
        version_range,
        versions,
        version_req.as_str(),
        formatter,
    );

    let Ok(registry_versions) = registry.get_versions(dep.name()).await else {
        if let Some(fix) = fix {
            actions.push(fix.action);
        }
        return actions;
    };

    // S4: a fix target that the registry reports as yanked is dropped
    // entirely rather than offered — the surviving diagnostics carry the
    // finding either way, and there is no comparator here to bound a search
    // for an alternative target.
    let fix = fix.filter(|f| {
        !registry_versions
            .iter()
            .find(|v| v.version_string() == f.version_native)
            .is_some_and(|v| v.is_yanked())
    });

    let fix_version_native = fix.as_ref().map(|f| f.version_native.clone());
    // Captured before `fix.action` moves into `actions` below, so the dedup seeding
    // reads back the exact text the fix action's own `TextEdit` already carries
    // instead of recomputing it (see `VulnerabilityFixAction::new_text`'s doc comment).
    let fix_new_text = fix.as_ref().map(|f| strip_whitespace(&f.new_text));
    if let Some(fix) = fix {
        actions.push(fix.action);
    }

    let display_items = prepare_version_display_items(&registry_versions, dep.name());
    // De-duplicates every REFACTOR action's formatted edit text against the declared
    // requirement, the fix action's edit (if any), and every REFACTOR action already
    // emitted below, so no two actions in the response — nor a REFACTOR action and the
    // fix action above — ever carry a byte-identical `WorkspaceEdit`. Seeding with the
    // declared requirement subsumes the former N1 guard (an item whose formatted text
    // equals the declared text is a no-op); checking formatted text rather than raw
    // version also subsumes the former `item.version == fix_version_native` check, since
    // `format_version_replacing` is deterministic in its inputs. Whitespace-insensitive,
    // matching every other no-op guard in this module (see `strip_whitespace`).
    let mut emitted_texts: HashSet<String> = HashSet::new();
    emitted_texts.insert(strip_whitespace(version_req.as_str()));
    if let Some(fix_text) = fix_new_text {
        emitted_texts.insert(fix_text);
    }

    for item in display_items {
        let new_text = formatter.format_version_replacing(&item.version, version_req.as_str());

        if !emitted_texts.insert(strip_whitespace(&new_text)) {
            continue;
        }

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
            // Only one preferred action is meaningful; the fix action above
            // takes that role when present.
            is_preferred: (fix_version_native.is_none()).then_some(item.is_latest),
            ..Default::default()
        });
    }

    actions
}

/// Diagnostic severity levels for the four per-dependency issue categories.
///
/// Threaded from `DiagnosticsConfig` (`deps-lsp`) through
/// [`crate::Ecosystem::generate_diagnostics`] into [`generate_diagnostics_from_cache`]
/// and [`generate_diagnostics`].
///
/// # Examples
///
/// ```
/// use deps_core::DiagnosticSeverities;
/// use tower_lsp_server::ls_types::DiagnosticSeverity;
///
/// let severities = DiagnosticSeverities::default();
/// assert_eq!(severities.outdated, DiagnosticSeverity::HINT);
/// assert_eq!(severities.unknown, DiagnosticSeverity::WARNING);
/// assert_eq!(severities.yanked, DiagnosticSeverity::WARNING);
/// assert_eq!(severities.unsatisfiable, DiagnosticSeverity::WARNING);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticSeverities {
    /// Severity for a dependency with a newer version available.
    pub outdated: DiagnosticSeverity,
    /// Severity for a dependency not found in the registry (or with an invalid name).
    pub unknown: DiagnosticSeverity,
    /// Severity for a dependency pinned to a yanked/deprecated version.
    pub yanked: DiagnosticSeverity,
    /// Severity for a dependency whose requirement matches zero published versions.
    pub unsatisfiable: DiagnosticSeverity,
}

impl Default for DiagnosticSeverities {
    fn default() -> Self {
        Self {
            outdated: DiagnosticSeverity::HINT,
            unknown: DiagnosticSeverity::WARNING,
            yanked: DiagnosticSeverity::WARNING,
            unsatisfiable: DiagnosticSeverity::WARNING,
        }
    }
}

/// Shared shape for a [`EcosystemFormatter::compile_requirement`] guarded by one predicate.
///
/// This is the pattern several ecosystems' guards independently re-implemented
/// (`deps-go`'s pseudo-version check, `deps-composer`'s dev-branch/`@dev` check,
/// `deps-bundler`'s exact-pin check, `deps-maven`/`deps-gradle`'s malformed-range check,
/// `deps-nuget`'s malformed-requirement check). See
/// [`EcosystemFormatter::compile_requirement`]'s docs for why `None` is correct in exactly
/// this case: `is_undecidable(requirement)` true means the fetched `available` list
/// structurally cannot contain a version that would decide the match either way, so scanning
/// it would always report `Some(false)` and produce a false "no published version satisfies
/// this requirement" diagnostic.
///
/// Returns `None` when `is_undecidable(requirement)` is `true`. Otherwise builds `matcher`
/// from `requirement`'s owned `String` and boxes it as the trait object
/// [`EcosystemFormatter::compile_requirement`] returns.
///
/// Ecosystems whose guard is a fallible parse rather than a named predicate over the
/// requirement string (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-swift`) don't fit this
/// shape and implement `compile_requirement` directly via `.ok().map(...)` instead.
/// `deps-dart` implements `compile_requirement` but has no guard at all — every requirement
/// string is a valid Dart constraint by construction, so it is always `Some`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{compile_requirement_unless, RequirementMatcher};
///
/// struct ExactMatcher(String);
/// impl RequirementMatcher for ExactMatcher {
///     fn matches(&self, version: &str) -> Option<bool> {
///         Some(version == self.0)
///     }
/// }
///
/// let is_pseudo_version = |r: &str| r.starts_with("v0.0.0-");
///
/// assert!(
///     compile_requirement_unless(
///         "v0.0.0-20191109021931-daa7c04131f5",
///         is_pseudo_version,
///         ExactMatcher,
///     )
///     .is_none()
/// );
/// assert!(compile_requirement_unless("v1.2.3", is_pseudo_version, ExactMatcher).is_some());
/// ```
pub fn compile_requirement_unless<M>(
    requirement: &str,
    is_undecidable: impl FnOnce(&str) -> bool,
    matcher: impl FnOnce(String) -> M,
) -> Option<Box<dyn RequirementMatcher>>
where
    M: RequirementMatcher + 'static,
{
    if is_undecidable(requirement) {
        return None;
    }
    Some(Box::new(matcher(requirement.to_string())))
}

/// Requirement strings longer than this are rejected by [`requirement_is_unsatisfiable`]
/// before compilation, rather than compiled and scanned. No real manifest requirement in any
/// supported ecosystem approaches this length; it exists solely to bound the cost of an
/// adversarial or corrupted requirement string. All eleven ecosystems' `compile_requirement`
/// implementations now parse `requirement` exactly once per dependency and reuse the parsed
/// form across every candidate in `matches` — Maven/Gradle/NuGet's `RequirementMatcher`s were
/// the last holdouts re-parsing per candidate, fixed alongside this comment — so the scan
/// itself is O(`available.len()`) in the size of the candidate list, not the requirement.
/// This cap stays as defense-in-depth against the one-time parse cost: Maven's range union
/// can still degrade non-linearly on a pathological multi-KB comma union, and a stray
/// oversized string is never a real requirement, only a corrupted or adversarial one.
const MAX_REQUIREMENT_LEN: usize = 256;

/// Returns `true` when no published version satisfies `requirement`.
///
/// `available` must be non-empty, `requirement` must be a concrete (non-empty, resolved,
/// not implausibly long) constraint, and no entry in `available` — of any kind: stable,
/// prerelease, or yanked — may satisfy it. All of the following must hold for `true`:
///
/// 1. `!available.is_empty()` — an empty or not-yet-loaded list means "unknown", not
///    "unsatisfiable" (FR-004: no diagnostic while loading or offline).
/// 2. `!requirement.as_str().trim().is_empty()`.
/// 3. `requirement.as_str().len() <= MAX_REQUIREMENT_LEN` — see that constant's docs; an
///    oversized requirement is treated the same as "unmodellable" (suppressed, not warned).
/// 4. `!formatter.requirement_is_unresolved(requirement)` (FR-005) — an unresolved
///    placeholder requirement was never actually checked against anything.
/// 5. `!formatter.requirement_is_undecidable_given_available(requirement, available)` — this
///    ecosystem's registry can hide a published version that would have decided the match.
/// 6. `formatter.compile_requirement(requirement)` returns `Some(matcher)` — this
///    ecosystem opted in and the requirement string itself parses.
/// 7. Scanning `available` with `matcher.matches`: **at least one** candidate returned
///    `Some(false)`, and **none** returned `Some(true)`. Candidates returning `None`
///    (unparseable candidate strings) are skipped and count toward neither side —
///    condition 7's "at least one `Some(false)`" is load-bearing: if every candidate is
///    unparseable, nothing was decided, so the verdict is `false` (no diagnostic) rather
///    than a vacuous `true`.
///
/// The scan short-circuits on the first `Some(true)` — O(N) worst case, and the newest-first
/// ordering of `available` means a satisfiable requirement typically exits within the first
/// few entries.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{requirement_is_unsatisfiable, EcosystemFormatter, RequirementMatcher};
/// use deps_core::{PackageName, VersionReq};
///
/// struct ExactMatcher(String);
/// impl RequirementMatcher for ExactMatcher {
///     fn matches(&self, version: &str) -> Option<bool> {
///         Some(version == self.0)
///     }
/// }
///
/// struct ExactFormatter;
/// impl EcosystemFormatter for ExactFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
///     fn compile_requirement(
///         &self,
///         requirement: &VersionReq,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
///     }
/// }
///
/// let available = vec!["1.0.0".to_string(), "0.9.0".to_string()];
/// assert!(requirement_is_unsatisfiable(
///     &ExactFormatter,
///     &VersionReq::new("2.0.0"),
///     &available,
/// ));
/// assert!(!requirement_is_unsatisfiable(
///     &ExactFormatter,
///     &VersionReq::new("1.0.0"),
///     &available,
/// ));
/// ```
pub fn requirement_is_unsatisfiable(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[String],
) -> bool {
    if available.is_empty() || requirement.as_str().trim().is_empty() {
        return false;
    }
    if requirement.as_str().len() > MAX_REQUIREMENT_LEN {
        return false;
    }
    if formatter.requirement_is_unresolved(requirement) {
        return false;
    }
    if formatter.requirement_is_undecidable_given_available(requirement, available) {
        return false;
    }
    let Some(matcher) = formatter.compile_requirement(requirement) else {
        return false;
    };

    let mut saw_decided_false = false;
    for candidate in available {
        match matcher.matches(candidate) {
            Some(true) => return false,
            Some(false) => saw_decided_false = true,
            None => {}
        }
    }
    saw_decided_false
}

/// Returns `true` when `requirement` is satisfied by at least one entry in `available`, but
/// every matching entry is yanked — i.e. the dependency is currently satisfiable only by a
/// yanked/deprecated version.
///
/// Mutually exclusive with [`requirement_is_unsatisfiable`]: both scan `available` through the
/// same `formatter.compile_requirement` matcher, but this one additionally cross-references
/// `yanked` (see [`PackageVersions::yanked`]) to distinguish "satisfied, but only by a yanked
/// version" from "satisfied by an ordinary version" or "not satisfied at all". Callers should
/// only invoke this once `requirement_is_unsatisfiable` has returned `false` for the same
/// `requirement`/`available` pair, so a match is already known to exist.
///
/// Shares `requirement_is_unsatisfiable`'s guard cascade (empty `available`/`requirement`,
/// oversized `requirement`, unresolved placeholder `requirement`, uncompilable `requirement`)
/// — each returns `false` here for the identical reason it does there.
///
/// Unlike `requirement_is_unsatisfiable`, an undecided candidate (`matcher.matches` returns
/// `None` — an unparseable candidate string) does not just get skipped: it disqualifies a
/// `true` verdict entirely. That candidate might have been a genuine non-yanked match this
/// scan simply could not evaluate, so claiming "every match is yanked" without accounting for
/// it would be a false positive — the same #206 conservatism (nothing decided means no
/// diagnostic, not a guess) applied to a different question than `requirement_is_unsatisfiable`
/// asks.
fn requirement_matches_only_yanked(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[String],
    yanked: &[String],
) -> bool {
    if available.is_empty() || yanked.is_empty() || requirement.as_str().trim().is_empty() {
        return false;
    }
    if requirement.as_str().len() > MAX_REQUIREMENT_LEN {
        return false;
    }
    if formatter.requirement_is_unresolved(requirement) {
        return false;
    }
    let Some(matcher) = formatter.compile_requirement(requirement) else {
        return false;
    };

    let mut saw_match = false;
    let mut saw_undecided = false;
    for candidate in available {
        match matcher.matches(candidate) {
            Some(true) => {
                saw_match = true;
                if !yanked.iter().any(|y| y == candidate) {
                    return false;
                }
            }
            Some(false) => {}
            None => saw_undecided = true,
        }
    }
    saw_match && !saw_undecided
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
/// * `severities` - Configured severity for each diagnostic category
pub fn generate_diagnostics_from_cache(
    parse_result: &dyn ParseResult,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
    _freshness: crate::freshness::FreshnessSettings,
    severities: DiagnosticSeverities,
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

        // Independent of the registry-outage/no-range early-`continue`s below,
        // for the same reason as the vulnerability push above — a yanked
        // finding from the lifecycle probe must never be suppressed by an
        // unrelated "latest" lookup failure.
        //
        // Two independent yanked-version checks exist and both run in this loop:
        // this one (#263) flags the specific in-use version (lockfile-resolved,
        // or an exact manifest pin) when it is yanked, while `yanked_only` below
        // (#247) flags a declared *range* requirement that can currently only be
        // satisfied by a yanked version, even with no lockfile at all. They answer
        // different questions and neither subsumes the other, but for a dependency
        // pinned to the one version that also happens to be the only version
        // satisfying its own requirement, both would fire on the same dependency.
        // `yanked_diagnostic_pushed` suppresses the second (#247) check once the
        // first (#263) already emitted a diagnostic for this dependency, so a
        // single dependency never gets two yanked diagnostics.
        //
        // The two checks deliberately keep different outdated-interaction policies —
        // this is not an oversight left over from the merge. This (#263) check has no
        // `continue`, so it co-emits alongside an "outdated" diagnostic for the same
        // dependency (see `test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted`,
        // asserting exactly that on the upstream #263 design). `yanked_only` below
        // (#247) does `continue`, suppressing "outdated" for the same dependency (see
        // `test_yanked_only_match_suppresses_outdated_diagnostic`). Each policy was
        // independently reviewed and tested before this merge; harmonizing them is out
        // of scope here.
        let yanked_diagnostic_pushed =
            if let Some(yanked_version) = versions.yanked.and_then(|y| y.get(&normalized_name)) {
                diagnostics.push(Diagnostic {
                    range: dep.version_range().unwrap_or_else(|| dep.name_range()),
                    severity: Some(severities.yanked),
                    message: format!("{} ({})", formatter.yanked_message(), yanked_version),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                true
            } else {
                false
            };

        let package_versions = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()));

        let Some(package_versions) = package_versions else {
            // Skip "unknown" diagnostic if package exists in lock file
            // (registry fetch may have failed due to rate limiting), or if
            // the source isn't resolvable against the registry this LSP
            // queries (e.g. `CustomRegistry` / Git / Path) — an absent cache
            // entry there just means we never fetched it, not that the
            // package doesn't exist (#248). Name-syntax validation is
            // unaffected: it never depends on registry data.
            let in_lockfile = versions.resolved.contains_key(normalized_name.as_str())
                || versions.resolved.contains_key(dep.name());
            if !in_lockfile {
                // A fetch error/timeout (#267) is not evidence the package doesn't
                // exist — the registry was never successfully asked. Report it
                // distinctly from a genuine "not found" so a transient registry
                // outage or a malformed response (e.g. unparseable
                // maven-metadata.xml) doesn't masquerade as "Unknown package".
                let fetch_failed = dep.source().is_version_resolvable()
                    && versions
                        .fetch_failed
                        .is_some_and(|f| f.contains(normalized_name.as_str()));
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => Some(format!("Invalid package name '{}': {reason}", dep.name())),
                    Ok(()) if fetch_failed => Some(format!(
                        "Registry lookup failed for '{}'; package status could not be determined",
                        dep.name()
                    )),
                    Ok(()) if dep.source().is_version_resolvable() => {
                        Some(format!("Unknown package '{}'", dep.name()))
                    }
                    Ok(()) => None,
                };
                if let Some(message) = message {
                    diagnostics.push(Diagnostic {
                        range: dep.name_range(),
                        severity: Some(severities.unknown),
                        message,
                        source: Some("deps-lsp".into()),
                        ..Default::default()
                    });
                }
            }
            continue;
        };
        let latest = package_versions.latest.as_str();

        let Some(version_range) = dep.version_range() else {
            continue;
        };

        // Path/git/URL/SDK/workspace dependencies never resolve against a
        // registry version list at all — `package_versions` (when present)
        // either came from a coincidentally-matching registry entry of the
        // same name (e.g. this workspace's own `deps-core = { path = ...
        // version = "0.10.1" }`, which only avoids a false WARNING today
        // because 0.10.1 also happens to be published) or an entirely
        // unrelated package (Dart's `{ sdk: flutter, version = "^3.24.0" }`
        // resolves against pub.dev's unrelated `flutter` package). Neither
        // is a meaningful "no published version satisfies this" check.
        let unsatisfiable = dep.source().is_version_resolvable()
            && dep.version_requirement().is_some_and(|version_req| {
                requirement_is_unsatisfiable(formatter, version_req, &package_versions.available)
            });

        if unsatisfiable {
            let req_str = dep.version_requirement().map_or("", |r| r.as_str());
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.unsatisfiable),
                message: format!(
                    "No published version satisfies requirement '{req_str}'; latest is {latest}"
                ),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
            continue;
        }

        // Same source-resolvability guard as `unsatisfiable` above — only meaningful once a
        // requirement is known to match *something* in `available` (see `requirement_is_unsatisfiable`).
        // `yanked_diagnostic_applies_to` additionally opts an ecosystem out for a requirement
        // shape where `is_yanked()` is not a genuine per-version signal (npm/Composer restrict
        // to exact pins — see that method's docs). Skipped entirely when the in-use-version
        // check above already pushed a yanked diagnostic for this dependency (see
        // `yanked_diagnostic_pushed`), so the two checks never double-report.
        let yanked_only = !yanked_diagnostic_pushed
            && dep.source().is_version_resolvable()
            && dep.version_requirement().is_some_and(|version_req| {
                formatter.yanked_diagnostic_applies_to(version_req)
                    && requirement_matches_only_yanked(
                        formatter,
                        version_req,
                        &package_versions.available,
                        &package_versions.yanked,
                    )
            });

        if yanked_only {
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.yanked),
                message: format!("{}; latest is {latest}", formatter.yanked_message()),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
            continue;
        }

        // As with the unsatisfiable check above, a non-resolvable source's `latest`
        // (when present at all) comes from an unrelated or coincidental cache entry,
        // not a real lookup against the registry this dependency actually resolves
        // against — so "Outdated" must not be evaluated for it either (#248).
        let status = match dep.version_requirement() {
            Some(version_req) if dep.source().is_version_resolvable() => {
                formatter.requirement_status(version_req, latest)
            }
            _ => RequirementStatus::Unresolved,
        };

        if status == RequirementStatus::Outdated {
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.outdated),
                message: format!("Newer version available: {}", latest),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
        }
    }

    diagnostics
}

/// Strips every whitespace character from `s`, so two textually-equivalent strings that
/// differ only in spacing compare equal.
///
/// Shared by every no-op/literal-match guard in this module (`build_vulnerability_fix_action`'s
/// N1 guard, `generate_code_actions`'s REFACTOR-loop guard, `literal_span_matches`, and
/// `collect_update_all_edits`'s no-op guard), all of which compare a declared requirement
/// string against a differently-normalized counterpart — e.g. pep508's `>=1.7, <2.0` vs. a
/// formatter's `>=1.7,<2.0`.
fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
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
    let norm_slice = strip_whitespace(slice);
    let norm_req = strip_whitespace(requirement);
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
/// use deps_core::lsp_helpers::{
///     collect_update_all_edits, EcosystemFormatter, PackageVersions, VersionData,
/// };
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
/// cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
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
            .map(|v| v.latest.as_str())
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

        let new_text = formatter.format_version_replacing(latest, version_req.as_str());
        // No-op guard, mirroring the REFACTOR-loop dedup and vulnerability-fix N1
        // guard elsewhere in this module: a formatter can decide a declared
        // requirement has no single unambiguous rewrite (e.g. `deps-gradle`'s
        // `{strictly}!!{preferred}` shorthand, left unchanged rather than risking a
        // destructive or misleading edit) and return it unchanged. Without this
        // check, such a dependency would still count toward — and appear fixed
        // by — the "Update N outdated dependencies" lens while its click applies
        // nothing.
        if strip_whitespace(&new_text) == strip_whitespace(version_req.as_str()) {
            continue;
        }

        edits.push(TextEdit {
            range: version_range,
            new_text,
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
/// re-exported as `deps_core::lsp_generate_diagnostics`. Does not emit a yanked-version
/// diagnostic: `get_latest_matching`'s trait contract filters yanked versions by default
/// (see [`Registry::get_latest_matching`]), so the version it returns is never yanked
/// under a normal requirement (#233).
pub async fn generate_diagnostics<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    _freshness: crate::freshness::FreshnessSettings,
    severities: DiagnosticSeverities,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        // Deliberately `get_versions`, not `get_versions_with`: diagnostics render no
        // publish ages, so paying for a registry's extra freshness fetch here would be
        // pure waste. This function is not called anywhere in this workspace (see the
        // doc comment above), so `_freshness` stays unused by design, not oversight.
        let versions = match registry.get_versions(dep.name()).await {
            Ok(v) => v,
            Err(e) => {
                // Same distinction as `generate_diagnostics_from_cache`/`FetchResult::fetch_failed`
                // (#267): a genuine not-found means the registry answered "no such package",
                // while any other error means the registry couldn't be asked at all.
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => format!("Invalid package name '{}': {reason}", dep.name()),
                    Ok(()) if e.is_not_found() => format!("Unknown package '{}'", dep.name()),
                    Ok(()) => format!(
                        "Registry lookup failed for '{}'; package status could not be determined",
                        dep.name()
                    ),
                };
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(severities.unknown),
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

        if matching.is_some() {
            let latest = crate::registry::find_latest_stable(&versions);
            if let Some(latest) = latest
                && formatter.requirement_status(version_req, latest.version_string())
                    == RequirementStatus::Outdated
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(severities.outdated),
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
    fn test_line_offset_table_line_start_crlf() {
        let table = LineOffsetTable::new("a\r\nbb\r\nc");
        assert_eq!(table.line_start(0), Some(0));
        assert_eq!(table.line_start(1), Some(3));
        assert_eq!(table.line_start(2), Some(7));
        assert_eq!(table.line_start(3), None);
    }

    #[test]
    fn test_byte_offset_to_position_clamps_to_char_boundary_instead_of_panicking() {
        // "é" is a 2-byte UTF-8 sequence; offset 1 lands inside it.
        let content = "é";
        let table = LineOffsetTable::new(content);
        // Must not panic; clamps down to the nearest boundary (offset 0).
        let pos = table.byte_offset_to_position(content, 1);
        assert_eq!(pos, Position::new(0, 0));
    }

    #[test]
    fn test_byte_offset_to_position_multi_byte_boundary_in_longer_line() {
        let content = "ab é cd";
        let table = LineOffsetTable::new(content);
        // Byte 3 is 'é's leading byte (boundary); byte 4 is its continuation
        // byte (not a boundary) and must clamp back to 3 rather than panic.
        assert!(content.is_char_boundary(3));
        assert!(!content.is_char_boundary(4));
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos, table.byte_offset_to_position(content, 3));
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

    /// Formatter stub mirroring `GoFormatter`'s override: reports the manifest
    /// version-requirement line (go.mod's `require`) as itself the resolved
    /// version, since it is already the exact MVS-selected version (#235).
    struct MockGoFormatter;

    impl EcosystemFormatter for MockGoFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://pkg.go.dev/{}", name)
        }

        fn manifest_requirement_is_resolved_version(&self, _dep: &dyn Dependency) -> bool {
            true
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

    /// A registry whose `get_versions` always errs with `PackageNotFound`, for
    /// exercising `generate_diagnostics`'s "Unknown package" branch (#267 C1) —
    /// distinct from [`ErrorRegistry`], whose `CacheError` must instead produce
    /// the "Registry lookup failed" message.
    struct NotFoundRegistry;

    impl crate::Registry for NotFoundRegistry {
        fn get_versions<'a>(
            &'a self,
            name: &'a PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move {
                Err(crate::error::DepsError::PackageNotFound {
                    package: name.to_string(),
                    registry: "mock",
                })
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

    /// A registry whose `get_versions` succeeds with a newer stable version and
    /// whose `get_latest_matching` returns a non-yanked current version, for
    /// exercising `generate_diagnostics`'s outdated-severity wiring.
    struct OutdatedRegistry;

    impl crate::Registry for OutdatedRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move {
                Ok(vec![Box::new(MockVersionWithAge {
                    version: "2.0.0".to_string(),
                    yanked: false,
                    published_at: None,
                }) as Box<dyn crate::Version>])
            })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a PackageName,
            _req: &'a VersionReq,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
        {
            Box::pin(async move {
                Ok(Some(Box::new(MockVersionWithAge {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    published_at: None,
                }) as Box<dyn crate::Version>))
            })
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

    /// A version with a configurable yanked flag and publish time, used for the
    /// "Recent versions" hover freshness tests below.
    struct MockVersionWithAge {
        version: String,
        yanked: bool,
        published_at: Option<PublishTime>,
    }

    impl crate::Version for MockVersionWithAge {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn published_at(&self) -> Option<PublishTime> {
            self.published_at
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct TestVersion {
        version: String,
        yanked: bool,
    }

    impl crate::Version for TestVersion {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A registry whose `get_versions` returns a fixed, caller-supplied version list —
    /// used to exercise hover's "Recent versions" rendering, which `MockRegistry`
    /// above (always empty) cannot.
    struct MockRegistryWithVersions {
        versions: Vec<MockVersionWithAge>,
    }

    impl crate::Registry for MockRegistryWithVersions {
        fn get_versions<'a>(
            &'a self,
            _name: &'a crate::PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            let versions = self
                .versions
                .iter()
                .map(|v| {
                    Box::new(MockVersionWithAge {
                        version: v.version.clone(),
                        yanked: v.yanked,
                        published_at: v.published_at,
                    }) as Box<dyn crate::Version>
                })
                .collect();
            Box::pin(async move { Ok(versions) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a crate::PackageName,
            _req: &'a crate::VersionReq,
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

        fn package_url(&self, _name: &crate::PackageName) -> String {
            String::new()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A registry returning a fixed, caller-supplied version list — used to
    /// exercise the yank check and display-item dedup in
    /// [`generate_code_actions`].
    struct FixedVersionRegistry {
        versions: Vec<(&'static str, bool)>,
    }

    impl crate::Registry for FixedVersionRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            let versions: Vec<Box<dyn crate::Version>> = self
                .versions
                .iter()
                .map(|(version, yanked)| {
                    Box::new(TestVersion {
                        version: (*version).to_string(),
                        yanked: *yanked,
                    }) as Box<dyn crate::Version>
                })
                .collect();
            Box::pin(async move { Ok(versions) })
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

    /// Builds a single-dependency parse result for the freshness hover tests, cursor
    /// positioned on the dependency name.
    fn freshness_test_parse_result(name: &str) -> MockParseResult {
        MockParseResult {
            deps: vec![MockDep {
                name: name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, name.len() as u32)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        }
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_shows_age_when_known() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                // 2 days ago — safely mid-bucket, immune to sub-second test flakiness.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("- `1.2.3` *(latest)* — 2 days ago"),
            "got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_omits_age_when_unknown() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Exactly the pre-feature line: no trailing age suffix.
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
    }

    #[tokio::test]
    async fn test_generate_hover_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 16)),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        // Stale go.sum entry left behind by a downgrade (#235): go.mod's `require`
        // line was downgraded back to v0.8.1, but the ledger-only go.sum still
        // records the higher v0.9.1 and sorts last, so it would win naive
        // last-occurrence-wins parsing if hover trusted `versions.resolved` here.
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example.com/mod".into(), "v0.9.1".to_string());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockGoFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Current**: `v0.8.1`"),
            "expected hover to show go.mod's pinned version, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("v0.9.1"),
            "hover must not surface the stale go.sum version: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_non_go_formatter_uses_resolved_lockfile_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.2.0".to_string());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Non-Go formatters must keep showing the lockfile-resolved version
        // ("1.2.0"), not the raw manifest requirement ("1.0.0") — confirms the Go
        // override does not leak into other ecosystems.
        assert!(
            content.value.contains("**Current**: `1.2.0`"),
            "expected hover to show the resolved lockfile version, got: {}",
            content.value
        );
        assert!(!content.value.contains("**Current**: `1.0.0`"));
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_preserves_yanked_marker_with_age() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "1.2.3".to_string(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "1.2.1".to_string(),
                    yanked: true,
                    // ~5 months ago.
                    published_at: Some(PublishTime::from_unix_secs(
                        PublishTime::now().as_unix_secs() - 5 * 30 * 24 * 60 * 60,
                    )),
                },
            ],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("- `1.2.1` *(yanked)* — 5 months ago"),
            "got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_respects_freshness_disabled() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
    }

    /// A formatter whose `format_version_for_text_edit` is the identity —
    /// unlike [`MockFormatter`], which wraps the version in quotes and would
    /// otherwise confound the N1 no-op-edit guard's own test.
    struct IdentityFormatter;

    impl EcosystemFormatter for IdentityFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    /// A formatter mimicking `deps-dart`'s non-identity
    /// `format_version_for_text_edit` (wraps the version in a caret
    /// constraint) — used to prove the N1 guard compares the *formatted*
    /// text actually written, not the bare version (critic S3).
    struct CaretWrappingFormatter;

    impl EcosystemFormatter for CaretWrappingFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            format!("^{version}")
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    /// A formatter mimicking `deps-pypi`'s non-identity
    /// `format_version_replacing` override (preserves an `==` pin instead of
    /// falling back to `format_version_for_text_edit`) — used to prove the
    /// vulnerability-fix action's `TextEdit` goes through the override, not
    /// the default delegation (critic S3).
    struct PinPreservingFormatter;

    impl EcosystemFormatter for PinPreservingFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            format!(">={version}")
        }

        fn format_version_replacing(&self, version: &str, current: &str) -> String {
            if current.starts_with("==") {
                format!("=={version}")
            } else {
                self.format_version_for_text_edit(version)
            }
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    /// Builds a `pkg = "<version_req>"`-shaped fixture: a dependency whose
    /// `version_range` slices `content` to exactly `version_req` (so the
    /// literal-span guard in `generate_code_actions` never rejects it).
    fn vulnerable_dep(version_req: &str) -> (MockDep, tower_lsp_server::ls_types::Range, String) {
        use tower_lsp_server::ls_types::{Position, Range};

        let content = format!("pkg = \"{version_req}\"");
        let start = 7u32; // len(`pkg = "`)
        let end = start + version_req.chars().count() as u32;
        let version_range = Range::new(Position::new(0, start), Position::new(0, end));
        (
            MockDep {
                name: pkg("pkg"),
                version_req: VersionReq::new(version_req),
                version_range,
                name_range: Range::new(Position::new(0, 0), Position::new(0, 3)),
            },
            version_range,
            content,
        )
    }

    fn quickfix_titles(actions: &[CodeAction]) -> Vec<&str> {
        actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::QUICKFIX))
            .map(|a| a.title.as_str())
            .collect()
    }

    fn refactor_titles(actions: &[CodeAction]) -> Vec<&str> {
        actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
            .map(|a| a.title.as_str())
            .collect()
    }

    /// A formatter whose formatted edit text differs from the bare version only in
    /// whitespace (a trailing space) — used to prove the REFACTOR-loop no-op guard
    /// compares whitespace-insensitively rather than by raw string equality.
    struct TrailingSpaceFormatter;

    impl EcosystemFormatter for TrailingSpaceFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            format!("{version} ")
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_combines_advisories_sharing_the_highest_fix() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![
                    std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["1.1.0".to_string()],
                        url: String::new(),
                    }),
                    std::sync::Arc::new(Advisory {
                        id: "A2".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::Critical,
                        cvss_vector: None,
                        fixed_versions: vec!["1.2.0".to_string()],
                        url: String::new(),
                    }),
                ],
                total_known: 2,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2 +1 more)"]);
        assert_eq!(actions[0].kind, Some(CodeActionKind::QUICKFIX));
        assert_eq!(actions[0].is_preferred, Some(true));
        // The full id list still travels in `data` for the diagnostics
        // binding, even though the title only names the first one.
        assert_eq!(
            actions[0].data,
            Some(serde_json::json!({ "advisory_ids": ["A2", "A1"] }))
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_target_is_not_inflated_by_a_subtracted_advisory() {
        // Critic S1 counterexample: A1 is fixed at a high version (3.0.0) but
        // phase B reports it still applies at the checked candidate, so it is
        // excluded from the claim. A2 is fixed at a much lower version
        // (1.2.0) and is claimed. The recommended target must be 1.2.0 — the
        // version that clears what is actually claimed — not 3.0.0, which
        // would push the user across an unnecessary major-version boundary
        // for a fix A1 that version does not even resolve.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![
                    std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["3.0.0".to_string()],
                        url: String::new(),
                    }),
                    std::sync::Arc::new(Advisory {
                        id: "A2".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::Medium,
                        cvss_vector: None,
                        fixed_versions: vec!["1.2.0".to_string()],
                        url: String::new(),
                    }),
                ],
                total_known: 2,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "3.0.0".to_string(),
                    advisory_ids: vec!["A1".to_string()],
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_drops_yanked_fix_target() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["2.0.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0", true), ("1.5.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MockFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
        assert!(
            actions
                .iter()
                .any(|a| a.kind == Some(CodeActionKind::REFACTOR))
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_op_edit_is_skipped() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        // Manifest already declares exactly the fixed version.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &IdentityFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_op_guard_compares_formatted_text_not_bare_version() {
        // Critic S3: the manifest already declares "^1.2.0" — exactly what
        // `CaretWrappingFormatter::format_version_for_text_edit` produces for
        // the fixed version "1.2.0" (mirroring `deps-dart`'s real `^{v}`
        // wrap). A guard comparing the bare version ("1.2.0" != "^1.2.0")
        // would miss this and offer a no-op edit; the guard must compare
        // against the formatted text instead.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &CaretWrappingFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_skips_no_op_entry_but_keeps_real_update() {
        // Regression for #238: no OSV vulnerabilities are present, isolating the plain
        // REFACTOR loop's own no-op guard from `build_vulnerability_fix_action`'s
        // separate N1 guard (the two prior "no_op" tests above only exercise the latter,
        // since `MockRegistry` returns no versions and the REFACTOR loop body never
        // runs). The registry lists the already-declared version among the top-5
        // display items — the common case per `prepare_version_display_items`, not an
        // edge case — plus one genuinely newer version.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &IdentityFormatter,
        )
        .await;

        let titles = refactor_titles(&actions);
        assert!(
            !titles.iter().any(|t| t.starts_with("1.2.0")),
            "the already-declared version must not be offered as an update: {titles:?}"
        );
        assert!(
            titles.contains(&"1.1.0"),
            "a genuinely different version must still be offered: {titles:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_no_op_guard_ignores_whitespace() {
        // Whitespace-only divergence between the declared requirement and the
        // formatter's edit text must still be treated as a no-op, mirroring
        // `build_vulnerability_fix_action`'s N1 guard and `literal_span_matches`'s
        // `test_guard_accepts_whitespace_only_difference`.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TrailingSpaceFormatter,
        )
        .await;

        assert!(
            refactor_titles(&actions).is_empty(),
            "a whitespace-only edit-text divergence must still be skipped as a no-op"
        );
    }

    /// A formatter that truncates every version to `==<major>.<minor>`, mirroring
    /// `deps-pypi`'s `truncate_release_to_match` collapsing several distinct
    /// registry versions (or a registry version and an OSV fix version) to the
    /// same rewritten text — used to prove issue #242's two dedup gaps: an item
    /// matching the fix action's text under a different raw version, and two
    /// items matching each other's text.
    struct TruncatingFormatter;

    impl EcosystemFormatter for TruncatingFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }

        fn format_version_replacing(&self, version: &str, _current: &str) -> String {
            let mut parts = version.split('.');
            let major = parts.next().unwrap_or("0");
            let minor = parts.next().unwrap_or("0");
            format!("=={major}.{minor}")
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_dedups_item_matching_fix_text_by_different_raw_version()
     {
        // Regression for #242 (gap 1): the old guard compared `item.version` against
        // `fix.version_native` verbatim, so a display item whose *formatted* text
        // matched the fix action's edit but whose *raw* version differed slipped
        // through undeduped. Here the fix targets "1.2.5" (formatted "==1.2") and the
        // registry also offers "1.2.9" — a different raw version that formats to the
        // same "==1.2" text — which must be skipped.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/requirements.txt"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.5".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.9", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TruncatingFormatter,
        )
        .await;

        assert_eq!(quickfix_titles(&actions).len(), 1);

        let titles = refactor_titles(&actions);
        assert!(
            !titles.iter().any(|t| t.starts_with("1.2.9")),
            "an item whose formatted text matches the fix action's text must be \
             skipped even though its raw version differs from the fix's: {titles:?}"
        );
        assert!(titles.iter().any(|t| t.starts_with("1.1.0")));

        for action in actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
        {
            let edit_text = &action.edit.as_ref().unwrap().changes.as_ref().unwrap()
                [parse_result.uri()][0]
                .new_text;
            for other in actions.iter() {
                if std::ptr::eq(action, other) {
                    continue;
                }
                let other_text = &other.edit.as_ref().unwrap().changes.as_ref().unwrap()
                    [parse_result.uri()][0]
                    .new_text;
                assert_ne!(
                    edit_text, other_text,
                    "no two actions may carry a byte-identical edit"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_dedups_item_matching_another_items_text() {
        // Regression for #242 (gap 2): two display items whose formatted text
        // coincides (e.g. PyPI's release-segment truncation) must not both be
        // offered as REFACTOR actions, even with no fix action in play at all.
        // Registry-native order is newest-first, so "1.1.9" is `is_latest`; both
        // "1.1.9" and "1.1.5" truncate to "==1.1" and must collapse into one action.
        let (dep, version_range, content) = vulnerable_dep("==1.0.*");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/requirements.txt"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.1.9", false), ("1.1.5", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TruncatingFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());

        let titles = refactor_titles(&actions);
        assert_eq!(
            titles,
            vec!["1.1.9 (latest)"],
            "identical-text items after the first must be deduped: {titles:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_lockfile_hit_gets_title_suffix() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.0.2".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let mut resolved = HashMap::new();
        resolved.insert(pkg("pkg"), "1.0.1".to_string());
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(
            titles,
            vec!["Update to 1.0.2 (fixes A1; update lockfile to apply)"]
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_action_survives_registry_error() {
        // FR-007 / registry-independence: a registry outage must never
        // suppress an OSV-derived fix. The fix action is computed before the
        // `registry.get_versions` call, but this test exercises the early
        // return on `Err` specifically, which no prior test reached.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &ErrorRegistry,
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A1)"]);
        // No plain "update to X" items either, since the registry fetch that
        // would produce them failed.
        assert_eq!(actions.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_code_actions_coexistence_dedups_fix_version_and_demotes_preferred() {
        // Exercises the branch where the registry fetch succeeds *and*
        // returns the fix's own target version alongside other non-yanked
        // versions: the display item for that exact version must not be
        // duplicated, and no plain item may claim `is_preferred` once a fix
        // action exists.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        // Registry-native order is descending (index 0 = latest); the fix's
        // own target (1.2.0) is present and not yanked, alongside others.
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false), ("1.1.0", false), ("1.0.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MockFormatter,
        )
        .await;

        assert_eq!(quickfix_titles(&actions).len(), 1);

        let refactor_titles: Vec<&str> = actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
            .map(|a| a.title.as_str())
            .collect();
        assert!(
            !refactor_titles.iter().any(|t| t.starts_with("1.2.0")),
            "the display item duplicating the fix's own target must be skipped: {refactor_titles:?}"
        );
        assert!(refactor_titles.iter().any(|t| t.starts_with("1.1.0")));

        assert!(
            actions
                .iter()
                .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
                .all(|a| a.is_preferred.is_none()),
            "only the fix action may be preferred once it exists"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_uses_ecosystem_format_version_replacing_override() {
        // Critic S3: `format_version_replacing` is overridden in exactly one
        // place workspace-wide (`deps-pypi`); no test anywhere proved the
        // vulnerability-fix action's `TextEdit` actually goes through such
        // an override rather than the default delegation to
        // `format_version_for_text_edit` — the same bug class the original
        // #216 critique caught (a guard/edit comparing the wrong string,
        // silently bypassed per-ecosystem).
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let uri = crate::test_util::test_uri("/test/requirements.txt");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.0.2".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &PinPreservingFormatter,
        )
        .await;

        let quickfix = actions
            .iter()
            .find(|a| a.kind == Some(CodeActionKind::QUICKFIX))
            .expect("a vulnerability-fix quickfix should be offered");
        let new_text = quickfix
            .edit
            .as_ref()
            .and_then(|e| e.changes.as_ref())
            .and_then(|c| c.get(&uri))
            .and_then(|edits| edits.first())
            .map(|e| e.new_text.as_str())
            .expect("quickfix should carry a TextEdit for the document uri");

        assert_eq!(
            new_text, "==1.0.2",
            "the fix action's TextEdit must go through format_version_replacing's \
             pin-preserving override, not the default format_version_for_text_edit delegation"
        );
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
            crate::freshness::FreshnessSettings::default(),
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
            crate::freshness::FreshnessSettings::default(),
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
            crate::freshness::FreshnessSettings::default(),
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
            crate::freshness::FreshnessSettings::default(),
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
            crate::freshness::FreshnessSettings::default(),
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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.1.1"));

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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.1.1"));

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
    fn test_inlay_hint_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockGoFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "example.com/mod".into(),
            PackageVersions::latest_only("v0.9.1"),
        );

        // Stale go.sum entry left behind by a downgrade: go.sum is sorted ascending by
        // semver, so it sorts last and would win naive last-occurrence-wins parsing
        // even though go.mod's `require` line was downgraded back to v0.8.1 (#235).
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example.com/mod".into(), "v0.9.1".to_string());

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
                // Bug: using the stale go.sum "v0.9.1" as resolved would equal latest
                // ("v0.9.1") and wrongly report up-to-date. The fix takes go.mod's
                // pinned "v0.8.1", which is genuinely outdated relative to latest.
                assert!(
                    text.starts_with("❌"),
                    "expected outdated hint driven by go.mod pin, got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_non_go_formatter_uses_resolved_lockfile_version() {
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
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.2.0"));

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.2.0".to_string());

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
                // Non-Go formatters must keep using the lockfile-resolved version
                // ("1.2.0", matching latest) rather than the raw manifest requirement
                // ("1.0.0", which would wrongly report outdated) — confirms the Go
                // override does not leak into other ecosystems.
                assert!(
                    text.starts_with("✅"),
                    "expected up-to-date hint from resolved lockfile version, got: {text}"
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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

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
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("unknown-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_not_reported_as_unknown() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A package missing from `cached` because its registry fetch errored
        // or timed out (#267) must not be reported as "Unknown package" — the
        // registry was never successfully asked, so absence is not evidence
        // the package doesn't exist.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "flaky-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let fetch_failed = HashSet::from(["flaky-pkg".to_string()]);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_fetch_failed(&fetch_failed),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("Registry lookup failed"));
        assert!(diagnostics[0].message.contains("flaky-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_does_not_mask_invalid_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A syntactically invalid name is a local, name-only check independent
        // of any registry round trip — it must win over a fetch-failure
        // marker for the same (invalid) name, not be suppressed by it.
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad name".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let fetch_failed = HashSet::from(["bad name".to_string()]);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_fetch_failed(&fetch_failed),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("Invalid package name"));
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
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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

        let diagnostics = generate_diagnostics(
            &parse_result,
            &ErrorRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
        assert!(!diagnostics[0].message.contains("Unknown package"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_unknown_uses_configured_severity() {
        use tower_lsp_server::ls_types::{Position, Range};

        // `NotFoundRegistry`, not `ErrorRegistry`: "Unknown package" is only
        // correct when the registry was actually asked and said "no such
        // package" (#267 C1) — an opaque `CacheError` must not reach this
        // branch, or a transient outage would be mislabeled as a genuinely
        // nonexistent dependency.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let severities = DiagnosticSeverities {
            unknown: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &NotFoundRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            severities,
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.starts_with("Unknown package"));
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_registry_error_not_reported_as_unknown() {
        use tower_lsp_server::ls_types::{Position, Range};

        // #267 C1: an opaque registry failure (`ErrorRegistry`'s `CacheError`,
        // standing in for a network error, timeout, or malformed response)
        // must not produce "Unknown package" — the registry was never
        // successfully asked, so absence of a result is not evidence the
        // package doesn't exist.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &ErrorRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("Registry lookup failed"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_outdated_uses_configured_severity() {
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let severities = DiagnosticSeverities {
            outdated: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &OutdatedRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            severities,
        )
        .await;

        let outdated_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with("Newer version available"))
            .expect("expected an outdated diagnostic");
        assert_eq!(outdated_diag.severity, Some(DiagnosticSeverity::ERROR));
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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));
        cached_versions.insert("tokio".into(), PackageVersions::latest_only("2.0.0"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
        cached_versions.insert("criterion".into(), PackageVersions::latest_only("0.5.1"));

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
        cached_versions.insert("criterion".into(), PackageVersions::latest_only("0.5.1"));

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
        cached_versions.insert(
            "spring-boot-starter".into(),
            PackageVersions::latest_only("3.2.0"),
        );

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for an unresolved requirement, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_uses_configured_severity() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".to_string());

        let severities = DiagnosticSeverities {
            yanked: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            severities,
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(DiagnosticSeverity::ERROR));
        assert!(yanked_diag.message.contains("1.0.5"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_default_severity_unchanged() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".to_string());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(DiagnosticSeverity::WARNING));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_no_yanked_map_emits_no_yanked_diagnostic() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Regression guard for the four handlers (hover, completion, code_lens,
        // inlay_hints) that keep calling `VersionData::new` without
        // `.with_yanked(..)` — `yanked: None` must never produce a diagnostic.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.5"));
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message())),
            "Expected no yanked diagnostic when `yanked` is None, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Proves the yanked push sits before the early-`continue`s, so a dep
        // that is both yanked (in-use version) and outdated (vs. latest)
        // gets both diagnostics.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".to_string());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert_eq!(
            diagnostics.len(),
            2,
            "expected both diagnostics: {diagnostics:?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message()))
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Newer version available"))
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_no_version_range_uses_name_range() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let name_range = Range::new(Position::new(0, 0), Position::new(0, 5));

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "serde".into(),
                name_range,
                markers: None,
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".to_string());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic even without a version_range");
        assert_eq!(yanked_diag.range, name_range);
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_normalized_name_keying() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        /// Mirrors a Composer/NuGet/Swift-shaped formatter whose normalized
        /// name differs from the manifest-declared raw name.
        struct MockLowercaseFormatter;
        impl EcosystemFormatter for MockLowercaseFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.to_string().to_lowercase()
            }
        }

        let formatter = MockLowercaseFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "Newtonsoft.Json".into(),
                version_req: "13.0.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/project.csproj"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        // Keyed by the *normalized* (lowercase) name, not the raw manifest name.
        yanked.insert("newtonsoft.json".to_string(), "13.0.1".to_string());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );

        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message())),
            "expected normalized-name lookup to resolve the yanked entry, got: {diagnostics:?}"
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
        cached_versions.insert(
            "spring-boot-starter".into(),
            PackageVersions::latest_only("3.2.0"),
        );

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
        /// point is actually consulted rather than the trait default. Appends `-forced`
        /// in `format_version_for_text_edit` so the resulting edit is never a no-op: the
        /// override-is-honored test below intentionally declares a requirement already
        /// textually identical to `latest` (to isolate "was the hook consulted" from "is
        /// this genuinely outdated"), which would otherwise be indistinguishable from a
        /// real no-op and get filtered by `collect_update_all_edits`'s no-op guard.
        struct FloorFormatter;

        impl EcosystemFormatter for FloorFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                format!("{version}-forced")
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
            cached.insert("serde".into(), PackageVersions::latest_only("1.0.0"));
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
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            cached.insert("tokio".into(), PackageVersions::latest_only("1.3.0"));
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
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
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
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
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
            cached.insert("pkg".into(), PackageVersions::latest_only("1.0.0"));
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
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
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
            cached.insert("pkg".into(), PackageVersions::latest_only("1.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &FloorFormatter,
            );
            assert_eq!(edits.len(), 1);
            assert_eq!(edits[0].new_text, "1.0.0-forced");
        }

        #[test]
        fn test_no_op_edit_is_excluded() {
            // M2: a formatter can decide a declared requirement has no single
            // unambiguous rewrite and return it unchanged (e.g. `deps-gradle`'s
            // `{strictly}!!{preferred}` infix shorthand). Without a no-op guard, this
            // dependency would still count toward, and be "fixed" by, the "Update N
            // outdated dependencies" lens while applying nothing.
            struct NoOpFormatter;
            impl EcosystemFormatter for NoOpFormatter {
                fn format_version_for_text_edit(&self, version: &str) -> String {
                    version.to_string()
                }
                fn package_url(&self, name: &PackageName) -> String {
                    format!("https://example.com/{name}")
                }
                fn format_version_replacing(&self, _version: &str, current: &str) -> String {
                    current.to_string()
                }
                fn is_requirement_up_to_date(
                    &self,
                    _requirement: &VersionReq,
                    _latest: &str,
                ) -> bool {
                    false
                }
            }

            let content = r#"pkg = "1.0.0""#;
            let pr = parse_result(vec![dep("pkg", Some("1.0.0"), Some(range(0, 7, 0, 12)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("1.2.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &NoOpFormatter,
            );
            assert!(edits.is_empty());
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
            cached.insert("slf4j-api".into(), PackageVersions::latest_only("2.1.0"));
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
            cached.insert("pkg".into(), PackageVersions::latest_only("3.0.0"));
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
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
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
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
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
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
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
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
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
            cached.insert("interval-dep".into(), PackageVersions::latest_only("3.0.0"));
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
            cached.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
            cached.insert("tokio".into(), PackageVersions::latest_only("1.9.0"));
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            let diagnostics = generate_diagnostics_from_cache(
                &pr,
                versions,
                &MockFormatter,
                crate::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );
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
            cached.insert("aaaa".into(), PackageVersions::latest_only("2.0.0"));
            cached.insert("aaaa-dup".into(), PackageVersions::latest_only("3.0.0"));
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

    /// Wraps a [`MockDep`] to report a non-`Registry` [`crate::parser::DependencySource`],
    /// without touching every other `MockDep` literal in this test module.
    struct NonRegistryDep(MockDep, crate::parser::DependencySource);

    impl Dependency for NonRegistryDep {
        fn name(&self) -> &PackageName {
            self.0.name()
        }
        fn name_range(&self) -> Range {
            self.0.name_range()
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
            self.0.version_requirement()
        }
        fn version_range(&self) -> Option<Range> {
            self.0.version_range()
        }
        fn source(&self) -> crate::parser::DependencySource {
            self.1.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// `ParseResult` holding exactly one dependency of any concrete `Dependency`
    /// type, so single-dependency tests aren't forced to use `MockDep`/`MockParseResult`.
    struct SingleDepParseResult<D> {
        dep: D,
        uri: Uri,
    }

    impl<D: Dependency + 'static> ParseResult for SingleDepParseResult<D> {
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

    /// Formatter whose `compile_requirement` does exact-string matching, so
    /// `requirement_is_unsatisfiable` can actually return `true` in a test
    /// (unlike the default `MockFormatter`, whose `compile_requirement`
    /// default always returns `None`).
    struct ExactMatchFormatter;

    struct ExactMatcher(String);
    impl RequirementMatcher for ExactMatcher {
        fn matches(&self, version: &str) -> Option<bool> {
            Some(version == self.0)
        }
    }

    impl EcosystemFormatter for ExactMatchFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name)
        }
        fn compile_requirement(
            &self,
            requirement: &VersionReq,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
        }
    }

    #[test]
    fn test_generate_diagnostics_unsatisfiable_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        // Requirement "1.0.0" against available ["9.9.9"] is unsatisfiable
        // under ExactMatchFormatter — proven by the Registry-source case below.
        for source in [
            DependencySource::Path {
                path: "../local".into(),
            },
            DependencySource::Git {
                url: "https://example.com/repo.git".into(),
                rev: None,
            },
            DependencySource::Url {
                url: "https://example.com/pkg.tar.gz".into(),
            },
            DependencySource::Sdk {
                sdk: "flutter".into(),
            },
            DependencySource::Workspace,
            DependencySource::CustomRegistry {
                url: "my-corp".into(),
            },
        ] {
            let parse_result = SingleDepParseResult {
                dep: NonRegistryDep(dep_at("dep"), source.clone()),
                uri: uri.clone(),
            };
            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &ExactMatchFormatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message.contains("No published version satisfies")),
                "source {source:?} must never produce the unsatisfiable-requirement WARNING"
            );
        }

        // Control: the same requirement/available pair on a Registry-source
        // dependency DOES produce the WARNING, proving the loop above isn't
        // vacuously passing because the fixture never triggers it at all.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &ExactMatchFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("No published version satisfies")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_unknown_package_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // No cache entry at all for "dep" — simulates a `CustomRegistry`
        // dependency, which this LSP never fetches from a real registry.
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message.contains("Unknown package")),
            "a CustomRegistry-sourced dependency must never produce the \"Unknown package\" WARNING"
        );

        // Control: the same missing cache entry on a Registry-source
        // dependency DOES produce the WARNING.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Unknown package")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_invalid_name_still_reported_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // Invalid-name validation is pure syntax checking, independent of
        // registry data — it must still fire even when the source is not
        // resolvable (unlike "Unknown package", which requires a real lookup).
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/package.json");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &RejectingFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
    }

    #[test]
    fn test_generate_diagnostics_outdated_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // "dep" resolves to a coincidentally-matching cache entry with a newer
        // "latest", as would happen for a Cargo path dependency that happens
        // to share a name with an unrelated published crate.
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message.contains("Newer version available")),
            "a CustomRegistry-sourced dependency must never produce the \"Outdated\" WARNING"
        );

        // Control: the same requirement/cache pair on a Registry-source
        // dependency DOES produce the WARNING.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Newer version available")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_registry_sections_suppressed_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "9.9.9".to_string(),
                yanked: false,
                published_at: None,
            }],
        };
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("**Latest**"));
        assert!(!content.value.contains("**Recent versions**"));
        assert!(content.value.contains("**Requirement**"));

        // Control: the same fixture on a Registry-source dependency DOES show
        // both registry-derived sections, proving the fixture isn't vacuous.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let hover = generate_hover(
            &registry_parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**"));
        assert!(content.value.contains("**Recent versions**"));
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
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
        cached_versions.insert("git-pkg".into(), PackageVersions::latest_only("1.0.0"));
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
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
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
            crate::FreshnessSettings::default(),
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
            crate::FreshnessSettings::default(),
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
            crate::FreshnessSettings::default(),
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

    /// Tests for the `literal_span_matches` guard on `generate_code_actions`
    /// (§6.3): a dependency whose `version_range` no longer slices to its
    /// declared requirement must yield no code action, mirroring the guard
    /// `collect_update_all_edits` already applies.
    mod code_actions_guard_tests {
        use super::*;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        struct CaDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            version_range: Option<Range>,
        }

        impl Dependency for CaDep {
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

        struct CaParseResult {
            deps: Vec<CaDep>,
            uri: Uri,
        }

        impl ParseResult for CaParseResult {
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

        struct CaVersion {
            version: String,
            yanked: bool,
        }

        crate::impl_version!(CaVersion {
            version: version,
            yanked: yanked,
        });

        struct CaRegistry;

        impl crate::Registry for CaRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(CaVersion {
                        version: "2.0.0".to_string(),
                        yanked: false,
                    }) as Box<dyn crate::Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
            ) -> crate::ecosystem::BoxFuture<
                'a,
                crate::error::Result<Option<Box<dyn crate::Version>>>,
            > {
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

        fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Range {
            Range::new(Position::new(sl, sc), Position::new(el, ec))
        }

        #[tokio::test]
        async fn test_guard_rejects_span_that_does_not_match_requirement() {
            // content has "1.0.0" at 0..5, but the dependency claims its
            // version_range covers 6..11 (out of bounds / wrong slice) —
            // simulate via a version_range that slices to different text.
            let content = "1.0.0 extra";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 6, 0, 11)), // slices to "extra"
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            // Must fall inside `version_range` (6..11) for
            // `is_position_on_dependency`'s default impl to select this
            // dependency at all — the point of this test is the guard past
            // that selection, not the selection itself.
            let position = Position::new(0, 7);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MockFormatter,
            )
            .await;

            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_span_even_with_a_pending_vulnerability_fix() {
            // Critic S2: the guard must gate the vulnerability-fix quickfix
            // too, not just the plain "update version" action — a future
            // refactor moving `build_vulnerability_fix_action` above the
            // guard would reintroduce manifest corruption on a rejected
            // span (e.g. a Maven `${property}` reference) at P0 severity.
            // Every other test in this module uses an empty `VersionData`,
            // which would pass even if the guard only gated the plain
            // action; this one carries a real OSV hit so a regression that
            // reorders the two checks fails here.
            use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};

            let content = "1.0.0 extra";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 6, 0, 11)), // slices to "extra"
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 7);

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                "serde".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["2.0.0".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
                }),
            );
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions =
                VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MockFormatter,
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_accepts_matching_span() {
            let content = "1.0.0";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 0, 0, 5)),
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MockFormatter,
            )
            .await;

            assert!(!actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_empty_requirement() {
            let content = "1.0.0";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("")),
                version_range: Some(range(0, 0, 0, 5)),
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MockFormatter,
            )
            .await;

            assert!(actions.is_empty());
        }
    }

    /// Table-driven coverage for `requirement_is_unsatisfiable` (plan §4), using a
    /// formatter whose `compile_requirement` is configured per test via a closure-backed
    /// matcher, rather than one of the fixed ecosystem formatters.
    mod requirement_is_unsatisfiable_tests {
        use super::*;

        type Decide = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

        /// A matcher backed by a type-erased closure, so each test can express its own
        /// per-candidate decision table without a new named type per test.
        struct ClosureMatcher(Decide);

        impl RequirementMatcher for ClosureMatcher {
            fn matches(&self, version: &str) -> Option<bool> {
                (self.0)(version)
            }
        }

        /// A formatter whose `compile_requirement` is `None` (requirement is treated as
        /// unmodellable) unless `requirement.as_str() == "modelled"`, in which case it
        /// returns a `ClosureMatcher` wrapping `decide`. `requirement_is_unresolved` fires
        /// on the literal string `"unresolved"`.
        struct TableFormatter {
            decide: Decide,
        }

        impl TableFormatter {
            fn new(decide: impl Fn(&str) -> Option<bool> + Send + Sync + 'static) -> Self {
                Self {
                    decide: Arc::new(decide),
                }
            }
        }

        impl EcosystemFormatter for TableFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
            fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
                requirement.as_str() == "unresolved"
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                if requirement.as_str() != "modelled" {
                    return None;
                }
                Some(Box::new(ClosureMatcher(Arc::clone(&self.decide)))
                    as Box<dyn RequirementMatcher>)
            }
        }

        fn versions(strs: &[&str]) -> Vec<String> {
            strs.iter().map(|s| (*s).to_string()).collect()
        }

        #[test]
        fn test_empty_available_list_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &[],
            ));
        }

        #[test]
        fn test_empty_requirement_string_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new(""),
                &versions(&["1.0.0"]),
            ));
        }

        /// S-1 (security): an oversized requirement is rejected before `compile_requirement`
        /// is even called, bounding the cost of an adversarial/corrupted requirement string
        /// regardless of how expensive that ecosystem's matcher is per candidate.
        #[test]
        fn test_oversized_requirement_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan an oversized requirement"));
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new(oversized),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_unresolved_requirement_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("unresolved"),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_compile_requirement_none_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("not-modelled"),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_all_candidates_decided_false_is_true() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0", "3.0.0"]),
            ));
        }

        #[test]
        fn test_one_match_among_many_non_matches_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "2.0.0"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0", "3.0.0"]),
            ));
        }

        /// S2 regression: every candidate unparseable means nothing was decided, so the
        /// verdict must be `false` (no diagnostic), not a vacuous `true`.
        #[test]
        fn test_all_candidates_unparseable_is_false() {
            let formatter = TableFormatter::new(|_v| None);
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0"]),
            ));
        }

        /// S2 regression, other half: a single junk entry among otherwise-all-`Some(false)`
        /// candidates is skipped, not fatal to the whole scan.
        #[test]
        fn test_one_unparseable_candidate_among_false_is_still_true() {
            let formatter = TableFormatter::new(|v| if v == "junk" { None } else { Some(false) });
            assert!(requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "junk", "2.0.0"]),
            ));
        }

        /// §1.3: a match on a candidate that happens to be yanked still counts as
        /// satisfied — `available` carries no yanked flag, so this is exercised the same
        /// way any other match is: the matcher deciding `Some(true)` for that entry.
        #[test]
        fn test_match_on_yanked_only_candidate_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0-yanked"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0-yanked"]),
            ));
        }

        /// §1.2: same, for a prerelease-only match.
        #[test]
        fn test_match_on_prerelease_only_candidate_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "2.0.0-beta.1"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["2.0.0-beta.1"]),
            ));
        }

        #[test]
        fn test_scan_short_circuits_on_first_match() {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls_clone = Arc::clone(&calls);
            let formatter = TableFormatter::new(move |v| {
                calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(v == "1.0.0")
            });
            let result = requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "0.9.0", "0.8.0"]),
            );
            assert!(!result);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "must stop scanning at the first Some(true)"
            );
        }
    }

    /// Coverage for `requirement_matches_only_yanked` and its wiring into
    /// `generate_diagnostics_from_cache` (issue #247): the cache-only diagnostics path's
    /// substitute for the network path's `current.is_yanked()` check in `generate_diagnostics`,
    /// which never fires against a real registry because `Registry::get_latest_matching`
    /// filters yanked entries out by contract on every current implementation (#233). This
    /// scans `available`/`yanked` directly instead, so it observes yanked entries that
    /// `get_latest_matching` never returns.
    mod requirement_matches_only_yanked_tests {
        use super::*;

        type Decide = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

        struct ClosureMatcher(Decide);

        impl RequirementMatcher for ClosureMatcher {
            fn matches(&self, version: &str) -> Option<bool> {
                (self.0)(version)
            }
        }

        /// Same shape as `requirement_is_unsatisfiable_tests::TableFormatter`:
        /// `compile_requirement` only opts in for the literal requirement string `"modelled"`.
        struct TableFormatter {
            decide: Decide,
        }

        impl TableFormatter {
            fn new(decide: impl Fn(&str) -> Option<bool> + Send + Sync + 'static) -> Self {
                Self {
                    decide: Arc::new(decide),
                }
            }
        }

        impl EcosystemFormatter for TableFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
            fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
                requirement.as_str() == "unresolved"
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                if requirement.as_str() != "modelled" {
                    return None;
                }
                Some(Box::new(ClosureMatcher(Arc::clone(&self.decide)))
                    as Box<dyn RequirementMatcher>)
            }
        }

        fn versions(strs: &[&str]) -> Vec<String> {
            strs.iter().map(|s| (*s).to_string()).collect()
        }

        #[test]
        fn test_yanked_only_match_is_true() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));
            assert!(requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_no_match_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_match_on_non_yanked_alongside_yanked_is_false() {
            // "^1.0" matches both a yanked 1.0.0 and a non-yanked 1.0.1 — a non-yanked
            // alternative exists, so this must not be reported as "yanked-only".
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.1", "1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_scan_continues_past_a_yanked_match_to_find_a_non_yanked_alternative() {
            // Same as above but with the yanked candidate ordered first, so a scan that
            // stopped at the first `Some(true)` (as `requirement_is_unsatisfiable` does) would
            // wrongly report "yanked-only" here.
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "1.0.1"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_empty_yanked_list_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan when yanked is empty"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0"]),
                &[],
            ));
        }

        #[test]
        fn test_empty_available_list_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &[],
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_unresolved_requirement_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("unresolved"),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_compile_requirement_none_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("not-modelled"),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        /// End-to-end: `generate_diagnostics_from_cache` emits the yanked diagnostic (default
        /// severity, `formatter.yanked_message()` plus a "; latest is X" suffix mirroring the
        /// sibling unsatisfiable diagnostic's actionability) and nothing else for a dependency
        /// whose requirement matches only a yanked version.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_only_match_fires_yanked_diagnostic() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: Arc::from(vec!["2.0.0".to_string(), "1.2.1".to_string()]),
                    yanked: Arc::from(vec!["1.2.1".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
            assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
            assert_eq!(
                diagnostics[0].message,
                format!("{}; latest is 2.0.0", formatter.yanked_message())
            );
        }

        /// #247 vs. #263 dedup: a dependency whose in-use version (lock-file-resolved, or an
        /// exact pin) is yanked *and* is the only version satisfying its own requirement
        /// triggers both the in-use-version check (`versions.yanked`, #263) and the
        /// requirement-only-satisfiable-by-yanked check (`requirement_matches_only_yanked`,
        /// #247). Exactly one diagnostic must be emitted, not two.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_dedup_in_use_and_requirement_only_match() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: Arc::from(vec!["2.0.0".to_string(), "1.2.1".to_string()]),
                    yanked: Arc::from(vec!["1.2.1".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();
            let mut in_use_yanked = HashMap::new();
            in_use_yanked.insert("serde".to_string(), "1.2.1".to_string());

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_yanked(&in_use_yanked),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            // Two diagnostics are expected, not one: the in-use-version check (#263) has
            // no `continue`, so it co-emits alongside the ordinary "outdated" diagnostic
            // for the same dependency (the fixture's declared requirement "modelled"
            // does not itself equal `latest` "2.0.0", so `requirement_status` reports
            // `Outdated`) — this is #263's deliberate, separately-tested policy, see
            // `test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted`.
            // What this test actually proves is narrower: exactly one *yanked*
            // diagnostic, not two — #247's `yanked_only` check must not also fire.
            let yanked_diags: Vec<_> = diagnostics
                .iter()
                .filter(|d| d.message.starts_with(formatter.yanked_message()))
                .collect();
            assert_eq!(
                yanked_diags.len(),
                1,
                "expected exactly one yanked diagnostic, got: {diagnostics:?}"
            );
            // The in-use-version check (#263) runs first and wins.
            assert_eq!(
                yanked_diags[0].message,
                format!("{} (1.2.1)", formatter.yanked_message())
            );
            assert_eq!(
                diagnostics.len(),
                2,
                "expected exactly the yanked diagnostic plus the co-emitted outdated \
                 diagnostic (#263's policy), got: {diagnostics:?}"
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message == "Newer version available: 2.0.0"),
                "expected the co-emitted outdated diagnostic, got: {diagnostics:?}"
            );
        }

        /// `severities.yanked` reaches the emitted diagnostic on the cache-only path, the same
        /// way `outdated_severity`/`unknown_severity`/`unsatisfiable_severity` already do.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_only_match_uses_configured_severity() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "1.2.1".to_string(),
                    available: Arc::from(vec!["1.2.1".to_string()]),
                    yanked: Arc::from(vec!["1.2.1".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();

            let severities = DiagnosticSeverities {
                yanked: DiagnosticSeverity::ERROR,
                ..DiagnosticSeverities::default()
            };

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                severities,
            );

            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
        }

        /// When a non-yanked version also satisfies the requirement, no yanked diagnostic
        /// fires — the dependency falls through to the ordinary outdated/up-to-date check.
        #[test]
        fn test_generate_diagnostics_from_cache_match_with_non_yanked_alternative_skips_yanked_diagnostic()
         {
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: Arc::from(vec![
                        "2.0.0".to_string(),
                        "1.0.1".to_string(),
                        "1.0.0".to_string(),
                    ]),
                    yanked: Arc::from(vec!["1.0.0".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message.starts_with(formatter.yanked_message())),
                "a non-yanked match exists, so no yanked diagnostic should fire, got: {diagnostics:?}"
            );
        }

        /// M1 regression: an undecided candidate (`matcher.matches` returns `None`) must not
        /// be silently skipped — it might have been a genuine non-yanked match this scan
        /// could not evaluate, so it disqualifies a `true` verdict entirely.
        #[test]
        fn test_undecided_candidate_prevents_true_verdict() {
            let formatter = TableFormatter::new(|v| match v {
                "1.2.1" => Some(true),
                "unparseable" => None,
                _ => Some(false),
            });
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1", "unparseable"]),
                &versions(&["1.2.1"]),
            ));
        }

        /// Same scenario, but the undecided candidate is scanned before the yanked match —
        /// proves the early `return false` on a non-yanked match doesn't accidentally mask
        /// this case, and that the `saw_undecided` flag survives regardless of scan order.
        #[test]
        fn test_undecided_candidate_before_match_still_prevents_true_verdict() {
            let formatter = TableFormatter::new(|v| match v {
                "1.2.1" => Some(true),
                "unparseable" => None,
                _ => Some(false),
            });
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["unparseable", "1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_oversized_requirement_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan an oversized requirement"));
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new(oversized),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        /// The yanked-only-match diagnostic must never fire for a non-registry-resolvable
        /// dependency source (path/git/URL/SDK/workspace) — the same guard
        /// `requirement_is_unsatisfiable` already has (see
        /// `test_generate_diagnostics_unsatisfiable_skipped_for_non_registry_sources`).
        #[test]
        fn test_yanked_only_match_skipped_for_non_registry_sources() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));
            let uri = crate::test_util::test_uri("/test/Cargo.toml");

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "dep".into(),
                PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: Arc::from(vec!["2.0.0".to_string(), "1.2.1".to_string()]),
                    yanked: Arc::from(vec!["1.2.1".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();

            let dep = MockDep {
                name: "dep".into(),
                version_req: "modelled".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 3)),
            };
            let parse_result = SingleDepParseResult {
                dep: NonRegistryDep(
                    dep,
                    crate::parser::DependencySource::Path {
                        path: "../local".into(),
                    },
                ),
                uri,
            };

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message.starts_with(formatter.yanked_message())),
                "a path dependency must never produce the yanked diagnostic, got: {diagnostics:?}"
            );
        }

        /// The `continue` after emitting the yanked diagnostic must suppress the sibling
        /// outdated check for the same dependency — proven directly rather than just
        /// inferred from `diagnostics.len() == 1` elsewhere in this module.
        #[test]
        fn test_yanked_only_match_suppresses_outdated_diagnostic() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: Arc::from(vec!["2.0.0".to_string(), "1.2.1".to_string()]),
                    yanked: Arc::from(vec!["1.2.1".to_string()]),
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message.contains("Newer version available")),
                "the yanked diagnostic must suppress the outdated hint, not add to it, got: {diagnostics:?}"
            );
        }
    }
}
