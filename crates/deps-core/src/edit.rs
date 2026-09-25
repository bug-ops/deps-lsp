//! Protocol-agnostic manifest-edit planning (issue #1329, spec 068).
//!
//! Ungated (unlike `lsp_helpers::code_lenses`/`lsp_helpers::code_actions`, which require the
//! `lsp-responses` feature): `deps-cli update` links this module directly,
//! and CI forbids `tower-lsp-server` from reaching `deps-cli`'s non-dev dependency tree (spec
//! 064, #1083). [`collect_update_edits`] and [`plan_vulnerability_fix`] are the domain-level
//! planners `deps-lsp`'s `lsp_helpers::code_lenses::collect_update_all_edits` and
//! `lsp_helpers::code_actions::build_vulnerability_fix_action` now delegate to as thin
//! adapters — the extraction shape spec 064 already applied to [`crate::diagnostic::Diagnostic`]
//! and spec 063 applied to [`crate::Dependency`]/[`crate::lockfile::LockFileCache`].

use crate::lsp_helpers::{
    EcosystemFormatter, LineOffsetTable, RequirementStatus, VersionData, is_safe_version_string,
    literal_span_matches, resolve_in_use_version, slice_for_range, strip_whitespace,
    warn_rejected_value,
};
use crate::{ConcreteVersion, Dependency, ParseResult, VersionReq};

/// Whether `current` — or `dep`'s own literal version span — is an unexpanded placeholder.
///
/// Checks both `current` (the requirement text a caller is about to consider rewriting) and
/// [`Dependency::version_literal`] (when present) rather than `current` alone, folding
/// `deps-swift`'s literal-vs-synthesized-comparator distinction (a `from: "\(v)"` declaration's
/// `current` is a synthesized `">=\(v), <1.0.0"` comparator, while `version_literal` is the raw
/// `\(v)` interpolation actually embedded in the manifest) into one shared check instead of a
/// per-ecosystem `format_version_replacing_for` override having to re-derive it.
///
/// This is the gate every central edit-planning call site
/// ([`collect_update_candidates`], [`plan_verified_fix`],
/// `crate::lsp_helpers::code_actions`'s unsatisfiable-requirement fix builder and REFACTOR
/// "Update to X" loop) checks before ever calling [`replacement_text`] — see that function's
/// doc for why the two are split into a boolean gate and a text-producing step rather than one
/// combined call.
///
/// # Examples
///
/// ```
/// use deps_core::edit::requirement_is_placeholder_for;
/// use deps_core::lsp_helpers::{DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering, RequirementResolution, SourcePolicy};
/// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
///
/// struct PlainFormatter;
/// impl PackageNaming for PlainFormatter {}
/// impl PackageRendering for PlainFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for PlainFormatter {}
/// impl DiagnosticMessages for PlainFormatter {}
/// impl DiagnosticPolicy for PlainFormatter {}
/// impl SourcePolicy for PlainFormatter {}
/// impl OsvNaming for PlainFormatter {}
///
/// struct PlainDependency(PackageName);
/// impl Dependency for PlainDependency {
///     fn name(&self) -> &PackageName {
///         &self.0
///     }
///     fn name_range(&self) -> deps_core::position::Range {
///         deps_core::position::Range::default()
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
///     }
///     fn version_range(&self) -> Option<deps_core::position::Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn std::any::Any {
///         self
///     }
/// }
///
/// let dep = PlainDependency(PackageName::new("example"));
/// assert!(!requirement_is_placeholder_for(&PlainFormatter, &dep, "^1.2"));
/// assert!(requirement_is_placeholder_for(&PlainFormatter, &dep, "{{ version }}"));
/// ```
#[must_use]
pub fn requirement_is_placeholder_for(
    formatter: &dyn EcosystemFormatter,
    dep: &dyn Dependency,
    current: &str,
) -> bool {
    formatter.requirement_is_placeholder(&VersionReq::new(current))
        || dep
            .version_literal()
            .is_some_and(|literal| formatter.requirement_is_placeholder(&VersionReq::new(literal)))
}

/// The only production path that rewrites a manifest's version-requirement text.
///
/// `None` when [`requirement_is_placeholder_for`] says `current`/`dep`'s literal is an
/// unexpanded placeholder, else `Some(formatter.format_version_replacing_for(dep, version,
/// current))`.
///
/// Centralizing the placeholder gate here — rather than leaving it to each ecosystem's
/// [`PackageRendering::format_version_replacing`](crate::lsp_helpers::PackageRendering::format_version_replacing)/
/// [`format_version_replacing_for`](crate::lsp_helpers::PackageRendering::format_version_replacing_for)
/// override to re-check — means a formatter implementation can never destructively rewrite a
/// placeholder no matter how it is reached: the 14 previously hand-rolled per-crate guards
/// inside those methods are gone (#1391), and this free function is the sole call site that
/// still invokes them in production. Every central edit-planning call site
/// ([`collect_update_candidates`], [`plan_verified_fix`],
/// `crate::lsp_helpers::code_actions`'s unsatisfiable-requirement fix builder and REFACTOR
/// "Update to X" loop) already checks [`requirement_is_placeholder_for`] as an early gate for
/// its own control-flow reasons (skip vs. `Err`/`None`/`continue` differ per caller) before
/// ever reaching this call — that earlier check makes this function's own `None` branch
/// unreachable in practice, and is kept anyway as a fail-closed defense-in-depth backstop
/// rather than relied upon as the only gate.
///
/// # Examples
///
/// ```
/// use deps_core::edit::replacement_text;
/// use deps_core::lsp_helpers::{DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering, RequirementResolution, SourcePolicy};
/// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
///
/// struct PlainFormatter;
/// impl PackageNaming for PlainFormatter {}
/// impl PackageRendering for PlainFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for PlainFormatter {}
/// impl DiagnosticMessages for PlainFormatter {}
/// impl DiagnosticPolicy for PlainFormatter {}
/// impl SourcePolicy for PlainFormatter {}
/// impl OsvNaming for PlainFormatter {}
///
/// struct PlainDependency(PackageName);
/// impl Dependency for PlainDependency {
///     fn name(&self) -> &PackageName {
///         &self.0
///     }
///     fn name_range(&self) -> deps_core::position::Range {
///         deps_core::position::Range::default()
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
///     }
///     fn version_range(&self) -> Option<deps_core::position::Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn std::any::Any {
///         self
///     }
/// }
///
/// let dep = PlainDependency(PackageName::new("example"));
/// assert_eq!(
///     replacement_text(&PlainFormatter, &dep, &ConcreteVersion::new("1.2.3"), "^1.0"),
///     Some("1.2.3".to_string())
/// );
/// assert_eq!(
///     replacement_text(&PlainFormatter, &dep, &ConcreteVersion::new("1.2.3"), "{{ version }}"),
///     None
/// );
/// ```
#[must_use]
pub fn replacement_text(
    formatter: &dyn EcosystemFormatter,
    dep: &dyn Dependency,
    version: &ConcreteVersion,
    current: &str,
) -> Option<String> {
    if requirement_is_placeholder_for(formatter, dep, current) {
        return None;
    }
    Some(formatter.format_version_replacing_for(dep, version, current))
}

/// Protocol-agnostic replacement for `ls_types::TextEdit` — a single manifest-text
/// replacement.
///
/// # Examples
///
/// ```
/// use deps_core::edit::ManifestEdit;
/// use deps_core::position::{Position, Range};
///
/// let edit = ManifestEdit {
///     range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///     new_text: "1.2.0".to_string(),
/// };
/// assert_eq!(edit.new_text, "1.2.0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEdit {
    /// The span in the manifest source this edit replaces.
    pub range: crate::position::Range,
    /// The replacement text.
    pub new_text: String,
}

/// A manifest-edit plan with attribution — what makes ignore-rule/`--package` filtering
/// possible. The `ls_types::TextEdit` this generalizes discards everything but the edit
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedUpdate {
    /// The dependency's declared (raw) name.
    pub name: String,
    /// [`crate::lsp_helpers::PackageNaming::normalize_package_name`]'s output for `name`.
    pub normalized_name: String,
    /// The dependency name's span in the manifest source.
    pub name_range: crate::position::Range,
    /// The version this dependency is currently pinned to, when it could be resolved (see
    /// [`collect_update_edits`]'s doc for exactly how) — empty when it could not be, which
    /// [`crate::edit::classify_update`] always classifies [`UpdateKind::Unknown`].
    pub current: String,
    /// The version this edit would move the dependency to.
    pub target: ConcreteVersion,
    /// The edit itself.
    pub edit: ManifestEdit,
}

/// A type with a `[start, end)` span, generalizing over [`ManifestEdit`] (this crate) and
/// `ls_types::TextEdit` (the `lsp-responses`-gated impl in [`crate::lsp_helpers`]).
///
/// Implemented locally for a foreign type (`ls_types::TextEdit`) in the gated module —
/// orphan-rule-clean since this trait is local to this crate.
pub trait EditSpan {
    /// The span's inclusive start, as `(line, character)`.
    fn start(&self) -> (u32, u32);
    /// The span's exclusive end, as `(line, character)`.
    fn end(&self) -> (u32, u32);
}

impl EditSpan for ManifestEdit {
    fn start(&self) -> (u32, u32) {
        (self.range.start.line, self.range.start.character)
    }

    fn end(&self) -> (u32, u32) {
        (self.range.end.line, self.range.end.character)
    }
}

impl EditSpan for PlannedUpdate {
    fn start(&self) -> (u32, u32) {
        self.edit.start()
    }

    fn end(&self) -> (u32, u32) {
        self.edit.end()
    }
}

/// Sorts `edits` by start position and drops any edit that overlaps the previous one.
///
/// A dropped edit's start falls before the previous (surviving) edit's end — an overlap no
/// LSP `WorkspaceEdit`/manifest rewrite can apply safely. Generic replacement for the
/// type-specific `TextEdit` version this crate carried before #1329 — see [`EditSpan`]'s doc.
///
/// **Breaking**: this is a breaking `pub` API change on `deps-core` (the old signature only
/// accepted `Vec<ls_types::TextEdit>`) — see `CHANGELOG.md`'s `[Unreleased]` section.
///
/// `caller` names the collector in the `tracing::warn!` emitted for each dropped edit.
///
/// # Examples
///
/// ```
/// use deps_core::edit::{ManifestEdit, dedup_overlapping_edits};
/// use deps_core::position::{Position, Range};
///
/// let edits = vec![
///     ManifestEdit {
///         range: Range::new(Position::new(0, 0), Position::new(0, 5)),
///         new_text: "a".to_string(),
///     },
///     ManifestEdit {
///         range: Range::new(Position::new(0, 2), Position::new(0, 7)),
///         new_text: "b".to_string(),
///     },
/// ];
/// let kept = dedup_overlapping_edits(edits, "test");
/// assert_eq!(kept.len(), 1);
/// ```
pub fn dedup_overlapping_edits<E: EditSpan>(mut edits: Vec<E>, caller: &str) -> Vec<E> {
    edits.sort_by_key(EditSpan::start);

    let mut non_overlapping: Vec<E> = Vec::with_capacity(edits.len());
    for edit in edits {
        let overlaps_prev = non_overlapping
            .last()
            .is_some_and(|prev: &E| edit.start() < prev.end());
        if overlaps_prev {
            tracing::warn!(
                start = ?edit.start(),
                end = ?edit.end(),
                caller,
                "dropping overlapping edit"
            );
            continue;
        }
        non_overlapping.push(edit);
    }

    non_overlapping
}

/// Applies `edits` to `content`, returning the rewritten manifest text.
///
/// `edits` must be non-overlapping (see [`dedup_overlapping_edits`]) — this function does not
/// itself check for overlap, it splices every edit's range in reverse start-position order so
/// an earlier edit's byte offsets are never invalidated by a later one's length change. Each
/// edit's `range.start` must not come after its own `range.end` (an inverted range); an edit
/// violating this precondition is skipped rather than applied — every current parser
/// produces structurally ordered ranges, so this is a defense-in-depth guard against a
/// future parser bug, not an expected code path (this function is `pub` `deps-core` API
/// consumed in-process by `deps-cli`, unlike its pre-#1329 callers, which only ever handed
/// equivalent ranges back to an LSP client as `TextEdit`s for the editor to apply).
///
/// # Examples
///
/// ```
/// use deps_core::edit::{ManifestEdit, apply_edits};
/// use deps_core::position::{Position, Range};
///
/// let content = "serde = \"1.0.0\"\n";
/// let edits = vec![ManifestEdit {
///     range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///     new_text: "1.2.0".to_string(),
/// }];
/// assert_eq!(apply_edits(content, &edits), "serde = \"1.2.0\"\n");
/// ```
#[must_use]
pub fn apply_edits(content: &str, edits: &[ManifestEdit]) -> String {
    let table = LineOffsetTable::new(content);
    let mut byte_edits: Vec<(usize, usize, &str)> = edits
        .iter()
        .filter_map(|edit| {
            let start = table.position_to_byte_offset(content, edit.range.start);
            let end = table.position_to_byte_offset(content, edit.range.end);
            if start > end {
                tracing::warn!(range = ?edit.range, "dropping edit with an inverted range");
                return None;
            }
            Some((start, end, edit.new_text.as_str()))
        })
        .collect();
    byte_edits.sort_by_key(|&(start, ..)| start);

    let mut result = content.to_string();
    for &(start, end, new_text) in byte_edits.iter().rev() {
        result.replace_range(start..end, new_text);
    }
    result
}

/// The magnitude of a version bump, per semver-shaped leading-numeric-segment comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateKind {
    /// The leading numeric segment (major) differs.
    Major,
    /// Major is equal, minor differs.
    Minor,
    /// Major and minor are equal (only patch, or nothing, differs).
    Patch,
    /// `from`/`to` could not both be classified as a version with an unambiguous leading
    /// dotted-numeric segment (a SHA pin, a Go pseudo-version, a range/comparator string,
    /// `*`/`latest`/`workspace:*`, Gradle's `{strictly}!!{preferred}`, ...).
    Unknown,
}

/// Classifies the version bump from `from` to `to`.
///
/// Returns [`UpdateKind::Unknown`] unless **both** strings have an unambiguous leading
/// dotted-numeric segment (an optional `v`/`V` prefix, then one or more all-digit
/// dot-separated components, then either nothing or a `-`/`+` suffix) — deliberately not
/// built on [`crate::lsp_helpers::is_same_major_minor`], whose permissive `_ => true`
/// fallback arm is wrong for this purpose. A Go pseudo-version
/// (`v0.0.0-20210101000000-abcdef123456`) would otherwise parse as a plain leading version
/// (`0.0.0`) by accident, so it is rejected by an explicit shape check before the general
/// parse runs.
///
/// # Examples
///
/// ```
/// use deps_core::edit::{UpdateKind, classify_update};
///
/// assert_eq!(classify_update("1.2.3", "2.0.0"), UpdateKind::Major);
/// assert_eq!(classify_update("1.2.3", "1.3.0"), UpdateKind::Minor);
/// assert_eq!(classify_update("1.2.3", "1.2.4"), UpdateKind::Patch);
/// assert_eq!(classify_update("*", "1.0.0"), UpdateKind::Unknown);
/// assert_eq!(
///     classify_update("v0.0.0-20210101000000-abcdef123456", "v1.0.0"),
///     UpdateKind::Unknown
/// );
/// ```
#[must_use]
pub fn classify_update(from: &str, to: &str) -> UpdateKind {
    match (
        parse_leading_dotted_numeric(from),
        parse_leading_dotted_numeric(to),
    ) {
        (Some(f), Some(t)) => {
            if f.0 != t.0 {
                UpdateKind::Major
            } else if f.1 != t.1 {
                UpdateKind::Minor
            } else {
                UpdateKind::Patch
            }
        }
        _ => UpdateKind::Unknown,
    }
}

/// Whether `s` has the shape of a Go pseudo-version: an optional `v`/`V` prefix, then a
/// component ending in a hyphen-separated 14-digit timestamp and a 12-hex-digit commit hash
/// (`vX.Y.Z-yyyymmddhhmmss-abcdefabcdef`, or the pre-release-shaped
/// `vX.Y.Z-0.yyyymmddhhmmss-abcdefabcdef`, whose timestamp segment carries a `0.` prefix).
///
/// Checked before [`parse_leading_dotted_numeric`] runs its general parse, since a pseudo-
/// version's leading `vX.Y.Z` would otherwise parse as an ordinary version by accident.
fn is_go_pseudo_version(s: &str) -> bool {
    let body = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let mut parts = body.rsplitn(3, '-');
    let Some(hash) = parts.next() else {
        return false;
    };
    let Some(timestamp) = parts.next() else {
        return false;
    };
    if parts.next().is_none() {
        return false;
    }
    let timestamp = timestamp.strip_prefix("0.").unwrap_or(timestamp);
    hash.len() == 12
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
        && timestamp.len() == 14
        && timestamp.bytes().all(|b| b.is_ascii_digit())
}

/// Parses `s`'s leading `(major, minor, patch)` dotted-numeric segment, or `None` when `s` is
/// not unambiguously one (see [`classify_update`]'s doc). A component beyond the third is
/// still required to be all-digit (so a 4-component version like NuGet's assembly-version
/// style is accepted), but only the first three are returned.
fn parse_leading_dotted_numeric(s: &str) -> Option<(u64, u64, u64)> {
    if is_go_pseudo_version(s) {
        return None;
    }
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let core = match stripped.find(['-', '+']) {
        Some(idx) => stripped.get(..idx)?,
        None => stripped,
    };
    if core.is_empty() {
        return None;
    }

    let mut major = 0u64;
    let mut minor = 0u64;
    let mut patch = 0u64;
    let mut count = 0usize;
    for part in core.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u64 = part.parse().ok()?;
        match count {
            0 => major = n,
            1 => minor = n,
            2 => patch = n,
            _ => {}
        }
        count += 1;
    }
    if count == 0 {
        return None;
    }
    Some((major, minor, patch))
}

/// Default-mode planner: every dependency [`RequirementStatus::Outdated`] would report, as a
/// [`PlannedUpdate`].
///
/// Verbatim move of the logic `lsp_helpers::code_lenses::collect_update_all_edits` used to
/// implement directly (moved here for #1329/spec 068's `deps_core::edit` extraction; that
/// function is now a thin adapter over this one — see this crate's `lib.rs` "LSP type
/// stability" doc section) — the literal-span guard, the `is_safe_version_string` check, the
/// `requirement_status_for == Outdated` filter, the no-op guard, and overlap dedup are
/// unchanged. See that function's historical doc (preserved in git history) for the full
/// per-guard rationale.
///
/// [`PlannedUpdate::current`] is the dependency's resolved in-use version
/// ([`resolve_in_use_version`], **per occurrence**, never the collapsed per-name map — spec
/// 050's fix), when `versions` carries an [`crate::EcosystemId`]
/// ([`VersionData::with_ecosystem`]) and resolution succeeds; empty otherwise, which
/// [`classify_update`] always reports as [`UpdateKind::Unknown`] against any target.
///
/// # Examples
///
/// ```
/// use deps_core::edit::collect_update_edits;
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     PackageVersions, RequirementResolution, SourcePolicy, VersionData,
/// };
/// use deps_core::{ConcreteVersion, Dependency, ParseResult, PackageName, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use deps_core::position::{Position, Range};
///
/// struct MockFormatter;
/// impl PackageNaming for MockFormatter {}
/// impl PackageRendering for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{}", name.as_str())
///     }
/// }
/// impl RequirementResolution for MockFormatter {}
/// impl DiagnosticMessages for MockFormatter {}
/// impl DiagnosticPolicy for MockFormatter {}
/// impl SourcePolicy for MockFormatter {}
/// impl OsvNaming for MockFormatter {}
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
/// struct MockParseResult { deps: Vec<MockDep>, uri: url::Url }
/// impl ParseResult for MockParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> { None }
///     fn uri(&self) -> &url::Url { &self.uri }
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
/// let planned = collect_update_edits(
///     &parse_result,
///     content,
///     VersionData::new(&cached, &resolved),
///     &MockFormatter,
/// );
///
/// assert_eq!(planned.len(), 1);
/// assert_eq!(planned[0].edit.new_text, "1.2.0");
/// assert_eq!(planned[0].name, "serde");
/// ```
#[must_use]
pub fn collect_update_edits(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<PlannedUpdate> {
    let planned: Vec<PlannedUpdate> =
        collect_update_candidates(parse_result, content, versions, formatter)
            .into_iter()
            .filter_map(|candidate| match candidate {
                UpdateCandidate::Planned(planned) => Some(planned),
                UpdateCandidate::Unplannable { .. } => None,
            })
            .collect();

    dedup_overlapping_edits(planned, "collect_update_edits")
}

/// Why a dependency [`crate::lsp_helpers::RequirementStatus::Outdated`] could not become a
/// writable [`PlannedUpdate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnplannableReason {
    /// The registry's cached `latest` value failed the [`is_safe_version_string`] gate.
    UnsafeLatestVersion,
    /// The declared span does not hold the literal requirement text — a Maven
    /// `${property}` reference, a Gradle DSL variable/version-catalog alias, or similar.
    NonLiteralSpan,
    /// The formatter's rewrite would be a no-op (no single unambiguous rewrite exists, e.g.
    /// `deps-gradle`'s `{strictly}!!{preferred}` shorthand).
    NoOpRewrite,
}

/// One [`crate::lsp_helpers::RequirementStatus::Outdated`] dependency's planning outcome.
#[derive(Debug, Clone)]
pub enum UpdateCandidate {
    /// A safe edit was planned.
    Planned(PlannedUpdate),
    /// The dependency is `Outdated` but no edit could be safely produced — callers that
    /// report per-dependency outcomes (`deps-cli update`) must surface this rather than
    /// silently dropping the dependency; [`collect_update_edits`] (the LSP-facing planner,
    /// which only needs the writable subset) drops it instead.
    Unplannable {
        /// The dependency's declared (raw) name.
        name: String,
        /// [`crate::lsp_helpers::PackageNaming::normalize_package_name`]'s output for `name`.
        normalized_name: String,
        /// The dependency name's span in the manifest source.
        name_range: crate::position::Range,
        /// Why no edit could be planned.
        reason: UnplannableReason,
    },
}

/// Every [`crate::lsp_helpers::RequirementStatus::Outdated`] dependency, classified into
/// [`UpdateCandidate::Planned`] or [`UpdateCandidate::Unplannable`].
///
/// [`collect_update_edits`] is a thin filter over this function (only the `Planned` subset,
/// deduped) — this is the richer form `deps-cli update`'s default-mode planner consumes so an
/// `Unplannable` dependency can be reported to the operator instead of vanishing from the
/// plan with no signal (spec 068 S4).
///
/// A dependency that never reaches `Outdated` status at all (no `version_range`, unknown to
/// the registry, no declared requirement, an empty requirement, or genuinely up to date) is
/// not a candidate and produces no entry here — reporting those would be noise, not signal
/// (most manifest dependencies are exactly this case on any given run). An unexpanded
/// placeholder ([`crate::lsp_helpers::RequirementResolution::requirement_is_placeholder`],
/// #1370) is checked and skipped the same way, independent of whatever status an ecosystem's
/// own classification logic reports for it — this is one of the four central edit-planning
/// gates that predicate consults.
#[must_use]
pub fn collect_update_candidates(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<UpdateCandidate> {
    let deps = parse_result.dependencies();
    let mut candidates: Vec<UpdateCandidate> = Vec::with_capacity(deps.len());
    // Built once and reused for every dependency below (matches the pre-extraction
    // `collect_update_all_edits`'s own rationale for doing so).
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
            .map(|v| &v.latest)
        else {
            continue;
        };

        let Some(version_req) = dep.version_requirement() else {
            continue;
        };
        if version_req.as_str().is_empty() {
            // Defense-in-depth: an empty requirement would trivially satisfy the literal-span
            // guard below (both sides normalize to "") and could anchor an edit on a
            // non-literal span.
            continue;
        }
        // #1370: central placeholder gate, checked independently of `requirement_status_for`'s
        // own classification — a placeholder is never a rewrite candidate regardless of what
        // status an ecosystem's own (possibly still-buggy) classification logic reports for it,
        // the same defense-in-depth reasoning as the other three central edit-planning gates.
        if requirement_is_placeholder_for(formatter, dep, version_req.as_str()) {
            continue;
        }
        if formatter.requirement_status_for(dep, version_req, latest) != RequirementStatus::Outdated
        {
            continue;
        }

        // From here, `dep` is a confirmed `Outdated` candidate — every remaining guard below
        // must surface as `UpdateCandidate::Unplannable`, not a silent `continue`.
        let name = dep.name().as_str().to_string();
        let name_range = dep.name_range();

        if !is_safe_version_string(latest.as_str()) {
            warn_rejected_value(
                "is_safe_version_string",
                "update edit plan",
                latest.as_str(),
            );
            candidates.push(UpdateCandidate::Unplannable {
                name,
                normalized_name,
                name_range,
                reason: UnplannableReason::UnsafeLatestVersion,
            });
            continue;
        }

        // Intentionally not calling `dependency_version_range_is_literal` (#919) —
        // empty-requirement semantics differ (edit: nothing to update; completion: everything
        // to offer).
        let slice = slice_for_range(content, &line_offsets, version_range);
        let literal_target = dep
            .version_literal()
            .unwrap_or_else(|| version_req.as_str());
        if !literal_span_matches(slice, literal_target) {
            candidates.push(UpdateCandidate::Unplannable {
                name,
                normalized_name,
                name_range,
                reason: UnplannableReason::NonLiteralSpan,
            });
            continue;
        }

        // Unreachable after the gate above; fails closed rather than unwrapping.
        let Some(new_text) = replacement_text(formatter, dep, latest, version_req.as_str()) else {
            continue;
        };
        if strip_whitespace(&new_text) == strip_whitespace(literal_target) {
            candidates.push(UpdateCandidate::Unplannable {
                name,
                normalized_name,
                name_range,
                reason: UnplannableReason::NoOpRewrite,
            });
            continue;
        }

        // FR-003: per occurrence, never the collapsed per-name map — a renamed/aliased
        // dependency (spec 050) must classify against its own resolved pin. `unwrap_or_default`
        // (empty string) is the honest "unresolvable" value: `classify_update` always maps it
        // to `UpdateKind::Unknown`.
        let current = versions
            .ecosystem
            .and_then(|ecosystem| {
                resolve_in_use_version(
                    dep,
                    &normalized_name,
                    versions.resolved,
                    versions.resolved_version_candidates,
                    formatter,
                    ecosystem,
                )
            })
            .unwrap_or_default();

        candidates.push(UpdateCandidate::Planned(PlannedUpdate {
            name,
            normalized_name,
            name_range,
            current,
            target: latest.clone(),
            edit: ManifestEdit {
                range: version_range,
                new_text,
            },
        }));
    }

    candidates
}

/// Why [`plan_vulnerability_fix`] could not produce a [`PlannedUpdate`] for a dependency
/// already known to be [`crate::osv::ScanOutcome::Vulnerable`].
///
/// Mirrors [`UnplannableReason`]'s role for the default-mode planner (spec 068's typed-skip
/// convention) — before this type existed, every one of these six causes collapsed into a
/// single `None`, forcing `deps-cli update --security-only`'s
/// `classify_vulnerable_dependency` to re-run [`resolve_recommended_fix`]'s and
/// `fix_target_is_verified`'s own chain itself just to tell `NoVerifiedFix` apart from
/// `RequiresLockfileUpdate` (#1350).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnFixSkip {
    /// No advisory on `dv` has a claimable fix — [`crate::osv::DependencyVulnerabilities::recommended_fix`]
    /// returned `None`.
    NoRecommendedFix,
    /// The recommended fix's version, converted to this ecosystem's native namespace, failed
    /// [`is_safe_version_string`].
    UnsafeVersion,
    /// The internal fix-target verification gate could not confirm the fix target F against
    /// OSV — F was never live-checked, or the live check found F still vulnerable to an
    /// advisory this recommendation claims to resolve.
    UnverifiedTarget,
    /// The dependency's declared requirement, left unedited, already resolves forward to the
    /// fix target under this ecosystem's own resolution rules — nothing to rewrite (#1344).
    RequirementAlreadyResolves,
    /// The formatter's rewrite would be textually identical to the declared literal — no edit
    /// to make.
    NoOpRewrite,
    /// `current` is an unexpanded placeholder/interpolation
    /// ([`crate::lsp_helpers::RequirementResolution::requirement_is_placeholder`]) — there is
    /// no concrete version text to replace, so the requirement is never rewritten regardless
    /// of what any other resolution predicate or the formatter's own rewrite logic would do
    /// with it (#1370).
    UnresolvedPlaceholder,
}

/// Resolves and validates the OSV-recommended fix for `dv`.
///
/// The common prefix every vulnerability-fix caller needs before it can decide what to do
/// next: is there a fix, and is its version string safe to act on. Shared by
/// [`plan_vulnerability_fix`] and `deps-engine`'s phase-B fix-target verification
/// (`classify::osv::resolve_fix_target`), which independently ran the same two steps before
/// this was extracted (#1350).
///
/// # Errors
///
/// Returns [`VulnFixSkip::NoRecommendedFix`] when `dv.recommended_fix()` is `None`, or
/// [`VulnFixSkip::UnsafeVersion`] when the fix's version fails [`is_safe_version_string`].
///
/// # Examples
///
/// ```
/// use deps_core::edit::{VulnFixSkip, resolve_recommended_fix};
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::{Advisory, Capped, DependencyVulnerabilities, VulnSeverity};
/// use deps_core::{ConcreteVersion, PackageName};
/// use std::sync::Arc;
///
/// struct MockFormatter;
/// impl PackageNaming for MockFormatter {}
/// impl PackageRendering for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{}", name.as_str())
///     }
/// }
/// impl RequirementResolution for MockFormatter {}
/// impl DiagnosticMessages for MockFormatter {}
/// impl DiagnosticPolicy for MockFormatter {}
/// impl SourcePolicy for MockFormatter {}
/// impl OsvNaming for MockFormatter {}
///
/// let dv = DependencyVulnerabilities::new(Capped::new(Vec::<Arc<Advisory>>::new(), 0));
/// assert_eq!(
///     resolve_recommended_fix(&dv, &MockFormatter),
///     Err(VulnFixSkip::NoRecommendedFix)
/// );
/// ```
pub fn resolve_recommended_fix(
    dv: &crate::osv::DependencyVulnerabilities,
    formatter: &dyn EcosystemFormatter,
) -> Result<(crate::osv::FixRecommendation, String), VulnFixSkip> {
    let fix = dv.recommended_fix().ok_or(VulnFixSkip::NoRecommendedFix)?;
    let version_native = formatter.osv_version_to_native(&fix.version).into_string();
    if !is_safe_version_string(&version_native) {
        warn_rejected_value(
            "is_safe_version_string",
            "vulnerability fix plan",
            &version_native,
        );
        return Err(VulnFixSkip::UnsafeVersion);
    }
    Ok((fix, version_native))
}

/// Whether `dv.fix_target_status` clears `fix`'s target version as an honest, presentable fix
/// (#462 FR-003) — verbatim move of `lsp_helpers::code_actions`'s private helper of the same
/// name and doc.
///
/// `CandidateClean { version: F }` always clears it. A `CandidateVulnerable { version: F,
/// advisory_ids }` result can also clear it — F may legitimately still be affected by
/// advisories `recommended_fix()` never claimed to resolve in the first place — but is
/// suppressed the moment `advisory_ids` names either a *claimed* advisory or one this
/// dependency's own `advisories` never recorded at all. Any other state means F was never
/// actually verified, so it is rejected too. `known_ids` is built from `dv.advisories`, the
/// fix-computation set capped at [`crate::osv::MAX_ADVISORY_RECORDS`] — not the smaller,
/// render-only [`crate::osv::DependencyVulnerabilities::advisories_for_display`] — so this gate
/// sees the same advisory set `recommended_fix()` itself claimed against (#1422).
///
/// `pub(crate)`: `deps-cli update --security-only` (#1329) used to call this directly to
/// distinguish "no verified fix target" from [`plan_vulnerability_fix`]'s other `None` cause,
/// but now matches on [`VulnFixSkip`] directly (#1350), so this no longer needs to be `pub`.
#[must_use]
pub(crate) fn fix_target_is_verified(
    dv: &crate::osv::DependencyVulnerabilities,
    fix: &crate::osv::FixRecommendation,
    version_native: &str,
) -> bool {
    use crate::osv::UpgradeStatus;
    use std::collections::HashSet;

    match &dv.fix_target_status {
        UpgradeStatus::CandidateClean { version } => version == version_native,
        UpgradeStatus::CandidateVulnerable {
            version,
            advisory_ids,
        } => {
            if version != version_native || !advisory_ids.is_complete() {
                return false;
            }
            let known_ids: HashSet<&str> = dv
                .advisories
                .items()
                .iter()
                .map(|a| a.id.as_str())
                .collect();
            advisory_ids
                .items()
                .iter()
                .all(|id| known_ids.contains(id.as_str()) && !fix.advisory_ids.contains(id))
        }
        UpgradeStatus::NotChecked => false,
    }
}

/// [`resolve_recommended_fix`] plus the internal `fix_target_is_verified` gate — resolves the
/// OSV-recommended fix for `dv` AND confirms its target version's own OSV status.
///
/// Callers that need to know "is there a *usable* fix" (not just "is there *a* fix") call
/// this instead of [`resolve_recommended_fix`] alone — see [`plan_vulnerability_fix`] and
/// `deps-cli`'s `classify_vulnerable_dependency` (#1350 S1 regression fix: that caller must
/// run this check *before* any other requirement/range/yanked-status decision, exactly as it
/// did when it held its own copy of the `fix_target_is_verified` call, or an unverified fix
/// target gets misreported as `RequiresLockfileUpdate`/`Unfixable(Yanked)` instead of
/// `Unfixable(NoVerifiedFix)`).
///
/// `deps-engine`'s phase-B fix-target verification (`classify::osv::resolve_fix_target`) is
/// the producer of `dv.fix_target_status` in the first place, so it calls
/// [`resolve_recommended_fix`] directly instead of this function — gating on a status it has
/// not computed yet would be circular.
///
/// # Errors
///
/// Returns anything [`resolve_recommended_fix`] can return, plus
/// [`VulnFixSkip::UnverifiedTarget`] when the internal `fix_target_is_verified` gate rejects
/// the fix target.
///
/// # Examples
///
/// ```
/// use deps_core::edit::{VulnFixSkip, resolve_verified_fix};
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::{
///     Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
/// };
/// use deps_core::{ConcreteVersion, PackageName};
/// use std::sync::Arc;
///
/// struct MockFormatter;
/// impl PackageNaming for MockFormatter {}
/// impl PackageRendering for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{}", name.as_str())
///     }
/// }
/// impl RequirementResolution for MockFormatter {}
/// impl DiagnosticMessages for MockFormatter {}
/// impl DiagnosticPolicy for MockFormatter {}
/// impl SourcePolicy for MockFormatter {}
/// impl OsvNaming for MockFormatter {}
///
/// let advisory = Arc::new(
///     Advisory::new(
///         "RUSTSEC-2024-0001".to_string(),
///         "2024-01-01T00:00:00Z".to_string(),
///         VulnSeverity::High,
///     )
///     .expect("valid osv id")
///     .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
/// );
/// // `fix_target_status` left at its `NotChecked` default — never live-checked yet.
/// let unverified = DependencyVulnerabilities::new(Capped::new(vec![advisory.clone()], 1));
/// assert_eq!(
///     resolve_verified_fix(&unverified, &MockFormatter),
///     Err(VulnFixSkip::UnverifiedTarget)
/// );
///
/// let verified = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
///     .with_fix_target_status(UpgradeStatus::CandidateClean { version: "1.2.0".to_string() });
/// assert!(resolve_verified_fix(&verified, &MockFormatter).is_ok());
/// ```
pub fn resolve_verified_fix(
    dv: &crate::osv::DependencyVulnerabilities,
    formatter: &dyn EcosystemFormatter,
) -> Result<(crate::osv::FixRecommendation, String), VulnFixSkip> {
    let (fix, version_native) = resolve_recommended_fix(dv, formatter)?;
    if !fix_target_is_verified(dv, &fix, &version_native) {
        return Err(VulnFixSkip::UnverifiedTarget);
    }
    Ok((fix, version_native))
}

/// Security-mode planner: plans the vulnerability-fix edit for one dependency.
///
/// The dependency must already be known to be [`crate::osv::ScanOutcome::Vulnerable`]; this
/// targets [`crate::osv::DependencyVulnerabilities::recommended_fix`] rather than `latest`.
///
/// Originally a verbatim move of `lsp_helpers::code_actions::build_vulnerability_fix_action`'s
/// planning core (the no-op guard, `is_safe_version_string`, `osv_version_to_native`,
/// `format_version_replacing_for`, and the `fix_target_is_verified` gate) — yank/timeout
/// filtering is deliberately **not** moved: both `deps-lsp` and `deps-cli` apply their own
/// source and policy for that (see `lsp_helpers::code_actions::generate_code_actions`'s
/// yank-filtering block and `deps-cli`'s `update::security` module).
///
/// #1344: also gated on whether `dep`'s own declared requirement, left unedited, already
/// *resolves forward* to the fix target under this ecosystem's own resolution rules
/// (`formatter.requirement_already_resolves_to(..)`) — not just the textual no-op guard below
/// (which only catches the declared literal already *spelling* the fix version verbatim).
/// `serde = "1"` with fix `1.0.2` must not be rewritten to `serde = "1.0.2"`: the declared
/// range already accepts `1.0.2`, so re-resolving already gets there without a manifest edit
/// (a `cargo update`/lock-file refresh, for an ecosystem that has one — not every ecosystem
/// does: Maven and Gradle have none, and a NuGet project's is opt-in. For those, suppression
/// is instead because the requirement already structurally expresses the fix — e.g. a Maven
/// dynamic range/`LATEST`/`SNAPSHOT` resolves it at build time — not because of any lock
/// file). `requirement_already_resolves_to`'s default asks only "is the fix a member of the
/// requirement's accepted set", correct for a requirement a resolver picks its *newest*
/// admissible member from, but wrong for one a resolver instead pins to its *lowest*
/// admissible member (NuGet's bare `Version="1.0.0"` floor, #1344) — ecosystems with that
/// resolution shape override the method rather than relying on the default; see
/// `deps-nuget`'s override. Ecosystems with no `compile_requirement` override (GitHub Actions,
/// GitLab CI — SHA/tag pins, not version ranges) fall through to the textual no-op guard as
/// the only available signal. Originally only checked by `deps-cli update --security-only`'s
/// `classify_vulnerable_dependency` (#1329); moved here so `deps-lsp`'s vulnerability-fix code
/// action shares the same decision instead of reimplementing it.
///
/// `dv` and `current` are supplied by the caller rather than resolved internally — the
/// pre-extraction function rebuilt `crate::osv::vulnerability_keys` per call, tolerable for
/// one position-driven LSP request but O(n²) for a planner iterating every dependency in a
/// manifest; both call sites now build that map once and look up each dependency's key
/// themselves.
///
/// # Examples
///
/// ```
/// use deps_core::edit::plan_vulnerability_fix;
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::{
///     Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
/// };
/// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
/// use deps_core::position::{Position, Range};
/// use std::any::Any;
/// use std::sync::Arc;
///
/// struct MockFormatter;
/// impl PackageNaming for MockFormatter {}
/// impl PackageRendering for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{}", name.as_str())
///     }
/// }
/// impl RequirementResolution for MockFormatter {}
/// impl DiagnosticMessages for MockFormatter {}
/// impl DiagnosticPolicy for MockFormatter {}
/// impl SourcePolicy for MockFormatter {}
/// impl OsvNaming for MockFormatter {}
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
/// let dep = MockDep {
///     name: PackageName::new("serde"),
///     version_req: VersionReq::new("1.0.0"),
///     version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
/// };
///
/// let advisory = Arc::new(
///     Advisory::new(
///         "RUSTSEC-2024-0001".to_string(),
///         "2024-01-01T00:00:00Z".to_string(),
///         VulnSeverity::High,
///     )
///     .expect("valid osv id")
///     .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
/// );
/// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
///     .with_fix_target_status(UpgradeStatus::CandidateClean { version: "1.2.0".to_string() });
///
/// let planned = plan_vulnerability_fix(&dep, dep.version_range, "1.0.0", &dv, &MockFormatter);
/// assert_eq!(planned.unwrap().edit.new_text, "1.2.0");
/// ```
///
/// # Errors
///
/// Returns [`VulnFixSkip`] for any of the six causes that make an edit impossible or
/// unnecessary — see that type's variants.
pub fn plan_vulnerability_fix(
    dep: &dyn Dependency,
    version_range: crate::position::Range,
    current: &str,
    dv: &crate::osv::DependencyVulnerabilities,
    formatter: &dyn EcosystemFormatter,
) -> Result<PlannedUpdate, VulnFixSkip> {
    let (_fix, version_native) = resolve_verified_fix(dv, formatter)?;
    plan_verified_fix(dep, version_range, current, &version_native, formatter)
}

/// The remainder of [`plan_vulnerability_fix`]'s decision, for a fix target already resolved
/// and verified via [`resolve_verified_fix`].
///
/// Split out for a caller that already holds `version_native` because it needed it for its
/// own decision (e.g. a yank check) before ever reaching this point —
/// [`plan_vulnerability_fix`] itself calls [`resolve_verified_fix`] internally, so calling
/// that first and then [`plan_vulnerability_fix`] would run the same resolve-and-verify chain
/// twice per dependency (code review finding, #1350). `deps-cli`'s
/// `classify_vulnerable_dependency` is this function's only caller outside
/// [`plan_vulnerability_fix`] itself.
///
/// # Errors
///
/// Returns [`VulnFixSkip::UnresolvedPlaceholder`], [`VulnFixSkip::RequirementAlreadyResolves`],
/// or [`VulnFixSkip::NoOpRewrite`] — the three causes that can still make an edit unnecessary
/// once the fix is already known resolved and verified.
pub fn plan_verified_fix(
    dep: &dyn Dependency,
    version_range: crate::position::Range,
    current: &str,
    version_native: &str,
    formatter: &dyn EcosystemFormatter,
) -> Result<PlannedUpdate, VulnFixSkip> {
    // #1370: central placeholder gate, checked first — an unexpanded placeholder has no
    // concrete version text to replace, independent of whether `requirement_already_resolves_to`
    // or the formatter's own rewrite logic would coincidentally treat it as safe. Checked
    // against `current` (the exact text a caller is about to consider rewriting), not
    // `dep.version_requirement()`, since a caller may reach this with `current` derived from
    // somewhere other than the dependency's own preserved requirement field.
    if requirement_is_placeholder_for(formatter, dep, current) {
        return Err(VulnFixSkip::UnresolvedPlaceholder);
    }

    let fix_concrete = ConcreteVersion::new(version_native);
    let requirement_already_resolves_to_fix =
        dep.version_requirement().is_some_and(|version_req| {
            formatter.requirement_already_resolves_to(version_req, &fix_concrete)
        });
    if requirement_already_resolves_to_fix {
        return Err(VulnFixSkip::RequirementAlreadyResolves);
    }

    // Unreachable after the gate above; fails closed rather than unwrapping.
    let Some(new_text) = replacement_text(formatter, dep, &fix_concrete, current) else {
        return Err(VulnFixSkip::UnresolvedPlaceholder);
    };
    let literal_target = dep.version_literal().unwrap_or(current);
    if strip_whitespace(literal_target) == strip_whitespace(&new_text) {
        return Err(VulnFixSkip::NoOpRewrite);
    }

    let normalized_name = formatter.normalize_package_name(dep.name());
    Ok(PlannedUpdate {
        name: dep.name().as_str().to_string(),
        normalized_name,
        name_range: dep.name_range(),
        current: current.to_string(),
        target: ConcreteVersion::new(version_native),
        edit: ManifestEdit {
            range: version_range,
            new_text,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::Position;

    fn range(sl: u32, sc: u32, el: u32, ec: u32) -> crate::position::Range {
        crate::position::Range::new(Position::new(sl, sc), Position::new(el, ec))
    }

    // --- classify_update / UpdateKind ---

    #[test]
    fn test_classify_update_major() {
        assert_eq!(classify_update("1.2.3", "2.0.0"), UpdateKind::Major);
    }

    #[test]
    fn test_classify_update_minor() {
        assert_eq!(classify_update("1.2.3", "1.3.0"), UpdateKind::Minor);
    }

    #[test]
    fn test_classify_update_patch() {
        assert_eq!(classify_update("1.2.3", "1.2.4"), UpdateKind::Patch);
    }

    #[test]
    fn test_classify_update_v_prefix() {
        assert_eq!(classify_update("v1.2.3", "v2.0.0"), UpdateKind::Major);
    }

    #[test]
    fn test_classify_update_prerelease_and_build_suffix_ignored() {
        assert_eq!(
            classify_update("1.2.3-alpha.1", "1.2.3+build.5"),
            UpdateKind::Patch
        );
    }

    #[test]
    fn test_classify_update_github_actions_sha_pin_is_unknown() {
        assert_eq!(
            classify_update(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
            ),
            UpdateKind::Unknown
        );
    }

    #[test]
    fn test_classify_update_go_pseudo_version_is_unknown() {
        assert_eq!(
            classify_update("v0.0.0-20210101000000-abcdef123456", "v1.0.0"),
            UpdateKind::Unknown
        );
        assert_eq!(
            classify_update(
                "v1.2.3-0.20210101000000-abcdef123456",
                "v1.2.3-0.20210102000000-abcdef654321"
            ),
            UpdateKind::Unknown
        );
    }

    #[test]
    fn test_classify_update_maven_nuget_range_syntax_is_unknown() {
        assert_eq!(classify_update("[1.0,2.0)", "2.0.0"), UpdateKind::Unknown);
        assert_eq!(classify_update("1.0.0", "[1.0,2.0)"), UpdateKind::Unknown);
    }

    #[test]
    fn test_classify_update_wildcard_latest_workspace_star_is_unknown() {
        assert_eq!(classify_update("*", "1.0.0"), UpdateKind::Unknown);
        assert_eq!(classify_update("latest", "1.0.0"), UpdateKind::Unknown);
        assert_eq!(classify_update("workspace:*", "1.0.0"), UpdateKind::Unknown);
    }

    #[test]
    fn test_classify_update_gradle_strictly_preferred_syntax_is_unknown() {
        assert_eq!(
            classify_update("{strictly 1.0}!!1.2", "1.3.0"),
            UpdateKind::Unknown
        );
    }

    #[test]
    fn test_classify_update_equal_versions_is_patch() {
        assert_eq!(classify_update("1.2.3", "1.2.3"), UpdateKind::Patch);
    }

    #[test]
    fn test_classify_update_four_component_version() {
        assert_eq!(classify_update("1.0.0.0", "1.0.1.0"), UpdateKind::Patch);
    }

    // --- dedup_overlapping_edits<ManifestEdit> ---

    #[test]
    fn test_dedup_overlapping_manifest_edits_drops_the_later_overlap() {
        let edits = vec![
            ManifestEdit {
                range: range(0, 0, 0, 5),
                new_text: "a".to_string(),
            },
            ManifestEdit {
                range: range(0, 2, 0, 7),
                new_text: "b".to_string(),
            },
        ];
        let kept = dedup_overlapping_edits(edits, "test");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].new_text, "a");
    }

    #[test]
    fn test_dedup_non_overlapping_manifest_edits_keeps_both() {
        let edits = vec![
            ManifestEdit {
                range: range(0, 0, 0, 5),
                new_text: "a".to_string(),
            },
            ManifestEdit {
                range: range(1, 0, 1, 5),
                new_text: "b".to_string(),
            },
        ];
        let kept = dedup_overlapping_edits(edits, "test");
        assert_eq!(kept.len(), 2);
    }

    // --- apply_edits ---

    #[test]
    fn test_apply_edits_single_line() {
        let content = "serde = \"1.0.0\"\n";
        let edits = vec![ManifestEdit {
            range: range(0, 9, 0, 14),
            new_text: "1.2.0".to_string(),
        }];
        assert_eq!(apply_edits(content, &edits), "serde = \"1.2.0\"\n");
    }

    #[test]
    fn test_apply_edits_multiple_lines_reverse_splice() {
        let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\n";
        let edits = vec![
            ManifestEdit {
                range: range(0, 9, 0, 14),
                new_text: "1.2.0".to_string(),
            },
            ManifestEdit {
                range: range(1, 9, 1, 14),
                new_text: "1.3.0".to_string(),
            },
        ];
        assert_eq!(
            apply_edits(content, &edits),
            "serde = \"1.2.0\"\ntokio = \"1.3.0\"\n"
        );
    }

    #[test]
    fn test_apply_edits_empty_slice_is_a_no_op() {
        let content = "serde = \"1.0.0\"\n";
        assert_eq!(apply_edits(content, &[]), content);
    }

    /// Security-S2 regression: an inverted range (`start > end`) must be dropped, not panic
    /// `replace_range`. `apply_edits` splices ranges in-process now (deps-cli), unlike its
    /// pre-#1329 callers, which only ever handed ranges back to an LSP client.
    #[test]
    fn test_apply_edits_drops_inverted_range_instead_of_panicking() {
        let content = "serde = \"1.0.0\"\n";
        let edits = vec![ManifestEdit {
            range: range(0, 14, 0, 9),
            new_text: "evil".to_string(),
        }];
        assert_eq!(apply_edits(content, &edits), content);
    }

    #[test]
    fn test_apply_edits_valid_edit_still_applies_alongside_a_dropped_inverted_one() {
        let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\n";
        let edits = vec![
            ManifestEdit {
                range: range(0, 14, 0, 9),
                new_text: "evil".to_string(),
            },
            ManifestEdit {
                range: range(1, 9, 1, 14),
                new_text: "1.3.0".to_string(),
            },
        ];
        assert_eq!(
            apply_edits(content, &edits),
            "serde = \"1.0.0\"\ntokio = \"1.3.0\"\n"
        );
    }

    // --- collect_update_edits / collect_update_candidates ---

    mod collect_update_tests {
        use super::*;
        use crate::lsp_helpers::PackageVersions;
        use crate::lsp_helpers::test_support::{MOCK_FORMATTER, MockDep, MockParseResult, pkg};
        use crate::{EcosystemId, PackageName};
        use std::collections::HashMap;

        fn dep(name: &str, req: &str, version_range: crate::position::Range) -> MockDep {
            MockDep {
                name: pkg(name),
                version_req: crate::VersionReq::new(req),
                version_range,
                name_range: crate::position::Range::default(),
            }
        }

        fn parse_result(deps: Vec<MockDep>) -> MockParseResult {
            MockParseResult {
                deps,
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            }
        }

        /// spec 050 (T002): a renamed/aliased dependency's two occurrences must each
        /// classify `current` against their own resolved pin, never the collapsed per-name
        /// map.
        #[test]
        fn test_collect_update_edits_renamed_occurrence_resolves_its_own_pin() {
            let content = "serde = \"0.9\"\nserde = \"1.0\"\n";
            let pr = parse_result(vec![
                dep("serde", "0.9", range(0, 9, 0, 12)),
                dep("serde", "1.0", range(1, 9, 1, 12)),
            ]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            let resolved_versions: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let mut candidates = HashMap::new();
            candidates.insert(
                pkg("serde"),
                vec![
                    ConcreteVersion::from("0.9.15"),
                    ConcreteVersion::from("1.0.219"),
                ],
            );
            let versions = VersionData::new(&cached, &resolved_versions)
                .with_resolved_version_candidates(&candidates)
                .with_ecosystem(EcosystemId::Cargo);

            let mut planned = collect_update_edits(&pr, content, versions, &MOCK_FORMATTER);
            planned.sort_by_key(|p| p.edit.range.start.line);

            assert_eq!(planned.len(), 2);
            assert_eq!(planned[0].current, "0.9.15");
            assert_eq!(planned[1].current, "1.0.219");
        }

        #[test]
        fn test_collect_update_candidates_non_literal_span_is_unplannable() {
            // Mirrors the Maven `${property}` class: `version_range` spans a reference, not
            // the literal requirement text.
            let content = "<version>${slf4j.version}</version>";
            let pr = parse_result(vec![dep("slf4j-api", "2.0.16", range(0, 9, 0, 25))]);
            let mut cached = HashMap::new();
            cached.insert("slf4j-api".into(), PackageVersions::latest_only("2.1.0"));
            let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let candidates = collect_update_candidates(&pr, content, versions, &MOCK_FORMATTER);
            assert_eq!(candidates.len(), 1);
            assert!(matches!(
                candidates[0],
                UpdateCandidate::Unplannable {
                    reason: UnplannableReason::NonLiteralSpan,
                    ..
                }
            ));
            assert!(
                collect_update_edits(&pr, content, versions, &MOCK_FORMATTER).is_empty(),
                "an unplannable candidate must never reach collect_update_edits's writable subset"
            );
        }

        #[test]
        fn test_collect_update_candidates_no_op_rewrite_is_unplannable() {
            struct NoOpFormatter;
            impl crate::lsp_helpers::PackageNaming for NoOpFormatter {}
            impl crate::lsp_helpers::PackageRendering for NoOpFormatter {
                fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                    version.to_string()
                }
                fn package_url(&self, name: &PackageName) -> String {
                    name.as_str().to_string()
                }
                fn format_version_replacing(
                    &self,
                    _version: &ConcreteVersion,
                    current: &str,
                ) -> String {
                    current.to_string()
                }
            }
            impl crate::lsp_helpers::RequirementResolution for NoOpFormatter {
                fn is_requirement_up_to_date(
                    &self,
                    _requirement: &crate::VersionReq,
                    _latest: &ConcreteVersion,
                ) -> bool {
                    false
                }
            }
            impl crate::lsp_helpers::DiagnosticMessages for NoOpFormatter {}
            impl crate::lsp_helpers::DiagnosticPolicy for NoOpFormatter {}
            impl crate::lsp_helpers::SourcePolicy for NoOpFormatter {}
            impl crate::lsp_helpers::OsvNaming for NoOpFormatter {}

            let content = "pkg = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("pkg", "1.0.0", range(0, 7, 0, 12))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("1.2.0"));
            let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let candidates = collect_update_candidates(&pr, content, versions, &NoOpFormatter);
            assert_eq!(candidates.len(), 1);
            assert!(matches!(
                candidates[0],
                UpdateCandidate::Unplannable {
                    reason: UnplannableReason::NoOpRewrite,
                    ..
                }
            ));
        }

        #[test]
        fn test_collect_update_candidates_unsafe_latest_is_unplannable() {
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", "1.0.0", range(0, 8, 0, 15))]);
            let mut cached = HashMap::new();
            cached.insert(
                "serde".into(),
                PackageVersions::latest_only("1.2.0\", \"evil\": \"true"),
            );
            let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let candidates = collect_update_candidates(&pr, content, versions, &MOCK_FORMATTER);
            assert_eq!(candidates.len(), 1);
            assert!(matches!(
                candidates[0],
                UpdateCandidate::Unplannable {
                    reason: UnplannableReason::UnsafeLatestVersion,
                    ..
                }
            ));
        }

        #[test]
        fn test_collect_update_candidates_up_to_date_dependency_produces_no_candidate() {
            // A dependency that is not `Outdated` at all must produce no entry — reporting
            // every up-to-date dependency as a "candidate" would be noise, not signal.
            let content = "serde = \"^1.0\"\n";
            let pr = parse_result(vec![dep("serde", "^1.0", range(0, 8, 0, 14))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let candidates = collect_update_candidates(&pr, content, versions, &MOCK_FORMATTER);
            assert!(candidates.is_empty());
        }
    }

    // --- plan_vulnerability_fix: #1344 requirement-already-admits-fix gate, #1347
    // requirement_is_unresolved hardening ---

    mod plan_vulnerability_fix_tests {
        use super::*;
        use crate::PackageName;
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::{
            MOCK_FORMATTER, MockDep, StrictSemverFormatter, pkg,
        };
        use crate::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementMatcher, RequirementResolution, SourcePolicy,
        };
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        fn dep(name: &str, req: &str, version_range: crate::position::Range) -> MockDep {
            MockDep {
                name: PackageName::new(name),
                version_req: crate::VersionReq::new(req),
                version_range,
                name_range: crate::position::Range::default(),
            }
        }

        fn verified_dv(fixed_version: &str) -> DependencyVulnerabilities {
            let advisory = std::sync::Arc::new(
                Advisory::new(
                    "RUSTSEC-2024-0001".to_string(),
                    "2024-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                )
                .expect("valid osv id")
                .with_fixed_versions(vec![OsvVersion::new(fixed_version)]),
            );
            DependencyVulnerabilities::new(Capped::new(vec![advisory], 1)).with_fix_target_status(
                UpgradeStatus::CandidateClean {
                    version: fixed_version.to_string(),
                },
            )
        }

        /// Reproduces `GithubActionsFormatter`'s real semantics: `requirement_is_unresolved`
        /// is `true` for a full-SHA pin (it means "not decidable from text alone", not
        /// "unexpanded placeholder"), yet `format_version_replacing_for` still produces a
        /// legitimate SHA-preserving rewrite for it. Guards against reintroducing #1347's C1
        /// regression (gating `plan_vulnerability_fix` on `requirement_is_unresolved`, which
        /// would silently drop this ecosystem's working vulnerability remediation) — a real
        /// cross-crate `GithubActionsFormatter` can't be used here (`deps-core` cannot depend
        /// on `deps-github-actions`), so this mock reproduces its documented override shape
        /// instead.
        struct ShaPinFormatter;
        impl PackageNaming for ShaPinFormatter {}
        impl PackageRendering for ShaPinFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &crate::PackageName) -> String {
                name.as_str().to_string()
            }
            fn format_version_replacing(
                &self,
                version: &ConcreteVersion,
                _current: &str,
            ) -> String {
                format!("{version} # v-resolved")
            }
        }
        impl RequirementResolution for ShaPinFormatter {
            fn requirement_is_unresolved(&self, _requirement: &VersionReq) -> bool {
                true
            }
        }
        impl DiagnosticMessages for ShaPinFormatter {}
        impl DiagnosticPolicy for ShaPinFormatter {}
        impl SourcePolicy for ShaPinFormatter {}
        impl OsvNaming for ShaPinFormatter {}

        /// A caret range ("^1" is what Cargo/npm-shaped bare "1" compiles to) that already
        /// admits the fix target must suppress the edit — the declared requirement needs no
        /// manifest change, only a lock-file update.
        #[test]
        fn test_requirement_already_admitting_fix_returns_none() {
            let d = dep("serde", "1", range(0, 8, 0, 9));
            let dv = verified_dv("1.0.2");

            let planned =
                plan_vulnerability_fix(&d, d.version_range, "1", &dv, &StrictSemverFormatter);
            assert_eq!(planned, Err(VulnFixSkip::RequirementAlreadyResolves));
        }

        /// A requirement the comparator confirms does NOT admit the fix target must still
        /// produce a rewrite — the #1344 gate must not suppress legitimate fixes.
        #[test]
        fn test_requirement_not_admitting_fix_returns_planned_edit() {
            let d = dep("serde", "0.9", range(0, 8, 0, 11));
            let dv = verified_dv("1.0.2");

            let planned =
                plan_vulnerability_fix(&d, d.version_range, "0.9", &dv, &StrictSemverFormatter)
                    .expect("0.9 does not admit 1.0.2, so an edit must be planned");
            assert_eq!(planned.edit.new_text, "1.0.2");
            assert_eq!(planned.target.as_str(), "1.0.2");
        }

        /// An ecosystem with no `compile_requirement` override (e.g. GitHub Actions/GitLab CI)
        /// has no comparator to consult, so the gate is inert and the textual no-op guard is
        /// the only available signal — a genuinely different target must still be planned.
        #[test]
        fn test_no_compile_requirement_override_falls_back_to_no_op_guard() {
            let d = dep("serde", "1", range(0, 8, 0, 9));
            let dv = verified_dv("1.0.2");

            let planned =
                plan_vulnerability_fix(&d, d.version_range, "1", &dv, &MOCK_FORMATTER).unwrap();
            assert_eq!(planned.edit.new_text, "\"1.0.2\"");
        }

        /// A malformed `fixed_versions` entry (as if it somehow reached this dependency's
        /// `advisories` despite OSV's own wire-boundary validation) must be rejected before
        /// any other gate runs — `VulnFixSkip::UnsafeVersion`, not a planned edit.
        #[test]
        fn test_unsafe_fix_version_is_rejected() {
            let d = dep("serde", "0.9", range(0, 8, 0, 11));
            // A space is not in `is_safe_version_string`'s allowlist.
            let dv = verified_dv("1.2.0 evil");

            let planned = plan_vulnerability_fix(&d, d.version_range, "0.9", &dv, &MOCK_FORMATTER);
            assert_eq!(planned, Err(VulnFixSkip::UnsafeVersion));
        }

        /// A genuine textual no-op — the formatter's rewrite is byte-identical to the literal
        /// fallback `current` text — must be `VulnFixSkip::NoOpRewrite`, distinct from
        /// `RequirementAlreadyResolves` above (no `compile_requirement` override here, so that
        /// gate never fires; this is the plain textual guard alone).
        #[test]
        fn test_true_no_op_rewrite_is_rejected() {
            let d = dep("serde", "1", range(0, 8, 0, 9));
            let dv = verified_dv("1.0.2");

            // `MOCK_FORMATTER.format_version_for_text_edit` quotes its input, so the
            // already-quoted literal fallback below is byte-identical to the planned rewrite.
            let planned =
                plan_vulnerability_fix(&d, d.version_range, "\"1.0.2\"", &dv, &MOCK_FORMATTER);
            assert_eq!(planned, Err(VulnFixSkip::NoOpRewrite));
        }

        /// #1422 regression: a dependency with more than `ADVISORY_DISPLAY_CAP` advisories must
        /// still resolve and verify a fix computed from an advisory beyond that display cap —
        /// `resolve_recommended_fix`/`fix_target_is_verified` must read the full
        /// `MAX_ADVISORY_RECORDS`-capped `advisories` set, not the render-only
        /// `advisories_for_display` truncation.
        #[test]
        fn test_plan_vulnerability_fix_uses_advisory_beyond_display_cap() {
            use crate::osv::ADVISORY_DISPLAY_CAP;

            let mut advisories: Vec<std::sync::Arc<Advisory>> = (0..ADVISORY_DISPLAY_CAP + 3)
                .map(|i| {
                    std::sync::Arc::new(
                        Advisory::new(
                            format!("ADV-{i}"),
                            "2024-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.0.0")]),
                    )
                })
                .collect();
            // The true highest fix sits past ADVISORY_DISPLAY_CAP; every other advisory fixes
            // at a lower version.
            let beyond_cap_index = ADVISORY_DISPLAY_CAP + 1;
            advisories[beyond_cap_index] = std::sync::Arc::new(
                Advisory::new(
                    format!("ADV-{beyond_cap_index}"),
                    "2024-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                )
                .expect("valid osv id")
                .with_fixed_versions(vec![OsvVersion::new("2.0.0")]),
            );
            let total = advisories.len();
            let dv = DependencyVulnerabilities::new(Capped::new(advisories, total))
                .with_fix_target_status(UpgradeStatus::CandidateClean {
                    version: "2.0.0".to_string(),
                });

            let d = dep("serde", "0.9", range(0, 8, 0, 11));
            let planned = plan_vulnerability_fix(&d, d.version_range, "0.9", &dv, &MOCK_FORMATTER)
                .expect("fix beyond the display cap must still be recommended and verified");
            assert_eq!(planned.edit.new_text, "\"2.0.0\"");
            assert_eq!(planned.target.as_str(), "2.0.0");
        }

        /// A synthetic formatter mimicking a resolver that pins a bare requirement to its
        /// *lowest* admissible member (NuGet's bare `Version="1.0.0"` floor, #1344 C1) rather
        /// than following forward to the newest one. Its raw `compile_requirement` matcher is
        /// deliberately permissive (matches any version at or above the floor, exactly like
        /// NuGet's `Minimum` shape) so this test proves `plan_vulnerability_fix` consults
        /// `requirement_already_resolves_to`'s override — which correctly refuses to
        /// suppress — rather than the raw matcher alone.
        struct FloorFormatter;

        struct FloorMatcher(String);
        impl RequirementMatcher for FloorMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                Some(version.as_str() >= self.0.as_str())
            }
        }

        impl PackageNaming for FloorFormatter {}
        impl PackageRendering for FloorFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for FloorFormatter {
            fn compile_requirement(
                &self,
                requirement: &crate::VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(FloorMatcher(requirement.as_str().to_string())))
            }

            fn requirement_already_resolves_to(
                &self,
                _requirement: &crate::VersionReq,
                _target: &ConcreteVersion,
            ) -> bool {
                // A floor never auto-follows forward — leaving it unedited always keeps
                // resolving to the floor itself, never to a higher target.
                false
            }
        }
        impl DiagnosticMessages for FloorFormatter {}
        impl DiagnosticPolicy for FloorFormatter {}
        impl SourcePolicy for FloorFormatter {}
        impl OsvNaming for FloorFormatter {}

        /// #1344 C1 regression: a floor-shaped requirement must NOT be suppressed just
        /// because `compile_requirement`'s raw matcher admits the fix target — the resolver
        /// keeps pinning to the floor, so an edit is still the only way to actually apply the
        /// fix. See `deps-nuget`'s real `requirement_already_resolves_to` override for the
        /// concrete regression this mirrors.
        #[test]
        fn test_floor_shaped_requirement_still_returns_planned_edit() {
            let d = dep("nuget.pkg", "1.0.0", range(0, 8, 0, 15));
            let dv = verified_dv("1.0.2");

            // Sanity: the raw matcher alone would wrongly admit the fix, if the gate used it
            // directly instead of `requirement_already_resolves_to`.
            assert_eq!(
                FloorFormatter
                    .compile_requirement(&crate::VersionReq::new("1.0.0"))
                    .unwrap()
                    .matches(&ConcreteVersion::new("1.0.2")),
                Some(true)
            );

            let planned =
                plan_vulnerability_fix(&d, d.version_range, "1.0.0", &dv, &FloorFormatter)
                    .expect("a floor-shaped requirement must not suppress the fix");
            assert_eq!(planned.edit.new_text, "1.0.2");
        }

        #[test]
        fn test_plan_vulnerability_fix_ignores_requirement_is_unresolved() {
            let action_dep = MockDep {
                name: pkg("some-action"),
                version_req: VersionReq::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                version_range: range(0, 9, 0, 49),
                name_range: crate::position::Range::default(),
            };
            let dv = verified_dv("1.2.0");

            let planned = plan_vulnerability_fix(
                &action_dep,
                action_dep.version_range,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &dv,
                &ShaPinFormatter,
            );

            assert_eq!(
                planned.expect("fix must still be planned").edit.new_text,
                "1.2.0 # v-resolved"
            );
        }
    }
}
