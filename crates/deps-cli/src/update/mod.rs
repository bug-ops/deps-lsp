//! `deps-cli update`: default-mode planning and plan application.
//!
//! Also hosts the shared plan/outcome types both planners (this module's [`plan_updates`]
//! and [`security`]'s `plan_security_updates`) produce (spec 068, #1329).

pub mod ignore;
pub mod security;

use deps_core::PackageName;
use deps_core::edit::{
    EditSpan, ManifestEdit, UpdateKind, apply_edits, classify_update, dedup_overlapping_edits,
};
use deps_core::lsp_helpers::EcosystemFormatter;

use crate::analyze::ManifestAnalysis;
use ignore::IgnoreRules;

/// One completed `update` run's per-dependency plan.
#[derive(Debug, Clone, Default)]
pub struct UpdatePlan {
    /// One entry per candidate dependency this planner considered.
    pub items: Vec<PlannedUpdateItem>,
}

impl UpdatePlan {
    /// Every item's [`ManifestEdit`], for items whose [`Outcome`] is [`Outcome::Applied`] —
    /// what [`apply_plan`] writes.
    fn applied_edits(&self) -> Vec<ManifestEdit> {
        self.items
            .iter()
            .filter(|item| matches!(item.outcome, Outcome::Applied))
            .filter_map(|item| item.edit.clone())
            .collect()
    }
}

/// One dependency's disposition in an [`UpdatePlan`].
#[derive(Debug, Clone)]
pub struct PlannedUpdateItem {
    /// The dependency's declared (raw) name.
    pub name: String,
    /// The version this dependency is currently pinned to (or its declared requirement text,
    /// when no concrete in-use version could be resolved).
    pub current: String,
    /// The version this item's edit (when [`Self::outcome`] is [`Outcome::Applied`]) would
    /// move the dependency to — the target considered, even when no edit was written.
    pub target: String,
    /// This item's disposition.
    pub outcome: Outcome,
    /// The edit that would apply this item's `target`, present only when [`Self::outcome`]
    /// is [`Outcome::Applied`].
    pub edit: Option<ManifestEdit>,
    /// OSV advisory ids this item resolves, populated only in `--security-only` mode.
    pub advisory_ids: Vec<String>,
    /// Whether a matching `[update].ignore` rule exists but was overridden (FR-008,
    /// `--security-only` mode only — the rule never applies in default mode, since a match
    /// there is reported via <code>[Outcome::Skipped]([SkipReason::IgnoreRule])</code>
    /// instead).
    pub ignore_rule_overridden: bool,
}

/// A dependency's disposition within an [`UpdatePlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A fix plan existed and its edit was written (or would be, under `--dry-run`).
    /// Contributes to exit 0.
    Applied,
    /// Excluded from this run, for [`SkipReason`].
    Skipped(SkipReason),
    /// (`--security-only` only) The dependency is `Vulnerable`, but its declared requirement
    /// already admits the fix target, so no requirement-level edit exists — needs #1116.
    /// Contributes to exit 1.
    RequiresLockfileUpdate,
    /// (`--security-only` only) No verified fix could be written, for [`UnfixableReason`].
    /// Contributes to exit 1.
    Unfixable(UnfixableReason),
}

/// Why a default-mode candidate was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A matching `[update].ignore` rule excluded this dependency (FR-006).
    IgnoreRule,
    /// `--package` was given and this dependency was not named (FR-005).
    NotRequested,
    /// The dependency is outdated but could not be safely rewritten — the registry's cached
    /// `latest` value failed the safety gate, the declared span is not the literal
    /// requirement text (e.g. a Maven `${property}` reference or a Gradle DSL variable/
    /// version-catalog alias), or the formatter has no single unambiguous rewrite for it.
    /// See [`deps_core::edit::UnplannableReason`] for which of the three applies.
    NotSafelyEditable(deps_core::edit::UnplannableReason),
    /// The edit overlapped another item's edit and was dropped by the apply-time dedup pass
    /// (see [`dedup_applied_items`]) — a report never claims `applied` for something that was
    /// not actually written (critic finding M2).
    OverlapsAnotherEdit,
}

/// Why a `--security-only` candidate could not be fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnfixableReason {
    /// No independently-verified fix target exists: no advisory has a claimable fix, the fix
    /// target failed the safety gate, or [`deps_core::edit::fix_target_is_verified`] could
    /// not confirm it (FR-010).
    NoVerifiedFix,
    /// The dependency's registry fetch failed/timed out, or produced no `PackageVersions`
    /// entry at all — the FR-011 two-signal, load-bearing rule.
    FetchFailedOrAbsent,
    /// The fix target is present in the registry's yanked list with a status that
    /// [`deps_core::RemovalStatus::blocks_resolution`] (FR-012).
    Yanked,
}

impl Outcome {
    /// The FR-021 wire token (`--format json`'s `outcome` field, and the table's `[..]`
    /// prefix): one of exactly `applied` / `skipped` / `requires-lockfile-update` /
    /// `unfixable` — a [`SkipReason`]/[`UnfixableReason`]'s own detail is carried in
    /// [`PlannedUpdateItem::reason`] instead, not folded into this token.
    #[must_use]
    pub const fn wire_token(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Skipped(_) => "skipped",
            Self::RequiresLockfileUpdate => "requires-lockfile-update",
            Self::Unfixable(_) => "unfixable",
        }
    }
}

impl PlannedUpdateItem {
    /// A one-line human-readable reason for [`Self::outcome`] (FR-021's `reason` field).
    #[must_use]
    pub fn reason(&self) -> String {
        let base = match self.outcome {
            Outcome::Applied => "update applied",
            Outcome::Skipped(SkipReason::IgnoreRule) => "matched an [update].ignore rule",
            Outcome::Skipped(SkipReason::NotRequested) => "not named by --package",
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::UnsafeLatestVersion,
            )) => "the registry-reported latest version failed a safety check",
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::NonLiteralSpan,
            )) => {
                "the declared version is not a plain literal (e.g. a property reference or variable) and cannot be safely rewritten"
            }
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::NoOpRewrite,
            )) => "no single unambiguous rewrite exists for this dependency's requirement syntax",
            Outcome::Skipped(SkipReason::OverlapsAnotherEdit) => {
                "this edit's span overlapped another item's and was dropped"
            }
            Outcome::RequiresLockfileUpdate => {
                "declared requirement already admits the fix target; regenerate the lock file (see #1116)"
            }
            Outcome::Unfixable(UnfixableReason::NoVerifiedFix) => {
                "no independently-verified fix target is available"
            }
            Outcome::Unfixable(UnfixableReason::FetchFailedOrAbsent) => {
                "registry fetch for this dependency failed or returned no data"
            }
            Outcome::Unfixable(UnfixableReason::Yanked) => "the fix target is yanked",
        };
        if self.ignore_rule_overridden {
            format!("{base} (a matching [update].ignore rule was overridden by --security-only)")
        } else {
            base.to_string()
        }
    }
}

/// `--package` narrowing input, matched after `formatter.normalize_package_name` on both
/// sides (FR-005).
#[must_use]
pub fn is_requested(
    package_filter: &[String],
    normalized_name: &str,
    formatter: &dyn EcosystemFormatter,
) -> bool {
    package_filter.is_empty()
        || package_filter.iter().any(|name| {
            formatter.normalize_package_name(&PackageName::new(name.clone())) == normalized_name
        })
}

/// Default-mode planner: every dependency [`deps_core::edit::collect_update_candidates`]
/// considers, narrowed by `--package` and `[update].ignore` (FR-003, FR-005, FR-006, FR-007).
///
/// An outdated dependency `collect_update_candidates` could not safely rewrite (a
/// [`deps_core::edit::UpdateCandidate::Unplannable`] — an unsafe registry value, a
/// non-literal span, or a formatter with no unambiguous rewrite) is still reported here as
/// <code>[Outcome::Skipped]([SkipReason::NotSafelyEditable])</code> rather than silently
/// vanishing from the plan (spec 068 S4) — a `--package <NAME>` run naming exactly that
/// dependency must not exit 0 with no signal.
///
/// `[update].ignore` rules are honored only when `ignore_rules` was actually built from an
/// explicit `--config <path>` (FR-007) — callers pass [`IgnoreRules::empty`] otherwise, never
/// an auto-discovered config's rules.
///
/// # Examples
///
/// ```
/// use deps_cli::analyze::ManifestAnalysis;
/// use deps_cli::update::ignore::IgnoreRules;
/// use deps_cli::update::{Outcome, plan_updates};
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, DependencyOutcomes, OsvNaming, PackageNaming,
///     PackageRendering, PackageVersions, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::parser::DependencySource;
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, EcosystemId, ParseResult, PackageName, VersionReq};
/// use std::any::Any;
/// use std::collections::{HashMap, HashSet};
///
/// struct MockFormatter;
/// impl PackageNaming for MockFormatter {}
/// impl PackageRendering for MockFormatter {
///     fn format_version_for_text_edit(&self, v: &ConcreteVersion) -> String { v.to_string() }
///     fn package_url(&self, name: &PackageName) -> String { name.as_str().to_string() }
/// }
/// impl RequirementResolution for MockFormatter {}
/// impl DiagnosticMessages for MockFormatter {}
/// impl DiagnosticPolicy for MockFormatter {}
/// impl SourcePolicy for MockFormatter {}
/// impl OsvNaming for MockFormatter {}
///
/// struct MockDep { name: PackageName, version_req: VersionReq, version_range: Range }
/// impl Dependency for MockDep {
///     fn name(&self) -> &PackageName { &self.name }
///     fn name_range(&self) -> Range { Range::default() }
///     fn version_requirement(&self) -> Option<&VersionReq> { Some(&self.version_req) }
///     fn version_range(&self) -> Option<Range> { Some(self.version_range) }
///     fn source(&self) -> DependencySource { DependencySource::Registry }
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
/// let mut cached_versions = HashMap::new();
/// cached_versions.insert(PackageName::new("serde"), PackageVersions::latest_only("1.2.0"));
///
/// let analysis = ManifestAnalysis {
///     parse_result: Box::new(MockParseResult {
///         deps: vec![MockDep {
///             name: PackageName::new("serde"),
///             version_req: VersionReq::new("1.0.0"),
///             version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///         }],
///         uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
///     }),
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
///     ecosystem_id: EcosystemId::Cargo,
///     cached_versions,
///     resolved_versions: HashMap::new(),
///     resolved_version_candidates: HashMap::new(),
///     outcomes: DependencyOutcomes::new(),
///     vulnerabilities: None,
///     licenses: HashMap::new(),
///     license_policy: deps_core::licenses::LicensePolicy::default(),
///     license_source: deps_core::LicenseSource::default(),
///     offline: false,
///     fetch_failed: HashSet::new(),
///     registry_unreachable: false,
///     license_fetch_incomplete: false,
/// };
///
/// let plan = plan_updates(&analysis, content, &MockFormatter, &[], &IgnoreRules::empty());
///
/// assert_eq!(plan.items.len(), 1);
/// assert!(matches!(plan.items[0].outcome, Outcome::Applied));
/// assert_eq!(plan.items[0].target, "1.2.0");
/// ```
#[must_use]
pub fn plan_updates(
    analysis: &ManifestAnalysis,
    content: &str,
    formatter: &dyn EcosystemFormatter,
    package_filter: &[String],
    ignore_rules: &IgnoreRules,
) -> UpdatePlan {
    let candidates = deps_core::edit::collect_update_candidates(
        analysis.parse_result.as_ref(),
        content,
        analysis.version_data(),
        formatter,
    );

    let mut planned = Vec::new();
    let mut unplannable = Vec::new();
    for candidate in candidates {
        match candidate {
            deps_core::edit::UpdateCandidate::Planned(p) => planned.push(p),
            deps_core::edit::UpdateCandidate::Unplannable {
                name,
                normalized_name,
                reason,
                ..
            } => unplannable.push((name, normalized_name, reason)),
        }
    }
    // Deduped over the full writable candidate set, before any `--package`/ignore-rule
    // filtering — matches `collect_update_edits`'s own dedup semantics, so a genuinely
    // overlapping edit is dropped identically regardless of which planner produced it.
    let planned = deps_core::edit::dedup_overlapping_edits(planned, "deps-cli update plan_updates");

    let mut items: Vec<PlannedUpdateItem> = planned
        .into_iter()
        .map(|p| {
            let target = p.target.as_str().to_string();

            if !is_requested(package_filter, &p.normalized_name, formatter) {
                return PlannedUpdateItem {
                    name: p.name,
                    current: p.current,
                    target,
                    outcome: Outcome::Skipped(SkipReason::NotRequested),
                    edit: None,
                    advisory_ids: Vec::new(),
                    ignore_rule_overridden: false,
                };
            }

            let kind = classify_update(&p.current, &target);
            if let Some(reason) = ignore_rules.skip_reason(&p.normalized_name, kind) {
                return PlannedUpdateItem {
                    name: p.name,
                    current: p.current,
                    target,
                    outcome: Outcome::Skipped(reason),
                    edit: None,
                    advisory_ids: Vec::new(),
                    ignore_rule_overridden: false,
                };
            }

            PlannedUpdateItem {
                name: p.name,
                current: p.current,
                target,
                outcome: Outcome::Applied,
                edit: Some(p.edit),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
            }
        })
        .collect();

    for (name, normalized_name, reason) in unplannable {
        // Code-review finding 1: this arm previously never consulted `ignore_rules`, so a
        // dependency matching an explicit `[update].ignore` rule that also happened to be
        // structurally unplannable (non-literal span, unsafe version string, ...) was
        // misreported `Skipped(NotSafelyEditable)` — exit 1 — instead of `Skipped(IgnoreRule)`
        // — exit 0. There is no concrete `current`/`target` pair to run `classify_update` on
        // here (the candidate never got far enough to have one), so this matches an
        // unplannable candidate against `UpdateKind::Unknown`, the same fail-closed treatment
        // `skip_reason`'s own doc already gives a truly unclassifiable update.
        let outcome = if !is_requested(package_filter, &normalized_name, formatter) {
            Outcome::Skipped(SkipReason::NotRequested)
        } else if let Some(rule_reason) =
            ignore_rules.skip_reason(&normalized_name, UpdateKind::Unknown)
        {
            Outcome::Skipped(rule_reason)
        } else {
            Outcome::Skipped(SkipReason::NotSafelyEditable(reason))
        };
        items.push(PlannedUpdateItem {
            name,
            current: String::new(),
            target: String::new(),
            outcome,
            edit: None,
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
        });
    }

    UpdatePlan { items }
}

/// Error applying an [`UpdatePlan`] to disk.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The manifest changed on disk between planning and writing (FR-019) — the byte-compare
    /// against the content the plan's ranges were computed against failed.
    #[error("{path} changed on disk since it was read; aborting without writing")]
    StaleManifest {
        /// The manifest path.
        path: std::path::PathBuf,
    },
    /// Re-reading the manifest for the TOCTOU check failed.
    #[error("failed to re-read {path}: {source}")]
    Read {
        /// The manifest path.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// [`deps_core::fs_probe::write_atomic`] failed (including a symlink refusal).
    #[error("failed to write {path}: {source}")]
    Write {
        /// The manifest path.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Deduplicates `items`' [`Outcome::Applied`] edits by span in place, demoting any item whose
/// edit was dropped as an overlap to
/// <code>[Outcome::Skipped]([SkipReason::OverlapsAnotherEdit])</code>.
///
/// [`plan_updates`] already dedups before classification, so this is a no-op there; it is
/// load-bearing for [`security::plan_security_updates`], which does not dedup its own
/// `Applied` items (two vulnerable occurrences of one name can share a span). Without this,
/// [`apply_plan`]'s own dedup pass could silently drop an edit a planner had already reported
/// `applied`, breaking the "`applied` implies written" invariant `--format json` consumers
/// rely on (critic finding M2). Call this on a planner's output before reporting/rendering
/// it, not after — the whole point is that the *reported* outcome must match what
/// [`apply_plan`] will actually write.
pub fn dedup_applied_items(items: &mut [PlannedUpdateItem]) {
    struct Indexed {
        index: usize,
        edit: ManifestEdit,
    }
    impl EditSpan for Indexed {
        fn start(&self) -> (u32, u32) {
            self.edit.start()
        }
        fn end(&self) -> (u32, u32) {
            self.edit.end()
        }
    }

    let indexed: Vec<Indexed> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| matches!(item.outcome, Outcome::Applied))
        .filter_map(|(index, item)| item.edit.clone().map(|edit| Indexed { index, edit }))
        .collect();
    let kept_indices: std::collections::HashSet<usize> =
        dedup_overlapping_edits(indexed, "deps-cli update dedup_applied_items")
            .into_iter()
            .map(|indexed| indexed.index)
            .collect();

    for (index, item) in items.iter_mut().enumerate() {
        if matches!(item.outcome, Outcome::Applied) && !kept_indices.contains(&index) {
            item.outcome = Outcome::Skipped(SkipReason::OverlapsAnotherEdit);
            item.edit = None;
        }
    }
}

/// Applies `plan`'s [`Outcome::Applied`] edits to `path`, whose content the plan's ranges
/// were computed against was `original_content` (FR-016 through FR-020).
///
/// Always re-reads and byte-compares `path` against `original_content` before writing (FR-019)
/// — even under `dry_run`, so a `--dry-run` report never claims success for a plan a following
/// real run would actually reject. `dry_run = true` skips the [`deps_core::fs_probe::write_atomic`]
/// call itself; so does a plan whose edits would produce byte-identical content (no `Applied`
/// items, or all-no-op edits) — skipping an unnecessary rewrite avoids churning the file's
/// mtime/inode for file watchers and rebuild systems (critic finding M3).
///
/// # Errors
///
/// Returns [`ApplyError::StaleManifest`] if `path`'s content no longer matches
/// `original_content`, [`ApplyError::Read`] if the re-read fails, or [`ApplyError::Write`] if
/// [`deps_core::fs_probe::write_atomic`] fails (including refusing a symlinked `path`).
pub fn apply_plan(
    plan: &UpdatePlan,
    path: &std::path::Path,
    original_content: &str,
    dry_run: bool,
) -> Result<(), ApplyError> {
    // Defensive: `dedup_applied_items` should already have run over `plan` before this is
    // called, so this is normally a no-op — kept as a safety net, not the primary mechanism.
    let edits = dedup_overlapping_edits(plan.applied_edits(), "deps-cli update");
    let new_content = apply_edits(original_content, &edits);

    let reread = deps_core::fs_probe::read_to_string_capped(path, crate::MAX_MANIFEST_FILE_SIZE)
        .map_err(|source| ApplyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if reread.as_deref() != Some(original_content) {
        return Err(ApplyError::StaleManifest {
            path: path.to_path_buf(),
        });
    }

    if dry_run || new_content == original_content {
        return Ok(());
    }

    deps_core::fs_probe::write_atomic(path, &new_content).map_err(|source| ApplyError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::licenses::LicensePolicy;
    use deps_core::parser::DependencySource;
    use deps_core::position::{Position, Range};
    use deps_core::{ConcreteVersion, Dependency, EcosystemId, PackageVersions, ParseResult};
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    struct StubFormatter;
    impl deps_core::lsp_helpers::PackageNaming for StubFormatter {}
    impl deps_core::lsp_helpers::PackageRendering for StubFormatter {
        fn format_version_for_text_edit(&self, v: &ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl deps_core::lsp_helpers::RequirementResolution for StubFormatter {}
    impl deps_core::lsp_helpers::DiagnosticMessages for StubFormatter {}
    impl deps_core::lsp_helpers::DiagnosticPolicy for StubFormatter {}
    impl deps_core::lsp_helpers::SourcePolicy for StubFormatter {}
    impl deps_core::lsp_helpers::OsvNaming for StubFormatter {}

    struct TestDep {
        name: PackageName,
        version_req: deps_core::VersionReq,
        version_range: Range,
    }
    impl Dependency for TestDep {
        fn name(&self) -> &PackageName {
            &self.name
        }
        fn name_range(&self) -> Range {
            Range::default()
        }
        fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
            Some(&self.version_req)
        }
        fn version_range(&self) -> Option<Range> {
            Some(self.version_range)
        }
        fn source(&self) -> DependencySource {
            DependencySource::Registry
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct TestParseResult {
        deps: Vec<TestDep>,
        uri: url::Url,
    }
    impl ParseResult for TestParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            self.deps.iter().map(|d| d as &dyn Dependency).collect()
        }
        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }
        fn uri(&self) -> &url::Url {
            &self.uri
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn test_dep(name: &str, req: &str, range: Range) -> TestDep {
        TestDep {
            name: PackageName::new(name),
            version_req: deps_core::VersionReq::new(req),
            version_range: range,
        }
    }

    fn test_analysis(
        deps: Vec<TestDep>,
        cached: HashMap<PackageName, PackageVersions>,
    ) -> ManifestAnalysis {
        ManifestAnalysis {
            parse_result: Box::new(TestParseResult {
                deps,
                uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
            }),
            uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
            ecosystem_id: EcosystemId::Cargo,
            cached_versions: cached,
            resolved_versions: HashMap::new(),
            resolved_version_candidates: HashMap::new(),
            outcomes: deps_core::lsp_helpers::DependencyOutcomes::new(),
            vulnerabilities: None,
            licenses: HashMap::new(),
            license_policy: LicensePolicy::default(),
            license_source: deps_core::LicenseSource::default(),
            offline: false,
            fetch_failed: HashSet::new(),
            registry_unreachable: false,
            license_fetch_incomplete: false,
        }
    }

    fn cached(name: &str, latest: &str) -> HashMap<PackageName, PackageVersions> {
        let mut map = HashMap::new();
        map.insert(PackageName::new(name), PackageVersions::latest_only(latest));
        map
    }

    /// US-001: multiple outdated dependencies, one already at latest.
    #[test]
    fn test_plan_updates_us001_multiple_outdated_one_up_to_date() {
        let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\nlibc = \"1.2.0\"\n";
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("tokio"),
            PackageVersions::latest_only("1.3.0"),
        );
        versions.insert(
            PackageName::new("libc"),
            PackageVersions::latest_only("1.2.0"),
        );
        let analysis = test_analysis(
            vec![
                test_dep(
                    "serde",
                    "1.0.0",
                    Range::new(Position::new(0, 9), Position::new(0, 14)),
                ),
                test_dep(
                    "tokio",
                    "1.0.0",
                    Range::new(Position::new(1, 9), Position::new(1, 14)),
                ),
                test_dep(
                    "libc",
                    "1.2.0",
                    Range::new(Position::new(2, 8), Position::new(2, 13)),
                ),
            ],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &StubFormatter,
            &[],
            &IgnoreRules::empty(),
        );
        let applied: Vec<&str> = plan
            .items
            .iter()
            .filter(|i| matches!(i.outcome, Outcome::Applied))
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(
            applied.len(),
            2,
            "serde and tokio are outdated, libc is not: {applied:?}"
        );
        assert!(applied.contains(&"serde"));
        assert!(applied.contains(&"tokio"));
        assert!(
            !plan.items.iter().any(|i| i.name == "libc"),
            "an up-to-date dependency must never appear as a candidate at all"
        );
    }

    /// US-002: `--package` narrows the update set; the excluded dependency is still reported.
    #[test]
    fn test_plan_updates_us002_package_filter_narrows_to_one() {
        let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\n";
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("tokio"),
            PackageVersions::latest_only("1.3.0"),
        );
        let analysis = test_analysis(
            vec![
                test_dep(
                    "serde",
                    "1.0.0",
                    Range::new(Position::new(0, 9), Position::new(0, 14)),
                ),
                test_dep(
                    "tokio",
                    "1.0.0",
                    Range::new(Position::new(1, 9), Position::new(1, 14)),
                ),
            ],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &StubFormatter,
            &["serde".to_string()],
            &IgnoreRules::empty(),
        );

        let serde_item = plan.items.iter().find(|i| i.name == "serde").unwrap();
        assert!(matches!(serde_item.outcome, Outcome::Applied));
        let tokio_item = plan.items.iter().find(|i| i.name == "tokio").unwrap();
        assert!(matches!(
            tokio_item.outcome,
            Outcome::Skipped(SkipReason::NotRequested)
        ));
    }

    /// US-004 default-mode half: an `update_types`-scoped ignore rule skips a major bump.
    #[test]
    fn test_plan_updates_us004_ignore_rule_skips_major_bump() {
        let content = "tokio = \"1.0.0\"\n";
        let versions = cached("tokio", "2.0.0");
        let analysis = test_analysis(
            vec![test_dep(
                "tokio",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        let ignore_rules = crate::update::ignore::IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "tokio".to_string(),
                update_types: Some(vec![crate::config::UpdateTypeToken::Major]),
            }],
            &StubFormatter,
        );

        let plan = plan_updates(&analysis, content, &StubFormatter, &[], &ignore_rules);

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::IgnoreRule)
        ));
    }

    /// Code review finding 1: an `Unplannable` candidate (here, a `NonLiteralSpan` — the
    /// content at `version_range` does not match the declared requirement text) that also
    /// matches an `[update].ignore` rule must be reported `Skipped(IgnoreRule)` — exit 0 — not
    /// `Skipped(NotSafelyEditable)` — exit 1. Before this fix, the unplannable-candidate loop
    /// never consulted `ignore_rules` at all, so this case always fell through to
    /// `NotSafelyEditable` regardless of a matching rule.
    #[test]
    fn test_plan_updates_unplannable_candidate_still_honors_ignore_rule() {
        let content = "tokio = \"weird\"\n";
        let versions = cached("tokio", "2.0.0");
        let analysis = test_analysis(
            vec![test_dep(
                "tokio",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        let ignore_rules = crate::update::ignore::IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "tokio".to_string(),
                update_types: None,
            }],
            &StubFormatter,
        );

        let plan = plan_updates(&analysis, content, &StubFormatter, &[], &ignore_rules);

        assert_eq!(plan.items.len(), 1);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped(SkipReason::IgnoreRule)
            ),
            "got {:?}",
            plan.items[0].outcome
        );
    }

    /// Companion to the above: the same unplannable candidate with no matching ignore rule
    /// still reports `NotSafelyEditable`, proving the new `ignore_rules` check above is
    /// additive, not a blanket bypass of the unplannable-candidate reporting.
    #[test]
    fn test_plan_updates_unplannable_candidate_without_ignore_rule_is_not_safely_editable() {
        let content = "tokio = \"weird\"\n";
        let versions = cached("tokio", "2.0.0");
        let analysis = test_analysis(
            vec![test_dep(
                "tokio",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &StubFormatter,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::NonLiteralSpan
            ))
        ));
    }

    /// FR-007 edge case: with no `--config` (empty ignore rules), an `Unknown`-kind update is
    /// still applied — `Unknown` only fails closed *under a matching scoped rule*, never on
    /// its own.
    #[test]
    fn test_plan_updates_fr007_no_config_no_ignore_rules_loaded() {
        let content = "tokio = \"1.0.0\"\n";
        let versions = cached("tokio", "2.0.0");
        let analysis = test_analysis(
            vec![test_dep(
                "tokio",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &StubFormatter,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].outcome, Outcome::Applied));
    }

    #[test]
    fn test_is_requested_empty_filter_matches_everything() {
        assert!(is_requested(&[], "serde", &StubFormatter));
        assert!(is_requested(
            &["serde".to_string()],
            "serde",
            &StubFormatter
        ));
        assert!(!is_requested(
            &["tokio".to_string()],
            "serde",
            &StubFormatter
        ));
    }

    #[test]
    fn test_apply_plan_stale_manifest_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "serde = \"1.0.0\"\n").unwrap();

        // Simulates a concurrent edit landing between planning and applying.
        std::fs::write(&path, "serde = \"1.0.1\"\n").unwrap();

        let plan = UpdatePlan {
            items: vec![PlannedUpdateItem {
                name: "serde".to_string(),
                current: "1.0.0".to_string(),
                target: "1.2.0".to_string(),
                outcome: Outcome::Applied,
                edit: Some(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
            }],
        };

        let result = apply_plan(&plan, &path, "serde = \"1.0.0\"\n", false);
        assert!(matches!(result, Err(ApplyError::StaleManifest { .. })));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "serde = \"1.0.1\"\n"
        );
    }

    #[test]
    fn test_apply_plan_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "serde = \"1.0.0\"\n").unwrap();

        let plan = UpdatePlan {
            items: vec![PlannedUpdateItem {
                name: "serde".to_string(),
                current: "1.0.0".to_string(),
                target: "1.2.0".to_string(),
                outcome: Outcome::Applied,
                edit: Some(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
            }],
        };

        apply_plan(&plan, &path, "serde = \"1.0.0\"\n", true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "serde = \"1.0.0\"\n"
        );
    }

    #[test]
    fn test_apply_plan_writes_applied_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "serde = \"1.0.0\"\n").unwrap();

        let plan = UpdatePlan {
            items: vec![PlannedUpdateItem {
                name: "serde".to_string(),
                current: "1.0.0".to_string(),
                target: "1.2.0".to_string(),
                outcome: Outcome::Applied,
                edit: Some(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
            }],
        };

        apply_plan(&plan, &path, "serde = \"1.0.0\"\n", false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "serde = \"1.2.0\"\n"
        );
    }

    #[test]
    fn test_apply_plan_skipped_items_are_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "serde = \"1.0.0\"\n").unwrap();

        let plan = UpdatePlan {
            items: vec![PlannedUpdateItem {
                name: "serde".to_string(),
                current: "1.0.0".to_string(),
                target: "1.2.0".to_string(),
                outcome: Outcome::Skipped(SkipReason::IgnoreRule),
                edit: Some(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
            }],
        };

        apply_plan(&plan, &path, "serde = \"1.0.0\"\n", false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "serde = \"1.0.0\"\n"
        );
    }
}
