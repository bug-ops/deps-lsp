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
            .filter_map(|item| match &item.outcome {
                Outcome::Applied(edit) => Some(edit.clone()),
                _ => None,
            })
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
    /// This item's disposition — the edit that would apply [`Self::target`] lives inside
    /// [`Outcome::Applied`] itself (#1349: folding it in here as a second, independently
    /// settable field made `Applied` with no edit a representable-but-invalid state).
    pub outcome: Outcome,
    /// OSV advisory ids this item resolves, populated only in `--security-only` mode.
    pub advisory_ids: Vec<String>,
    /// Whether a matching `[update].ignore` rule exists but was overridden (FR-008,
    /// `--security-only` mode only — the rule never applies in default mode, since a match
    /// there is reported via <code>[Outcome::Skipped]([SkipReason::IgnoreRule])</code>
    /// instead).
    pub ignore_rule_overridden: bool,
    /// A newer version excluded from this item's [`Self::target`] by an active GOSSIP cooldown
    /// finding (issue #1521 item 1) — mirrors `check`'s identical
    /// [`deps_core::lsp_helpers::PackageVersions::gossip_excluded_version`] attribution
    /// (`crate::report::to_finding`). Populated only for [`Outcome::Applied`] items in default
    /// mode; always `None` under `--security-only`, whose fix target never reads a
    /// GOSSIP-filtered `latest` at all.
    pub gossip_excluded_version: Option<deps_core::ConcreteVersion>,
}

/// A dependency's disposition within an [`UpdatePlan`].
///
/// # The invalid state this makes unrepresentable (#1349)
///
/// Before this type carried [`ManifestEdit`] directly, [`PlannedUpdateItem`] stored `outcome`
/// and `edit: Option<ManifestEdit>` as two independent fields the caller had to keep in sync by
/// convention. Nothing stopped `PlannedUpdateItem { outcome: Outcome::Applied, edit: None, .. }`
/// — empirically, that combination made `apply_plan` report success (`Ok(())`) without writing
/// anything. `edit` no longer exists as a separate field, so that state fails to compile:
///
/// ```compile_fail
/// use deps_cli::update::{Outcome, PlannedUpdateItem};
///
/// let item = PlannedUpdateItem {
///     name: "serde".to_string(),
///     current: "1.0.0".to_string(),
///     target: "1.2.0".to_string(),
///     outcome: Outcome::Applied,
///     edit: None,
///     advisory_ids: Vec::new(),
///     ignore_rule_overridden: false,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A fix plan existed and its edit was written (or would be, under `--dry-run`).
    /// Contributes to exit 0. Carries the edit itself — #1349: this makes "applied, but no
    /// edit to write" unrepresentable, where a separate `PlannedUpdateItem::edit: Option<_>`
    /// field previously let the two drift out of sync (`apply_plan` would report success
    /// without writing anything).
    Applied(ManifestEdit),
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
    /// The selected update target was published more recently than `freshness.cooldown_secs`
    /// allows (issue #1525). The per-version publish-time list needed to instead fall back to
    /// an older, already-cooled-down candidate — the way spec 074's GOSSIP filter does for its
    /// own signal — is not available at this planner layer (`PackageVersions` only carries
    /// `latest`'s own `published_at`, not every candidate's), so this dependency is simply left
    /// alone for this run rather than risking a downgrade guess (critique D1 tracks the
    /// fallback as a follow-up). **Not guaranteed to self-resolve**: a package that publishes
    /// at least once per cooldown window can stay skipped indefinitely — it only clears once a
    /// release survives long enough for its age to exceed `cooldown_secs` without a newer
    /// release replacing it.
    WithinFreshnessCooldown,
}

/// Why a `--security-only` candidate could not be fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnfixableReason {
    /// No independently-verified fix target exists: no advisory has a claimable fix, the fix
    /// target failed the safety gate, or `deps_core::edit`'s internal fix-target verification
    /// could not confirm it — see [`deps_core::edit::VulnFixSkip`] (FR-010).
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
    pub const fn wire_token(&self) -> &'static str {
        match self {
            Self::Applied(_) => "applied",
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
        let base = match &self.outcome {
            Outcome::Applied(_) => "update applied",
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
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestFlaggedByOsv,
            )) => "the registry's latest version is flagged by OSV.dev — refusing to write it",
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestUnverified,
            )) => {
                "the registry's latest version could not be verified against OSV.dev — refusing to write it"
            }
            Outcome::Skipped(SkipReason::OverlapsAnotherEdit) => {
                "this edit's span overlapped another item's and was dropped"
            }
            Outcome::Skipped(SkipReason::WithinFreshnessCooldown) => {
                "the selected update target was published within the freshness cooldown window"
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
        let mut reason = base.to_string();
        if self.ignore_rule_overridden {
            reason.push_str(" (a matching [update].ignore rule was overridden by --security-only)");
        }
        // Issue #1521 item 1: mirrors `crate::report::to_finding`'s identical GOSSIP-cooldown
        // message attribution for `check`.
        if self.gossip_excluded_version.is_some() {
            reason.push_str(
                " (a newer version was excluded from this pick by an active GOSSIP cooldown finding)",
            );
        }
        reason
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

/// Whether `normalized_name`'s (or, failing that, `raw_name`'s) cached registry `latest` was
/// published within `freshness.cooldown_secs` of `now` (issue #1525).
///
/// `collect_update_candidates` has no equivalent gate: `freshness.cooldown_secs` otherwise only
/// ever rewords a downstream hover/diagnostic/completion message, never excludes a version from
/// being `latest` (see `PackageVersions::gossip_excluded_version`'s doc for that round-1
/// correction, made for GOSSIP's own distinct signal). `false` whenever `freshness.enabled` is
/// off or the registry never reported a publish time for `latest` (most ecosystems today), so
/// this degrades to a silent no-op rather than an error.
///
/// **Deliberate divergences, documented rather than reconciled (critique M2/Q1):**
/// - `check`'s `apply_outdated_rule` (`deps-core/src/lsp_helpers/diagnostics.rs`) lets a
///   definitive GOSSIP verdict (`Active`/`NotActive`) supersede this same local heuristic when
///   rendering its `Outdated` message; this function applies the local heuristic
///   unconditionally, independent of any GOSSIP verdict. Reconciling the two would need a
///   GOSSIP-verdict signal threaded into `ManifestAnalysis` beyond the `gossip_excluded_version`
///   attribution already carried — out of scope for this fix; a `check` vs. `update` cooldown
///   message can therefore legitimately differ for the same dependency. Tracked as issue #1529.
/// - `deps-lsp`'s "update to latest" code action (`deps_core::edit::collect_update_edits`, the
///   `collect_update_candidates` sibling that drops the `Unplannable` arm) does **not** gain
///   this filter — it stays scoped to `deps-cli update`'s planner only, so an editor quick-fix
///   can still offer a version this command would skip as too fresh. Whether this should
///   eventually converge, and whether `update`'s long-term default should pick the newest
///   already-cooled-down version instead of a full skip, is tracked in issue #1528.
//
// TODO(critic): this is a full skip, not a fallback to the newest already-cooled-down
// candidate the way GOSSIP's floor-protected filter (`deps-engine/src/classify/fetch.rs`)
// does for its own signal — starves a package that publishes at least once per cooldown
// window (it never becomes an update target). A real fallback needs a per-version
// publish-time list threaded from the fetch layer, which `PackageVersions` does not carry
// today (only `latest`'s own `published_at`) — tracked as issue #1528.
fn within_freshness_cooldown(
    analysis: &ManifestAnalysis,
    normalized_name: &str,
    raw_name: &str,
    freshness: deps_core::FreshnessSettings,
    now: deps_core::PublishTime,
) -> bool {
    freshness.enabled
        && cached_package_versions(analysis, normalized_name, raw_name)
            .and_then(|v| v.published_at)
            .is_some_and(|published_at| {
                deps_core::is_within_cooldown(
                    published_at.age_secs_from(now),
                    freshness.cooldown_secs,
                )
            })
}

/// The cached registry data for `normalized_name` (or, failing that, `raw_name`) — the shared
/// lookup [`within_freshness_cooldown`] and [`gossip_excluded_version`] both need (code-review
/// finding: previously each ran this same two-step `HashMap` lookup independently).
fn cached_package_versions<'a>(
    analysis: &'a ManifestAnalysis,
    normalized_name: &str,
    raw_name: &str,
) -> Option<&'a deps_core::lsp_helpers::PackageVersions> {
    analysis
        .cached_versions
        .get(normalized_name)
        .or_else(|| analysis.cached_versions.get(raw_name))
}

/// The version [`deps_core::lsp_helpers::PackageVersions::gossip_excluded_version`] recorded
/// for `normalized_name` (or, failing that, `raw_name`), when the registry fetch's spec 074
/// GOSSIP-cooldown filter held one back from being `latest` (issue #1521 item 1) — mirrors
/// `crate::report::to_finding`'s identical lookup for `check`'s own attribution.
fn gossip_excluded_version(
    analysis: &ManifestAnalysis,
    normalized_name: &str,
    raw_name: &str,
) -> Option<deps_core::ConcreteVersion> {
    cached_package_versions(analysis, normalized_name, raw_name)
        .and_then(|v| v.gossip_excluded_version.clone())
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
///     latest_status: None,
///     licenses: HashMap::new(),
///     license_policy: deps_core::licenses::LicensePolicy::default(),
///     license_source: deps_core::LicenseSource::default(),
///     offline: false,
///     fetch_failed: HashSet::new(),
///     registry_unreachable: false,
///     license_fetch_incomplete: false,
/// };
///
/// let plan = plan_updates(
///     &analysis,
///     content,
///     &MockFormatter,
///     &[],
///     &IgnoreRules::empty(),
///     deps_core::FreshnessSettings::default(),
///     deps_core::PublishTime::now(),
/// );
///
/// assert_eq!(plan.items.len(), 1);
/// assert!(matches!(plan.items[0].outcome, Outcome::Applied(_)));
/// assert_eq!(plan.items[0].target, "1.2.0");
/// ```
#[must_use]
pub fn plan_updates(
    analysis: &ManifestAnalysis,
    content: &str,
    formatter: &dyn EcosystemFormatter,
    package_filter: &[String],
    ignore_rules: &IgnoreRules,
    freshness: deps_core::FreshnessSettings,
    now: deps_core::PublishTime,
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
            // Critique M1: computed once, up front, and attached to every disposition below
            // (not just `Applied`) — this is a property of the candidate's resolved registry
            // data, independent of why the run didn't end up writing an edit. Previously only
            // the `Applied` branch set this, so a cooldown skip on a GOSSIP-substituted target
            // silently dropped the GOSSIP attribution entirely.
            let gossip_excluded_version =
                gossip_excluded_version(analysis, &p.normalized_name, &p.name);

            if !is_requested(package_filter, &p.normalized_name, formatter) {
                return PlannedUpdateItem {
                    name: p.name,
                    current: p.current,
                    target,
                    outcome: Outcome::Skipped(SkipReason::NotRequested),
                    advisory_ids: Vec::new(),
                    ignore_rule_overridden: false,
                    gossip_excluded_version,
                };
            }

            let kind = classify_update(&p.current, &target);
            if let Some(reason) = ignore_rules.skip_reason(&p.normalized_name, kind) {
                return PlannedUpdateItem {
                    name: p.name,
                    current: p.current,
                    target,
                    outcome: Outcome::Skipped(reason),
                    advisory_ids: Vec::new(),
                    ignore_rule_overridden: false,
                    gossip_excluded_version,
                };
            }

            if within_freshness_cooldown(analysis, &p.normalized_name, &p.name, freshness, now) {
                return PlannedUpdateItem {
                    name: p.name,
                    current: p.current,
                    target,
                    outcome: Outcome::Skipped(SkipReason::WithinFreshnessCooldown),
                    advisory_ids: Vec::new(),
                    ignore_rule_overridden: false,
                    gossip_excluded_version,
                };
            }

            PlannedUpdateItem {
                name: p.name,
                current: p.current,
                target,
                outcome: Outcome::Applied(p.edit),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version,
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
        let gossip_excluded_version = gossip_excluded_version(analysis, &normalized_name, &name);
        let outcome = if !is_requested(package_filter, &normalized_name, formatter) {
            Outcome::Skipped(SkipReason::NotRequested)
        } else if let Some(rule_reason) =
            ignore_rules.skip_reason(&normalized_name, UpdateKind::Unknown)
        {
            Outcome::Skipped(rule_reason)
        } else if !matches!(
            reason,
            deps_core::edit::UnplannableReason::LatestFlaggedByOsv
                | deps_core::edit::UnplannableReason::LatestUnverified
        ) && within_freshness_cooldown(analysis, &normalized_name, &name, freshness, now)
        {
            // Critique M3: a locally-fresh `latest` that also failed to become a writable edit
            // (an unsafe version string, a non-literal span, a no-op rewrite) gets the same
            // clean cooldown skip a `Planned` candidate would — whether an edit happens to be
            // mechanically plannable is orthogonal to whether the version is even a real
            // recommendation yet. `LatestFlaggedByOsv`/`LatestUnverified` are the two
            // exceptions (code-review finding, post-M3): per `UnplannableReason::LatestUnverified`'s
            // own doc, an unverified version "fails closed the same way `LatestFlaggedByOsv`
            // does... never distinguishable from a flagged one at write time" — demoting only
            // the flagged case to a routine cooldown pause while still letting the unverified
            // case through would silently violate that same fail-closed guarantee.
            Outcome::Skipped(SkipReason::WithinFreshnessCooldown)
        } else {
            Outcome::Skipped(SkipReason::NotSafelyEditable(reason))
        };
        items.push(PlannedUpdateItem {
            name,
            current: String::new(),
            target: String::new(),
            outcome,
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
            gossip_excluded_version,
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
        .filter_map(|(index, item)| match &item.outcome {
            Outcome::Applied(edit) => Some(Indexed {
                index,
                edit: edit.clone(),
            }),
            _ => None,
        })
        .collect();
    let kept_indices: std::collections::HashSet<usize> =
        dedup_overlapping_edits(indexed, "deps-cli update dedup_applied_items")
            .into_iter()
            .map(|indexed| indexed.index)
            .collect();

    for (index, item) in items.iter_mut().enumerate() {
        if matches!(item.outcome, Outcome::Applied(_)) && !kept_indices.contains(&index) {
            item.outcome = Outcome::Skipped(SkipReason::OverlapsAnotherEdit);
        }
    }
}

/// Applies `plan`'s [`Outcome::Applied`] edits to `path`, whose content the plan's ranges
/// were computed against was `original_content` (FR-016 through FR-020).
///
/// Always re-reads and byte-compares `path` against `original_content` before writing (FR-019)
/// — even under `dry_run`, so a `--dry-run` report never claims success for a plan a following
/// real run would actually reject. [`crate::format::DryRun::Yes`] skips the
/// [`deps_core::fs_probe::write_atomic`] call itself; so does a plan whose edits would produce
/// byte-identical content (no `Applied` items, or all-no-op edits) — skipping an unnecessary
/// rewrite avoids churning the file's mtime/inode for file watchers and rebuild systems (critic
/// finding M3).
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
    dry_run: crate::format::DryRun,
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

    if dry_run == crate::format::DryRun::Yes || new_content == original_content {
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
    use deps_core::{Dependency, EcosystemId, PackageVersions, ParseResult};
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    const STUB_FORMATTER: deps_core::test_util::StubFormatter =
        deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

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

    /// [`plan_updates`] with freshness cooldown filtering disabled — the pre-#1525 behavior
    /// every test not specifically about that filter wants.
    ///
    /// Critique M5: actually passes `enabled: false`, not [`deps_core::FreshnessSettings::default`]
    /// (which is `enabled: true` — a prior version of this helper passed that and only
    /// happened to work because every fixture omitted `published_at`; a fixture that later set
    /// one via [`PackageVersions::with_published_at`] would have been silently skipped instead
    /// of applied).
    fn plan_updates_no_cooldown(
        analysis: &ManifestAnalysis,
        content: &str,
        formatter: &dyn EcosystemFormatter,
        package_filter: &[String],
        ignore_rules: &IgnoreRules,
    ) -> UpdatePlan {
        plan_updates(
            analysis,
            content,
            formatter,
            package_filter,
            ignore_rules,
            deps_core::FreshnessSettings {
                enabled: false,
                cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
            },
            deps_core::PublishTime::now(),
        )
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
            latest_status: None,
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

    /// Issue #1525: a `latest` published within `freshness.cooldown_secs` of `now` must be
    /// skipped as the update target in default mode, not silently applied — the empirically
    /// verified bug (`deps-cli update --cooldown N --dry-run` had no effect at all).
    #[test]
    fn test_plan_updates_within_freshness_cooldown_is_skipped() {
        let content = "serde = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000); // 1000s old
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0").with_published_at(published_at),
        );
        let analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: true,
                cooldown_secs: 2_000, // wider than the 1000s age above
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::WithinFreshnessCooldown)
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN,
            "an automatic freshness-cooldown pause must not fail the run"
        );
    }

    /// The same fixture, but `freshness.enabled = false`: the cooldown filter must be a
    /// complete no-op, mirroring how the local heuristic is opt-out everywhere else.
    #[test]
    fn test_plan_updates_freshness_disabled_ignores_cooldown() {
        let content = "serde = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000);
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0").with_published_at(published_at),
        );
        let analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: false,
                cooldown_secs: 2_000,
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].outcome, Outcome::Applied(_)));
    }

    /// Issue #1521 item 1: `update`'s output must attribute a GOSSIP-cooldown-excluded newer
    /// version on its `PlannedUpdateItem`, mirroring `check`'s equivalent message attribution.
    #[test]
    fn test_plan_updates_surfaces_gossip_excluded_version() {
        let content = "serde = \"1.0.0\"\n";
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0")
                .with_gossip_excluded_version(deps_core::ConcreteVersion::new("2.0.0")),
        );
        let analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].outcome, Outcome::Applied(_)));
        assert_eq!(
            plan.items[0].gossip_excluded_version,
            Some(deps_core::ConcreteVersion::new("2.0.0"))
        );
        // Tester finding: an exact-suffix assertion (not just `.contains`) catches future
        // wording drift between this literal and `crate::report::to_finding`'s identical one.
        assert_eq!(
            plan.items[0].reason(),
            "update applied (a newer version was excluded from this pick by an active GOSSIP cooldown finding)"
        );
    }

    /// Critique M1: when both the local freshness cooldown and a GOSSIP cooldown exclusion
    /// apply to the same candidate, the freshness skip wins the `outcome` decision (no
    /// per-version publish-time list exists here to reconsider the pick), but the GOSSIP
    /// attribution must still surface on the item — previously it was hardcoded to `None` on
    /// every skip branch, silently dropping which version GOSSIP had already excluded.
    #[test]
    fn test_plan_updates_freshness_cooldown_takes_precedence_but_keeps_gossip_attribution() {
        let content = "serde = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000); // 1000s old
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0")
                .with_published_at(published_at)
                .with_gossip_excluded_version(deps_core::ConcreteVersion::new("2.0.0")),
        );
        let analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: true,
                cooldown_secs: 2_000, // wider than the 1000s age above
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::WithinFreshnessCooldown),
            "the local cooldown skip must win the outcome decision"
        );
        assert_eq!(
            plan.items[0].gossip_excluded_version,
            Some(deps_core::ConcreteVersion::new("2.0.0")),
            "the GOSSIP attribution must survive the cooldown skip, not be silently dropped"
        );
        let reason = plan.items[0].reason();
        assert!(
            reason.contains("freshness cooldown window") && reason.contains("GOSSIP cooldown"),
            "got: {reason}"
        );
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

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
        );
        let applied: Vec<&str> = plan
            .items
            .iter()
            .filter(|i| matches!(i.outcome, Outcome::Applied(_)))
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

    /// Issue #1517 critique S6: no test covered `plan_updates`/`collect_update_candidates`'s
    /// actual gate on a `Flagged` OSV verdict for the registry's cached "latest" — this pins
    /// the whole wiring end to end: the candidate must come back
    /// `Skipped(NotSafelyEditable(LatestFlaggedByOsv))`, never `Applied`, and
    /// `deps_cli::exit::update_exit_code` must treat that as a nonzero (policy-violation) exit,
    /// the same as any other `NotSafelyEditable` reason.
    #[test]
    fn test_plan_updates_refuses_a_flagged_latest() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "serde = \"1.0.0\"\n";
        let versions = cached("serde", "1.2.0");
        let mut analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            deps_core::test_util::vuln_key("serde"),
            UpgradeStatus::CandidateVulnerable {
                version: "1.2.0".to_string(),
                advisory_ids: Capped::new(vec!["MAL-2026-00001".to_string()], 1),
                worst_severity: Some(VulnSeverity::Malicious),
            },
        );
        analysis.latest_status = Some(latest_status);

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestFlaggedByOsv
            )),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION,
            "a flagged latest must never exit clean"
        );
    }

    /// Critique M3 (the `LatestFlaggedByOsv` exception): a locally-fresh `latest` that is
    /// *also* OSV-flagged must still surface as `NotSafelyEditable(LatestFlaggedByOsv)` — the
    /// cooldown skip's "not a real recommendation yet, wait" framing must never demote a
    /// confirmed-malicious verdict to a routine, exit-0 pause.
    #[test]
    fn test_plan_updates_flagged_latest_is_never_masked_by_cooldown() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "serde = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000); // 1000s old, in-window
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0").with_published_at(published_at),
        );
        let mut analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            deps_core::test_util::vuln_key("serde"),
            UpgradeStatus::CandidateVulnerable {
                version: "1.2.0".to_string(),
                advisory_ids: Capped::new(vec!["MAL-2026-00001".to_string()], 1),
                worst_severity: Some(VulnSeverity::Malicious),
            },
        );
        analysis.latest_status = Some(latest_status);

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: true,
                cooldown_secs: 2_000,
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestFlaggedByOsv
            )),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION,
            "a flagged latest must never exit clean, even when also within cooldown"
        );
    }

    /// Code-review finding (post-M3): `UnplannableReason::LatestUnverified`'s own doc says it
    /// "fails closed the same way `LatestFlaggedByOsv` does... never distinguishable from a
    /// flagged one at write time" — the M3 exception must therefore cover both variants, not
    /// only `LatestFlaggedByOsv`. Before this fix, a locally-fresh `latest` with an unverified
    /// OSV check was silently reclassified from `NotSafelyEditable(LatestUnverified)` (exit 1)
    /// to `WithinFreshnessCooldown` (exit 0).
    #[test]
    fn test_plan_updates_unverified_latest_is_never_masked_by_cooldown() {
        use deps_core::osv::LatestStatusMap;

        let content = "serde = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000); // 1000s old, in-window
        let mut versions = cached("serde", "1.2.0");
        versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0").with_published_at(published_at),
        );
        let mut analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        // `Some(&empty map)`: OSV checking is on, but nothing has verified this dependency's
        // latest yet — the pre-phase-B state, distinct from `None` (checking disabled/offline).
        analysis.latest_status = Some(LatestStatusMap::new());

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: true,
                cooldown_secs: 2_000,
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestUnverified
            )),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION,
            "an unverified latest must never exit clean, even when also within cooldown"
        );
    }

    /// Critique M3: an unplannable candidate whose `latest` is locally fresh gets the same
    /// clean cooldown skip a `Planned` candidate would — whether an edit happens to be
    /// mechanically writable is orthogonal to whether the version is even a real
    /// recommendation yet.
    #[test]
    fn test_plan_updates_unplannable_candidate_within_cooldown_is_cooldown_skip_not_unsafe() {
        let content = "tokio = \"weird\"\n"; // literal mismatch -> NonLiteralSpan, absent this fix
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_000);
        let versions_map = {
            let mut map = cached("tokio", "2.0.0");
            map.insert(
                PackageName::new("tokio"),
                PackageVersions::latest_only("2.0.0").with_published_at(published_at),
            );
            map
        };
        let analysis = test_analysis(
            vec![test_dep(
                "tokio",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions_map,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings {
                enabled: true,
                cooldown_secs: 2_000,
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::WithinFreshnessCooldown),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN,
            "a cooldown-driven pause must exit clean even when the candidate was also unplannable"
        );
    }

    /// Issue #1517 critique S6: same as the flagged case above, for an `Unverified` OSV
    /// verdict (no phase-B/scan result for this dependency at all) — the shared gate must
    /// fail closed the same way, not only for a confirmed-malicious `Flagged` verdict.
    #[test]
    fn test_plan_updates_refuses_an_unverified_latest() {
        use deps_core::osv::LatestStatusMap;

        let content = "serde = \"1.0.0\"\n";
        let versions = cached("serde", "1.2.0");
        let mut analysis = test_analysis(
            vec![test_dep(
                "serde",
                "1.0.0",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            )],
            versions,
        );
        // `Some(&empty map)`: OSV checking is on, but nothing has verified this dependency's
        // latest yet — the pre-phase-B state, distinct from `None` (checking disabled/offline).
        analysis.latest_status = Some(LatestStatusMap::new());

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items[0].outcome,
            Outcome::Skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestUnverified
            )),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION,
            "an unverified latest must never exit clean"
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

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &["serde".to_string()],
            &IgnoreRules::empty(),
        );

        let serde_item = plan.items.iter().find(|i| i.name == "serde").unwrap();
        assert!(matches!(serde_item.outcome, Outcome::Applied(_)));
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
            &STUB_FORMATTER,
        );

        let plan =
            plan_updates_no_cooldown(&analysis, content, &STUB_FORMATTER, &[], &ignore_rules);

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
            &STUB_FORMATTER,
        );

        let plan =
            plan_updates_no_cooldown(&analysis, content, &STUB_FORMATTER, &[], &ignore_rules);

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

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
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

        let plan = plan_updates_no_cooldown(
            &analysis,
            content,
            &STUB_FORMATTER,
            &[],
            &IgnoreRules::empty(),
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].outcome, Outcome::Applied(_)));
    }

    #[test]
    fn test_is_requested_empty_filter_matches_everything() {
        assert!(is_requested(&[], "serde", &STUB_FORMATTER));
        assert!(is_requested(
            &["serde".to_string()],
            "serde",
            &STUB_FORMATTER
        ));
        assert!(!is_requested(
            &["tokio".to_string()],
            "serde",
            &STUB_FORMATTER
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
                outcome: Outcome::Applied(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
            }],
        };

        let result = apply_plan(
            &plan,
            &path,
            "serde = \"1.0.0\"\n",
            crate::format::DryRun::No,
        );
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
                outcome: Outcome::Applied(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
            }],
        };

        apply_plan(
            &plan,
            &path,
            "serde = \"1.0.0\"\n",
            crate::format::DryRun::Yes,
        )
        .unwrap();
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
                outcome: Outcome::Applied(ManifestEdit {
                    range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                    new_text: "1.2.0".to_string(),
                }),
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
            }],
        };

        apply_plan(
            &plan,
            &path,
            "serde = \"1.0.0\"\n",
            crate::format::DryRun::No,
        )
        .unwrap();
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
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
            }],
        };

        apply_plan(
            &plan,
            &path,
            "serde = \"1.0.0\"\n",
            crate::format::DryRun::No,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "serde = \"1.0.0\"\n"
        );
    }

    // --- dedup_applied_items (previously untested; touched by #1349's `Outcome::Applied`
    // edit-extraction rewrite) ---

    fn applied_item(name: &str, range: Range) -> PlannedUpdateItem {
        PlannedUpdateItem {
            name: name.to_string(),
            current: "1.0.0".to_string(),
            target: "1.2.0".to_string(),
            outcome: Outcome::Applied(ManifestEdit {
                range,
                new_text: "1.2.0".to_string(),
            }),
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
            gossip_excluded_version: None,
        }
    }

    #[test]
    fn test_dedup_applied_items_keeps_non_overlapping_edits_applied() {
        let mut items = vec![
            applied_item(
                "serde",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            ),
            applied_item(
                "tokio",
                Range::new(Position::new(1, 9), Position::new(1, 14)),
            ),
        ];
        dedup_applied_items(&mut items);
        assert!(
            items
                .iter()
                .all(|i| matches!(i.outcome, Outcome::Applied(_)))
        );
    }

    /// M2/critic finding this dedup pass exists for: two vulnerable occurrences of one name
    /// (or any other overlap) both reported `Applied` must have the loser demoted to
    /// `Skipped(OverlapsAnotherEdit)` before `apply_plan` runs, not silently write only one.
    #[test]
    fn test_dedup_applied_items_demotes_the_later_overlap() {
        let mut items = vec![
            applied_item(
                "serde",
                Range::new(Position::new(0, 9), Position::new(0, 14)),
            ),
            applied_item(
                "serde",
                Range::new(Position::new(0, 11), Position::new(0, 16)),
            ),
        ];
        dedup_applied_items(&mut items);
        assert!(matches!(items[0].outcome, Outcome::Applied(_)));
        assert!(matches!(
            items[1].outcome,
            Outcome::Skipped(SkipReason::OverlapsAnotherEdit)
        ));
    }
}
