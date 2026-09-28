//! `deps-cli update`: default-mode planning and plan application.
//!
//! Also hosts the shared plan/outcome types both planners (this module's [`plan_updates`]
//! and [`security`]'s `plan_security_updates`) produce (spec 068, #1329).

pub mod ignore;
pub mod security;

use deps_core::ConcreteVersion;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::edit::{
    EditSpan, ManifestEdit, ManifestReparse, UnplannableReason, UpdateCandidate, UpdateKind,
    apply_edits, classify_update, collect_update_candidates, dedup_overlapping_edits,
};
use deps_core::lsp_helpers::{
    CooldownDisposition, EcosystemFormatter, FallbackEditVerdict, LatestVerdict, PackageVersions,
    cooldown_disposition, fallback_edit_excludes_newer, latest_verdict,
};
use std::collections::HashMap;

use crate::analyze::ManifestAnalysis;
use ignore::IgnoreRules;

/// A dependency's "current" version for `deps-cli update`'s report.
///
/// Replaces the historical three-way `String`/`""` convention (issue #1593) with an
/// exhaustive state, so an unresolved current version can no longer be silently confused with
/// a resolved empty-string one.
///
/// # Examples
///
/// ```
/// use deps_cli::update::CurrentVersion;
/// use deps_core::ConcreteVersion;
/// use deps_core::edit::UpdateKind;
///
/// let current = CurrentVersion::Resolved(ConcreteVersion::from("1.0.0"));
/// assert_eq!(
///     current.update_kind_to(&ConcreteVersion::from("2.0.0")),
///     UpdateKind::Major
/// );
/// assert_eq!(
///     CurrentVersion::Unknown.update_kind_to(&ConcreteVersion::from("2.0.0")),
///     UpdateKind::Unknown
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentVersion {
    /// A lockfile/registry-resolved in-use version.
    Resolved(ConcreteVersion),
    /// No in-use version could be resolved; falls back to the dependency's declared
    /// requirement text (`--security-only` mode only — see `security`'s `security_current`).
    Declared(VersionReq),
    /// Neither a resolved in-use version nor a declared requirement was available.
    Unknown,
}

impl From<Option<ConcreteVersion>> for CurrentVersion {
    /// `Some` maps to [`Self::Resolved`], `None` to [`Self::Unknown`] — the default planner's
    /// only two possible states (it never produces [`Self::Declared`]; only `--security-only`
    /// does, via `security_current`).
    fn from(value: Option<ConcreteVersion>) -> Self {
        match value {
            Some(version) => Self::Resolved(version),
            None => Self::Unknown,
        }
    }
}

impl CurrentVersion {
    /// Classifies the update from this current version to `target`.
    ///
    /// [`Self::Declared`] and [`Self::Unknown`] both classify as [`UpdateKind::Unknown`] —
    /// behavior-identical to pre-#1593, though for two different reasons per variant: the
    /// default planner (the only caller that ever classifies `current`) never produced
    /// [`Self::Declared`] to begin with, and `--security-only` (the only caller that could)
    /// never called [`classify_update`] on `current` at all before this refactor. Neither
    /// caller's classification behavior changes; this method exists so a *future* caller
    /// cannot classify a [`Self::Declared`] requirement range as if it were a resolved version.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cli::update::CurrentVersion;
    /// use deps_core::{ConcreteVersion, VersionReq};
    /// use deps_core::edit::UpdateKind;
    ///
    /// let declared = CurrentVersion::Declared(VersionReq::new("^1.0"));
    /// assert_eq!(
    ///     declared.update_kind_to(&ConcreteVersion::from("2.0.0")),
    ///     UpdateKind::Unknown
    /// );
    /// ```
    #[must_use]
    pub fn update_kind_to(&self, target: &ConcreteVersion) -> UpdateKind {
        match self {
            Self::Resolved(version) => classify_update(version.as_str(), target.as_str()),
            Self::Declared(_) | Self::Unknown => UpdateKind::Unknown,
        }
    }

    /// Renders this version for the `--format json`/`table` wire boundary — [`Self::Unknown`]
    /// renders as an empty string, matching this field's pre-#1593 `""` convention.
    ///
    /// Deliberately not [`std::fmt::Display`] (issue #1593 critic M3): a `Display` impl invites
    /// a caller to reach for `.to_string().is_empty()` as an `Unknown` check, reintroducing the
    /// same stringly-typed comparison this type exists to remove. This method is the one
    /// sanctioned render boundary, used by `format::json`/`format::table` only.
    pub(crate) fn render_text(&self) -> String {
        match self {
            Self::Resolved(version) => version.to_string(),
            Self::Declared(req) => req.as_str().to_string(),
            Self::Unknown => String::new(),
        }
    }
}

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
                Outcome::Applied { edit, .. } => Some(edit.clone()),
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
    /// The version this dependency is currently pinned to, its declared requirement text when
    /// no concrete in-use version could be resolved, or [`CurrentVersion::Unknown`] when
    /// neither is available.
    pub current: CurrentVersion,
    /// This item's disposition — the target version considered (even when no edit was
    /// written) lives inside [`Self::outcome`]'s own variant (#1615: folding it into `Outcome`
    /// makes a target only representable where the variant actually carries one, rather than
    /// as a second, independently settable item-level field). Read it via [`Self::target`].
    pub outcome: Outcome,
    /// OSV advisory ids this item resolves. Populated in `--security-only` mode, and also in
    /// default mode for a cooldown-fallback decision that names a `Flagged` `latest`/fallback
    /// verdict (spec 075 FR-011/FR-012) — empty for an `Unverified` verdict, which carries no
    /// advisory list to report.
    pub advisory_ids: Vec<String>,
    /// Whether a matching `[update].ignore` rule exists but was overridden (FR-008,
    /// `--security-only` mode only — the rule never applies in default mode, since a match
    /// there is reported via [`Outcome::Skipped`] with reason [`SkipReason::IgnoreRule`]
    /// instead).
    pub ignore_rule_overridden: bool,
    /// A newer version excluded from this item's [`Self::target`] by an active GOSSIP cooldown
    /// finding (issue #1521 item 1) — mirrors `check`'s identical
    /// [`deps_core::lsp_helpers::PackageVersions::gossip_excluded_version`] attribution
    /// (`crate::report::to_finding`). Populated only for [`Outcome::Applied`] items in default
    /// mode; always `None` under `--security-only`, whose fix target never reads a
    /// GOSSIP-filtered `latest` at all.
    pub gossip_excluded_version: Option<deps_core::ConcreteVersion>,
    /// Spec 075 FR-013: attribution for a cooldown-fallback decision — one field so
    /// [`CooldownFallbackNote::AppliedInsteadOf`] and [`CooldownFallbackNote::Blocked`] can
    /// never both be set for the same item. `None` when no fallback candidate was ever
    /// consulted for this occurrence (`CooldownDisposition::NotEvaluated`/`Cleared`, or
    /// `Blocked { fallback: None }`).
    pub cooldown_fallback: Option<CooldownFallbackNote>,
}

/// Why [`PlannedUpdateItem::cooldown_fallback`] is set (spec 075 FR-013) — mirrors
/// [`PlannedUpdateItem::gossip_excluded_version`]'s existing attribution-field shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooldownFallbackNote {
    /// The fallback candidate was written; names the fresher, cooldown-blocked `latest` this
    /// occurrence targeted instead.
    AppliedInsteadOf(deps_core::ConcreteVersion),
    /// A fallback candidate existed but was itself OSV-`Flagged`/`Unverified` (FR-011) and was
    /// never written; names the blocked fallback version.
    Blocked {
        /// The blocked fallback candidate's version.
        version: deps_core::ConcreteVersion,
    },
}

/// A dependency's disposition within an [`UpdatePlan`].
///
/// # The invalid state this makes unrepresentable (#1349, #1615)
///
/// Before this type carried [`ManifestEdit`] directly, [`PlannedUpdateItem`] stored `outcome`
/// and `edit: Option<ManifestEdit>` as two independent fields the caller had to keep in sync by
/// convention (#1349) — that combination made `apply_plan` report success (`Ok(())`) without
/// writing anything. `edit` was folded into [`Self::Applied`] to close that gap, but the
/// dependency's target version stayed a second, independently settable field on
/// [`PlannedUpdateItem`] itself, which reopened the same class of bug: an `Applied` item with no
/// target. #1615 folds the target into each variant that actually carries one instead, so
/// [`Self::Applied`] with no target fails to compile:
///
/// ```compile_fail
/// use deps_cli::update::Outcome;
/// use deps_core::edit::ManifestEdit;
/// use deps_core::position::{Position, Range};
///
/// let outcome = Outcome::Applied {
///     edit: ManifestEdit {
///         range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///         new_text: "1.2.0".to_string(),
///     },
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A fix plan existed and its edit was written (or would be, under `--dry-run`).
    /// Contributes to exit 0. Carries the edit and its target version — #1349/#1615: this
    /// makes "applied, but no edit/target to write" unrepresentable, where separate
    /// `PlannedUpdateItem` fields previously let them drift out of sync (`apply_plan` would
    /// report success without writing anything).
    Applied {
        /// The edit [`apply_plan`] writes.
        edit: ManifestEdit,
        /// The version this edit moves the dependency to.
        target: ConcreteVersion,
    },
    /// Excluded from this run, for [`SkipReason`].
    Skipped {
        /// Why this candidate was skipped.
        reason: SkipReason,
        /// The target version considered for this occurrence, when one was known — `None` when
        /// no concrete target exists (an unplannable latest, an ignore-rule skip of an
        /// OSV-blocked fallback, or — under `--security-only` — a not-requested item).
        target: Option<ConcreteVersion>,
    },
    /// (`--security-only` only) The dependency is `Vulnerable`, but its declared requirement
    /// already admits the fix target, so no requirement-level edit exists — needs #1116.
    /// Contributes to exit 1.
    RequiresLockfileUpdate {
        /// The already-admitted fix target.
        target: ConcreteVersion,
    },
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
    /// Spec 075 FR-014: nothing available clears the freshness cooldown for this occurrence —
    /// either no fallback candidate exists at all (no lockfile-resolved in-use version to floor
    /// the search, spec 075 OQ1's documented no-floor limitation; or the newest
    /// cooldown-cleared candidate failed an ecosystem-safety/in-use-floor/requirement-floor
    /// guard, FR-001/FR-002/FR-003), or a candidate exists but the fallback view shows it
    /// already satisfies the declared requirement (FR-009, so there is nothing to rewrite), or
    /// it was itself blocked for a non-OSV structural reason (FR-007's decision table). A
    /// fallback candidate blocked by its own OSV verdict is reported separately as
    /// [`Self::NotSafelyEditable`] (exit 1, FR-011) — never demoted to this routine, exit-0
    /// pause. Since the engine (`deps-engine`) now computes a fallback candidate whenever one
    /// exists, this is no longer the unconditional starvation risk it was before spec 075: a
    /// package publishing faster than the cooldown window can still resolve via its fallback,
    /// provided one clears every guard.
    WithinFreshnessCooldown,
}

/// Why a `--security-only` candidate could not be fixed.
///
/// The three variants that reject a specific, known fix target (#1614) carry it inline, so
/// `--security-only` output can report the rejected version instead of nothing; the two that
/// mean no fix target was ever established carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Yanked {
        /// The yanked fix target that was rejected.
        target: ConcreteVersion,
    },
    /// The declared requirement has a shape the formatter has no single unambiguous rewrite
    /// for (e.g. a compound comma-separated Cargo requirement, #1566) *and* a requirement
    /// matcher exists that has already confirmed the declared requirement does not admit the
    /// fix target — distinct from [`Outcome::RequiresLockfileUpdate`], which means the
    /// requirement already admits the fix and nothing needs rewriting at all. Conflating the
    /// two would tell the operator to regenerate the lock file for a dependency that is still
    /// vulnerable (#1566 S1).
    UnsupportedRequirementShape {
        /// The confirmed-excluded fix target.
        target: ConcreteVersion,
    },
    /// The declared requirement's raw text exceeds `deps_core::lsp_helpers::MAX_REQUIREMENT_LEN`
    /// (`deps_core::lsp_helpers::requirement_is_oversized`, #1472's CWE-400 defense-in-depth
    /// bound) — a size-based fail-closed guard applied *before* a requirement matcher is ever
    /// compiled, never itself a confirmed exclusion. Distinct from
    /// [`Self::UnsupportedRequirementShape`] (#1578 S1): that variant means a matcher actually
    /// ran and confirmed the declared requirement excludes the fix target, while this one means
    /// the matcher never ran at all, so an oversized requirement that would in fact have
    /// admitted the fix is still reported here rather than as
    /// [`Outcome::RequiresLockfileUpdate`] — conflating the two would let a false "confirmed
    /// excluded" claim reach the operator for a case that was never actually checked.
    OversizedRequirement {
        /// The fix target the oversized requirement was never checked against.
        target: ConcreteVersion,
    },
}

impl Outcome {
    /// The FR-021 wire token (`--format json`'s `outcome` field, and the table's `[..]`
    /// prefix): one of exactly `applied` / `skipped` / `requires-lockfile-update` /
    /// `unfixable` — a [`SkipReason`]/[`UnfixableReason`]'s own detail is carried in
    /// [`PlannedUpdateItem::reason`] instead, not folded into this token.
    #[must_use]
    pub const fn wire_token(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::Skipped { .. } => "skipped",
            Self::RequiresLockfileUpdate { .. } => "requires-lockfile-update",
            Self::Unfixable(_) => "unfixable",
        }
    }

    /// This outcome's target version, when its variant carries one — the sole read path for a
    /// dependency's considered/applied target (#1615), used by [`PlannedUpdateItem::target`] and
    /// every formatter.
    #[must_use]
    pub const fn target(&self) -> Option<&ConcreteVersion> {
        match self {
            Self::Applied { target, .. } | Self::RequiresLockfileUpdate { target } => Some(target),
            Self::Skipped { target, .. } => target.as_ref(),
            Self::Unfixable(
                UnfixableReason::Yanked { target }
                | UnfixableReason::UnsupportedRequirementShape { target }
                | UnfixableReason::OversizedRequirement { target },
            ) => Some(target),
            Self::Unfixable(
                UnfixableReason::NoVerifiedFix | UnfixableReason::FetchFailedOrAbsent,
            ) => None,
        }
    }
}

impl PlannedUpdateItem {
    /// Builds a `PlannedUpdateItem` from its already-computed fields.
    ///
    /// Replaces the near-identical hand-rolled struct literals `security.rs`'s four
    /// terminal-outcome builders and this module's own `resolve_occurrence` `build` closure
    /// previously each constructed independently (issue #1551 finding 5) — a field change
    /// affecting those two call sites now only requires touching this constructor. Fields stay
    /// `pub` and other construction sites remain plain struct literals (e.g. `deps-cli`'s
    /// `exit.rs`, this module's own tests, and the doctest above) — this constructor does not
    /// make the type `#[non_exhaustive]` or migrate every existing literal to it.
    #[must_use]
    pub fn new(
        name: String,
        current: CurrentVersion,
        outcome: Outcome,
        advisory_ids: Vec<String>,
        ignore_rule_overridden: bool,
        gossip_excluded_version: Option<deps_core::ConcreteVersion>,
        cooldown_fallback: Option<CooldownFallbackNote>,
    ) -> Self {
        Self {
            name,
            current,
            outcome,
            advisory_ids,
            ignore_rule_overridden,
            gossip_excluded_version,
            cooldown_fallback,
        }
    }

    /// This item's considered/applied target version — delegates to [`Outcome::target`], the
    /// sole read path since #1615 folded the target into [`Self::outcome`]'s own variant.
    #[must_use]
    pub const fn target(&self) -> Option<&ConcreteVersion> {
        self.outcome.target()
    }

    /// A one-line human-readable reason for [`Self::outcome`] (FR-021's `reason` field).
    #[must_use]
    pub fn reason(&self) -> String {
        let base = match &self.outcome {
            Outcome::Applied { .. } => "update applied",
            Outcome::Skipped {
                reason: SkipReason::IgnoreRule,
                ..
            } => "matched an [update].ignore rule",
            Outcome::Skipped {
                reason: SkipReason::NotRequested,
                ..
            } => "not named by --package",
            Outcome::Skipped {
                reason:
                    SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::UnsafeLatestVersion,
                    ),
                ..
            } => "the registry-reported latest version failed a safety check",
            Outcome::Skipped {
                reason:
                    SkipReason::NotSafelyEditable(deps_core::edit::UnplannableReason::NonLiteralSpan),
                ..
            } => {
                "the declared version is not a plain literal (e.g. a property reference or variable) and cannot be safely rewritten"
            }
            Outcome::Skipped {
                reason:
                    SkipReason::NotSafelyEditable(deps_core::edit::UnplannableReason::NoOpRewrite),
                ..
            } => "no single unambiguous rewrite exists for this dependency's requirement syntax",
            // Fix-cycle item 6/M1 minor: `NotSafelyEditable(LatestFlaggedByOsv|LatestUnverified)`
            // is reused for a blocked FALLBACK candidate (row 10, FR-011) as well as a blocked
            // `latest` — `UpdateCandidate` carries no marker distinguishing which view produced
            // it, so the base text branches on `cooldown_fallback` instead of naming "latest"
            // unconditionally (which previously read as self-contradictory once the `Blocked`
            // attribution suffix below named the fallback candidate specifically).
            Outcome::Skipped {
                reason:
                    SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestFlaggedByOsv,
                    ),
                ..
            } => {
                if matches!(
                    self.cooldown_fallback,
                    Some(CooldownFallbackNote::Blocked { .. })
                ) {
                    "the freshness-cooldown fallback candidate is flagged by OSV.dev — refusing to write it"
                } else {
                    "the registry's latest version is flagged by OSV.dev — refusing to write it"
                }
            }
            Outcome::Skipped {
                reason:
                    SkipReason::NotSafelyEditable(deps_core::edit::UnplannableReason::LatestUnverified),
                ..
            } => {
                if matches!(
                    self.cooldown_fallback,
                    Some(CooldownFallbackNote::Blocked { .. })
                ) {
                    "the freshness-cooldown fallback candidate could not be verified against OSV.dev — refusing to write it"
                } else {
                    "the registry's latest version could not be verified against OSV.dev — refusing to write it"
                }
            }
            Outcome::Skipped {
                reason: SkipReason::OverlapsAnotherEdit,
                ..
            } => "this edit's span overlapped another item's and was dropped",
            Outcome::Skipped {
                reason: SkipReason::WithinFreshnessCooldown,
                ..
            } => "the selected update target was published within the freshness cooldown window",
            Outcome::RequiresLockfileUpdate { .. } => {
                "declared requirement already admits the fix target; regenerate the lock file (see #1116)"
            }
            Outcome::Unfixable(UnfixableReason::NoVerifiedFix) => {
                "no independently-verified fix target is available"
            }
            Outcome::Unfixable(UnfixableReason::FetchFailedOrAbsent) => {
                "registry fetch for this dependency failed or returned no data"
            }
            Outcome::Unfixable(UnfixableReason::Yanked { .. }) => "the fix target is yanked",
            Outcome::Unfixable(UnfixableReason::UnsupportedRequirementShape { .. }) => {
                "the declared requirement's syntax has no safe single-value rewrite and does not already admit the fix target — manual edit required"
            }
            Outcome::Unfixable(UnfixableReason::OversizedRequirement { .. }) => {
                "the declared requirement is too large to safely evaluate; treating as unfixable — manual edit required"
            }
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
        // Spec 075 FR-013: attributes a cooldown-fallback decision on top of the base reason —
        // `AppliedInsteadOf` names the fresher version this item bypassed; `Blocked` names the
        // specific candidate the base text above already describes as blocked (see the
        // `NotSafelyEditable` match arms' own fallback-aware wording).
        match &self.cooldown_fallback {
            Some(CooldownFallbackNote::AppliedInsteadOf(latest)) => {
                reason.push_str(&format!(
                    " (targeted a cooldown-cleared fallback instead of {latest}, which is still \
                     within its freshness cooldown window)"
                ));
            }
            Some(CooldownFallbackNote::Blocked { version }) => {
                reason.push_str(&format!(" (candidate: {version})"));
            }
            None => {}
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

/// The cached registry data for `normalized_name` (or, failing that, `raw_name`) — the shared
/// lookup [`gossip_excluded_version`] and the unified planner both need (code-review finding:
/// previously each ran this same two-step `HashMap` lookup independently).
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

/// Spec 075 FR-007/FR-008/FR-010: the fallback-substituted view [`plan_updates`] feeds through
/// [`collect_update_candidates`] alongside the real `latest` view — only `latest` swapped for
/// each dependency's stored cooldown-fallback candidate, when one exists.
///
/// Reuses [`ManifestAnalysis::cooldown_fallback_view`] when `analyze_manifest` already built it
/// for its own FR-010 OSV round, rather than recomputing an identical view from scratch (issue
/// #1551 finding 3) — that field already carries the same "something actually changed" gate
/// `analyze_manifest`'s own OSV round applies (NFR-004: zero extra work when nothing is
/// cooldown-blocked with a usable fallback). When the field was never populated (a caller that
/// built [`ManifestAnalysis`] directly, e.g. this module's own tests), the identical gate is
/// applied here instead of computing the view unconditionally — `None` either way means
/// `plan_updates` skips [`collect_update_candidates`]'s full-manifest pass over the fallback
/// view entirely, since [`resolve_occurrence`] only ever consults it when a dependency's own
/// [`cooldown_disposition`] is `Blocked { fallback: Some(_), .. }`.
///
/// The reuse path (impl-critic m3) does *not* re-apply `freshness`/`now` to the already-built
/// view — it relies on the caller passing the same values `analyze_manifest` used to build it,
/// the same invariant [`ManifestAnalysis::now`]'s own doc already requires of every
/// `plan_updates` caller. A caller that violates it only affects this reuse path, never the
/// recompute-and-gate fallback below, which always uses its own `freshness`/`now` arguments.
fn resolve_cooldown_fallback_view(
    analysis: &ManifestAnalysis,
    freshness: deps_core::FreshnessSettings,
    now: deps_core::PublishTime,
) -> Option<HashMap<PackageName, PackageVersions>> {
    if let Some(view) = analysis.cooldown_fallback_view.as_ref() {
        return Some(view.clone());
    }
    let view = crate::analyze::cooldown_fallback_view(
        &analysis.cached_versions,
        Some(&analysis.gossip_findings),
        freshness,
        now,
    );
    view.iter()
        .any(|(name, v)| {
            analysis
                .cached_versions
                .get(name)
                .is_none_or(|c| c.latest != v.latest)
        })
        .then_some(view)
}

/// Default-mode planner: every dependency [`deps_core::edit::collect_update_candidates`]
/// considers, narrowed by `--package` and `[update].ignore` (FR-003, FR-005, FR-006, FR-007).
///
/// An outdated dependency `collect_update_candidates` could not safely rewrite (a
/// [`deps_core::edit::UpdateCandidate::Unplannable`] — an unsafe registry value, a
/// non-literal span, or a formatter with no unambiguous rewrite) is still reported here as
/// [`Outcome::Skipped`] with reason [`SkipReason::NotSafelyEditable`] rather than silently
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
///     now: deps_core::PublishTime::now(),
///     ecosystem_id: EcosystemId::Cargo,
///     cached_versions,
///     resolved_versions: HashMap::new(),
///     resolved_version_candidates: HashMap::new(),
///     outcomes: DependencyOutcomes::new(),
///     vulnerabilities: None,
///     latest_status: None,
///     fallback_status: None,
///     cooldown_fallback_view: None,
///     gossip_findings: HashMap::new(),
///     licenses: HashMap::new(),
///     license_policy: deps_core::licenses::LicensePolicy::default(),
///     license_source: deps_core::LicenseSource::default(),
///     network: deps_core::NetworkMode::Online,
///     fetch_failed: HashSet::new(),
///     registry_unreachable: false,
///     license_fetch_incomplete: false,
/// };
///
/// // Freshness is disabled by default, so this fixture never reaches the fallback-edit guard
/// // — the closure is never actually called.
/// let reparse = |_content: &str| -> Option<Box<dyn ParseResult>> { None };
///
/// let plan = plan_updates(
///     &analysis,
///     content,
///     &MockFormatter,
///     &reparse,
///     &[],
///     &IgnoreRules::empty(),
///     deps_core::FreshnessSettings::default(),
///     deps_core::PublishTime::now(),
/// );
///
/// assert_eq!(plan.items.len(), 1);
/// assert!(matches!(plan.items[0].outcome, Outcome::Applied { .. }));
/// assert_eq!(plan.items[0].target(), Some(&ConcreteVersion::from("1.2.0")));
/// ```
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "spec 076 T004 adds `reparse` (FR-024) to the existing FR-007 planner surface; \
              grouping into a struct would only move, not reduce, churn (mirrors \
              resolve_occurrence's own identical rationale)"
)]
pub fn plan_updates(
    analysis: &ManifestAnalysis,
    content: &str,
    formatter: &dyn EcosystemFormatter,
    reparse: &dyn ManifestReparse,
    package_filter: &[String],
    ignore_rules: &IgnoreRules,
    freshness: deps_core::FreshnessSettings,
    now: deps_core::PublishTime,
) -> UpdatePlan {
    let latest_candidates = collect_update_candidates(
        analysis.parse_result.as_ref(),
        content,
        analysis.version_data(),
        formatter,
    );

    // Spec 075 FR-007/FR-008: a fallback view of the registry data (only `latest` swapped for
    // each dependency's stored cooldown-fallback candidate, when one exists) fed through the
    // exact same planner — so a fallback candidate is verified/planned identically to `latest`,
    // never through a separate code path. Only occurrences already present in
    // `latest_candidates` (i.e. `Outdated` against real `latest`) ever look this up (FR-008).
    // `resolve_cooldown_fallback_view` reuses `analysis.cooldown_fallback_view` when
    // `analyze_manifest` already built it (issue #1551 finding 3), and gates the
    // `collect_update_candidates` pass below on the same "something actually changed" check
    // either way — `None` means no dependency is cooldown-blocked with a usable fallback.
    let fallback_view = resolve_cooldown_fallback_view(analysis, freshness, now);
    // Issue #1561 item 1 (defense-in-depth, library-API callers only — `deps-cli`'s own
    // `analyze_manifest` always populates both together): an empty map, never a bare `None`,
    // stands in for a missing `fallback_status` whenever `latest_status` IS populated — a bare
    // `None` here would make `latest_verdict` treat every fallback candidate as
    // `NotApplicable` ("no check needed"), silently bypassing OSV verification instead of
    // failing closed to `Unverified` the way a genuinely never-checked candidate does.
    let empty_fallback_status = deps_core::osv::LatestStatusMap::new();
    let fallback_candidates = match fallback_view.as_ref() {
        Some(view) => {
            let mut fallback_version_data =
                deps_core::VersionData::new(view, &analysis.resolved_versions)
                    .with_resolved_version_candidates(&analysis.resolved_version_candidates)
                    .with_ecosystem(analysis.ecosystem_id);
            fallback_version_data = match analysis.fallback_status.as_ref() {
                Some(fallback_status) => fallback_version_data.with_latest_status(fallback_status),
                None if analysis.latest_status.is_some() => {
                    fallback_version_data.with_latest_status(&empty_fallback_status)
                }
                None => fallback_version_data,
            };
            collect_update_candidates(
                analysis.parse_result.as_ref(),
                content,
                fallback_version_data,
                formatter,
            )
        }
        None => Vec::new(),
    };

    // Base identity every dependency carries unconditionally — `(normalized_name, name_range)`
    // — grouped (not collapsed) so a genuine collision (two dependencies sharing both, e.g.
    // Gradle/Composer's degraded-position parsing) stays visible instead of one silently
    // shadowing the other. `occurrence_key` resolves each occurrence's `version_range` via
    // `Dependency::version_range()` uniformly, rather than from whichever `UpdateCandidate`
    // variant (`Planned`'s `edit.range`, or nothing at all for `Unplannable`) a given view
    // happened to produce — but only when the group has exactly one member: code review traced
    // a path where the earlier single-dep-per-pair map let a collision's downgrade guard
    // (`fallback_satisfies_requirement`) silently run against the WRONG occurrence's declared
    // requirement. `None` on a detected collision is deliberate — every lookup keyed on it
    // (the downgrade guard, OSV advisory attribution) then fails closed instead of guessing.
    let mut deps_by_name_range: HashMap<
        (String, deps_core::position::Range),
        Vec<&dyn deps_core::Dependency>,
    > = HashMap::new();
    for dep in analysis.parse_result.dependencies() {
        deps_by_name_range
            .entry((
                formatter.normalize_package_name(dep.name()),
                dep.name_range(),
            ))
            .or_default()
            .push(dep);
    }
    let occurrence_key = |normalized_name: &str, name_range: deps_core::position::Range| {
        let version_range = match deps_by_name_range
            .get(&(normalized_name.to_string(), name_range))
            .map(Vec::as_slice)
        {
            Some([dep]) => dep.version_range(),
            _ => None,
        };
        (normalized_name.to_string(), name_range, version_range)
    };

    // Same collision guard as `dep_by_key` below: a colliding occurrence's fallback candidate is
    // excluded rather than collapsed with the other's, so both occurrences fall through to the
    // same "fallback absent" (row 6) handling instead of one silently stealing the other's
    // `SkipReason`/attribution in the `Unplannable` branch (impl-critic, rows 8/10/11).
    let mut fallback_by_key: HashMap<OccurrenceKey, UpdateCandidate> = fallback_candidates
        .into_iter()
        .filter(|c| {
            let (normalized_name, name_range) = candidate_identity(c);
            deps_by_name_range
                .get(&(normalized_name, name_range))
                .is_some_and(|deps| deps.len() == 1)
        })
        .map(|c| {
            let (normalized_name, name_range) = candidate_identity(&c);
            (occurrence_key(&normalized_name, name_range), c)
        })
        .collect();

    let dep_by_key: HashMap<OccurrenceKey, &dyn deps_core::Dependency> = deps_by_name_range
        .iter()
        .filter_map(
            |(&(ref normalized_name, name_range), deps)| match deps.as_slice() {
                [dep] => Some((occurrence_key(normalized_name, name_range), *dep)),
                _ => None,
            },
        )
        .collect();

    let vuln_keys = deps_core::osv::vulnerability_keys(
        analysis.parse_result.as_ref(),
        &analysis.resolved_versions,
        Some(&analysis.resolved_version_candidates),
        formatter,
        analysis.ecosystem_id,
    );

    let mut items: Vec<PlannedUpdateItem> = latest_candidates
        .into_iter()
        .map(|latest_candidate| {
            let (normalized_name, name_range) = candidate_identity(&latest_candidate);
            let key = occurrence_key(&normalized_name, name_range);
            resolve_occurrence(
                latest_candidate,
                key,
                &mut fallback_by_key,
                &dep_by_key,
                analysis,
                content,
                formatter,
                reparse,
                package_filter,
                ignore_rules,
                freshness,
                &vuln_keys,
                now,
            )
        })
        .collect();

    // FR-015: the overlap-collapsing pass runs AFTER per-occurrence view selection, over the
    // chosen `PlannedUpdate`s only — never over both views' raw candidates. This also makes
    // `SkipReason::OverlapsAnotherEdit` reachable from this planner for the first time (it
    // previously only ever came from `security::plan_security_updates`'s own items, since this
    // planner's pre-#1543 pre-classification dedup dropped an overlapping candidate silently,
    // with no `PlannedUpdateItem` at all).
    dedup_applied_items(&mut items);

    UpdatePlan { items }
}

/// Spec 075 FR-007: one manifest occurrence's join key between the latest and fallback views —
/// `(normalized_name, name_range, version_range)` rather than `name_range` alone (fix-cycle
/// item 6/M2 minor, strengthened per code review): some formatters' degraded parsing paths
/// (Gradle's `find_name_range`, Composer's AST-degraded path) can return `Range::default()` for
/// more than one occurrence in the same manifest — a bare `name_range` collision would hand one
/// occurrence another package's fallback edit, and for two occurrences of the *same* package
/// name, that could approve a downgrade against the WRONG occurrence's declared requirement
/// (FR-003's guard would run with a `&dyn Dependency` borrowed from a different span).
///
/// `version_range` is always resolved from [`deps_core::Dependency::version_range`] itself (via
/// [`plan_updates`]'s `occurrence_key` closure), never from a specific [`UpdateCandidate`]
/// variant's own field — an occurrence that is `Planned` in one view and `Unplannable` in the
/// other (rows 7/10, this feature's own main additions) must still resolve to the identical key
/// in both, or the cross-view join breaks. This discriminates two occurrences of the same
/// package whenever their version text sits at different positions — true in every realistic
/// case, since that is where the difference between two declarations actually lives even when
/// both degrade to the same synthetic name range. The residual gap this cannot close is two
/// occurrences of one package whose version text ALSO sits at the same (degraded) position;
/// closing that fully needs the deeper per-occurrence identity plan.md's `OccurrenceCandidate`
/// design implies.
type OccurrenceKey = (
    String,
    deps_core::position::Range,
    Option<deps_core::position::Range>,
);

/// [`UpdateCandidate`]'s `(normalized_name, name_range)` — the two fields every variant carries
/// unconditionally, fed into [`plan_updates`]'s `occurrence_key` closure to resolve the full
/// [`OccurrenceKey`] (including `version_range`) uniformly regardless of Planned/Unplannable.
fn candidate_identity(candidate: &UpdateCandidate) -> (String, deps_core::position::Range) {
    match candidate {
        UpdateCandidate::Planned(p) => (p.normalized_name.clone(), p.name_range),
        UpdateCandidate::Unplannable {
            normalized_name,
            name_range,
            ..
        } => (normalized_name.clone(), *name_range),
    }
}

/// `(current, target)` for a `WithinFreshnessCooldown`/`NotRequested` item built directly from
/// the latest view — a `Planned` candidate carries both; an `Unplannable` one carries neither
/// (matches this planner's pre-#1543 convention for an item with no concrete write target).
fn latest_current_target(candidate: &UpdateCandidate) -> (CurrentVersion, Option<ConcreteVersion>) {
    match candidate {
        UpdateCandidate::Planned(p) => (
            CurrentVersion::from(p.current.clone()),
            Some(p.target.clone()),
        ),
        UpdateCandidate::Unplannable { .. } => (CurrentVersion::Unknown, None),
    }
}

/// Spec 075 FR-004 rows 1/2/3/5/8 (§6): resolves an occurrence purely from the latest view —
/// `disposition` is `NotEvaluated`/`Cleared`, or `Blocked` with no usable fallback and `latest`
/// is itself OSV-unplannable ("never demoted" by a cooldown skip). Mirrors this planner's
/// pre-#1543 `planned`/`unplannable` loop bodies exactly, minus the `is_requested` check (the
/// caller already ran it once for both views) and minus any cooldown check (the caller's
/// disposition match already decided this occurrence reaches this function at all).
fn resolve_from_latest(
    latest_candidate: UpdateCandidate,
    ignore_rules: &IgnoreRules,
) -> (CurrentVersion, Outcome, Vec<String>) {
    match latest_candidate {
        UpdateCandidate::Planned(p) => {
            let target = p.target.clone();
            let current = CurrentVersion::from(p.current);
            let kind = current.update_kind_to(&p.target);
            if let Some(reason) = ignore_rules.skip_reason(&p.normalized_name, kind) {
                (
                    current,
                    Outcome::Skipped {
                        reason,
                        target: Some(target),
                    },
                    Vec::new(),
                )
            } else {
                (
                    current,
                    Outcome::Applied {
                        edit: p.edit,
                        target,
                    },
                    Vec::new(),
                )
            }
        }
        UpdateCandidate::Unplannable {
            normalized_name,
            reason,
            ..
        } => {
            let outcome = if let Some(rule_reason) =
                ignore_rules.skip_reason(&normalized_name, UpdateKind::Unknown)
            {
                Outcome::Skipped {
                    reason: rule_reason,
                    target: None,
                }
            } else {
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(reason),
                    target: None,
                }
            };
            (CurrentVersion::Unknown, outcome, Vec::new())
        }
    }
}

/// Spec 075 FR-011/FR-012: `version`'s OSV verdict advisory ids, looked up against `status` —
/// empty unless the verdict is `Flagged` (an `Unverified` verdict has no advisory list; the two
/// call sites below never reach this helper for a `Verified`/`NotApplicable` version).
fn osv_advisory_ids(
    status: Option<&deps_core::osv::LatestStatusMap>,
    dep: Option<&dyn deps_core::Dependency>,
    vuln_keys: &deps_core::osv::VulnKeys,
    normalized_name: &str,
    version: &str,
    formatter: &dyn EcosystemFormatter,
) -> Vec<String> {
    let Some(dep) = dep else {
        return Vec::new();
    };
    match latest_verdict(
        status,
        dep,
        Some(vuln_keys),
        normalized_name,
        version,
        formatter,
    ) {
        LatestVerdict::Flagged { advisory_ids, .. } => advisory_ids,
        LatestVerdict::Unverified | LatestVerdict::Verified | LatestVerdict::NotApplicable => {
            Vec::new()
        }
    }
}

/// Spec 075 FR-007: the unified per-occurrence planner pipeline. Builds `latest_candidate`'s
/// identity once, resolves this occurrence's [`CooldownDisposition`], and — only when it is
/// `Blocked` — consults `fallback_by_key` (removed so each fallback occurrence is used at most
/// once) to pick between `latest` and the fallback candidate per spec 075 §6's decision table,
/// before running `is_requested`/`ignore_rules` exactly once against the SELECTED target.
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is either the two views' shared lookup data or a planning \
              knob already threaded through plan_updates; grouping into a struct would only \
              move, not reduce, churn (mirrors deps-engine::classify::fetch's identical call)"
)]
fn resolve_occurrence(
    latest_candidate: UpdateCandidate,
    key: OccurrenceKey,
    fallback_by_key: &mut HashMap<OccurrenceKey, UpdateCandidate>,
    dep_by_key: &HashMap<OccurrenceKey, &dyn deps_core::Dependency>,
    analysis: &ManifestAnalysis,
    content: &str,
    formatter: &dyn EcosystemFormatter,
    reparse: &dyn ManifestReparse,
    package_filter: &[String],
    ignore_rules: &IgnoreRules,
    freshness: deps_core::FreshnessSettings,
    vuln_keys: &deps_core::osv::VulnKeys,
    now: deps_core::PublishTime,
) -> PlannedUpdateItem {
    let (name, normalized_name) = match &latest_candidate {
        UpdateCandidate::Planned(p) => (p.name.clone(), p.normalized_name.clone()),
        UpdateCandidate::Unplannable {
            name,
            normalized_name,
            ..
        } => (name.clone(), normalized_name.clone()),
    };
    let gossip_excluded = gossip_excluded_version(analysis, &normalized_name, &name);
    let fallback_candidate = fallback_by_key.remove(&key);

    let build = |current: CurrentVersion,
                 outcome: Outcome,
                 advisory_ids: Vec<String>,
                 cooldown_fallback: Option<CooldownFallbackNote>| {
        PlannedUpdateItem::new(
            name.clone(),
            current,
            outcome,
            advisory_ids,
            false,
            gossip_excluded.clone(),
            cooldown_fallback,
        )
    };

    if !is_requested(package_filter, &normalized_name, formatter) {
        let (current, target) = latest_current_target(&latest_candidate);
        return build(
            current,
            Outcome::Skipped {
                reason: SkipReason::NotRequested,
                target,
            },
            Vec::new(),
            None,
        );
    }

    let package_versions = cached_package_versions(analysis, &normalized_name, &name);
    // Security M1: the RAW name — matches `gossip_findings`/`apply_outdated_rule`'s own keying;
    // the normalized name silently hid GOSSIP data for case-changing ecosystems (#1529).
    let gossip_name = PackageName::new(name.clone());
    let disposition = package_versions.map_or(CooldownDisposition::NotEvaluated, |versions| {
        cooldown_disposition(
            versions,
            &gossip_name,
            freshness,
            Some(&analysis.gossip_findings),
            now,
        )
    });
    let latest_is_osv_unplannable = matches!(
        &latest_candidate,
        UpdateCandidate::Unplannable {
            reason: UnplannableReason::LatestFlaggedByOsv | UnplannableReason::LatestUnverified,
            ..
        }
    );
    // Fix-cycle item 6 (DRY): "never demote a flagged/unverified latest" is the shared shape
    // behind rows 5/6/8/FR-003-reject — one closure instead of four hand-rolled copies.
    let never_demoted = |latest_candidate: UpdateCandidate| {
        let (current, outcome, advisory_ids) = resolve_from_latest(latest_candidate, ignore_rules);
        build(current, outcome, advisory_ids, None)
    };
    // DRY (code review finding): the routine "cooldown pause, targeting whatever `latest`
    // itself carries" shape recurs across rows 4/6/(fb.target-mismatch)/(requirement rejected)/11
    // — one closure instead of five hand-rolled copies.
    let cooldown_skip_from_latest = |latest_candidate: &UpdateCandidate| {
        let (current, target) = latest_current_target(latest_candidate);
        build(
            current,
            Outcome::Skipped {
                reason: SkipReason::WithinFreshnessCooldown,
                target,
            },
            Vec::new(),
            None,
        )
    };

    match disposition {
        CooldownDisposition::NotEvaluated | CooldownDisposition::Cleared => {
            let (current, outcome, advisory_ids) =
                resolve_from_latest(latest_candidate, ignore_rules);
            build(current, outcome, advisory_ids, None)
        }
        CooldownDisposition::Blocked { fallback: None, .. } => {
            if latest_is_osv_unplannable {
                // Row 5: never demoted by a routine cooldown pause.
                never_demoted(latest_candidate)
            } else {
                // Row 4.
                cooldown_skip_from_latest(&latest_candidate)
            }
        }
        // `by` (GOSSIP vs. local) is deliberately unread here: the wording difference is
        // `cooldown_disposition`'s own read-time concern (`apply_outdated_rule`), not this
        // planner's — it only ever decides fallback-vs-latest, never which blocker to name.
        CooldownDisposition::Blocked {
            by: _,
            fallback: Some(fallback),
        } => {
            let latest_version = package_versions.map(|v| v.latest.clone());
            let available: &[deps_core::ConcreteVersion] =
                package_versions.map_or(&[], |v| &v.available);
            match fallback_candidate {
                // Row 6 (FR-009): absent from the fallback view means the fallback already
                // satisfies the declared requirement — never silently treat that as "use
                // latest anyway". Fix-cycle item 2/S2: never demote a flagged/unverified
                // latest to a routine cooldown pause just because no fallback view entry
                // exists — that regresses #1517's "never masked by cooldown" invariant.
                None => {
                    if latest_is_osv_unplannable {
                        never_demoted(latest_candidate)
                    } else {
                        cooldown_skip_from_latest(&latest_candidate)
                    }
                }
                Some(UpdateCandidate::Planned(fb)) => {
                    // Issue #1561 item 2 (defense-in-depth): `fb.target` (the fallback view's
                    // own planned edit) and `fallback.version` (this occurrence's own
                    // `cooldown_disposition` pick, computed independently above) must always
                    // agree by construction — both ultimately derive from the same stored
                    // `CooldownFallback`. Never write an edit neither computation fully
                    // vouches for; a divergence falls through to the same fail-closed handling
                    // as "fallback absent" above.
                    if fb.target != fallback.version {
                        return if latest_is_osv_unplannable {
                            never_demoted(latest_candidate)
                        } else {
                            cooldown_skip_from_latest(&latest_candidate)
                        };
                    }
                    // Spec 076 FR-022/FR-023/FR-025: one uniform, re-parse-based guard applied
                    // identically to the `Located` (this occurrence has a lockfile-resolved
                    // in-use version) and `Absent` (spec 076's no-lockfile) paths — no per-
                    // ecosystem override, no Go exception (removed, FR-022: `ExactMatcher`
                    // alone is sufficient once this guard ships).
                    let requirement_ok = dep_by_key.get(&key).copied().is_some_and(|dep| {
                        let verdict = fallback_edit_excludes_newer(
                            formatter, reparse, content, dep, &fb.edit, &fb.target, available,
                        );
                        if let FallbackEditVerdict::Rejected(reason) = verdict {
                            tracing::debug!(
                                package = %normalized_name,
                                fallback = %fb.target,
                                ?reason,
                                "fallback edit rejected by fallback_edit_excludes_newer"
                            );
                        }
                        matches!(verdict, FallbackEditVerdict::Writable)
                    });
                    if requirement_ok {
                        // Rows 7 & 9 (fix-cycle item 3/S3): `ignore_rules` now runs against
                        // the SELECTED (fallback) target unconditionally, regardless of
                        // whether latest is OSV-blocked — previously row 7 wrote the fallback
                        // edit without ever consulting `[update].ignore`.
                        let current = CurrentVersion::from(fb.current);
                        let kind = current.update_kind_to(&fb.target);
                        if let Some(reason) = ignore_rules.skip_reason(&fb.normalized_name, kind) {
                            build(
                                current,
                                Outcome::Skipped {
                                    reason,
                                    target: Some(fb.target.clone()),
                                },
                                Vec::new(),
                                None,
                            )
                        } else if latest_is_osv_unplannable {
                            // Row 7 (FR-012/OQ3): target the fallback, keep the
                            // flagged/unverified latest's own attribution in the same row.
                            let advisory_ids =
                                latest_version.as_ref().map_or_else(Vec::new, |latest| {
                                    osv_advisory_ids(
                                        analysis.latest_status.as_ref(),
                                        dep_by_key.get(&key).copied(),
                                        vuln_keys,
                                        &normalized_name,
                                        latest.as_str(),
                                        formatter,
                                    )
                                });
                            build(
                                current,
                                Outcome::Applied {
                                    edit: fb.edit,
                                    target: fb.target,
                                },
                                advisory_ids,
                                latest_version.map(CooldownFallbackNote::AppliedInsteadOf),
                            )
                        } else {
                            // Row 9: the ordinary cooldown-fallback substitution.
                            build(
                                current,
                                Outcome::Applied {
                                    edit: fb.edit,
                                    target: fb.target,
                                },
                                Vec::new(),
                                latest_version.map(CooldownFallbackNote::AppliedInsteadOf),
                            )
                        }
                    } else {
                        // FR-003 (A1) / fix-cycle item 2/S2: the compiled matcher rejects the
                        // fallback as a downgrade (or is unavailable) — never write it, and
                        // never demote a flagged/unverified latest here either.
                        if latest_is_osv_unplannable {
                            never_demoted(latest_candidate)
                        } else {
                            cooldown_skip_from_latest(&latest_candidate)
                        }
                    }
                }
                // FR-011: an OSV-flagged/unverified fallback must surface here even when
                // `fallback_edit_excludes_newer` (never consulted in this arm) would also reject it.
                Some(UpdateCandidate::Unplannable {
                    reason: fb_reason, ..
                }) => {
                    if latest_is_osv_unplannable {
                        // Row 8: both blocked — defer to latest's own attribution, exit 1,
                        // never demoted regardless of why the fallback also failed.
                        never_demoted(latest_candidate)
                    } else if let Some(rule_reason) =
                        ignore_rules.skip_reason(&normalized_name, UpdateKind::Unknown)
                    {
                        // Fix-cycle item 4/S4: an ignored package's OSV-blocked fallback must
                        // not exit non-zero — mirrors `resolve_from_latest`'s identical
                        // Unplannable-candidate ignore-rule check (there is no concrete
                        // current/target pair here either, the same fail-closed
                        // `UpdateKind::Unknown` treatment applies).
                        build(
                            CurrentVersion::Unknown,
                            Outcome::Skipped {
                                reason: rule_reason,
                                target: None,
                            },
                            Vec::new(),
                            None,
                        )
                    } else if matches!(
                        fb_reason,
                        UnplannableReason::LatestFlaggedByOsv | UnplannableReason::LatestUnverified
                    ) {
                        // Row 10 (FR-011): the fallback itself is OSV-blocked — exit 1, naming
                        // the fallback version, never a silent cooldown skip.
                        let advisory_ids = osv_advisory_ids(
                            analysis.fallback_status.as_ref(),
                            dep_by_key.get(&key).copied(),
                            vuln_keys,
                            &normalized_name,
                            fallback.version.as_str(),
                            formatter,
                        );
                        let (current, _) = latest_current_target(&latest_candidate);
                        build(
                            current,
                            Outcome::Skipped {
                                reason: SkipReason::NotSafelyEditable(fb_reason),
                                target: Some(fallback.version.clone()),
                            },
                            advisory_ids,
                            Some(CooldownFallbackNote::Blocked {
                                version: fallback.version.clone(),
                            }),
                        )
                    } else {
                        // Row 11: fallback blocked by a non-OSV structural reason.
                        cooldown_skip_from_latest(&latest_candidate)
                    }
                }
            }
        }
    }
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
/// [`Outcome::Skipped`] with reason [`SkipReason::OverlapsAnotherEdit`].
///
/// Spec 075 FR-015: [`plan_updates`] now calls this itself, after per-occurrence view
/// selection, over its own chosen `PlannedUpdate`s — the correct place for this pass to run
/// (never over both the latest and fallback views' raw candidates together). Still
/// load-bearing for [`security::plan_security_updates`], which does not dedup its own
/// `Applied` items (two vulnerable occurrences of one name can share a span), and for
/// `main.rs`'s own defensive call after either planner returns. Without this,
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
            Outcome::Applied { edit, .. } => Some(Indexed {
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
        if !kept_indices.contains(&index)
            && let Outcome::Applied { target, .. } = &item.outcome
        {
            item.outcome = Outcome::Skipped {
                reason: SkipReason::OverlapsAnotherEdit,
                target: Some(target.clone()),
            };
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

    /// Issue #1593 critic M5: a `Declared` current version must never classify as anything
    /// but `Unknown` — guards against a future caller feeding it into a classification path
    /// (e.g. `ignore_rules.skip_reason`) that starts treating a declared range as comparable.
    #[test]
    fn test_current_version_declared_update_kind_is_always_unknown() {
        let declared = CurrentVersion::Declared(deps_core::VersionReq::new("^1.0"));
        assert_eq!(
            declared.update_kind_to(&ConcreteVersion::from("2.0.0")),
            UpdateKind::Unknown
        );
    }

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

    /// Spec 076 T004/M6: a [`ManifestReparse`] stub that must never actually be called — for
    /// fixtures whose disposition never reaches [`fallback_edit_excludes_newer`]'s re-parse
    /// phase (freshness disabled, no fallback candidate, or the fallback view's own OSV/
    /// structural rejection resolves the occurrence before the guard ever runs).
    fn never_reparse(_content: &str) -> Option<Box<dyn ParseResult>> {
        unreachable!("this fixture's disposition must never reach the fallback-edit re-parse phase")
    }

    /// Spec 076 M6: shared `ManifestReparse` test stub for this module's quoted-version,
    /// one-dependency-per-line fixtures (`name = "X"`). Rebuilds each `deps` entry's occurrence
    /// by reading back whatever version text now sits between ITS OWN quotes in the edited
    /// content, at the SAME position its original `version_range.start` had — genuinely
    /// reflects the edit `plan_updates` applied, rather than hard-coding the expected target
    /// (mirrors production `EcosystemReparse`'s re-parse-the-actual-edit contract).
    fn reparse_quoted_deps(deps: Vec<(&'static str, Position)>) -> impl ManifestReparse {
        move |edited_content: &str| -> Option<Box<dyn ParseResult>> {
            let rebuilt: Vec<TestDep> = deps
                .iter()
                .map(|&(name, start)| {
                    let line = edited_content.lines().nth(start.line as usize)?;
                    let rest = line.get(start.character as usize..)?;
                    let version_len = rest.find('"')?;
                    let version = rest.get(..version_len)?;
                    Some(TestDep {
                        name: PackageName::new(name),
                        version_req: deps_core::VersionReq::new(version),
                        version_range: Range::new(
                            start,
                            Position::new(
                                start.line,
                                start.character + u32::try_from(version_len).ok()?,
                            ),
                        ),
                    })
                })
                .collect::<Option<_>>()?;
            Some(Box::new(TestParseResult {
                deps: rebuilt,
                uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
            }) as Box<dyn ParseResult>)
        }
    }

    /// [`plan_updates`] with freshness cooldown filtering disabled — the pre-#1525 behavior
    /// every test not specifically about that filter wants.
    ///
    /// Critique M5: actually passes [`deps_core::FreshnessSettings::Disabled`], not
    /// [`deps_core::FreshnessSettings::default`] (which is enabled — a prior version of this
    /// helper passed that and only happened to work because every fixture omitted
    /// `published_at`; a fixture that later set one via [`PackageVersions::with_published_at`]
    /// would have been silently skipped instead of applied).
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
            &never_reparse,
            package_filter,
            ignore_rules,
            deps_core::FreshnessSettings::Disabled,
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
            now: deps_core::PublishTime::now(),
            ecosystem_id: EcosystemId::Cargo,
            cached_versions: cached,
            resolved_versions: HashMap::new(),
            resolved_version_candidates: HashMap::new(),
            outcomes: deps_core::lsp_helpers::DependencyOutcomes::new(),
            vulnerabilities: None,
            latest_status: None,
            fallback_status: None,
            cooldown_fallback_view: None,
            gossip_findings: HashMap::new(),
            licenses: HashMap::new(),
            license_policy: LicensePolicy::default(),
            license_source: deps_core::LicenseSource::default(),
            network: deps_core::NetworkMode::Online,
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
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(2_000), // wider than the 1000s age above
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(
            plan.items[0].outcome,
            Outcome::Skipped {
                reason: SkipReason::WithinFreshnessCooldown,
                ..
            }
        ));
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
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Disabled,
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].outcome, Outcome::Applied { .. }));
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
        assert!(matches!(plan.items[0].outcome, Outcome::Applied { .. }));
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
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(2_000), // wider than the 1000s age above
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
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
            .filter(|i| matches!(i.outcome, Outcome::Applied { .. }))
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
                version: ConcreteVersion::new("1.2.0"),
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
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestFlaggedByOsv
                    ),
                    ..
                }
            ),
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
                version: ConcreteVersion::new("1.2.0"),
                advisory_ids: Capped::new(vec!["MAL-2026-00001".to_string()], 1),
                worst_severity: Some(VulnSeverity::Malicious),
            },
        );
        analysis.latest_status = Some(latest_status);

        let plan = plan_updates(
            &analysis,
            content,
            &STUB_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(2_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestFlaggedByOsv
                    ),
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            plan.items[0].target(),
            None,
            "an Unplannable candidate has no concrete target"
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
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(2_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestUnverified
                    ),
                    ..
                }
            ),
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
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(2_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 1);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
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
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestUnverified
                    ),
                    ..
                }
            ),
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
        assert!(matches!(serde_item.outcome, Outcome::Applied { .. }));
        let tokio_item = plan.items.iter().find(|i| i.name == "tokio").unwrap();
        assert!(matches!(
            tokio_item.outcome,
            Outcome::Skipped {
                reason: SkipReason::NotRequested,
                ..
            }
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
            Outcome::Skipped {
                reason: SkipReason::IgnoreRule,
                ..
            }
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
                Outcome::Skipped {
                    reason: SkipReason::IgnoreRule,
                    ..
                }
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
            Outcome::Skipped {
                reason: SkipReason::NotSafelyEditable(
                    deps_core::edit::UnplannableReason::NonLiteralSpan
                ),
                ..
            }
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
        assert!(matches!(plan.items[0].outcome, Outcome::Applied { .. }));
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
                current: CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
                outcome: Outcome::Applied {
                    edit: ManifestEdit {
                        range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                        new_text: "1.2.0".to_string(),
                    },
                    target: ConcreteVersion::from("1.2.0"),
                },
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
                cooldown_fallback: None,
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
                current: CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
                outcome: Outcome::Applied {
                    edit: ManifestEdit {
                        range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                        new_text: "1.2.0".to_string(),
                    },
                    target: ConcreteVersion::from("1.2.0"),
                },
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
                cooldown_fallback: None,
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
                current: CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
                outcome: Outcome::Applied {
                    edit: ManifestEdit {
                        range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                        new_text: "1.2.0".to_string(),
                    },
                    target: ConcreteVersion::from("1.2.0"),
                },
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
                cooldown_fallback: None,
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
                current: CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
                outcome: Outcome::Skipped {
                    reason: SkipReason::IgnoreRule,
                    target: Some(ConcreteVersion::from("1.2.0")),
                },
                advisory_ids: Vec::new(),
                ignore_rule_overridden: false,
                gossip_excluded_version: None,
                cooldown_fallback: None,
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
            current: CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
            outcome: Outcome::Applied {
                edit: ManifestEdit {
                    range,
                    new_text: "1.2.0".to_string(),
                },
                target: ConcreteVersion::from("1.2.0"),
            },
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
            gossip_excluded_version: None,
            cooldown_fallback: None,
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
                .all(|i| matches!(i.outcome, Outcome::Applied { .. }))
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
        assert!(matches!(items[0].outcome, Outcome::Applied { .. }));
        assert!(matches!(
            items[1].outcome,
            Outcome::Skipped {
                reason: SkipReason::OverlapsAnotherEdit,
                ..
            }
        ));
        assert_eq!(
            items[1].target(),
            Some(&ConcreteVersion::from("1.2.0")),
            "a demoted item must keep its target, not silently drop it (#1615)"
        );
    }

    // --- Spec 075 (`deps-cli update` cooldown fallback) ---

    const FALLBACK_FORMATTER: deps_core::test_util::StubFormatter =
        deps_core::test_util::StubFormatter::new().with_manifest_requirement_as_resolved_version();

    /// A formatter with a REAL `compile_bounded_requirement` — `semver::VersionReq`-backed, via the
    /// same `deps_core::lsp_helpers::compile_semver_requirement` deps-cargo/deps-swift use in
    /// production. Fix-cycle item 1/S1: the original test used a synthetic `AtLeastMajor3`
    /// matcher whose behavior happened to be self-consistent with the (wrong)
    /// `fallback_satisfies_requirement` implementation it was meant to catch — impl-critic
    /// proved the bug only surfaced with a real ecosystem comparator. Using the genuine semver
    /// matcher here (rather than adding a `deps-npm`/`deps-cargo` dev-dependency) closes that
    /// gap without a new workspace dependency.
    struct RealSemverFormatter;
    impl deps_core::lsp_helpers::PackageNaming for RealSemverFormatter {}
    impl deps_core::lsp_helpers::PackageRendering for RealSemverFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl deps_core::lsp_helpers::RequirementResolution for RealSemverFormatter {
        fn compile_bounded_requirement(
            &self,
            requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn deps_core::lsp_helpers::RequirementMatcher>> {
            let requirement = requirement.get();
            deps_core::lsp_helpers::compile_semver_requirement(requirement)
        }
    }
    impl deps_core::lsp_helpers::DiagnosticMessages for RealSemverFormatter {}
    impl deps_core::lsp_helpers::DiagnosticPolicy for RealSemverFormatter {}
    impl deps_core::lsp_helpers::SourcePolicy for RealSemverFormatter {}
    impl deps_core::lsp_helpers::OsvNaming for RealSemverFormatter {}

    /// Spec 076 FR-022/FR-023 (A1 repro, phase-1 d0), corrected for #1564/#1561: rejects a
    /// fallback whose UNEDITED requirement's own floor (the oldest `available` entry it still
    /// matches) is newer than the fallback — replaces spec 075's isolated
    /// `fallback_satisfies_requirement` unit test (that function is deleted, and with it the Go
    /// `manifest_requirement_is_resolved_version` bypass, FR-022: Go's `ExactMatcher` alone is
    /// sufficient — the bypass's own inversion test lives in `deps-go` as part of T005/SC-020,
    /// since `deps-cli` does not depend on `deps-go`).
    #[test]
    fn test_fallback_edit_excludes_newer_rejects_a1_repro_downgrade() {
        let dep = test_dep(
            "pkg",
            ">=3.0.0",
            Range::new(Position::new(0, 0), Position::new(0, 5)),
        );
        let edit = ManifestEdit {
            range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            new_text: "2.9.0".to_string(),
        };

        // A1 repro: `latest` (3.2.0) already satisfies `>=3.0.0`, so falling back to the older
        // 2.9.0 would be a downgrade relative to what re-resolution already gives — reject at
        // d0, before any re-parse (`never_reparse` must never be consulted).
        let available_with_newer_match: Vec<deps_core::ConcreteVersion> =
            vec!["3.2.0".into(), "2.9.0".into()];
        assert_eq!(
            deps_core::lsp_helpers::fallback_edit_excludes_newer(
                &RealSemverFormatter,
                &never_reparse,
                "pkg = \">=3.0.0\"\n",
                &dep,
                &edit,
                &deps_core::ConcreteVersion::new("2.9.0"),
                &available_with_newer_match,
            ),
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::OriginalResolvesPastFallback
            ),
            "2.9.0 is a downgrade relative to what >=3.0.0 already resolves to (3.2.0) and must \
             never be treated as a usable fallback"
        );
    }

    /// Issue #1564, adapted to spec 076's two-phase guard — and DELIBERATELY corrected, not
    /// carried over verbatim, from #1565's own single-phase `Applied`/`Writable` expectation.
    /// R0 (unedited, "0.22.6", implicit caret) already resolves past the fallback (0.22.7) just
    /// as freely as it resolves past the cooldown-blocked `latest` (0.22.8) — #1565's
    /// floor-comparison fix (d0 here) correctly does NOT reject this alone, since the
    /// requirement's own floor (0.22.6) is not newer than the fallback. But spec 076 adds a
    /// SECOND phase (d1) #1565 never had: the WRITTEN edit ("0.22.7", also an implicit caret)
    /// auto-follows forward into the fresh 0.22.8, which is exactly spec 076's S1 anti-
    /// auto-follow protection this guard exists to add. So unlike #1565's own repro, this must
    /// resolve `Rejected(EditedAdmitsNewer)`, not `Writable` — d0 passing does not mean the edit
    /// is safe to write once the two-phase guard also checks what the WRITTEN text re-admits.
    #[test]
    fn test_fallback_edit_excludes_newer_rejects_auto_follow_after_d0_passes_1564() {
        let dep = test_dep(
            "pkg",
            "0.22.6",
            Range::new(Position::new(0, 7), Position::new(0, 13)),
        );
        let edit = ManifestEdit {
            range: Range::new(Position::new(0, 7), Position::new(0, 13)),
            new_text: "0.22.7".to_string(),
        };
        let available: Vec<deps_core::ConcreteVersion> =
            vec!["0.22.8".into(), "0.22.7".into(), "0.22.6".into()];
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let verdict = deps_core::lsp_helpers::fallback_edit_excludes_newer(
            &RealSemverFormatter,
            &reparse,
            "pkg = \"0.22.6\"\n",
            &dep,
            &edit,
            &deps_core::ConcreteVersion::new("0.22.7"),
            &available,
        );
        assert_eq!(
            verdict,
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::EditedAdmitsNewer
            ),
            "d0 passes (0.22.6's own floor is not newer than 0.22.7), but the written 0.22.7 \
             caret still auto-follows into the fresh 0.22.8 — d1 must reject: {verdict:?}"
        );
    }

    /// Issue #1561 repro (CWE-1284), adapted: the declared exact pin (`=1.5.0`) is absent from
    /// `available` (unpublished/yanked/filtered) — the requirement's own floor (d0) cannot be
    /// evidenced by any listed entry, so this must fail closed rather than vacuously accept the
    /// fallback (1.4.0, strictly older than the declared pin).
    #[test]
    fn test_fallback_edit_excludes_newer_fails_closed_on_unlisted_pin_1561() {
        let dep = test_dep(
            "pkg",
            "=1.5.0",
            Range::new(Position::new(0, 7), Position::new(0, 14)),
        );
        let edit = ManifestEdit {
            range: Range::new(Position::new(0, 7), Position::new(0, 14)),
            new_text: "1.4.0".to_string(),
        };
        // 1.5.0 (the declared pin) is not listed — unpublished/yanked/filtered.
        let available: Vec<deps_core::ConcreteVersion> =
            vec!["2.0.0".into(), "1.4.0".into(), "1.0.0".into()];

        let verdict = deps_core::lsp_helpers::fallback_edit_excludes_newer(
            &RealSemverFormatter,
            &never_reparse,
            "pkg = \"=1.5.0\"\n",
            &dep,
            &edit,
            &deps_core::ConcreteVersion::new("1.4.0"),
            &available,
        );
        assert_eq!(
            verdict,
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::OriginalResolvesPastFallback
            ),
            "the declared pin 1.5.0 is unlisted; nothing evidences that 1.4.0 is not a \
             downgrade below it, so this must fail closed: {verdict:?}"
        );
    }

    /// Issue #1561, second cause: the FALLBACK itself is absent from `available` (a stale
    /// `CooldownFallback` computed against a version list that has since changed) — distinct
    /// from the declared-pin-unlisted case above, which is why `fallback_edit_excludes_newer`
    /// reports it as its own `FallbackUnlisted` variant.
    #[test]
    fn test_fallback_edit_excludes_newer_fails_closed_on_unlisted_fallback() {
        let dep = test_dep(
            "pkg",
            "0.22.6",
            Range::new(Position::new(0, 7), Position::new(0, 13)),
        );
        let edit = ManifestEdit {
            range: Range::new(Position::new(0, 7), Position::new(0, 13)),
            new_text: "0.22.7".to_string(),
        };
        // 0.22.7 (the fallback) is not listed at all.
        let available: Vec<deps_core::ConcreteVersion> = vec!["0.22.8".into(), "0.22.6".into()];

        let verdict = deps_core::lsp_helpers::fallback_edit_excludes_newer(
            &RealSemverFormatter,
            &never_reparse,
            "pkg = \"0.22.6\"\n",
            &dep,
            &edit,
            &deps_core::ConcreteVersion::new("0.22.7"),
            &available,
        );
        assert_eq!(
            verdict,
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::FallbackUnlisted
            ),
            "got: {verdict:?}"
        );
    }

    /// One dependency, cooldown-blocked by the local heuristic, with a stored fallback
    /// candidate — shared setup for the SC-005/SC-006 fallback-selection tests below.
    ///
    /// Spec 076: the declared requirement is an exact pin (`=1.0.0`) and `latest` is a MAJOR
    /// version bump (`2.0.0`) — outside the caret range a bare-rendered fallback edit (e.g.
    /// `"1.1.0"` compiling to `^1.1.0`) would admit, so the two-phase guard's phase 1/2 checks
    /// pass for any test using this fixture that actually reaches `fallback_edit_excludes_newer`
    /// (most of the tests below do not: their fallback view's own OSV/structural rejection, or
    /// the ignore-rule short-circuit inside `never_demoted`, resolves the occurrence before the
    /// guard is ever consulted — see each test's own doc for which case it is).
    fn fallback_scenario_analysis(
        fallback_version: &str,
    ) -> (
        ManifestAnalysis,
        deps_core::FreshnessSettings,
        deps_core::PublishTime,
    ) {
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_900); // 100s old, within cooldown
        let mut versions = cached("pkg", "2.0.0");
        versions.insert(
            PackageName::new("pkg"),
            // `available` must list both the exact-pin R0's own floor ("1.0.0") and the
            // fallback candidate itself, or `fallback_edit_excludes_newer`'s fail-closed
            // `FallbackUnlisted`/floor checks reject before ever reaching a test's own
            // scenario under test — `latest_only`'s single-element `[latest]` list isn't
            // enough once that guard's two-phase, position-based checks are in play.
            PackageVersions::new(
                deps_core::ConcreteVersion::new("2.0.0"),
                std::sync::Arc::from(vec![
                    deps_core::ConcreteVersion::new("2.0.0"),
                    deps_core::ConcreteVersion::new("1.1.0"),
                    deps_core::ConcreteVersion::new("1.0.0"),
                ]),
            )
            .with_published_at(published_at)
            .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                fallback_version.into(),
                deps_core::PublishTime::from_unix_secs(1_000),
            )),
        );
        let analysis = test_analysis(
            vec![test_dep(
                "pkg",
                "=1.0.0",
                // 6-char span ("=1.0.0"), matching the exact-pin requirement text — a test using
                // this fixture's fallback view as `Planned` (not short-circuited by its own OSV
                // status) needs `content`'s literal span to match, or `collect_update_candidates`
                // marks it `Unplannable(NonLiteralSpan)` before the guard is ever reached.
                Range::new(Position::new(0, 7), Position::new(0, 13)),
            )],
            versions,
        );
        let freshness = deps_core::FreshnessSettings::Enabled {
            cooldown: deps_core::CooldownWindow::from_secs(1_000),
        };
        (analysis, freshness, now)
    }

    /// Like [`fallback_scenario_analysis`], but with a caller-controlled declared requirement
    /// and full `available` list — needed to exercise [`RealSemverFormatter`]'s real
    /// `compile_bounded_requirement` guard (fix-cycle item 1/S1, tester Gap C) end to end through
    /// [`plan_updates`]/[`resolve_occurrence`], not just the isolated helper.
    fn real_semver_scenario(
        req: &str,
        available: &[&str],
        fallback_version: &str,
    ) -> (
        ManifestAnalysis,
        deps_core::FreshnessSettings,
        deps_core::PublishTime,
    ) {
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_900); // 100s old, within cooldown
        let latest = available.first().copied().expect("at least one version");
        let available_arc: std::sync::Arc<[deps_core::ConcreteVersion]> =
            available.iter().map(|v| (*v).into()).collect();
        let mut versions = HashMap::new();
        versions.insert(
            PackageName::new("pkg"),
            PackageVersions::new(latest.into(), available_arc)
                .with_published_at(published_at)
                .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                    fallback_version.into(),
                    deps_core::PublishTime::from_unix_secs(1_000),
                )),
        );
        let end = 7 + u32::try_from(req.len()).expect("short test literal");
        let analysis = test_analysis(
            vec![test_dep(
                "pkg",
                req,
                Range::new(Position::new(0, 7), Position::new(0, end)),
            )],
            versions,
        );
        let freshness = deps_core::FreshnessSettings::Enabled {
            cooldown: deps_core::CooldownWindow::from_secs(1_000),
        };
        (analysis, freshness, now)
    }

    /// Spec 076 T006/FR-027 (verification candidate named by spec §10/tasks.md): under spec
    /// 075's guard this asserted `Applied`, because that guard only ever compiled the declared
    /// `=1.0.0` text itself, never the WRITTEN edit. Spec 076's two-phase guard re-parses the
    /// actual edit: `RealSemverFormatter`'s default rendering writes the fallback BARE
    /// (`"1.1.0"`), which Cargo-like semver compiles as a caret range `^1.1.0` — and that range
    /// still admits the fresh `1.2.0` it exists to exclude. d1 (`EditedAdmitsNewer`) now
    /// correctly rejects it — the documented, out-of-scope common-case fail-closed outcome for
    /// an auto-following ecosystem (spec 076 §1), not a regression. `1.0.0` (the exact pin's
    /// own value) must be listed for d0's fix-cycle floor-comparison scan to find it and let
    /// phase 1 pass, so this test actually reaches d1.
    #[test]
    fn test_plan_updates_real_semver_formatter_rejects_in_range_caret_admission() {
        let content = "pkg = \"=1.0.0\"\n";
        let (analysis, freshness, now) =
            real_semver_scenario("=1.0.0", &["1.2.0", "1.1.0", "1.0.0"], "1.1.0");
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );

        // Fix-cycle M3 (impl-critic): `Skipped(WithinFreshnessCooldown)` alone doesn't
        // distinguish `EditedAdmitsNewer` from `ReparseFailed`/`OccurrenceNotUnique` — pin the
        // exact rejection variant directly.
        let dep = test_dep(
            "pkg",
            "=1.0.0",
            Range::new(Position::new(0, 7), Position::new(0, 13)),
        );
        let candidate = ManifestEdit {
            range: Range::new(Position::new(0, 7), Position::new(0, 13)),
            new_text: "1.1.0".to_string(),
        };
        let verdict = deps_core::lsp_helpers::fallback_edit_excludes_newer(
            &RealSemverFormatter,
            &reparse,
            content,
            &dep,
            &candidate,
            &deps_core::ConcreteVersion::new("1.1.0"),
            &[
                deps_core::ConcreteVersion::new("1.2.0"),
                deps_core::ConcreteVersion::new("1.1.0"),
                deps_core::ConcreteVersion::new("1.0.0"),
            ],
        );
        assert_eq!(
            verdict,
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::EditedAdmitsNewer
            )
        );
    }

    /// Spec 075 SC-004/FR-003 (A1 repro), end to end (tester Gap C): `resolve_occurrence`'s own
    /// `dep`/`req`/`fb.target` extraction (not just the isolated `fallback_satisfies_requirement`
    /// helper) must reject a fallback that is a downgrade relative to a real `>=3.0.0`
    /// requirement `latest` (3.2.0) already resolves past.
    #[test]
    fn test_plan_updates_real_semver_formatter_rejects_a1_repro_end_to_end() {
        let content = "pkg = \">=3.0.0\"\n";
        let (analysis, freshness, now) =
            real_semver_scenario(">=3.0.0", &["3.2.0", "2.9.0"], "2.9.0");

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert!(plan.items[0].cooldown_fallback.is_none());
    }

    /// Issue #1564, end to end (crates.io `bevy_brp_mcp`-shaped repro), corrected per T006/S1
    /// for spec 076: a three-version, live-registry-shaped fixture — `0.22.8` (newest,
    /// cooldown-blocked, would be `latest`), `0.22.7` (cleared, the stored fallback), `0.22.6`
    /// (declared/locked) — under a bare (implicit-caret) Cargo-style requirement.
    ///
    /// #1565 (shipped, spec-075-only scope) fixed d0 (the check against the UNEDITED
    /// requirement) to stop over-rejecting this shape and expected `Applied(0.22.7)`. Spec
    /// 076's independent, ADDITIONAL d1 check (against the WRITTEN edit, which #1565 never had
    /// since spec 075 had no re-parse mechanism at all) still correctly rejects it: writing the
    /// fallback bare renders `^0.22.7`, which — exactly like `^0.22.6` — still admits the
    /// fresh, cooldown-blocked `0.22.8`. This is spec 076 §1's documented, user-decided
    /// (OQ-C) common-case fail-closed outcome for an auto-following ecosystem, not a
    /// regression of #1565 — see this fix cycle's handoff for the full architectural note.
    #[test]
    fn test_plan_updates_real_semver_formatter_rejects_permissive_range_1564() {
        let content = "pkg = \"0.22.6\"\n";
        let (analysis, freshness, now) =
            real_semver_scenario("0.22.6", &["0.22.8", "0.22.7", "0.22.6"], "0.22.7");
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert!(plan.items[0].cooldown_fallback.is_none());
    }

    /// Issue #1561, end to end (CWE-1284): the declared exact pin (`=1.5.0`) is absent from the
    /// registry's version list (unpublished/yanked/filtered) and the fallback (`1.4.0`) is
    /// strictly older than it — must never be applied, regardless of how the fallback view
    /// itself classifies the occurrence. Rejected at d0 (`OriginalResolvesPastFallback`),
    /// before re-parse is ever consulted.
    #[test]
    fn test_plan_updates_fails_closed_on_unlisted_pin_downgrade_1561() {
        let content = "pkg = \"=1.5.0\"\n";
        let (analysis, freshness, now) =
            real_semver_scenario("=1.5.0", &["2.0.0", "1.4.0", "1.0.0"], "1.4.0");

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "1.4.0 is a downgrade below the unlisted declared pin 1.5.0 and must never be \
             applied: {:?}",
            plan.items[0]
        );
        assert_eq!(
            plan.items[0].target(),
            Some(&ConcreteVersion::from("2.0.0")),
            "the rejected fallback must never leak into the reported target either"
        );
        assert!(plan.items[0].cooldown_fallback.is_none());
    }

    /// Spec 075 SC-005/FR-012 (OQ3): a flagged latest with an independently Verified fallback
    /// candidate resolves to `Applied(fallback)`, keeping the flagged-latest attribution
    /// (advisory ids) in the same row.
    ///
    /// Issue #1561 item 1: `fallback_status` is populated alongside `latest_status` here (both,
    /// not just one) — a bare `None` for `fallback_status` while `latest_status` is `Some` now
    /// fails the fallback candidate closed to `Unverified` rather than silently bypassing OSV
    /// verification, so a test genuinely claiming an "independently Verified" fallback must set
    /// up that verification explicitly.
    #[test]
    fn test_plan_updates_flagged_latest_with_verified_fallback_applies_fallback() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("2.0.0"),
                advisory_ids: Capped::new(vec!["GHSA-xxxx".to_string()], 1),
                worst_severity: Some(VulnSeverity::High),
            },
        );
        analysis.latest_status = Some(latest_status);
        // Issue #1561 item 1: `latest_status` is populated, so `fallback_status` must be too —
        // a bare `None` now fails the fallback closed to `Unverified` (defense-in-depth).
        let mut fallback_status = LatestStatusMap::new();
        fallback_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("1.1.0"),
            },
        );
        analysis.fallback_status = Some(fallback_status);
        // Spec 076: reaching `Applied` needs a real `compile_bounded_requirement` (the Go-bypass
        // `FALLBACK_FORMATTER` no longer short-circuits the guard, FR-022) and a working
        // re-parse (FR-024).
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(plan.items[0].outcome, Outcome::Applied { .. }),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            plan.items[0].target(),
            Some(&ConcreteVersion::from("1.1.0"))
        );
        assert!(
            !plan.items[0].advisory_ids.is_empty(),
            "the flagged-latest attribution must be retained: {:?}",
            plan.items[0]
        );
        assert_eq!(
            plan.items[0].cooldown_fallback,
            Some(CooldownFallbackNote::AppliedInsteadOf("2.0.0".into()))
        );
    }

    /// Issue #1561 item 1: `latest_status` is populated (OSV verification is in effect for
    /// this run) but `fallback_status` was never set — a caller bug distinct from an
    /// intentionally offline/no-OSV run. The fallback candidate must fail closed to
    /// `Unverified` (never written) rather than silently bypassing OSV verification as
    /// `NotApplicable` ("no check needed") the way a bare `None` for BOTH fields does.
    #[test]
    fn test_plan_updates_latest_status_without_fallback_status_treats_fallback_as_unverified() {
        use deps_core::osv::{LatestStatusMap, UpgradeStatus};

        let content = "pkg = \"1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("1.2.0"),
            },
        );
        analysis.latest_status = Some(latest_status);
        // `analysis.fallback_status` deliberately left `None`.

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestUnverified
                    ),
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
    }

    /// Issue #1561 item 2: `resolve_occurrence`'s `fb.target != fallback.version` guard
    /// (update/mod.rs's `'occurrence` block). Simulates the divergence it defends against — a
    /// stale/inconsistent precomputed `analysis.cooldown_fallback_view` (`latest` = `1.9.0`)
    /// disagreeing with `cached_versions`' own stored `CooldownFallback` (`1.1.0`) that
    /// `cooldown_disposition` independently picks inside `resolve_occurrence` — and confirms
    /// the divergence falls through to the same fail-closed handling as "fallback absent",
    /// never silently writing either version.
    #[test]
    fn test_plan_updates_fb_target_fallback_version_divergence_fails_closed() {
        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");

        let mut divergent_view = HashMap::new();
        divergent_view.insert(
            PackageName::new("pkg"),
            PackageVersions::latest_only("1.9.0"),
        );
        analysis.cooldown_fallback_view = Some(divergent_view);

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "a divergence between the fallback view's own planned target (1.9.0) and \
             `cooldown_disposition`'s independently computed pick (1.1.0) must never be \
             silently written: {:?}",
            plan.items[0]
        );
        assert_eq!(
            plan.items[0].target(),
            Some(&ConcreteVersion::from("2.0.0")),
            "must fall back to the real (unmodified) latest, never either divergent fallback \
             value"
        );
        assert!(plan.items[0].cooldown_fallback.is_none());
    }

    /// Spec 075 SC-006/FR-011 (OQ5'): the fallback candidate is itself OSV-`Flagged` — exit 1,
    /// naming the blocked fallback version, never a silent cooldown skip.
    #[test]
    fn test_plan_updates_flagged_fallback_blocks_and_exits_nonzero() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let mut fallback_status = LatestStatusMap::new();
        fallback_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.1.0"),
                advisory_ids: Capped::new(vec!["GHSA-yyyy".to_string()], 1),
                worst_severity: Some(VulnSeverity::High),
            },
        );
        analysis.fallback_status = Some(fallback_status);

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestFlaggedByOsv
                    ),
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            plan.items[0].target(),
            Some(&ConcreteVersion::from("1.1.0")),
            "must name the blocked fallback version, not latest"
        );
        assert!(!plan.items[0].advisory_ids.is_empty());
        assert_eq!(
            plan.items[0].cooldown_fallback,
            Some(CooldownFallbackNote::Blocked {
                version: "1.1.0".into()
            })
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION
        );
    }

    /// Spec 075 SC-006/FR-011 (OQ5'): the fallback candidate is `Unverified` (never checked) —
    /// exit 1 for parity with the `Flagged` case, not a silent exit-0 skip.
    #[test]
    fn test_plan_updates_unverified_fallback_blocks_and_exits_nonzero() {
        use deps_core::osv::LatestStatusMap;

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        // Present but empty: OSV checking is on, but this fallback was never verified.
        analysis.fallback_status = Some(LatestStatusMap::new());

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestUnverified
                    ),
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            plan.items[0].target(),
            Some(&ConcreteVersion::from("1.1.0"))
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION
        );
    }

    /// Tester Gap A / decision-table row 8: both `latest` AND the fallback are OSV-blocked
    /// simultaneously — defers entirely to `latest`'s own attribution (via `resolve_from_latest`),
    /// exit 1, never demoted, regardless of why the fallback also failed.
    #[test]
    fn test_plan_updates_both_latest_and_fallback_osv_blocked_defers_to_latest() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let flagged = |version: &str| {
            let mut status = LatestStatusMap::new();
            status.insert(
                deps_core::test_util::vuln_key("pkg"),
                UpgradeStatus::CandidateVulnerable {
                    version: deps_core::ConcreteVersion::new(version),
                    advisory_ids: Capped::new(vec!["GHSA-x".to_string()], 1),
                    worst_severity: Some(VulnSeverity::High),
                },
            );
            status
        };
        analysis.latest_status = Some(flagged("2.0.0"));
        analysis.fallback_status = Some(flagged("1.1.0"));

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::NotSafelyEditable(
                        deps_core::edit::UnplannableReason::LatestFlaggedByOsv
                    ),
                    ..
                }
            ),
            "got: {:?}",
            plan.items[0].outcome
        );
        assert!(
            plan.items[0].cooldown_fallback.is_none(),
            "row 8 defers entirely to latest's own attribution, no fallback note"
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_POLICY_VIOLATION
        );
    }

    /// Tester Gap B / decision-table row 11: the fallback is blocked by a non-OSV structural
    /// reason (an unsafe version string) — a routine cooldown skip, exit clean, never
    /// `NotSafelyEditable`.
    #[test]
    fn test_plan_updates_fallback_blocked_by_non_osv_reason_is_cooldown_skip() {
        let content = "pkg = \"=1.0.0\"\n";
        // A space is outside `is_safe_version_string`'s allowlist, so the fallback view
        // resolves this occurrence to `Unplannable(UnsafeLatestVersion)`.
        let (analysis, freshness, now) = fallback_scenario_analysis("1.1.0 unsafe");

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "a fallback blocked by a non-OSV structural reason is a routine cooldown skip, not \
             an exit-1 safety refusal: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN
        );
    }

    /// Fix-cycle item 3/S3 (impl-critic repro E): row 7 (a flagged latest with a clean
    /// fallback) must still honor `[update].ignore` — previously it wrote `Applied(fb.edit)`
    /// unconditionally, bypassing the rule the identical row-9 case already respected.
    ///
    /// Fix-cycle S1 (impl-critic, significant): this MUST reach `requirement_ok = true` (the
    /// guard's `Writable` verdict) so the ignore-rule check inside that branch is the thing
    /// actually under test — `RealSemverFormatter` + a working `reparse_quoted_deps` and a
    /// `content` literal matching the exact-pin requirement text are required for that; using
    /// `FALLBACK_FORMATTER`/`never_reparse` (a0-uncompilable) made this test pass through
    /// `never_demoted`'s OWN, unrelated ignore-rule check instead, leaving the actual row-7
    /// branch with zero coverage (proven by mutation: removing the ignore-rule check inside
    /// `requirement_ok` still passed 318/318 deps-cli tests before this fix).
    #[tokio::test]
    async fn test_plan_updates_row7_honors_ignore_rule_instead_of_applying() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("2.0.0"),
                advisory_ids: Capped::new(vec!["GHSA-x".to_string()], 1),
                worst_severity: Some(VulnSeverity::High),
            },
        );
        analysis.latest_status = Some(latest_status);
        let ignore_pkg = IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "pkg".to_string(),
                update_types: None,
            }],
            &RealSemverFormatter,
        );
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &ignore_pkg,
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::IgnoreRule,
                    ..
                }
            ),
            "an ignored package's row-7 fallback must not be applied: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN
        );
    }

    /// Fix-cycle S1 follow-up (row-9 counterpart, impl-critic recommendation): the identical
    /// ignore-rule check inside `requirement_ok`, but for an UNFLAGGED latest (row 9's ordinary
    /// cooldown-fallback substitution, not row 7's flagged-latest variant) — proves the
    /// ignore-rule branch is covered regardless of which row reaches it.
    #[tokio::test]
    async fn test_plan_updates_row9_honors_ignore_rule_instead_of_applying() {
        let content = "pkg = \"=1.0.0\"\n";
        let (analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let ignore_pkg = IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "pkg".to_string(),
                update_types: None,
            }],
            &RealSemverFormatter,
        );
        let reparse = reparse_quoted_deps(vec![("pkg", Position::new(0, 7))]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &ignore_pkg,
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::IgnoreRule,
                    ..
                }
            ),
            "an ignored package's row-9 fallback must not be applied: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN
        );
    }

    /// Fix-cycle item 4/S4 (impl-critic repro F): row 10 (an OSV-blocked fallback) must still
    /// honor `[update].ignore` — previously an ignored package's blocked fallback exited 1
    /// regardless of the rule, unlike row 8's identical `resolve_from_latest` handling.
    #[test]
    fn test_plan_updates_row10_honors_ignore_rule_instead_of_exiting_nonzero() {
        use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let content = "pkg = \"=1.0.0\"\n";
        let (mut analysis, freshness, now) = fallback_scenario_analysis("1.1.0");
        let mut fallback_status = LatestStatusMap::new();
        fallback_status.insert(
            deps_core::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.1.0"),
                advisory_ids: Capped::new(vec!["GHSA-x".to_string()], 1),
                worst_severity: Some(VulnSeverity::High),
            },
        );
        analysis.fallback_status = Some(fallback_status);
        let ignore_pkg = IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "pkg".to_string(),
                update_types: None,
            }],
            &FALLBACK_FORMATTER,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &ignore_pkg,
            freshness,
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::IgnoreRule,
                    ..
                }
            ),
            "an ignored package's row-10 blocked fallback must exit clean, not policy-violation: {:?}",
            plan.items[0].outcome
        );
        assert_eq!(
            plan.items[0].target(),
            None,
            "the ignore-rule skip of an OSV-blocked fallback has no concrete target"
        );
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN
        );
    }

    /// Fix-cycle item 5/security M1: the GOSSIP lookup in `resolve_occurrence` must use the
    /// RAW package name — `analysis.gossip_findings` (from `fetch_gossip_findings_batch`) is
    /// keyed by the raw name, matching `diagnostics::apply_outdated_rule`/hover. Using the
    /// *normalized* name instead made the planner blind to GOSSIP data for any formatter whose
    /// normalization changes case, reopening the check/update divergence #1529 closed.
    #[test]
    fn test_plan_updates_gossip_lookup_uses_raw_name_not_normalized() {
        let lowercase_formatter: deps_core::test_util::StubFormatter =
            deps_core::test_util::StubFormatter::new().with_lowercase_names();
        let content = "Django = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        // Well outside any realistic local cooldown window — if the GOSSIP-Active verdict is
        // missed (the bug), this dependency falls through to the local heuristic and clears.
        let old_published_at = deps_core::PublishTime::from_unix_secs(10_000 - 30 * 24 * 60 * 60);
        let mut versions = HashMap::new();
        versions.insert(
            PackageName::new("Django"),
            PackageVersions::latest_only("2.0.0").with_published_at(old_published_at),
        );
        let mut analysis = test_analysis(
            vec![test_dep(
                "Django",
                "1.0.0",
                Range::new(Position::new(0, 10), Position::new(0, 15)),
            )],
            versions,
        );
        let mut gossip = HashMap::new();
        gossip.insert(
            PackageName::new("Django"), // raw name — must NOT be looked up as "django"
            deps_core::test_util::stub_gossip_findings(
                "2.0.0",
                Some(deps_core::GossipCooldown::new(
                    deps_core::PublishTime::from_unix_secs(10_000 + 1_000),
                    deps_core::GossipRiskLevel::High,
                )),
            ),
        );
        analysis.gossip_findings = gossip;

        let plan = plan_updates(
            &analysis,
            content,
            &lowercase_formatter,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(1_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 1, "{:?}", plan.items);
        assert!(
            matches!(
                plan.items[0].outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    ..
                }
            ),
            "the GOSSIP-Active cooldown for the raw name 'Django' must be detected even though \
             normalize_package_name lowercases it to 'django': {:?}",
            plan.items[0].outcome
        );
    }

    /// Code review (M2 minor, strengthened `OccurrenceKey`): two different packages whose
    /// `name_range` collides (`TestDep::name_range` always returns `Range::default()`, modeling
    /// Gradle/Composer's degraded-parsing paths) must never swap fallback edits or requirement
    /// checks — each occurrence's distinct `version_range` disambiguates them.
    #[test]
    fn test_plan_updates_name_range_collision_does_not_swap_occurrences() {
        let content = "alpha = \"=1.0.0\"\nbeta = \"=9.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_900); // within cooldown

        // Spec 076: exact pins, with `latest` a major-version bump OUTSIDE the caret range a
        // bare-rendered fallback edit compiles to (`^1.1.0` excludes `2.0.0`; `^9.1.0` excludes
        // `10.0.0`) — otherwise the two-phase guard's d1 check would correctly fail closed
        // (spec 076 §1's documented auto-following-ecosystem case), which is not what this
        // test's own point (no cross-occurrence swap) is about.
        let mut versions = HashMap::new();
        versions.insert(
            PackageName::new("alpha"),
            // `available` must list both the exact-pin R0's own floor ("1.0.0") and the
            // fallback itself ("1.1.0"), or the guard's fail-closed `FallbackUnlisted`/floor
            // checks reject before this test's own cross-occurrence scenario is exercised.
            PackageVersions::new(
                deps_core::ConcreteVersion::new("2.0.0"),
                std::sync::Arc::from(vec![
                    deps_core::ConcreteVersion::new("2.0.0"),
                    deps_core::ConcreteVersion::new("1.1.0"),
                    deps_core::ConcreteVersion::new("1.0.0"),
                ]),
            )
            .with_published_at(published_at)
            .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                "1.1.0".into(),
                deps_core::PublishTime::from_unix_secs(1_000),
            )),
        );
        versions.insert(
            PackageName::new("beta"),
            PackageVersions::new(
                deps_core::ConcreteVersion::new("10.0.0"),
                std::sync::Arc::from(vec![
                    deps_core::ConcreteVersion::new("10.0.0"),
                    deps_core::ConcreteVersion::new("9.1.0"),
                    deps_core::ConcreteVersion::new("9.0.0"),
                ]),
            )
            .with_published_at(published_at)
            .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                "9.1.0".into(),
                deps_core::PublishTime::from_unix_secs(1_000),
            )),
        );

        let analysis = test_analysis(
            vec![
                test_dep(
                    "alpha",
                    "=1.0.0",
                    Range::new(Position::new(0, 9), Position::new(0, 15)),
                ),
                test_dep(
                    "beta",
                    "=9.0.0",
                    Range::new(Position::new(1, 8), Position::new(1, 14)),
                ),
            ],
            versions,
        );
        let reparse = reparse_quoted_deps(vec![
            ("alpha", Position::new(0, 9)),
            ("beta", Position::new(1, 8)),
        ]);

        let plan = plan_updates(
            &analysis,
            content,
            &RealSemverFormatter,
            &reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(1_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 2, "{:?}", plan.items);
        let alpha = plan
            .items
            .iter()
            .find(|i| i.name == "alpha")
            .expect("alpha item present");
        let beta = plan
            .items
            .iter()
            .find(|i| i.name == "beta")
            .expect("beta item present");
        assert_eq!(
            alpha.target(),
            Some(&ConcreteVersion::from("1.1.0")),
            "alpha must get its own fallback, not beta's: {alpha:?}"
        );
        assert_eq!(
            beta.target(),
            Some(&ConcreteVersion::from("9.1.0")),
            "beta must get its own fallback, not alpha's: {beta:?}"
        );
        assert!(matches!(alpha.outcome, Outcome::Applied { .. }));
        assert!(matches!(beta.outcome, Outcome::Applied { .. }));
    }

    /// Code review (severity upgrade over the earlier "attribution only, never a wrong write"
    /// signoff): the SAME package declared twice, both occurrences degrading to the identical
    /// `name_range` (`TestDep::name_range` always returns `Range::default()`, modeling
    /// Gradle/Composer's degraded-position parsing) but with distinct `version_range`s, is a
    /// genuine collision the planner cannot disambiguate from `UpdateCandidate` alone. Proves the
    /// fail-closed fix: neither occurrence's FR-003 downgrade guard runs against the other's
    /// declared requirement, and neither gets a swapped/incorrect fallback write — both
    /// conservatively skip as `WithinFreshnessCooldown` with their own unmodified `latest`.
    #[test]
    fn test_plan_updates_true_name_range_collision_fails_closed_on_both_occurrences() {
        let content = "pkg = \"1.0.0\"\npkg = \"5.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_900); // within cooldown

        let mut versions = HashMap::new();
        versions.insert(
            PackageName::new("pkg"),
            PackageVersions::latest_only("1.2.0")
                .with_published_at(published_at)
                .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                    "1.1.0".into(),
                    deps_core::PublishTime::from_unix_secs(1_000),
                )),
        );

        let analysis = test_analysis(
            vec![
                test_dep(
                    "pkg",
                    "1.0.0",
                    Range::new(Position::new(0, 7), Position::new(0, 12)),
                ),
                test_dep(
                    "pkg",
                    "5.0.0",
                    Range::new(Position::new(1, 7), Position::new(1, 12)),
                ),
            ],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(1_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 2, "{:?}", plan.items);
        for item in &plan.items {
            assert!(
                matches!(
                    item.outcome,
                    Outcome::Skipped {
                        reason: SkipReason::WithinFreshnessCooldown,
                        ..
                    }
                ),
                "an unresolvable collision must fail closed, never approve a downgrade or a \
                 swapped write: {item:?}"
            );
            assert_eq!(
                item.target(),
                Some(&ConcreteVersion::from("1.2.0")),
                "target must stay the real (unmodified) latest, never a fallback picked via a \
                 collided lookup: {item:?}"
            );
        }
    }

    /// Team-lead/impl-critic follow-up: `fallback_by_key` used to build its map the same
    /// "collapse-then-key" way `dep_by_key` did, so on a collision `.collect()` kept only the
    /// last occurrence's fallback candidate — the other occurrence could then be resolved
    /// against a stolen `UpdateCandidate` in the `Unplannable` branch (rows 8/10/11), a
    /// mismatched `SkipReason`/attribution even though (per impl-critic's trace) it never
    /// produced a wrong write. `pkg`'s two occurrences collide on `(name, name_range)`: one has
    /// a perfectly valid, independently-Applicable fallback; the other's fallback is
    /// structurally broken (`NonLiteralSpan`, its declared requirement doesn't match the
    /// manifest text at its own span). Excluding collision keys from `fallback_by_key` (mirroring
    /// `dep_by_key`) means NEITHER occurrence gets a fallback candidate at all — both fail closed
    /// through the "fallback absent" (row 6) branch uniformly, never `Applied`, never a nonzero
    /// exit, and never one silently wearing the other's specific `UnplannableReason`.
    #[test]
    fn test_plan_updates_mixed_planned_unplannable_collision_fails_closed_uniformly() {
        let content = "pkg = \"1.0.0\"\npkg = \"1.0.0\"\n";
        let now = deps_core::PublishTime::from_unix_secs(10_000);
        let published_at = deps_core::PublishTime::from_unix_secs(9_900); // within cooldown

        let mut versions = HashMap::new();
        versions.insert(
            PackageName::new("pkg"),
            PackageVersions::latest_only("1.2.0")
                .with_published_at(published_at)
                .with_cooldown_fallback(deps_core::lsp_helpers::CooldownFallback::new(
                    "1.1.0".into(),
                    deps_core::PublishTime::from_unix_secs(1_000),
                )),
        );

        let analysis = test_analysis(
            vec![
                // occ1: requirement matches the manifest text — a genuinely valid,
                // independently-Applicable fallback candidate in isolation.
                test_dep(
                    "pkg",
                    "1.0.0",
                    Range::new(Position::new(0, 7), Position::new(0, 12)),
                ),
                // occ2: declared requirement ("9.9.9") does not match the manifest text
                // ("1.0.0") at its own span — always `Unplannable(NonLiteralSpan)`,
                // independent of which registry view (latest/fallback) classifies it.
                test_dep(
                    "pkg",
                    "9.9.9",
                    Range::new(Position::new(1, 7), Position::new(1, 12)),
                ),
            ],
            versions,
        );

        let plan = plan_updates(
            &analysis,
            content,
            &FALLBACK_FORMATTER,
            &never_reparse,
            &[],
            &IgnoreRules::empty(),
            deps_core::FreshnessSettings::Enabled {
                cooldown: deps_core::CooldownWindow::from_secs(1_000),
            },
            now,
        );

        assert_eq!(plan.items.len(), 2, "{:?}", plan.items);
        for item in &plan.items {
            assert!(
                matches!(
                    item.outcome,
                    Outcome::Skipped {
                        reason: SkipReason::WithinFreshnessCooldown,
                        ..
                    }
                ),
                "a collision must fail closed uniformly for both occurrences, never `Applied` \
                 and never attributing one occurrence's structural defect to the other: {item:?}"
            );
        }
        assert_eq!(
            crate::exit::update_exit_code(&plan),
            crate::exit::EXIT_CLEAN
        );
    }
}
