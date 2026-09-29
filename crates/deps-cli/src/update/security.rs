//! `--security-only` planner: phase-B OSV re-verification, `recommended_fix()` targeting, the
//! native-form yank filter, and the three-outcome classification (#1120, spec 068 FR-008
//! through FR-015).

use std::time::Duration;

use deps_core::Ecosystem;
use deps_core::edit::{VulnFixSkip, plan_verified_fix, resolve_verified_fix};
use deps_core::lsp_helpers::{RequirementGate, resolve_in_use_version, resolve_scan_outcome};
use deps_core::osv::{OsvClient, ScanOutcome};

use crate::analyze::ManifestAnalysis;
use crate::update::ignore::IgnoreRules;
use crate::update::{
    CurrentVersion, Outcome, PlannedUpdateItem, UnfixableReason, UpdatePlan, is_requested,
};

/// Ceiling on the phase-B `check_candidates` timeout, mirroring `analyze.rs`'s own OSV scan
/// timeout ceiling — the shared `reqwest` client already imposes its own client-wide 30s
/// timeout, so a longer configured value would never actually bind.
const OSV_CHECK_TIMEOUT_CEILING_SECS: u64 = 30;

/// Plans the `--security-only` update set.
///
/// Every OSV-`Vulnerable` dependency, targeting `recommended_fix()`, independently
/// re-verified against OSV before being classified
/// `Applied`/`RequiresLockfileUpdate`/`Unfixable`.
///
/// `ignore_rules` is consulted only for **reporting** which rule was overridden (FR-008) —
/// never to suppress a candidate; pass [`IgnoreRules::empty`] when no `--config` was given,
/// same as the default planner.
///
/// # Examples
///
/// With no OSV scan having run (`analysis.vulnerabilities` is `None` — `--security-only` was
/// combined with `network.offline`/`vulnerabilities_enabled = false`, or simply never
/// executed against this manifest), this returns an empty plan without ever touching `osv`,
/// so this example runs deterministically with no network access:
///
/// ```
/// use deps_cli::analyze::ManifestAnalysis;
/// use deps_cli::update::ignore::IgnoreRules;
/// use deps_cli::update::security::plan_security_updates;
/// use deps_core::osv::OsvClient;
/// use deps_core::{EcosystemId, HttpCache};
/// use deps_engine::test_util::TestTier3Ecosystem;
/// use std::collections::{HashMap, HashSet};
/// use std::sync::Arc;
///
/// # #[tokio::main]
/// # async fn main() {
/// let ecosystem = TestTier3Ecosystem::returning(vec![]);
/// let osv = OsvClient::new(Arc::new(HttpCache::new()));
///
/// let analysis = ManifestAnalysis {
///     parse_result: deps_core::test_util::stub_parse_result_with_dependencies(0),
///     uri: deps_core::test_util::test_uri("/test/pubspec.yaml"),
///     now: deps_core::PublishTime::now(),
///     ecosystem_id: EcosystemId::Dart,
///     cached_versions: HashMap::new(),
///     resolved_versions: HashMap::new(),
///     resolved_version_candidates: HashMap::new(),
///     outcomes: deps_core::lsp_helpers::DependencyOutcomes::new(),
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
/// let plan = plan_security_updates(
///     &analysis,
///     &ecosystem,
///     &osv,
///     &[],
///     &IgnoreRules::empty(),
///     30,
/// )
/// .await;
///
/// assert!(plan.items.is_empty());
/// # }
/// ```
pub async fn plan_security_updates(
    analysis: &ManifestAnalysis,
    ecosystem: &dyn Ecosystem,
    osv: &OsvClient,
    package_filter: &[String],
    ignore_rules: &IgnoreRules,
    fetch_timeout_secs: u64,
) -> UpdatePlan {
    let formatter = ecosystem.formatter();
    let ecosystem_id = analysis.ecosystem_id;

    let Some(vulnerabilities) = analysis.vulnerabilities.as_ref() else {
        return UpdatePlan::default();
    };

    let vulnerable_keys: Vec<deps_core::osv::VulnKey> = vulnerabilities
        .iter()
        .filter(|(_, outcome)| matches!(outcome, ScanOutcome::Vulnerable(_)))
        .map(|(key, _)| key.clone())
        .collect();
    if vulnerable_keys.is_empty() {
        return UpdatePlan::default();
    }

    let (targets, _skipped) = deps_engine::classify::osv::build_scan_targets(
        analysis.parse_result.as_ref(),
        &analysis.resolved_versions,
        &analysis.resolved_version_candidates,
        formatter,
        ecosystem_id,
    );
    let osv_name_by_key = deps_engine::classify::osv::osv_name_by_key(&targets);

    // Issue #1517 (former FR-009 hazard, now dissolved): `deps-cli` runs its own phase-B.1
    // "latest" check (`analyze_manifest`'s `latest_check`), so — unlike before, when this map
    // was deliberately left empty — the CLI now has a real `LatestStatusMap` to pass here,
    // the same shared source of truth `deps-lsp` commits to `DocumentState.signals`. `None`
    // (vulnerabilities checking disabled, or offline) degrades to an empty map, which
    // `collect_fix_target_resolutions` already treats as "nothing to reuse, always live-check"
    // — never a silently-suppressed fix.
    static EMPTY_LATEST_STATUS: std::sync::LazyLock<deps_core::osv::LatestStatusMap> =
        std::sync::LazyLock::new(deps_core::osv::LatestStatusMap::new);
    let latest_status = analysis
        .latest_status
        .as_ref()
        .unwrap_or(&EMPTY_LATEST_STATUS);
    let (resolved, live_check_candidates) =
        deps_engine::classify::osv::collect_fix_target_resolutions(
            vulnerabilities,
            &vulnerable_keys,
            &osv_name_by_key,
            latest_status,
            formatter,
        );

    let mut vulnerabilities = vulnerabilities.clone();
    for (key, status) in resolved {
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(&key) {
            dv.fix_target_status = status;
        }
    }
    if !live_check_candidates.is_empty() {
        let timeout = Duration::from_secs(fetch_timeout_secs.min(OSV_CHECK_TIMEOUT_CEILING_SECS));
        let statuses = osv
            .check_candidates(ecosystem_id, &live_check_candidates, timeout)
            .await;
        deps_engine::classify::osv::apply_live_fix_target_statuses(&mut vulnerabilities, statuses);
    }

    let vuln_key_by_range = deps_core::osv::vulnerability_keys(
        analysis.parse_result.as_ref(),
        &analysis.resolved_versions,
        Some(&analysis.resolved_version_candidates),
        formatter,
        ecosystem_id,
    );

    let mut items = Vec::new();
    for dep in analysis.parse_result.dependencies() {
        let normalized_name = formatter.normalize_package_name(dep.name());
        let Some(ScanOutcome::Vulnerable(dv)) = resolve_scan_outcome(
            &vulnerabilities,
            dep,
            Some(&vuln_key_by_range),
            &normalized_name,
        ) else {
            continue;
        };

        if !is_requested(package_filter, &normalized_name, formatter) {
            items.push(skipped_not_requested(
                dep,
                &normalized_name,
                ecosystem_id,
                analysis,
                formatter,
            ));
            continue;
        }

        let latest = analysis.latest_status.as_ref().and_then(|map| {
            deps_core::lsp_helpers::resolve_latest_status(
                map,
                dep,
                Some(&vuln_key_by_range),
                &normalized_name,
            )
        });

        items.push(classify_vulnerable_dependency(
            dep,
            dv,
            latest,
            &normalized_name,
            analysis,
            formatter,
            ecosystem_id,
            ignore_rules,
        ));
    }

    UpdatePlan { items }
}

/// Classifies one already-confirmed-`Vulnerable`, already-requested dependency into its
/// final [`PlannedUpdateItem`] — the pure, synchronous per-dependency decision the async
/// orchestration in [`plan_security_updates`] delegates to once `dv.fix_target_status` has
/// been resolved (live-checked or not). Split out specifically so this decision logic is
/// unit-testable without an `OsvClient`/network dependency (spec 068 S5) — `dv` is taken
/// pre-resolved rather than re-deriving its `fix_target_status` here.
#[expect(
    clippy::too_many_arguments,
    reason = "issue #1517 added `latest` alongside seven pre-existing parameters; mirrors \
              `deps-lsp::document::osv_scan::run_osv_fix_target_verification`'s identical \
              precedent for the same OSV-plumbing reason"
)]
fn classify_vulnerable_dependency(
    dep: &dyn deps_core::Dependency,
    dv: &deps_core::osv::DependencyVulnerabilities,
    latest: Option<&deps_core::osv::UpgradeStatus>,
    normalized_name: &str,
    analysis: &ManifestAnalysis,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem_id: deps_core::EcosystemId,
    ignore_rules: &IgnoreRules,
) -> PlannedUpdateItem {
    // M8: the resolved in-use version, not the declared requirement text, is what
    // `deps-cli check` and default mode both report as `current` — a security report must
    // show which version is actually vulnerable ("serde 1.0.1 -> 1.0.2"), not the declared
    // range ("serde 1 -> 1.0.2"), which hides that information.
    //
    // Code review finding 4: `security_current`'s fallback chain is *not* the same as default
    // mode's. Default mode's `collect_update_candidates` (`deps-core::edit`) falls straight
    // from an unresolved `resolve_in_use_version` to `CurrentVersion::Unknown` (rendered as
    // `""`), the honest "we don't know" value `CurrentVersion::update_kind_to` maps to
    // `UpdateKind::Unknown`. This function instead falls back to the declared requirement text
    // (`CurrentVersion::Declared`) before `Unknown`, deliberately: an empty `current` in a
    // vulnerability report ("serde  -> 1.0.2") reads as a rendering bug, and a
    // `--security-only` report's whole purpose is communicating exposure, so showing the
    // declared range ("serde 1 -> 1.0.2") when the exact in-use version can't be resolved is
    // strictly more useful here than it would be worth changing default mode's shared,
    // LSP-facing `current` semantics to match (which FR-001's byte-identical-`deps-lsp`
    // constraint rules out doing casually anyway).
    let current = security_current(dep, normalized_name, analysis, formatter, ecosystem_id);
    let ignore_rule_overridden = ignore_override(ignore_rules, normalized_name);

    // FR-011: the two-signal, load-bearing `Unfixable` rule — `fetch_and_classify_package`
    // (`crates/deps-engine/src/classify/fetch.rs:605-825`) upholds the disjointness between
    // `fetch_failed` and a present `PackageVersions` entry by convention across a large
    // `match`, not by the type system, so both signals are checked explicitly: a future
    // refactor breaking that disjointness degrades to fail-closed here rather than silently
    // admitting a stale-but-present entry through the yank filter below. Deliberately
    // stricter than `deps-lsp` (`code_actions.rs:590-604`), which fails closed only on a
    // *timed-out* fetch and leaves a plain fetch failure unfiltered — the CLI's broader rule
    // is intentional (the safe direction) and must not be narrowed to match `deps-lsp`.
    let cached = analysis
        .cached_versions
        .get(normalized_name)
        .or_else(|| analysis.cached_versions.get(dep.name()));
    if analysis.fetch_failed.contains(dep.name()) || cached.is_none() {
        return unfixable_item(
            dep,
            current,
            UnfixableReason::FetchFailedOrAbsent,
            ignore_rule_overridden,
        );
    }

    // #1350: `resolve_verified_fix` replaces this function's own copy of the
    // `recommended_fix -> osv_version_to_native -> is_safe_version_string ->
    // fix_target_is_verified` chain (`fix_target_is_verified` is `pub(crate)` in `deps-core`
    // again since this is its only remaining caller outside it). S1 fix: this must run
    // *before* the version_requirement/version_range/yanked checks below, exactly like the
    // pre-#1350 code did, so an unverified fix target is never misreported as
    // `RequiresLockfileUpdate`/`Unfixable(Yanked)` instead of `Unfixable(NoVerifiedFix)`.
    let (fix, version_native) = match resolve_verified_fix(dv, latest, formatter) {
        Ok(pair) => pair,
        Err(_) => {
            return unfixable_item(
                dep,
                current,
                UnfixableReason::NoVerifiedFix,
                ignore_rule_overridden,
            );
        }
    };

    // C1 (critic finding, FR-010): a `Vulnerable` dependency with no declared
    // `version_requirement()` at all (a Cargo workspace-inherited dependency, a git/path
    // dependency whose manifest line carries no version) has nothing to rewrite — same
    // treatment as the `version_range()` miss below, never a silent `continue` that would let
    // the run exit 0 with a known-vulnerable dependency neither remediated nor reported.
    let Some(version_req) = dep.version_requirement() else {
        return requires_lockfile_update_item(
            dep,
            current,
            deps_core::ConcreteVersion::new(version_native),
            &fix.advisory_ids,
            ignore_rule_overridden,
        );
    };

    let Some(version_range) = dep.version_range() else {
        return requires_lockfile_update_item(
            dep,
            current,
            deps_core::ConcreteVersion::new(version_native),
            &fix.advisory_ids,
            ignore_rule_overridden,
        );
    };

    // FR-012: native-form comparison — comparing OSV's wire-form version directly against
    // `PackageVersions::yanked` would silently never match for an ecosystem whose OSV and
    // native spellings diverge (PyPI, Maven, NuGet). `reports_yanked() == false` ecosystems
    // structurally never populate `yanked` at all (`fetch.rs:617-629`), so this filter is
    // inert — not converted to `Unfixable` — for them, matching `deps-lsp`'s own documented
    // fail-open (FR-013).
    let yanked = cached.is_some_and(|pv| {
        pv.yanked
            .iter()
            .any(|(v, status)| v.as_str() == version_native && status.blocks_resolution())
    });
    if yanked {
        return unfixable_item(
            dep,
            current,
            UnfixableReason::Yanked {
                target: deps_core::ConcreteVersion::new(version_native),
            },
            ignore_rule_overridden,
        );
    }

    // #1350 code review: `plan_verified_fix`, not `plan_vulnerability_fix` — this function
    // already resolved and verified the fix above via `resolve_verified_fix`, so calling the
    // higher-level `plan_vulnerability_fix` here would re-run that same resolve-and-verify
    // chain a second time per dependency for no reason.
    match plan_verified_fix(
        dep,
        version_range,
        version_req.as_str(),
        &version_native,
        formatter,
    ) {
        // FR-014: `--security-only`'s fix target comes from the advisory, never a
        // GOSSIP-filtered registry `latest` (issue #1521 item 1) — `gossip_excluded_version`
        // and `cooldown_fallback` both stay `None` (PlannedUpdateItem::new's defaults).
        Ok(planned) => PlannedUpdateItem::new(
            dep.name().as_str().to_string(),
            current,
            Outcome::Applied {
                edit: planned.edit,
                target: deps_core::ConcreteVersion::new(version_native),
            },
            fix.advisory_ids,
            ignore_rule_overridden,
            None,
            None,
        ),
        // #1344/#1350: `RequirementAlreadyResolves` (the declared requirement already resolves
        // forward to the fix target — see `bounded_requirement_already_resolves_to`'s and
        // `NuGetFormatter`'s doc for why this is not simply "the requirement admits the fix")
        // reads as "nothing to rewrite here" — note this runs after the FR-012 yanked filter
        // above, so a requirement that already resolves forward but whose fix target is yanked
        // was already reported `Unfixable(Yanked)` and never reaches this match.
        Err(VulnFixSkip::RequirementAlreadyResolves) => requires_lockfile_update_item(
            dep,
            current,
            deps_core::ConcreteVersion::new(version_native),
            &fix.advisory_ids,
            ignore_rule_overridden,
        ),
        // #1566 S1: `NoOpRewrite` here no longer safely implies "the literal already reads as
        // the fix." `plan_verified_fix` only reaches `NoOpRewrite` after `bounded_requirement_already_resolves_to`
        // has already returned `false` above (a `true` answer would have hit
        // `RequirementAlreadyResolves` instead), so the historical assumption — no
        // `compile_bounded_requirement` comparator exists (e.g. GitHub Actions/GitLab CI tag pins), and
        // the declared literal happens to already spell the fix text verbatim — no longer holds
        // once an ecosystem's formatter can deliberately echo `current` back unchanged for a
        // requirement shape it has no safe single-value rewrite for (Cargo's compound
        // comma-separated requirements, #1566).
        //
        // Code review regression: checking only `compile_bounded_requirement(..).is_some()` (a matcher
        // *exists*) is not enough, because `bounded_requirement_already_resolves_to` can diverge from
        // the raw matcher's verdict — `NuGetFormatter` overrides it to always report `false`
        // for a bare/open-ended-minimum floor requirement regardless of what the matcher itself
        // says (floor semantics: leaving the manifest unedited restores the floor version, even
        // when the floor mathematically admits the fix), and `Pep440Matcher::matches` can
        // return `None` (indeterminate — the compared version failed to parse) rather than a
        // confirmed `Some(false)`. Neither case means the requirement was *confirmed* to
        // exclude the fix, so re-deriving the verdict from the underlying matcher directly —
        // not `bounded_requirement_already_resolves_to`, which those two overrides deliberately bend
        // away from the matcher's plain answer — and requiring exactly `Some(false)` is the
        // only way to tell "confirmed excluded" apart from "unknown"/"overridden for other
        // reasons". Only a confirmed exclusion is a real gap; anything else falls back to the
        // legacy "assume already fixed" reading, preserving pre-#1566 behavior.
        Err(VulnFixSkip::NoOpRewrite) => {
            let fix_concrete = deps_core::ConcreteVersion::new(version_native.as_str());
            let confirmed_excluded = formatter
                .compile_requirement(version_req)
                .is_some_and(|matcher| matcher.matches(&fix_concrete) == Some(false));
            if confirmed_excluded {
                unfixable_item(
                    dep,
                    current,
                    UnfixableReason::UnsupportedRequirementShape {
                        target: fix_concrete,
                    },
                    ignore_rule_overridden,
                )
            } else {
                requires_lockfile_update_item(
                    dep,
                    current,
                    fix_concrete,
                    &fix.advisory_ids,
                    ignore_rule_overridden,
                )
            }
        }
        // #1578 S1: an oversized requirement is a size-based fail-closed guard, never a
        // confirmed exclusion; reported as `OversizedRequirement` rather than
        // `UnsupportedRequirementShape`, whose doc/message both assert confirmation.
        Err(VulnFixSkip::OversizedRequirement) => unfixable_item(
            dep,
            current,
            UnfixableReason::OversizedRequirement {
                target: deps_core::ConcreteVersion::new(version_native.as_str()),
            },
            ignore_rule_overridden,
        ),
        // #1370: `UnresolvedPlaceholder` joins the `NoVerifiedFix` bucket, not the
        // `RequirementAlreadyResolves`/`NoOpRewrite` one above — "requires lockfile update"
        // implies the manifest requirement already admits the fix target, which is not known
        // (and can never be, statically) for an unexpanded placeholder.
        Err(
            VulnFixSkip::UnverifiedTarget
            | VulnFixSkip::NoRecommendedFix
            | VulnFixSkip::UnsafeVersion
            | VulnFixSkip::UnresolvedPlaceholder,
        ) => unfixable_item(
            dep,
            current,
            UnfixableReason::NoVerifiedFix,
            ignore_rule_overridden,
        ),
    }
}

/// `--security-only`'s `current` resolution (M8/code-review finding 4): the resolved in-use
/// version when one exists, else the declared requirement text, else [`CurrentVersion::Unknown`]
/// — see [`classify_vulnerable_dependency`]'s doc for why this differs from default mode's
/// [`deps_core::edit::collect_update_candidates`], which never falls back to the declared text.
fn security_current(
    dep: &dyn deps_core::Dependency,
    normalized_name: &str,
    analysis: &ManifestAnalysis,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem_id: deps_core::EcosystemId,
) -> CurrentVersion {
    resolve_in_use_version(
        dep,
        normalized_name,
        &analysis.resolved_versions,
        Some(&analysis.resolved_version_candidates),
        formatter,
        ecosystem_id,
    )
    .map(CurrentVersion::Resolved)
    .or_else(|| {
        dep.version_requirement()
            .cloned()
            .map(CurrentVersion::Declared)
    })
    .unwrap_or(CurrentVersion::Unknown)
}

/// Whether a `[update].ignore` rule matches this dependency, purely for the FR-008 override
/// report — never for suppression in `--security-only` mode.
fn ignore_override(ignore_rules: &IgnoreRules, normalized_name: &str) -> bool {
    ignore_rules.matches_name(normalized_name)
}

fn skipped_not_requested(
    dep: &dyn deps_core::Dependency,
    normalized_name: &str,
    ecosystem_id: deps_core::EcosystemId,
    analysis: &ManifestAnalysis,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> PlannedUpdateItem {
    let current = security_current(dep, normalized_name, analysis, formatter, ecosystem_id);
    PlannedUpdateItem::new(
        dep.name().as_str().to_string(),
        current,
        Outcome::Skipped {
            reason: crate::update::SkipReason::NotRequested,
            target: None,
        },
        Vec::new(),
        false,
        None,
        None,
    )
}

fn unfixable_item(
    dep: &dyn deps_core::Dependency,
    current: CurrentVersion,
    reason: UnfixableReason,
    ignore_rule_overridden: bool,
) -> PlannedUpdateItem {
    PlannedUpdateItem::new(
        dep.name().as_str().to_string(),
        current,
        Outcome::Unfixable(reason),
        Vec::new(),
        ignore_rule_overridden,
        None,
        None,
    )
}

fn requires_lockfile_update_item(
    dep: &dyn deps_core::Dependency,
    current: CurrentVersion,
    target: deps_core::ConcreteVersion,
    advisory_ids: &[String],
    ignore_rule_overridden: bool,
) -> PlannedUpdateItem {
    PlannedUpdateItem::new(
        dep.name().as_str().to_string(),
        current,
        Outcome::RequiresLockfileUpdate { target },
        advisory_ids.to_vec(),
        ignore_rule_overridden,
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IgnoreRule;
    use deps_core::licenses::LicensePolicy;
    use deps_core::lsp_helpers::{
        DiagnosticMessages, DiagnosticPolicy, MAX_REQUIREMENT_LEN, OsvNaming, PackageNaming,
        PackageRendering, RequirementMatcher, RequirementResolution, SourcePolicy,
    };
    use deps_core::osv::{Advisory, Capped, OsvVersion, UpgradeStatus, VulnSeverity};
    use deps_core::parser::DependencySource;
    use deps_core::position::{Position, Range};
    use deps_core::{
        ConcreteVersion, Dependency, EcosystemId, PackageName, PackageVersions, RemovalStatus,
        VersionReq,
    };
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    struct MockDep {
        name: PackageName,
        version_req: Option<VersionReq>,
        version_range: Option<Range>,
    }

    impl Dependency for MockDep {
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
        fn source(&self) -> DependencySource {
            DependencySource::Registry
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn dep(name: &str, req: &str) -> MockDep {
        MockDep {
            name: PackageName::new(name),
            version_req: Some(VersionReq::new(req)),
            version_range: Some(Range::new(
                Position::new(0, 9),
                Position::new(0, 9 + req.len() as u32),
            )),
        }
    }

    /// A fixed-answer [`RequirementMatcher`] — the test controls whether `compile_bounded_requirement`
    /// reports the declared requirement as already admitting the fix target, independent of
    /// real semver semantics (deps-cli has no `semver` dependency of its own to build a real
    /// one with).
    struct FixedMatcher(bool);
    impl RequirementMatcher for FixedMatcher {
        fn matches(&self, _version: &deps_core::ConcreteVersion) -> Option<bool> {
            Some(self.0)
        }

        fn strict_prerelease_exclusion(&self) -> bool {
            false
        }
    }

    /// A formatter with a `compile_bounded_requirement` override (like 12 of the 14 real ecosystems),
    /// whose verdict is fixed per test rather than computed from a real requirement grammar.
    struct TestFormatter {
        requirement_already_admits_fix: bool,
        osv_native_differs: bool,
    }
    impl PackageNaming for TestFormatter {}
    impl PackageRendering for TestFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl RequirementResolution for TestFormatter {
        fn compile_bounded_requirement(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(FixedMatcher(self.requirement_already_admits_fix)))
        }
    }
    impl DiagnosticMessages for TestFormatter {}
    impl DiagnosticPolicy for TestFormatter {}
    impl SourcePolicy for TestFormatter {}
    impl OsvNaming for TestFormatter {
        fn osv_version_to_native(
            &self,
            version: &deps_core::osv::OsvVersion,
        ) -> deps_core::ConcreteVersion {
            // SC-005: simulates an ecosystem whose OSV and native version spellings diverge
            // (PyPI/Maven/NuGet) — prefixes with "v" so a yank-filter test can prove the
            // comparison goes through this conversion, not the raw OSV wire form.
            let version = version.as_str();
            if self.osv_native_differs {
                deps_core::ConcreteVersion::new(format!("v{version}"))
            } else {
                deps_core::ConcreteVersion::new(version)
            }
        }
    }

    /// #1566 S1: simulates an ecosystem formatter (like Cargo's compound comma-separated
    /// requirement handling) whose `compile_bounded_requirement` comparator has already confirmed the
    /// fix target is NOT admitted, yet whose `format_version_replacing` deliberately echoes
    /// `current` back unchanged because no single-value rewrite preserves the requirement
    /// shape's semantics.
    struct UnsupportedShapeFormatter;
    impl PackageNaming for UnsupportedShapeFormatter {}
    impl PackageRendering for UnsupportedShapeFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
        fn format_version_replacing(
            &self,
            _version: &deps_core::ConcreteVersion,
            current: &str,
        ) -> String {
            current.to_string()
        }
    }
    impl RequirementResolution for UnsupportedShapeFormatter {
        fn compile_bounded_requirement(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(FixedMatcher(false)))
        }
    }
    impl DiagnosticMessages for UnsupportedShapeFormatter {}
    impl DiagnosticPolicy for UnsupportedShapeFormatter {}
    impl SourcePolicy for UnsupportedShapeFormatter {}
    impl OsvNaming for UnsupportedShapeFormatter {}

    /// Code review regression (S1 fix): mirrors `NuGetFormatter::bounded_requirement_already_resolves_to`'s
    /// real bare-floor override — the raw matcher mathematically admits the fix (`Some(true)`),
    /// but the ecosystem overrides `bounded_requirement_already_resolves_to` to always report `false`
    /// for a floor shape (floor semantics: leaving the manifest unedited keeps restoring the
    /// declared floor). `format_version_replacing` echoes `current` back unchanged, so
    /// `plan_verified_fix` reaches `NoOpRewrite` — but the raw matcher's `Some(true)` must never
    /// be read as "confirmed excluded".
    struct FloorLikeFormatter;
    impl PackageNaming for FloorLikeFormatter {}
    impl PackageRendering for FloorLikeFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
        fn format_version_replacing(
            &self,
            _version: &deps_core::ConcreteVersion,
            current: &str,
        ) -> String {
            current.to_string()
        }
    }
    impl RequirementResolution for FloorLikeFormatter {
        fn compile_bounded_requirement(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(FixedMatcher(true)))
        }
        fn bounded_requirement_already_resolves_to(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
            _target: &deps_core::ConcreteVersion,
        ) -> bool {
            false
        }
    }
    impl DiagnosticMessages for FloorLikeFormatter {}
    impl DiagnosticPolicy for FloorLikeFormatter {}
    impl SourcePolicy for FloorLikeFormatter {}
    impl OsvNaming for FloorLikeFormatter {}

    /// A matcher that cannot decide — mirrors `Pep440Matcher::matches` returning `None` when
    /// the compared version fails to parse, rather than a confirmed `Some(false)`.
    struct IndeterminateMatcher;
    impl RequirementMatcher for IndeterminateMatcher {
        fn matches(&self, _version: &deps_core::ConcreteVersion) -> Option<bool> {
            None
        }
        fn strict_prerelease_exclusion(&self) -> bool {
            false
        }
    }

    /// Code review regression (S1 fix): a matcher exists but returns `None` (indeterminate),
    /// never `Some(false)` (confirmed excluded) — must not be treated the same as a confirmed
    /// exclusion. `format_version_replacing` echoes `current` back unchanged so `plan_verified_fix`
    /// reaches `NoOpRewrite`.
    struct IndeterminateFormatter;
    impl PackageNaming for IndeterminateFormatter {}
    impl PackageRendering for IndeterminateFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
        fn format_version_replacing(
            &self,
            _version: &deps_core::ConcreteVersion,
            current: &str,
        ) -> String {
            current.to_string()
        }
    }
    impl RequirementResolution for IndeterminateFormatter {
        fn compile_bounded_requirement(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(IndeterminateMatcher))
        }
    }
    impl DiagnosticMessages for IndeterminateFormatter {}
    impl DiagnosticPolicy for IndeterminateFormatter {}
    impl SourcePolicy for IndeterminateFormatter {}
    impl OsvNaming for IndeterminateFormatter {}

    /// Issue #1578: echoes `current` back unchanged but panics if `compile_bounded_requirement`
    /// is ever called — proves `plan_verified_fix`'s `OversizedRequirement` skip
    /// short-circuits before reaching it, rather than merely happening to also produce the
    /// right outcome.
    struct PanicsIfCompiledFormatter;
    impl PackageNaming for PanicsIfCompiledFormatter {}
    impl PackageRendering for PanicsIfCompiledFormatter {
        fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String {
            v.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
        fn format_version_replacing(
            &self,
            _version: &deps_core::ConcreteVersion,
            current: &str,
        ) -> String {
            current.to_string()
        }
    }
    impl RequirementResolution for PanicsIfCompiledFormatter {
        fn compile_bounded_requirement(
            &self,
            _requirement: deps_core::lsp_helpers::BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            panic!(
                "compile_bounded_requirement must not be called for an oversized requirement (#1578)"
            );
        }
    }
    impl DiagnosticMessages for PanicsIfCompiledFormatter {}
    impl DiagnosticPolicy for PanicsIfCompiledFormatter {}
    impl SourcePolicy for PanicsIfCompiledFormatter {}
    impl OsvNaming for PanicsIfCompiledFormatter {}

    /// A formatter with no `compile_bounded_requirement` override (like GitHub Actions/GitLab CI) —
    /// `plan_vulnerability_fix`'s own textual no-op guard is the only available signal.
    const NO_COMPILE_REQUIREMENT_FORMATTER: deps_core::test_util::StubFormatter =
        deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

    fn advisory(id: &str, fixed_version: &str) -> std::sync::Arc<Advisory> {
        std::sync::Arc::new(
            Advisory::new(
                id.to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new(fixed_version)]),
        )
    }

    fn verified_dv(fixed_version: &str) -> deps_core::osv::DependencyVulnerabilities {
        deps_core::osv::DependencyVulnerabilities::new(Capped::new(
            vec![advisory("RUSTSEC-2024-0001", fixed_version)],
            1,
        ))
        .with_fix_target_status(UpgradeStatus::CandidateClean {
            version: ConcreteVersion::new(fixed_version),
        })
    }

    fn test_analysis(
        cached_versions: HashMap<PackageName, PackageVersions>,
        fetch_failed: HashSet<PackageName>,
    ) -> ManifestAnalysis {
        ManifestAnalysis {
            parse_result: deps_core::test_util::stub_parse_result_with_dependencies(0),
            uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
            now: deps_core::PublishTime::now(),
            ecosystem_id: EcosystemId::Cargo,
            cached_versions,
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
            fetch_failed,
            registry_unreachable: false,
            license_fetch_incomplete: false,
        }
    }

    fn cached_with(name: &str, latest: &str) -> HashMap<PackageName, PackageVersions> {
        let mut map = HashMap::new();
        map.insert(PackageName::new(name), PackageVersions::latest_only(latest));
        map
    }

    #[test]
    fn test_classify_happy_path_is_applied() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(item.outcome, Outcome::Applied { .. }));
        assert_eq!(
            item.target(),
            Some(&deps_core::ConcreteVersion::from("1.0.2"))
        );
    }

    /// C1 (critical): a `Vulnerable` dependency with no declared `version_requirement()` at
    /// all must be reported `RequiresLockfileUpdate`, never silently dropped.
    #[test]
    fn test_classify_no_version_requirement_is_requires_lockfile_update() {
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: None,
            version_range: None,
        };
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::RequiresLockfileUpdate { .. }
        ));
    }

    #[test]
    fn test_classify_no_version_range_is_requires_lockfile_update() {
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: Some(VersionReq::new("1")),
            version_range: None,
        };
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::RequiresLockfileUpdate { .. }
        ));
    }

    /// S1 (significant, US-003): a requirement the ecosystem's own comparator confirms
    /// already admits the fix target must be `RequiresLockfileUpdate`, never rewritten.
    #[test]
    fn test_classify_requirement_already_admits_fix_is_requires_lockfile_update() {
        let dep = dep("serde", "1");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: true,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::RequiresLockfileUpdate { .. }
        ));
        assert_eq!(
            item.target(),
            Some(&deps_core::ConcreteVersion::from("1.0.2"))
        );
    }

    /// Fallback path (GitHub Actions/GitLab CI — no `compile_bounded_requirement`): the declared
    /// literal already spelling the fix text verbatim still resolves to
    /// `RequiresLockfileUpdate` via `plan_vulnerability_fix`'s own no-op guard.
    #[test]
    fn test_classify_no_compile_requirement_falls_back_to_no_op_guard() {
        let dep = dep("serde", "1.0.2");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &NO_COMPILE_REQUIREMENT_FORMATTER,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::RequiresLockfileUpdate { .. }
        ));
    }

    /// #1566 S1 regression: a requirement shape (e.g. Cargo's compound `">=1.2, <1.5"`) whose
    /// formatter echoes `current` back unchanged, while a real comparator has already
    /// confirmed the fix is NOT admitted, must be `Unfixable(UnsupportedRequirementShape)` —
    /// never `RequiresLockfileUpdate`, whose message would falsely tell the operator the
    /// vulnerability is already resolved by regenerating the lock file.
    #[test]
    fn test_classify_unsupported_requirement_shape_is_unfixable_not_requires_lockfile_update() {
        let dep = dep("foo", ">=1.2, <1.5");
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &UnsupportedShapeFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::UnsupportedRequirementShape { .. })
            ),
            "expected Unfixable(UnsupportedRequirementShape), got {:?}",
            item.outcome
        );
        assert_eq!(
            item.target(),
            Some(&deps_core::ConcreteVersion::from("1.5.2")),
            "an Unfixable item with a rejected fix target must report it (#1614)"
        );
        assert!(
            !item.reason().contains("regenerate the lock file"),
            "message must not claim the fix is already admitted: {}",
            item.reason()
        );
    }

    /// Code review regression (S1 fix): a bare/open-ended-minimum floor requirement (like
    /// NuGet's), whose raw matcher mathematically admits the fix (`Some(true)`) but whose
    /// `bounded_requirement_already_resolves_to` override always reports `false` for floor shapes, must
    /// still be `RequiresLockfileUpdate` — the matcher's `Some(true)` is not a confirmed
    /// exclusion, so `NoOpRewrite` here means the declared floor already spells the fix
    /// version, not that the shape is unsupported.
    #[test]
    fn test_classify_floor_requirement_matching_matcher_is_requires_lockfile_update_not_unfixable()
    {
        let dep = dep("foo", "1.5.2");
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &FloorLikeFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(item.outcome, Outcome::RequiresLockfileUpdate { .. }),
            "expected RequiresLockfileUpdate, got {:?}",
            item.outcome
        );
    }

    /// Code review regression (S1 fix): a matcher that cannot decide (`None`, like
    /// `Pep440Matcher::matches` on an unparseable comparison) must not be treated as a
    /// confirmed exclusion — falls back to `RequiresLockfileUpdate`, the legacy "assume already
    /// fixed" reading, rather than a false `Unfixable(UnsupportedRequirementShape)`.
    #[test]
    fn test_classify_indeterminate_matcher_is_requires_lockfile_update_not_unfixable() {
        let dep = dep("foo", "1.5.2");
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &IndeterminateFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(item.outcome, Outcome::RequiresLockfileUpdate { .. }),
            "expected RequiresLockfileUpdate, got {:?}",
            item.outcome
        );
    }

    /// US-003 mixed-outcome regression: spec.md's own US-003 fixture has one dependency whose
    /// requirement does not yet admit the fix (`Applied`) alongside one whose requirement
    /// already does (`RequiresLockfileUpdate`) — this proves both outcomes are reachable from
    /// the same classification function with the S1 gate wired in, not that a real
    /// `plan_security_updates` run over both dependencies at once shares no state (each call
    /// below is independent, driven by its own `TestFormatter` verdict; N2, critic re-review:
    /// this test cannot and does not rule out a shared-state bug across dependencies within
    /// one `plan_security_updates` call — that would need a network-mocked end-to-end test,
    /// out of scope here).
    #[test]
    fn test_classify_us003_mixed_outcomes_are_both_reachable() {
        let rewrite_dep = dep("serde", "0.9");
        let rewrite_dv = verified_dv("1.0.2");
        let rewrite_analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let rewrite_formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let rewrite_item = classify_vulnerable_dependency(
            &rewrite_dep,
            &rewrite_dv,
            None,
            "serde",
            &rewrite_analysis,
            &rewrite_formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );

        let lockfile_dep = dep("tokio", "1");
        let lockfile_dv = verified_dv("1.0.2");
        let lockfile_analysis = test_analysis(cached_with("tokio", "1.0.2"), HashSet::new());
        let lockfile_formatter = TestFormatter {
            requirement_already_admits_fix: true,
            osv_native_differs: false,
        };
        let lockfile_item = classify_vulnerable_dependency(
            &lockfile_dep,
            &lockfile_dv,
            None,
            "tokio",
            &lockfile_analysis,
            &lockfile_formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );

        assert!(
            matches!(rewrite_item.outcome, Outcome::Applied { .. }),
            "serde's requirement (\"0.9\") does not yet admit 1.0.2, so it must be rewritten"
        );
        assert_eq!(
            rewrite_item.target(),
            Some(&deps_core::ConcreteVersion::from("1.0.2"))
        );
        assert!(
            matches!(
                lockfile_item.outcome,
                Outcome::RequiresLockfileUpdate { .. }
            ),
            "tokio's requirement (\"1\") already admits 1.0.2 per spec.md's US-003 fixture, so \
             it must be reported, not rewritten"
        );
        assert_eq!(
            lockfile_item.target(),
            Some(&deps_core::ConcreteVersion::from("1.0.2"))
        );
    }

    /// FR-011: registry fetch failure is `Unfixable`, not silently passed through.
    #[test]
    fn test_classify_fetch_failed_is_unfixable() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let mut fetch_failed = HashSet::new();
        fetch_failed.insert(PackageName::new("serde"));
        let analysis = test_analysis(cached_with("serde", "1.0.2"), fetch_failed);
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::FetchFailedOrAbsent)
        ));
    }

    /// FR-011: no `PackageVersions` entry at all is `Unfixable`, even without a `fetch_failed`
    /// entry (the two-signal rule).
    #[test]
    fn test_classify_absent_package_versions_is_unfixable() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(HashMap::new(), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::FetchFailedOrAbsent)
        ));
    }

    #[test]
    fn test_classify_no_recommended_fix_is_unfixable() {
        let dep = dep("serde", "0.9");
        // No advisory has a claimable fix (no `fixed_versions`), so `recommended_fix()` is
        // `None`.
        let advisory = std::sync::Arc::new(
            Advisory::new(
                "RUSTSEC-2024-0001".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id"),
        );
        let dv = deps_core::osv::DependencyVulnerabilities::new(Capped::new(vec![advisory], 1));
        let analysis = test_analysis(cached_with("serde", "1.2.0"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::NoVerifiedFix)
        ));
    }

    #[test]
    fn test_classify_unverified_fix_target_is_unfixable() {
        let dep = dep("serde", "0.9");
        // `fix_target_status` left at `NotChecked` — `fix_target_is_verified` rejects it.
        let dv = deps_core::osv::DependencyVulnerabilities::new(Capped::new(
            vec![advisory("RUSTSEC-2024-0001", "1.0.2")],
            1,
        ));
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::NoVerifiedFix)
        ));
    }

    /// #1350 S1 regression: an unverified fix target must report `Unfixable(NoVerifiedFix)`
    /// even when the dependency also has no declared `version_requirement()` — the
    /// `resolve_verified_fix` check must run BEFORE the C1 no-requirement guard, exactly as
    /// the pre-#1350 code's `fix_target_is_verified` check did, or this misreports
    /// `RequiresLockfileUpdate` for a fix that was never actually confirmed safe.
    #[test]
    fn test_classify_unverified_target_with_no_version_requirement_is_unfixable_not_lockfile() {
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: None,
            version_range: None,
        };
        // `fix_target_status` left at `NotChecked` — never verified.
        let dv = deps_core::osv::DependencyVulnerabilities::new(Capped::new(
            vec![advisory("RUSTSEC-2024-0001", "1.0.2")],
            1,
        ));
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::NoVerifiedFix)
            ),
            "got {:?}",
            item.outcome
        );
    }

    /// #1350 S1 regression: an unverified fix target must report `Unfixable(NoVerifiedFix)`
    /// even when its (never-verified) target version also happens to appear in the registry's
    /// yanked list — the verification check must run BEFORE the FR-012 yanked filter, exactly
    /// as the pre-#1350 code's combined check did.
    #[test]
    fn test_classify_unverified_target_and_yanked_is_unfixable_no_verified_fix_not_yanked() {
        let dep = dep("serde", "0.9");
        // `fix_target_status` left at `NotChecked` — never verified.
        let dv = deps_core::osv::DependencyVulnerabilities::new(Capped::new(
            vec![advisory("RUSTSEC-2024-0001", "1.0.2")],
            1,
        ));
        let mut cached = HashMap::new();
        cached.insert(
            PackageName::new("serde"),
            PackageVersions::new("1.0.2".into(), std::sync::Arc::from([])).with_yanked(
                std::sync::Arc::from([("1.0.2".into(), RemovalStatus::from_yanked(true))]),
            ),
        );
        let analysis = test_analysis(cached, HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::NoVerifiedFix)
            ),
            "got {:?}",
            item.outcome
        );
    }

    /// FR-012: the fix target is present in the registry's yanked list — `Unfixable`, not
    /// written.
    #[test]
    fn test_classify_yanked_fix_target_is_unfixable() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let mut cached = HashMap::new();
        cached.insert(
            PackageName::new("serde"),
            PackageVersions::new("1.0.2".into(), std::sync::Arc::from([])).with_yanked(
                std::sync::Arc::from([("1.0.2".into(), RemovalStatus::from_yanked(true))]),
            ),
        );
        let analysis = test_analysis(cached, HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::Yanked { .. })
        ));
        assert_eq!(
            item.target(),
            Some(&deps_core::ConcreteVersion::from("1.0.2")),
            "a yanked-unfixable item must report the rejected fix target (#1614)"
        );
    }

    /// #1344 C3: since the requirement-already-admits-fix gate moved inside
    /// `plan_vulnerability_fix`, it now runs AFTER the FR-012 yanked filter, not before it —
    /// a requirement that already admits the fix AND a yanked fix target must report
    /// `Unfixable(Yanked)`, not `RequiresLockfileUpdate`: a yanked version is never actually
    /// selected by re-resolving regardless of what the declared requirement admits, so
    /// `Unfixable(Yanked)` is the more truthful classification. Pins this intentional
    /// ordering so a future refactor that reverts it is a visible test failure, not a silent
    /// behavior change.
    #[test]
    fn test_classify_requirement_admits_fix_and_yanked_is_unfixable_yanked_not_lockfile() {
        let dep = dep("serde", "1");
        let dv = verified_dv("1.0.2");
        let mut cached = HashMap::new();
        cached.insert(
            PackageName::new("serde"),
            PackageVersions::new("1.0.2".into(), std::sync::Arc::from([])).with_yanked(
                std::sync::Arc::from([("1.0.2".into(), RemovalStatus::from_yanked(true))]),
            ),
        );
        let analysis = test_analysis(cached, HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: true,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(
            item.outcome,
            Outcome::Unfixable(UnfixableReason::Yanked { .. })
        ));
    }

    /// SC-005: the yank filter must compare via the ecosystem's *native* version spelling,
    /// not OSV's raw wire form — proven here with a formatter whose two forms diverge
    /// (mirrors PyPI/Maven/NuGet).
    #[test]
    fn test_classify_yank_filter_uses_native_form_not_osv_wire_form() {
        let dep = dep("serde", "0.9");
        // `fixed_versions` is OSV's own wire-form spelling ("1.0.2"); `fix_target_status` is
        // already converted to native form ("v1.0.2") — matching what `osv_version_to_native`
        // would have produced and what `fix_target_is_verified` compares against.
        let dv = deps_core::osv::DependencyVulnerabilities::new(Capped::new(
            vec![advisory("RUSTSEC-2024-0001", "1.0.2")],
            1,
        ))
        .with_fix_target_status(UpgradeStatus::CandidateClean {
            version: ConcreteVersion::new("v1.0.2"),
        });
        let mut cached = HashMap::new();
        cached.insert(
            PackageName::new("serde"),
            PackageVersions::new("v1.0.2".into(), std::sync::Arc::from([])).with_yanked(
                std::sync::Arc::from([("v1.0.2".into(), RemovalStatus::from_yanked(true))]),
            ),
        );
        let analysis = test_analysis(cached, HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: true,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::Yanked { .. })
            ),
            "the yanked native-form entry (v1.0.2) must match the converted native-form fix \
             target, not the raw OSV wire form (1.0.2), which was never in the yanked list"
        );
    }

    /// FR-013: an ecosystem that never reports yank status (`yanked` structurally empty) must
    /// not be converted to `Unfixable` solely for that reason — the filter is inert, not a
    /// failure.
    #[test]
    fn test_classify_empty_yanked_list_is_fail_open() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(matches!(item.outcome, Outcome::Applied { .. }));
    }

    /// FR-008: a matching `[update].ignore` rule is reported as overridden, never suppressed.
    #[test]
    fn test_classify_ignore_rule_is_overridden_not_suppressed() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let ignore_rules = IgnoreRules::new(
            vec![IgnoreRule {
                name: "serde".to_string(),
                update_types: None,
            }],
            &formatter,
        );
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &ignore_rules,
        );
        assert!(matches!(item.outcome, Outcome::Applied { .. }));
        assert!(
            item.ignore_rule_overridden,
            "a matching rule must be reported as overridden, not silently applied"
        );
    }

    /// M8: `current` must be the resolved in-use version, not the bare declared requirement
    /// text — a security report must show which version is actually vulnerable.
    #[test]
    fn test_classify_current_falls_back_to_declared_requirement_when_unresolvable() {
        let dep = dep("serde", "0.9");
        let dv = verified_dv("1.0.2");
        let analysis = test_analysis(cached_with("serde", "1.0.2"), HashSet::new());
        let formatter = TestFormatter {
            requirement_already_admits_fix: false,
            osv_native_differs: false,
        };
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "serde",
            &analysis,
            &formatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        // No lockfile-resolved version in `analysis.resolved_versions` and Cargo's bare "0.9"
        // is a caret range (not a pin), so `resolve_in_use_version` returns `None` and this
        // falls back to the declared requirement text.
        assert_eq!(
            item.current,
            CurrentVersion::Declared(VersionReq::new("0.9"))
        );
    }

    /// Issue #1578 gap 1: the mock-only `NoOpRewrite`/`UnsupportedRequirementShape` regression
    /// (`test_classify_unsupported_requirement_shape_is_unfixable_not_requires_lockfile_update`)
    /// proves the *decision logic*, but not that Cargo's real `semver`-backed matcher actually
    /// returns `Some(false)` (not `None`/`Some(true)`) for this exact compound-requirement/fix
    /// pair. This exercises the real `deps_engine::setup::CargoFormatter` (Cargo's own
    /// `deps_cargo::CargoFormatter`, reached through deps-engine's ecosystem registry rather
    /// than linking deps-cargo directly) end to end: its own
    /// `format_version_replacing` echoes a compound requirement back unchanged (reaching
    /// `NoOpRewrite`), and its `compile_bounded_requirement` (real `semver::VersionReq`) must confirm
    /// `1.5.2` is excluded by `">=1.2, <1.5"`.
    #[test]
    fn test_classify_real_cargo_formatter_compound_requirement_confirms_exclusion() {
        let dep = dep("foo", ">=1.2, <1.5");
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &deps_engine::setup::CargoFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::UnsupportedRequirementShape { .. })
            ),
            "real Cargo semver matcher must confirm 1.5.2 is excluded by \">=1.2, <1.5\", got {:?}",
            item.outcome
        );
    }

    /// Issue #1578 gap 2: an oversized requirement must be rejected as `Unfixable` before ever
    /// reaching `compile_bounded_requirement` — `PanicsIfCompiledFormatter` panics if that call is
    /// made, so this fails loudly (not just with the wrong outcome) if the gate is removed or
    /// reordered after the `compile_bounded_requirement` call.
    #[test]
    fn test_classify_oversized_requirement_never_reaches_compile_requirement() {
        let oversized_req = "1".repeat(MAX_REQUIREMENT_LEN + 1);
        let dep = dep("foo", &oversized_req);
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &PanicsIfCompiledFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        // #1578 S1: `OversizedRequirement`, not `UnsupportedRequirementShape` — the matcher
        // (which would have panicked) never ran, so this is a size-based fail-closed guard, not
        // a confirmed exclusion.
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::OversizedRequirement { .. })
            ),
            "got {:?}",
            item.outcome
        );
        assert_eq!(
            item.target(),
            Some(&deps_core::ConcreteVersion::from("1.5.2")),
            "an oversized-requirement-unfixable item must report the rejected fix target (#1614)"
        );
    }

    /// #1578 M2: exactly at `MAX_REQUIREMENT_LEN` must NOT be treated as oversized
    /// (`requirement_is_oversized` uses strict `>`) — falls through to the real matcher, which
    /// confirms the compound requirement excludes the fix (`UnsupportedRequirementShape`, not
    /// `OversizedRequirement`).
    #[test]
    fn test_classify_requirement_at_exact_cap_is_not_oversized() {
        let head = ">=1.2,";
        let tail = " <1.5";
        let padding = " ".repeat(MAX_REQUIREMENT_LEN - head.len() - tail.len());
        let requirement = format!("{head}{padding}{tail}");
        assert_eq!(requirement.len(), MAX_REQUIREMENT_LEN);

        let dep = dep("foo", &requirement);
        let dv = verified_dv("1.5.2");
        let analysis = test_analysis(cached_with("foo", "1.5.2"), HashSet::new());
        let item = classify_vulnerable_dependency(
            &dep,
            &dv,
            None,
            "foo",
            &analysis,
            &deps_engine::setup::CargoFormatter,
            EcosystemId::Cargo,
            &IgnoreRules::empty(),
        );
        assert!(
            matches!(
                item.outcome,
                Outcome::Unfixable(UnfixableReason::UnsupportedRequirementShape { .. })
            ),
            "expected the matcher to run at the exact cap and confirm exclusion, got {:?}",
            item.outcome
        );
    }
}
