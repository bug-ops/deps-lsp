//! Shared parse -> lockfile -> fetch -> OSV pipeline.
//!
//! Extracted out of [`crate::report::check_manifest`] (spec 062) so `deps-cli update` (spec
//! 068, #1329) can reuse the identical classification inputs `check` builds, without
//! duplicating any of it.
//!
//! [`check_manifest`](crate::report::check_manifest) is now [`analyze_manifest`] followed by
//! `generate_diagnostics`/`to_finding` — no behavior change to `check` itself.

use deps_core::licenses::LicensePolicy;
use deps_core::lsp_helpers::{
    CooldownDisposition, DependencyOutcomes, LatestVerdict, PackageVersions, RequirementGate,
    cooldown_disposition, latest_verdict,
};
use deps_core::osv::{LatestStatusMap, VulnerabilityMap};
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, FreshnessSettings, GossipFindings, LicenseSource,
    PackageName, PublishTime, VersionData,
};
use deps_engine::classify::diff::{
    merge_deprecations_after_fetch, merge_no_comparable_versions_after_fetch,
};
use deps_engine::classify::fetch::{
    apply_fetch_outcomes, fetch_latest_versions_parallel, prepare_fetch,
};
use deps_engine::classify::license::prefetch_tier3_licenses;
use deps_engine::classify::osv::{build_latest_check_targets, build_scan_targets};
use deps_engine::classify::resolved::load_resolved_versions;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::report::{CheckContext, CheckError};

/// Ceiling on the OSV scan timeout, independent of the configured `fetch_timeout_secs` —
/// mirrors `deps-lsp`'s `document::osv_scan::OSV_SCAN_TIMEOUT_CEILING_SECS` and
/// `report.rs`'s own (now-removed) copy of the same constant: the shared `reqwest` client
/// behind [`deps_core::HttpCache`] already imposes its own client-wide 30s timeout, so a
/// longer per-phase timeout would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

/// Which of [`analyze_manifest`]'s independent, network-touching phases (beyond the mandatory
/// registry version fetch) actually run.
///
/// Code review finding 6: before this type existed, `analyze_manifest` always ran both the
/// tier-3 license prefetch and the OSV scan, even for `deps-cli update`'s default mode — which
/// reads neither `ManifestAnalysis::licenses` nor `ManifestAnalysis::vulnerabilities` at all —
/// wasting a network round trip per dependency and burning shared rate-limit budgets (e.g.
/// Swift's 60 req/h unauthenticated GitHub budget) on every plain `deps-cli update` run.
///
/// # Examples
///
/// ```
/// use deps_cli::analyze::AnalysisScope;
///
/// let update_default_mode = AnalysisScope::update_default();
/// assert!(!update_default_mode.licenses);
/// assert!(!update_default_mode.vulnerabilities);
/// assert!(update_default_mode.gossip);
/// assert!(update_default_mode.cooldown_fallback);
///
/// let update_security_only = AnalysisScope::vulnerabilities_only();
/// assert!(!update_security_only.licenses);
/// assert!(update_security_only.vulnerabilities);
/// assert!(!update_security_only.gossip);
/// assert!(!update_security_only.cooldown_fallback);
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent phase-gate knob (license/vulnerability/gossip/\
              cooldown-fallback), not overlapping state a two-variant enum could express \
              more clearly — mirrors StubFormatter's identical rationale"
)]
#[derive(Debug, Clone, Copy)]
pub struct AnalysisScope {
    /// Whether to run the tier-3 license prefetch (Dart/Swift/Gradle/Deno — a no-op for every
    /// other ecosystem regardless of this flag). Only [`crate::report::check_manifest`] reads
    /// license data; no `update` mode does.
    pub licenses: bool,
    /// Whether to run the OSV vulnerability scan, subject to the existing
    /// `diagnostics.vulnerabilities_enabled`/`network.offline` policy gates either way. `check`
    /// and `update --security-only` both need this; `update`'s default mode does not.
    pub vulnerabilities: bool,
    /// Whether to run the spec 074 GOSSIP prefetch, subject to the existing `[gossip].enabled`
    /// policy gate either way (issue #1521 item 4). **Deliberately independent of
    /// `[freshness].enabled`** — spec 074 FR-002/FR-009/NFR-004 enumerate GOSSIP's gates
    /// exhaustively (`[gossip].enabled`, not offline, a `deps_dev_system`-covered ecosystem, a
    /// public-registry-content source) and never include freshness; GOSSIP and the local
    /// `freshness.cooldown_secs` heuristic are deliberately independent signals (NFR-004),
    /// mirroring `deps-lsp`'s own `run_gossip_prefetch`, which likewise gates only on
    /// `is_gossip_enabled()`/offline. `false` under `update --security-only`: that mode's fix
    /// target comes from the advisory's `recommended_fix()`, never the freshness/GOSSIP-filtered
    /// registry pick (FR-014), so the prefetch's result would never be read — an avoidable
    /// network call.
    pub gossip: bool,
    /// Whether to run spec 075 FR-010's extra, uncapped OSV round verifying every occurrence's
    /// cooldown-fallback candidate. Only `true` for `update`'s default mode: `check` never
    /// writes a fallback candidate (spec 075 §1 Out of Scope) and `--security-only`'s fix
    /// target always comes from the advisory, never a freshness/GOSSIP-filtered pick — so
    /// neither reads [`ManifestAnalysis::fallback_status`], and running this round for them
    /// would be a wasted network call (NFR-004).
    pub cooldown_fallback: bool,
}

impl AnalysisScope {
    /// Both phases run — [`crate::report::check_manifest`]'s scope, and the default for any
    /// caller that reads everything `ManifestAnalysis` can carry.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            licenses: true,
            vulnerabilities: true,
            gossip: true,
            cooldown_fallback: false,
        }
    }

    /// Only the OSV scan runs — `deps-cli update --security-only`'s scope. `gossip` is `false`
    /// (issue #1521 item 4): see [`Self::gossip`]'s doc.
    #[must_use]
    pub const fn vulnerabilities_only() -> Self {
        Self {
            licenses: false,
            vulnerabilities: true,
            gossip: false,
            cooldown_fallback: false,
        }
    }

    /// Neither the license nor the vulnerability-classification phase runs —
    /// `deps-cli update`'s default-mode scope. Named for that one caller (not `none()`,
    /// its pre-#1517 name) since [`analyze_manifest`] still unconditionally runs the OSV
    /// **latest-check** (issue #1517) regardless of this scope: `update`'s default mode
    /// must never write a flagged/unverified `latest` into the manifest, so that check is
    /// not one of the two phases this scope can opt out of. `gossip` is `true`: default mode
    /// is exactly the consumer spec 074's cooldown filter exists for. `cooldown_fallback` is
    /// `true`: spec 075's fallback-candidate OSV round.
    #[must_use]
    pub const fn update_default() -> Self {
        Self {
            licenses: false,
            vulnerabilities: false,
            gossip: true,
            cooldown_fallback: true,
        }
    }
}

/// One manifest's fully-assembled classification inputs.
///
/// The parsed dependencies, every lock-file/registry/OSV-derived map [`VersionData`]
/// borrows, and the two registry/license-fetch incompleteness signals `check`/`update` both
/// need for their own exit-code decisions.
///
/// Built by [`analyze_manifest`]; call [`Self::version_data`] to get the borrowed
/// [`VersionData`] view [`deps_core::Ecosystem::generate_diagnostics`] and
/// [`deps_core::edit::collect_update_edits`]/[`deps_core::edit::plan_vulnerability_fix`] all
/// take.
pub struct ManifestAnalysis {
    /// The parsed manifest.
    pub parse_result: Box<dyn deps_core::ParseResult>,
    /// The manifest's file URI (derived from the path `analyze_manifest` was given).
    pub uri: url::Url,
    /// The instant this analysis ran, captured once (fix-cycle item 9/security L3).
    ///
    /// `analyze_manifest`'s own fallback-candidate OSV round (FR-010) and `deps-cli update`'s
    /// planner (`plan_updates`) must evaluate `cooldown_disposition` against the SAME `now` —
    /// two independent `PublishTime::now()` calls straddling the OSV round could, under
    /// backward clock skew, let the planner see a dependency as `Blocked` that the OSV-gating
    /// pass never verified a fallback for (`fallback_status` would then read `None`, degrading
    /// to `NotApplicable` and writing an unverified fallback). Callers building `plan_updates`'s
    /// `now` argument should use this field rather than calling `PublishTime::now()` again.
    pub now: PublishTime,
    /// The manifest's ecosystem.
    pub ecosystem_id: EcosystemId,
    /// Latest known versions and full version lists from the registry.
    pub cached_versions: HashMap<PackageName, deps_core::lsp_helpers::PackageVersions>,
    /// Versions actually resolved in the lock file.
    pub resolved_versions: HashMap<PackageName, ConcreteVersion>,
    /// Every lock-file-resolved version for a package name, when more than one is retained
    /// (issue #649).
    pub resolved_version_candidates: HashMap<PackageName, Vec<ConcreteVersion>>,
    /// Yanked/deprecation/fetch-failure/no-comparable-versions findings from the fetch.
    pub outcomes: DependencyOutcomes,
    /// OSV scan results, when the scan ran (enabled and not offline).
    pub vulnerabilities: Option<VulnerabilityMap>,
    /// Phase B's per-key "latest" check result (issue #1517), when the check ran (enabled and
    /// not offline) — populated regardless of `AnalysisScope`, since `update`'s default mode
    /// needs this even though it opts out of both `licenses` and `vulnerabilities`. See
    /// [`deps_core::osv::LatestStatusMap`] for the map's fail-closed-on-absence contract.
    pub latest_status: Option<LatestStatusMap>,
    /// Spec 075 FR-010: a separate OSV verdict map for every occurrence's cooldown-fallback
    /// candidate, keyed identically to [`Self::latest_status`] but populated from a
    /// fallback-substituted version view — NEVER merged into [`Self::latest_status`], since
    /// [`LatestStatusMap`] has no version key and a merge would silently overwrite `latest`'s
    /// own verdict. `None` when [`AnalysisScope::cooldown_fallback`] is `false`, the OSV
    /// check is disabled/offline, or no dependency has a stored fallback candidate to verify
    /// (NFR-004: this round costs zero extra network calls in that case).
    pub fallback_status: Option<LatestStatusMap>,
    /// Spec 075 FR-010's fallback-substituted view of [`Self::cached_versions`] (only
    /// `latest` swapped for each dependency's stored cooldown-fallback candidate, when one
    /// exists) — the exact view this OSV round already built to verify a fallback candidate
    /// against, retained here so `deps-cli update`'s planner (`plan_updates`) can reuse it
    /// instead of recomputing an identical `cooldown_fallback_view` from scratch (issue
    /// #1551 finding 3). Same gate as [`Self::fallback_status`]: `None` when
    /// [`AnalysisScope::cooldown_fallback`] is `false`, or no dependency's [`cooldown_disposition`]
    /// actually differs from [`Self::cached_versions`] (NFR-004: nothing to substitute).
    pub cooldown_fallback_view: Option<HashMap<PackageName, PackageVersions>>,
    /// Already-computed GOSSIP findings (spec 074/075 FR-006), retained here instead of being
    /// discarded after the registry fetch — fixes `check`'s dead `with_gossip_prefetch` branch
    /// (`ManifestAnalysis::version_data` never called it before this field existed), so `check`
    /// and `update` consult the same [`deps_core::lsp_helpers::cooldown_disposition`] precedence
    /// end to end. Empty when GOSSIP is disabled/offline/unsupported, never absent.
    pub gossip_findings: HashMap<PackageName, deps_core::GossipFindings>,
    /// License data backfilled from the registry fetch (tier 1) and the tier-3 prefetch,
    /// keyed by raw package name.
    pub licenses: HashMap<PackageName, Vec<String>>,
    /// The resolved SPDX allow/deny license policy for this run.
    pub license_policy: LicensePolicy,
    /// How license strings were sourced (registry-declared SPDX vs. free text).
    pub license_source: LicenseSource,
    /// The [`deps_core::NetworkMode`] set for this run.
    pub network: deps_core::NetworkMode,
    /// Raw package names whose registry fetch errored or timed out (`FetchResult::fetch_failed`,
    /// captured before [`apply_fetch_outcomes`] consumes it) — the two-signal input
    /// `deps-cli update --security-only`'s `Unfixable` classification needs (FR-011): a
    /// dependency is `Unfixable` when it appears here **or** has no [`Self::cached_versions`]
    /// entry.
    pub fetch_failed: HashSet<PackageName>,
    /// Whether at least one dependency's *version* registry fetch failed while not offline.
    pub registry_unreachable: bool,
    /// Whether at least one dependency's tier-3 license fetch timed out while not offline.
    pub license_fetch_incomplete: bool,
}

impl ManifestAnalysis {
    /// The borrowed [`VersionData`] view over this analysis's maps.
    #[must_use]
    pub fn version_data(&self) -> VersionData<'_> {
        let mut version_data = VersionData::new(&self.cached_versions, &self.resolved_versions)
            .with_resolved_version_candidates(&self.resolved_version_candidates)
            .with_outcomes(&self.outcomes)
            .with_ecosystem(self.ecosystem_id)
            .with_network(self.network)
            .with_license_source(self.license_source)
            .with_license_policy(&self.license_policy)
            .with_license_prefetch(&self.licenses)
            .with_gossip_prefetch(&self.gossip_findings);
        if let Some(vulnerabilities) = self.vulnerabilities.as_ref() {
            version_data = version_data.with_vulnerabilities(vulnerabilities);
        }
        if let Some(latest_status) = self.latest_status.as_ref() {
            version_data = version_data.with_latest_status(latest_status);
        }
        version_data
    }

    /// Whether any [`deps_core::lsp_helpers::RequirementStatus::Outdated`] dependency actually
    /// in scope for this run's plan (per `package_filter`/`ignore_rules`, issue #1517 critique
    /// S4) came back [`LatestVerdict::Unverified`] (issue #1517) — a transient OSV
    /// failure/timeout, or the check never having run at all despite being enabled. Callers
    /// (`deps-cli update`'s default mode) treat this the same as
    /// [`Self::registry_unreachable`]: abort the whole run rather than silently omitting just
    /// the affected dependency from the plan, since an unverifiable check must never be
    /// mistaken for a clean one.
    ///
    /// `package_filter` is matched via `crate::update::is_requested`, and `ignore_rules` via
    /// [`crate::update::ignore::IgnoreRules::matches_name`] (a name-only match, deliberately not
    /// [`crate::update::ignore::IgnoreRules::skip_reason`]'s kind-scoped one: this abort-check
    /// runs before any concrete `current`/target pair exists to classify an [`UpdateKind`] from).
    /// A dependency this widens past scope (a kind-scoped ignore rule that would not actually
    /// have matched this update) is not a regression: `deps_core::edit::collect_update_candidates`
    /// applies the exact same [`latest_verdict`] gate per-candidate independently, so an
    /// unverified `latest` for it still surfaces as `Skipped(NotSafelyEditable(LatestUnverified))`
    /// in the final plan (a nonzero exit) rather than silently vanishing — this check only
    /// controls whether the *whole run* aborts early with a clearer message, not whether the
    /// unverified dependency itself is ever caught.
    ///
    /// [`UpdateKind`]: deps_core::edit::UpdateKind
    #[must_use]
    pub fn has_unverified_latest_check(
        &self,
        formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
        package_filter: &[String],
        ignore_rules: &crate::update::ignore::IgnoreRules,
    ) -> bool {
        let vuln_keys = deps_core::osv::vulnerability_keys(
            self.parse_result.as_ref(),
            &self.resolved_versions,
            Some(&self.resolved_version_candidates),
            formatter,
            self.ecosystem_id,
        );
        self.parse_result.dependencies().into_iter().any(|dep| {
            let normalized_name = formatter.normalize_package_name(dep.name());
            if !crate::update::is_requested(package_filter, &normalized_name, formatter)
                || ignore_rules.matches_name(&normalized_name)
            {
                return false;
            }
            let Some(latest) = self
                .cached_versions
                .get(normalized_name.as_str())
                .or_else(|| self.cached_versions.get(dep.name()))
                .map(|v| &v.latest)
            else {
                return false;
            };
            let Some(version_req) = dep.version_requirement() else {
                return false;
            };
            if formatter.requirement_status_for(dep, version_req, latest)
                != deps_core::lsp_helpers::RequirementStatus::Outdated
            {
                return false;
            }
            matches!(
                latest_verdict(
                    self.latest_status.as_ref(),
                    dep,
                    Some(&vuln_keys),
                    &normalized_name,
                    latest.as_str(),
                    formatter,
                ),
                LatestVerdict::Unverified
            )
        })
    }
}

/// Builds a fallback view of `cached_versions`: every package whose [`cooldown_disposition`]
/// is `Blocked { fallback: Some(_), .. }` has its `latest` swapped for the stored
/// [`deps_core::lsp_helpers::CooldownFallback`] candidate, everything else left unchanged.
///
/// Feeds both spec 075 FR-010's OSV verification round (this module) and FR-007's unified
/// planner pipeline (`crate::update`) the exact same substituted view, via
/// [`deps_core::edit::collect_update_candidates`]/[`build_latest_check_targets`] reading
/// `PackageVersions::latest` as they always do — so a fallback candidate is verified and
/// planned against identically, with no separate code path to drift out of sync.
pub(crate) fn cooldown_fallback_view(
    cached_versions: &HashMap<PackageName, PackageVersions>,
    gossip_prefetch: Option<&HashMap<PackageName, GossipFindings>>,
    freshness: FreshnessSettings,
    now: PublishTime,
) -> HashMap<PackageName, PackageVersions> {
    cached_versions
        .iter()
        .map(|(name, versions)| {
            let mut substituted = versions.clone();
            if let CooldownDisposition::Blocked {
                fallback: Some(fallback),
                ..
            } = cooldown_disposition(versions, name, freshness, gossip_prefetch, now)
            {
                substituted.latest = fallback.version.clone();
            }
            (name.clone(), substituted)
        })
        .collect()
}

/// Parses `content`, resolves in-use/lock-file versions, and fetches latest registry versions.
///
/// Per `scope`, also runs the tier-3 license prefetch and/or an OSV scan (each additionally
/// subject to its own existing policy/offline gates either way).
///
/// The shared prefix [`crate::report::check_manifest`] and `deps-cli update` both need,
/// extracted verbatim from `check_manifest`'s former body (spec 068 T007). `scope` exists so
/// `update`'s default mode (which reads neither `licenses` nor `vulnerabilities`) does not pay
/// for phases nothing in its plan consumes — see [`AnalysisScope`]'s doc (code review finding
/// 6).
///
/// # Errors
///
/// Returns [`CheckError::InvalidPath`] if `manifest_path` cannot be represented as a file
/// URI, or [`CheckError::Parse`] if `content` fails to parse as this ecosystem's manifest
/// format.
pub async fn analyze_manifest(
    ecosystem: &Arc<dyn Ecosystem>,
    manifest_path: &Path,
    content: &str,
    ctx: &CheckContext,
    scope: AnalysisScope,
) -> Result<ManifestAnalysis, CheckError> {
    // Fix-cycle item 9/security L3: captured once, threaded through this function's own
    // fallback-OSV-round gate below and stored on the returned `ManifestAnalysis` for
    // `plan_updates` to reuse — never a second independent `PublishTime::now()` call.
    let now = PublishTime::now();
    let uri = crate::report::path_to_uri(manifest_path).ok_or_else(|| CheckError::InvalidPath {
        path: manifest_path.to_path_buf(),
    })?;
    let parse_result = deps_core::parse_manifest_blocking(ecosystem, content, &uri)
        .await
        .map_err(|source| CheckError::Parse {
            path: manifest_path.to_path_buf(),
            source,
        })?;
    let formatter = ecosystem.formatter();
    let ecosystem_id = ecosystem.ecosystem_id();

    // A one-shot check has no prior in-memory resolved-version state to protect from a
    // transient parse failure the way `deps-lsp` does, so the reload-ok signal (issue
    // #1407) isn't needed here.
    let (resolved_versions, resolved_version_candidates) =
        load_resolved_versions(&uri, &ctx.lockfile_cache, ecosystem.as_ref())
            .await
            .into_maps();

    let prep = prepare_fetch(
        parse_result.as_ref(),
        formatter,
        ecosystem_id,
        &resolved_versions,
        &resolved_version_candidates,
    );
    let collided_names = prep.collided_names;
    let attempted_names: Vec<PackageName> = prep
        .dep_sources
        .iter()
        .map(|(name, _)| name.clone())
        .collect();

    // Spec 074 FR-002: one batch prefetch per manifest, mirroring `prefetch_tier3_licenses`'s
    // own "prefetch once, thread the result through" shape below. `None` when
    // `!ctx.policy.gossip.enabled` short-circuits `fetch_gossip_findings_batch` before any
    // HTTP call (FR-009) — construction of `ctx.deps_dev` itself is unconditional (FR-001).
    // Issue #1521 item 4: also `None` under `scope.gossip == false` (`update --security-only`,
    // whose fix target never reads a GOSSIP-filtered `latest` at all) — see `AnalysisScope::gossip`'s
    // doc for why this is *not* additionally gated on `ctx.policy.freshness.enabled`.
    let network = ctx.policy.network.mode();
    let gossip_client = (scope.gossip && ctx.policy.gossip.enabled).then_some(&ctx.deps_dev);
    let gossip_findings = deps_core::lsp_helpers::fetch_gossip_findings_batch(
        ecosystem_id,
        parse_result.as_ref(),
        formatter,
        network,
        gossip_client,
    )
    .await;

    let fetch_result = fetch_latest_versions_parallel(
        ecosystem.registry(),
        prep.dep_sources,
        &prep.in_use,
        None,
        ctx.policy.freshness.to_freshness(),
        ctx.policy.cache.fetch_timeout_secs,
        ctx.policy.cache.max_concurrent_fetches,
        &prep.selection_context,
        Some(&gossip_findings),
    )
    .await;
    // `fetch_failed` (genuine failures only), not `failure_summary`'s count, which also
    // includes not-found lookups — using that here made a typo'd dependency exit 2 every run.
    let registry_unreachable = network.is_online() && !fetch_result.fetch_failed.is_empty();
    // Captured before `apply_fetch_outcomes` consumes `fetch_result.fetch_failed` below —
    // `deps-cli update --security-only`'s FR-011 two-signal `Unfixable` rule needs the raw
    // set independently of the yanked/deprecation-merged `DependencyOutcomes`.
    let fetch_failed: HashSet<PackageName> = fetch_result.fetch_failed.keys().cloned().collect();

    let mut outcomes = DependencyOutcomes::new();
    let fetched_names: Vec<PackageName> = fetch_result.versions.keys().cloned().collect();
    apply_fetch_outcomes(
        &mut outcomes,
        fetch_result.yanked_versions,
        fetch_result.fetch_failed,
        collided_names,
        formatter,
    );
    merge_deprecations_after_fetch(
        &mut outcomes,
        &fetched_names,
        fetch_result.deprecations,
        formatter,
    );
    merge_no_comparable_versions_after_fetch(
        &mut outcomes,
        &attempted_names,
        fetch_result.no_comparable_versions,
        formatter,
    );
    let cached_versions = fetch_result.versions;
    // Tier-1 license backfill (issue #660/#661 precedent): populated for native-list
    // ecosystems (PyPI, Composer) whose registry response carries a license field.
    let mut licenses = fetch_result.licenses;

    // Hoisted so both the tier-3 gate below and the returned `ManifestAnalysis` share one
    // computed policy (issue #1133 critic M1).
    let license_policy = ctx.policy.license_policy.to_policy();

    // Tier-3 license prefetch (issue #1133, populated for Dart/Swift/Gradle/Deno, a no-op
    // for every other ecosystem — see `deps_engine::classify::license`'s doc) and the OSV
    // scan are independent (OSV never reads licenses) and both make network round trips, so
    // they run concurrently via `tokio::join!` rather than sequentially (critic M2) —
    // mirrors `deps-lsp`, which spawns both as separate concurrent tasks.
    //
    // Only `!offline` is gated here — the non-empty-`license_policy` check (critic M1) is
    // enforced *inside* `prefetch_tier3_licenses` itself (code-review finding #3), not
    // re-derived at this call site, so it can't be silently forgotten by a future caller:
    // `licenses`' only consumer in this crate is `apply_license_policy_rule`, a no-op when
    // no policy is configured, so with the default (empty) policy this call would otherwise
    // issue N network round trips for a result nothing reads — burning Swift's
    // unauthenticated 60 req/h GitHub budget among others for nothing. `scope.licenses` adds a
    // second, caller-declared reason to skip this entirely (code review finding 6) — no
    // `update` mode ever reads `ManifestAnalysis::licenses`.
    let run_tier3_prefetch = scope.licenses && network.is_online();
    let tier3_license_fetch = async {
        if run_tier3_prefetch {
            prefetch_tier3_licenses(
                ecosystem.as_ref(),
                parse_result.as_ref(),
                &resolved_versions,
                &resolved_version_candidates,
                &license_policy,
                ctx.policy.cache.fetch_timeout_secs,
                ctx.policy.cache.max_concurrent_fetches,
            )
            .await
        } else {
            deps_engine::classify::license::TierThreeLicenseFetch::default()
        }
    };

    // `scope.vulnerabilities` (code review finding 6): `update`'s default mode never reads
    // `ManifestAnalysis::vulnerabilities`, so it declares this scope out entirely rather than
    // paying for a scan nothing consumes.
    let run_osv_scan = scope.vulnerabilities && ctx.policy.osv_checks().is_active();
    let osv_scan = async {
        if run_osv_scan {
            let (targets, skipped) = build_scan_targets(
                parse_result.as_ref(),
                &resolved_versions,
                &resolved_version_candidates,
                formatter,
                ecosystem_id,
            );
            let mut vulns = skipped;
            if !targets.is_empty() {
                let timeout = Duration::from_secs(
                    ctx.policy
                        .cache
                        .fetch_timeout_secs
                        .min(OSV_SCAN_TIMEOUT_CEILING_SECS),
                );
                let scanned = ctx.osv.scan(ecosystem_id, &targets, timeout).await;
                vulns.extend(scanned);
            }
            Some(vulns)
        } else {
            None
        }
    };

    // Issue #1517: unconditional on `scope` (unlike the OSV vulnerability scan above) —
    // `update`'s default mode never reads `ManifestAnalysis::vulnerabilities`, but it always
    // needs to know whether the `latest` it's about to write is itself safe. Still gated on
    // the same `vulnerabilities_enabled`/`!offline` policy every other OSV call respects.
    let run_latest_check = ctx.policy.osv_checks().is_active();

    // Spec 075 FR-010: the fallback-candidate OSV round only fires when
    // `scope.cooldown_fallback` is set AND at least one dependency's `cooldown_disposition`
    // actually found `Blocked { fallback: Some(_) }` — NFR-004: zero extra network calls
    // otherwise (a view identical to `cached_versions` has nothing new to verify).
    let cooldown_fallback_view_map = scope
        .cooldown_fallback
        .then(|| {
            cooldown_fallback_view(
                &cached_versions,
                Some(&gossip_findings),
                ctx.policy.freshness.to_freshness(),
                now,
            )
        })
        .filter(|view| {
            view.iter().any(|(name, v)| {
                cached_versions
                    .get(name)
                    .is_none_or(|c| c.latest != v.latest)
            })
        });
    let run_fallback_check = run_latest_check && cooldown_fallback_view_map.is_some();

    // FR-010: computed once and shared between the latest-status and fallback-status futures
    // below, instead of each independently re-deriving the same map.
    let vuln_keys = (run_latest_check || run_fallback_check).then(|| {
        deps_core::osv::vulnerability_keys(
            parse_result.as_ref(),
            &resolved_versions,
            Some(&resolved_version_candidates),
            formatter,
            ecosystem_id,
        )
    });

    let candidate_tags = vuln_keys.as_ref().map(|keys| {
        deps_engine::classify::osv::candidate_tag_sources(
            parse_result.as_ref(),
            keys,
            formatter,
            ecosystem_id,
        )
    });

    let latest_check = async {
        let (true, Some(vuln_keys), Some(candidate_tags)) = (
            run_latest_check,
            vuln_keys.as_ref(),
            candidate_tags.as_ref(),
        ) else {
            return None;
        };
        let (targets, mut latest_status) = build_latest_check_targets(
            parse_result.as_ref(),
            &cached_versions,
            vuln_keys,
            candidate_tags,
            formatter,
        );
        if !targets.is_empty() {
            let timeout = Duration::from_secs(
                ctx.policy
                    .cache
                    .fetch_timeout_secs
                    .min(OSV_SCAN_TIMEOUT_CEILING_SECS),
            );
            let checked = ctx
                .osv
                .check_candidates(ecosystem_id, &targets, timeout)
                .await;
            latest_status.extend(checked);
        }
        Some(latest_status)
    };

    // Spec 075 FR-010: reuses `build_latest_check_targets` (never a new OSV-request builder)
    // over the fallback-substituted view, so the fallback candidate is verified exactly the
    // way `latest` itself is. Result is a wholly separate map — never merged into
    // `latest_status` (see `ManifestAnalysis::fallback_status`'s doc for why).
    let fallback_check = async {
        let (true, Some(vuln_keys), Some(candidate_tags), Some(view)) = (
            run_fallback_check,
            vuln_keys.as_ref(),
            candidate_tags.as_ref(),
            cooldown_fallback_view_map.as_ref(),
        ) else {
            return None;
        };
        let (targets, mut fallback_status) = build_latest_check_targets(
            parse_result.as_ref(),
            view,
            vuln_keys,
            candidate_tags,
            formatter,
        );
        if !targets.is_empty() {
            let timeout = Duration::from_secs(
                ctx.policy
                    .cache
                    .fetch_timeout_secs
                    .min(OSV_SCAN_TIMEOUT_CEILING_SECS),
            );
            let checked = ctx
                .osv
                .check_candidates(ecosystem_id, &targets, timeout)
                .await;
            fallback_status.extend(checked);
        }
        Some(fallback_status)
    };

    let (tier3_result, vulnerabilities, latest_status, fallback_status): (
        _,
        Option<VulnerabilityMap>,
        _,
        _,
    ) = tokio::join!(tier3_license_fetch, osv_scan, latest_check, fallback_check);

    // Merged (not replaced) alongside the tier-1 backfill above via `entry().or_insert()`,
    // not `extend` (critic nit): the two sources are disjoint today (only Composer
    // populates `FetchResult::licenses`, and it's `RegistryDeclaredSpdx`, never a tier-3
    // ecosystem), but `or_insert` makes the intended precedence explicit — an
    // author-declared tier-1 license must win over a heuristic tier-3 one if that ever
    // stops holding, rather than whichever call happened to run last.
    for (name, license) in tier3_result.licenses {
        licenses.entry(name).or_insert(license);
    }
    // A confirmed tier-3 timeout feeds the same exit-2 "incomplete report" signal a
    // registry-unreachable manifest does, but through its own field (issue #1133 code-review
    // finding #1) — not `registry_unreachable` itself: a Maven Central outage while the
    // version registry is fully reachable is a different failure than an unreachable
    // registry, and a caller inspecting `registry_unreachable` must not be misled into
    // diagnosing the wrong system.
    let license_fetch_incomplete = tier3_result.timed_out > 0;

    Ok(ManifestAnalysis {
        parse_result,
        uri,
        now,
        ecosystem_id,
        cached_versions,
        resolved_versions,
        resolved_version_candidates,
        outcomes,
        vulnerabilities,
        latest_status,
        fallback_status,
        cooldown_fallback_view: cooldown_fallback_view_map,
        gossip_findings,
        licenses,
        license_policy,
        license_source: ecosystem.license_source(),
        network,
        fetch_failed,
        registry_unreachable,
        license_fetch_incomplete,
    })
}

#[cfg(test)]
mod has_unverified_latest_check_tests {
    use super::ManifestAnalysis;
    use crate::update::ignore::IgnoreRules;
    use deps_core::licenses::LicensePolicy;
    use deps_core::lsp_helpers::{DependencyOutcomes, PackageVersions};
    use deps_core::osv::LatestStatusMap;
    use deps_core::parser::DependencySource;
    use deps_core::position::{Position, Range};
    use deps_core::test_util::StubFormatter;
    use deps_core::{Dependency, EcosystemId, PackageName, ParseResult, VersionReq};
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    struct MockDep {
        name: PackageName,
        version_req: VersionReq,
        version_range: Range,
    }
    impl Dependency for MockDep {
        fn name(&self) -> &PackageName {
            &self.name
        }
        fn name_range(&self) -> Range {
            Range::default()
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
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

    struct MockParseResult {
        deps: Vec<MockDep>,
        uri: url::Url,
    }
    impl ParseResult for MockParseResult {
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

    /// One outdated `serde` dependency ("1.0.0" -> cached latest "1.2.0"), with `latest_status`
    /// set to `Some(&empty map)` — the exact pre-phase-B/never-checked state `latest_verdict`
    /// treats as `Unverified` (fail closed).
    fn analysis_with_one_outdated_unverified_dep() -> ManifestAnalysis {
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            PackageName::new("serde"),
            PackageVersions::latest_only("1.2.0"),
        );

        ManifestAnalysis {
            parse_result: Box::new(MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: VersionReq::new("1.0.0"),
                    version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
                }],
                uri: uri.clone(),
            }),
            uri,
            now: deps_core::PublishTime::now(),
            ecosystem_id: EcosystemId::Cargo,
            cached_versions,
            resolved_versions: HashMap::new(),
            resolved_version_candidates: HashMap::new(),
            outcomes: DependencyOutcomes::new(),
            vulnerabilities: None,
            latest_status: Some(LatestStatusMap::new()),
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

    /// Baseline: an unfiltered, unignored outdated dependency with no OSV verdict for its
    /// cached latest is reported as unverified.
    #[test]
    fn true_for_outdated_unverified_dependency_in_scope() {
        let analysis = analysis_with_one_outdated_unverified_dep();
        assert!(analysis.has_unverified_latest_check(
            &StubFormatter::DEFAULT,
            &[],
            &IgnoreRules::empty(),
        ));
    }

    /// Issue #1517 critique S4: a `--package` filter that does not name the unverified
    /// dependency must exclude it from this abort-check, the same scoping
    /// `deps_cli::update::is_requested` applies to the actual plan.
    #[test]
    fn false_when_package_filter_excludes_the_dependency() {
        let analysis = analysis_with_one_outdated_unverified_dep();
        assert!(!analysis.has_unverified_latest_check(
            &StubFormatter::DEFAULT,
            &["some-other-package".to_string()],
            &IgnoreRules::empty(),
        ));
    }

    /// A `--package` filter that does name the dependency still reports it.
    #[test]
    fn true_when_package_filter_names_the_dependency() {
        let analysis = analysis_with_one_outdated_unverified_dep();
        assert!(analysis.has_unverified_latest_check(
            &StubFormatter::DEFAULT,
            &["serde".to_string()],
            &IgnoreRules::empty(),
        ));
    }

    /// Issue #1517 critique S4: an `[update].ignore` rule naming the dependency must exclude
    /// it from this abort-check too, regardless of the rule's `update_types` scope (a name-only
    /// match — see `has_unverified_latest_check`'s own doc for why it does not attempt
    /// `IgnoreRules::skip_reason`'s kind-scoped match here).
    #[test]
    fn false_when_an_ignore_rule_names_the_dependency() {
        let analysis = analysis_with_one_outdated_unverified_dep();
        let rules = IgnoreRules::new(
            vec![crate::config::IgnoreRule {
                name: "serde".to_string(),
                update_types: None,
            }],
            &StubFormatter::DEFAULT,
        );
        assert!(!analysis.has_unverified_latest_check(&StubFormatter::DEFAULT, &[], &rules));
    }
}
