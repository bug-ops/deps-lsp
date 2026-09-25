//! Shared parse -> lockfile -> fetch -> OSV pipeline.
//!
//! Extracted out of [`crate::report::check_manifest`] (spec 062) so `deps-cli update` (spec
//! 068, #1329) can reuse the identical classification inputs `check` builds, without
//! duplicating any of it.
//!
//! [`check_manifest`](crate::report::check_manifest) is now [`analyze_manifest`] followed by
//! `generate_diagnostics`/`to_finding` — no behavior change to `check` itself.

use deps_core::licenses::LicensePolicy;
use deps_core::lsp_helpers::DependencyOutcomes;
use deps_core::osv::VulnerabilityMap;
use deps_core::{ConcreteVersion, Ecosystem, EcosystemId, LicenseSource, PackageName, VersionData};
use deps_engine::classify::diff::{
    merge_deprecations_after_fetch, merge_no_comparable_versions_after_fetch,
};
use deps_engine::classify::fetch::{
    apply_fetch_outcomes, composer_minimum_stability, dedup_dependencies_by_source,
    fetch_latest_versions_parallel,
};
use deps_engine::classify::license::prefetch_tier3_licenses;
use deps_engine::classify::osv::build_scan_targets;
use deps_engine::classify::resolved::{collect_in_use_versions, load_resolved_versions};
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
/// let update_default_mode = AnalysisScope::none();
/// assert!(!update_default_mode.licenses);
/// assert!(!update_default_mode.vulnerabilities);
///
/// let update_security_only = AnalysisScope::vulnerabilities_only();
/// assert!(!update_security_only.licenses);
/// assert!(update_security_only.vulnerabilities);
/// ```
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
}

impl AnalysisScope {
    /// Both phases run — [`crate::report::check_manifest`]'s scope, and the default for any
    /// caller that reads everything `ManifestAnalysis` can carry.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            licenses: true,
            vulnerabilities: true,
        }
    }

    /// Only the OSV scan runs — `deps-cli update --security-only`'s scope.
    #[must_use]
    pub const fn vulnerabilities_only() -> Self {
        Self {
            licenses: false,
            vulnerabilities: true,
        }
    }

    /// Neither phase runs — `deps-cli update`'s default-mode scope.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            licenses: false,
            vulnerabilities: false,
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
    /// License data backfilled from the registry fetch (tier 1) and the tier-3 prefetch,
    /// keyed by raw package name.
    pub licenses: HashMap<PackageName, Vec<String>>,
    /// The resolved SPDX allow/deny license policy for this run.
    pub license_policy: LicensePolicy,
    /// How license strings were sourced (registry-declared SPDX vs. free text).
    pub license_source: LicenseSource,
    /// Whether `network.offline` was set for this run.
    pub offline: bool,
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
            .with_offline(self.offline)
            .with_license_source(self.license_source)
            .with_license_policy(&self.license_policy)
            .with_license_prefetch(&self.licenses);
        if let Some(vulnerabilities) = self.vulnerabilities.as_ref() {
            version_data = version_data.with_vulnerabilities(vulnerabilities);
        }
        version_data
    }
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

    let (dep_sources, collided_names) =
        dedup_dependencies_by_source(parse_result.as_ref(), formatter);
    let in_use = collect_in_use_versions(
        parse_result.as_ref(),
        &resolved_versions,
        &resolved_version_candidates,
        formatter,
        ecosystem_id,
    );
    let minimum_stability = composer_minimum_stability(parse_result.as_ref());
    let attempted_names: Vec<PackageName> = dep_sources.keys().cloned().collect();

    let fetch_result = fetch_latest_versions_parallel(
        ecosystem.registry(),
        dep_sources.into_iter().collect(),
        &in_use,
        None,
        ctx.policy.freshness.to_settings(),
        ctx.policy.cache.fetch_timeout_secs,
        ctx.policy.cache.max_concurrent_fetches,
        minimum_stability.as_deref(),
    )
    .await;
    // `failed_count` also counts not-found lookups, which aren't evidence of an unreachable
    // registry — using it here made any repo with one typo'd dependency exit 2 every run.
    let registry_unreachable = !ctx.policy.network.offline && !fetch_result.fetch_failed.is_empty();
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
    let run_tier3_prefetch = scope.licenses && !ctx.policy.network.offline;
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
    let run_osv_scan = scope.vulnerabilities
        && ctx.policy.diagnostics.vulnerabilities_enabled
        && !ctx.policy.network.offline;
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

    let (tier3_result, vulnerabilities): (_, Option<VulnerabilityMap>) =
        tokio::join!(tier3_license_fetch, osv_scan);

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
        ecosystem_id,
        cached_versions,
        resolved_versions,
        resolved_version_candidates,
        outcomes,
        vulnerabilities,
        licenses,
        license_policy,
        license_source: ecosystem.license_source(),
        offline: ctx.policy.network.offline,
        fetch_failed,
        registry_unreachable,
        license_fetch_incomplete,
    })
}
