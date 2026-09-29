//! Vulnerability-scan target construction and fix-target-verification decision logic.
//!
//! Pure classification helpers extracted from `deps-lsp`'s `document/osv_scan.rs`: deciding
//! which dependencies to scan and how to resolve a recommended fix target's verification
//! status. The orchestration around these decisions — the phase-A/await/phase-B-commit shape,
//! the mid-flight staleness guard, and the `OsvClient` network calls themselves — stays in
//! `deps-lsp`'s `run_osv_scan_phase_a`/`run_osv_phase_b_and_commit`/
//! `run_osv_fix_target_verification`, since it owns a progress/staleness lifecycle this crate
//! must not know about (issue #1059).

use deps_core::ConcreteVersion;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::lsp_helpers::{has_unqueryable_resolved_pin, resolve_in_use_version};
use std::collections::HashMap;

/// Builds the OSV scan targets for one manifest's dependencies, applying the
/// version-selection policy from `architecture.md` §3 in order:
///
/// 0. Skip unless `formatter.source_is_public_registry_content(&dep.source())` — a patched
///    git/path fork must never be flagged with a CVE for a version it does
///    not actually contain, and neither must a genuinely different private registry's
///    dependency (only a verified crates.io mirror counts as public-registry content,
///    F1/F1b).
/// 1. Use the lock-file-resolved version if present.
/// 2. Otherwise use the declared requirement, if it is already concrete.
/// 3. Otherwise skip — querying a fabricated version is a silent false
///    negative, which is worse than not scanning at all.
///
/// **Go exception** (#228 follow-up, unified with #235's
/// [`deps_core::lsp_helpers::RequirementResolution::manifest_requirement_is_resolved_version`]):
/// step 1 is skipped entirely for a dependency whose manifest requirement is
/// itself the resolved version (a Go `require`-directive dependency), going
/// straight to step 2. Go's `go.mod` `require` line is already an exact
/// pinned version, never a range, unlike Cargo/npm where the manifest is a
/// range and the lockfile holds the pin. go.sum-derived `resolved_versions`
/// is unreliable here: go.sum is a checksum ledger that `go get`/`go build`
/// only ever append to (only `go mod tidy` prunes it), so its
/// last-occurrence-wins parse can surface a version still recorded in the
/// file but no longer selected by Go's MVS — silently querying OSV against
/// the wrong version. Routing through the formatter hook (rather than a bare
/// `ecosystem == EcosystemId::Go` check) also excludes Go's `exclude`/
/// `replace` directive pseudo-dependencies, whose `version_requirement()` is
/// not an in-use version.
///
/// Every dependency that does **not** become a [`deps_core::osv::ScanTarget`]
/// gets an explicit [`deps_core::osv::ScanOutcome::Skipped`] entry in the
/// returned map instead of silently vanishing (critique C1) — absence from
/// [`deps_core::osv::VulnerabilityMap`] must never happen for an input this
/// function considered.
///
/// Each dependency's map/target key comes from
/// [`deps_core::osv::vulnerability_keys`] rather than a bare
/// `formatter.normalize_package_name(dep.name())` (#394 S2): when two
/// occurrences of one name resolve to different in-use versions (or mix a
/// registry source with a git/path fork), their keys are disambiguated so
/// one occurrence's OSV result never overwrites another's in the shared
/// [`deps_core::osv::VulnerabilityMap`]. Occurrences that share both a name
/// and an identical in-use version keep the plain key and are scanned once —
/// a dedup, not a gap, since the OSV result would be identical either way.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::test_util::stub_parse_result_with_dependencies;
/// use deps_core::{ConcreteVersion, EcosystemId, PackageName};
/// use deps_engine::classify::osv::build_scan_targets;
/// use std::collections::HashMap;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// // A single registry-sourced dependency ("dep-0"), with a lock-file-resolved version —
/// // step 1 of the ladder above.
/// let parsed = stub_parse_result_with_dependencies(1);
/// let mut resolved_versions = HashMap::new();
/// resolved_versions.insert(PackageName::new("dep-0"), ConcreteVersion::from("1.0.0"));
///
/// let (targets, skipped) = build_scan_targets(
///     parsed.as_ref(),
///     &resolved_versions,
///     &HashMap::new(),
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
///
/// assert_eq!(targets.len(), 1);
/// assert!(skipped.is_empty(), "the one dependency became a scan target, nothing to skip");
/// ```
pub fn build_scan_targets(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> (
    Vec<deps_core::osv::ScanTarget>,
    deps_core::osv::VulnerabilityMap,
) {
    use deps_core::osv::{ScanOutcome, SkipReason};

    let mut targets = Vec::new();
    let mut skipped = deps_core::osv::VulnerabilityMap::new();
    let keys = deps_core::osv::vulnerability_keys(
        parse_result,
        resolved_versions,
        Some(resolved_version_candidates),
        formatter,
        ecosystem,
    );

    for dep in parse_result.dependencies() {
        let normalized_name = formatter.normalize_package_name(dep.name());
        let key = deps_core::osv::vuln_key_for(dep, Some(&keys), formatter);

        if !formatter.source_is_public_registry_content(&dep.source()) {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NonRegistrySource));
            continue;
        }

        // go.mod's `require` line, not go.sum, is authoritative for Go: go.sum is an
        // append-only ledger (only `go mod tidy` prunes it), so its last-occurrence-wins
        // parse can yield a stale, no-longer-selected version (see
        // `manifest_requirement_is_resolved_version`).
        let version = resolve_in_use_version(
            dep,
            &normalized_name,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        );

        let Some(version) = version else {
            let reason = if has_unqueryable_resolved_pin(dep, formatter, ecosystem) {
                SkipReason::ResolvedTagNotFullVersion
            } else {
                SkipReason::NoConcreteVersion
            };
            skipped.insert(key, ScanOutcome::Skipped(reason));
            continue;
        };

        let Some(osv_name) = formatter.osv_package_name(dep) else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::UnmappableName));
            continue;
        };

        targets.push(deps_core::osv::ScanTarget::from_native(
            key, osv_name, version, formatter,
        ));
    }

    (targets, skipped)
}
/// Outcome of classifying one dependency for [`build_latest_check_targets`]/
/// [`build_candidate_check_targets`]'s shared registry-source/cached-version/OSV-name gates
/// (code-review finding: the two functions used to duplicate this exact branch sequence, which
/// this PR's `StructuralSkipReason` retyping had to edit in lockstep in both copies).
enum DepCheckClassification<'a> {
    /// `formatter.source_is_public_registry_content` returned `false`.
    NonRegistrySource,
    /// No registry-cached version list yet for this dependency — absence, not a structural
    /// skip: a later commit populating `cached_versions` can still turn this into a real
    /// target (see both callers' own doc for why this must not be read as "not applicable").
    NoCachedVersions,
    /// A cached version list exists, but `formatter.osv_package_name` returned `None`.
    UnmappableName {
        /// This dependency's registry-cached version list, for a caller that still wants to
        /// report a real (if unmappable) candidate version.
        cached: &'a deps_core::lsp_helpers::PackageVersions,
    },
    /// A real, checkable target: the resolved OSV package name and this dependency's
    /// registry-cached version list.
    Target {
        /// `formatter.osv_package_name(dep)`'s resolved value.
        osv_name: deps_core::osv::OsvPackageName,
        /// This dependency's registry-cached version list.
        cached: &'a deps_core::lsp_helpers::PackageVersions,
    },
}

/// The shared classification steps behind [`DepCheckClassification`]'s variants — see that
/// type's doc.
fn classify_dep_for_check_targets<'a>(
    dep: &dyn deps_core::Dependency,
    cached_versions: &'a HashMap<PackageName, deps_core::lsp_helpers::PackageVersions>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> DepCheckClassification<'a> {
    if !formatter.source_is_public_registry_content(&dep.source()) {
        return DepCheckClassification::NonRegistrySource;
    }

    let normalized_name = formatter.normalize_package_name(dep.name());
    let Some(cached) = cached_versions
        .get(normalized_name.as_str())
        .or_else(|| cached_versions.get(dep.name()))
    else {
        return DepCheckClassification::NoCachedVersions;
    };

    match formatter.osv_package_name(dep) {
        Some(osv_name) => DepCheckClassification::Target { osv_name, cached },
        None => DepCheckClassification::UnmappableName { cached },
    }
}

/// Builds phase B.1's latest-check targets for **every** dependency with a registry-cached
/// latest (issue #1517).
///
/// Not just ones phase A already flagged [`deps_core::osv::ScanOutcome::Vulnerable`] at their
/// pinned version — closes the gap that let a cleanly-pinned dependency's malicious/vulnerable
/// `latest` go completely unchecked while every renderer (hover, diagnostics, code actions,
/// code lens, inlay hints, completion) and `deps-cli update`'s default mode still recommended
/// it as a safe upgrade.
///
/// `osv_name` comes from `formatter.osv_package_name(dep)` directly, not from phase A's
/// `osv_name_by_key` — that map only has entries for dependencies phase A actually built a
/// [`deps_core::osv::ScanTarget`] for, which excludes any dependency phase A skipped for
/// [`deps_core::osv::SkipReason::NoConcreteVersion`] (e.g. a `^1.0.4` requirement with no
/// committed lock file) — such a dependency still has a resolvable registry `latest` and must
/// still have it checked.
///
/// Every dependency considered gets either a [`deps_core::osv::ScanTarget`] in the returned
/// `Vec` or an explicit structural entry in the returned [`deps_core::osv::LatestStatusMap`] —
/// never silently neither, mirroring [`build_scan_targets`]'s own invariant 0 discipline
/// (absence must never be read as "clean" or "not applicable"). A dependency with no
/// registry-cached `latest` at all (the fetch hasn't completed, or the registry doesn't know
/// the package) gets neither: it isn't a structural gap, since a later commit populating
/// `cached_versions` can turn it into a real target — the map's absence there falls through to
/// [`deps_core::lsp_helpers::LatestVerdict::Unverified`] (fail-closed), not
/// [`deps_core::lsp_helpers::LatestVerdict::NotApplicable`].
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     PackageVersions, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::{UpgradeStatus, vulnerability_keys};
/// use deps_core::test_util::stub_parse_result_with_dependencies;
/// use deps_core::{ConcreteVersion, EcosystemId, PackageName};
/// use deps_engine::classify::osv::build_latest_check_targets;
/// use std::collections::HashMap;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// let parsed = stub_parse_result_with_dependencies(1);
/// let mut cached_versions = HashMap::new();
/// cached_versions.insert(
///     PackageName::new("dep-0"),
///     PackageVersions::latest_only("2.0.0"),
/// );
/// let vuln_keys = vulnerability_keys(
///     parsed.as_ref(),
///     &HashMap::new(),
///     None,
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
///
/// let (targets, structural) = build_latest_check_targets(
///     parsed.as_ref(),
///     &cached_versions,
///     &vuln_keys,
///     &SimpleFormatter,
/// );
///
/// assert_eq!(targets.len(), 1);
/// assert_eq!(targets[0].display_version, "2.0.0");
/// assert!(structural.is_empty(), "the one dependency became a real target, nothing structural");
/// ```
pub fn build_latest_check_targets(
    parse_result: &dyn deps_core::ParseResult,
    cached_versions: &HashMap<PackageName, deps_core::lsp_helpers::PackageVersions>,
    vuln_keys: &deps_core::osv::VulnKeys,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    Vec<deps_core::osv::ScanTarget>,
    deps_core::osv::LatestStatusMap,
) {
    use deps_core::osv::{SkipReason, StructuralSkipReason, UpgradeStatus, vuln_key_for};

    let mut targets = Vec::new();
    let mut structural = deps_core::osv::LatestStatusMap::new();
    let mut seen = std::collections::HashSet::new();

    for dep in parse_result.dependencies() {
        let key = vuln_key_for(dep, Some(vuln_keys), formatter);

        match classify_dep_for_check_targets(dep, cached_versions, formatter) {
            DepCheckClassification::NonRegistrySource => {
                structural.insert(
                    key,
                    UpgradeStatus::StructurallyUnchecked(StructuralSkipReason::NonRegistrySource),
                );
            }
            // No registry-cached latest yet — absence, not a structural skip (see doc above).
            DepCheckClassification::NoCachedVersions => {}
            DepCheckClassification::UnmappableName { cached } => {
                structural.insert(
                    key,
                    UpgradeStatus::CandidateUnverified {
                        version: cached.latest.clone(),
                        reason: SkipReason::UnmappableName,
                    },
                );
            }
            DepCheckClassification::Target { osv_name, cached } => {
                // Occurrences sharing a key share one result (see `build_scan_targets`).
                if !seen.insert(key.clone()) {
                    continue;
                }
                targets.push(deps_core::osv::ScanTarget::from_native(
                    key,
                    osv_name,
                    cached.latest.clone(),
                    formatter,
                ));
            }
        }
    }

    (targets, structural)
}

/// Bounds how many candidate versions per dependency [`build_candidate_check_targets`] checks
/// (#1524) — code actions/completion display at most a handful of "update to X" items per
/// dependency, so checking a small superset of that is enough to cover what a
/// candidate-offering surface could actually display, without unbounded OSV traffic for a
/// dependency with hundreds of published versions.
const MAX_CANDIDATE_CHECK_VERSIONS: usize = 6;

/// Builds phase B's candidate-check targets for #1524.
///
/// Organized into up to `MAX_CANDIDATE_CHECK_VERSIONS` "rounds": round `r`'s
/// `Vec<ScanTarget>` holds, for every dependency that has one, its `r`-th newest non-yanked
/// registry version (rank 0 = newest). Callers batch-check one round at a time via
/// [`deps_core::osv::OsvClient::check_candidates`]
/// — at most one target per [`deps_core::osv::VulnKey`] per round, so a single call never
/// collapses two of one dependency's own candidates into one result — and merge each round's
/// [`deps_core::osv::LatestStatusMap`]-shaped result into a
/// [`deps_core::osv::CandidateStatusMap`] keyed by the version each round actually checked.
///
/// Shares [`build_latest_check_targets`]'s structural-skip classification via
/// `classify_dep_for_check_targets` (non-public-registry source, unmappable OSV name) — recorded
/// once per dependency in the returned `structural` map as
/// [`deps_core::osv::CandidateStatuses::Structural`] (see that type's doc), never duplicated per
/// round.
///
/// Selection is deliberately simpler than
/// [`deps_core::completion::prepare_version_display_items`]'s exact display-item algorithm
/// (which needs the full `dyn Version` registry response this background task never has
/// cached, only the bare [`ConcreteVersion`] list [`deps_core::lsp_helpers::PackageVersions`]
/// carries): the newest `MAX_CANDIDATE_CHECK_VERSIONS` non-yanked entries from
/// [`deps_core::lsp_helpers::PackageVersions::available`], newest-first. A display item this
/// selection doesn't happen to cover (rare: `prepare_version_display_items`'s own "bump the
/// latest pick in" `#956` behavior) simply reads as
/// [`deps_core::lsp_helpers::LatestVerdict::Unverified`] and is excluded — over-conservative,
/// never under-conservative.
pub fn build_candidate_check_targets(
    parse_result: &dyn deps_core::ParseResult,
    cached_versions: &HashMap<PackageName, deps_core::lsp_helpers::PackageVersions>,
    vuln_keys: &deps_core::osv::VulnKeys,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    Vec<Vec<deps_core::osv::ScanTarget>>,
    deps_core::osv::CandidateStatusMap,
) {
    use deps_core::osv::{CandidateStatuses, StructuralSkipReason, vuln_key_for};

    let mut rounds: Vec<Vec<deps_core::osv::ScanTarget>> =
        vec![Vec::new(); MAX_CANDIDATE_CHECK_VERSIONS];
    let mut structural = deps_core::osv::CandidateStatusMap::new();
    let mut seen = std::collections::HashSet::new();

    for dep in parse_result.dependencies() {
        let key = vuln_key_for(dep, Some(vuln_keys), formatter);

        let (osv_name, package_versions) =
            match classify_dep_for_check_targets(dep, cached_versions, formatter) {
                DepCheckClassification::NonRegistrySource => {
                    structural.insert(
                        key,
                        CandidateStatuses::Structural(StructuralSkipReason::NonRegistrySource),
                    );
                    continue;
                }
                // No registry-cached version list yet — absence, not a structural skip (see
                // doc above), matching `build_latest_check_targets`'s identical treatment.
                DepCheckClassification::NoCachedVersions => continue,
                DepCheckClassification::UnmappableName { .. } => {
                    structural.insert(
                        key,
                        CandidateStatuses::Structural(StructuralSkipReason::UnmappableName),
                    );
                    continue;
                }
                DepCheckClassification::Target { osv_name, cached } => (osv_name, cached),
            };

        if !seen.insert(key.clone()) {
            continue;
        }

        let yanked: std::collections::HashSet<&ConcreteVersion> = package_versions
            .yanked
            .iter()
            .map(|(version, _)| version)
            .collect();

        for (rank, version) in package_versions
            .available
            .iter()
            .filter(|v| !yanked.contains(v))
            .take(MAX_CANDIDATE_CHECK_VERSIONS)
            .enumerate()
        {
            // `rank` is in `0..MAX_CANDIDATE_CHECK_VERSIONS` by construction (bounded by the
            // `take` above), matching `rounds`' own length — but a bare index would still
            // panic if that invariant were ever broken, so this fails closed instead.
            let Some(bucket) = rounds.get_mut(rank) else {
                continue;
            };
            bucket.push(deps_core::osv::ScanTarget::from_native(
                key.clone(),
                osv_name.clone(),
                version.clone(),
                formatter,
            ));
        }
    }

    (rounds, structural)
}

/// Outcome of `resolve_fix_target` for one vulnerable dependency.
#[derive(Debug, PartialEq, Eq)]
enum FixTargetResolution {
    /// No fix recommended, F failed [`deps_core::lsp_helpers::is_safe_version_string`], or no
    /// `osv_name` is on record for this key — nothing to verify or record; `fix_target_status`
    /// stays untouched (left at `NotChecked`).
    Skip,
    /// F's status was resolved without a network call by reusing the already-checked
    /// "latest" candidate's result (FR-002, F == latest).
    Resolved(deps_core::osv::UpgradeStatus),
    /// F differs from latest and needs a live [`deps_core::osv::OsvClient::check_candidates`]
    /// check — carries the [`deps_core::osv::ScanTarget`] to batch into the caller's single
    /// combined call (NFR-001). Keyed with the dependency's plain [`deps_core::osv::VulnKey`]:
    /// this candidate is always checked via a *separate* `check_candidates` call from the "B.1
    /// latest" candidates, so its result `HashMap` never shares a key space with the phase-A
    /// `VulnerabilityMap` — no suffix is needed to disambiguate.
    NeedsLiveCheck(deps_core::osv::ScanTarget),
}
/// Pure (network-free) decision logic for `run_osv_fix_target_verification`'s per-dependency
/// resolution order — see that function's doc for the two cases and their rationale. Split
/// out so each case is unit-testable without an `OsvClient`/network dependency.
fn resolve_fix_target(
    dv: &deps_core::osv::DependencyVulnerabilities,
    key: &deps_core::osv::VulnKey,
    latest_status: &deps_core::osv::LatestStatusMap,
    osv_name_by_key: &HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvPackageName>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> FixTargetResolution {
    use deps_core::edit::{VulnFixSkip, resolve_recommended_fix};
    use deps_core::osv::{ScanTarget, UpgradeStatus};

    let latest = latest_status.get(key);

    // #1350: `resolve_recommended_fix` is the shared prefix (`recommended_fix` ->
    // `osv_version_to_native` -> `is_safe_version_string`) this function used to duplicate.
    // Deliberately the *unverified* helper, not `resolve_verified_fix`: this function is
    // itself the producer of `dv.fix_target_status`, so it must not gate on a status it
    // has not computed yet.
    let (fix, version_native) = match resolve_recommended_fix(dv, latest, formatter) {
        Ok(pair) => pair,
        Err(VulnFixSkip::NoRecommendedFix) => return FixTargetResolution::Skip,
        // `resolve_recommended_fix` already emits a WARN via `warn_rejected_value` for this
        // case (M1: consistent with every other unsafe-value rejection gate in this codebase,
        // not the accidental DEBUG this call site used before #1350) — this DEBUG line adds
        // only the batch-scan `key` that generic warning doesn't carry.
        Err(VulnFixSkip::UnsafeVersion) => {
            tracing::debug!(
                key = %key,
                "OSV #462: fix-target version failed validation, skipping verification"
            );
            return FixTargetResolution::Skip;
        }
        // `resolve_recommended_fix` can only ever return `NoRecommendedFix`/`UnsafeVersion` —
        // these five variants exist only for `plan_vulnerability_fix`'s later,
        // `resolve_verified_fix`-based decision. Handled explicitly rather than folded into a
        // wildcard (code review finding) so a future `VulnFixSkip` variant, or a change that
        // starts surfacing one of these here, is a compile error instead of silently
        // degrading to `Skip` — the same bug class `EcosystemId`'s exhaustive-match
        // convention exists to catch project-wide.
        Err(
            VulnFixSkip::UnverifiedTarget
            | VulnFixSkip::RequirementAlreadyResolves
            | VulnFixSkip::NoOpRewrite
            | VulnFixSkip::UnresolvedPlaceholder
            | VulnFixSkip::OversizedRequirement,
        ) => return FixTargetResolution::Skip,
    };

    // Issue #1517: only a *resolved* latest verdict (`CandidateClean`/`CandidateVulnerable`)
    // can be reused — `NotChecked`/`CandidateUnverified` (transient failure, structural skip,
    // or simply never checked) must always fall through to a live check below, never be
    // silently treated as "F already covered by the latest check".
    let reused_latest_version: Option<&str> = match latest {
        Some(
            UpgradeStatus::CandidateClean { version }
            | UpgradeStatus::CandidateVulnerable { version, .. },
        ) => Some(version.as_str()),
        // `UpgradeStatus` is `#[non_exhaustive]` across the crate boundary: the wildcard is
        // required by the compiler, not a stylistic shortcut — every variant defined *today*
        // (`NotChecked`, `CandidateUnverified`) is still handled by the fall-through-to-`None`
        // (never-reuse) behavior, matching this project's `EcosystemId`-style exhaustive-match
        // convention as closely as a foreign `#[non_exhaustive]` type allows.
        Some(_) | None => None,
    };
    if reused_latest_version == Some(version_native.as_str()) {
        return FixTargetResolution::Resolved(latest.cloned().unwrap_or(UpgradeStatus::NotChecked));
    }

    let Some(osv_name) = osv_name_by_key.get(key).cloned() else {
        tracing::debug!(
            key = %key,
            "OSV #462: no osv_name on record for fix-target verification, skipping"
        );
        return FixTargetResolution::Skip;
    };
    FixTargetResolution::NeedsLiveCheck(ScanTarget::new(
        key.clone(),
        osv_name,
        fix.version,
        ConcreteVersion::new(version_native),
    ))
}
/// Pure aggregation step of `run_osv_fix_target_verification`: resolves every vulnerable
/// dependency's fix target via `resolve_fix_target`.
///
/// Splits immediately-resolvable results (`resolved`) from the ones that need a live check
/// (`live_check_candidates`) — the latter collected into one `Vec` across *every* dependency
/// before the caller's single `check_candidates` call, so multiple dependencies needing a live
/// check always batch into one network round-trip rather than one per dependency (NFR-001).
/// Split out from the async orchestrator specifically so this batching/aggregation behavior is
/// unit-testable without an `OsvClient`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::{
///     Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, UpgradeStatus,
///     VulnSeverity, VulnerabilityMap,
/// };
/// use deps_core::test_util::vuln_key;
/// use deps_core::{ConcreteVersion, PackageName};
/// use deps_engine::classify::osv::collect_fix_target_resolutions;
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
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
/// let latest_status = UpgradeStatus::CandidateClean {
///     version: ConcreteVersion::new("1.2.0"),
/// };
/// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1));
///
/// let mut vulnerabilities = VulnerabilityMap::new();
/// vulnerabilities.insert(vuln_key("pkg"), ScanOutcome::Vulnerable(dv));
///
/// let mut latest_status_map = HashMap::new();
/// latest_status_map.insert(vuln_key("pkg"), latest_status.clone());
///
/// // F (the fix, 1.2.0) equals the already-checked "latest" candidate — resolved without a
/// // live network check.
/// let (resolved, live_check_candidates) = collect_fix_target_resolutions(
///     &vulnerabilities,
///     &[vuln_key("pkg")],
///     &HashMap::new(),
///     &latest_status_map,
///     &SimpleFormatter,
/// );
///
/// assert_eq!(resolved, vec![(vuln_key("pkg"), latest_status)]);
/// assert!(live_check_candidates.is_empty());
/// ```
pub fn collect_fix_target_resolutions(
    vulnerabilities: &deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[deps_core::osv::VulnKey],
    osv_name_by_key: &HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvPackageName>,
    latest_status: &deps_core::osv::LatestStatusMap,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    Vec<(deps_core::osv::VulnKey, deps_core::osv::UpgradeStatus)>,
    Vec<deps_core::osv::ScanTarget>,
) {
    use deps_core::osv::ScanOutcome;

    let mut resolved = Vec::new();
    let mut live_check_candidates = Vec::new();

    for key in vulnerable_keys {
        let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get(key) else {
            continue;
        };
        match resolve_fix_target(dv, key, latest_status, osv_name_by_key, formatter) {
            FixTargetResolution::Skip => {}
            FixTargetResolution::Resolved(status) => resolved.push((key.clone(), status)),
            FixTargetResolution::NeedsLiveCheck(target) => live_check_candidates.push(target),
        }
    }

    (resolved, live_check_candidates)
}
/// Applies a live [`deps_core::osv::OsvClient::check_candidates`] result back onto the matching
/// dependency's `fix_target_status`.
///
/// Keyed by the same plain [`deps_core::osv::VulnKey`] the vulnerable dependency was scanned
/// under.
///
/// A key absent from `statuses` (timeout, OSV outage, or a chunk `check_candidates` itself
/// dropped) simply leaves that dependency's `fix_target_status` untouched — still
/// `NotChecked` if it was never set, which is exactly the fail-closed degradation
/// FR-004/NFR-002 call for (never a panic, never a fabricated "verified" status).
///
/// # Examples
///
/// ```
/// use deps_core::osv::{
///     Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
///     VulnerabilityMap,
/// };
/// use deps_core::test_util::vuln_key;
/// use deps_core::ConcreteVersion;
/// use deps_engine::classify::osv::apply_live_fix_target_statuses;
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// let advisory = Arc::new(
///     Advisory::new(
///         "RUSTSEC-2024-0001".to_string(),
///         "2024-01-01T00:00:00Z".to_string(),
///         VulnSeverity::High,
///     )
///     .expect("valid osv id"),
/// );
/// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1));
///
/// let mut vulnerabilities = VulnerabilityMap::new();
/// vulnerabilities.insert(vuln_key("pkg"), ScanOutcome::Vulnerable(dv));
///
/// let mut statuses = HashMap::new();
/// statuses.insert(
///     vuln_key("pkg"),
///     UpgradeStatus::CandidateClean {
///         version: ConcreteVersion::new("1.2.0"),
///     },
/// );
///
/// apply_live_fix_target_statuses(&mut vulnerabilities, statuses);
///
/// let ScanOutcome::Vulnerable(dv) = vulnerabilities.get(&vuln_key("pkg")).unwrap() else {
///     unreachable!()
/// };
/// assert_eq!(
///     dv.fix_target_status,
///     UpgradeStatus::CandidateClean {
///         version: ConcreteVersion::new("1.2.0")
///     }
/// );
/// ```
pub fn apply_live_fix_target_statuses(
    vulnerabilities: &mut deps_core::osv::VulnerabilityMap,
    statuses: HashMap<deps_core::osv::VulnKey, deps_core::osv::UpgradeStatus>,
) {
    use deps_core::osv::ScanOutcome;

    for (key, status) in statuses {
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(&key) {
            dv.fix_target_status = status;
        }
    }
}

/// Projects `targets` down to `key -> osv_name`.
///
/// A two-line helper centralizing an identical inline `HashMap` build `deps-lsp` used to
/// duplicate at `document/osv_scan.rs:116` and `deps-cli`'s `--security-only` planner (#1329)
/// needs too — both consume this instead of re-deriving it from [`build_scan_targets`]'s own
/// `Vec<deps_core::osv::ScanTarget>` output.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::osv::{OsvPackageName, OsvVersion, ScanTarget};
/// use deps_core::test_util::vuln_key;
/// use deps_engine::classify::osv::osv_name_by_key;
///
/// let targets = vec![ScanTarget::new(
///     vuln_key("serde"),
///     OsvPackageName::new("serde"),
///     OsvVersion::new("1.0.0"),
///     ConcreteVersion::new("1.0.0"),
/// )];
/// let map = osv_name_by_key(&targets);
/// assert_eq!(map.get(&vuln_key("serde")), Some(&OsvPackageName::new("serde")));
/// ```
#[must_use]
pub fn osv_name_by_key(
    targets: &[deps_core::osv::ScanTarget],
) -> HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvPackageName> {
    targets
        .iter()
        .map(|t| (t.key.clone(), t.osv_name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::resolved::collect_in_use_versions;
    use deps_core::VersionReq;
    use std::assert_matches;

    mod osv_scan_target_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy,
        };
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};
        use deps_core::test_util::StubFormatter;
        use std::any::Any;

        struct MockDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            source: DependencySource,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                // Distinct per instance: `vulnerability_keys` (#394 S2) keys a
                // `HashMap<Range, String>` by `name_range()` — a fixed range would
                // make every `MockDep` collide on one map entry.
                let addr = std::ptr::from_ref(self) as u32;
                Range::new(Position::new(0, addr), Position::new(0, addr + 1))
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> DependencySource {
                self.source.clone()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            deps: Vec<MockDep>,
        }

        impl deps_core::ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                static URI: std::sync::OnceLock<url::Url> = std::sync::OnceLock::new();
                URI.get_or_init(|| deps_core::test_util::test_uri("/test/Cargo.toml"))
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        use deps_core::osv::{ScanOutcome, SkipReason};

        // `is_concrete_version`/`concrete_pin_version` unit tests moved to
        // `deps-core`'s `lsp_helpers::in_use_version` module alongside the
        // functions themselves (#394).

        #[test]
        fn build_scan_targets_step0_skips_non_registry_source_even_with_lockfile_version() {
            // A git/path/patched fork must never be flagged with a CVE for a
            // version it does not actually contain, even when its lockfile
            // entry carries a plausible-looking version (critique C2).
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("0.1.43")),
                    source: DependencySource::Git {
                        url: "https://github.com/example/time".to_string(),
                        rev: None,
                    },
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("time"), "0.1.43".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("time")),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            );
        }

        #[test]
        fn build_scan_targets_step1_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert!(skipped.is_empty());
        }

        /// Formatter stub mirroring `GoFormatter`'s override: every
        /// dependency's manifest requirement is itself the resolved version
        /// (#235's `manifest_requirement_is_resolved_version` unification).
        const MOCK_GO_FORMATTER: StubFormatter = StubFormatter::new()
            .with_package_url_prefix("https://pkg.go.dev/")
            .with_manifest_requirement_as_resolved_version();

        struct MockVPrefixFormatter;
        impl PackageNaming for MockVPrefixFormatter {}

        impl PackageRendering for MockVPrefixFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }
        }

        impl RequirementResolution for MockVPrefixFormatter {}

        impl DiagnosticMessages for MockVPrefixFormatter {}

        impl DiagnosticPolicy for MockVPrefixFormatter {}

        impl SourcePolicy for MockVPrefixFormatter {}

        impl OsvNaming for MockVPrefixFormatter {
            fn osv_version(&self, version: &ConcreteVersion) -> deps_core::osv::OsvVersion {
                let version = version.as_str();
                deps_core::osv::OsvVersion::new(version.strip_prefix('v').unwrap_or(version))
            }
        }

        #[test]
        fn build_scan_targets_normalizes_version_via_formatter_osv_version_hook() {
            // Go's mandatory "v" prefix isn't valid OSV SEMVER (#228) — must route through
            // the formatter hook rather than sending the native spelling on the wire.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/gin-gonic/gin"),
                    version_req: Some(VersionReq::new("v1.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(
                PackageName::new("github.com/gin-gonic/gin"),
                "v1.9.0".into(),
            );

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockVPrefixFormatter,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.9.0");
            // display_version keeps the ecosystem-native "v" spelling (S1
            // regression guard) — only the wire-format `version` is stripped.
            assert_eq!(targets[0].display_version, "v1.9.0");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_leaves_version_unaffected_for_default_identity_formatter() {
            // Regression guard: ecosystems that do not override osv_version
            // must keep sending the native spelling verbatim (no regression
            // from introducing the hook).
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert_eq!(targets[0].display_version, "1.0.195");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_go_ignores_stale_lockfile_version_uses_go_mod_requirement() {
            // go.sum is append-only (only `go mod tidy` prunes it) and sorted ascending by
            // semver, so a stale higher version from before a downgrade can sort last and
            // win last-occurrence-wins parsing. go.mod's `require` line is already an exact
            // pin, so for Go the manifest — not lockfile-derived `resolved_versions` — must
            // be authoritative for OSV scanning.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/pkg/errors"),
                    version_req: Some(VersionReq::new("v0.8.1")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            // Stale entry: go.sum still records v0.9.1 from before a
            // downgrade back to v0.8.1 that only `go get` (not `go mod
            // tidy`) performed.
            resolved.insert(PackageName::new("github.com/pkg/errors"), "v0.9.1".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MOCK_GO_FORMATTER,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            // `.version` (the wire-format value) goes through `formatter.osv_version`,
            // whose shared default (`deps-core`) strips a leading `v`/`V` — `MOCK_GO_FORMATTER`
            // doesn't override it, unlike the real `GoFormatter`. `.display_version` is the
            // raw, untransformed value this test is actually about (manifest vs. lockfile
            // authority), so it keeps the native "v" spelling.
            assert_eq!(targets[0].version, "0.8.1");
            assert_eq!(targets[0].display_version, "v0.8.1");
            assert!(skipped.is_empty());
        }

        /// #667 follow-up (impl-critic): before this reclassification, a Deno `jsr:`
        /// dependency's bare requirement always failed the version gate under
        /// `AlwaysRange` (`resolve_in_use_version` always `None`), so `DenoFormatter::
        /// osv_package_name`'s `_ => None` arm for `jsr:` never actually ran in a live
        /// scan. Now that Deno is `ConcreteIfFullVersion`, a bare-full-version-pinned
        /// `jsr:` dependency passes the version gate and correctness rests entirely on
        /// that match arm — this exercises it end-to-end through the real
        /// `DenoFormatter`, not just `osv_package_name`'s own unit test in isolation.
        #[cfg(feature = "deno")]
        #[test]
        fn build_scan_targets_deno_bare_pinned_jsr_dep_is_unmappable_name_skip() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("jsr:@std/fs"),
                    version_req: Some(VersionReq::new("1.0.0")),
                    source: DependencySource::Registry,
                }],
            };

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &deps_deno::DenoFormatter,
                EcosystemId::Deno,
            );

            assert!(targets.is_empty(), "jsr: dep must never reach an OSV query");
            assert_eq!(skipped.len(), 1);
            // Key is the full scheme-qualified name: `DenoFormatter` doesn't override
            // `normalize_package_name`, unlike `osv_package_name` (which strips the
            // scheme only for `npm:` and returns `None` for everything else).
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("jsr:@std/fs")),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName))
            );
        }

        /// #1545: `ComposerFormatter::osv_package_name`'s lowercase override had an
        /// incorrect `#[cfg(feature = "lsp-responses")]` gate, so a `deps-cli` build
        /// (which never enables `lsp-responses`) silently fell back to `OsvNaming`'s
        /// identity default and sent Packagist's mixed-case spelling to OSV.dev's
        /// case-sensitive API. Exercises the real `ComposerFormatter` end-to-end (not
        /// just `osv_package_name`'s own unit test in isolation) so this regression
        /// class — a gated `OsvNaming` override silently no-op'ing — is caught by CI
        /// under a non-`lsp-responses` build, mirroring the Deno/jsr precedent above.
        #[cfg(feature = "composer")]
        #[test]
        fn build_scan_targets_composer_mixed_case_name_is_lowercased_for_osv() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("Symfony/Http-Kernel"),
                    version_req: Some(VersionReq::new("4.4.0")),
                    source: DependencySource::Registry,
                }],
            };

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &deps_composer::ComposerFormatter,
                EcosystemId::Composer,
            );

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].osv_name, "symfony/http-kernel");
            assert!(skipped.is_empty());
        }

        /// #1663: a separator-only Poetry key normalizes to an empty OSV name, which OSV
        /// rejects with a batch-wide HTTP 400 — it must be skipped as `UnmappableName` while a
        /// valid sibling still yields its (PEP 503-normalized) query.
        #[cfg(feature = "pypi")]
        #[test]
        fn build_scan_targets_pypi_separator_only_key_is_skipped_and_sibling_still_queried() {
            let dep = |name: &str| MockDep {
                name: PackageName::new(name),
                version_req: Some(VersionReq::new("==1.0.0")),
                source: DependencySource::Registry,
            };
            let parse_result = MockParseResult {
                deps: vec![dep("Werkzeug"), dep("---")],
            };

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &deps_pypi::PypiFormatter,
                EcosystemId::Pypi,
            );

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].osv_name, "werkzeug");
            assert_eq!(skipped.len(), 1);
            // The skip is keyed by the normalized name, which is empty for `---`.
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("")),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName))
            );
        }

        /// #1556 impl-critic S1: a GitHub Actions SHA pin whose `TagIndex`-resolved tag is
        /// itself a moving-major/partial name (here, `v1`, from a `# v1` comment) is NOT a
        /// queryable OSV version — `TagIndex.sha_to_tag` is first-wins over every tag
        /// pointing at that commit, so it can just as easily hand back `"v1"` or `"2.9"` as
        /// a genuine full tag, and querying OSV.dev with a fabricated version is exactly
        /// the #503 invariant this must not regress. `resolved_pin_version`'s raw output
        /// must still pass through the same full-semver-shape gate
        /// (`concrete_pin_version`) as manifest text before `resolve_in_use_version`
        /// accepts it — see the positive case below for the tag shape that IS accepted.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_sha_pin_with_moving_major_comment_stays_skipped() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_core::osv::{ScanOutcome, SkipReason};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let sha = "d".repeat(40);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v1\n");
            let parse_result =
                deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");

            let cache = Arc::new(deps_core::HttpCache::new());
            let registry = GithubActionsRegistry::new(cache);
            let tag_index = registry.tag_index();
            let mut index = TagIndex::default();
            index.insert_sha_pin(
                CommitSha::parse(&sha).unwrap(),
                deps_core::lsp_helpers::ResolvedPin::MostSpecific(deps_core::ConcreteVersion::new(
                    "v1",
                )),
            );
            tag_index.insert(PackageName::new("actions/checkout"), Arc::new(index));
            let formatter = GithubActionsFormatter::new(tag_index);

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &formatter,
                EcosystemId::GithubActions,
            );

            assert!(
                targets.is_empty(),
                "a moving-major TagIndex-resolved tag must not reach OSV as a fabricated version: {targets:?}"
            );
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("actions/checkout")),
                Some(ScanOutcome::Skipped(SkipReason::ResolvedTagNotFullVersion))
            );
        }

        /// #1668: a SHA pin whose commit carries a two-component release tag (`v2.9`) plus its
        /// moving alias (`v2`) is scanned as `v2.9`; a commit carrying only the moving alias
        /// (`v2`) stays skipped, with the accurate "resolved tag is not a full version" reason.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_sha_pin_two_component_release_tag() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_core::osv::{ScanOutcome, SkipReason};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let sha = "f".repeat(40);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v2.9\n");
            let parse_result =
                deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");
            let commit = CommitSha::parse(&sha).unwrap();

            for (tags, expected) in [
                (vec!["v2", "v2.9"], Some("v2.9")),
                (vec!["v2.9", "v2.9.1"], Some("v2.9.1")),
                (vec!["v2.9"], Some("v2.9")),
                (vec!["v2"], None),
            ] {
                let cache = Arc::new(deps_core::HttpCache::new());
                let registry = GithubActionsRegistry::new(cache);
                let tag_index = registry.tag_index();
                tag_index.insert(
                    PackageName::new("actions/checkout"),
                    Arc::new(TagIndex::from_tags(tags.iter().map(|t| (*t, &commit)))),
                );
                let formatter = GithubActionsFormatter::new(tag_index);

                let (targets, skipped) = build_scan_targets(
                    &parse_result,
                    &HashMap::new(),
                    &HashMap::new(),
                    &formatter,
                    EcosystemId::GithubActions,
                );

                match expected {
                    Some(version) => {
                        assert_eq!(targets.len(), 1, "{tags:?}: {skipped:?}");
                        assert_eq!(targets[0].display_version, version);
                        assert!(skipped.is_empty());
                    }
                    None => {
                        assert!(targets.is_empty(), "{tags:?}: {targets:?}");
                        assert_matches!(
                            skipped.get(&deps_core::test_util::vuln_key("actions/checkout")),
                            Some(ScanOutcome::Skipped(SkipReason::ResolvedTagNotFullVersion))
                        );
                    }
                }
            }
        }

        /// #1556: the actually-intended fix — a GitHub Actions SHA pin whose `TagIndex`
        /// resolves it to a genuine full `major.minor.patch` tag (here `v1.3.0`, matching
        /// the issue's own `moonrepo/setup-rust@<sha> # v1` example where the SHA's real
        /// tag turns out to be a full release) must reach a real OSV scan target, even
        /// though the pin's own trailing `# v1` comment alone is not full-semver-shaped.
        /// Exercises the real `deps-github-actions` formatter end-to-end (not just
        /// `resolve_in_use_version`'s isolated unit tests), mirroring the Deno/Composer
        /// end-to-end precedent above.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_sha_pin_tag_index_resolves_to_full_semver_tag() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let sha = "e".repeat(40);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v1\n");
            let parse_result =
                deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");

            let cache = Arc::new(deps_core::HttpCache::new());
            let registry = GithubActionsRegistry::new(cache);
            let tag_index = registry.tag_index();
            let mut index = TagIndex::default();
            index.insert_sha_pin(
                CommitSha::parse(&sha).unwrap(),
                deps_core::lsp_helpers::ResolvedPin::MostSpecific(deps_core::ConcreteVersion::new(
                    "v1.3.0",
                )),
            );
            tag_index.insert(PackageName::new("actions/checkout"), Arc::new(index));
            let formatter = GithubActionsFormatter::new(tag_index);

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &formatter,
                EcosystemId::GithubActions,
            );

            assert_eq!(
                targets.len(),
                1,
                "expected the SHA pin to reach a real OSV scan target: {skipped:?}"
            );
            assert!(skipped.is_empty());
            assert_eq!(targets[0].display_version, "v1.3.0");
        }

        #[test]
        fn build_scan_targets_step2_uses_concrete_requirement_verbatim() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Maven,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "2.14.1");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step2_strips_pin_marker_for_operator_prefixed_requirements() {
            // impl-critic M2: `concrete_pin_version` (originally PyPI `==`-only) also
            // strips Cargo's `=` and NuGet's `[..]` exact-pin markers via the shared helper.
            let cargo_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("=1.2.3")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &cargo_result,
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.2.3");
            assert!(skipped.is_empty());

            let nuget_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("Newtonsoft.Json"),
                    version_req: Some(VersionReq::new("[1.0.0]")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &nuget_result,
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::NuGet,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.0");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step3_skips_caret_range_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("serde")),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
        }

        #[test]
        fn build_scan_targets_step3_skips_wildcard_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("*")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("serde")),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
        }

        #[test]
        fn build_scan_targets_all_non_registry_sources_are_skipped() {
            let sources = vec![
                DependencySource::Path {
                    path: "../local".to_string(),
                },
                DependencySource::Url {
                    url: "https://example.com/pkg.tgz".to_string(),
                },
                DependencySource::Sdk {
                    sdk: "flutter".to_string(),
                },
                DependencySource::Workspace,
                DependencySource::CustomRegistry {
                    url: "https://private.example.com".to_string(),
                },
            ];

            for source in sources {
                let parse_result = MockParseResult {
                    deps: vec![MockDep {
                        name: PackageName::new("pkg"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: source.clone(),
                    }],
                };
                let mut resolved = HashMap::new();
                resolved.insert(PackageName::new("pkg"), "1.0.0".into());

                let (targets, skipped) = build_scan_targets(
                    &parse_result,
                    &resolved,
                    &HashMap::new(),
                    &StubFormatter::DEFAULT,
                    EcosystemId::Cargo,
                );
                assert!(targets.is_empty(), "{source:?} must be skipped (step 0)");
                assert_matches!(
                    skipped.get(&deps_core::test_util::vuln_key("pkg")),
                    Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
                );
            }
        }

        #[test]
        fn build_scan_targets_never_drops_a_dependency_silently() {
            // Critique C1: every dependency considered must end up in either
            // `targets` or `skipped` — never absent from both.
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("concrete"),
                        version_req: Some(VersionReq::new("2.14.1")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("range-only"),
                        version_req: Some(VersionReq::new("^1.0")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("git-dep"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: DependencySource::Git {
                            url: "https://example.com/git-dep".to_string(),
                            rev: None,
                        },
                    },
                ],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Maven,
            );

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].key.as_str(), "concrete");
            assert_eq!(skipped.len(), 2);
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("range-only")),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("git-dep")),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            );
        }

        // `collect_in_use_versions` (§4.6) reuses the same `resolve_in_use_version`
        // ladder as `build_scan_targets` above, plus its own step-0 filter —
        // these tests exercise that reuse directly.

        #[test]
        fn collect_in_use_versions_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("serde")),
                Some(&vec![ConcreteVersion::from("1.0.195")])
            );
        }

        #[test]
        fn collect_in_use_versions_concrete_pin_without_lockfile() {
            // Closes the former R4 gap: an exact pin with no lock file must
            // still produce an in-use version for the yanked probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Maven,
            );
            assert_eq!(
                in_use.get(&PackageName::new("log4j-core")),
                Some(&vec![ConcreteVersion::from("2.14.1")])
            );
        }

        #[test]
        fn collect_in_use_versions_strips_pep440_double_equals_pin_for_pypi() {
            // The scenario the plan's R4 closure claim actually targets:
            // a PyPI `requirements.txt`-style `==` exact pin with no lock
            // file. `in_use.get(..)` must be the bare `"4.9.0"` so it can
            // ever match a real registry version string during the probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("typing_extensions"),
                    version_req: Some(VersionReq::new("==4.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Pypi,
            );
            assert_eq!(
                in_use.get(&PackageName::new("typing_extensions")),
                Some(&vec![ConcreteVersion::from("4.9.0")]),
                "pep440 '==' comparator must be stripped, not carried into the in-use version"
            );
        }

        #[test]
        fn collect_in_use_versions_skips_non_concrete_requirement_with_no_lockfile() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_excludes_non_registry_source_even_with_lockfile_version() {
            // Step 0 (§4.5): a patched git/path fork must never be flagged
            // for a registry version it does not contain.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("0.1.43")),
                    source: DependencySource::Git {
                        url: "https://github.com/example/time".to_string(),
                        rev: None,
                    },
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("time"), "0.1.43".into());

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_tracks_all_occurrences_of_duplicate_name() {
            // Regression guard for #394: two occurrences of the same name with different
            // pins (e.g. `[dependencies]` + `[dev-dependencies]`) must both surface — a
            // name-keyed `HashMap<PackageName, String>` would drop all but the last pin.
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("time"),
                        version_req: Some(VersionReq::new("=0.1.43")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("time"),
                        version_req: Some(VersionReq::new("=0.1.44")),
                        source: DependencySource::Registry,
                    },
                ],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("time")),
                Some(&vec![
                    ConcreteVersion::from("0.1.43"),
                    ConcreteVersion::from("0.1.44")
                ]),
                "both occurrences' in-use versions must be tracked, not just the last one"
            );
        }
    }

    /// #1624 tester gap 1: `build_latest_check_targets`/`build_candidate_check_targets`'s
    /// structural-skip insert paths and `build_candidate_check_targets`'s per-rank
    /// round-bucketing loop, previously entirely unexercised by any unit test (only the one
    /// doctest above, which covers just the "real target" happy path).
    mod build_check_targets_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            PackageVersions, RequirementResolution, SourcePolicy,
        };
        use deps_core::osv::{CandidateStatuses, StructuralSkipReason, UpgradeStatus};
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};
        use deps_core::test_util::StubFormatter;
        use std::any::Any;
        use std::sync::Arc;

        struct MockDep {
            name: PackageName,
            source: DependencySource,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                let addr = std::ptr::from_ref(self) as u32;
                Range::new(Position::new(0, addr), Position::new(0, addr + 1))
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                None
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> DependencySource {
                self.source.clone()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            deps: Vec<MockDep>,
        }

        impl deps_core::ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                static URI: std::sync::OnceLock<url::Url> = std::sync::OnceLock::new();
                URI.get_or_init(|| deps_core::test_util::test_uri("/test/Cargo.toml"))
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// A formatter whose package name is never mappable to an OSV ecosystem name —
        /// `StubFormatter`'s `OsvNaming` default (always `Some`) can't drive the
        /// `UnmappableName` structural-skip branch.
        struct UnmappableNameFormatter;
        impl PackageNaming for UnmappableNameFormatter {}
        impl PackageRendering for UnmappableNameFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for UnmappableNameFormatter {}
        impl DiagnosticMessages for UnmappableNameFormatter {}
        impl DiagnosticPolicy for UnmappableNameFormatter {}
        impl SourcePolicy for UnmappableNameFormatter {}
        impl OsvNaming for UnmappableNameFormatter {
            fn osv_package_name(
                &self,
                _dep: &dyn Dependency,
            ) -> Option<deps_core::osv::OsvPackageName> {
                None
            }
        }

        fn vuln_keys_for(
            parse_result: &dyn deps_core::ParseResult,
            formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
        ) -> deps_core::osv::VulnKeys {
            deps_core::osv::vulnerability_keys(
                parse_result,
                &HashMap::new(),
                None,
                formatter,
                EcosystemId::Cargo,
            )
        }

        #[test]
        fn build_latest_check_targets_non_registry_source_is_structurally_unchecked() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("vendored"),
                    source: DependencySource::Path {
                        path: "../vendored".to_string(),
                    },
                }],
            };
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);

            let (targets, structural) = build_latest_check_targets(
                &parse_result,
                &HashMap::new(),
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            assert!(targets.is_empty());
            assert_eq!(
                structural.get(&deps_core::test_util::vuln_key("vendored")),
                Some(&UpgradeStatus::StructurallyUnchecked(
                    StructuralSkipReason::NonRegistrySource
                ))
            );
        }

        #[test]
        fn build_candidate_check_targets_non_registry_source_is_structural() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("vendored"),
                    source: DependencySource::Path {
                        path: "../vendored".to_string(),
                    },
                }],
            };
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);

            let (rounds, structural) = build_candidate_check_targets(
                &parse_result,
                &HashMap::new(),
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            assert!(
                rounds.iter().all(Vec::is_empty),
                "no round may hold a non-registry dependency"
            );
            assert_eq!(
                structural.get(&deps_core::test_util::vuln_key("vendored")),
                Some(&CandidateStatuses::Structural(
                    StructuralSkipReason::NonRegistrySource
                ))
            );
        }

        #[test]
        fn build_candidate_check_targets_unmappable_name_is_structural() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("jsr-pinned"),
                    source: DependencySource::Registry,
                }],
            };
            let vuln_keys = vuln_keys_for(&parse_result, &UnmappableNameFormatter);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::new("jsr-pinned"),
                PackageVersions::latest_only("1.0.0"),
            );

            let (rounds, structural) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &UnmappableNameFormatter,
            );

            assert!(
                rounds.iter().all(Vec::is_empty),
                "an unmappable name has no OSV-checkable round targets"
            );
            assert_eq!(
                structural.get(&deps_core::test_util::vuln_key("jsr-pinned")),
                Some(&CandidateStatuses::Structural(
                    StructuralSkipReason::UnmappableName
                ))
            );
        }

        fn duplicated_registry_dep() -> MockParseResult {
            MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("lodash"),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("lodash"),
                        source: DependencySource::Registry,
                    },
                ],
            }
        }

        #[test]
        fn build_latest_check_targets_dedups_duplicate_key_occurrences() {
            let parse_result = duplicated_registry_dep();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::new("lodash"),
                PackageVersions::latest_only("4.17.21"),
            );

            let (targets, structural) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(
                targets.len(),
                1,
                "two same-key occurrences are checked once"
            );
            assert!(structural.is_empty());
        }

        #[test]
        fn build_candidate_check_targets_dedups_duplicate_key_occurrences() {
            let parse_result = duplicated_registry_dep();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let mut cached_versions = HashMap::new();
            let available: Arc<[ConcreteVersion]> = Arc::from(vec![
                ConcreteVersion::new("2.0.0"),
                ConcreteVersion::new("1.0.0"),
            ]);
            cached_versions.insert(
                PackageName::new("lodash"),
                PackageVersions::new(ConcreteVersion::new("2.0.0"), available),
            );

            let (rounds, _) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(rounds[0].len(), 1);
            assert_eq!(rounds[1].len(), 1);
        }

        fn dup_other_dup() -> MockParseResult {
            let dep = |name: &str| MockDep {
                name: PackageName::new(name),
                source: DependencySource::Registry,
            };
            MockParseResult {
                deps: vec![dep("dup"), dep("other"), dep("dup")],
            }
        }

        #[test]
        fn build_latest_check_targets_keeps_first_occurrence_order() {
            let parse_result = dup_other_dup();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::new("dup"),
                PackageVersions::latest_only("2.0.0"),
            );
            cached_versions.insert(
                PackageName::new("other"),
                PackageVersions::latest_only("3.0.0"),
            );

            let (targets, _) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            let keys: Vec<_> = targets.iter().map(|t| t.key.clone()).collect();
            assert_eq!(
                keys,
                [
                    deps_core::test_util::vuln_key("dup"),
                    deps_core::test_util::vuln_key("other")
                ]
            );
            assert_eq!(targets[0].display_version, "2.0.0");
            assert_eq!(targets[1].display_version, "3.0.0");
        }

        #[test]
        fn build_candidate_check_targets_keeps_first_occurrence_order() {
            let parse_result = dup_other_dup();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let mut cached_versions = HashMap::new();
            for (name, newest) in [("dup", "2.0.0"), ("other", "3.0.0")] {
                let available: Arc<[ConcreteVersion]> =
                    Arc::from(vec![ConcreteVersion::new(newest)]);
                cached_versions.insert(
                    PackageName::new(name),
                    PackageVersions::new(ConcreteVersion::new(newest), available),
                );
            }

            let (rounds, _) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            let keys: Vec<_> = rounds[0].iter().map(|t| t.key.clone()).collect();
            assert_eq!(
                keys,
                [
                    deps_core::test_util::vuln_key("dup"),
                    deps_core::test_util::vuln_key("other")
                ]
            );
            assert_eq!(rounds[0][0].display_version, "2.0.0");
            assert_eq!(rounds[0][1].display_version, "3.0.0");
            assert!(rounds[1..].iter().all(Vec::is_empty));
        }

        #[test]
        fn build_candidate_check_targets_buckets_newest_first_by_round() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("pkg"),
                    source: DependencySource::Registry,
                }],
            };
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let mut cached_versions = HashMap::new();
            let available: Arc<[ConcreteVersion]> = Arc::from(vec![
                ConcreteVersion::new("3.0.0"),
                ConcreteVersion::new("2.0.0"),
                ConcreteVersion::new("1.0.0"),
            ]);
            cached_versions.insert(
                PackageName::new("pkg"),
                PackageVersions::new(ConcreteVersion::new("3.0.0"), available),
            );

            let (rounds, structural) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &StubFormatter::DEFAULT,
            );

            assert!(structural.is_empty());
            assert_eq!(
                rounds[0].len(),
                1,
                "round 0 must hold this dependency's newest candidate"
            );
            assert_eq!(rounds[0][0].display_version, "3.0.0");
            assert_eq!(rounds[1].len(), 1);
            assert_eq!(rounds[1][0].display_version, "2.0.0");
            assert_eq!(rounds[2].len(), 1);
            assert_eq!(rounds[2][0].display_version, "1.0.0");
            assert!(
                rounds[3..].iter().all(Vec::is_empty),
                "only 3 candidate versions were available, so later rounds must stay empty"
            );
        }
    }

    /// #462: `resolve_fix_target`'s pure per-dependency decision logic (reuse / provably
    /// clean / needs a live check / skip), and `apply_live_fix_target_statuses`'s handling of
    /// a live-check result map that may be missing keys (timeout/outage).
    mod fix_target_verification_tests {
        use super::*;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, UpgradeStatus,
            VulnSeverity, VulnerabilityMap,
        };
        use deps_core::test_util::StubFormatter;
        use std::sync::Arc;

        fn advisory(id: &str, fixed_versions: &[&str]) -> Arc<Advisory> {
            Arc::new(
                Advisory::new(
                    id.to_string(),
                    "2023-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                )
                .expect("valid osv id")
                .with_fixed_versions(
                    fixed_versions
                        .iter()
                        .copied()
                        .map(OsvVersion::new)
                        .collect(),
                ),
            )
        }

        fn dv(advisories: Vec<Arc<Advisory>>) -> DependencyVulnerabilities {
            let total = advisories.len();
            DependencyVulnerabilities::new(Capped::new(advisories, total))
        }

        /// Builds a one-entry [`deps_core::osv::LatestStatusMap`] for `"pkg"`.
        fn latest_status_map(status: UpgradeStatus) -> deps_core::osv::LatestStatusMap {
            let mut map = deps_core::osv::LatestStatusMap::new();
            map.insert(deps_core::test_util::vuln_key("pkg"), status);
            map
        }

        #[test]
        fn resolve_fix_target_skips_when_no_fix_is_recommended() {
            // No advisory has a known fix, so `recommended_fix()` returns `None`.
            let dv = dv(vec![advisory("A1", &[])]);
            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_reuses_latest_when_f_equals_latest() {
            // Case (c): F (1.2.0, the only advisory's fix) coincides with the already-checked
            // "latest" candidate — reuse its result, no live check queued.
            let latest_status = UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("1.2.0"),
            };
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let latest_status_map = latest_status_map(latest_status.clone());

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &latest_status_map,
                &HashMap::new(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(resolution, FixTargetResolution::Resolved(latest_status));
        }

        #[test]
        fn resolve_fix_target_always_needs_live_check_when_f_differs_from_latest() {
            // #462 critic C1: no data-derived shortcut — F is *computed from* these exact
            // advisories, so "F <= advisories' fix" is a tautology that proves nothing about
            // an advisory phase A never fetched. F (1.2.0) != latest (3.0.0) must always
            // queue a live check.
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let latest_status_map = latest_status_map(UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("3.0.0"),
            });
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("pkg"),
                deps_core::osv::OsvPackageName::new("pkg"),
            );

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &latest_status_map,
                &osv_name_by_key,
                &StubFormatter::DEFAULT,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    deps_core::test_util::vuln_key("pkg"),
                    deps_core::osv::OsvPackageName::new("pkg"),
                    OsvVersion::new("1.2.0"),
                    ConcreteVersion::new("1.2.0"),
                ))
            );
        }

        #[test]
        fn resolve_fix_target_never_reuses_a_candidate_unverified_latest() {
            // Issue #1517: a transient (or structural) `CandidateUnverified` latest-check
            // result must never be mistaken for a resolved "F == latest" match — even when
            // its own `version` field happens to equal F, that field is not a confirmed
            // clean/vulnerable verdict, so this must still queue a live check.
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let latest_status_map = latest_status_map(UpgradeStatus::CandidateUnverified {
                version: ConcreteVersion::new("1.2.0"),
                reason: deps_core::osv::SkipReason::QueryFailed,
            });
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("pkg"),
                deps_core::osv::OsvPackageName::new("pkg"),
            );

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &latest_status_map,
                &osv_name_by_key,
                &StubFormatter::DEFAULT,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    deps_core::test_util::vuln_key("pkg"),
                    deps_core::osv::OsvPackageName::new("pkg"),
                    OsvVersion::new("1.2.0"),
                    ConcreteVersion::new("1.2.0"),
                ))
            );
        }

        #[test]
        fn resolve_fix_target_skips_when_osv_name_is_unavailable() {
            // A live check is needed (F != latest) but no `osv_name` is on record for this
            // key — nothing to query, so this degrades to `Skip` rather than panicking or
            // building a `ScanTarget` with an empty name.
            let dv = dv(vec![advisory("A1", &["1.0.0"])]);
            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_skips_when_f_is_not_a_safe_version_string() {
            // A malformed `fixed_versions` entry (as if it somehow reached this dependency's
            // `advisories` despite OSV's own wire-boundary validation) must never be queued
            // for a live check or treated as any kind of resolvable target — `is_safe_version_string`
            // rejects it before anything else runs.
            let dv = dv(vec![advisory("A1", &["1.2.0\", \"evil\": \"true"])]);
            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn collect_fix_target_resolutions_batches_multiple_dependencies_needing_live_check_into_one_vec()
         {
            // #462 NFR-001: three vulnerable dependencies — "reused" (F == latest, resolved
            // without a call), "live-a" and "live-b" (F != latest, both need a live check) —
            // must collapse into exactly one `resolved` entry and one `live_check_candidates`
            // Vec of length 2, proving multiple dependencies needing verification are batched
            // into a single prospective `check_candidates` call rather than one per dependency.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("reused"),
                ScanOutcome::Vulnerable(dv(vec![advisory("A1", &["1.0.0"])])),
            );
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("live-a"),
                ScanOutcome::Vulnerable(dv(vec![advisory("A2", &["1.2.0"])])),
            );
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("live-b"),
                ScanOutcome::Vulnerable(dv(vec![advisory("A3", &["2.2.0"])])),
            );

            let vulnerable_keys = vec![
                deps_core::test_util::vuln_key("reused"),
                deps_core::test_util::vuln_key("live-a"),
                deps_core::test_util::vuln_key("live-b"),
            ];
            let mut latest_status: deps_core::osv::LatestStatusMap = HashMap::new();
            latest_status.insert(
                deps_core::test_util::vuln_key("reused"),
                UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.0.0"),
                },
            );
            latest_status.insert(
                deps_core::test_util::vuln_key("live-a"),
                UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("9.0.0"),
                },
            );
            latest_status.insert(
                deps_core::test_util::vuln_key("live-b"),
                UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("9.0.0"),
                },
            );
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("reused"),
                deps_core::osv::OsvPackageName::new("reused"),
            );
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("live-a"),
                deps_core::osv::OsvPackageName::new("live-a"),
            );
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("live-b"),
                deps_core::osv::OsvPackageName::new("live-b"),
            );

            let (resolved, live_check_candidates) = collect_fix_target_resolutions(
                &vulnerabilities,
                &vulnerable_keys,
                &osv_name_by_key,
                &latest_status,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(resolved.len(), 1, "{resolved:?}");
            assert_eq!(resolved[0].0.as_str(), "reused");

            assert_eq!(live_check_candidates.len(), 2, "{live_check_candidates:?}");
            let keys: std::collections::HashSet<&str> = live_check_candidates
                .iter()
                .map(|t| t.key.as_str())
                .collect();
            assert!(keys.contains("live-a"));
            assert!(keys.contains("live-b"));
        }

        #[test]
        fn apply_live_fix_target_statuses_sets_only_matching_keys_leaving_others_untouched() {
            // Case (e): a live-check batch that timed out for one dependency simply omits
            // its key from `statuses` — that dependency's `fix_target_status` must stay
            // `NotChecked` afterward, with no panic, while a dependency whose result did
            // arrive gets it applied.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("checked"),
                ScanOutcome::Vulnerable(dv(vec![advisory("A1", &["1.0.0"])])),
            );
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("timed-out"),
                ScanOutcome::Vulnerable(dv(vec![advisory("A2", &["1.0.0"])])),
            );

            let mut statuses = HashMap::new();
            statuses.insert(
                deps_core::test_util::vuln_key("checked"),
                UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.0.0"),
                },
            );
            // "timed-out" deliberately has no entry in `statuses`.

            apply_live_fix_target_statuses(&mut vulnerabilities, statuses);

            let ScanOutcome::Vulnerable(checked) = vulnerabilities
                .get(&deps_core::test_util::vuln_key("checked"))
                .unwrap()
            else {
                panic!("expected Vulnerable");
            };
            assert_eq!(
                checked.fix_target_status,
                UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.0.0")
                }
            );

            let ScanOutcome::Vulnerable(timed_out) = vulnerabilities
                .get(&deps_core::test_util::vuln_key("timed-out"))
                .unwrap()
            else {
                panic!("expected Vulnerable");
            };
            assert_eq!(timed_out.fix_target_status, UpgradeStatus::NotChecked);
        }
    }
}
