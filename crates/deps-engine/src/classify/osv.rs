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
use deps_core::lsp_helpers::{
    CandidateSiblings, CandidateSiblingsUnknown, CandidateTagSource, OsvNameAvailability,
    TaggedVersions, has_unqueryable_resolved_pin, resolve_in_use_versions,
};
use std::collections::HashMap;

/// Per-[`deps_core::osv::VulnKey`] sibling-tag sources for phase B's candidate checks (#1727).
///
/// Built once per phase B from the parsed manifest and shared by the latest, candidate and
/// fix-target builders, so all three agree on which candidate versions have sibling release
/// tags and none of them can silently skip the lookup.
#[derive(Debug, Clone)]
pub struct CandidateTagSources {
    ecosystem: EcosystemId,
    by_key: HashMap<deps_core::osv::VulnKey, CandidateTagSource>,
}

impl CandidateTagSources {
    /// The sibling release tags of `candidate` for the dependency scanned under `key`.
    ///
    /// A key absent from the sources is an error when any other dependency is tag based: phase A
    /// keys embed tag-index-derived signatures and can differ from phase B's, so an unknown key
    /// cannot be assumed to have no siblings. In an ecosystem without tag-based dependencies
    /// there is nothing to look up and the answer is an empty list.
    ///
    /// # Errors
    ///
    /// [`CandidateSiblingsUnknown`] when the siblings cannot be established.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{
    ///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    ///     RequirementResolution, SourcePolicy,
    /// };
    /// use deps_core::osv::vulnerability_keys;
    /// use deps_core::test_util::{stub_parse_result_with_dependencies, vuln_key};
    /// use deps_core::{ConcreteVersion, EcosystemId, PackageName};
    /// use deps_engine::classify::osv::candidate_tag_sources;
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
    /// let keys = vulnerability_keys(
    ///     parsed.as_ref(),
    ///     &HashMap::new(),
    ///     None,
    ///     &SimpleFormatter,
    ///     EcosystemId::Cargo,
    /// );
    /// let sources =
    ///     candidate_tag_sources(parsed.as_ref(), &keys, &SimpleFormatter, EcosystemId::Cargo);
    /// let siblings = sources
    ///     .siblings_for(&vuln_key("dep-0"), &ConcreteVersion::new("2.0.0"))
    ///     .unwrap();
    /// assert!(deps_core::lsp_helpers::TaggedVersions::siblings(&siblings).is_empty());
    /// ```
    pub fn siblings_for(
        &self,
        key: &deps_core::osv::VulnKey,
        candidate: &ConcreteVersion,
    ) -> Result<CandidateSiblings, CandidateSiblingsUnknown> {
        match self.by_key.get(key) {
            Some(source) => source.siblings_of(candidate, self.ecosystem),
            None if self.by_key.values().any(CandidateTagSource::is_tag_based) => {
                Err(CandidateSiblingsUnknown)
            }
            None => CandidateTagSource::NotTagBased.siblings_of(candidate, self.ecosystem),
        }
    }
}

/// Collects each dependency's [`CandidateTagSource`] under its phase-B scan key.
///
/// Occurrences sharing a key are merged by [`CandidateTagSource::merge`].
#[must_use]
pub fn candidate_tag_sources(
    parse_result: &dyn deps_core::ParseResult,
    vuln_keys: &deps_core::osv::VulnKeys,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> CandidateTagSources {
    let mut by_key: HashMap<deps_core::osv::VulnKey, CandidateTagSource> = HashMap::new();
    for dep in parse_result.dependencies() {
        let key = deps_core::osv::vuln_key_for(dep, Some(vuln_keys), formatter);
        let source = formatter.candidate_tag_source(dep);
        match by_key.remove(&key) {
            Some(existing) => by_key.insert(key, existing.merge(source)),
            None => by_key.insert(key, source),
        };
    }
    CandidateTagSources { ecosystem, by_key }
}

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
    use deps_core::osv::{OsvQueryName, ScanOutcome, SkipReason};
    use std::collections::hash_map::Entry;

    let mut targets: Vec<deps_core::osv::ScanTarget> = Vec::new();
    let mut target_index: HashMap<deps_core::osv::VulnKey, usize> = HashMap::new();
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
        let versions = resolve_in_use_versions(
            dep,
            &normalized_name,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        );

        let Some(versions) = versions else {
            let reason = if has_unqueryable_resolved_pin(dep, formatter, ecosystem) {
                SkipReason::ResolvedTagNotFullVersion
            } else {
                SkipReason::NoConcreteVersion
            };
            skipped.insert(key, ScanOutcome::Skipped(reason));
            continue;
        };

        let osv_name = match formatter.osv_name_availability(dep) {
            OsvNameAvailability::Ready => match formatter.osv_package_name(dep) {
                Some(name) => OsvQueryName::Confirmed(name),
                None => {
                    skipped.insert(key, ScanOutcome::Skipped(SkipReason::UnmappableName));
                    continue;
                }
            },
            OsvNameAvailability::AwaitingRegistryData {
                written_fallback: Some(name),
            } => OsvQueryName::Provisional(name),
            OsvNameAvailability::AwaitingRegistryData {
                written_fallback: None,
            } => {
                skipped.insert(
                    key,
                    ScanOutcome::Skipped(SkipReason::CanonicalNameUnconfirmed),
                );
                continue;
            }
        };

        let target = deps_core::osv::ScanTarget::from_native(
            key,
            osv_name,
            versions.primary().clone(),
            formatter,
        )
        .with_siblings(&versions, formatter);
        match target_index.entry(target.key.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(targets.len());
                targets.push(target);
            }
            Entry::Occupied(slot) => {
                if let Some(existing) = targets.get_mut(*slot.get())
                    && matches!(existing.osv_name, OsvQueryName::Provisional(_))
                    && matches!(target.osv_name, OsvQueryName::Confirmed(_))
                {
                    *existing = target;
                }
            }
        }
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
    /// A cached version list exists, but the OSV name still depends on registry data that has
    /// not landed (`OsvNameAvailability::AwaitingRegistryData`) — transient, never structural.
    AwaitingOsvName {
        /// This dependency's registry-cached version list.
        cached: &'a deps_core::lsp_helpers::PackageVersions,
    },
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

    if matches!(
        formatter.osv_name_availability(dep),
        OsvNameAvailability::AwaitingRegistryData { .. }
    ) {
        return DepCheckClassification::AwaitingOsvName { cached };
    }

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
/// use deps_engine::classify::osv::{build_latest_check_targets, candidate_tag_sources};
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
/// let candidate_tags = candidate_tag_sources(
///     parsed.as_ref(),
///     &vuln_keys,
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
///
/// let (targets, structural) = build_latest_check_targets(
///     parsed.as_ref(),
///     &cached_versions,
///     &vuln_keys,
///     &candidate_tags,
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
    candidate_tags: &CandidateTagSources,
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
            DepCheckClassification::AwaitingOsvName { cached } => {
                structural.insert(
                    key,
                    UpgradeStatus::CandidateUnverified {
                        version: cached.latest.clone(),
                        reason: SkipReason::CanonicalNameUnconfirmed,
                    },
                );
            }
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
                let Ok(siblings) = candidate_tags.siblings_for(&key, &cached.latest) else {
                    structural.insert(
                        key,
                        UpgradeStatus::CandidateUnverified {
                            version: cached.latest.clone(),
                            reason: SkipReason::SiblingTagsUnknown,
                        },
                    );
                    continue;
                };
                tracing::debug!(
                    key = %key,
                    siblings = siblings.siblings().len(),
                    "OSV latest check: candidate sibling tags"
                );
                targets.push(
                    deps_core::osv::ScanTarget::from_native(
                        key,
                        deps_core::osv::OsvQueryName::Confirmed(osv_name),
                        cached.latest.clone(),
                        formatter,
                    )
                    .with_siblings(&siblings, formatter),
                );
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
    candidate_tags: &CandidateTagSources,
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
                // Transient, like an absent cache: never recorded as structural.
                DepCheckClassification::AwaitingOsvName { .. } => continue,
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
            // Unknown siblings: no target, so the candidate reads as unverified (fail-closed).
            let Ok(siblings) = candidate_tags.siblings_for(&key, version) else {
                continue;
            };
            tracing::debug!(
                key = %key,
                siblings = siblings.siblings().len(),
                "OSV candidate check: candidate sibling tags"
            );
            bucket.push(
                deps_core::osv::ScanTarget::from_native(
                    key.clone(),
                    deps_core::osv::OsvQueryName::Confirmed(osv_name.clone()),
                    version.clone(),
                    formatter,
                )
                .with_siblings(&siblings, formatter),
            );
        }
    }

    (rounds, structural)
}

/// Outcome of `resolve_fix_target` for one vulnerable dependency.
#[derive(Debug, PartialEq, Eq)]
enum FixTargetResolution {
    /// No fix recommended, F failed [`deps_core::lsp_helpers::is_safe_version_string`], or no
    /// `osv_name` is on record for this key, or that name is only provisional (#1694) — nothing to
    /// verify or record; `fix_target_status`
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
    osv_name_by_key: &HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName>,
    candidate_tags: &CandidateTagSources,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> FixTargetResolution {
    use deps_core::edit::{VulnFixSkip, resolve_recommended_fix};
    use deps_core::osv::{OsvQueryName, ScanTarget, UpgradeStatus};

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

    let Some(osv_name) = osv_name_by_key.get(key) else {
        tracing::debug!(
            key = %key,
            "OSV #462: no osv_name on record for fix-target verification, skipping"
        );
        return FixTargetResolution::Skip;
    };
    let osv_name = match osv_name {
        OsvQueryName::Confirmed(name) => name.clone(),
        OsvQueryName::Provisional(_) => {
            tracing::debug!(
                key = %key,
                "OSV #1694: unconfirmed package name, fix target stays unverified"
            );
            return FixTargetResolution::Skip;
        }
    };
    let display_version = ConcreteVersion::new(version_native);
    let Ok(siblings) = candidate_tags.siblings_for(key, &display_version) else {
        return FixTargetResolution::Resolved(UpgradeStatus::CandidateUnverified {
            version: display_version,
            reason: deps_core::osv::SkipReason::SiblingTagsUnknown,
        });
    };
    tracing::debug!(
        key = %key,
        siblings = siblings.siblings().len(),
        "OSV fix-target check: candidate sibling tags"
    );
    FixTargetResolution::NeedsLiveCheck(
        ScanTarget::new(
            key.clone(),
            OsvQueryName::Confirmed(osv_name),
            fix.version,
            display_version,
        )
        .with_siblings(&siblings, formatter),
    )
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
///     VulnSeverity, VulnerabilityMap, vulnerability_keys,
/// };
/// use deps_core::test_util::{stub_parse_result_with_dependencies, vuln_key};
/// use deps_core::{ConcreteVersion, EcosystemId, PackageName};
/// use deps_engine::classify::osv::{candidate_tag_sources, collect_fix_target_resolutions};
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
/// let parsed = stub_parse_result_with_dependencies(1);
/// let vuln_keys = vulnerability_keys(
///     parsed.as_ref(),
///     &HashMap::new(),
///     None,
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
/// let candidate_tags = candidate_tag_sources(
///     parsed.as_ref(),
///     &vuln_keys,
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
/// let (resolved, live_check_candidates) = collect_fix_target_resolutions(
///     &vulnerabilities,
///     &[vuln_key("pkg")],
///     &HashMap::new(),
///     &latest_status_map,
///     &candidate_tags,
///     &SimpleFormatter,
/// );
///
/// assert_eq!(resolved, vec![(vuln_key("pkg"), latest_status)]);
/// assert!(live_check_candidates.is_empty());
/// ```
pub fn collect_fix_target_resolutions(
    vulnerabilities: &deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[deps_core::osv::VulnKey],
    osv_name_by_key: &HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName>,
    latest_status: &deps_core::osv::LatestStatusMap,
    candidate_tags: &CandidateTagSources,
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
        match resolve_fix_target(
            dv,
            key,
            latest_status,
            osv_name_by_key,
            candidate_tags,
            formatter,
        ) {
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
/// use deps_core::osv::{OsvPackageName, OsvQueryName, OsvVersion, ScanTarget};
/// use deps_core::test_util::vuln_key;
/// use deps_engine::classify::osv::osv_name_by_key;
///
/// let name = OsvQueryName::Confirmed(OsvPackageName::new("serde").unwrap());
/// let targets = vec![ScanTarget::new(
///     vuln_key("serde"),
///     name.clone(),
///     OsvVersion::new("1.0.0"),
///     ConcreteVersion::new("1.0.0"),
/// )];
/// let map = osv_name_by_key(&targets);
/// assert_eq!(map.get(&vuln_key("serde")), Some(&name));
/// ```
#[must_use]
pub fn osv_name_by_key(
    targets: &[deps_core::osv::ScanTarget],
) -> HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName> {
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

    fn no_tags() -> CandidateTagSources {
        CandidateTagSources {
            ecosystem: EcosystemId::Cargo,
            by_key: HashMap::new(),
        }
    }

    fn tagged_source(
        tags: &[(&str, char)],
        scope: deps_core::lsp_helpers::SiblingScope,
    ) -> CandidateTagSource {
        tagged_source_with_coverage(tags, scope, deps_core::pagination::ListCoverage::Complete)
    }

    fn tagged_source_with_coverage(
        tags: &[(&str, char)],
        scope: deps_core::lsp_helpers::SiblingScope,
        coverage: deps_core::pagination::ListCoverage,
    ) -> CandidateTagSource {
        let shas: Vec<(&str, deps_core::lsp_helpers::CommitSha)> = tags
            .iter()
            .map(|(tag, c)| {
                (
                    *tag,
                    deps_core::lsp_helpers::CommitSha::parse(&c.to_string().repeat(40)).unwrap(),
                )
            })
            .collect();
        CandidateTagSource::Indexed {
            index: std::sync::Arc::new(
                deps_core::lsp_helpers::TagIndex::from_tags(
                    shas.iter().map(|(tag, sha)| (*tag, sha)),
                )
                .with_coverage(coverage),
            ),
            scope,
        }
    }

    fn sources_with(key: &str, source: CandidateTagSource) -> CandidateTagSources {
        CandidateTagSources {
            ecosystem: EcosystemId::GithubActions,
            by_key: HashMap::from([(deps_core::test_util::vuln_key(key), source)]),
        }
    }

    #[test]
    fn siblings_for_key_miss_is_unknown_only_when_some_entry_is_tag_based() {
        let candidate = ConcreteVersion::new("1.0.0");
        let missing = deps_core::test_util::vuln_key("missing");

        let tag_based = sources_with("other", CandidateTagSource::NotYetIndexed);
        assert!(tag_based.siblings_for(&missing, &candidate).is_err());

        let plain = sources_with("other", CandidateTagSource::NotTagBased);
        assert!(plain.siblings_for(&missing, &candidate).is_ok());
    }

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
            assert_eq!(targets[0].osv_name.name(), "symfony/http-kernel");
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
            assert_eq!(targets[0].osv_name.name(), "werkzeug");
            assert_eq!(skipped.len(), 1);
            // The skip is keyed by the normalized name, which is empty for `---`.
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("")),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName))
            );
        }

        /// #1689: a Dart `+N` build-number pin with no lock file is a concrete OSV query target.
        #[cfg(feature = "dart")]
        #[test]
        fn build_scan_targets_dart_plus_build_number_pin_without_lockfile_is_queried() {
            let dep = |name: &str, req: &str| MockDep {
                name: PackageName::new(name),
                version_req: Some(VersionReq::new(req)),
                source: DependencySource::Registry,
            };
            let parse_result = MockParseResult {
                deps: vec![
                    dep("image_picker_android", "0.8.13+1"),
                    dep("caret_pkg", "^0.8.13+1"),
                ],
            };

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &deps_dart::DartFormatter,
                EcosystemId::Dart,
            );

            assert_eq!(targets.len(), 1, "{skipped:?}");
            assert_eq!(targets[0].display_version, "0.8.13+1");
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
                deps_core::lsp_helpers::ResolvedPin::most_specific(
                    deps_core::ConcreteVersion::new("v1"),
                ),
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
                    Arc::new(
                        TagIndex::from_tags(tags.iter().map(|t| (*t, &commit)))
                            .with_canonical_repo_name(
                                deps_core::github::CanonicalRepoName::from_commit_url(
                                    "https://api.github.com/repos/actions/checkout/commits/abc",
                                ),
                            ),
                    ),
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
                deps_core::lsp_helpers::ResolvedPin::most_specific(
                    deps_core::ConcreteVersion::new("v1.3.0"),
                ),
            );
            let index = index.with_canonical_repo_name(
                deps_core::github::CanonicalRepoName::from_commit_url(
                    "https://api.github.com/repos/actions/checkout/commits/abc",
                ),
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

        /// #1709: every release tag on the pinned commit reaches the scan target, for a SHA pin
        /// and for an exact tag pin (primary stays the written tag); no sibling for a lone tag.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_attaches_sibling_release_tags() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let sha = "e".repeat(40);
            let commit = CommitSha::parse(&sha).unwrap();
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!(
                "steps:\n  - uses: actions/checkout@{sha}\n  - uses: other/action@v4.9.0\n"
            );
            let parse_result =
                deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");

            let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
            let tag_index = registry.tag_index();
            let canonical = |repo: &str| {
                deps_core::github::CanonicalRepoName::from_commit_url(&format!(
                    "https://api.github.com/repos/{repo}/commits/abc"
                ))
            };
            tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(
                    TagIndex::from_tags([("v4.8.0", &commit), ("v4.9.0", &commit)])
                        .with_canonical_repo_name(canonical("actions/checkout")),
                ),
            );
            tag_index.insert(
                PackageName::new("other/action"),
                Arc::new(
                    TagIndex::from_tags([("v4.9.0", &commit), ("v4.10.0", &commit)])
                        .with_canonical_repo_name(canonical("other/action")),
                ),
            );
            let formatter = GithubActionsFormatter::new(tag_index);

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &formatter,
                EcosystemId::GithubActions,
            );

            assert!(skipped.is_empty(), "{skipped:?}");
            let versions = |name: &str| {
                let target = targets
                    .iter()
                    .find(|t| t.key.as_str() == name)
                    .expect("target for name");
                (
                    target.display_version.to_string(),
                    target
                        .siblings()
                        .iter()
                        .map(|s| s.display_version().to_string())
                        .collect::<Vec<_>>(),
                )
            };
            assert_eq!(
                versions("actions/checkout"),
                ("v4.8.0".to_string(), vec!["v4.9.0".to_string()])
            );
            assert_eq!(
                versions("other/action"),
                ("v4.9.0".to_string(), vec!["v4.10.0".to_string()])
            );
        }

        /// #1769: a truncated tag list marks the in-use target's sibling list incomplete, for a
        /// listed SHA pin and for an exact tag pin the list does not reach (read from text).
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_truncated_index_marks_siblings_incomplete() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_core::pagination::ListCoverage;
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let sha = "e".repeat(40);
            let commit = CommitSha::parse(&sha).unwrap();
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!(
                "steps:\n  - uses: actions/checkout@{sha}\n  - uses: other/action@v4.9.0\n"
            );
            let parse_result =
                deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");

            let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
            let tag_index = registry.tag_index();
            let canonical = |repo: &str| {
                deps_core::github::CanonicalRepoName::from_commit_url(&format!(
                    "https://api.github.com/repos/{repo}/commits/abc"
                ))
            };
            for (repo, tag) in [("actions/checkout", "v4.8.0"), ("other/action", "v4.1.0")] {
                tag_index.insert(
                    PackageName::new(repo),
                    Arc::new(
                        TagIndex::from_tags([(tag, &commit)])
                            .with_canonical_repo_name(canonical(repo))
                            .with_coverage(ListCoverage::Truncated),
                    ),
                );
            }
            let formatter = GithubActionsFormatter::new(tag_index);

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &formatter,
                EcosystemId::GithubActions,
            );

            assert!(skipped.is_empty(), "{skipped:?}");
            assert_eq!(targets.len(), 2);
            assert!(
                targets
                    .iter()
                    .all(|t| t.sibling_coverage() == ListCoverage::Truncated),
                "{targets:?}"
            );
        }

        #[test]
        fn build_scan_targets_without_a_tag_pin_has_no_siblings() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, _) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &StubFormatter::DEFAULT,
                EcosystemId::Maven,
            );
            assert!(targets.iter().all(|t| t.siblings().is_empty()));
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

        /// A formatter whose OSV name is derived from registry data that has not landed yet;
        /// `with_fallback` offers the written name as a provisional query name (#1694).
        #[derive(Default)]
        struct AwaitingNameFormatter {
            with_fallback: bool,
        }
        impl PackageNaming for AwaitingNameFormatter {}
        impl PackageRendering for AwaitingNameFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for AwaitingNameFormatter {}
        impl DiagnosticMessages for AwaitingNameFormatter {}
        impl DiagnosticPolicy for AwaitingNameFormatter {}
        impl SourcePolicy for AwaitingNameFormatter {}
        impl OsvNaming for AwaitingNameFormatter {
            fn osv_name_availability(
                &self,
                dep: &dyn Dependency,
            ) -> deps_core::lsp_helpers::OsvNameAvailability {
                deps_core::lsp_helpers::OsvNameAvailability::AwaitingRegistryData {
                    written_fallback: self
                        .with_fallback
                        .then(|| deps_core::osv::OsvPackageName::new_or_skip(dep.name().as_str()))
                        .flatten(),
                }
            }
        }

        fn awaiting_name_fixture() -> (
            MockParseResult,
            deps_core::osv::VulnKeys,
            HashMap<PackageName, PackageVersions>,
        ) {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("gha-action"),
                    source: DependencySource::Registry,
                }],
            };
            let vuln_keys = vuln_keys_for(&parse_result, &AwaitingNameFormatter::default());
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::new("gha-action"),
                PackageVersions::latest_only("1.0.0"),
            );
            (parse_result, vuln_keys, cached_versions)
        }

        #[test]
        fn build_latest_check_targets_awaiting_osv_name_is_unverified_not_structural() {
            let (parse_result, vuln_keys, cached_versions) = awaiting_name_fixture();

            let (targets, statuses) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &no_tags(),
                &AwaitingNameFormatter::default(),
            );

            assert!(targets.is_empty());
            assert_eq!(
                statuses.get(&deps_core::test_util::vuln_key("gha-action")),
                Some(&UpgradeStatus::CandidateUnverified {
                    version: ConcreteVersion::new("1.0.0"),
                    reason: deps_core::osv::SkipReason::CanonicalNameUnconfirmed,
                })
            );
        }

        #[test]
        fn build_candidate_check_targets_awaiting_osv_name_records_no_entry() {
            let (parse_result, vuln_keys, cached_versions) = awaiting_name_fixture();

            let (rounds, statuses) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &no_tags(),
                &AwaitingNameFormatter::default(),
            );

            assert!(rounds.iter().all(Vec::is_empty));
            assert!(
                statuses.is_empty(),
                "a transient name gap must never be stored as structural: {statuses:?}"
            );
        }

        /// #1694: an unconfirmed casing queries the written name as a provisional target
        /// (only a positive answer is trusted); a confirmed one is the authoritative target.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_unconfirmed_name_is_provisional() {
            use deps_core::lsp_helpers::TagIndex;
            use deps_core::osv::OsvQueryName;
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = deps_github_actions::parse_workflow_yaml(
                "steps:\n  - uses: azure/setup-kubectl@v4.1.2\n",
                &uri,
            )
            .expect("valid yaml");
            let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
            let written = deps_core::osv::OsvPackageName::new("azure/setup-kubectl").unwrap();
            let canonical = deps_core::osv::OsvPackageName::new("Azure/setup-kubectl").unwrap();

            for warm_without_canonical in [false, true] {
                let tag_index = registry.tag_index();
                tag_index.clear();
                if warm_without_canonical {
                    tag_index.insert(
                        PackageName::new("azure/setup-kubectl"),
                        Arc::new(TagIndex::default()),
                    );
                }
                let formatter = GithubActionsFormatter::new(tag_index);

                let (targets, skipped) = build_scan_targets(
                    &parse_result,
                    &HashMap::new(),
                    &HashMap::new(),
                    &formatter,
                    EcosystemId::GithubActions,
                );

                assert!(skipped.is_empty(), "{skipped:?}");
                assert_eq!(targets.len(), 1);
                assert_eq!(
                    targets[0].osv_name,
                    OsvQueryName::Provisional(written.clone()),
                    "warm_without_canonical={warm_without_canonical}"
                );
            }

            let tag_index = registry.tag_index();
            tag_index.insert(
                PackageName::new("azure/setup-kubectl"),
                Arc::new(TagIndex::default().with_canonical_repo_name(
                    deps_core::github::CanonicalRepoName::from_commit_url(
                        "https://api.github.com/repos/Azure/setup-kubectl/commits/abc",
                    ),
                )),
            );
            let formatter = GithubActionsFormatter::new(tag_index);
            let (targets, _) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &formatter,
                EcosystemId::GithubActions,
            );
            assert_eq!(targets[0].osv_name, OsvQueryName::Confirmed(canonical));
        }

        /// #1684: a floating `@v4` scans the release its tag's commit carries, and stays an
        /// honest skip while the index is cold or the commit only carries the floating tag.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_floating_tag_resolves_via_commit() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_core::osv::{OsvQueryName, ScanOutcome, SkipReason};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = deps_github_actions::parse_workflow_yaml(
                "steps:\n  - uses: actions/checkout@v4\n",
                &uri,
            )
            .expect("valid yaml");
            let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
            let key = deps_core::test_util::vuln_key("actions/checkout");
            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            let scan = |tags: &[&str]| {
                let tag_index = registry.tag_index();
                tag_index.clear();
                if !tags.is_empty() {
                    let index = TagIndex::from_tags(tags.iter().map(|t| (*t, &commit)))
                        .with_canonical_repo_name(
                            deps_core::github::CanonicalRepoName::from_commit_url(
                                "https://api.github.com/repos/actions/checkout/commits/abc",
                            ),
                        );
                    tag_index.insert(PackageName::new("actions/checkout"), Arc::new(index));
                }
                build_scan_targets(
                    &parse_result,
                    &HashMap::new(),
                    &HashMap::new(),
                    &GithubActionsFormatter::new(tag_index),
                    EcosystemId::GithubActions,
                )
            };

            let (targets, skipped) = scan(&["v4", "v4.2.2"]);
            assert!(skipped.is_empty(), "{skipped:?}");
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "4.2.2");
            assert_matches!(targets[0].osv_name, OsvQueryName::Confirmed(_));

            let (targets, skipped) = scan(&[]);
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&key),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );

            let (targets, skipped) = scan(&["v4"]);
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&key),
                Some(ScanOutcome::Skipped(SkipReason::ResolvedTagNotFullVersion))
            );
        }

        /// #1795: a full-release tag pin no published tag matches is never queried, so hover and
        /// diagnostics report vulnerability data as not checked (`NoConcreteVersion`'s footer)
        /// instead of a clean result; a listed tag is still scanned.
        #[cfg(feature = "github-actions")]
        #[test]
        fn build_scan_targets_github_actions_unpublished_tag_pin_is_not_checked() {
            use deps_core::lsp_helpers::{CommitSha, TagIndex};
            use deps_core::osv::{ScanOutcome, SkipReason};
            use deps_github_actions::{GithubActionsFormatter, GithubActionsRegistry};
            use std::sync::Arc;

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = deps_github_actions::parse_workflow_yaml(
                "steps:\n  - uses: actions/checkout@4.2.2\n  - uses: actions/checkout@v999.0.0\n",
                &uri,
            )
            .expect("valid yaml");
            let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            registry.tag_index().insert(
                PackageName::new("actions/checkout"),
                Arc::new(
                    TagIndex::from_tags([("v4.2.2", &commit)]).with_canonical_repo_name(
                        deps_core::github::CanonicalRepoName::from_commit_url(
                            "https://api.github.com/repos/actions/checkout/commits/abc",
                        ),
                    ),
                ),
            );

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &GithubActionsFormatter::new(registry.tag_index()),
                EcosystemId::GithubActions,
            );
            assert!(targets.is_empty(), "{targets:?}");
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("actions/checkout")),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
        }

        /// #1694: a written name that is not a valid OSV name stays a fail-closed skip.
        #[test]
        fn build_scan_targets_awaiting_name_without_fallback_is_unconfirmed_skip() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("gha-action"),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(
                PackageName::new("gha-action"),
                ConcreteVersion::new("1.0.0"),
            );

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &AwaitingNameFormatter::default(),
                EcosystemId::Cargo,
            );

            assert!(targets.is_empty());
            assert_matches!(
                skipped.get(&deps_core::test_util::vuln_key("gha-action")),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::CanonicalNameUnconfirmed
                ))
            );
        }

        /// A formatter reporting a different name availability per successive dependency.
        struct SequencedNameFormatter {
            ready: [bool; 2],
            calls: std::sync::atomic::AtomicUsize,
        }
        impl PackageNaming for SequencedNameFormatter {}
        impl PackageRendering for SequencedNameFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for SequencedNameFormatter {}
        impl DiagnosticMessages for SequencedNameFormatter {}
        impl DiagnosticPolicy for SequencedNameFormatter {}
        impl SourcePolicy for SequencedNameFormatter {}
        impl OsvNaming for SequencedNameFormatter {
            fn osv_name_availability(
                &self,
                dep: &dyn Dependency,
            ) -> deps_core::lsp_helpers::OsvNameAvailability {
                let idx = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.ready[idx] {
                    deps_core::lsp_helpers::OsvNameAvailability::Ready
                } else {
                    deps_core::lsp_helpers::OsvNameAvailability::AwaitingRegistryData {
                        written_fallback: deps_core::osv::OsvPackageName::new_or_skip(
                            dep.name().as_str(),
                        ),
                    }
                }
            }
        }

        /// #1694 (critic M1): occurrences sharing a key collapse to one target, and a
        /// confirmed name wins over a provisional one whichever comes first.
        #[test]
        fn build_scan_targets_dedups_per_key_preferring_confirmed_name() {
            use deps_core::osv::OsvQueryName;

            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("dup"), ConcreteVersion::new("1.0.0"));
            let name = deps_core::osv::OsvPackageName::new("dup").unwrap();

            for (ready, expected) in [
                ([false, true], OsvQueryName::Confirmed(name.clone())),
                ([true, false], OsvQueryName::Confirmed(name.clone())),
                ([false, false], OsvQueryName::Provisional(name)),
            ] {
                let parse_result = MockParseResult {
                    deps: ["dup", "dup"]
                        .into_iter()
                        .map(|n| MockDep {
                            name: PackageName::new(n),
                            source: DependencySource::Registry,
                        })
                        .collect(),
                };
                let formatter = SequencedNameFormatter {
                    ready,
                    calls: std::sync::atomic::AtomicUsize::new(0),
                };
                let (targets, _) = build_scan_targets(
                    &parse_result,
                    &resolved,
                    &HashMap::new(),
                    &formatter,
                    EcosystemId::Cargo,
                );
                assert_eq!(targets.len(), 1, "ready={ready:?}");
                assert_eq!(targets[0].osv_name, expected, "ready={ready:?}");
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

        fn gha_like_fixture() -> (MockParseResult, HashMap<PackageName, PackageVersions>) {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("gha-action"),
                    source: DependencySource::Registry,
                }],
            };
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::new("gha-action"),
                PackageVersions::latest_only("v4.8.0"),
            );
            (parse_result, cached_versions)
        }

        #[test]
        fn build_latest_check_targets_attaches_candidate_siblings_without_touching_the_version() {
            let (parse_result, cached_versions) = gha_like_fixture();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let sources = sources_with(
                "gha-action",
                tagged_source(
                    &[("v4.8.0", 'a'), ("v4.9.0", 'a'), ("v5.0.0", 'a')],
                    deps_core::lsp_helpers::SiblingScope::SameMajor,
                ),
            );

            let (targets, structural) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &sources,
                &StubFormatter::DEFAULT,
            );

            assert!(structural.is_empty());
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].display_version, "v4.8.0");
            let siblings: Vec<&str> = targets[0]
                .siblings()
                .iter()
                .map(|s| s.display_version().as_str())
                .collect();
            assert_eq!(siblings, ["v4.9.0"]);
        }

        /// #1769: a truncated tag list marks the candidate target's sibling list incomplete.
        #[test]
        fn build_latest_check_targets_truncated_index_marks_siblings_incomplete() {
            use deps_core::pagination::ListCoverage;

            let (parse_result, cached_versions) = gha_like_fixture();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let sources = sources_with(
                "gha-action",
                tagged_source_with_coverage(
                    &[("v4.8.0", 'a'), ("v4.9.0", 'a')],
                    deps_core::lsp_helpers::SiblingScope::SameMajor,
                    ListCoverage::Truncated,
                ),
            );

            let (targets, _) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &sources,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(targets[0].sibling_coverage(), ListCoverage::Truncated);
        }

        #[test]
        fn build_latest_check_targets_whole_commit_scope_spans_majors() {
            let (parse_result, cached_versions) = gha_like_fixture();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let sources = sources_with(
                "gha-action",
                tagged_source(
                    &[("v4.8.0", 'a'), ("v5.0.0", 'a')],
                    deps_core::lsp_helpers::SiblingScope::WholeCommit,
                ),
            );

            let (targets, _) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &sources,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(targets[0].siblings().len(), 1);
        }

        #[test]
        fn build_latest_check_targets_cold_tag_index_is_unverified_not_clean() {
            let (parse_result, cached_versions) = gha_like_fixture();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);
            let sources = sources_with("gha-action", CandidateTagSource::NotYetIndexed);

            let (targets, structural) = build_latest_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &sources,
                &StubFormatter::DEFAULT,
            );

            assert!(targets.is_empty());
            assert_eq!(
                structural.get(&deps_core::test_util::vuln_key("gha-action")),
                Some(&UpgradeStatus::CandidateUnverified {
                    version: ConcreteVersion::new("v4.8.0"),
                    reason: deps_core::osv::SkipReason::SiblingTagsUnknown,
                })
            );
        }

        #[test]
        fn build_candidate_check_targets_omits_candidates_with_unknown_siblings() {
            let (parse_result, cached_versions) = gha_like_fixture();
            let vuln_keys = vuln_keys_for(&parse_result, &StubFormatter::DEFAULT);

            let (control, _) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &no_tags(),
                &StubFormatter::DEFAULT,
            );
            assert!(control.iter().any(|round| !round.is_empty()));

            let cold = sources_with("gha-action", CandidateTagSource::NotYetIndexed);
            let (rounds, _) = build_candidate_check_targets(
                &parse_result,
                &cached_versions,
                &vuln_keys,
                &cold,
                &StubFormatter::DEFAULT,
            );
            assert!(rounds.iter().all(Vec::is_empty));
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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
                &no_tags(),
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

        fn name_map(key: &str) -> HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName> {
            HashMap::from([(
                deps_core::test_util::vuln_key(key),
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new(key).unwrap(),
                ),
            )])
        }

        #[test]
        fn resolve_fix_target_attaches_siblings_and_keeps_the_native_version() {
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let sources = sources_with(
                "pkg",
                tagged_source(
                    &[("1.2.0", 'a'), ("1.2.1", 'a')],
                    deps_core::lsp_helpers::SiblingScope::SameMajor,
                ),
            );

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &HashMap::new(),
                &name_map("pkg"),
                &sources,
                &StubFormatter::DEFAULT,
            );

            let FixTargetResolution::NeedsLiveCheck(target) = resolution else {
                panic!("expected a live check, got {resolution:?}");
            };
            assert_eq!(target.display_version, "1.2.0");
            assert_eq!(target.siblings().len(), 1);
        }

        #[test]
        fn resolve_fix_target_phase_a_key_missing_from_phase_b_sources_is_unverified() {
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let sources = sources_with("other", CandidateTagSource::NotYetIndexed);

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &HashMap::new(),
                &name_map("pkg"),
                &sources,
                &StubFormatter::DEFAULT,
            );

            assert_eq!(
                resolution,
                FixTargetResolution::Resolved(UpgradeStatus::CandidateUnverified {
                    version: ConcreteVersion::new("1.2.0"),
                    reason: deps_core::osv::SkipReason::SiblingTagsUnknown,
                })
            );
        }

        #[test]
        fn resolve_fix_target_looks_up_siblings_only_after_reuse_and_provisional_checks() {
            let cold = sources_with("pkg", CandidateTagSource::NotYetIndexed);
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let key = deps_core::test_util::vuln_key("pkg");

            let reused = UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("1.2.0"),
            };
            assert_eq!(
                resolve_fix_target(
                    &dv,
                    &key,
                    &latest_status_map(reused.clone()),
                    &HashMap::new(),
                    &cold,
                    &StubFormatter::DEFAULT,
                ),
                FixTargetResolution::Resolved(reused)
            );

            let provisional = HashMap::from([(
                key.clone(),
                deps_core::osv::OsvQueryName::Provisional(
                    deps_core::osv::OsvPackageName::new("pkg").unwrap(),
                ),
            )]);
            assert_eq!(
                resolve_fix_target(
                    &dv,
                    &key,
                    &HashMap::new(),
                    &provisional,
                    &cold,
                    &StubFormatter::DEFAULT,
                ),
                FixTargetResolution::Skip
            );
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
                &no_tags(),
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
                &no_tags(),
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
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new("pkg").unwrap(),
                ),
            );

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &latest_status_map,
                &osv_name_by_key,
                &no_tags(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    deps_core::test_util::vuln_key("pkg"),
                    deps_core::osv::OsvQueryName::Confirmed(
                        deps_core::osv::OsvPackageName::new("pkg").unwrap()
                    ),
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
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new("pkg").unwrap(),
                ),
            );

            let resolution = resolve_fix_target(
                &dv,
                &deps_core::test_util::vuln_key("pkg"),
                &latest_status_map,
                &osv_name_by_key,
                &no_tags(),
                &StubFormatter::DEFAULT,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    deps_core::test_util::vuln_key("pkg"),
                    deps_core::osv::OsvQueryName::Confirmed(
                        deps_core::osv::OsvPackageName::new("pkg").unwrap()
                    ),
                    OsvVersion::new("1.2.0"),
                    ConcreteVersion::new("1.2.0"),
                ))
            );
        }

        /// #1694: a fix target can never be verified through an unconfirmed name — a clean
        /// answer there is not evidence, so the fix stays unverified and no query is queued.
        #[test]
        fn resolve_fix_target_skips_provisional_name_and_queues_no_live_check() {
            let dv = dv(vec![advisory("A1", &["1.2.0"])]);
            let key = deps_core::test_util::vuln_key("pkg");
            let latest_status_map = latest_status_map(UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("3.0.0"),
            });
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert(
                key.clone(),
                deps_core::osv::OsvQueryName::Provisional(
                    deps_core::osv::OsvPackageName::new("pkg").unwrap(),
                ),
            );

            assert_eq!(
                resolve_fix_target(
                    &dv,
                    &key,
                    &latest_status_map,
                    &osv_name_by_key,
                    &no_tags(),
                    &StubFormatter::DEFAULT,
                ),
                FixTargetResolution::Skip
            );

            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(key.clone(), ScanOutcome::Vulnerable(dv));
            let (resolved, live_check_candidates) = collect_fix_target_resolutions(
                &vulnerabilities,
                &[key],
                &osv_name_by_key,
                &latest_status_map,
                &no_tags(),
                &StubFormatter::DEFAULT,
            );
            assert!(resolved.is_empty(), "{resolved:?}");
            assert!(
                live_check_candidates.is_empty(),
                "{live_check_candidates:?}"
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
                &no_tags(),
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
                &no_tags(),
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
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new("reused").unwrap(),
                ),
            );
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("live-a"),
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new("live-a").unwrap(),
                ),
            );
            osv_name_by_key.insert(
                deps_core::test_util::vuln_key("live-b"),
                deps_core::osv::OsvQueryName::Confirmed(
                    deps_core::osv::OsvPackageName::new("live-b").unwrap(),
                ),
            );

            let (resolved, live_check_candidates) = collect_fix_target_resolutions(
                &vulnerabilities,
                &vulnerable_keys,
                &osv_name_by_key,
                &latest_status,
                &no_tags(),
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
