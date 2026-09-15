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
use deps_core::lsp_helpers::resolve_in_use_version;
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
///         name.to_string()
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
        let key = keys
            .get(&dep.name_range())
            .cloned()
            .unwrap_or_else(|| normalized_name.clone());

        if !formatter.source_is_public_registry_content(&dep.source()) {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NonRegistrySource));
            continue;
        }

        // lockfile holds the pin) — so for a Go `require` dependency the
        // manifest itself is the authoritative version, not go.sum. go.sum is
        // a checksum ledger that `go get`/`go build` only ever append to
        // (only `go mod tidy` prunes it), so its last-occurrence-wins parse
        // can yield a stale version still recorded in the file but no longer
        // selected by Go's MVS, silently mismatching whatever's actually in
        // use. Skipping the lockfile lookup avoids feeding that stale version
        // to OSV (excludes/replaces fall through to the lockfile lookup below
        // like any other ecosystem, since their `version_requirement()` is
        // not an in-use version — see `manifest_requirement_is_resolved_version`).
        let version = resolve_in_use_version(
            dep,
            &normalized_name,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        );

        let Some(version) = version else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NoConcreteVersion));
            continue;
        };

        let Some(osv_name) = formatter.osv_package_name(dep) else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::UnmappableName));
            continue;
        };

        targets.push(deps_core::osv::ScanTarget::new(
            key,
            osv_name,
            formatter.osv_version(&version),
            version,
        ));
    }

    (targets, skipped)
}
/// Synthetic [`deps_core::osv::ScanTarget::key`] suffix marking a fix-target (F) live-check
/// candidate as distinct from the same dependency's "latest" candidate (B.1) within the
/// shared `VulnerabilityMap` key space — see `run_osv_fix_target_verification`.
const FIX_TARGET_KEY_SUFFIX: &str = "\u{0}fix";
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
    /// combined call (NFR-001), keyed with `FIX_TARGET_KEY_SUFFIX` so its result cannot
    /// collide with the same dependency's "latest" candidate in the same `VulnerabilityMap`
    /// key space.
    NeedsLiveCheck(deps_core::osv::ScanTarget),
}
/// Pure (network-free) decision logic for `run_osv_fix_target_verification`'s per-dependency
/// resolution order — see that function's doc for the two cases and their rationale. Split
/// out so each case is unit-testable without an `OsvClient`/network dependency.
fn resolve_fix_target(
    dv: &deps_core::osv::DependencyVulnerabilities,
    key: &str,
    latest_native_by_key: &HashMap<String, String>,
    osv_name_by_key: &HashMap<String, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> FixTargetResolution {
    use deps_core::lsp_helpers::is_safe_version_string;
    use deps_core::osv::ScanTarget;

    let Some(fix) = dv.recommended_fix() else {
        return FixTargetResolution::Skip;
    };
    let version_native = formatter.osv_version_to_native(&fix.version);
    if !is_safe_version_string(&version_native) {
        tracing::debug!(
            key,
            version = %fix.version,
            "OSV #462: fix-target version failed validation, skipping verification"
        );
        return FixTargetResolution::Skip;
    }

    if latest_native_by_key.get(key) == Some(&version_native) {
        return FixTargetResolution::Resolved(dv.upgrade_status.clone());
    }

    let Some(osv_name) = osv_name_by_key.get(key).cloned() else {
        tracing::debug!(
            key,
            "OSV #462: no osv_name on record for fix-target verification, skipping"
        );
        return FixTargetResolution::Skip;
    };
    FixTargetResolution::NeedsLiveCheck(ScanTarget::new(
        format!("{key}{FIX_TARGET_KEY_SUFFIX}"),
        osv_name,
        fix.version,
        version_native,
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
///     Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
///     VulnerabilityMap,
/// };
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
///         name.to_string()
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
///         String::new(),
///     )
///     .with_fixed_versions(vec!["1.2.0".to_string()]),
/// );
/// let latest_status = UpgradeStatus::CandidateClean {
///     version: "1.2.0".to_string(),
/// };
/// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
///     .with_upgrade_status(latest_status.clone());
///
/// let mut vulnerabilities = VulnerabilityMap::new();
/// vulnerabilities.insert("pkg".to_string(), ScanOutcome::Vulnerable(dv));
///
/// let mut latest_native_by_key = HashMap::new();
/// latest_native_by_key.insert("pkg".to_string(), "1.2.0".to_string());
///
/// // F (the fix, 1.2.0) equals the already-checked "latest" candidate — resolved without a
/// // live network check.
/// let (resolved, live_check_candidates) = collect_fix_target_resolutions(
///     &vulnerabilities,
///     &["pkg".to_string()],
///     &HashMap::new(),
///     &latest_native_by_key,
///     &SimpleFormatter,
/// );
///
/// assert_eq!(resolved, vec![("pkg".to_string(), latest_status)]);
/// assert!(live_check_candidates.is_empty());
/// ```
pub fn collect_fix_target_resolutions(
    vulnerabilities: &deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[String],
    osv_name_by_key: &HashMap<String, String>,
    latest_native_by_key: &HashMap<String, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    Vec<(String, deps_core::osv::UpgradeStatus)>,
    Vec<deps_core::osv::ScanTarget>,
) {
    use deps_core::osv::ScanOutcome;

    let mut resolved = Vec::new();
    let mut live_check_candidates = Vec::new();

    for key in vulnerable_keys {
        let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get(key.as_str()) else {
            continue;
        };
        match resolve_fix_target(dv, key, latest_native_by_key, osv_name_by_key, formatter) {
            FixTargetResolution::Skip => {}
            FixTargetResolution::Resolved(status) => resolved.push((key.clone(), status)),
            FixTargetResolution::NeedsLiveCheck(target) => live_check_candidates.push(target),
        }
    }

    (resolved, live_check_candidates)
}
/// Applies a live [`deps_core::osv::OsvClient::check_candidates`] result keyed with
/// `FIX_TARGET_KEY_SUFFIX` back onto the matching dependency's `fix_target_status`.
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
/// use deps_engine::classify::osv::apply_live_fix_target_statuses;
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// let advisory = Arc::new(Advisory::new(
///     "RUSTSEC-2024-0001".to_string(),
///     "2024-01-01T00:00:00Z".to_string(),
///     VulnSeverity::High,
///     String::new(),
/// ));
/// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1));
///
/// let mut vulnerabilities = VulnerabilityMap::new();
/// vulnerabilities.insert("pkg".to_string(), ScanOutcome::Vulnerable(dv));
///
/// let mut statuses = HashMap::new();
/// // Keyed with the fix-target suffix a live `check_candidates` call was batched under.
/// statuses.insert(
///     "pkg\u{0}fix".to_string(),
///     UpgradeStatus::CandidateClean {
///         version: "1.2.0".to_string(),
///     },
/// );
///
/// apply_live_fix_target_statuses(&mut vulnerabilities, statuses);
///
/// let ScanOutcome::Vulnerable(dv) = vulnerabilities.get("pkg").unwrap() else {
///     unreachable!()
/// };
/// assert_eq!(
///     dv.fix_target_status,
///     UpgradeStatus::CandidateClean {
///         version: "1.2.0".to_string()
///     }
/// );
/// ```
pub fn apply_live_fix_target_statuses(
    vulnerabilities: &mut deps_core::osv::VulnerabilityMap,
    statuses: HashMap<String, deps_core::osv::UpgradeStatus>,
) {
    use deps_core::osv::ScanOutcome;

    for (synthetic_key, status) in statuses {
        let Some(key) = synthetic_key.strip_suffix(FIX_TARGET_KEY_SUFFIX) else {
            continue;
        };
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(key) {
            dv.fix_target_status = status;
        }
    }
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
        use std::any::Any;
        use tower_lsp_server::ls_types::{Position, Range, Uri};

        struct MockFormatter;
        impl PackageNaming for MockFormatter {}

        impl PackageRendering for MockFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockFormatter {}

        impl DiagnosticMessages for MockFormatter {}

        impl DiagnosticPolicy for MockFormatter {}

        impl SourcePolicy for MockFormatter {}

        impl OsvNaming for MockFormatter {}

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
                // Distinct per instance (not a fixed constant): `vulnerability_keys`
                // (#394 S2) keys a `HashMap<Range, String>` by `name_range()`,
                // requiring it to uniquely identify each occurrence the way a
                // real parser's source-derived range always does. A hardcoded
                // range here would make every `MockDep` in a test collide on
                // one map entry.
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
            fn uri(&self) -> &Uri {
                static URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("time"),
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert!(skipped.is_empty());
        }

        /// Formatter stub mirroring `GoFormatter`'s override: every
        /// dependency's manifest requirement is itself the resolved version
        /// (#235's `manifest_requirement_is_resolved_version` unification).
        struct MockGoFormatter;
        impl PackageNaming for MockGoFormatter {}

        impl PackageRendering for MockGoFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pkg.go.dev/{name}")
            }
        }

        impl RequirementResolution for MockGoFormatter {
            fn manifest_requirement_is_resolved_version(&self, _dep: &dyn Dependency) -> bool {
                true
            }
        }

        impl DiagnosticMessages for MockGoFormatter {}

        impl DiagnosticPolicy for MockGoFormatter {}

        impl SourcePolicy for MockGoFormatter {}

        impl OsvNaming for MockGoFormatter {}

        struct MockVPrefixFormatter;
        impl PackageNaming for MockVPrefixFormatter {}

        impl PackageRendering for MockVPrefixFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockVPrefixFormatter {}

        impl DiagnosticMessages for MockVPrefixFormatter {}

        impl DiagnosticPolicy for MockVPrefixFormatter {}

        impl SourcePolicy for MockVPrefixFormatter {}

        impl OsvNaming for MockVPrefixFormatter {
            fn osv_version(&self, version: &str) -> String {
                version.strip_prefix('v').unwrap_or(version).to_string()
            }
        }

        #[test]
        fn build_scan_targets_normalizes_version_via_formatter_osv_version_hook() {
            // Go module versions carry a mandatory "v" prefix that OSV's
            // SEMVER range matching forbids (#228) — build_scan_targets must
            // route the resolved version through the formatter hook rather
            // than sending the native spelling on the wire.
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert_eq!(targets[0].display_version, "1.0.195");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_go_ignores_stale_lockfile_version_uses_go_mod_requirement() {
            // go.sum is a checksum ledger that `go get`/`go build` only ever
            // append to — a stale, no-longer-selected higher version can
            // remain recorded there after a downgrade (only `go mod tidy`
            // prunes it), and since go.sum is written sorted ascending by
            // semver, that stale entry always sorts last and wins
            // last-occurrence-wins parsing. Unlike Cargo/npm, go.mod's
            // `require` line is already an exact pinned version, so for Go
            // the manifest itself — not the lockfile-derived
            // `resolved_versions` — must be authoritative for OSV scanning.
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
                &MockGoFormatter,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            // `.version` (the wire-format value) goes through `formatter.osv_version`,
            // whose shared default (`deps-core`) strips a leading `v`/`V` — `MockGoFormatter`
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
                skipped.get("jsr:@std/fs"),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName))
            );
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
                &MockFormatter,
                EcosystemId::Maven,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "2.14.1");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step2_strips_pin_marker_for_operator_prefixed_requirements() {
            // impl-critic M2: the `concrete_pin_version` fix (originally
            // scoped to the PyPI `==` case) also strips Cargo's `=` and
            // NuGet's `[..]` exact-pin markers, since both callers share the
            // same helper — a strict improvement over the old verbatim
            // `"=1.2.3"`/`"[1.0.0]"` OSV scan targets, which would never
            // have matched a real advisory's affected-version range anyway.
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
                &MockFormatter,
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
                &MockFormatter,
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("serde"),
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("serde"),
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
                    &MockFormatter,
                    EcosystemId::Cargo,
                );
                assert!(targets.is_empty(), "{source:?} must be skipped (step 0)");
                assert_matches!(
                    skipped.get("pkg"),
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
                &MockFormatter,
                EcosystemId::Maven,
            );

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].key, "concrete");
            assert_eq!(skipped.len(), 2);
            assert_matches!(
                skipped.get("range-only"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
            assert_matches!(
                skipped.get("git-dep"),
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("serde")),
                Some(&vec!["1.0.195".to_string()])
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
                &MockFormatter,
                EcosystemId::Maven,
            );
            assert_eq!(
                in_use.get(&PackageName::new("log4j-core")),
                Some(&vec!["2.14.1".to_string()])
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
                &MockFormatter,
                EcosystemId::Pypi,
            );
            assert_eq!(
                in_use.get(&PackageName::new("typing_extensions")),
                Some(&vec!["4.9.0".to_string()]),
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
                &MockFormatter,
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_tracks_all_occurrences_of_duplicate_name() {
            // Regression guard for #394: two occurrences of the same
            // dependency name (e.g. under different
            // `[target.*.dependencies]` blocks, or `[dependencies]` +
            // `[dev-dependencies]`) with different concrete pins and no lock
            // file must both surface an in-use version for the yanked probe
            // — a name-keyed `HashMap<PackageName, String>` would silently
            // drop all but the last occurrence's pin.
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
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("time")),
                Some(&vec!["0.1.43".to_string(), "0.1.44".to_string()]),
                "both occurrences' in-use versions must be tracked, not just the last one"
            );
        }
    }
    /// #462: `resolve_fix_target`'s pure per-dependency decision logic (reuse / provably
    /// clean / needs a live check / skip), and `apply_live_fix_target_statuses`'s handling of
    /// a live-check result map that may be missing keys (timeout/outage).
    mod fix_target_verification_tests {
        use super::*;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy,
        };
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };
        use std::sync::Arc;

        struct IdentityFormatter;
        impl PackageNaming for IdentityFormatter {}

        impl PackageRendering for IdentityFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for IdentityFormatter {}

        impl DiagnosticMessages for IdentityFormatter {}

        impl DiagnosticPolicy for IdentityFormatter {}

        impl SourcePolicy for IdentityFormatter {}

        impl OsvNaming for IdentityFormatter {}

        fn advisory(id: &str, fixed_versions: &[&str]) -> Arc<Advisory> {
            Arc::new(
                Advisory::new(
                    id.to_string(),
                    "2023-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                    String::new(),
                )
                .with_fixed_versions(fixed_versions.iter().map(ToString::to_string).collect()),
            )
        }

        fn dv(
            advisories: Vec<Arc<Advisory>>,
            upgrade_status: UpgradeStatus,
        ) -> DependencyVulnerabilities {
            let total = advisories.len();
            DependencyVulnerabilities::new(Capped::new(advisories, total))
                .with_upgrade_status(upgrade_status)
        }

        #[test]
        fn resolve_fix_target_skips_when_no_fix_is_recommended() {
            // No advisory has a known fix, so `recommended_fix()` returns `None`.
            let dv = dv(vec![advisory("A1", &[])], UpgradeStatus::NotChecked);
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_reuses_latest_when_f_equals_latest() {
            // Case (c): F (1.2.0, the only advisory's fix) coincides with the already-checked
            // "latest" candidate — reuse its result, no live check queued.
            let latest_status = UpgradeStatus::CandidateClean {
                version: "1.2.0".to_string(),
            };
            let dv = dv(vec![advisory("A1", &["1.2.0"])], latest_status.clone());
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("pkg".to_string(), "1.2.0".to_string());

            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &latest_native_by_key,
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Resolved(latest_status));
        }

        #[test]
        fn resolve_fix_target_always_needs_live_check_when_f_differs_from_latest() {
            // #462 critic C1: there is no data-derived shortcut. Even though every known
            // advisory's fix (1.2.0) is already at or below F, that is a tautology — F is
            // *computed from* these exact advisories, so this check would always pass at its
            // only call site and prove nothing about an advisory phase A never fetched at
            // all. F (1.2.0) differs from latest (3.0.0), so this must always queue a live
            // check, batched under the fix-target key suffix.
            let dv = dv(
                vec![advisory("A1", &["1.2.0"])],
                UpgradeStatus::CandidateClean {
                    version: "3.0.0".to_string(),
                },
            );
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("pkg".to_string(), "3.0.0".to_string());
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert("pkg".to_string(), "pkg".to_string());

            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &latest_native_by_key,
                &osv_name_by_key,
                &IdentityFormatter,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    format!("pkg{FIX_TARGET_KEY_SUFFIX}"),
                    "pkg".to_string(),
                    "1.2.0".to_string(),
                    "1.2.0".to_string(),
                ))
            );
        }

        #[test]
        fn resolve_fix_target_skips_when_osv_name_is_unavailable() {
            // A live check is needed (F != latest) but no `osv_name` is on record for this
            // key — nothing to query, so this degrades to `Skip` rather than panicking or
            // building a `ScanTarget` with an empty name.
            let dv = dv(vec![advisory("A1", &["1.0.0"])], UpgradeStatus::NotChecked);
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_skips_when_f_is_not_a_safe_version_string() {
            // A malformed `fixed_versions` entry (as if it somehow reached this dependency's
            // `advisories` despite OSV's own wire-boundary validation) must never be queued
            // for a live check or treated as any kind of resolvable target — `is_safe_version_string`
            // rejects it before anything else runs.
            let dv = dv(
                vec![advisory("A1", &["1.2.0\", \"evil\": \"true"])],
                UpgradeStatus::NotChecked,
            );
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
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
                "reused".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A1", &["1.0.0"])],
                    UpgradeStatus::CandidateClean {
                        version: "1.0.0".to_string(),
                    },
                )),
            );
            vulnerabilities.insert(
                "live-a".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A2", &["1.2.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );
            vulnerabilities.insert(
                "live-b".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A3", &["2.2.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );

            let vulnerable_keys = vec![
                "reused".to_string(),
                "live-a".to_string(),
                "live-b".to_string(),
            ];
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("reused".to_string(), "1.0.0".to_string());
            latest_native_by_key.insert("live-a".to_string(), "9.0.0".to_string());
            latest_native_by_key.insert("live-b".to_string(), "9.0.0".to_string());
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert("reused".to_string(), "reused".to_string());
            osv_name_by_key.insert("live-a".to_string(), "live-a".to_string());
            osv_name_by_key.insert("live-b".to_string(), "live-b".to_string());

            let (resolved, live_check_candidates) = collect_fix_target_resolutions(
                &vulnerabilities,
                &vulnerable_keys,
                &osv_name_by_key,
                &latest_native_by_key,
                &IdentityFormatter,
            );

            assert_eq!(resolved.len(), 1, "{resolved:?}");
            assert_eq!(resolved[0].0, "reused");

            assert_eq!(live_check_candidates.len(), 2, "{live_check_candidates:?}");
            let keys: std::collections::HashSet<&str> = live_check_candidates
                .iter()
                .map(|t| t.key.as_str())
                .collect();
            assert!(keys.contains(format!("live-a{FIX_TARGET_KEY_SUFFIX}").as_str()));
            assert!(keys.contains(format!("live-b{FIX_TARGET_KEY_SUFFIX}").as_str()));
        }

        #[test]
        fn apply_live_fix_target_statuses_sets_only_matching_keys_leaving_others_untouched() {
            // Case (e): a live-check batch that timed out for one dependency simply omits
            // its key from `statuses` — that dependency's `fix_target_status` must stay
            // `NotChecked` afterward, with no panic, while a dependency whose result did
            // arrive gets it applied.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "checked".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A1", &["1.0.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );
            vulnerabilities.insert(
                "timed-out".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A2", &["1.0.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );

            let mut statuses = HashMap::new();
            statuses.insert(
                format!("checked{FIX_TARGET_KEY_SUFFIX}"),
                UpgradeStatus::CandidateClean {
                    version: "1.0.0".to_string(),
                },
            );
            // "timed-out" deliberately has no entry in `statuses`.

            apply_live_fix_target_statuses(&mut vulnerabilities, statuses);

            let ScanOutcome::Vulnerable(checked) = vulnerabilities.get("checked").unwrap() else {
                panic!("expected Vulnerable");
            };
            assert_eq!(
                checked.fix_target_status,
                UpgradeStatus::CandidateClean {
                    version: "1.0.0".to_string()
                }
            );

            let ScanOutcome::Vulnerable(timed_out) = vulnerabilities.get("timed-out").unwrap()
            else {
                panic!("expected Vulnerable");
            };
            assert_eq!(timed_out.fix_target_status, UpgradeStatus::NotChecked);
        }
    }
}
