//! Wire types for the OSV.dev batch and single-query APIs, and the
//! `deps-lsp`-facing types derived from them.
//!
//! The wire types deliberately mirror OSV's schema sparsely: every optional
//! field uses `#[serde(default)]` because OSV records are sparse and the
//! schema evolves, and a missing field must never fail the whole response
//! (see `architecture.md` §6).

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::lsp_helpers::is_safe_version_string;

/// One dependency to query against OSV.
///
/// Four distinct strings, deliberately: `key` is this project's internal
/// lookup key (`EcosystemFormatter::normalize_package_name`), `osv_name` is
/// OSV's canonical spelling (`EcosystemFormatter::osv_package_name`). The
/// transform from `key` to `osv_name` is not round-trippable (Swift
/// `owner/repo` -> `github.com/owner/repo`; NuGet raw vs Composer lowercased),
/// so the client cannot reconstruct the map key from what it sends on the
/// wire — both must be carried alongside each other.
///
/// `version` and `display_version` are the same split, one level down: `version`
/// is what gets sent on the wire (`EcosystemFormatter::osv_version`), while
/// `display_version` is the ecosystem-native spelling a caller should surface
/// back to the user (e.g. in [`crate::osv::UpgradeStatus`]). They coincide for
/// every ecosystem except Go, where `osv_version` strips the mandatory `v`
/// prefix — a caller that echoed `version` in an upgrade suggestion would show
/// `1.2.3` instead of the `go.mod`-native `v1.2.3`.
///
/// # Examples
///
/// ```
/// use deps_core::osv::ScanTarget;
///
/// let target = ScanTarget {
///     key: "time".to_string(),
///     osv_name: "time".to_string(),
///     version: "0.1.43".to_string(),
///     display_version: "0.1.43".to_string(),
/// };
/// assert_eq!(target.key, target.osv_name);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    /// This project's internal lookup key — used to key [`VulnerabilityMap`].
    pub key: String,
    /// OSV's canonical package name for this ecosystem — sent on the wire.
    pub osv_name: String,
    /// Concrete version to query, resolved per the version-selection policy
    /// and rewritten to OSV's wire spelling via
    /// `EcosystemFormatter::osv_version`. Never surface this to the user —
    /// use [`Self::display_version`] instead.
    pub version: String,
    /// The same version in the ecosystem's native spelling (pre-`osv_version`
    /// rewrite), for callers that need to display it back to the user rather
    /// than send it to OSV.
    pub display_version: String,
}

/// Severity bucket derived from an OSV advisory record.
///
/// See `architecture.md` §6 for the precedence rules used to derive this
/// from a raw record, and [`crate::osv::diagnostic_severity_for`] for the mapping to
/// [`tower_lsp_server::ls_types::DiagnosticSeverity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnSeverity {
    /// `database_specific.severity` or `ecosystem_specific.severity` reported `CRITICAL`.
    Critical,
    /// Reported `HIGH`.
    High,
    /// Reported `MODERATE` or `MEDIUM`.
    Medium,
    /// Reported `LOW`.
    Low,
    /// No severity field was present or recognized on the record.
    Unknown,
}

/// A single vulnerability advisory, converted from OSV's wire format at the
/// crate boundary.
///
/// # Examples
///
/// ```
/// use deps_core::osv::{Advisory, VulnSeverity};
///
/// let advisory = Advisory {
///     id: "RUSTSEC-2020-0071".to_string(),
///     modified: "2023-01-01T00:00:00Z".to_string(),
///     summary: Some("Potential segfault in the time crate".to_string()),
///     aliases: vec!["CVE-2020-26235".to_string()],
///     severity: VulnSeverity::High,
///     cvss_vector: None,
///     fixed_versions: vec!["0.2.23".to_string()],
///     url: "https://osv.dev/vulnerability/RUSTSEC-2020-0071".to_string(),
/// };
/// assert_eq!(advisory.fixed_versions.last(), Some(&"0.2.23".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// Advisory identifier (e.g. `"RUSTSEC-2020-0071"`, `"GHSA-..."`).
    pub id: String,
    /// RFC3339 last-modified timestamp — the [`crate::osv::OsvClient`] record-cache validator.
    pub modified: String,
    /// Human-readable one-line summary, if OSV provided one.
    pub summary: Option<String>,
    /// Alternate identifiers (CVE, GHSA, ...).
    pub aliases: Vec<String>,
    /// Derived severity bucket.
    pub severity: VulnSeverity,
    /// Raw CVSS vector string, shown verbatim in hover but never parsed.
    pub cvss_vector: Option<String>,
    /// All `fixed` events found in the record's ranges, ascending. May be
    /// empty if OSV recorded no fix. The highest entry is the one to surface
    /// as "the fix" — see `architecture.md` §6 for why the *first* one is not.
    pub fixed_versions: Vec<String>,
    /// `https://osv.dev/vulnerability/{id}`.
    pub url: String,
}

/// A list that may have been truncated when it was produced, paired with the
/// true count of items that existed at the source.
///
/// Exists so a truncated list can never be silently read as complete: items are
/// only reachable through [`Capped::items`] and the real count only through
/// [`Capped::total`], so `items().len()` is never mistaken for "everything there
/// is". Both OSV lists capped at [`crate::osv::ADVISORY_DISPLAY_CAP`] use it —
/// [`DependencyVulnerabilities::advisories`] and [`UpgradeStatus::CandidateVulnerable`].
///
/// # Examples
///
/// ```
/// use deps_core::osv::Capped;
///
/// let truncated = Capped::new(vec!["A1".to_string(), "A2".to_string()], 5);
/// assert_eq!(truncated.items().len(), 2);
/// assert_eq!(truncated.total(), 5);
/// assert!(!truncated.is_complete());
/// assert_eq!(truncated.remaining(), 3);
///
/// let complete = Capped::new(vec!["A1".to_string()], 1);
/// assert!(complete.is_complete());
/// assert_eq!(complete.remaining(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped<T> {
    items: Vec<T>,
    total: usize,
}

impl<T> Capped<T> {
    /// Pairs an already-truncated `items` list with the `total` the source
    /// reported, which may exceed `items.len()`.
    #[must_use]
    pub fn new(items: Vec<T>, total: usize) -> Self {
        Self { items, total }
    }

    /// The items actually retained — **not necessarily all [`Self::total`] of them**.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// The count the source reported, independent of how many items were retained.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Whether [`Self::items`] holds everything the source reported.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.items.len() >= self.total
    }

    /// How many items were dropped — the render layer's "+N more" count.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.total.saturating_sub(self.items.len())
    }
}

#[cfg(test)]
mod capped_tests {
    use super::Capped;

    #[test]
    fn new_exposes_items_and_total_as_given() {
        let capped = Capped::new(vec!["A1", "A2"], 5);
        assert_eq!(capped.items(), ["A1", "A2"]);
        assert_eq!(capped.total(), 5);
    }

    #[test]
    fn is_complete_true_when_items_cover_total() {
        let capped = Capped::new(vec!["A1"], 1);
        assert!(capped.is_complete());
    }

    #[test]
    fn is_complete_false_when_truncated() {
        let capped = Capped::new(vec!["A1"], 2);
        assert!(!capped.is_complete());
    }

    #[test]
    fn remaining_reports_truncated_count() {
        let capped = Capped::new(vec!["A1", "A2"], 5);
        assert_eq!(capped.remaining(), 3);
    }

    #[test]
    fn remaining_is_zero_when_not_truncated() {
        let capped = Capped::new(vec!["A1"], 1);
        assert_eq!(capped.remaining(), 0);
    }

    #[test]
    fn empty_items_with_zero_total_is_complete() {
        let capped: Capped<&str> = Capped::new(vec![], 0);
        assert!(capped.is_complete());
        assert_eq!(capped.remaining(), 0);
    }
}

/// Result of checking whether a recommended upgrade target is itself affected.
///
/// Populated by [`crate::osv::OsvClient::check_candidates`] (phase B), which only runs for
/// dependencies phase A already flagged as [`ScanOutcome::Vulnerable`]. Used for both the
/// registry's "latest" candidate ([`DependencyVulnerabilities::upgrade_status`]) and the
/// independently-verified fix target F ([`DependencyVulnerabilities::fix_target_status`]) —
/// see the latter's doc for why F needs its own verification result distinct from latest's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeStatus {
    /// Phase B has not run for this dependency (phase A found nothing, or
    /// phase B has not completed yet).
    NotChecked,
    /// The candidate upgrade version is not itself affected by any known advisory.
    CandidateClean {
        /// The version that was checked.
        version: String,
    },
    /// The candidate upgrade version is itself affected.
    CandidateVulnerable {
        /// The version that was checked.
        version: String,
        /// Advisory IDs that still apply to the candidate version, capped at
        /// [`crate::osv::ADVISORY_DISPLAY_CAP`] the same way
        /// [`DependencyVulnerabilities::advisories`] is (#462 critic M1) —
        /// **not necessarily exhaustive**. Check [`Capped::is_complete`] before
        /// treating it as the complete set of advisories still affecting this
        /// candidate; an incomplete list means some are missing, not that none
        /// exist.
        advisory_ids: Capped<String>,
    },
}

/// Vulnerability data for one dependency that OSV reported as non-clean.
#[derive(Debug, Clone)]
pub struct DependencyVulnerabilities {
    /// Advisories fetched in full, capped at [`crate::osv::ADVISORY_DISPLAY_CAP`] (invariant 3
    /// in `architecture.md` §8: the fetch itself is capped, not only the render) — the total
    /// advisory count OSV reported is carried alongside via [`Capped::total`], independent of
    /// how many were actually fetched, and is the source of the render layer's "+N more
    /// advisories" count (`architecture.md` §7/§8 invariant 3).
    pub advisories: Capped<Arc<Advisory>>,
    /// Result of phase B's "latest" check, if it has run for this dependency.
    pub upgrade_status: UpgradeStatus,
    /// Independent verification of [`Self::recommended_fix`]'s target version F, if F
    /// differs from the "latest" candidate `upgrade_status` already covers. Left at
    /// [`UpgradeStatus::NotChecked`] until [`Self::recommended_fix`] has been computed and F's
    /// status resolved — either reused from `upgrade_status` when F equals latest, or checked
    /// live via [`crate::osv::OsvClient::check_candidates`] otherwise (always live-checked when
    /// F differs from latest: a data-derived shortcut was tried and rejected — see git history
    /// on this field and #462's critique — because it degenerates into checking F against
    /// exactly the advisories it was computed from, proving nothing about an advisory phase
    /// A never fetched at all, which is the actual gap #462 closes). See
    /// `run_osv_phase_b_and_commit` in `deps-lsp` for the resolution order.
    ///
    /// A caller must not treat a bare [`UpgradeStatus::CandidateClean`] check as the only valid
    /// "verified" state: [`UpgradeStatus::CandidateVulnerable`] can also be a legitimate,
    /// presentable fix when every reported id is an advisory [`Self::recommended_fix`] already
    /// declined to claim (excluded via `still_applying`, or never had a known fix) — see
    /// `deps-core`'s `lsp_helpers::code_actions::fix_target_is_verified` (the actual gate
    /// `generate_code_actions` uses) for the full contract, rather than re-deriving it ad hoc.
    pub fix_target_status: UpgradeStatus,
}

/// A single upgrade target recommended by [`DependencyVulnerabilities::recommended_fix`].
///
/// `version` is in OSV's version namespace (see
/// [`crate::lsp_helpers::EcosystemFormatter::osv_version_to_native`] for the
/// conversion callers must apply before using it in a manifest edit or a
/// registry lookup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixRecommendation {
    /// The highest [`Advisory::fixed_versions`] entry across the advisories
    /// named in `advisory_ids` — the lowest version that resolves everything
    /// this recommendation actually claims to fix.
    pub version: String,
    /// Advisory ids this recommendation actually resolves, sorted by
    /// severity descending (worst first) and tied by id — the order a
    /// title should list them in.
    pub advisory_ids: Vec<String>,
}

/// Numeric ranking used only to sort [`FixRecommendation::advisory_ids`],
/// worst severity first.
const fn severity_rank(severity: VulnSeverity) -> u8 {
    match severity {
        VulnSeverity::Critical => 4,
        VulnSeverity::High => 3,
        VulnSeverity::Medium => 2,
        VulnSeverity::Low => 1,
        VulnSeverity::Unknown => 0,
    }
}

impl DependencyVulnerabilities {
    /// Recommends a single upgrade target that resolves as many of this
    /// dependency's known advisories as possible.
    ///
    /// `advisory_ids` is computed first: every advisory with a known fix,
    /// minus — when phase B ([`UpgradeStatus::CandidateVulnerable`]) reports
    /// that some ids still apply to the checked candidate — those ids,
    /// since claiming a fix for them would be false. `version` is then the
    /// highest [`Advisory::fixed_versions`] entry across only the
    /// *remaining* claimed advisories, not every advisory: computing it over
    /// the full set first would let an advisory this method just excluded
    /// (because its own fix is known not to hold) drag the recommendation
    /// past a lower version that already clears everything actually being
    /// claimed. Returns `None` when no advisory has a claimable fix.
    ///
    /// The subtraction's premise is that the checked candidate is at least
    /// as new as `version`; when phase B checked an older candidate the
    /// subtraction is merely over-conservative (it only ever removes
    /// claims), so this is documented rather than guarded against.
    ///
    /// # Limitations
    ///
    /// `advisories` is capped at fetch time
    /// ([`crate::osv::ADVISORY_DISPLAY_CAP`]), so `version` is the max over a
    /// possibly incomplete subset — the "+N more advisories" hint already
    /// signals that incompleteness, so this is an accepted under-report, not
    /// a bug. `Advisory` also retains only `fixed_versions`, never
    /// `introduced` events, so a version reintroduced above its own last
    /// known fix (and not yet re-fixed) can still be claimed as a fix
    /// whenever phase B has not run for this dependency
    /// ([`UpgradeStatus::NotChecked`]) — the post-edit rescan is what
    /// surfaces that case.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
    /// use std::sync::Arc;
    ///
    /// fn advisory(id: &str, fixed: &str) -> Arc<Advisory> {
    ///     Arc::new(Advisory {
    ///         id: id.to_string(),
    ///         modified: "2023-01-01T00:00:00Z".to_string(),
    ///         summary: None,
    ///         aliases: vec![],
    ///         severity: VulnSeverity::High,
    ///         cvss_vector: None,
    ///         fixed_versions: vec![fixed.to_string()],
    ///         url: String::new(),
    ///     })
    /// }
    ///
    /// let dv = DependencyVulnerabilities {
    ///     advisories: Capped::new(vec![advisory("RUSTSEC-1", "1.2.0")], 1),
    ///     upgrade_status: UpgradeStatus::NotChecked,
    ///     fix_target_status: UpgradeStatus::NotChecked,
    /// };
    ///
    /// let fix = dv.recommended_fix().unwrap();
    /// assert_eq!(fix.version, "1.2.0");
    /// assert_eq!(fix.advisory_ids, vec!["RUSTSEC-1".to_string()]);
    /// ```
    #[must_use]
    pub fn recommended_fix(&self) -> Option<FixRecommendation> {
        let still_applying: &[String] = match &self.upgrade_status {
            UpgradeStatus::CandidateVulnerable { advisory_ids, .. } => advisory_ids.items(),
            UpgradeStatus::NotChecked | UpgradeStatus::CandidateClean { .. } => &[],
        };

        let mut claimed: Vec<&Advisory> = self
            .advisories
            .items()
            .iter()
            .map(Arc::as_ref)
            .filter(|a| !a.fixed_versions.is_empty())
            .filter(|a| !still_applying.contains(&a.id))
            .collect();

        if claimed.is_empty() {
            return None;
        }

        // The minimum version that clears every *claimed* advisory — not the
        // max over every advisory (including ones just excluded above),
        // which could push the recommendation past a version that resolves
        // nothing beyond what a lower, still-claimed fix already covers.
        let version = claimed
            .iter()
            .filter_map(|a| a.fixed_versions.last())
            .max_by(|a, b| super::compare_version_strings(a, b))?
            .clone();

        claimed.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.id.cmp(&b.id))
        });

        Some(FixRecommendation {
            version,
            advisory_ids: claimed.into_iter().map(|a| a.id.clone()).collect(),
        })
    }
}

/// Why a dependency produced no advisories.
///
/// Absence from [`VulnerabilityMap`] is never a synonym for "clean" — every
/// input to [`crate::osv::OsvClient::scan`] gets an entry, and every filtered-out or
/// failed path must declare itself as one of these reasons rather than
/// silently vanishing from the map (`architecture.md` §6, §8 invariant 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `dep.source()` was not [`crate::parser::DependencySource::Registry`] (§3 step 0).
    NonRegistrySource,
    /// No lockfile-resolved or concrete version was available (§3 steps 1-3).
    NoConcreteVersion,
    /// `EcosystemFormatter::osv_package_name` returned `None`.
    UnmappableName,
    /// `EcosystemId::osv_ecosystem` returned `None`.
    UnmappableEcosystem,
    /// The batch or single-package query failed (network error, non-2xx, malformed JSON,
    /// or a chunk whose result count did not match its query count).
    QueryFailed,
    /// The batch result was truncated (`next_page_token` present) and the
    /// bounded individual-requery budget was exhausted before this entry
    /// could be recovered (§8 invariant 2).
    Truncated,
}

impl SkipReason {
    /// Short tag used in the `info`-level scan summary log line.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NonRegistrySource => "non-registry-source",
            Self::NoConcreteVersion => "no-concrete-version",
            Self::UnmappableName => "unmappable-name",
            Self::UnmappableEcosystem => "unmappable-ecosystem",
            Self::QueryFailed => "query-failed",
            Self::Truncated => "truncated",
        }
    }
}

/// Outcome of scanning one dependency.
///
/// The three variants are mutually exclusive and collectively exhaustive for
/// every dependency passed to [`crate::osv::OsvClient::scan`] — see `architecture.md` §6 for
/// why this must never collapse back to `Option<DependencyVulnerabilities>`.
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    /// Never queried, or the query could not be resolved — say nothing about it.
    Skipped(SkipReason),
    /// Queried; OSV reported no advisories.
    Clean,
    /// Queried; OSV reported one or more advisories.
    Vulnerable(DependencyVulnerabilities),
}

/// Per-scan result map.
///
/// Normally keyed by the normalized dependency name
/// (`EcosystemFormatter::normalize_package_name` — the same key
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] and
/// [`crate::lsp_helpers::generate_hover`] already use to look up
/// `cached`/`resolved` versions), but see [`vulnerability_keys`] for the
/// version-qualified form a duplicated dependency name's occurrences use.
pub type VulnerabilityMap = HashMap<String, ScanOutcome>;

/// Computes the [`VulnerabilityMap`] key each occurrence in `parse_result`
/// should be scanned/looked-up under.
///
/// Keyed by [`Dependency::name_range`](crate::Dependency::name_range) —
/// unique per occurrence within one document, so callers holding a specific
/// `dep` (not just its name) can look their own key up directly.
///
/// Normally an occurrence's key is just its normalized name (the common
/// case, and the only form most `VulnerabilityMap` test fixtures use). When
/// two or more occurrences of the *same* name resolve to different signatures
/// — e.g. the same crate under `[dependencies]` and `[dev-dependencies]`, or
/// multiple `[target.'cfg(...)'.dependencies]` blocks (#394), pinned to
/// different versions, or mixing a registry source with a git/path fork —
/// each such occurrence's key is instead qualified with a signature specific
/// to it, so their OSV results can never collide in the shared map.
/// Occurrences that share both a name and an identical signature
/// (registry-source, same in-use version) intentionally keep the plain,
/// shared key and get scanned once: the OSV result would be identical
/// either way, so collapsing them is a dedup, not a gap.
///
/// Every caller that builds or looks up a `VulnerabilityMap` entry for a
/// *specific* dependency occurrence — `deps-lsp`'s `build_scan_targets`,
/// and the vulnerability lookups in `generate_diagnostics_from_cache`,
/// `generate_hover`, and `generate_code_actions` — must go through this
/// function so key construction never drifts out of sync between producer
/// and consumer. A caller with no [`EcosystemId`](crate::EcosystemId) to
/// give (most test fixtures) skips this and falls back to the plain
/// normalized name, which still finds any entry a test inserted under that
/// name directly.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::EcosystemFormatter;
/// use deps_core::osv::vulnerability_keys;
/// use deps_core::{ConcreteVersion, Dependency, EcosystemId, PackageName, ParseResult, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use tower_lsp_server::ls_types::{Position, Range, Uri};
///
/// struct SimpleDep {
///     name: PackageName,
///     version_req: Option<VersionReq>,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         self.version_req.as_ref()
///     }
///     fn version_range(&self) -> Option<Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleParseResult {
///     deps: Vec<SimpleDep>,
///     uri: Uri,
/// }
///
/// impl ParseResult for SimpleParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> {
///         None
///     }
///     fn uri(&self) -> &Uri {
///         &self.uri
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleFormatter;
/// impl EcosystemFormatter for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
/// }
///
/// // `time` declared twice, pinned to two different versions.
/// let parse_result = SimpleParseResult {
///     deps: vec![
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.43")),
///             name_range: Range::new(Position::new(0, 0), Position::new(0, 4)),
///         },
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.44")),
///             name_range: Range::new(Position::new(3, 0), Position::new(3, 4)),
///         },
///     ],
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
/// };
/// let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
///
/// let keys = vulnerability_keys(&parse_result, &resolved, &SimpleFormatter, EcosystemId::Cargo);
/// let deps = parse_result.dependencies();
/// let key0 = keys.get(&deps[0].name_range()).unwrap();
/// let key1 = keys.get(&deps[1].name_range()).unwrap();
/// assert_ne!(key0, key1, "differently-pinned occurrences of one name get distinct keys");
/// ```
pub fn vulnerability_keys(
    parse_result: &dyn crate::ParseResult,
    resolved: &HashMap<crate::PackageName, crate::ConcreteVersion>,
    formatter: &dyn crate::lsp_helpers::EcosystemFormatter,
    ecosystem: crate::EcosystemId,
) -> HashMap<tower_lsp_server::ls_types::Range, String> {
    use crate::lsp_helpers::in_use_version;

    let deps = parse_result.dependencies();

    // One signature per occurrence: public-registry-content deps (crates.io itself, or a
    // verified crates.io mirror per `source_is_public_registry_content` — F1b) carry their
    // own in-use version (or "u" when none is determinable — a range requirement with no
    // lock file); every other source (git/path forks, a genuinely different private
    // registry) always carries "n", since their `ScanOutcome` is always
    // `Skipped(NonRegistrySource)` regardless of any declared version.
    let signatures: Vec<(String, String)> = deps
        .iter()
        .map(|dep| {
            let name = formatter.normalize_package_name(dep.name());
            let signature = if formatter.source_is_public_registry_content(&dep.source()) {
                match in_use_version(*dep, &name, resolved, formatter, ecosystem) {
                    Some(v) => format!("v:{v}"),
                    None => "u".to_string(),
                }
            } else {
                "n".to_string()
            };
            (name, signature)
        })
        .collect();

    let mut distinct_signatures_by_name: HashMap<&str, std::collections::HashSet<&str>> =
        HashMap::new();
    for (name, signature) in &signatures {
        distinct_signatures_by_name
            .entry(name.as_str())
            .or_default()
            .insert(signature.as_str());
    }

    deps.iter()
        .zip(&signatures)
        .map(|(dep, (name, signature))| {
            let ambiguous = distinct_signatures_by_name
                .get(name.as_str())
                .is_some_and(|s| s.len() > 1);
            let key = if ambiguous {
                format!("{name}\u{0}{signature}")
            } else {
                name.clone()
            };
            (dep.name_range(), key)
        })
        .collect()
}

// ---- OSV wire types (private) -------------------------------------------

#[derive(Debug, Serialize)]
pub(super) struct OsvBatchRequest {
    pub(super) queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
pub(super) struct OsvQuery {
    pub(super) package: OsvPackage,
    pub(super) version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OsvPackage {
    pub(super) name: String,
    pub(super) ecosystem: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvBatchResponse {
    #[serde(default)]
    pub(super) results: Vec<OsvBatchResult>,
}

/// One entry in a batch response. `vulns` may be entirely absent (not just
/// empty) when the aggregate batch result was paginated — see `architecture.md`
/// §8 invariant 2. `next_page_token`'s presence, not `vulns`'s absence, is
/// the truncation signal.
#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvBatchResult {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVulnStub>,
    #[serde(default)]
    pub(super) next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvVulnStub {
    pub(super) id: String,
    #[serde(default)]
    pub(super) modified: String,
}

/// Response shape of `POST /v1/query` — deliberately distinct from the batch
/// endpoint: full advisory records inline, not id stubs (`architecture.md` §8).
///
/// `next_page_token` is deserialized (even though this endpoint is only ever
/// used to *recover from* batch truncation) because `/v1/query` can itself
/// paginate — trusting `vulns.len()` as the authoritative count without
/// checking this field would reintroduce §8 invariant 2 one layer below the
/// fix that closed it for the batch endpoint.
#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvSingleQueryResponse {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVulnRecord>,
    #[serde(default)]
    pub(super) next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvVulnRecord {
    pub(super) id: String,
    #[serde(default)]
    pub(super) modified: String,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) aliases: Vec<String>,
    #[serde(default)]
    pub(super) severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    pub(super) database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvSeverityEntry {
    #[serde(rename = "type", default)]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) score: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvAffected {
    /// Which package this entry describes. A single OSV record can cover
    /// several packages sharing one advisory id (e.g. a GHSA affecting both
    /// `log4j-core` and `log4j-api`), so this must be checked before
    /// extracting `fixed`/severity data — see `into_advisory`.
    #[serde(default)]
    pub(super) package: Option<OsvPackage>,
    #[serde(default)]
    pub(super) ecosystem_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvRange {
    #[serde(default)]
    pub(super) events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvEvent {
    #[serde(default)]
    pub(super) fixed: Option<String>,
}

/// Returns `true` if `id` matches OSV's advisory id grammar
/// (`[A-Za-z0-9._-]+`, non-empty, capped at 128 bytes) — the same alphabet
/// every real id scheme in this space uses (`RUSTSEC-2020-0071`,
/// `GHSA-xxxx-yyyy-zzzz`, `CVE-2020-26235`); real ids are a few dozen
/// characters, so the cap exists only to bound how much of a record-supplied
/// string can ride along into `Diagnostic.code`, hover markdown, and a
/// `CodeAction` title. `id` is echoed verbatim into a markdown link
/// destination (`push_vulnerability_hover_section`) and a `Diagnostic.code`,
/// so this is the parse-boundary chokepoint that keeps a malformed id from
/// ever reaching either — rejecting it here means every downstream consumer
/// can treat `Advisory.id` as inherently safe, rather than needing to
/// sanitize it again at each render site.
fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl OsvVulnRecord {
    /// Converts a raw wire record into the `deps-lsp`-facing [`Advisory`],
    /// or `None` if the record's id fails [`is_valid_osv_id`] (dropped, same
    /// as a 404 on `/v1/vulns/{id}` — the dependency renders with whichever
    /// advisories did resolve, never a half-trusted one). Individual `fixed`
    /// events failing [`is_safe_version_string`] are dropped the same way,
    /// but only that entry — the record as a whole still renders with its
    /// remaining, valid `fixed_versions`.
    ///
    /// `osv_name`/`osv_eco` are the package actually queried: a record can
    /// legitimately cover several unrelated packages sharing one advisory id
    /// (critique S3), so `affected[]` is filtered to entries whose `package`
    /// matches (or omits) before `fixed_versions`/severity are extracted —
    /// otherwise a stranger package's fix version or severity could leak
    /// into this one's rendering.
    pub(super) fn into_advisory(self, osv_name: &str, osv_eco: &str) -> Option<Advisory> {
        if !is_valid_osv_id(&self.id) {
            tracing::warn!(id = %self.id, "OSV record has a malformed id, dropping");
            return None;
        }

        let relevant: Vec<&OsvAffected> = self
            .affected
            .iter()
            .filter(|a| {
                a.package
                    .as_ref()
                    .is_none_or(|p| p.name == osv_name && p.ecosystem == osv_eco)
            })
            .collect();
        // Every `affected[]` entry named a different package: OSV returned
        // this record in response to our exact query, so that should not
        // happen in practice. Fall back to using every entry rather than
        // rendering fixed_versions/severity as empty/Unknown outright.
        let relevant: Vec<&OsvAffected> = if relevant.is_empty() && !self.affected.is_empty() {
            tracing::warn!(
                id = %self.id, osv_name, osv_eco,
                "no affected[] entry matched the queried package; using all entries"
            );
            self.affected.iter().collect()
        } else {
            relevant
        };

        let severity = super::severity::classify(self.database_specific.as_ref(), &relevant);
        let cvss_vector = self
            .severity
            .iter()
            .find(|s| s.kind == "CVSS_V3")
            .or_else(|| self.severity.first())
            .map(|s| s.score.clone());

        let mut fixed_versions: Vec<String> = relevant
            .iter()
            .flat_map(|a| a.ranges.iter())
            .flat_map(|r| r.events.iter())
            .filter_map(|e| e.fixed.clone())
            .filter(|v| {
                let valid = is_safe_version_string(v);
                if !valid {
                    tracing::warn!(
                        id = %self.id, version = %v,
                        "OSV record has a malformed fixed version, dropping"
                    );
                }
                valid
            })
            .collect();
        fixed_versions.sort_by(|a, b| super::compare_version_strings(a, b));
        fixed_versions.dedup();

        let url = format!("https://osv.dev/vulnerability/{}", self.id);

        Some(Advisory {
            id: self.id,
            modified: self.modified,
            summary: self.summary,
            aliases: self.aliases,
            severity,
            cvss_vector,
            fixed_versions,
            url,
        })
    }
}

#[cfg(test)]
mod recommended_fix_tests {
    use super::*;

    fn advisory(id: &str, severity: VulnSeverity, fixed_versions: &[&str]) -> Arc<Advisory> {
        Arc::new(Advisory {
            id: id.to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity,
            cvss_vector: None,
            fixed_versions: fixed_versions.iter().map(ToString::to_string).collect(),
            url: String::new(),
        })
    }

    fn dv(
        advisories: Vec<Arc<Advisory>>,
        upgrade_status: UpgradeStatus,
    ) -> DependencyVulnerabilities {
        let total = advisories.len();
        DependencyVulnerabilities {
            advisories: Capped::new(advisories, total),
            upgrade_status,
            fix_target_status: UpgradeStatus::NotChecked,
        }
    }

    #[test]
    fn no_advisory_has_a_fix_returns_none() {
        let vulns = dv(
            vec![advisory("A1", VulnSeverity::High, &[])],
            UpgradeStatus::NotChecked,
        );
        assert!(vulns.recommended_fix().is_none());
    }

    #[test]
    fn multiple_advisories_combine_into_one_fix_at_the_highest_version() {
        // A1 fixed at 1.1.0, A2 fixed at 1.3.0: the recommendation targets
        // the highest of the two and claims both ids.
        let vulns = dv(
            vec![
                advisory("A1", VulnSeverity::High, &["1.1.0"]),
                advisory("A2", VulnSeverity::Critical, &["1.3.0"]),
            ],
            UpgradeStatus::NotChecked,
        );

        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.version, "1.3.0");
        // Sorted by severity descending: Critical (A2) before High (A1).
        assert_eq!(fix.advisory_ids, vec!["A2".to_string(), "A1".to_string()]);
    }

    #[test]
    fn candidate_vulnerable_subtracts_only_the_ids_it_names() {
        // Critic's counterexample: A1 fixed 1.1.0, A2 fixed 1.2.0. Phase B
        // reports the candidate is still affected by A1 only, so A1 must be
        // dropped from the claim while A2 survives.
        let vulns = dv(
            vec![
                advisory("A1", VulnSeverity::High, &["1.1.0"]),
                advisory("A2", VulnSeverity::Medium, &["1.2.0"]),
            ],
            UpgradeStatus::CandidateVulnerable {
                version: "1.2.0".to_string(),
                advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            },
        );

        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.version, "1.2.0");
        assert_eq!(fix.advisory_ids, vec!["A2".to_string()]);
    }

    #[test]
    fn candidate_vulnerable_subtracting_every_claimed_id_returns_none() {
        let vulns = dv(
            vec![advisory("A1", VulnSeverity::High, &["1.1.0"])],
            UpgradeStatus::CandidateVulnerable {
                version: "1.1.0".to_string(),
                advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            },
        );
        assert!(vulns.recommended_fix().is_none());
    }

    #[test]
    fn candidate_clean_subtracts_nothing() {
        let vulns = dv(
            vec![advisory("A1", VulnSeverity::High, &["1.1.0"])],
            UpgradeStatus::CandidateClean {
                version: "2.0.0".to_string(),
            },
        );
        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.advisory_ids, vec!["A1".to_string()]);
    }

    #[test]
    fn advisory_without_a_fix_is_excluded_from_the_claim() {
        let vulns = dv(
            vec![
                advisory("A1", VulnSeverity::High, &["1.1.0"]),
                advisory("A2", VulnSeverity::Critical, &[]),
            ],
            UpgradeStatus::NotChecked,
        );

        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.version, "1.1.0");
        assert_eq!(fix.advisory_ids, vec!["A1".to_string()]);
    }

    #[test]
    fn subtracted_advisory_with_a_higher_fix_does_not_inflate_the_recommended_version() {
        // Critic S1 counterexample: A1 is fixed at a high version (3.0.0)
        // but still applies at the checked candidate, so it is excluded.
        // A2 is fixed at a much lower version (1.2.0) and is claimed. The
        // recommended version must be 1.2.0 — computed over what is
        // actually claimed — not 3.0.0, which A1's exclusion proves does
        // not even resolve A1.
        let vulns = dv(
            vec![
                advisory("A1", VulnSeverity::High, &["3.0.0"]),
                advisory("A2", VulnSeverity::Medium, &["1.2.0"]),
            ],
            UpgradeStatus::CandidateVulnerable {
                version: "3.0.0".to_string(),
                advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            },
        );

        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.version, "1.2.0");
        assert_eq!(fix.advisory_ids, vec!["A2".to_string()]);
    }

    #[test]
    fn equal_severity_ties_break_lexicographically_by_id() {
        let vulns = dv(
            vec![
                advisory("B1", VulnSeverity::High, &["1.0.0"]),
                advisory("A1", VulnSeverity::High, &["1.0.0"]),
            ],
            UpgradeStatus::NotChecked,
        );

        let fix = vulns.recommended_fix().unwrap();
        assert_eq!(fix.advisory_ids, vec!["A1".to_string(), "B1".to_string()]);
    }
}

#[cfg(test)]
mod osv_version_validation_tests {
    use super::*;

    fn record_with_fixed(fixed: &[&str]) -> OsvVulnRecord {
        OsvVulnRecord {
            id: "RUSTSEC-2020-0071".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                package: None,
                ecosystem_specific: None,
                ranges: vec![OsvRange {
                    events: fixed
                        .iter()
                        .map(|f| OsvEvent {
                            fixed: Some((*f).to_string()),
                        })
                        .collect(),
                }],
            }],
        }
    }

    #[test]
    fn is_valid_osv_id_rejects_over_length_cap() {
        let long_id = "A".repeat(129);
        assert!(!is_valid_osv_id(&long_id));
        assert!(is_valid_osv_id(&"A".repeat(128)));
    }

    #[test]
    fn malformed_fixed_version_is_dropped_but_record_still_resolves() {
        // Security S-1: a `fixed` value containing manifest-breakout
        // characters (quotes, comma, newline) must never reach
        // `Advisory::fixed_versions`, since that field is later written
        // verbatim into a `TextEdit`.
        let record = record_with_fixed(&["1.0.0", "1.0.0\", git = \"https://evil/x"]);
        let advisory = record
            .into_advisory("pkg", "crates.io")
            .expect("valid id, should still resolve");

        assert_eq!(advisory.fixed_versions, vec!["1.0.0".to_string()]);
    }

    #[test]
    fn fixed_version_over_length_cap_is_dropped() {
        let long_version = format!("1.0.0-{}", "a".repeat(64));
        let record = record_with_fixed(&["1.0.0", &long_version]);
        let advisory = record.into_advisory("pkg", "crates.io").unwrap();

        assert_eq!(advisory.fixed_versions, vec!["1.0.0".to_string()]);
    }

    #[test]
    fn every_fixed_version_malformed_yields_empty_fixed_versions_not_a_dropped_advisory() {
        let record = record_with_fixed(&["1.0.0\nEvil"]);
        let advisory = record
            .into_advisory("pkg", "crates.io")
            .expect("the advisory itself is still valid, just with no usable fix");

        assert!(advisory.fixed_versions.is_empty());
    }

    #[test]
    fn realistic_version_syntax_is_accepted() {
        // SemVer, PEP 440 pre/post-release segments, Go's `+incompatible`.
        for v in [
            "1.2.3",
            "1.2.3-alpha.1",
            "1.2.3+incompatible",
            "1.2.3.post1",
        ] {
            assert!(is_safe_version_string(v), "expected {v:?} to be valid");
        }
    }

    #[test]
    fn manifest_breakout_characters_are_rejected() {
        for v in ["1.0.0\", git = \"evil", "1.0.0,2.0.0", "1.0.0\nEvil", ""] {
            assert!(!is_safe_version_string(v), "expected {v:?} to be rejected");
        }
    }
}
