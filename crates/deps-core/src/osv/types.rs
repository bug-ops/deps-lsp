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

/// Result of checking whether a recommended upgrade target is itself affected.
///
/// Populated by [`crate::osv::OsvClient::check_candidates`] (phase B), which only runs for
/// dependencies phase A already flagged as [`ScanOutcome::Vulnerable`].
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
        /// Advisory IDs that still apply to the candidate version.
        advisory_ids: Vec<String>,
    },
}

/// Vulnerability data for one dependency that OSV reported as non-clean.
#[derive(Debug, Clone)]
pub struct DependencyVulnerabilities {
    /// Advisories fetched in full, capped at [`crate::osv::ADVISORY_DISPLAY_CAP`] (invariant 3
    /// in `architecture.md` §8: the fetch itself is capped, not only the render).
    pub advisories: Vec<Arc<Advisory>>,
    /// Total advisory count OSV reported for this dependency, independent of
    /// how many were actually fetched — the source of the render layer's
    /// "+N more advisories" count (`architecture.md` §7/§8 invariant 3).
    pub total_known: usize,
    /// Result of phase B, if it has run for this dependency.
    pub upgrade_status: UpgradeStatus,
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

/// Per-scan result map, keyed by the normalized dependency name.
///
/// The key is `EcosystemFormatter::normalize_package_name` — the same key
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] and
/// [`crate::lsp_helpers::generate_hover`] already use to look up
/// `cached`/`resolved` versions.
pub type VulnerabilityMap = HashMap<String, ScanOutcome>;

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
/// (`[A-Za-z0-9._-]+`, non-empty) — the same alphabet every real id scheme
/// in this space uses (`RUSTSEC-2020-0071`, `GHSA-xxxx-yyyy-zzzz`,
/// `CVE-2020-26235`). `id` is echoed verbatim into a markdown link
/// destination (`push_vulnerability_hover_section`) and a `Diagnostic.code`,
/// so this is the parse-boundary chokepoint that keeps a malformed id from
/// ever reaching either — rejecting it here means every downstream consumer
/// can treat `Advisory.id` as inherently safe, rather than needing to
/// sanitize it again at each render site.
fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl OsvVulnRecord {
    /// Converts a raw wire record into the `deps-lsp`-facing [`Advisory`],
    /// or `None` if the record's id fails [`is_valid_osv_id`] (dropped, same
    /// as a 404 on `/v1/vulns/{id}` — the dependency renders with whichever
    /// advisories did resolve, never a half-trusted one).
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
