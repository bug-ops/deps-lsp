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
/// let target = ScanTarget::new(
///     "time".to_string(),
///     "time".to_string(),
///     "0.1.43".to_string(),
///     "0.1.43".to_string(),
/// );
/// assert_eq!(target.key, target.osv_name);
/// ```
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for ScanTarget {
    /// Manual, not derived: `key`/`osv_name` are raw package names — the weaker #1217
    /// name-shape sibling of the #1222 sweep (#1237).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanTarget")
            .field("key", &crate::net_policy::redact_declaration_key(&self.key))
            .field(
                "osv_name",
                &crate::net_policy::redact_declaration_key(&self.osv_name),
            )
            .field("version", &self.version)
            .field("display_version", &self.display_version)
            .finish()
    }
}

impl ScanTarget {
    /// Constructs a `ScanTarget` from its four fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Arguments
    ///
    /// * `key` - This project's internal lookup key — used to key [`VulnerabilityMap`],
    ///   **not** what gets sent to OSV
    /// * `osv_name` - OSV's canonical package name for this ecosystem — sent on the wire,
    ///   distinct from `key` because the two do not always round-trip (see [`Self::key`]'s docs)
    /// * `version` - Concrete version rewritten to OSV's wire spelling
    ///   (`EcosystemFormatter::osv_version`) — sent to OSV, never shown to the user
    /// * `display_version` - The same version in the ecosystem's native spelling, for
    ///   surfacing back to the user instead of `version`
    #[must_use]
    pub fn new(key: String, osv_name: String, version: String, display_version: String) -> Self {
        Self {
            key,
            osv_name,
            version,
            display_version,
        }
    }
}

#[cfg(test)]
mod scan_target_debug_redaction_tests {
    use super::ScanTarget;

    crate::debug_redaction_conformance!(
        test_scan_target_debug_redacts_credentials,
        2,
        ScanTarget {
            key: crate::conformance::CREDENTIAL_PROBE_KEY.to_string(),
            osv_name: crate::conformance::CREDENTIAL_PROBE_KEY.to_string(),
            version: "1.0.0".to_string(),
            display_version: "1.0.0".to_string(),
        },
    );
}

/// Severity bucket derived from an OSV advisory record.
///
/// See `architecture.md` §6 for the precedence rules used to derive this
/// from a raw record, and [`crate::osv::diagnostic_severity_for`] for the mapping to
/// [`crate::diagnostic::Severity`].
#[non_exhaustive]
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
    /// The advisory's `id`, or any entry in its `aliases`, carries OSV's
    /// `MAL-` prefix, identifying a confirmed-malicious-package record
    /// ingested from the OpenSSF `malicious-packages` feed: this exact
    /// published version is known malware (typically "fully compromised,
    /// rotate all secrets"), not a graded-but-uncertain risk. `MAL-*`
    /// records carry no CVSS-style severity field at all, so without this
    /// variant they would collapse into [`Self::Unknown`] and render
    /// identically to a merely unscored, low-confidence CVE — see the
    /// `MAL-` prefix check (on both `id` and `aliases`) this crate's OSV
    /// severity classification runs before its graded-severity fallback,
    /// and `architecture.md` §6. The `aliases` check matters because OSV
    /// can serve one confirmed-malicious-package event under a non-`MAL-`
    /// primary id, cross-referencing the canonical `MAL-*` id only via
    /// `aliases`. Deliberately not folded into [`Self::Critical`] either: a
    /// confirmed compromise is categorically different from a graded
    /// CVSS-CRITICAL score, and collapsing the two would make them
    /// indistinguishable to a reader.
    Malicious,
    /// A relevant `affected[]` entry carries a non-empty
    /// `database_specific.informational` value (e.g. RUSTSEC's
    /// `"unmaintained"`) and no graded severity was found anywhere on the
    /// record. Distinct from [`Self::Unknown`]: this is not a vulnerability
    /// this crate failed to grade, it is OSV explicitly saying the record is
    /// a maintenance-status notice rather than a security finding — see
    /// `crate::osv::severity::classify`'s two-pass precedence (issue #1007).
    Informational,
}

/// A single vulnerability advisory, converted from OSV's wire format at the
/// crate boundary.
///
/// # Examples
///
/// ```
/// use deps_core::osv::{Advisory, VulnSeverity};
///
/// let advisory = Advisory::new(
///     "RUSTSEC-2020-0071".to_string(),
///     "2023-01-01T00:00:00Z".to_string(),
///     VulnSeverity::High,
/// )
/// .expect("valid osv id")
/// .with_summary("Potential segfault in the time crate".to_string())
/// .with_aliases(vec!["CVE-2020-26235".to_string()])
/// .with_fixed_versions(vec!["0.2.23".to_string()]);
/// assert_eq!(advisory.fixed_versions.last(), Some(&"0.2.23".to_string()));
/// ```
#[non_exhaustive]
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
    /// `https://osv.dev/vulnerability/{id}`, always derived from [`Self::id`] via
    /// [`validated_osv_url`]. Private (not `pub`) rather than a plain field — see
    /// [`Self::new`]'s doc for why (#1271). Read via [`Self::url()`].
    url: String,
}

impl Advisory {
    /// Constructs an `Advisory` from its required fields, deriving [`Self::url()`] from `id`,
    /// with [`Self::summary`], [`Self::aliases`], [`Self::cvss_vector`], and
    /// [`Self::fixed_versions`] left empty/`None` — chain the corresponding `with_*` setters
    /// to attach them.
    ///
    /// Returns `None` if `id` fails [`is_valid_osv_id`] — mirrors
    /// `OsvVulnRecord::into_advisory`'s own early return for the same check, so a
    /// caller cannot construct an `Advisory` whose URL [`validated_osv_url`] could not
    /// build safely.
    ///
    /// This is the only way to set the URL outside this module: unlike a merely
    /// `#[non_exhaustive]` `pub` field — which still allows a direct field write
    /// (`advisory.url = "...".into()`) from any crate holding an owned value — the private
    /// `url` field makes an unvalidated/unsanitized URL structurally unconstructible from
    /// outside this file (#1271). Mirrors `Diagnostic`'s own private-field-plus-getter
    /// pattern for `message`/`code`, adopted there for the identical reason (closing "a
    /// sanitization-backstop bypass via ... a direct field write").
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (including test code) must go through this
    /// constructor instead.
    ///
    /// # Arguments
    ///
    /// * `id` - Advisory identifier (e.g. `"RUSTSEC-2020-0071"`, `"GHSA-..."`)
    /// * `modified` - RFC3339 last-modified timestamp — not the advisory's publish date
    /// * `severity` - Derived severity bucket
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Advisory, VulnSeverity};
    ///
    /// let advisory = Advisory::new(
    ///     "RUSTSEC-2020-0071".to_string(),
    ///     "2023-01-01T00:00:00Z".to_string(),
    ///     VulnSeverity::High,
    /// )
    /// .expect("valid osv id")
    /// .with_fixed_versions(vec!["0.2.23".to_string()]);
    /// assert_eq!(advisory.fixed_versions.last(), Some(&"0.2.23".to_string()));
    /// ```
    #[must_use]
    pub fn new(id: String, modified: String, severity: VulnSeverity) -> Option<Self> {
        let url = validated_osv_url(&id)?;
        Some(Self {
            id,
            modified,
            summary: None,
            aliases: Vec::new(),
            severity,
            cvss_vector: None,
            fixed_versions: Vec::new(),
            url,
        })
    }

    /// Returns `https://osv.dev/vulnerability/{id}` — [`Self::id`]'s advisory page on
    /// OSV.dev.
    ///
    /// The only accessor for the private `url` field (#1271): every `Advisory` in existence
    /// was built by [`Self::new`], so this value is always [`validated_osv_url`]'s output for
    /// [`Self::id`], never an arbitrary caller-supplied string.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Advisory, VulnSeverity};
    ///
    /// let advisory = Advisory::new(
    ///     "RUSTSEC-2020-0071".to_string(),
    ///     "2023-01-01T00:00:00Z".to_string(),
    ///     VulnSeverity::High,
    /// )
    /// .expect("valid osv id");
    /// assert_eq!(advisory.url(), "https://osv.dev/vulnerability/RUSTSEC-2020-0071");
    /// ```
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Attaches a human-readable one-line summary. See [`Self::summary`].
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Attaches alternate identifiers (CVE, GHSA, ...). See [`Self::aliases`].
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Attaches the raw CVSS vector string. See [`Self::cvss_vector`].
    #[must_use]
    pub fn with_cvss_vector(mut self, cvss_vector: impl Into<String>) -> Self {
        self.cvss_vector = Some(cvss_vector.into());
        self
    }

    /// Attaches the `fixed` events found in the record's ranges. See [`Self::fixed_versions`].
    #[must_use]
    pub fn with_fixed_versions(mut self, fixed_versions: Vec<String>) -> Self {
        self.fixed_versions = fixed_versions;
        self
    }
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
#[non_exhaustive]
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
#[non_exhaustive]
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

impl DependencyVulnerabilities {
    /// Constructs a `DependencyVulnerabilities` from its fetched advisories, with
    /// [`Self::upgrade_status`] and [`Self::fix_target_status`] both left at
    /// [`UpgradeStatus::NotChecked`] — chain [`Self::with_upgrade_status`] and/or
    /// [`Self::with_fix_target_status`] to attach phase B results.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (including test code) must go through this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Capped, DependencyVulnerabilities};
    ///
    /// let dv = DependencyVulnerabilities::new(Capped::new(vec![], 0));
    /// assert!(dv.advisories.items().is_empty());
    /// ```
    #[must_use]
    pub const fn new(advisories: Capped<Arc<Advisory>>) -> Self {
        Self {
            advisories,
            upgrade_status: UpgradeStatus::NotChecked,
            fix_target_status: UpgradeStatus::NotChecked,
        }
    }

    /// Attaches phase B's "latest" check result. See [`Self::upgrade_status`].
    #[must_use]
    pub fn with_upgrade_status(mut self, upgrade_status: UpgradeStatus) -> Self {
        self.upgrade_status = upgrade_status;
        self
    }

    /// Attaches the independent verification of the recommended fix target. See
    /// [`Self::fix_target_status`].
    #[must_use]
    pub fn with_fix_target_status(mut self, fix_target_status: UpgradeStatus) -> Self {
        self.fix_target_status = fix_target_status;
        self
    }
}

/// A single upgrade target recommended by [`DependencyVulnerabilities::recommended_fix`].
///
/// `version` is in OSV's version namespace (see
/// [`crate::lsp_helpers::OsvNaming::osv_version_to_native`] for the
/// conversion callers must apply before using it in a manifest edit or a
/// registry lookup).
///
/// Output-only: constructed internally by [`DependencyVulnerabilities::recommended_fix`],
/// never by external code — no constructor is provided.
#[non_exhaustive]
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
///
/// `Malicious` ranks above `Critical`: a confirmed-malicious-package finding
/// is more urgent than any graded CVSS score. In practice a `Malicious`
/// advisory rarely reaches this ranking at all, since `recommended_fix` only
/// considers advisories with a known fix and a malicious-package record
/// typically has none.
const fn severity_rank(severity: VulnSeverity) -> u8 {
    match severity {
        VulnSeverity::Malicious => 6,
        VulnSeverity::Critical => 5,
        VulnSeverity::High => 4,
        VulnSeverity::Medium => 3,
        VulnSeverity::Low => 2,
        VulnSeverity::Unknown => 1,
        VulnSeverity::Informational => 0,
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
    ///     Arc::new(
    ///         Advisory::new(
    ///             id.to_string(),
    ///             "2023-01-01T00:00:00Z".to_string(),
    ///             VulnSeverity::High,
    ///         )
    ///         .expect("valid osv id")
    ///         .with_fixed_versions(vec![fixed.to_string()]),
    ///     )
    /// }
    ///
    /// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory("RUSTSEC-1", "1.2.0")], 1));
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
#[non_exhaustive]
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
// Exhaustive: deliberate trichotomy per the doc above — a new "no data" case becomes a new
// `SkipReason` variant, never a 4th `ScanOutcome` variant (issue #769).
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
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::vulnerability_keys;
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, EcosystemId, PackageName, ParseResult, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use url::Url;
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
///     uri: Url,
/// }
///
/// impl ParseResult for SimpleParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> {
///         None
///     }
///     fn uri(&self) -> &Url {
///         &self.uri
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
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
/// // `time` declared twice, pinned to two different versions.
/// let parse_result = SimpleParseResult {
///     deps: vec![
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.43")),
///             name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
///         },
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.44")),
///             name_range: Range::new(Position::new(3, 0), Position::new(3, 4)).into(),
///         },
///     ],
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
/// };
/// let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
///
/// let keys = vulnerability_keys(&parse_result, &resolved, None, &SimpleFormatter, EcosystemId::Cargo);
/// let deps = parse_result.dependencies();
/// let key0 = keys.get(&deps[0].name_range()).unwrap();
/// let key1 = keys.get(&deps[1].name_range()).unwrap();
/// assert_ne!(key0, key1, "differently-pinned occurrences of one name get distinct keys");
/// ```
pub fn vulnerability_keys(
    parse_result: &dyn crate::ParseResult,
    resolved: &HashMap<crate::PackageName, crate::ConcreteVersion>,
    resolved_candidates: Option<&HashMap<crate::PackageName, Vec<crate::ConcreteVersion>>>,
    formatter: &dyn crate::lsp_helpers::EcosystemFormatter,
    ecosystem: crate::EcosystemId,
) -> HashMap<crate::position::Range, String> {
    use crate::lsp_helpers::resolve_in_use_version;

    let deps = parse_result.dependencies();

    // One signature per occurrence: public-registry-content deps (F1b) carry their own
    // in-use version ("u" when undeterminable); every other source always carries "n"
    // (`ScanOutcome` is always `Skipped(NonRegistrySource)` there).
    //
    // `resolved_candidates` (#649) lets two occurrences of a renamed/aliased name pinned to
    // different lock-file majors compute distinct `v:{version}` signatures instead of
    // colliding — see `resolve_occurrence_version`.
    let signatures: Vec<(String, String)> = deps
        .iter()
        .map(|dep| {
            let name = formatter.normalize_package_name(dep.name());
            let signature = if formatter.source_is_public_registry_content(&dep.source()) {
                match resolve_in_use_version(
                    *dep,
                    &name,
                    resolved,
                    resolved_candidates,
                    formatter,
                    ecosystem,
                ) {
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
        // A synthetic `name_range()` is not a stable per-dependency position — every such
        // dependency would share the same key, each insertion evicting the last. Excluding
        // them here falls through to `apply_vulnerability_rule`'s own name-based fallback.
        .filter(|(dep, _)| !dep.name_range_is_synthetic())
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
    /// Per-entry `database_specific` — distinct from [`OsvVulnRecord`]'s
    /// record-level `database_specific` field (already read for
    /// `severity`). Carries OSV's `informational` value (e.g.
    /// RUSTSEC's `"unmaintained"`), read by `severity::classify` (issue
    /// #1007, FR-001).
    #[serde(default)]
    pub(super) database_specific: Option<serde_json::Value>,
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
/// (`[A-Za-z0-9._-]+`, non-empty, capped at 128 bytes).
///
/// The same alphabet every real id scheme in this space uses (`RUSTSEC-2020-0071`,
/// `GHSA-xxxx-yyyy-zzzz`, `CVE-2020-26235`); real ids are a few dozen
/// characters, so the cap exists only to bound how much of a record-supplied
/// string can ride along into `Diagnostic.code`, hover markdown, and a
/// `CodeAction` title. `id` is echoed verbatim into a markdown link
/// destination (`push_vulnerability_hover_section`) and a `Diagnostic.code`,
/// so this is the parse-boundary chokepoint that keeps a malformed id from
/// ever reaching either — rejecting it here means every downstream consumer
/// can treat `Advisory.id` as inherently safe, rather than needing to
/// sanitize it again at each render site.
///
/// The bare character class alone is not sufficient (issue #1077 review): `.` is an allowed
/// character (real ids can contain it), so a lone `id` of exactly `"."` or `".."` — RFC 3986's
/// two dot-segments — would otherwise still pass, and `https://osv.dev/vulnerability/..`
/// normalizes (`remove_dot_segments`) to `https://osv.dev/`, walking a consumer's link up and
/// out of `/vulnerability/` without `id` ever containing a literal `/`. Both are rejected as an
/// explicit special case.
pub fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Builds `https://osv.dev/vulnerability/{id}`, or `None` if `id` fails [`is_valid_osv_id`].
///
/// The single validated construction path for this URL (issue #1077 review): used by
/// `OsvVulnRecord::into_advisory` to build [`Advisory::url`], and reusable by any downstream
/// consumer that only has a bare advisory-id *string* (not a whole [`Advisory`]) and needs to
/// independently confirm it is safe to embed as a URI path segment before doing so — e.g.
/// `deps-cli`'s SARIF `helpUri`, which cannot assume every `code` string it sees necessarily
/// went through this crate's own OSV-response parsing (`crate::report::classify`'s documented
/// "any unrecognized diagnostic code -> Vulnerable" fallback can hand it a string this crate
/// never validated at all).
#[must_use]
pub fn validated_osv_url(id: &str) -> Option<String> {
    is_valid_osv_id(id).then(|| format!("https://osv.dev/vulnerability/{id}"))
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
        let used_fallback_all = relevant.is_empty() && !self.affected.is_empty();
        let relevant: Vec<&OsvAffected> = if used_fallback_all {
            tracing::warn!(
                id = %self.id, osv_name, osv_eco,
                "no affected[] entry matched the queried package; using all entries"
            );
            self.affected.iter().collect()
        } else {
            relevant
        };

        // FR-002b: `classify()` requires each candidate's `package` to equal
        // `osv_name`/`osv_eco` exactly before trusting its `informational` value, so a
        // `package`-less or fallback-pulled entry can never downgrade this classification
        // for a package it doesn't confirmedly describe (impl-critic M2).
        let severity = super::severity::classify(
            &self.id,
            &self.aliases,
            self.database_specific.as_ref(),
            &relevant,
            osv_name,
            osv_eco,
        );
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

        // Exhaustive literal (not `Advisory::new`) so a future new field fails to compile here.
        let url = validated_osv_url(&self.id)?;

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
        // Critic S1 counterexample: A1 (fixed 3.0.0) still applies at the candidate and is
        // excluded; A2 (fixed 1.2.0) is claimed. Recommended version must be 1.2.0, computed
        // over what's actually claimed — not 3.0.0, which doesn't even resolve A1.
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
                database_specific: None,
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

    /// Regression test for issue #1077 review: `.`/`..` pass the bare character-class
    /// allowlist (`.` is an allowed character) but are RFC 3986 dot-segments that would
    /// normalize `https://osv.dev/vulnerability/{id}` up and out of `/vulnerability/`.
    #[test]
    fn is_valid_osv_id_rejects_dot_segments() {
        assert!(!is_valid_osv_id("."));
        assert!(!is_valid_osv_id(".."));
        // A real id containing dots (but not equal to a bare dot-segment) is still valid.
        assert!(is_valid_osv_id("RUSTSEC-2020-0071"));
    }

    #[test]
    fn validated_osv_url_builds_the_expected_url_for_a_valid_id() {
        assert_eq!(
            validated_osv_url("RUSTSEC-2020-0071"),
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071".to_string())
        );
    }

    #[test]
    fn validated_osv_url_rejects_a_dot_segment_id() {
        assert_eq!(validated_osv_url(".."), None);
    }

    #[test]
    fn validated_osv_url_rejects_an_id_containing_a_slash() {
        // A `/` is not in the allowlist, so a multi-segment traversal attempt embedded in the
        // id (e.g. `../evil`) can never reach `Uri` parsing in the first place.
        assert_eq!(validated_osv_url("../evil"), None);
    }

    /// #1271: `Advisory::new` takes only `id`, never a caller-supplied `url` — this asserts
    /// the derived value actually matches `validated_osv_url`'s own formula, so the two can't
    /// drift apart.
    #[test]
    fn advisory_new_derives_url_from_id() {
        let advisory = Advisory::new(
            "RUSTSEC-2020-0071".to_string(),
            "2023-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
        )
        .expect("valid osv id");
        assert_eq!(
            advisory.url(),
            validated_osv_url("RUSTSEC-2020-0071").unwrap()
        );
    }

    /// #1271: an id that fails `is_valid_osv_id` (and so cannot produce a safe `url`) must
    /// make `Advisory` unconstructible via `new` — a future caller cannot bypass this by
    /// supplying a raw `url` directly, since the constructor no longer accepts one at all.
    #[test]
    fn advisory_new_rejects_a_malformed_id() {
        assert!(
            Advisory::new(
                "..".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .is_none()
        );
        // #1272 round 2 critic M4: the length cap matters at least as much as the
        // dot-segment case for the unbounded-length story this issue is about.
        assert!(
            Advisory::new(
                "A".repeat(129),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .is_none()
        );
    }

    /// Regression test for issue #1077 review: a record whose id is a dot-segment must be
    /// dropped by `into_advisory` itself (same as any other malformed id), not merely have a
    /// bad `helpUri` built from it somewhere downstream.
    #[test]
    fn into_advisory_drops_a_record_whose_id_is_a_dot_segment() {
        let record = OsvVulnRecord {
            id: "..".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![],
        };
        assert!(record.into_advisory("pkg", "crates.io").is_none());
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

/// Issue #1007: `into_advisory` end-to-end against the exact live-verified OSV wire
/// shape for `RUSTSEC-2024-0320` (`yaml-rust`) — re-queried 2026-09-14 via
/// `POST https://api.osv.dev/v1/query {"package":{"name":"yaml-rust","ecosystem":"crates.io"},
/// "version":"0.4.5"}`. Captured as a fixture rather than a live HTTP call per the
/// project's existing `mockito`-based test convention.
#[cfg(test)]
mod informational_record_tests {
    use super::*;

    const YAML_RUST_RUSTSEC_2024_0320: &str = r#"{
        "id": "RUSTSEC-2024-0320",
        "summary": "yaml-rust is unmaintained.",
        "modified": "2024-11-01T12:31:51Z",
        "database_specific": { "license": "CC0-1.0" },
        "affected": [
            {
                "package": {
                    "name": "yaml-rust",
                    "ecosystem": "crates.io",
                    "purl": "pkg:cargo/yaml-rust"
                },
                "ranges": [
                    { "type": "SEMVER", "events": [{ "introduced": "0.0.0-0" }] }
                ],
                "ecosystem_specific": {
                    "affects": { "arch": [], "functions": [], "os": [] },
                    "affected_functions": null
                },
                "database_specific": {
                    "categories": [],
                    "cvss": null,
                    "informational": "unmaintained",
                    "source": "https://github.com/rustsec/advisory-db/blob/osv/crates/RUSTSEC-2024-0320.json"
                }
            }
        ],
        "schema_version": "1.7.3"
    }"#;

    #[test]
    fn live_yaml_rust_unmaintained_record_classifies_as_informational() {
        let record: OsvVulnRecord = serde_json::from_str(YAML_RUST_RUSTSEC_2024_0320).unwrap();
        let advisory = record
            .into_advisory("yaml-rust", "crates.io")
            .expect("valid id, should resolve");

        assert_eq!(advisory.severity, VulnSeverity::Informational);
        assert!(
            advisory.fixed_versions.is_empty(),
            "an unmaintained notice has no fixed version"
        );
        assert_eq!(
            advisory.summary.as_deref(),
            Some("yaml-rust is unmaintained.")
        );
    }

    /// M3 (impl-critic): confirms `into_advisory` itself computes the
    /// genuine-match signal end-to-end — not just that `classify()` respects
    /// a pre-computed flag handed to it directly. Queries a *different*
    /// package than the record's sole `affected[]` entry names, so
    /// `into_advisory` falls back to its "no entry matched; using all
    /// entries" path (FR-002b) — the `informational` value on that stranger
    /// entry must not classify the record as `Informational`.
    #[test]
    fn into_advisory_rejects_informational_from_fallback_all_entries() {
        let record: OsvVulnRecord = serde_json::from_str(YAML_RUST_RUSTSEC_2024_0320).unwrap();
        let advisory = record
            .into_advisory("some-other-crate", "crates.io")
            .expect("valid id, should resolve");

        assert_ne!(advisory.severity, VulnSeverity::Informational);
    }

    /// M2/M3 (impl-critic): an `affected[]` entry with no `package` field at
    /// all is lenient-matched into `into_advisory`'s `relevant` set (not the
    /// fallback-all path — see the existing `is_none_or` filter), but must
    /// still not count as a genuine per-package match for the informational
    /// check specifically.
    #[test]
    fn into_advisory_rejects_informational_from_package_less_entry() {
        let json = r#"{
            "id": "RUSTSEC-2020-0071",
            "modified": "2023-01-01T00:00:00Z",
            "affected": [
                { "database_specific": { "informational": "unmaintained" } }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory("yaml-rust", "crates.io")
            .expect("valid id, should resolve");

        assert_ne!(advisory.severity, VulnSeverity::Informational);
    }

    /// H1 (security): RUSTSEC's `"unsound"` category (live-verified shape,
    /// e.g. `RUSTSEC-2021-0145`/`atty`) is a real memory-safety/UB finding,
    /// not a maintenance-status notice — `into_advisory` must never classify
    /// it as `Informational`.
    #[test]
    fn into_advisory_rejects_unsound_value() {
        let json = r#"{
            "id": "RUSTSEC-2021-0145",
            "modified": "2021-07-06T00:00:00Z",
            "affected": [
                {
                    "package": { "name": "atty", "ecosystem": "crates.io" },
                    "database_specific": { "informational": "unsound" }
                }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory("atty", "crates.io")
            .expect("valid id, should resolve");

        assert_ne!(
            advisory.severity,
            VulnSeverity::Informational,
            "an unsound (UB/memory-safety) advisory must never be downgraded to Informational"
        );
    }

    /// M4 (impl-critic, low): a non-object `database_specific` and a
    /// non-string `informational` value must never panic — both guard
    /// chains (`.as_object()`-free `.get()`/`.as_str()`) already handle
    /// this by returning `None`, this pins that behavior.
    #[test]
    fn into_advisory_does_not_panic_on_non_object_database_specific_or_non_string_informational() {
        let json = r#"{
            "id": "RUSTSEC-2020-0071",
            "modified": "2023-01-01T00:00:00Z",
            "affected": [
                {
                    "package": { "name": "yaml-rust", "ecosystem": "crates.io" },
                    "database_specific": "not-an-object"
                },
                {
                    "package": { "name": "yaml-rust", "ecosystem": "crates.io" },
                    "database_specific": { "informational": 12345 }
                }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory("yaml-rust", "crates.io")
            .expect("valid id, should resolve");

        assert_eq!(advisory.severity, VulnSeverity::Unknown);
    }
}

/// Issue #649 FR-004: `vulnerability_keys` with a populated `resolved_candidates` map, the
/// exact call shape `deps-lsp`'s `build_scan_targets`/phase A OSV scan use. Every production
/// `vulnerability_keys` call site was migrated to accept this parameter, but per the
/// pre-review test-coverage audit, every *test* call site only ever passed `None` — this
/// closes that direct-coverage gap.
#[cfg(test)]
mod vulnerability_keys_candidates_tests {
    use super::*;
    use crate::lsp_helpers::test_support::{MockDep, MockFormatter};
    use crate::position::{Position, Range};
    use crate::{ConcreteVersion, EcosystemId, PackageName, ParseResult, VersionReq};

    #[test]
    fn distinct_signatures_for_two_occurrences_resolving_to_different_candidates() {
        // The serde/serde_old shape from issue #649: one plain occurrence pinned to the
        // current major, one renamed occurrence pinned to an older major, both sharing the
        // resolved package name `serde`.
        let current_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0"),
            version_range: Range::new(Position::new(0, 0), Position::new(0, 4)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let renamed_old_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("0.9"),
            version_range: Range::new(Position::new(1, 0), Position::new(1, 4)),
            name_range: Range::new(Position::new(1, 0), Position::new(1, 9)),
        };

        struct TwoOccurrenceParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
        }
        impl crate::ParseResult for TwoOccurrenceParseResult {
            fn dependencies(&self) -> Vec<&dyn crate::Dependency> {
                self.deps
                    .iter()
                    .map(|d| d as &dyn crate::Dependency)
                    .collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let parse_result = TwoOccurrenceParseResult {
            deps: vec![current_major, renamed_old_major],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut resolved = std::collections::HashMap::new();
        resolved.insert(PackageName::new("serde"), ConcreteVersion::from("1.0.219"));
        let mut candidates = std::collections::HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let keys = vulnerability_keys(
            &parse_result,
            &resolved,
            Some(&candidates),
            &MockFormatter,
            EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let current_key = keys.get(&deps[0].name_range()).unwrap();
        let renamed_key = keys.get(&deps[1].name_range()).unwrap();

        assert_ne!(
            current_key, renamed_key,
            "the current-major and renamed-old-major occurrences must not share an OSV key"
        );
        assert!(
            current_key.ends_with("v:1.0.219"),
            "current-major occurrence's key must carry its own resolved version: {current_key}"
        );
        assert!(
            renamed_key.ends_with("v:0.9.15"),
            "renamed occurrence's key must carry its own resolved version, not the collapsed \
             1.0.219: {renamed_key}"
        );
    }

    /// Critic finding S1 (#905): a dependency with a synthetic `name_range()` (e.g.
    /// `deps-dart`'s container-anchor alias resolution) must not get an entry in this map —
    /// every such dependency in one document would share the exact same key
    /// (`Range::default()`), each insertion silently evicting the last, so a real dependency
    /// that happens to collide with that same sentinel (a pre-existing, rarer miss case on
    /// other ecosystems) could otherwise be handed an unrelated package's OSV lookup key.
    #[test]
    fn vulnerability_keys_excludes_synthetic_range_dependencies() {
        use crate::lsp_helpers::test_support::{MockMixedParseResult, MockSyntheticRangeDep};

        let parse_result = MockMixedParseResult {
            deps: vec![
                Box::new(MockSyntheticRangeDep {
                    name: PackageName::new("synthetic-pkg"),
                }),
                Box::new(MockDep {
                    name: PackageName::new("real-pkg"),
                    version_req: VersionReq::new("1.0.0"),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                }),
            ],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let resolved = std::collections::HashMap::new();
        let keys = vulnerability_keys(
            &parse_result,
            &resolved,
            None,
            &MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(
            keys.len(),
            1,
            "only the real dependency's real name_range should be keyed"
        );
        let deps = parse_result.dependencies();
        assert!(
            keys.contains_key(&deps[1].name_range()),
            "the real dependency's own range must still be present"
        );
    }
}
