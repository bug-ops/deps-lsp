//! `CheckReport`/`CheckFinding`/`Category`/`FailOnPolicy` and the classification
//! orchestrator that assembles one manifest's [`deps_core::VersionData`].
//!
//! It then calls its ecosystem's [`deps_core::Ecosystem::generate_diagnostics`] — the
//! identical call `deps-lsp`'s `handlers/diagnostics.rs` makes.
//!
//! Every outdated/yanked/vulnerable/unsatisfiable/deprecated verdict is decided by
//! [`deps_engine::classify`] or by `generate_diagnostics` itself; nothing in this module
//! re-derives a verdict from raw registry/lockfile/OSV data (spec 062 FR-005). `Category`
//! stays in this crate rather than `deps_core` per `specs/062-cli-check-mode/plan.md`'s
//! `[NEEDS CLARIFICATION: O-4]` marker — see that doc before moving it.

use deps_core::diagnostic::{Diagnostic, Severity};
use deps_core::lsp_helpers::{
    DEPRECATED_DIAGNOSTIC_CODE, DependencyOutcomes, LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE,
    UNSATISFIABLE_DIAGNOSTIC_CODE,
};
use deps_core::osv::{OsvClient, ScanOutcome, VulnSeverity, VulnerabilityMap};
use deps_core::policy_config::PolicyConfig;
use deps_core::position::Range;
use deps_core::{Dependency, Ecosystem, EcosystemId, HttpCache, PackageName, VersionData};
use deps_engine::classify::diff::{
    merge_deprecations_after_fetch, merge_no_comparable_versions_after_fetch,
};
use deps_engine::classify::fetch::{
    apply_fetch_outcomes, composer_minimum_stability, dedup_dependencies_by_source,
    fetch_latest_versions_parallel,
};
use deps_engine::classify::osv::build_scan_targets;
use deps_engine::classify::resolved::{collect_in_use_versions, load_resolved_versions};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Every non-`deps-core` diagnostic code constant in the workspace, mirrored here as
/// literals rather than importing `deps-github-actions`/`deps-gitlab-ci` directly (both are
/// optional, feature-gated dependencies of `deps-engine`; importing their constants
/// unconditionally would break a `--no-default-features --features cargo`-style build, and
/// `#[cfg]`-gating each match arm was judged not worth the complexity for three stable
/// strings). **This list must stay exhaustive** — issue C3 (spec 062 review) was exactly one
/// ecosystem-owned code (`UNRESOLVED_HOST_DIAGNOSTIC_CODE`) missing from it, which silently
/// misclassified an informational notice as `Category::Vulnerable`. Before trusting
/// [`classify`]'s fallback again, re-run
/// `grep -rn 'pub const.*_DIAGNOSTIC_CODE.*: &str' crates/*/src/lib.rs crates/*/src/ecosystem.rs`
/// across the workspace and add anything new here.
const GITHUB_ACTIONS_MUTABLE_REF_PIN_CODE: &str = "mutable-ref-pin";
/// See [`GITHUB_ACTIONS_MUTABLE_REF_PIN_CODE`]'s doc.
const GITLAB_CI_MUTABLE_REF_PIN_CODE: &str = "gitlab-ci-mutable-ref-pin";
/// `deps_gitlab_ci::UNRESOLVED_HOST_DIAGNOSTIC_CODE` — an informational notice (INFORMATION
/// severity, never a vulnerability), emitted unconditionally whenever GitLab CI's
/// `registries.gitlab_instance_host` is unset/invalid. See
/// [`GITHUB_ACTIONS_MUTABLE_REF_PIN_CODE`]'s doc for why this is a literal.
const GITLAB_CI_UNRESOLVED_HOST_CODE: &str = "unresolved-gitlab-host";

/// Ceiling on the OSV scan timeout, independent of the configured `fetch_timeout_secs` —
/// mirrors `deps-lsp`'s `document::osv_scan::OSV_SCAN_TIMEOUT_CEILING_SECS`: the shared
/// `reqwest` client behind [`HttpCache`] already imposes its own client-wide 30s timeout, so
/// a longer per-phase timeout would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

/// A category a [`CheckFinding`] can be classified into — the seven `--fail-on` tokens FR-009
/// defines, plus [`Category::Other`].
///
/// `Other` covers a `generate_diagnostics` finding that matches none of the seven (an
/// "Unknown package", a collapsed registry-lookup failure, or a workspace-registry/
/// offline/dependency-count notice). It is never selectable via `--fail-on`
/// (`#[value(skip)]`) and never matched by [`FailOnPolicy`] — it exists purely so
/// [`CheckFinding`] stays a 1:1 mapping of every diagnostic `generate_diagnostics` produced,
/// per spec 062 `tasks.md` T020, rather than silently dropping findings this crate cannot
/// classify.
///
/// # Examples
///
/// ```
/// use deps_cli::report::Category;
///
/// assert_eq!(Category::MutableRefPin.as_str(), "mutable-ref");
/// assert_eq!(Category::License.as_str(), "license");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, clap::ValueEnum)]
pub enum Category {
    /// A newer version is published for a dependency's declared requirement.
    Outdated,
    /// The in-use (or only-satisfying) version has been yanked/retracted.
    Yanked,
    /// A known OSV advisory affects the in-use version.
    Vulnerable,
    /// No published version satisfies the declared requirement.
    Unsatisfiable,
    /// Pinned to a mutable ref (tag/branch) instead of a commit SHA (GitHub Actions/GitLab
    /// CI).
    #[value(name = "mutable-ref")]
    MutableRefPin,
    /// The resolved license violates the configured allow/deny policy.
    License,
    /// The registry reports the package itself as deprecated/abandoned.
    Deprecated,
    /// A `generate_diagnostics` finding that does not map to any category above.
    #[value(skip)]
    Other,
}

impl Category {
    /// The FR-009 wire token for this category (`table`/`json` output and `--fail-on`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outdated => "outdated",
            Self::Yanked => "yanked",
            Self::Vulnerable => "vulnerable",
            Self::Unsatisfiable => "unsatisfiable",
            Self::MutableRefPin => "mutable-ref",
            Self::License => "license",
            Self::Deprecated => "deprecated",
            Self::Other => "other",
        }
    }

    /// A one-line human-readable description, longer than [`Self::as_str`]'s wire token —
    /// used as SARIF rule metadata (`crate::format::sarif`) for a rule that only has
    /// category-level granularity (no finer diagnostic code). Deliberately close in wording
    /// to each variant's own doc comment above (both describe the same category, and SARIF's
    /// `shortDescription` is meant to read like ordinary documentation prose) rather than a
    /// genuinely distinct text written just to avoid the overlap.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cli::report::Category;
    ///
    /// assert_eq!(
    ///     Category::Vulnerable.description(),
    ///     "A known security advisory affects the in-use version."
    /// );
    /// assert_eq!(
    ///     Category::License.description(),
    ///     "The resolved license violates the configured allow/deny policy."
    /// );
    /// ```
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Outdated => {
                "A newer version is published for the dependency's declared requirement."
            }
            Self::Yanked => "The in-use version has been yanked or retracted from the registry.",
            Self::Vulnerable => "A known security advisory affects the in-use version.",
            Self::Unsatisfiable => "No published version satisfies the declared requirement.",
            Self::MutableRefPin => {
                "Pinned to a mutable ref (tag or branch) instead of a commit SHA."
            }
            Self::License => "The resolved license violates the configured allow/deny policy.",
            Self::Deprecated => {
                "The registry reports the package itself as deprecated or abandoned."
            }
            Self::Other => "A finding that does not map to any of the other categories.",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One reported issue, derived 1:1 from a [`Diagnostic`] `generate_diagnostics` produced.
#[derive(Debug, Clone)]
pub struct CheckFinding {
    /// Which ecosystem's manifest this finding came from.
    pub ecosystem: EcosystemId,
    /// Path to the manifest, relative to the walked root when discovered by [`crate::walk`].
    pub manifest_path: PathBuf,
    /// The dependency's declared name, when a manifest occurrence's range matched the
    /// diagnostic's own range. `None` for a document-level finding not anchored to one
    /// dependency (e.g. an offline/dependency-count notice).
    pub dependency_name: Option<String>,
    /// The dependency's declared version requirement, when known.
    pub requirement: Option<String>,
    /// The classified category (see [`Category`]).
    pub category: Category,
    /// The diagnostic's own `code`, when it carried a string one (spec 062 review S3,
    /// issue #1075): a vulnerability diagnostic's code is an OSV advisory id
    /// (`RUSTSEC-...`/`GHSA-...`), finer-grained than [`Self::category`]; the workspace's
    /// other stable diagnostic-code constants (`UNSATISFIABLE_DIAGNOSTIC_CODE`, etc.) are
    /// 1:1 with a category, so carrying them here changes nothing beyond echoing
    /// `category`. `None` when `classify` fell back to matching the diagnostic's message
    /// text instead of its code (`Outdated`/`Yanked`/`Other`).
    pub code: Option<String>,
    /// The advisory's own `https://osv.dev/vulnerability/{id}` page, when [`Self::code`] is
    /// an OSV advisory id — sourced from the diagnostic's `code_description.href` (already
    /// `Uri`-parsed and validated by `deps_core::lsp_helpers::diagnostics::
    /// push_vulnerability_diagnostics` before it ever reaches a `Diagnostic`), not
    /// re-derived from `code` — the authoritative URL OSV itself gave us, rather than a
    /// second, redundant formula that could drift from it. `None` whenever `code_description`
    /// is absent (every non-advisory finding, and the rare case where OSV's own `url` failed
    /// `Uri` parsing upstream).
    pub advisory_url: Option<String>,
    /// The OSV-derived severity bucket for [`Self::code`], when it names an advisory this
    /// manifest's OSV scan actually fetched (issue #1077 C2) — looked up by advisory id from
    /// the same scan results `generate_diagnostics` consumed, not re-derived from
    /// [`Self::severity`] (the three-bucket [`Severity`] `code` already collapsed into is too
    /// coarse to recover a CVSS-style grade from). `None` for every non-advisory finding, and
    /// for an advisory `code` this run's scan did not itself fetch (e.g. a stale `code` from a
    /// formatter that does not source it from a live scan).
    pub advisory_severity: Option<VulnSeverity>,
    /// The diagnostic's severity.
    pub severity: Severity,
    /// The diagnostic's range within the manifest.
    pub range: Range,
    /// The diagnostic's human-readable message.
    pub message: String,
}

/// The full result of one `check` invocation.
#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    /// Every finding produced across every walked manifest.
    pub findings: Vec<CheckFinding>,
}

impl CheckReport {
    /// Per-category finding counts, derived from [`Self::findings`] rather than kept as
    /// separately mutated state (spec 062 tasks.md T020).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cli::report::{Category, CheckFinding, CheckReport};
    /// use deps_core::EcosystemId;
    /// use deps_core::diagnostic::Severity;
    /// use deps_core::position::Range;
    /// use std::path::PathBuf;
    ///
    /// let report = CheckReport {
    ///     findings: vec![CheckFinding {
    ///         ecosystem: EcosystemId::Cargo,
    ///         manifest_path: PathBuf::from("Cargo.toml"),
    ///         dependency_name: Some("serde".to_string()),
    ///         requirement: Some("1.0".to_string()),
    ///         category: Category::Outdated,
    ///         code: None,
    ///         advisory_url: None,
    ///         advisory_severity: None,
    ///         severity: Severity::Hint,
    ///         range: Range::default(),
    ///         message: "Newer version available: 1.1".to_string(),
    ///     }],
    /// };
    /// assert_eq!(report.summary().get(&Category::Outdated), Some(&1));
    /// ```
    #[must_use]
    pub fn summary(&self) -> BTreeMap<Category, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.category).or_insert(0_usize) += 1;
        }
        counts
    }
}

/// The set of categories that turn at least one matching [`CheckFinding`] into a
/// process-exit-1 policy violation (FR-009/FR-010).
#[derive(Debug, Clone)]
pub struct FailOnPolicy {
    categories: Vec<Category>,
}

impl FailOnPolicy {
    /// Builds a policy from an explicit category list.
    #[must_use]
    pub const fn new(categories: Vec<Category>) -> Self {
        Self { categories }
    }

    /// The default policy (FR-010): `vulnerable,yanked,unsatisfiable` — the categories that
    /// represent a broken or unsafe build, as opposed to advisory-only categories.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cli::report::{Category, FailOnPolicy};
    ///
    /// let policy = FailOnPolicy::default_categories();
    /// assert!(policy.categories().contains(&Category::Vulnerable));
    /// assert!(!policy.categories().contains(&Category::Outdated));
    /// ```
    #[must_use]
    pub fn default_categories() -> Self {
        Self::new(vec![
            Category::Vulnerable,
            Category::Yanked,
            Category::Unsatisfiable,
        ])
    }

    /// The categories this policy fails on.
    #[must_use]
    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    /// Whether any finding in `findings` matches this policy.
    #[must_use]
    pub fn matches(&self, findings: &[CheckFinding]) -> bool {
        findings
            .iter()
            .any(|finding| self.categories.contains(&finding.category))
    }
}

impl Default for FailOnPolicy {
    fn default() -> Self {
        Self::default_categories()
    }
}

/// Runtime handles and resolved policy shared across every manifest a `check` run classifies.
///
/// Built once in `main.rs` (or by an integration test) and passed by reference to
/// [`check_manifest`] for every discovered manifest.
#[derive(Clone)]
pub struct CheckContext {
    /// Shared HTTP cache for registry requests.
    pub cache: Arc<HttpCache>,
    /// Shared OSV.dev vulnerability scan client.
    pub osv: Arc<OsvClient>,
    /// Shared lock-file cache, keyed by resolved lockfile path.
    pub lockfile_cache: Arc<deps_core::lockfile::LockFileCache>,
    /// The resolved policy configuration for this run.
    pub policy: PolicyConfig,
}

/// Error running [`check_manifest`] for one manifest.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The manifest content could not be parsed by its ecosystem's parser.
    #[error("failed to parse {path}: {source}")]
    Parse {
        /// The manifest path that failed to parse.
        path: PathBuf,
        /// The underlying parse error.
        #[source]
        source: deps_core::DepsError,
    },
    /// `manifest_path` could not be represented as a file URI (e.g. a malformed or
    /// non-representable path on this platform).
    #[error("could not build a file URI for {path}")]
    InvalidPath {
        /// The manifest path that could not be converted.
        path: PathBuf,
    },
}

/// The result of classifying one manifest.
#[derive(Debug, Clone)]
pub struct ManifestCheckResult {
    /// Every finding produced for this manifest.
    pub findings: Vec<CheckFinding>,
    /// Whether at least one dependency's registry fetch failed while not offline (FR-012) —
    /// the caller uses this to decide between exit 1 (policy violation over an otherwise
    /// complete report) and exit 2 (an incomplete report because a registry was
    /// unreachable).
    pub registry_unreachable: bool,
}

/// Classifies one already-routed manifest.
///
/// Parses it, resolves in-use/lockfile versions, fetches latest registry versions, runs an
/// OSV scan (when enabled and not offline), and calls the ecosystem's own
/// `generate_diagnostics` — then converts each returned [`Diagnostic`] into a
/// [`CheckFinding`].
///
/// Every verdict decision (outdated/yanked/vulnerable/unsatisfiable/deprecated/license) is
/// made by [`deps_engine::classify`] or by `generate_diagnostics` itself; this function only
/// assembles their inputs and converts their output (spec 062 FR-005).
///
/// # Errors
///
/// Returns [`CheckError::InvalidPath`] if `manifest_path` cannot be represented as a file
/// URI, or [`CheckError::Parse`] if `content` fails to parse as this ecosystem's manifest
/// format.
pub async fn check_manifest(
    ecosystem: &Arc<dyn Ecosystem>,
    manifest_path: &Path,
    display_path: &Path,
    content: &str,
    ctx: &CheckContext,
) -> Result<ManifestCheckResult, CheckError> {
    let uri = path_to_uri(manifest_path).ok_or_else(|| CheckError::InvalidPath {
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

    let (resolved_versions, resolved_version_candidates) =
        load_resolved_versions(&uri, &ctx.lockfile_cache, ecosystem.as_ref()).await;

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
    // `failed_count` (unlike `fetch_failed`) also counts not-found lookups — "the registry
    // answered 'no such package'" — which is not evidence of an unreachable registry (see
    // `FetchResult::failed_count`'s own doc). Using it here made any repo with one
    // private/unpublished/typo'd dependency name exit 2 on every non-offline run.
    let registry_unreachable = !ctx.policy.network.offline && !fetch_result.fetch_failed.is_empty();

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
    // Tier-1 license backfill (issue #660/#661 precedent, `deps-lsp/src/document/fetch.rs:206`):
    // populated for the native-list ecosystems (PyPI, Composer) whose registry response
    // already carries a license field; empty for every other ecosystem, same as `deps-lsp`.
    let licenses = fetch_result.licenses;

    let vulnerabilities: Option<VulnerabilityMap> =
        if ctx.policy.diagnostics.vulnerabilities_enabled && !ctx.policy.network.offline {
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
        };

    // TODO(critic): tier-3 license prefetch (spec 062 deviation #2) — tier-1 licenses now
    // threaded via fetch_result.licenses above; Dart/Swift/Gradle/Deno's dedicated-fetch
    // license source (`Ecosystem::fetch_license`) is still not called from this crate.
    let license_policy = ctx.policy.license_policy.to_policy();
    let mut version_data = VersionData::new(&cached_versions, &resolved_versions)
        .with_resolved_version_candidates(&resolved_version_candidates)
        .with_outcomes(&outcomes)
        .with_ecosystem(ecosystem_id)
        .with_offline(ctx.policy.network.offline)
        .with_license_source(ecosystem.license_source())
        .with_license_policy(&license_policy)
        .with_license_prefetch(&licenses);
    if let Some(vulnerabilities) = vulnerabilities.as_ref() {
        version_data = version_data.with_vulnerabilities(vulnerabilities);
    }

    let severities = ctx.policy.diagnostics.to_severities();
    let diagnostics = ecosystem
        .generate_diagnostics(
            parse_result.as_ref(),
            version_data,
            &uri,
            ctx.policy.freshness.to_settings(),
            severities,
        )
        .await;

    let dep_index = DependencyIndex::build(parse_result.as_ref());
    let advisory_severities = advisory_severity_index(vulnerabilities.as_ref());
    // The same per-occurrence key `vulnerabilities` was itself built under — `to_finding`
    // resolves each finding's own occurrence to this key before looking it up in
    // `advisory_severities`, so a shared advisory id across two different dependencies can
    // never resolve to the wrong one's severity (issue #1077 review #4).
    let vuln_keys = deps_core::osv::vulnerability_keys(
        parse_result.as_ref(),
        &resolved_versions,
        Some(&resolved_version_candidates),
        formatter,
        ecosystem_id,
    );
    let findings = diagnostics
        .into_iter()
        .map(|diagnostic| {
            to_finding(
                ecosystem_id,
                display_path,
                &dep_index,
                formatter,
                diagnostic,
                &advisory_severities,
                &vuln_keys,
            )
        })
        .collect();
    Ok(ManifestCheckResult {
        findings,
        registry_unreachable,
    })
}

/// Indexes every dependency occurrence by its name range and (separately) its version
/// range, so a diagnostic anchored at either can be traced back to the declaration that
/// produced it (see [`to_finding`]).
///
/// Two separate maps (M6, spec 062 review) rather than one shared `HashMap<Range, _>`: a
/// single map risks one dependency's name-range entry silently overwriting a *different*
/// dependency's version-range entry if the two ranges ever coincide, misattributing
/// `dependency_name`. Keeping the two lookups apart makes that impossible regardless of
/// range values, not just unlikely in practice.
struct DependencyIndex<'a> {
    by_name_range: HashMap<Range, &'a dyn Dependency>,
    by_version_range: HashMap<Range, &'a dyn Dependency>,
}

impl<'a> DependencyIndex<'a> {
    fn build(parse_result: &'a dyn deps_core::ParseResult) -> Self {
        let mut by_name_range = HashMap::new();
        let mut by_version_range = HashMap::new();
        for dep in parse_result.dependencies() {
            if !dep.name_range_is_synthetic() {
                by_name_range.insert(dep.name_range(), dep);
            }
            if let Some(version_range) = dep.version_range() {
                by_version_range.insert(version_range, dep);
            }
        }
        Self {
            by_name_range,
            by_version_range,
        }
    }

    /// Looks up the dependency a diagnostic's `range` is anchored to, preferring a
    /// name-range match (diagnostics anchored at `resolved.version_range` still resolve via
    /// the version-range map when no name-range entry matches the same coordinates).
    fn lookup(&self, range: Range) -> Option<&'a dyn Dependency> {
        self.by_name_range
            .get(&range)
            .or_else(|| self.by_version_range.get(&range))
            .copied()
    }
}

/// Indexes every advisory this manifest's OSV scan fetched, keyed by (the [`VulnerabilityMap`]
/// key identifying the specific dependency occurrence, advisory id) rather than by advisory id
/// alone (issue #1077 review #4), so [`to_finding`] can attach a
/// [`CheckFinding::advisory_severity`] without re-deriving a grade from the coarser
/// [`Severity`] a `Diagnostic` carries.
///
/// A bare `HashMap<String, VulnSeverity>` keyed only by advisory id would let one dependency's
/// severity silently overwrite another's (unspecified `HashMap` iteration order) whenever two
/// dependencies in this manifest shared an advisory id — OSV can legitimately report one id
/// against several different packages in the same record. [`to_finding`] looks its own
/// dependency occurrence's key up via [`deps_core::osv::vulnerability_keys`] — the same
/// function `vulnerabilities` itself was keyed under — so this can never drift out of sync
/// with how the scan actually mapped occurrences to results.
///
/// `None` `vulnerabilities` (scan disabled, or offline) yields an empty index, same as a
/// (key, id) pair this index has no entry for — both resolve to
/// `CheckFinding::advisory_severity: None`.
fn advisory_severity_index(
    vulnerabilities: Option<&VulnerabilityMap>,
) -> HashMap<(String, String), VulnSeverity> {
    let mut index = HashMap::new();
    let Some(vulnerabilities) = vulnerabilities else {
        return index;
    };
    for (dependency_key, outcome) in vulnerabilities {
        if let ScanOutcome::Vulnerable(dv) = outcome {
            for advisory in dv.advisories.items() {
                index.insert(
                    (dependency_key.clone(), advisory.id.clone()),
                    advisory.severity,
                );
            }
        }
    }
    index
}

/// Converts one `generate_diagnostics` [`Diagnostic`] into a [`CheckFinding`], classifying
/// its [`Category`] (see [`classify`]) and, when its range matches a manifest occurrence
/// (from [`DependencyIndex`]), its `dependency_name`/`requirement`. `advisory_severities` and
/// `vuln_keys` together resolve [`CheckFinding::advisory_severity`] — see
/// [`advisory_severity_index`].
fn to_finding(
    ecosystem: EcosystemId,
    display_path: &Path,
    dep_index: &DependencyIndex<'_>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    diagnostic: Diagnostic,
    advisory_severities: &HashMap<(String, String), VulnSeverity>,
    vuln_keys: &HashMap<Range, String>,
) -> CheckFinding {
    let category = classify(&diagnostic, formatter);
    let dep = dep_index.lookup(diagnostic.range);
    let code = diagnostic.code.clone();
    let advisory_url = diagnostic
        .code_description
        .as_ref()
        .map(|code_description| code_description.href.as_str().to_string());
    let advisory_severity = code.as_deref().zip(dep).and_then(|(code, dep)| {
        let dependency_key = vuln_keys.get(&dep.name_range())?;
        advisory_severities
            .get(&(dependency_key.clone(), code.to_string()))
            .copied()
    });
    CheckFinding {
        ecosystem,
        manifest_path: display_path.to_path_buf(),
        dependency_name: dep.map(|d| d.name().to_string()),
        requirement: dep
            .and_then(Dependency::version_requirement)
            .map(ToString::to_string),
        category,
        code,
        advisory_url,
        advisory_severity,
        severity: diagnostic.severity.unwrap_or(Severity::Warning),
        range: diagnostic.range,
        message: diagnostic.message,
    }
}

/// Classifies a `generate_diagnostics` [`Diagnostic`] into a [`Category`].
///
/// Diagnostics that carry one of the workspace's known non-advisory codes (the three
/// `deps-core` sentinels, the two mutable-ref-pin codes, or GitLab CI's
/// [`GITLAB_CI_UNRESOLVED_HOST_CODE`] notice) classify directly from `code`. A vulnerability
/// advisory id (an OSV id such as `RUSTSEC-...`/`GHSA-...`) is the only other free-form `code`
/// value `generate_diagnostics_from_cache` ever sets, so any `Some(code)` that matches none of
/// the known non-advisory codes classifies as [`Category::Vulnerable`] — this fallback is
/// sound only as long as the known-code list above stays exhaustive (see that list's own doc
/// for the regression this already caused once). An outdated diagnostic carries no code but
/// always starts with the fixed prefix `apply_outdated_rule` uses; a yanked diagnostic carries
/// no code either, but always contains `formatter.yanked_message()` verbatim — the same text
/// it was built from. The advisory-overflow summary line ("+N more advisories") also carries
/// no code but always ends with that fixed suffix, and is still [`Category::Vulnerable`].
/// Anything else (unknown-package, collapsed fetch-failure, blocked-registry,
/// offline/dependency-count notices) classifies as [`Category::Other`].
fn classify(
    diagnostic: &Diagnostic,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> Category {
    if let Some(code) = &diagnostic.code {
        return match code.as_str() {
            UNSATISFIABLE_DIAGNOSTIC_CODE => Category::Unsatisfiable,
            LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE => Category::License,
            DEPRECATED_DIAGNOSTIC_CODE => Category::Deprecated,
            GITHUB_ACTIONS_MUTABLE_REF_PIN_CODE | GITLAB_CI_MUTABLE_REF_PIN_CODE => {
                Category::MutableRefPin
            }
            GITLAB_CI_UNRESOLVED_HOST_CODE => Category::Other,
            _ => Category::Vulnerable,
        };
    }
    if diagnostic.message.starts_with("Newer version available") {
        return Category::Outdated;
    }
    if diagnostic.message.contains(formatter.yanked_message()) {
        return Category::Yanked;
    }
    // The advisory-overflow summary line (`push_vulnerability_diagnostics`,
    // `deps-core/src/lsp_helpers/diagnostics.rs:1829`) carries no code either, but is still a
    // vulnerability finding (M1, spec 062 review) — without this, a manifest whose advisory
    // count exceeds `ADVISORY_DISPLAY_CAP` reports its overflow summary as `Other`.
    if diagnostic.message.ends_with("more advisories") {
        return Category::Vulnerable;
    }
    Category::Other
}

/// Builds a file URI from a filesystem path, without any path-existence check. Returns
/// `None` when `path` cannot be represented as a file URI at all — `Url::from_file_path`
/// requires an absolute path (this function already joins a relative one onto the current
/// directory first) and, on Windows, a disk (`C:`) or UNC (`\\`) prefix; UNC paths
/// themselves are supported, just not any other Windows path prefix shape. The caller
/// surfaces a `None` here as [`CheckError::InvalidPath`] rather than fabricating a
/// synthetic, unusable URI.
fn path_to_uri(path: &Path) -> Option<url::Url> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    url::Url::from_file_path(&absolute).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: Category) -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from("Cargo.toml"),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            category,
            code: None,
            advisory_url: None,
            advisory_severity: None,
            severity: Severity::Warning,
            range: Range::default(),
            message: "test".to_string(),
        }
    }

    #[test]
    fn test_category_as_str_matches_fr009_tokens() {
        assert_eq!(Category::Outdated.as_str(), "outdated");
        assert_eq!(Category::Yanked.as_str(), "yanked");
        assert_eq!(Category::Vulnerable.as_str(), "vulnerable");
        assert_eq!(Category::Unsatisfiable.as_str(), "unsatisfiable");
        assert_eq!(Category::MutableRefPin.as_str(), "mutable-ref");
        assert_eq!(Category::License.as_str(), "license");
        assert_eq!(Category::Deprecated.as_str(), "deprecated");
        assert_eq!(Category::Other.as_str(), "other");
    }

    #[test]
    fn test_fail_on_policy_default_categories() {
        let policy = FailOnPolicy::default_categories();
        assert!(policy.matches(&[finding(Category::Vulnerable)]));
        assert!(policy.matches(&[finding(Category::Yanked)]));
        assert!(policy.matches(&[finding(Category::Unsatisfiable)]));
        assert!(!policy.matches(&[finding(Category::Outdated)]));
        assert!(!policy.matches(&[finding(Category::License)]));
        assert!(!policy.matches(&[finding(Category::Deprecated)]));
        assert!(!policy.matches(&[finding(Category::MutableRefPin)]));
        assert!(!policy.matches(&[finding(Category::Other)]));
    }

    #[test]
    fn test_fail_on_policy_custom_categories() {
        let policy = FailOnPolicy::new(vec![Category::License]);
        assert!(policy.matches(&[finding(Category::License)]));
        assert!(!policy.matches(&[finding(Category::Vulnerable)]));
    }

    #[test]
    fn test_fail_on_policy_empty_findings_never_matches() {
        assert!(!FailOnPolicy::default_categories().matches(&[]));
    }

    #[test]
    fn test_check_report_summary_counts_per_category() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Outdated),
                finding(Category::Outdated),
                finding(Category::Vulnerable),
            ],
        };
        let summary = report.summary();
        assert_eq!(summary.get(&Category::Outdated), Some(&2));
        assert_eq!(summary.get(&Category::Vulnerable), Some(&1));
        assert_eq!(summary.get(&Category::License), None);
    }

    #[test]
    fn test_check_report_summary_empty_for_no_findings() {
        let report = CheckReport::default();
        assert!(report.summary().is_empty());
    }

    struct StubFormatter;
    impl deps_core::lsp_helpers::PackageNaming for StubFormatter {}
    impl deps_core::lsp_helpers::PackageRendering for StubFormatter {
        fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.to_string()
        }
    }
    impl deps_core::lsp_helpers::RequirementResolution for StubFormatter {}
    impl deps_core::lsp_helpers::DiagnosticMessages for StubFormatter {}
    impl deps_core::lsp_helpers::DiagnosticPolicy for StubFormatter {}
    impl deps_core::lsp_helpers::SourcePolicy for StubFormatter {}
    impl deps_core::lsp_helpers::OsvNaming for StubFormatter {}

    fn diagnostic_with(code: Option<&str>, message: &str) -> Diagnostic {
        let diagnostic =
            Diagnostic::new(Range::default(), message).with_severity(Severity::Warning);
        match code {
            Some(code) => diagnostic.with_code(code),
            None => diagnostic,
        }
    }

    #[test]
    fn test_classify_unsatisfiable_by_code() {
        let d = diagnostic_with(Some(UNSATISFIABLE_DIAGNOSTIC_CODE), "no matching version");
        assert_eq!(classify(&d, &StubFormatter), Category::Unsatisfiable);
    }

    #[test]
    fn test_classify_license_by_code() {
        let d = diagnostic_with(
            Some(LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE),
            "GPL-3.0 denied",
        );
        assert_eq!(classify(&d, &StubFormatter), Category::License);
    }

    #[test]
    fn test_classify_deprecated_by_code() {
        let d = diagnostic_with(Some(DEPRECATED_DIAGNOSTIC_CODE), "package deprecated");
        assert_eq!(classify(&d, &StubFormatter), Category::Deprecated);
    }

    #[test]
    fn test_classify_mutable_ref_pin_by_code() {
        let d = diagnostic_with(Some(GITHUB_ACTIONS_MUTABLE_REF_PIN_CODE), "pinned to a tag");
        assert_eq!(classify(&d, &StubFormatter), Category::MutableRefPin);
        let d = diagnostic_with(Some(GITLAB_CI_MUTABLE_REF_PIN_CODE), "pinned to a tag");
        assert_eq!(classify(&d, &StubFormatter), Category::MutableRefPin);
    }

    #[test]
    fn test_classify_advisory_code_is_vulnerable() {
        let d = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");
        assert_eq!(classify(&d, &StubFormatter), Category::Vulnerable);
    }

    #[test]
    fn test_classify_outdated_by_message_prefix() {
        let d = diagnostic_with(None, "Newer version available: 2.0.0");
        assert_eq!(classify(&d, &StubFormatter), Category::Outdated);
    }

    #[test]
    fn test_classify_yanked_by_formatter_message() {
        let d = diagnostic_with(None, "This version has been yanked (1.0.0)");
        assert_eq!(classify(&d, &StubFormatter), Category::Yanked);
    }

    #[test]
    fn test_classify_unknown_package_is_other() {
        let d = diagnostic_with(None, "Unknown package 'left-pad'");
        assert_eq!(classify(&d, &StubFormatter), Category::Other);
    }

    /// Regression test for M1 (spec 062 review): the trailing "+N more advisories" overflow
    /// summary carries no code but is still a vulnerability finding, not `Other`.
    #[test]
    fn test_classify_advisory_overflow_summary_is_vulnerable() {
        let d = diagnostic_with(None, "+5 more advisories");
        assert_eq!(classify(&d, &StubFormatter), Category::Vulnerable);
    }

    /// Regression test for C3 (spec 062 review): GitLab CI's `unresolved-gitlab-host` notice
    /// is informational (INFORMATION severity, never a vulnerability) and must not fall
    /// through to the advisory-id fallback.
    #[test]
    fn test_classify_gitlab_unresolved_host_is_other_not_vulnerable() {
        let d = diagnostic_with(
            Some(GITLAB_CI_UNRESOLVED_HOST_CODE),
            "registries.gitlab_instance_host is unset; skipping component/project host resolution",
        );
        assert_eq!(classify(&d, &StubFormatter), Category::Other);
    }

    /// A single-dependency parse result whose one dependency ("dep-0") sits at
    /// `Range::default()` (`deps_core::test_util::StubDependency::name_range` always
    /// returns it) — matching `diagnostic_with`'s own hardcoded `range: Range::default()`
    /// (both the same `deps_core::position::Range` `DependencyIndex` is keyed on), so
    /// `DependencyIndex::lookup` resolves it for tests that need a real, non-`None`
    /// dependency occurrence.
    fn dep_index_with_one_dependency() -> Box<dyn deps_core::ParseResult> {
        deps_core::test_util::stub_parse_result_with_dependencies(1)
    }

    fn empty_dep_index() -> Box<dyn deps_core::ParseResult> {
        deps_core::test_util::stub_parse_result_with_dependencies(0)
    }

    /// Regression test (issue #1077 tester must-fix #2): every other SARIF test hand-builds a
    /// `CheckFinding` with `code` pre-set, bypassing the real `Diagnostic.code ->
    /// CheckFinding.code` extraction this covers.
    #[test]
    fn test_to_finding_extracts_string_code_from_diagnostic() {
        let parse_result = empty_dep_index();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");
        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(finding.code.as_deref(), Some("RUSTSEC-2024-0001"));
    }

    #[test]
    fn test_to_finding_code_is_none_without_a_diagnostic_code() {
        let parse_result = empty_dep_index();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(None, "Newer version available: 2.0.0");
        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(finding.code.is_none());
    }

    #[test]
    fn test_to_finding_extracts_advisory_url_from_code_description() {
        let parse_result = empty_dep_index();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let href: url::Url = "https://osv.dev/vulnerability/RUSTSEC-2024-0001"
            .parse()
            .expect("valid URL");
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary")
            .with_code_description(deps_core::diagnostic::CodeDescription::new(href));
        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(
            finding.advisory_url.as_deref(),
            Some("https://osv.dev/vulnerability/RUSTSEC-2024-0001")
        );
    }

    #[test]
    fn test_to_finding_advisory_url_is_none_without_code_description() {
        let parse_result = empty_dep_index();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");
        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(finding.advisory_url.is_none());
    }

    #[test]
    fn test_to_finding_resolves_advisory_severity_from_index() {
        let parse_result = dep_index_with_one_dependency();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");

        let mut vuln_keys = HashMap::new();
        vuln_keys.insert(Range::default(), "dep-0".to_string());
        let mut severities = HashMap::new();
        severities.insert(
            ("dep-0".to_string(), "RUSTSEC-2024-0001".to_string()),
            VulnSeverity::Critical,
        );

        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &severities,
            &vuln_keys,
        );
        assert_eq!(finding.advisory_severity, Some(VulnSeverity::Critical));
    }

    #[test]
    fn test_to_finding_advisory_severity_is_none_for_an_unindexed_code() {
        let parse_result = dep_index_with_one_dependency();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");
        let mut vuln_keys = HashMap::new();
        vuln_keys.insert(Range::default(), "dep-0".to_string());

        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &HashMap::new(),
            &vuln_keys,
        );
        assert!(finding.advisory_severity.is_none());
    }

    /// Regression test for issue #1077 review #4: no matching dependency occurrence at all
    /// (an empty `dep_index`/`vuln_keys`, e.g. a document-level diagnostic) must resolve to
    /// `None`, not panic.
    #[test]
    fn test_to_finding_advisory_severity_is_none_without_a_matched_dependency() {
        let parse_result = empty_dep_index();
        let dep_index = DependencyIndex::build(parse_result.as_ref());
        let diagnostic = diagnostic_with(Some("RUSTSEC-2024-0001"), "advisory summary");
        let mut severities = HashMap::new();
        severities.insert(
            ("dep-0".to_string(), "RUSTSEC-2024-0001".to_string()),
            VulnSeverity::Critical,
        );

        let finding = to_finding(
            EcosystemId::Cargo,
            Path::new("Cargo.toml"),
            &dep_index,
            &StubFormatter,
            diagnostic,
            &severities,
            &HashMap::new(),
        );
        assert!(finding.advisory_severity.is_none());
    }

    #[test]
    fn test_advisory_severity_index_collects_from_vulnerable_outcomes() {
        use deps_core::osv::{Advisory, Capped, DependencyVulnerabilities};
        use std::sync::Arc;

        let advisory = Advisory::new(
            "RUSTSEC-2024-0001".to_string(),
            "2024-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
            "https://osv.dev/vulnerability/RUSTSEC-2024-0001".to_string(),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![Arc::new(advisory)], 1));
        let mut map: VulnerabilityMap = HashMap::new();
        map.insert("serde".to_string(), ScanOutcome::Vulnerable(dv));

        let index = advisory_severity_index(Some(&map));
        assert_eq!(
            index.get(&("serde".to_string(), "RUSTSEC-2024-0001".to_string())),
            Some(&VulnSeverity::High)
        );
    }

    /// Regression test for issue #1077 review #4: two different dependencies whose OSV
    /// records legitimately share one advisory id must not let one silently overwrite the
    /// other's severity bucket.
    #[test]
    fn test_advisory_severity_index_does_not_collide_across_dependencies_sharing_an_advisory_id() {
        use deps_core::osv::{Advisory, Capped, DependencyVulnerabilities};
        use std::sync::Arc;

        let advisory_for = |severity: VulnSeverity| {
            Arc::new(Advisory::new(
                "GHSA-shared-id".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                severity,
                "https://osv.dev/vulnerability/GHSA-shared-id".to_string(),
            ))
        };
        let mut map: VulnerabilityMap = HashMap::new();
        map.insert(
            "package-a".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities::new(Capped::new(
                vec![advisory_for(VulnSeverity::Critical)],
                1,
            ))),
        );
        map.insert(
            "package-b".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities::new(Capped::new(
                vec![advisory_for(VulnSeverity::Low)],
                1,
            ))),
        );

        let index = advisory_severity_index(Some(&map));
        assert_eq!(
            index.get(&("package-a".to_string(), "GHSA-shared-id".to_string())),
            Some(&VulnSeverity::Critical)
        );
        assert_eq!(
            index.get(&("package-b".to_string(), "GHSA-shared-id".to_string())),
            Some(&VulnSeverity::Low)
        );
    }

    #[test]
    fn test_advisory_severity_index_empty_without_vulnerabilities() {
        assert!(advisory_severity_index(None).is_empty());
    }
}
