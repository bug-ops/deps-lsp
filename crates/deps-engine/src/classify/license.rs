//! Tier-3 license pre-fetch fan-out: adapter-agnostic dispatch to
//! [`deps_core::Ecosystem::fetch_license`] (issue #660/#688/#697, spec 010 plan §1 tier 3).
//!
//! Today this covers pub.dev's `/score` endpoint (Dart), the GitHub repository API
//! (Swift), a Maven Central POM fetch (Gradle), and the JSR per-version API (Deno).
//!
//! Extracted from `deps-lsp`'s `document/osv_scan.rs::run_license_prefetch` (issue #1133) so
//! `deps-cli` reaches the same license-policy verdicts as `deps-lsp` for these four ecosystems,
//! instead of silently seeing no tier-3 license data at all. The orchestration around this
//! dispatch — spawning it concurrently with the registry fetch, joining it before a diagnostics
//! publish, the mid-flight staleness guard, and the additive `DocumentState::licenses` merge —
//! stays in `deps-lsp`, since it owns a document lifecycle this crate must not know about
//! (same split rationale as issue #1059).
//!
//! **Not universally off the critical path** (critic S1/M3 correction of this module's
//! original doc): `deps-lsp` only ever calls this from a background pre-fetch task, but
//! `deps-cli check` calls [`prefetch_tier3_licenses`] directly, concurrently with the OSV
//! scan, whenever a non-empty `license_policy` is configured — on that adapter it is on the
//! check gate's critical path. Callers own their own `concurrency`/timeout tradeoffs; see
//! [`fetch_tier3_licenses`]'s parameters.

use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::lsp_helpers::resolve_in_use_version;
use std::collections::HashMap;
use std::time::Duration;

/// Ceiling on the per-dependency tier-3 license fetch timeout, independent of the caller's
/// configured `fetch_timeout_secs`: the shared `reqwest` client behind `deps-lsp`'s
/// `HttpCache` already imposes its own client-wide 30s timeout, so a per-call timeout longer
/// than that would never actually bind.
const TIER3_LICENSE_PREFETCH_TIMEOUT_CEILING_SECS: u64 = 30;

/// Floor on the per-dependency tier-3 license fetch timeout, independent of the caller's
/// configured `fetch_timeout_secs` (issue #692 critic M2). `fetch_timeout_secs` is
/// user-configurable down to a minimum of 1s, but `deps_gradle::license::fetch_license_from`
/// may perform up to `deps_gradle::license::MAX_POM_FETCHES` **sequential** HTTPS round trips
/// inside the single timeout this budget bounds — a low `fetch_timeout_secs` would otherwise
/// silently starve exactly the parent-chained artifacts (e.g. Guava) issue #692 exists to
/// resolve. A deliberate accuracy-over-latency tradeoff for every caller, `deps-cli` included
/// (issue #1133 critic M3): a `deps-cli check --fetch-timeout-secs 1` run against an
/// unreachable Maven Central still waits out this floor per Gradle dependency (bounded by
/// `concurrency`, see [`fetch_tier3_licenses`]) rather than silently under-reporting Guava's
/// parent-chained license.
const TIER3_LICENSE_PREFETCH_TIMEOUT_FLOOR_SECS: u64 = 10;

/// Result of [`prefetch_tier3_licenses`]/[`fetch_tier3_licenses`].
///
/// # Examples
///
/// ```
/// use deps_engine::classify::license::TierThreeLicenseFetch;
/// use std::collections::HashMap;
///
/// let result = TierThreeLicenseFetch::new(HashMap::new(), 0);
/// assert!(result.licenses.is_empty());
/// assert_eq!(result.timed_out, 0);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierThreeLicenseFetch {
    /// The successfully fetched licenses, keyed by (already scheme-qualified where
    /// applicable, e.g. `jsr:@std/fs`) package name. A dependency absent from this map means
    /// either its fetch found no license, or it was skipped by [`tier3_license_targets`] —
    /// the two are indistinguishable here (see [`Self::timed_out`]'s doc for why only a
    /// timeout is ever observable as a distinct failure mode).
    pub licenses: HashMap<PackageName, Vec<String>>,
    /// How many per-dependency fetches were cut off by this function's own
    /// `tokio::time::timeout` (issue #1133 critic S1).
    ///
    /// A **partial**, best-effort "could this result be trusted" signal, not a full
    /// fetch-failure count: [`deps_core::Ecosystem::fetch_license`] returns a bare
    /// `Vec<String>` with no error channel, and every one of the four tier-3 implementations
    /// (Dart/Swift/Gradle/Deno) deliberately degrades a network error, a 404, or a GitHub
    /// rate limit to an empty `Vec` internally, before this function ever sees it — that
    /// class of failure is indistinguishable from "genuinely no license" and is *not*
    /// counted here. Only this function's own outer timeout firing is observable from
    /// outside the ecosystem crate's own implementation. Callers that need a
    /// "network-reachable" signal (e.g. `deps-cli`'s `registry_unreachable`/exit-code gate)
    /// should treat a non-zero count as at least one confirmed unreachable tier-3 source,
    /// while treating zero as "no *confirmed* failure" rather than "fully verified reachable".
    pub timed_out: usize,
}

impl TierThreeLicenseFetch {
    /// Constructs a result from its already-computed fields. `#[non_exhaustive]` blocks
    /// cross-crate struct-literal construction even with every field named, so a caller
    /// outside this crate (e.g. a `deps-lsp`/`deps-cli` unit test building a synthetic
    /// result) needs this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_engine::classify::license::TierThreeLicenseFetch;
    /// use std::collections::HashMap;
    ///
    /// let result = TierThreeLicenseFetch::new(HashMap::new(), 2);
    /// assert_eq!(result.timed_out, 2);
    /// ```
    #[must_use]
    pub const fn new(licenses: HashMap<PackageName, Vec<String>>, timed_out: usize) -> Self {
        Self {
            licenses,
            timed_out,
        }
    }
}

/// Builds the `(name, in-use version)` pairs [`prefetch_tier3_licenses`] should fetch a
/// license for.
///
/// The pure, network-free half of that function, split out so it is unit-testable without a
/// `dyn Ecosystem` (mirrors [`crate::classify::osv::build_scan_targets`]'s split of decision
/// logic from the network call).
///
/// Filters on
/// [`deps_core::lsp_helpers::SourcePolicy::source_is_public_registry_content`] (critic M3/S6
/// of the original `deps-lsp` implementation), the same stricter filter
/// [`crate::classify::osv::build_scan_targets`]'s OSV path already uses, not the looser
/// [`deps_core::lsp_helpers::SourcePolicy::can_resolve_source`]: a patched git/path fork is
/// resolvable but must never have its license misattributed to the upstream registry package
/// it forked from — the identical "is this really the same package" problem OSV's stricter
/// filter exists to solve.
///
/// Deduplicated by `(name, version)` pair (issue #1133 code-review finding #2, first
/// occurrence wins): a manifest declaring the same dependency under two sections (e.g.
/// Gradle's `implementation` and `testImplementation`) at the same in-use version must not
/// fetch its license twice — wasted work that undermines the exact rate-limit concern
/// (Swift's unauthenticated 60 req/h GitHub budget) this module elsewhere worries about. Two
/// occurrences of the same name at *different* in-use versions are kept as separate
/// targets, since Gradle's POM fetch and Deno's JSR API are genuinely version-specific (see
/// [`prefetch_tier3_licenses`]'s doc) — deduplicating those would silently drop a
/// legitimately different lookup, mirroring the main registry fetch's own
/// name-not-name+version dedup being *wrong* for this per-version-fetch shape.
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
/// use deps_engine::classify::license::tier3_license_targets;
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
/// let parsed = stub_parse_result_with_dependencies(1);
/// let mut resolved_versions = HashMap::new();
/// resolved_versions.insert(PackageName::new("dep-0"), ConcreteVersion::from("1.0.0"));
///
/// let targets = tier3_license_targets(
///     parsed.as_ref(),
///     &resolved_versions,
///     &HashMap::new(),
///     &SimpleFormatter,
///     EcosystemId::Dart,
/// );
///
/// assert_eq!(targets, vec![(PackageName::new("dep-0"), "1.0.0".to_string())]);
/// ```
pub fn tier3_license_targets(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem_id: EcosystemId,
) -> Vec<(PackageName, String)> {
    let mut seen = std::collections::HashSet::new();
    parse_result
        .dependencies()
        .into_iter()
        .filter(|d| formatter.source_is_public_registry_content(&d.source()))
        .filter_map(|d| {
            let normalized = formatter.normalize_package_name(d.name());
            let version = resolve_in_use_version(
                d,
                normalized.as_str(),
                resolved_versions,
                Some(resolved_version_candidates),
                formatter,
                ecosystem_id,
            )?;
            Some((d.name().clone(), version))
        })
        .filter(|target| seen.insert(target.clone()))
        .collect()
}

/// Fetches every eligible dependency's tier-3 license, for whichever ecosystems override
/// [`deps_core::Ecosystem::fetch_license`].
///
/// A no-op (returns an empty result immediately) for every other ecosystem, via
/// <code>ecosystem.[license_source](Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// (issue #697) — and likewise a no-op whenever `license_policy` is
/// [`empty`](deps_core::LicensePolicy::is_empty) (issue #1133 code-review finding #3): the
/// only consumer of this result is a license-policy evaluation, so an empty policy means
/// nothing would ever read it. Enforced *inside* this function, not left to each caller to
/// re-derive, so a future second caller cannot forget the check and silently pay N network
/// round trips for a result nothing consumes.
///
/// Target selection (which dependencies to fetch, at which version) is
/// [`tier3_license_targets`] — see that function's doc for the filtering rules. The network
/// dispatch itself is [`fetch_tier3_licenses`] — see that function's doc for
/// `concurrency`/timeout semantics and [`TierThreeLicenseFetch::timed_out`]'s doc for what
/// failure modes are (and are not) observable in the result.
///
/// **What version each source actually reflects is per-ecosystem, not uniform:** Gradle's POM
/// fetch and Deno's JSR API are genuinely version-specific (fetched at the dependency's
/// resolved/in-use version, the `version` passed into [`Ecosystem::fetch_license`]). Dart's
/// `fetch_license` calls pub.dev's per-*package* `/score` endpoint, which carries no version
/// parameter at all — it reflects pana's detection on whatever pub.dev last scored, not
/// necessarily the resolved version. Swift's `fetch_license` calls GitHub's
/// `GET /repos/{owner}/{repo}`, which reflects the repository's *default branch*, not the
/// resolved version's tag. [`resolve_in_use_version`] (inside [`tier3_license_targets`]) is
/// still required as a *gate* for all four (no version resolved means nothing to look up), but
/// for Dart/Swift it does not pin which version's license is actually returned.
///
/// # Examples
///
/// ```
/// use deps_core::{HttpCache, LicensePolicy};
/// use deps_engine::classify::license::prefetch_tier3_licenses;
/// use deps_engine::setup::CargoEcosystem;
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     // Cargo's `license_source()` is the default `RegistryDeclaredSpdx`, whose
///     // `requires_dedicated_fetch()` is `false` — this returns immediately, with no
///     // parsed manifest and no network call, mirroring every non-tier-3 ecosystem.
///     let ecosystem = CargoEcosystem::new(Arc::new(HttpCache::new()));
///     let parsed = deps_core::test_util::stub_parse_result_with_dependencies(1);
///     let license_policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
///
///     let result = prefetch_tier3_licenses(
///         &ecosystem,
///         parsed.as_ref(),
///         &HashMap::new(),
///         &HashMap::new(),
///         &license_policy,
///         10,
///         4,
///     )
///     .await;
///
///     assert!(result.licenses.is_empty());
/// }
/// ```
pub async fn prefetch_tier3_licenses(
    ecosystem: &dyn Ecosystem,
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    license_policy: &deps_core::LicensePolicy,
    fetch_timeout_secs: u64,
    concurrency: usize,
) -> TierThreeLicenseFetch {
    if license_policy.is_empty() || !ecosystem.license_source().requires_dedicated_fetch() {
        return TierThreeLicenseFetch::default();
    }

    let targets = tier3_license_targets(
        parse_result,
        resolved_versions,
        resolved_version_candidates,
        ecosystem.formatter(),
        ecosystem.ecosystem_id(),
    );

    fetch_tier3_licenses(ecosystem, targets, fetch_timeout_secs, concurrency).await
}

/// The network-dispatch half of [`prefetch_tier3_licenses`].
///
/// Split out so a caller that must not hold a document lock guard across an `.await`
/// (`deps-lsp`'s `run_license_prefetch`) can compute [`tier3_license_targets`] synchronously
/// while the guard is held, drop the guard, and only then call this function with the
/// already-owned target list — mirroring [`crate::classify::osv::build_scan_targets`] (sync,
/// guard-scoped) versus `OsvClient::scan` (async, called after the guard drops).
///
/// `fetch_timeout_secs` is clamped to `TIER3_LICENSE_PREFETCH_TIMEOUT_FLOOR_SECS..=
/// TIER3_LICENSE_PREFETCH_TIMEOUT_CEILING_SECS` (private constants; see their doc comments in
/// this module's source) independently of the caller's own timeout semantics.
///
/// `concurrency` (clamped to at least 1, mirroring `fetch_latest_versions_parallel`'s
/// `buffer_unordered(0)`-hangs-forever defense, issue #833) bounds how many per-dependency
/// fetches run at once — deliberately a caller-supplied parameter, not a hardcoded default
/// (issue #1133 critic M3): `deps-lsp`'s background pre-fetch and `deps-cli`'s check-gate
/// call have different latency budgets and no single constant serves both well.
///
/// Does **not** check
/// <code>ecosystem.[license_source](Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// itself — callers that skip [`prefetch_tier3_licenses`]'s convenience wrapper are expected
/// to have already gated on it (as `run_license_prefetch` does) before ever computing
/// `targets`, the same way `run_osv_scan_phase_a` gates on `vulnerabilities_enabled` before
/// calling `build_scan_targets`.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_engine::classify::license::fetch_tier3_licenses;
/// use deps_engine::test_util::TestTier3Ecosystem;
///
/// #[tokio::main]
/// async fn main() {
///     let ecosystem = TestTier3Ecosystem::returning(vec!["MIT".to_string()]);
///     let targets = vec![(PackageName::new("pkg"), "1.0.0".to_string())];
///
///     let result = fetch_tier3_licenses(&ecosystem, targets, 10, 4).await;
///
///     assert_eq!(
///         result.licenses.get(&PackageName::new("pkg")),
///         Some(&vec!["MIT".to_string()])
///     );
/// }
/// ```
pub async fn fetch_tier3_licenses(
    ecosystem: &dyn Ecosystem,
    targets: Vec<(PackageName, String)>,
    fetch_timeout_secs: u64,
    concurrency: usize,
) -> TierThreeLicenseFetch {
    use futures::stream::{self, StreamExt};

    if targets.is_empty() {
        return TierThreeLicenseFetch::default();
    }

    let timeout_duration = Duration::from_secs(fetch_timeout_secs.clamp(
        TIER3_LICENSE_PREFETCH_TIMEOUT_FLOOR_SECS,
        TIER3_LICENSE_PREFETCH_TIMEOUT_CEILING_SECS,
    ));

    // Each future owns its own `(name, found, timed_out)` result independently (code-review
    // finding #4) — no shared `Arc<AtomicUsize>`/`Ordering` needed just to count timeouts
    // across `buffer_unordered`'s concurrent futures; summing after `.collect()` is simpler
    // with no correctness difference.
    let results: Vec<(PackageName, Vec<String>, bool)> = stream::iter(targets)
        .map(|(name, version)| async move {
            let mut timed_out = false;
            let found = tokio::time::timeout(
                timeout_duration,
                ecosystem.fetch_license(name.as_str(), &version),
            )
            .await
            .unwrap_or_else(|_| {
                timed_out = true;
                tracing::debug!(package = %name.for_tracing(), "tier-3 license fetch timed out");
                Vec::new()
            });
            (name, found, timed_out)
        })
        // `.max(1)`: same defense as `fetch_latest_versions_parallel` (#833) — a caller
        // passing `0` must not hang this fetch forever.
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut licenses = HashMap::with_capacity(results.len());
    let mut timed_out_count = 0usize;
    for (name, found, timed_out) in results {
        if timed_out {
            timed_out_count += 1;
        }
        if !found.is_empty() {
            licenses.insert(name, found);
        }
    }

    TierThreeLicenseFetch::new(licenses, timed_out_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestTier3Ecosystem;
    use deps_core::Dependency;
    use deps_core::VersionReq;
    use deps_core::lsp_helpers::{
        DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
        RequirementResolution, SourcePolicy,
    };
    use deps_core::parser::DependencySource;
    use deps_core::position::{Position, Range};
    use std::any::Any;
    use std::sync::Arc;

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
            // Distinct per instance, mirroring `osv.rs`'s `MockDep` (`vulnerability_keys`
            // keys a `HashMap<Range, String>` by `name_range()`).
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
            URI.get_or_init(|| deps_core::test_util::test_uri("/test/pubspec.yaml"))
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn dep(name: &str, version_req: &str, source: DependencySource) -> MockDep {
        MockDep {
            name: PackageName::new(name),
            version_req: Some(VersionReq::new(version_req)),
            source,
        }
    }

    #[test]
    fn tier3_license_targets_includes_public_registry_dep_with_resolved_version() {
        let parse_result = MockParseResult {
            deps: vec![dep("collection", "^1.0", DependencySource::Registry)],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("collection"), "1.18.0".into());

        let targets = tier3_license_targets(
            &parse_result,
            &resolved,
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Dart,
        );

        assert_eq!(
            targets,
            vec![(PackageName::new("collection"), "1.18.0".to_string())]
        );
    }

    #[test]
    fn tier3_license_targets_excludes_non_public_registry_source() {
        // A patched git/path fork must never have its license misattributed to the
        // upstream registry package it forked from.
        let parse_result = MockParseResult {
            deps: vec![dep(
                "local-fork",
                "1.0.0",
                DependencySource::Path {
                    path: "../local-fork".to_string(),
                },
            )],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("local-fork"), "1.0.0".into());

        let targets = tier3_license_targets(
            &parse_result,
            &resolved,
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Dart,
        );

        assert!(targets.is_empty());
    }

    #[test]
    fn tier3_license_targets_excludes_dep_with_no_resolvable_in_use_version() {
        let parse_result = MockParseResult {
            deps: vec![dep("collection", "^1.0", DependencySource::Registry)],
        };

        let targets = tier3_license_targets(
            &parse_result,
            &HashMap::new(),
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Dart,
        );

        assert!(targets.is_empty());
    }

    #[test]
    fn tier3_license_targets_never_drops_multiple_eligible_deps() {
        let parse_result = MockParseResult {
            deps: vec![
                dep("collection", "1.18.0", DependencySource::Registry),
                dep("path", "1.9.0", DependencySource::Registry),
            ],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("collection"), "1.18.0".into());
        resolved.insert(PackageName::new("path"), "1.9.0".into());

        let targets = tier3_license_targets(
            &parse_result,
            &resolved,
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Dart,
        );

        assert_eq!(targets.len(), 2);
    }

    /// Issue #1133 code-review finding #2: two occurrences of the same name at the same
    /// in-use version (e.g. Gradle's `implementation` + `testImplementation`) must collapse
    /// into one target, not fetch the same package+version's license twice.
    #[test]
    fn tier3_license_targets_dedups_same_name_and_version() {
        let parse_result = MockParseResult {
            deps: vec![
                dep("okhttp", "4.12.0", DependencySource::Registry),
                dep("okhttp", "4.12.0", DependencySource::Registry),
            ],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("okhttp"), "4.12.0".into());

        let targets = tier3_license_targets(
            &parse_result,
            &resolved,
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Gradle,
        );

        assert_eq!(
            targets,
            vec![(PackageName::new("okhttp"), "4.12.0".to_string())]
        );
    }

    /// The other half of finding #2: two occurrences of the same name at *different*
    /// in-use versions must both survive — deduplicating by name alone (rather than
    /// name+version) would silently drop a legitimately different lookup.
    #[test]
    fn tier3_license_targets_keeps_same_name_at_different_versions() {
        let parse_result = MockParseResult {
            deps: vec![
                dep("okhttp", "4.12.0", DependencySource::Registry),
                dep("okhttp", "4.11.0", DependencySource::Registry),
            ],
        };

        let targets = tier3_license_targets(
            &parse_result,
            &HashMap::new(),
            &HashMap::new(),
            &MockFormatter,
            EcosystemId::Gradle,
        );

        assert_eq!(
            targets,
            vec![
                (PackageName::new("okhttp"), "4.12.0".to_string()),
                (PackageName::new("okhttp"), "4.11.0".to_string()),
            ]
        );
    }

    fn non_empty_license_policy() -> deps_core::LicensePolicy {
        deps_core::LicensePolicy::new(vec!["MIT".to_string()], vec![])
    }

    #[tokio::test]
    async fn prefetch_tier3_licenses_returns_empty_without_network_when_no_targets() {
        let ecosystem = TestTier3Ecosystem::returning(vec!["MIT".to_string()]);
        let parse_result = MockParseResult { deps: vec![] };

        let result = prefetch_tier3_licenses(
            &ecosystem,
            &parse_result,
            &HashMap::new(),
            &HashMap::new(),
            &non_empty_license_policy(),
            10,
            4,
        )
        .await;

        assert!(result.licenses.is_empty());
        assert_eq!(result.timed_out, 0);
    }

    /// Issue #1133 code-review finding #3: the empty-policy short-circuit must be enforced
    /// *inside* `prefetch_tier3_licenses`, not left to the caller — a
    /// `TestTier3Ecosystem::pending()` would hang this test forever if the gate didn't
    /// short-circuit before ever calling `fetch_license`.
    #[tokio::test]
    async fn prefetch_tier3_licenses_no_op_for_empty_license_policy() {
        let ecosystem = TestTier3Ecosystem::pending();
        let parse_result = MockParseResult {
            deps: vec![dep("collection", "1.18.0", DependencySource::Registry)],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("collection"), "1.18.0".into());

        let result = prefetch_tier3_licenses(
            &ecosystem,
            &parse_result,
            &resolved,
            &HashMap::new(),
            &deps_core::LicensePolicy::default(),
            10,
            4,
        )
        .await;

        assert!(result.licenses.is_empty());
    }

    /// Ecosystem gate (issue #697): a non-tier-3 `license_source()` must short-circuit before
    /// `tier3_license_targets` is even called — asserted indirectly here by never invoking
    /// `fetch_license` (a `TestTier3Ecosystem::pending()` would hang the test forever if the
    /// gate didn't short-circuit; this test's timeout would fail loudly instead).
    #[tokio::test]
    async fn prefetch_tier3_licenses_no_op_for_non_tier3_ecosystem() {
        struct NonTier3(TestTier3Ecosystem);
        impl deps_core::ecosystem::private::Sealed for NonTier3 {}
        impl Ecosystem for NonTier3 {
            fn ecosystem_id(&self) -> EcosystemId {
                self.0.ecosystem_id()
            }
            fn display_name(&self) -> &'static str {
                self.0.display_name()
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                self.0.manifest_filenames()
            }
            fn parse_manifest<'a>(
                &'a self,
                content: &'a str,
                uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Box<dyn deps_core::ParseResult>>,
            > {
                self.0.parse_manifest(content, uri)
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                self.0.registry()
            }
            fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter {
                self.0.formatter()
            }
            fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
                self.0.completion_insert_text(metadata)
            }
            #[cfg(feature = "lsp-responses")]
            fn complete_version<'a>(
                &'a self,
                request: deps_core::completion::CompletionRequest<'a>,
                package_name: PackageName,
                prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                self.0.complete_version(request, package_name, prefix)
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
            // `license_source()` and `fetch_license` deliberately keep the trait's own
            // defaults (`RegistryDeclaredSpdx` / unreachable no-op) — this type exists only
            // to prove the gate, not to override them.
        }

        let ecosystem = NonTier3(TestTier3Ecosystem::pending());
        let parse_result = MockParseResult {
            deps: vec![dep("serde", "1.0.0", DependencySource::Registry)],
        };
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("serde"), "1.0.0".into());

        let result = prefetch_tier3_licenses(
            &ecosystem,
            &parse_result,
            &resolved,
            &HashMap::new(),
            &non_empty_license_policy(),
            10,
            4,
        )
        .await;

        assert!(result.licenses.is_empty());
    }

    #[tokio::test]
    async fn fetch_tier3_licenses_filters_out_empty_results() {
        let ecosystem = TestTier3Ecosystem::returning(vec![]);
        let targets = vec![(PackageName::new("no-license-found"), "1.0.0".to_string())];

        let result = fetch_tier3_licenses(&ecosystem, targets, 10, 4).await;

        assert!(
            result.licenses.is_empty(),
            "an empty fetch_license result must not appear in the map: {:?}",
            result.licenses
        );
        assert_eq!(result.timed_out, 0);
    }

    #[tokio::test]
    async fn fetch_tier3_licenses_dispatches_and_keeps_non_empty_results() {
        let ecosystem = TestTier3Ecosystem::returning(vec!["Apache-2.0".to_string()]);
        let targets = vec![(PackageName::new("pkg"), "2.0.0".to_string())];

        let result = fetch_tier3_licenses(&ecosystem, targets, 10, 4).await;

        assert_eq!(
            result.licenses.get(&PackageName::new("pkg")),
            Some(&vec!["Apache-2.0".to_string()])
        );
        assert_eq!(result.timed_out, 0);
    }

    /// Issue #1133 critic S1: the one failure mode this module *can* observe — its own
    /// outer timeout firing — must be counted in `timed_out` and must not itself panic or
    /// hang, even though the per-dependency `fetch_license` future never resolves.
    ///
    /// Uses `start_paused` virtual time (not a real sleep) so this test proves the *clamp*
    /// fired, not just that some timeout eventually did: advancing only 5 virtual seconds for
    /// a `fetch_timeout_secs` of 1 must **not** yet resolve the future (proving the 1s
    /// requested timeout was raised to the 10s floor, not used verbatim), while advancing
    /// past 10s does.
    #[tokio::test(start_paused = true)]
    async fn fetch_tier3_licenses_timeout_is_clamped_to_floor_and_counted() {
        let ecosystem = TestTier3Ecosystem::pending();
        let targets = vec![(PackageName::new("unreachable-pkg"), "1.0.0".to_string())];

        let mut fut = Box::pin(fetch_tier3_licenses(&ecosystem, targets, 1, 4));

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(
            futures::poll!(&mut fut).is_pending(),
            "a 1s requested timeout must have been clamped up to the 10s floor, not fired at 5s"
        );

        tokio::time::advance(Duration::from_secs(6)).await;
        let result = fut.await;

        assert!(result.licenses.is_empty());
        assert_eq!(result.timed_out, 1);
    }

    /// Proves `concurrency` is actually threaded through to `buffer_unordered`, not just
    /// documented (issue #1133 critic M3) — 10 targets with `concurrency = 3` must never
    /// observe more than 3 in flight at once.
    #[tokio::test]
    async fn fetch_tier3_licenses_respects_concurrency_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ConcurrencyTrackingEcosystem {
            current: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
        }
        impl deps_core::ecosystem::private::Sealed for ConcurrencyTrackingEcosystem {}
        impl Ecosystem for ConcurrencyTrackingEcosystem {
            fn ecosystem_id(&self) -> EcosystemId {
                EcosystemId::Dart
            }
            fn display_name(&self) -> &'static str {
                "concurrency-tracking"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &[]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Box<dyn deps_core::ParseResult>>,
            > {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                Arc::new(crate::test_util::StubRegistry)
            }
            fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter {
                &crate::test_util::StubFormatter
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                None
            }
            #[cfg(feature = "lsp-responses")]
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move { deps_core::completion::Completions::default() })
            }
            fn fetch_license<'a>(
                &'a self,
                _name: &'a str,
                _version: &'a str,
            ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
                let current = Arc::clone(&self.current);
                let max_seen = Arc::clone(&self.max_seen);
                Box::pin(async move {
                    let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    current.fetch_sub(1, Ordering::SeqCst);
                    vec!["MIT".to_string()]
                })
            }
            fn license_source(&self) -> deps_core::LicenseSource {
                deps_core::LicenseSource::DetectedSpdx
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let ecosystem = ConcurrencyTrackingEcosystem {
            current: Arc::clone(&current),
            max_seen: Arc::clone(&max_seen),
        };
        let targets: Vec<_> = (0..10)
            .map(|i| (PackageName::new(format!("pkg-{i}")), "1.0.0".to_string()))
            .collect();

        fetch_tier3_licenses(&ecosystem, targets, 10, 3).await;

        assert!(
            max_seen.load(Ordering::SeqCst) <= 3,
            "concurrency limit of 3 was violated: {} concurrent fetches observed",
            max_seen.load(Ordering::SeqCst)
        );
    }
}
