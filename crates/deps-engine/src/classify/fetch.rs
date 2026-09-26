//! Registry fetch fan-out: concurrent version fetching and per-package classification.
//!
//! Pure classification helpers extracted from `deps-lsp`'s `document/fetch.rs`: resolving each
//! dependency occurrence to a fetchable source, fetching and classifying a single package's
//! latest/yanked/deprecated/license status, and fanning that out concurrently across a
//! manifest's dependencies. The orchestration around these decisions — marking a document
//! loading, opening an LSP progress notification, and reacting to a mid-flight document edit —
//! stays in `deps-lsp`'s `fetch_registry_versions_for_change`, since it owns state this crate
//! must not know about (issue #1059).

use crate::progress::ProgressSender;
use deps_core::ConcreteVersion;
use deps_core::Deprecation;
use deps_core::FetchFailure;
use deps_core::PackageName;
use deps_core::PackageVersions;
use deps_core::Registry;
use deps_core::RemovalStatus;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// A dependency name paired with the resolved source to route its registry fetch through
/// (spec FR-001), as built by [`dedup_dependencies_by_source`].
pub type DepSources = Vec<(PackageName, deps_core::parser::DependencySource)>;

/// Pairs each distinct dependency name in `parse_result` with the source its occurrence(s)
/// resolve to.
///
/// For the background registry fetch to route through
/// `Registry::get_versions_from`/`get_latest_matching_from` (spec FR-001).
///
/// Two gates, applied in order:
///
/// 1. **Resolvability** (closes a review-flagged leak): a dependency whose source is not
///    resolvable at all (`!formatter.can_resolve_source(source)` — Git, Path, an unresolved
///    `CustomRegistry` alias, ...) is dropped from the result entirely, never reaching the
///    fetch. Without this gate, `CargoRegistry`'s (and every other source-aware registry's)
///    `_ =>` default-to-crates.io arm would silently look up a private/unresolvable name
///    against the ecosystem's *public* registry — exactly the leak this feature's own
///    hover/code-actions/diagnostics gating was built to close, just reached through the
///    highest-traffic path (the background fetch feeding inlay hints and cached
///    diagnostics) instead.
/// 2. **Collision** (spec FR-011): when two occurrences of the same name both resolve
///    (gate 1 passed for both) to two *different* sources — e.g. a genuine resolution bug
///    producing two distinct index URLs for what should be one registry — both are dropped
///    from the map and the name is added to the returned collision set instead of being
///    fetched. The fetch result is shared across every occurrence of a name
///    (`FetchResult::versions` is name-keyed), so silently picking a source here would
///    silently apply it to occurrences whose author may have intended a different
///    registry. A `tracing::warn!` names both resolved sources, using message text
///    distinguishable from `deps-cargo`'s own FR-003 unresolved-alias warning.
///
/// Returns `(sources, collided)`: `sources` is ready to fetch as-is; `collided` must be
/// merged into `DocumentState::signals.outcomes`' fetch-failure channel by the caller so
/// `generate_diagnostics_from_cache` reports "lookup could not be determined" rather than
/// a false "Unknown package" for a dependency that was never actually queried.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::test_util::stub_parse_result_with_dependencies;
/// use deps_core::{ConcreteVersion, PackageName};
/// use deps_engine::classify::fetch::dedup_dependencies_by_source;
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
/// let parsed = stub_parse_result_with_dependencies(2);
/// let (sources, collided) = dedup_dependencies_by_source(parsed.as_ref(), &SimpleFormatter);
///
/// assert_eq!(sources.len(), 2, "both distinct names resolve, no collision");
/// assert!(collided.is_empty());
/// ```
pub fn dedup_dependencies_by_source(
    parse_result: &dyn deps_core::ParseResult,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    HashMap<PackageName, deps_core::parser::DependencySource>,
    HashSet<PackageName>,
) {
    use std::collections::hash_map::Entry;

    let mut by_name: HashMap<PackageName, deps_core::parser::DependencySource> = HashMap::new();
    let mut collided: HashSet<PackageName> = HashSet::new();

    for dep in parse_result
        .dependencies()
        .into_iter()
        .filter(|dep| formatter.can_resolve_source(&dep.source()))
    {
        let name = dep.name().clone();
        let source = dep.source();
        match by_name.entry(name.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(source);
            }
            Entry::Occupied(entry) => {
                if *entry.get() != source && collided.insert(name.clone()) {
                    tracing::warn!(
                        package = %name.for_tracing(),
                        source_a = ?entry.get(),
                        source_b = ?source,
                        "dependency declared against two different resolved registries; \
                         skipping version resolution for all occurrences"
                    );
                }
            }
        }
    }

    for name in &collided {
        by_name.remove(name);
    }
    (by_name, collided)
}

/// Inputs [`fetch_latest_versions_parallel`] needs, derived from a parsed manifest.
///
/// Which sources to fetch (deduped, collision-free — see [`dedup_dependencies_by_source`]), each
/// dependency's currently in-use version(s), and the manifest's own
/// [`deps_core::SelectionContext`] (e.g. Composer's `minimum-stability`, #1433).
///
/// Built by [`prepare_fetch`], which consolidates three independently hand-rolled copies of
/// this exact dedup -> in-use -> selection-context sequence (`deps-lsp`'s
/// `document/lifecycle.rs` and `document/fetch.rs`, `deps-cli`'s `analyze.rs`) so the LSP and
/// CLI fetch-preparation paths can no longer drift apart (#1433).
#[non_exhaustive]
pub struct FetchPreparation {
    /// Ready to hand to [`fetch_latest_versions_parallel`] as-is, or filtered further by a
    /// caller that only wants to fetch a subset (e.g. `deps-lsp`'s
    /// `fetch_registry_versions_for_change`, which fetches only added/version-changed
    /// dependencies).
    pub dep_sources: DepSources,
    /// `dep_name -> [in_use_version, ...]`, from [`crate::classify::resolved::collect_in_use_versions`].
    pub in_use: HashMap<PackageName, Vec<String>>,
    /// The manifest's own [`deps_core::SelectionContext`], from
    /// [`deps_core::ParseResult::selection_context`].
    pub selection_context: deps_core::SelectionContext,
    /// Names dropped by [`dedup_dependencies_by_source`]'s collision gate — must be merged
    /// into `DocumentState::signals.outcomes`' fetch-failure channel by the caller (spec FR-011).
    pub collided_names: HashSet<PackageName>,
}

/// Builds a [`FetchPreparation`] from a parsed manifest and its resolved lock-file state.
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
/// use deps_engine::classify::fetch::prepare_fetch;
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
/// let parsed = stub_parse_result_with_dependencies(2);
/// let prep = prepare_fetch(
///     parsed.as_ref(),
///     &SimpleFormatter,
///     EcosystemId::Cargo,
///     &HashMap::new(),
///     &HashMap::new(),
/// );
///
/// assert_eq!(prep.dep_sources.len(), 2);
/// assert!(prep.selection_context.minimum_stability().is_none());
/// ```
pub fn prepare_fetch(
    parse_result: &dyn deps_core::ParseResult,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: deps_core::EcosystemId,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
) -> FetchPreparation {
    let (sources_map, collided_names) = dedup_dependencies_by_source(parse_result, formatter);
    let dep_sources: DepSources = sources_map.into_iter().collect();
    let in_use = crate::classify::resolved::collect_in_use_versions(
        parse_result,
        resolved_versions,
        resolved_version_candidates,
        formatter,
        ecosystem,
    );
    FetchPreparation {
        dep_sources,
        in_use,
        selection_context: parse_result.selection_context(),
        collided_names,
    }
}

/// Result of parallel version fetching.
#[non_exhaustive]
pub struct FetchResult {
    /// Successfully fetched versions (package -> latest + full version list)
    pub versions: HashMap<PackageName, PackageVersions>,
    /// Yanked-version findings, keyed by **raw** package name (unlike
    /// `DocumentState::signals.outcomes`, which is normalized-keyed — see
    /// §3.1 of the design), to (the version string found yanked, its
    /// `RemovalStatus`). The status rides alongside so #205's package-level
    /// deprecation diagnostic can gate its yanked-check suppression on
    /// `AdvisoryDeprecated` specifically, never a genuine `Yanked` finding.
    /// Callers must re-key through `EcosystemFormatter::normalize_package_name`
    /// before merging into document state.
    pub yanked_versions: HashMap<PackageName, (ConcreteVersion, RemovalStatus)>,
    /// Package-level deprecation findings (issue #205), keyed by **raw** package name
    /// (same raw/normalized split as `yanked_versions` above). Derived from the
    /// `resolved`/"latest" pick in the fetch loop below, not by scanning the full
    /// `versions` list — see that loop's comments for why.
    pub deprecations: HashMap<PackageName, Deprecation>,
    /// Packages whose registry fetch errored or timed out, keyed by **raw**
    /// package name (same raw/normalized split as `yanked_versions` above).
    /// Lets diagnostic generation (#267) distinguish "the registry said this
    /// package doesn't exist" from "the registry couldn't be asked" instead
    /// of conflating both into a misleading "Unknown package" diagnostic.
    pub fetch_failed: HashMap<PackageName, FetchFailure>,
    /// Packages whose registry fetch succeeded but produced zero comparable versions
    /// (#550), keyed by **raw** package name (same raw/normalized split as
    /// `yanked_versions` above). Distinct from `fetch_failed`: the registry was
    /// successfully asked and the package demonstrably exists — it just has nothing a
    /// version-comparison rule can use — so `generate_diagnostics_from_cache` must
    /// report neither "Registry lookup failed" nor "Unknown package" for it.
    pub no_comparable_versions: HashSet<PackageName>,
    /// Number of packages whose registry fetch did not succeed, counting both a genuine
    /// fetch failure (timeout, error — recorded in `fetch_failed` above) and a not-found
    /// lookup (the registry answered "no such package", never recorded in `fetch_failed`,
    /// see #267 C1). Only the `fetch_failed` subset produces an inline "Registry lookup
    /// failed" diagnostic, so this count can exceed `fetch_failed.len()` (#276 S2, #490).
    pub failed_count: usize,
    /// First actionable error message (shown to user via `window/showMessage`)
    pub first_error: Option<String>,
    /// SPDX license identifier(s) for the resolved/"latest" pick, for every package
    /// whose `Version::license` on the already-fetched version-list entry is
    /// non-empty (issue #660/#661 tier-1 backfill) — today, only the native-list
    /// ecosystems (PyPI, Composer) ever populate this; every other ecosystem's
    /// `Version::license` default is empty, so this map stays empty for them.
    /// Deliberately *not* threaded into [`PackageVersions`] itself (that type is
    /// constructed identically across ~40 call sites throughout the workspace,
    /// including files outside this crate's ownership for this change) —
    /// `merge_registry_fetch_result` merges this map directly into
    /// `deps-lsp`'s `DocumentState::signals.licenses` instead, the same map the tier-3
    /// background pre-fetch (`run_license_prefetch`) already populates for
    /// Dart/Swift/Gradle/Deno. A merge (not replace), since the two sources are
    /// always disjoint per document (one ecosystem per document) but run as
    /// independent, non-ordered background tasks.
    pub licenses: HashMap<PackageName, Vec<String>>,
}

impl FetchResult {
    /// Constructs a `FetchResult` from its already-computed fields.
    ///
    /// `#[non_exhaustive]` blocks cross-crate struct-literal construction even with every
    /// field named, so a caller outside `deps-engine` (e.g. a `deps-lsp` unit test building a
    /// synthetic fetch outcome) needs this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_engine::classify::fetch::FetchResult;
    /// use std::collections::{HashMap, HashSet};
    ///
    /// let result = FetchResult::new(
    ///     HashMap::new(),
    ///     HashMap::new(),
    ///     HashMap::new(),
    ///     HashMap::new(),
    ///     HashSet::new(),
    ///     0,
    ///     None,
    ///     HashMap::new(),
    /// );
    /// assert_eq!(result.failed_count, 0);
    /// ```
    ///
    /// Parameters, in declaration order (see each field's own doc above for the full
    /// rationale — this is a quick cross-check against accidental transposition, several
    /// share the same `HashMap<PackageName, _>`/`HashSet<PackageName>` shape):
    /// `versions` (successful fetches), `yanked_versions` (yank findings),
    /// `deprecations` (package-level deprecation findings), `fetch_failed` (errored/timed-out
    /// packages), `no_comparable_versions` (fetched clean but nothing to compare),
    /// `failed_count`, `first_error`, `licenses`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        versions: HashMap<PackageName, PackageVersions>,
        yanked_versions: HashMap<PackageName, (ConcreteVersion, RemovalStatus)>,
        deprecations: HashMap<PackageName, Deprecation>,
        fetch_failed: HashMap<PackageName, FetchFailure>,
        no_comparable_versions: HashSet<PackageName>,
        failed_count: usize,
        first_error: Option<String>,
        licenses: HashMap<PackageName, Vec<String>>,
    ) -> Self {
        Self {
            versions,
            yanked_versions,
            deprecations,
            fetch_failed,
            no_comparable_versions,
            failed_count,
            first_error,
            licenses,
        }
    }
}

/// Fetches latest versions for multiple packages in parallel with progress reporting.
///
/// Returns a [`FetchResult`] containing successfully fetched versions and failure count.
/// Packages that fail to fetch are omitted from the versions map.
///
/// This function executes all registry requests concurrently with per-dependency
/// timeout isolation, preventing slow packages from blocking others.
///
/// Alongside the primary fetch, checks whether the in-use version of a
/// dependency has been yanked (#233), for registries that [report yank
/// data](Registry::reports_yanked). Unlike the original design, this is not
/// a second registry round trip: `registry.get_versions` below already
/// fetches the full, unfiltered version list once per package (see
/// [`PackageVersions`]), so the in-use-version check is a zero-cost
/// in-memory search over a list already in hand, run for every dependency
/// with a known in-use version rather than only when it differs from
/// `latest`.
///
/// # Arguments
///
/// * `registry` - Package registry to fetch from
/// * `package_names` - List of package names to fetch
/// * `in_use` - Raw dependency name -> the version(s) this project actually
///   has (lockfile-resolved or a concrete pin) for every occurrence of that
///   name in the manifest, checked against the fetched version list for
///   yank status
/// * `progress` - Optional progress tracker (will be updated after each fetch)
/// * `timeout_secs` - Timeout for each individual package fetch (default: 10s)
/// * `max_concurrent` - Maximum concurrent fetches (default: 20); clamped to `>= 1`
///   internally, since `buffer_unordered(0)` would hang forever (issue #833)
///
/// # Timeout Behavior
///
/// Each package fetch is wrapped in an individual timeout. If a package
/// takes longer than `timeout_secs` to fetch, it fails fast with a warning
/// and does NOT block other packages.
///
/// # Performance
///
/// With 50 dependencies and 100ms per request:
/// - Sequential: 50 × 100ms = 5000ms
/// - Parallel (no timeout): max(100ms) ≈ 150ms
/// - Parallel (10s timeout, 1 slow package at 30s): max(10s) ≈ 10s
///
/// # Examples
///
/// ```
/// use deps_core::parser::DependencySource;
/// use deps_core::{
///     ConcreteVersion, Metadata, PackageName, Registry, SelectionContext, Version, VersionReq,
/// };
/// use deps_engine::classify::fetch::fetch_latest_versions_parallel;
/// use std::any::Any;
/// use std::collections::HashMap;
/// use std::sync::Arc;
///
/// struct SingleVersionRegistry;
///
/// #[derive(Clone)]
/// struct SimpleVersion {
///     version: ConcreteVersion,
/// }
/// impl Version for SimpleVersion {
///     fn version_string(&self) -> &ConcreteVersion {
///         &self.version
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// impl Registry for SingleVersionRegistry {
///     fn get_versions<'a>(
///         &'a self,
///         _name: &'a PackageName,
///     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>> {
///         Box::pin(async move {
///             Ok(vec![Box::new(SimpleVersion { version: "1.0.0".into() }) as Box<dyn Version>])
///         })
///     }
///
///     // The default `select_latest_matching` always returns `None` (every real registry
///     // overrides it with ecosystem-specific comparison), so `fetch_and_classify_package`
///     // falls back to this method for its pick.
///     fn get_latest_matching<'a>(
///         &'a self,
///         _name: &'a PackageName,
///         _req: &'a VersionReq,
///         _selection_context: &'a SelectionContext,
///     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>> {
///         Box::pin(async move {
///             Ok(Some(Box::new(SimpleVersion { version: "1.0.0".into() }) as Box<dyn Version>))
///         })
///     }
///
///     fn search_raw<'a>(
///         &'a self,
///         _query: &'a str,
///         _limit: usize,
///     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>> {
///         Box::pin(async move { Ok(vec![]) })
///     }
///
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let sources = vec![(PackageName::new("time"), DependencySource::Registry)];
///
///     let result = fetch_latest_versions_parallel(
///         Arc::new(SingleVersionRegistry),
///         sources,
///         &HashMap::new(),
///         None,
///         deps_core::freshness::FreshnessSettings::default(),
///         5,
///         10,
///         &SelectionContext::none(),
///     )
///     .await;
///
///     assert_eq!(
///         result.versions.get(&PackageName::new("time")).map(|v| v.latest.to_string()),
///         Some("1.0.0".to_string())
///     );
/// }
/// ```
#[allow(
    clippy::too_many_arguments,
    reason = "internal (non-pub) call-site-controlled fetch tuning + ecosystem-context \
              parameters; grouping into a config struct would only move, not reduce, the \
              per-call-site churn across this module's ~15 production and test call sites"
)]
pub async fn fetch_latest_versions_parallel(
    registry: Arc<dyn Registry>,
    package_sources: DepSources,
    in_use: &HashMap<PackageName, Vec<String>>,
    progress_sender: Option<ProgressSender>,
    freshness: deps_core::freshness::FreshnessSettings,
    timeout_secs: u64,
    max_concurrent: usize,
    selection_context: &deps_core::SelectionContext,
) -> FetchResult {
    use futures::stream::{self, StreamExt};
    use std::time::Duration;

    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    // Separate from `first_error` (#480): not-found errors are excluded from
    // `fetch_failed`, but without this a fast not-found could still win the `first_error`
    // completion race over a slower, more actionable failure (e.g. a rate limit hit by
    // 20 other dependencies). Any `fetch_failed`-counted error always wins the toast over
    // a not-found regardless of finishing order; a not-found-only batch falls back to
    // `first_error`.
    //
    // Derived by folding each task's own `(name, message)` return value in completion
    // order (see the loop below) rather than written from inside the match arms via a
    // shared `Arc<Mutex>` like `first_error` — keeps `fetch_failed` and the priority error
    // in sync by construction instead of via two independently hand-maintained writes (#480).
    let timeout = Duration::from_secs(timeout_secs);
    let wildcard_req = deps_core::VersionReq::new("*");
    let check_yanked = registry.reports_yanked();

    let results: Vec<_> = stream::iter(package_sources)
        .map(|(name, source)| {
            let registry = Arc::clone(&registry);
            let fetched = Arc::clone(&fetched);
            let failed = Arc::clone(&failed);
            let first_error = Arc::clone(&first_error);
            let progress_sender = progress_sender.clone();
            let wildcard_req = &wildcard_req;
            let in_use_versions = in_use.get(&name).cloned().unwrap_or_default();
            async move {
                fetch_and_classify_package(
                    registry.as_ref(),
                    name,
                    source,
                    in_use_versions,
                    wildcard_req,
                    freshness,
                    timeout,
                    selection_context,
                    check_yanked,
                    &fetched,
                    &failed,
                    &first_error,
                    progress_sender.as_ref(),
                )
                .await
            }
        })
        // `.max(1)`: defence-in-depth against a direct-field-assignment caller bypassing
        // `with_max_concurrent_fetches`'s clamp with `0` — `buffer_unordered(0)` never
        // polls its source stream, hanging every fetch through this document forever (#833).
        .buffer_unordered(max_concurrent.max(1))
        .collect()
        .await;

    let mut versions = HashMap::with_capacity(results.len());
    let mut yanked_versions = HashMap::new();
    let mut fetch_failed = HashMap::new();
    let mut deprecations = HashMap::new();
    let mut no_comparable_versions = HashSet::new();
    let mut licenses = HashMap::new();
    // First actionable failure in completion order — `results` is collected from
    // `buffer_unordered`, so its order already reflects real finishing order, the same
    // order a shared `Arc<Mutex>` written from inside each task would have observed.
    let mut priority_error: Option<String> = None;
    for (version, yanked, failed_name, deprecation, no_comparable_versions_name, license) in results
    {
        if let Some((name, v)) = version {
            versions.insert(name, v);
        }
        if let Some((name, v, status)) = yanked {
            yanked_versions.insert(name, (v, status));
        }
        if let Some((name, failure, message)) = failed_name {
            fetch_failed.insert(name, failure);
            if priority_error.is_none() {
                priority_error = Some(message);
            }
        }
        if let Some((name, d)) = deprecation {
            deprecations.insert(name, d);
        }
        if let Some(name) = no_comparable_versions_name {
            no_comparable_versions.insert(name);
        }
        if let Some((name, license)) = license {
            licenses.insert(name, license);
        }
    }

    // `priority_error` (an actual fetch failure — rate limit, timeout, outage, ...)
    // always wins the toast over `first_error` (which may be a not-found race winner);
    // `first_error` is the fallback only for a batch whose only failures were
    // not-found (#480).
    let error_message =
        priority_error.or_else(|| first_error.lock().unwrap_or_else(|p| p.into_inner()).take());

    FetchResult {
        versions,
        yanked_versions,
        fetch_failed,
        deprecations,
        no_comparable_versions,
        failed_count: failed.load(std::sync::atomic::Ordering::Relaxed),
        first_error: error_message,
        licenses,
    }
}

/// Per-package outcome returned by [`fetch_and_classify_package`]: the resolved
/// `(name, PackageVersions)` entry, a yanked finding, a fetch failure, a package-level
/// deprecation finding, a name whose fetch succeeded with no comparable versions
/// (#550), and the resolved/"latest" pick's license when the ecosystem's already-fetched
/// version-list entries carry it (issue #660/#661 tier-1 backfill — see
/// [`FetchResult::licenses`]) — folded into [`fetch_latest_versions_parallel`]'s
/// aggregate `FetchResult` once every package in the stream has finished.
///
/// The license entry specifically comes from `select_latest_matching`'s
/// pick below (critic S1: previously documented here as "the resolved version's
/// license", which is wrong — this function never reads `resolved_versions` at all, it
/// picks the latest version matching the requirement/stability floor, same as
/// `PackageVersions.latest`).
type PackageFetchOutcome = (
    Option<(PackageName, PackageVersions)>,
    Option<(PackageName, ConcreteVersion, RemovalStatus)>,
    Option<(PackageName, FetchFailure, String)>,
    Option<(PackageName, Deprecation)>,
    Option<PackageName>,
    Option<(PackageName, Vec<String>)>,
);

/// Fetches, classifies, and version-selects a single package within
/// [`fetch_latest_versions_parallel`]'s concurrent stream: one round trip for the full
/// version list, an in-memory "latest" pick with a `get_latest_matching_from` fallback
/// when the list-based pick fails on a non-empty list, yanked/deprecation extraction,
/// and updates to the shared `fetched`/`failed`/`first_error` counters the stream
/// aggregates across every package.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the per-package async closure this was extracted from — every \
              parameter is either call-site fetch tuning already threaded through \
              fetch_latest_versions_parallel or a counter/sender shared across the \
              whole stream; grouping into a struct would only move, not reduce, churn"
)]
async fn fetch_and_classify_package(
    registry: &dyn Registry,
    name: PackageName,
    source: deps_core::parser::DependencySource,
    in_use_versions: Vec<String>,
    wildcard_req: &VersionReq,
    freshness: deps_core::freshness::FreshnessSettings,
    timeout: Duration,
    selection_context: &deps_core::SelectionContext,
    check_yanked: bool,
    fetched: &std::sync::atomic::AtomicUsize,
    failed: &std::sync::atomic::AtomicUsize,
    first_error: &std::sync::Mutex<Option<String>>,
    progress_sender: Option<&ProgressSender>,
) -> PackageFetchOutcome {
    // Single round trip: the full version list is fetched once and "latest" is a pure
    // in-memory pick over it, no second registry call. `get_versions_from` (source-aware,
    // spec FR-001) over `get_versions`: populates `published_at` where supported (#339) and
    // routes a resolved `AlternateRegistry` source to its own index — zero extra cost
    // either way for registries with no override.
    let result = tokio::time::timeout(
        timeout,
        registry.get_versions_from(&name, &source, freshness),
    )
    .await;

    let mut yanked: Option<(PackageName, ConcreteVersion, RemovalStatus)> = None;
    let mut failed_name: Option<(PackageName, FetchFailure, String)> = None;
    let mut deprecation: Option<(PackageName, Deprecation)> = None;
    let mut license: Option<(PackageName, Vec<String>)> = None;
    // Set only when the fetch (and its `get_latest_matching` fallback) both
    // genuinely succeeded yet resolved to no version at all (#550) — see the
    // `Ok(Ok(None))` fallback arm below.
    let mut no_comparable_versions = false;
    let version = match result {
        Ok(Ok(versions)) => {
            let available: Arc<[ConcreteVersion]> = versions
                .iter()
                .map(|v| v.version_string().clone())
                .collect();
            // Retained alongside `available` so diagnostics can flag a requirement
            // satisfiable only by a yanked version (`PackageVersions::yanked`). Gated on
            // `check_yanked`: a registry unable to answer `removal_status()` (§#298) must
            // not populate this with an untrustworthy always-`Available` signal. Carries
            // each entry's `RemovalStatus` (#437) so #247's diagnostic path can gate
            // deprecation suppression on `AdvisoryDeprecated` specifically, not `Yanked`.
            let yanked_list: Arc<[(ConcreteVersion, RemovalStatus)]> = if check_yanked {
                versions
                    .iter()
                    .filter_map(|v| {
                        let status = v.removal_status();
                        status
                            .is_flagged()
                            .then(|| (v.version_string().clone(), status))
                    })
                    .collect()
            } else {
                Arc::from([])
            };
            // `.get(idx)` not `versions[idx]`: `select_latest_matching` is a public trait
            // method, so an out-of-tree impl returning a stale index must not panic this
            // task. `selection_context` is threaded through so a registry with
            // manifest-level stability state (Composer's `minimum-stability`, #424 S1) can
            // apply it.
            let resolved = if let Some(v) = registry
                .select_latest_matching(&versions, wildcard_req, selection_context)
                .and_then(|idx| versions.get(idx))
            {
                let latest = v.version_string().clone();
                tracing::debug!(package = %name.for_tracing(), version = %latest, "fetched");
                Some((
                    latest,
                    v.removal_status(),
                    v.published_at(),
                    v.deprecation().cloned(),
                    v.license().to_vec(),
                ))
            } else {
                // The list-based pick found nothing — usually a genuine "no version", but
                // a registry with an incomplete list endpoint (Go's `/@v/list`, which never
                // enumerates pseudo-versions) may need the more complete `get_latest_matching`
                // (Go's `/@latest`). Costs a second network call, only in this rare case.
                let fallback = tokio::time::timeout(
                    timeout,
                    registry.get_latest_matching_from(
                        &name,
                        &source,
                        wildcard_req,
                        selection_context,
                    ),
                )
                .await;
                match fallback {
                    Ok(Ok(Some(v))) => {
                        let latest = v.version_string().clone();
                        tracing::debug!(
                            package = %name.for_tracing(),
                            version = %latest,
                            "fetched via get_latest_matching fallback"
                        );
                        Some((
                            latest,
                            v.removal_status(),
                            v.published_at(),
                            v.deprecation().cloned(),
                            v.license().to_vec(),
                        ))
                    }
                    Ok(Ok(None)) => {
                        tracing::debug!(package = %name.for_tracing(), "no version found");
                        // Both the list-based pick and this fallback succeeded and found
                        // nothing — the package exists but has zero comparable versions
                        // (#550), e.g. tags that don't parse as full semver. Distinct from
                        // every branch below that sets `failed_name`.
                        no_comparable_versions = true;
                        None
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            package = %name.for_tracing(),
                            error = %e,
                            "fetch fallback failed"
                        );
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let mut fe = first_error.lock().unwrap_or_else(|p| p.into_inner());
                        if fe.is_none() {
                            *fe = Some(e.to_string());
                        }
                        drop(fe);
                        // A genuine not-found (the registry was
                        // successfully asked and said "no such
                        // package") is not a fetch failure — only
                        // an unanswerable request is (#267 C1).
                        if !e.is_not_found() {
                            failed_name = Some((name.clone(), e.fetch_failure(), e.to_string()));
                        }
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            package = %name.for_tracing(),
                            "fetch fallback timed out ({}s)",
                            timeout.as_secs()
                        );
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        failed_name = Some((
                            name.clone(),
                            FetchFailure::Transient,
                            format!(
                                "{}: registry request timed out after {}s",
                                name.for_tracing(),
                                timeout.as_secs()
                            ),
                        ));
                        None
                    }
                }
            };

            if check_yanked {
                // Row 1 (§4.7): the picked "latest" itself yanked — free, already in hand.
                // Unreachable in production under today's hardcoded wildcard, but stays
                // correct as a defense-in-depth check.
                if let Some((latest, status, _, _, _)) = &resolved
                    && status.is_flagged()
                {
                    yanked = Some((name.clone(), latest.clone(), *status));
                }

                // Row 2/3 (§4.7, revised under #206): `versions` is the full, already-fetched
                // list — no second registry round trip needed, so this runs for every
                // dependency with a known in-use version, not just when it differs from
                // `latest`. A yanked in-use version wins over an already-recorded yanked
                // `latest` since it's the version the user actually has.
                //
                // Multiple occurrences of the same name (#394, e.g. `[dependencies]` +
                // `[target.*.dependencies]`) can carry different in-use versions — every one
                // is checked so a yanked pin on any occurrence is never missed. Filters on
                // `is_flagged()` inside `find` itself (not a separate `.filter()`) so a
                // response with multiple entries sharing `iv`'s version string still finds a
                // flagged one if any exists (mirrors the pre-#205 `.any` scan).
                if let Some((iv, status)) = in_use_versions.iter().find_map(|iv| {
                    versions
                        .iter()
                        .find(|v| {
                            v.version_string() == iv.as_str() && v.removal_status().is_flagged()
                        })
                        .map(|v| (iv, v.removal_status()))
                }) {
                    yanked = Some((name.clone(), iv.as_str().into(), status));
                }
            }

            // #205: the deprecation finding is derived from `resolved` (already picked as
            // "latest"), covering the fallback branch too, whose `Version` isn't a member
            // of `versions` at all — see `FetchResult::deprecations`'s doc for why this
            // must not scan `versions` instead.
            if let Some((_, _, _, dep_info, _)) = &resolved
                && let Some(dep_info) = dep_info
            {
                deprecation = Some((name.clone(), dep_info.clone()));
            }

            // #660/#661 tier-1 backfill: extracted from `resolved` before `.map()` consumes
            // it. Filtered here so a `Some((name, vec![]))` entry — indistinguishable from
            // "no data" once merged into `DocumentState::signals.licenses` — never gets inserted.
            license = resolved
                .as_ref()
                .map(|(_, _, _, _, lic)| lic)
                .filter(|lic| !lic.is_empty())
                .map(|lic| (name.clone(), lic.clone()));

            resolved.map(|(latest, _, published_at, _, _)| {
                let mut versions = PackageVersions::new(latest, available).with_yanked(yanked_list);
                if let Some(published_at) = published_at {
                    versions = versions.with_published_at(published_at);
                }
                (name.clone(), versions)
            })
        }
        Ok(Err(e)) => {
            // Issue #483: while offline, every fetch fails by design — this
            // would otherwise log a per-dependency WARNING for every open/edit,
            // contradicting the toast suppression two call sites away in this
            // same file for being "unusable".
            if e.is_offline() {
                tracing::debug!(package = %name.for_tracing(), "fetch skipped: offline");
            } else {
                tracing::warn!(package = %name.for_tracing(), error = %e, "fetch failed");
            }
            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut fe = first_error.lock().unwrap_or_else(|p| p.into_inner());
            if fe.is_none() {
                *fe = Some(e.to_string());
            }
            drop(fe);
            // A genuine not-found is not a fetch failure — only an unanswerable request is
            // (#267 C1). Marking it here would report "Registry lookup failed" for a
            // typo'd name instead of "Unknown package", inverting the bug this fixes.
            if !e.is_not_found() {
                failed_name = Some((name.clone(), e.fetch_failure(), e.to_string()));
            }
            None
        }
        Err(_) => {
            tracing::warn!(package = %name.for_tracing(), "fetch timed out ({}s)", timeout.as_secs());
            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            failed_name = Some((
                name.clone(),
                FetchFailure::Transient,
                format!(
                    "{}: registry request timed out after {}s",
                    name.for_tracing(),
                    timeout.as_secs()
                ),
            ));
            None
        }
    };

    let count = fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if let Some(sender) = progress_sender {
        sender.send(count);
    }

    let no_comparable_versions_name = no_comparable_versions.then(|| name.clone());
    (
        version,
        yanked,
        failed_name,
        deprecation,
        no_comparable_versions_name,
        license,
    )
}

/// Re-keys a completed fetch's yanked/fetch-failure findings from raw to normalized package
/// names and applies them to `outcomes`.
///
/// Also records every collided name (two occurrences resolving to different sources,
/// [`dedup_dependencies_by_source`]) as not-attempted.
///
/// `set_fetch_failure_if_absent` (not `set_fetch_failure`) for `collided_names`: a collided
/// name normalizing to the same key as a genuine failure just recorded above must not
/// clobber it (impl-critic M2).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DependencyOutcomes, DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming,
///     PackageRendering, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::{ConcreteVersion, PackageName, RemovalStatus};
/// use deps_engine::classify::fetch::apply_fetch_outcomes;
/// use std::collections::{HashMap, HashSet};
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
/// let mut outcomes = DependencyOutcomes::new();
/// let mut yanked = HashMap::new();
/// yanked.insert(
///     PackageName::new("time"),
///     (ConcreteVersion::from("0.1.43"), RemovalStatus::Yanked),
/// );
///
/// apply_fetch_outcomes(
///     &mut outcomes,
///     yanked,
///     HashMap::new(),
///     HashSet::new(),
///     &SimpleFormatter,
/// );
///
/// assert_eq!(
///     outcomes.yanked("time").map(|(v, _)| v.to_string()),
///     Some("0.1.43".to_string())
/// );
/// ```
pub fn apply_fetch_outcomes(
    outcomes: &mut deps_core::lsp_helpers::DependencyOutcomes,
    yanked_versions: HashMap<PackageName, (ConcreteVersion, RemovalStatus)>,
    fetch_failed: HashMap<PackageName, FetchFailure>,
    collided_names: HashSet<PackageName>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    for (name, version) in yanked_versions {
        outcomes.set_yanked(formatter.normalize_package_name(&name), version);
    }
    for (name, failure) in fetch_failed {
        outcomes.set_fetch_failure(formatter.normalize_package_name(&name), failure);
    }
    for name in collided_names {
        outcomes.set_fetch_failure_if_absent(
            formatter.normalize_package_name(&name),
            FetchFailure::NotAttempted,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::SelectionContext;
    use deps_core::parser::DependencySource;

    /// Pairs every name with the plain `Registry` source — the shape every pre-existing
    /// `fetch_latest_versions_parallel` test used before that function became source-aware
    /// (spec FR-001). Production call sites build real `(name, source)` pairs from a
    /// parsed manifest via `dedup_dependencies_by_source` instead.
    fn with_registry_source(names: Vec<PackageName>) -> Vec<(PackageName, DependencySource)> {
        names
            .into_iter()
            .map(|name| (name, DependencySource::Registry))
            .collect()
    }

    #[cfg(feature = "cargo")]
    mod apply_fetch_outcomes_tests {
        use super::*;
        use crate::setup::CargoFormatter;
        use deps_core::lsp_helpers::DependencyOutcomes;

        #[test]
        fn apply_fetch_outcomes_sets_yanked_re_keyed_to_normalized_name() {
            let mut outcomes = DependencyOutcomes::new();
            let mut yanked_versions = HashMap::new();
            yanked_versions.insert(
                PackageName::new("time"),
                ("0.1.43".into(), RemovalStatus::Yanked),
            );

            apply_fetch_outcomes(
                &mut outcomes,
                yanked_versions,
                HashMap::new(),
                HashSet::new(),
                &CargoFormatter,
            );

            assert_eq!(
                outcomes.yanked("time"),
                Some(&("0.1.43".into(), RemovalStatus::Yanked))
            );
        }

        /// Loop order (yanked → fetch_failed → collided) and `set_fetch_failure_if_absent`
        /// (impl-critic M2): a collided name that normalizes to the same key as a genuine
        /// failure recorded just before it must not clobber that failure.
        #[test]
        fn apply_fetch_outcomes_collided_name_does_not_clobber_existing_fetch_failure() {
            let mut outcomes = DependencyOutcomes::new();
            let mut fetch_failed = HashMap::new();
            fetch_failed.insert(PackageName::new("serde"), FetchFailure::Transient);
            let mut collided_names = HashSet::new();
            collided_names.insert(PackageName::new("serde"));

            apply_fetch_outcomes(
                &mut outcomes,
                HashMap::new(),
                fetch_failed,
                collided_names,
                &CargoFormatter,
            );

            assert_eq!(
                outcomes.fetch_failure("serde"),
                Some(&FetchFailure::Transient),
                "a genuine fetch failure must survive a collided name normalizing to the same key"
            );
        }

        /// The other half of the precedence rule: a collided name with no pre-existing
        /// failure under its normalized key must still be recorded as not-attempted.
        #[test]
        fn apply_fetch_outcomes_collided_name_alone_is_recorded_as_not_attempted() {
            let mut outcomes = DependencyOutcomes::new();
            let mut collided_names = HashSet::new();
            collided_names.insert(PackageName::new("serde"));

            apply_fetch_outcomes(
                &mut outcomes,
                HashMap::new(),
                HashMap::new(),
                collided_names,
                &CargoFormatter,
            );

            assert_eq!(
                outcomes.fetch_failure("serde"),
                Some(&FetchFailure::NotAttempted)
            );
        }
    }

    mod dedup_by_source_collision_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::position::{Position, Range};
        use deps_core::test_util::StubFormatter;
        use std::any::Any;

        /// Treats both `Registry` and `AlternateRegistry` as resolvable, mirroring the real
        /// `CargoFormatter`'s own `resolves_alternate_registry` override — needed so two
        /// distinct source values can both pass gate 1 (resolvability) and reach gate 2
        /// (collision) in the same test.
        const ALTERNATE_AWARE_FORMATTER: StubFormatter =
            StubFormatter::new().with_alternate_registry_resolution();

        struct MockDep {
            name: PackageName,
            source: DependencySource,
            addr_tag: u32,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::new(
                    Position::new(0, self.addr_tag),
                    Position::new(0, self.addr_tag + 1),
                )
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

        #[test]
        fn test_two_different_resolvable_sources_collide_and_are_dropped() {
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::Registry,
                        addr_tag: 0,
                    },
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::AlternateRegistry {
                            index: "https://index.mycorp.dev".into(),
                            mirrors_crates_io: false,
                        },
                        addr_tag: 1,
                    },
                ],
            };

            let (sources, collided) =
                dedup_dependencies_by_source(&parse_result, &ALTERNATE_AWARE_FORMATTER);

            assert!(
                !sources.contains_key(&PackageName::new("shared-name")),
                "a colliding name must not be fetched under either source"
            );
            assert!(
                collided.contains(&PackageName::new("shared-name")),
                "the collision must be recorded so the caller can mark it fetch_failed"
            );
        }

        #[test]
        fn test_identical_sources_do_not_collide() {
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::Registry,
                        addr_tag: 0,
                    },
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::Registry,
                        addr_tag: 1,
                    },
                ],
            };

            let (sources, collided) =
                dedup_dependencies_by_source(&parse_result, &ALTERNATE_AWARE_FORMATTER);

            assert!(collided.is_empty());
            assert_eq!(
                sources.get(&PackageName::new("shared-name")),
                Some(&DependencySource::Registry)
            );
        }

        /// Gate 1 (Critical review finding #1): a non-resolvable source is dropped
        /// entirely, never reaching the fetch — this is what prevents a Git/Path
        /// dependency's name from being looked up against the ecosystem's default
        /// registry via the background fetch's routing default arm.
        #[test]
        fn test_non_resolvable_source_is_dropped_not_fetched() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("local-fork"),
                    source: DependencySource::Path {
                        path: "../local-fork".into(),
                    },
                    addr_tag: 0,
                }],
            };

            let (sources, collided) =
                dedup_dependencies_by_source(&parse_result, &ALTERNATE_AWARE_FORMATTER);

            assert!(sources.is_empty());
            assert!(collided.is_empty());
        }

        /// #935/#936 sink-level regression test, mirroring the repo's precedent for this bug
        /// class (`deps-cargo/src/parser.rs`'s `test_parse_registry_index_env_collision_...`
        /// tests, and cache.rs #756): pinning the type-level fix (`DependencySource`'s
        /// hand-written `Debug`) alone leaves the actual `tracing::warn!(?source, ...)` call
        /// site in this function untested. Two `AlternateRegistry` sources, each carrying a
        /// distinct query-string credential, collide — this is the exact `tracing::warn!`
        /// this module emits with `source_a`/`source_b` via `?` (Debug) formatting.
        #[test]
        fn test_collision_warning_redacts_credentials_in_alternate_registry_debug_output() {
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::AlternateRegistry {
                            index: "https://index-a.mycorp.dev/api?api_key=SECRET_A".into(),
                            mirrors_crates_io: false,
                        },
                        addr_tag: 0,
                    },
                    MockDep {
                        name: PackageName::new("shared-name"),
                        source: DependencySource::AlternateRegistry {
                            index: "https://index-b.mycorp.dev/api?api_key=SECRET_B".into(),
                            mirrors_crates_io: false,
                        },
                        addr_tag: 1,
                    },
                ],
            };

            let log = deps_core::test_util::capture_tracing_output(|| {
                let (sources, collided) =
                    dedup_dependencies_by_source(&parse_result, &ALTERNATE_AWARE_FORMATTER);
                assert!(!sources.contains_key(&PackageName::new("shared-name")));
                assert!(collided.contains(&PackageName::new("shared-name")));
            });

            assert!(
                log.contains("two different resolved registries"),
                "expected the collision WARN to fire: {log:?}"
            );
            assert!(
                !log.contains("SECRET_A") && !log.contains("SECRET_B"),
                "tracing output leaked a query-string credential: {log:?}"
            );
            assert!(
                log.contains("index-a.mycorp.dev") && log.contains("index-b.mycorp.dev"),
                "host should survive redaction: {log:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_with_timeout() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct TimeoutRegistry;

        impl Registry for TimeoutRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(TimeoutRegistry);
        let packages = vec![PackageName::new("slow-package")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty(), "Slow package should timeout");
        assert_eq!(result.failed_count, 1, "Should track 1 failed package");
        // #267: a timeout is also a fetch failure, not a "not found" — must
        // be recorded the same way as a hard registry error.
        assert_eq!(
            result.fetch_failed,
            HashMap::from([(PackageName::new("slow-package"), FetchFailure::Transient)]),
            "timed-out package must be recorded in fetch_failed"
        );
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_fast_packages_not_blocked() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct MixedRegistry;

        impl Registry for MixedRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    if name == "slow-package" {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    if name == "slow-package" {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Ok(None)
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(MixedRegistry);
        let packages = vec![
            PackageName::new("slow-package"),
            PackageName::new("fast-package"),
        ];

        let start = std::time::Instant::now();
        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            &SelectionContext::none(),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(3),
            "Should not wait for slow package: {:?}",
            elapsed
        );

        assert!(
            result.versions.is_empty(),
            "No versions returned (test registry returns empty)"
        );
        assert_eq!(
            result.failed_count, 1,
            "Slow package should be marked as failed"
        );
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_concurrency_limit() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        struct ConcurrencyTrackingRegistry {
            current: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
        }

        impl Registry for ConcurrencyTrackingRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
                    self.max_seen.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    self.current.fetch_sub(1, Ordering::SeqCst);

                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
                    self.max_seen.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    self.current.fetch_sub(1, Ordering::SeqCst);

                    Ok(None)
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let registry: Arc<dyn Registry> = Arc::new(ConcurrencyTrackingRegistry {
            current: Arc::clone(&current),
            max_seen: Arc::clone(&max_seen),
        });

        let packages: Vec<PackageName> = (0..50)
            .map(|i| PackageName::new(format!("package-{}", i)))
            .collect();

        fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            20,
            &SelectionContext::none(),
        )
        .await;

        // +2 margin for timing noise around the limit of 20.
        let max = max_seen.load(Ordering::SeqCst);
        assert!(
            max <= 22,
            "Concurrency limit violated: {} concurrent requests (limit: 20)",
            max
        );
    }

    /// Regression test for issue #833: `buffer_unordered(0)` never polls its source
    /// stream and returns `Pending` forever, so a `max_concurrent` of `0` reaching this
    /// call previously hung the fetch indefinitely instead of completing or erroring.
    /// Wrapped in a short outer timeout so a regression fails fast instead of hanging
    /// the test suite.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_zero_max_concurrent_still_completes() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct InstantRegistry;

        impl Registry for InstantRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(InstantRegistry);
        let packages = vec![PackageName::new("some-package")];

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetch_latest_versions_parallel(
                registry,
                with_registry_source(packages),
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                0,
                &SelectionContext::none(),
            ),
        )
        .await
        .expect("fetch with max_concurrent=0 must not hang forever");

        assert!(
            result
                .no_comparable_versions
                .contains(&PackageName::new("some-package")),
            "fetch must still run to completion when max_concurrent is 0"
        );
    }

    #[tokio::test]
    async fn test_fetch_partial_success_with_mixed_outcomes() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }

            fn is_prerelease(&self) -> bool {
                false
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MixedOutcomeRegistry;

        impl Registry for MixedOutcomeRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    match name.as_str() {
                        "package-fast" => Ok(vec![Box::new(MockVersion {
                            version: "1.0.0".into(),
                        }) as Box<dyn Version>]),
                        "package-slow" => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            Ok(vec![])
                        }
                        "package-error" => Err(deps_core::error::DepsError::CacheError(
                            "Mock registry error".to_string(),
                        )),
                        _ => Ok(vec![]),
                    }
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    match name.as_str() {
                        "package-fast" => Ok(Some(Box::new(MockVersion {
                            version: "1.0.0".into(),
                        }) as Box<dyn Version>)),
                        "package-slow" => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            Ok(None)
                        }
                        "package-error" => Err(deps_core::error::DepsError::CacheError(
                            "Mock registry error".to_string(),
                        )),
                        _ => Ok(None),
                    }
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                // The fetch loop derives "latest" from `get_versions` via this method, not
                // `get_latest_matching` — must override it (not rely on the `None` default)
                // to keep exercising "package-fast" as a successful fetch.
                if versions.is_empty() { None } else { Some(0) }
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(MixedOutcomeRegistry);
        let packages = vec![
            PackageName::new("package-fast"),
            PackageName::new("package-slow"),
            PackageName::new("package-error"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert_eq!(
            result.versions.len(),
            1,
            "Should have exactly 1 successful package"
        );
        assert_eq!(
            result
                .versions
                .get("package-fast")
                .map(|v| v.latest.as_str()),
            Some("1.0.0"),
            "Fast package should have correct version"
        );
        assert!(
            !result.versions.contains_key("package-slow"),
            "Slow package should not be in results (timeout)"
        );
        assert!(
            !result.versions.contains_key("package-error"),
            "Error package should not be in results"
        );
    }

    /// Issue #247: the per-version yanked flag from `get_versions` must survive into
    /// `PackageVersions.yanked`, not be discarded — this is what lets
    /// `generate_diagnostics_from_cache` (via `requirement_matches_only_yanked`) detect a
    /// requirement that is satisfiable only by a yanked version.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_carries_yanked_flag_into_cache() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
            yanked: bool,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn removal_status(&self) -> deps_core::RemovalStatus {
                deps_core::RemovalStatus::from_yanked(self.yanked)
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct YankedRegistry;

        impl Registry for YankedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockVersion {
                            version: "1.0.214".into(),
                            yanked: false,
                        }) as Box<dyn Version>,
                        Box::new(MockVersion {
                            version: "1.0.213".into(),
                            yanked: true,
                        }) as Box<dyn Version>,
                    ])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(YankedRegistry);
        let packages = vec![PackageName::new("serde")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::none(),
        )
        .await;

        let serde = result
            .versions
            .get("serde")
            .expect("serde should be fetched");
        assert_eq!(serde.latest, "1.0.214", "latest must skip the yanked entry");
        assert_eq!(
            &*serde.available,
            &[
                ConcreteVersion::new("1.0.214"),
                ConcreteVersion::new("1.0.213")
            ],
            "available must remain unfiltered"
        );
        assert_eq!(
            &*serde.yanked,
            &[(
                ConcreteVersion::new("1.0.213"),
                deps_core::RemovalStatus::Yanked
            )],
            "yanked must carry only the entries reported as yanked, paired with their status"
        );
    }

    /// Issue #227 C3: `PackageVersions.published_at` must be the publish time of
    /// `latest` specifically, not of some other entry in `available` — a risk the old
    /// two-parallel-map design (a separate `HashMap<String, PublishTime>` alongside the
    /// version map) could not structurally rule out. Bundling `published_at` onto the
    /// same struct as `latest`/`available`/`yanked` makes that desync impossible: both
    /// are set from the same `Box<dyn Version>` in the same match arm.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_carries_published_at_for_latest_only() {
        use deps_core::freshness::PublishTime;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
            yanked: bool,
            published_at: Option<PublishTime>,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn removal_status(&self) -> deps_core::RemovalStatus {
                deps_core::RemovalStatus::from_yanked(self.yanked)
            }
            fn published_at(&self) -> Option<PublishTime> {
                self.published_at
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct DatedRegistry;

        impl Registry for DatedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockVersion {
                            version: "1.0.214".into(),
                            yanked: false,
                            published_at: Some(PublishTime::from_unix_secs(2_000)),
                        }) as Box<dyn Version>,
                        Box::new(MockVersion {
                            version: "1.0.213".into(),
                            yanked: true,
                            // Deliberately a different timestamp — proves the fetch loop
                            // never accidentally attaches this entry's age to `latest`.
                            published_at: Some(PublishTime::from_unix_secs(1_000)),
                        }) as Box<dyn Version>,
                    ])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(DatedRegistry);
        let packages = vec![PackageName::new("serde")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::none(),
        )
        .await;

        let serde = result
            .versions
            .get("serde")
            .expect("serde should be fetched");
        assert_eq!(serde.latest, "1.0.214");
        assert_eq!(
            serde.published_at,
            Some(PublishTime::from_unix_secs(2_000)),
            "published_at must be 1.0.214's own timestamp, not the yanked 1.0.213 entry's"
        );
    }

    /// Issue #660/#661 tier-1 backfill: a `Version::license()` override on the
    /// already-fetched version-list entry (today, only Composer's `impl_version!`
    /// includes one — `deps-composer/src/types.rs`) must flow into
    /// `FetchResult::licenses`, keyed by package name — this is what
    /// `merge_registry_fetch_result` then merges into `DocumentState::signals.licenses`,
    /// letting #661's policy diagnostics see it without a second, ecosystem-specific
    /// fetch. An empty `license()` (every other ecosystem's default) must produce no
    /// entry at all, not an empty-vec one — `merge_licenses` relies on this to never
    /// accidentally overwrite real data with a spurious empty entry.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_carries_license_into_fetch_result() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
            license: Vec<String>,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
            fn license(&self) -> &[String] {
                &self.license
            }
        }

        struct LicensedRegistry;

        impl Registry for LicensedRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let license = if name.as_str() == "licensed-pkg" {
                    vec!["MIT".to_string()]
                } else {
                    vec![]
                };
                Box::pin(async move {
                    Ok(vec![Box::new(MockVersion {
                        version: "1.0.0".into(),
                        license,
                    }) as Box<dyn Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                (!versions.is_empty()).then_some(0)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(LicensedRegistry);
        let packages = vec![
            PackageName::new("licensed-pkg"),
            PackageName::new("unlicensed-pkg"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert_eq!(
            result.licenses.get(&PackageName::new("licensed-pkg")),
            Some(&vec!["MIT".to_string()])
        );
        assert!(
            !result
                .licenses
                .contains_key(&PackageName::new("unlicensed-pkg")),
            "an empty Version::license() must produce no entry, not an empty-vec one"
        );
    }

    /// #339 regression guard: the bulk diagnostics-cache-population pass must call the
    /// freshness-aware `Registry::get_versions_with`, not the freshness-blind `get_versions`,
    /// for a registry that implements the override — otherwise `published_at` (and the
    /// cooldown-context diagnostic message it drives) is silently always `None` in
    /// production even though hover's separate call path gets it right.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_uses_get_versions_with_for_freshness() {
        use deps_core::freshness::{FreshnessSettings, PublishTime};
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
            published_at: Option<PublishTime>,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn published_at(&self) -> Option<PublishTime> {
                self.published_at
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct FreshnessAwareRegistry;

        impl Registry for FreshnessAwareRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                // Deliberately returns no `published_at` — if the fetch loop ever calls
                // this instead of `get_versions_with`, the assertion below catches it.
                Box::pin(async move {
                    Ok(vec![Box::new(MockVersion {
                        version: "1.0.0".into(),
                        published_at: None,
                    }) as Box<dyn Version>])
                })
            }

            fn get_versions_with<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                freshness: FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockVersion {
                        version: "1.0.0".into(),
                        published_at: freshness
                            .enabled
                            .then(|| PublishTime::from_unix_secs(5_000)),
                    }) as Box<dyn Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                if versions.is_empty() { None } else { Some(0) }
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(FreshnessAwareRegistry);
        let packages = vec![PackageName::new("widget")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::none(),
        )
        .await;

        let widget = result
            .versions
            .get("widget")
            .expect("widget should be fetched");
        assert_eq!(
            widget.published_at,
            Some(PublishTime::from_unix_secs(5_000)),
            "published_at must come from get_versions_with, not the freshness-blind \
             get_versions (#339)"
        );
    }

    /// #424 S1: `fetch_latest_versions_parallel` must call `select_latest_matching` with the
    /// `minimum_stability` value it was given — otherwise a registry with manifest-level
    /// stability state (e.g. Composer's `minimum-stability`) never actually sees it, and
    /// #424's S1 fix stays unreachable dead code from the live LSP fetch path's perspective
    /// (critic S3/tester's reachability gap).
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_threads_minimum_stability_into_select_latest_matching()
     {
        use deps_core::{Metadata, Registry, StabilityFloor, Version};
        use std::any::Any;
        use std::sync::Mutex;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct ContextAwareRegistry {
            // Records every `minimum_stability` value observed, in call order — an empty
            // `Vec` after the fetch means `select_latest_matching` was never invoked.
            seen_minimum_stability: Mutex<Vec<Option<StabilityFloor>>>,
        }

        impl Registry for ContextAwareRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockVersion {
                        version: "1.0.0".into(),
                    }) as Box<dyn Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                selection_context: &SelectionContext,
            ) -> Option<usize> {
                self.seen_minimum_stability
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(selection_context.minimum_stability());
                if versions.is_empty() { None } else { Some(0) }
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry = Arc::new(ContextAwareRegistry {
            seen_minimum_stability: Mutex::new(Vec::new()),
        });
        let packages = vec![PackageName::new("vendor/pkg")];

        let result = fetch_latest_versions_parallel(
            Arc::clone(&registry) as Arc<dyn Registry>,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::with_minimum_stability(StabilityFloor::Beta),
        )
        .await;

        assert_eq!(
            *registry
                .seen_minimum_stability
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            vec![Some(StabilityFloor::Beta)],
            "select_latest_matching must receive the caller's minimum_stability"
        );
        assert!(
            result.versions.contains_key("vendor/pkg"),
            "the pick must still succeed"
        );
    }

    /// #424 S1: the `get_latest_matching` fallback path (used when the pure list-based pick
    /// finds nothing) must also thread `minimum_stability` through.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_threads_minimum_stability_into_get_latest_matching_fallback()
     {
        use deps_core::{Metadata, Registry, StabilityFloor, Version};
        use std::any::Any;
        use std::sync::Mutex;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct FallbackContextAwareRegistry {
            // Records every `minimum_stability` value observed, in call order — an empty
            // `Vec` after the fetch means the fallback method was never invoked.
            seen_minimum_stability: Mutex<Vec<Option<StabilityFloor>>>,
        }

        impl Registry for FallbackContextAwareRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                // Empty list forces the fetch loop's `get_latest_matching` fallback (the pure
                // list-based pick over an empty list finds nothing).
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                selection_context: &'a SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                self.seen_minimum_stability
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(selection_context.minimum_stability());
                Box::pin(async move {
                    Ok(Some(Box::new(MockVersion {
                        version: "2.0.0-beta1".into(),
                    }) as Box<dyn Version>))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry = Arc::new(FallbackContextAwareRegistry {
            seen_minimum_stability: Mutex::new(Vec::new()),
        });
        let packages = vec![PackageName::new("vendor/pkg")];

        let result = fetch_latest_versions_parallel(
            Arc::clone(&registry) as Arc<dyn Registry>,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            10,
            10,
            &SelectionContext::with_minimum_stability(StabilityFloor::Beta),
        )
        .await;

        assert_eq!(
            *registry
                .seen_minimum_stability
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            vec![Some(StabilityFloor::Beta)],
            "get_latest_matching must receive the caller's minimum_stability"
        );
        let widget = result
            .versions
            .get("vendor/pkg")
            .expect("fallback pick should succeed");
        assert_eq!(widget.latest, "2.0.0-beta1");
    }

    /// S3 regression: a registry whose `get_versions` list is incomplete (e.g. Go's
    /// `/@v/list`, which never enumerates pseudo-versions and can be entirely empty for an
    /// untagged module) must not render the package as "no version found" just because
    /// `select_latest_matching`'s pure list-based pick came up empty — the fetch loop must
    /// fall back to the registry's own `get_latest_matching`.
    #[tokio::test]
    async fn test_fetch_falls_back_to_get_latest_matching_when_list_based_pick_finds_nothing() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        #[derive(Debug)]
        struct MockVersion {
            version: ConcreteVersion,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Mimics an untagged Go module: `get_versions` (the list endpoint) is empty, but
        /// `get_latest_matching` (a different, more complete endpoint) still resolves a
        /// pseudo-version. `select_latest_matching` deliberately relies on the trait
        /// default (`None`), matching a real registry whose list-based pick has nothing to
        /// work with.
        struct UntaggedModuleRegistry;

        impl Registry for UntaggedModuleRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(Some(Box::new(MockVersion {
                        version: "v0.0.0-20191109021931-daa7c04131f5".into(),
                    }) as Box<dyn Version>))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(UntaggedModuleRegistry);
        let packages = vec![PackageName::new("golang.org/x/exp")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert_eq!(
            result
                .versions
                .get("golang.org/x/exp")
                .map(|v| v.latest.as_str()),
            Some("v0.0.0-20191109021931-daa7c04131f5"),
            "must fall back to get_latest_matching instead of reporting no version found"
        );
    }

    #[tokio::test]
    async fn test_fetch_registry_error_handled() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct ErrorRegistry;

        impl Registry for ErrorRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::CacheError(format!(
                        "Failed to fetch package: {}",
                        name.as_str()
                    )))
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::CacheError(format!(
                        "Failed to fetch package: {}",
                        name.as_str()
                    )))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(ErrorRegistry);
        let packages = vec![
            PackageName::new("package-1"),
            PackageName::new("package-2"),
            PackageName::new("package-3"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(
            result.versions.is_empty(),
            "All packages with errors should be omitted from results"
        );
        assert_eq!(
            result.failed_count, 3,
            "All 3 packages should be marked as failed"
        );
        // #267: a fetch error must be recorded per-package, not just counted,
        // so diagnostic generation can tell "fetch failed" apart from
        // "genuinely not found" instead of reporting "Unknown package".
        assert_eq!(
            result.fetch_failed,
            HashMap::from([
                (PackageName::new("package-1"), FetchFailure::Transient),
                (PackageName::new("package-2"), FetchFailure::Transient),
                (PackageName::new("package-3"), FetchFailure::Transient),
            ]),
            "every errored package must be recorded in fetch_failed"
        );
    }

    /// #1209: the `"fetch failed"` WARN's `package` field used to interpolate the raw,
    /// manifest-derived name directly (`package = %name`) — a credential embedded in a
    /// name-shaped manifest field (e.g. via property interpolation) reached this log
    /// verbatim. Now redacted via [`deps_core::PackageName::for_tracing`]. Asserts against
    /// the fully rendered line (not just the event message), mirroring
    /// `deps-maven::registry::tests::test_fetch_publish_times_failure_log_redacts_url_query_string`'s
    /// precedent: a leak reintroduced only in an enclosing span/field would otherwise pass a
    /// message-only assertion.
    #[tokio::test]
    async fn test_fetch_failed_log_redacts_credential_shaped_package_name() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        // M1 (impl-critic on the original #1209 fix): a real ecosystem registry's
        // `get_versions` runs inside a `#[tracing::instrument(fields(package = ...))]` span
        // (e.g. `deps-maven`'s `get_metadata`) — the exact shape the original audit's most
        // defensible finding hinged on (`warn_rejected_value`'s len-only design defeated by
        // its own enclosing span). Without an instrumented mock here, this test would still
        // pass if a *span*-level redaction fix were reverted, since only `fetch.rs`'s own
        // event field would be exercised. `inner_fetch` mirrors the production idiom exactly
        // (`fields(package = %name.for_tracing())`) so a regression to `?name`/`%name` here
        // would fail this test's assertions.
        #[tracing::instrument(skip_all, fields(package = %name.for_tracing()), level = "debug")]
        async fn inner_fetch(name: &PackageName) -> deps_core::Result<Vec<Box<dyn Version>>> {
            // An event fired *from inside* the span (not just the span's own fields) is what
            // makes `tracing_subscriber`'s default formatter render the span context
            // (`inner_fetch{package=...}: ...`) into the captured line at all — a span with no
            // event inside it produces no output on its own.
            tracing::debug!("mock registry fetch invoked");
            Err(deps_core::error::DepsError::CacheError(
                "transient backend failure".to_string(),
            ))
        }

        struct AlwaysFailsRegistry;

        impl Registry for AlwaysFailsRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(inner_fetch(name))
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::CacheError(
                        "transient backend failure".to_string(),
                    ))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let sentinel_name =
            PackageName::new("com.example:deploy:AUDITSENTINEL0000@git.internal.corp");
        let registry: Arc<dyn Registry> = Arc::new(AlwaysFailsRegistry);
        let packages = vec![sentinel_name.clone()];

        let log =
            deps_core::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
                let result = fetch_latest_versions_parallel(
                    registry,
                    with_registry_source(packages),
                    &HashMap::new(),
                    None,
                    deps_core::freshness::FreshnessSettings::default(),
                    5,
                    10,
                    &SelectionContext::none(),
                )
                .await;
                assert_eq!(result.failed_count, 1);
            })
            .await;

        assert!(
            log.contains("fetch failed"),
            "expected the fetch-failed WARN to fire: {log:?}"
        );
        assert!(
            log.contains("mock registry fetch invoked"),
            "expected the in-span event to fire — without it the span's fields never render, \
             silently downgrading this test back to event-field-only coverage: {log:?}"
        );
        assert!(
            !log.contains("AUDITSENTINEL0000"),
            "tracing output leaked a credential-shaped package name: {log:?}"
        );
        assert!(
            log.contains("git.internal.corp"),
            "host should survive redaction: {log:?}"
        );
    }

    #[tokio::test]
    async fn test_fetch_not_found_is_not_recorded_as_fetch_failed() {
        // #267 C1: a genuine not-found (`DepsError::PackageNotFound`, the
        // variant npm/PyPI/Go/Swift map a 404 to) means the registry was
        // successfully asked and answered "no such package" — recording it
        // in `fetch_failed` would make `generate_diagnostics_from_cache`
        // report "Registry lookup failed" instead of "Unknown package" for
        // the common typo'd-dependency case, inverting the bug this field
        // exists to fix.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct NotFoundRegistry;

        impl Registry for NotFoundRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::PackageNotFound {
                        package: name.as_str().into(),
                        registry: "mock",
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::PackageNotFound {
                        package: name.as_str().into(),
                        registry: "mock",
                    })
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(NotFoundRegistry);
        let packages = vec![PackageName::new("typo-pkg")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty());
        assert!(
            result.fetch_failed.is_empty(),
            "a genuine not-found must not be recorded in fetch_failed, or \
             generate_diagnostics_from_cache would report it as a registry \
             error instead of Unknown package"
        );
    }

    /// Regression for #550: a registry fetch that genuinely succeeds (no error at
    /// either the list-based pick or the `get_latest_matching` fallback) but resolves
    /// to zero versions must be recorded in `no_comparable_versions`, distinct from
    /// both a normal successful fetch (`versions`) and a real failure
    /// (`fetch_failed`). Mirrors `GithubActionsRegistry::get_versions("dtolnay/rust-toolchain")`,
    /// whose sole tag `v1` doesn't parse as full semver, so `tags_to_versions` filters
    /// it out and returns `Ok(vec![])`.
    #[tokio::test]
    async fn test_fetch_success_with_zero_versions_is_recorded_as_no_comparable_versions() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct EmptyButRealRegistry;

        impl Registry for EmptyButRealRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(EmptyButRealRegistry);
        let packages = vec![PackageName::new("dtolnay/rust-toolchain")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty());
        assert!(
            result.fetch_failed.is_empty(),
            "a genuine empty-but-successful fetch must not be recorded as a fetch \
             failure, or generate_diagnostics_from_cache would report a registry \
             error instead of nothing"
        );
        assert!(
            result
                .no_comparable_versions
                .contains(&PackageName::new("dtolnay/rust-toolchain")),
            "a package whose fetch succeeded with zero comparable versions must be \
             recorded in no_comparable_versions, or R5 would misreport it as Unknown \
             package; got: {:?}",
            result.no_comparable_versions
        );
    }

    #[tokio::test]
    async fn test_fetch_http_404_is_not_recorded_as_fetch_failed() {
        // Same as `test_fetch_not_found_is_not_recorded_as_fetch_failed`, for
        // the ecosystems (Cargo, Maven, Gradle, Bundler, Dart, Composer,
        // NuGet) that propagate a raw `DepsError::HttpStatus { status: 404 }`
        // instead of mapping it to `PackageNotFound`.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct Http404Registry;

        impl Registry for Http404Registry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::HttpStatus {
                        url: format!("https://example.com/{}", name.as_str()).into(),
                        status: 404,
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::HttpStatus {
                        url: format!("https://example.com/{}", name.as_str()).into(),
                        status: 404,
                    })
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(Http404Registry);
        let packages = vec![PackageName::new("typo-pkg")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty());
        assert!(
            result.fetch_failed.is_empty(),
            "a bare HTTP 404 must not be recorded in fetch_failed either"
        );
    }

    #[tokio::test]
    async fn test_fetch_fallback_error_recorded_as_fetch_failed_unless_not_found() {
        // Go-shaped path: `get_versions` returns an empty list (nothing for
        // `select_latest_matching` to pick), so `fetch_latest_versions_parallel`
        // falls back to `get_latest_matching`. Exercises the fallback's own
        // error/timeout arms (previously zero test coverage — tester gap),
        // and confirms the same not-found-vs-failure gating (#267 C1) applies
        // there too, per-package via the `not_found` name.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct FallbackErrorRegistry;

        impl Registry for FallbackErrorRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let name = name.clone();
                Box::pin(async move {
                    if name.as_str() == "not-found" {
                        Err(deps_core::error::DepsError::PackageNotFound {
                            package: name.as_str().into(),
                            registry: "mock",
                        })
                    } else {
                        Err(deps_core::error::DepsError::CacheError(
                            "mock fallback failure".to_string(),
                        ))
                    }
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(FallbackErrorRegistry);
        let packages = vec![PackageName::new("flaky"), PackageName::new("not-found")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty());
        assert_eq!(
            result.fetch_failed,
            HashMap::from([(PackageName::new("flaky"), FetchFailure::Transient)]),
            "the fallback's own non-not-found error must be recorded in fetch_failed, \
             but its not-found error must not"
        );
        assert_eq!(
            result.failed_count, 2,
            "both fallback failures count toward failed_count regardless of cause (S2)"
        );
    }

    #[tokio::test]
    async fn test_fetch_fallback_timeout_recorded_as_fetch_failed() {
        // Timeout coverage for the `get_latest_matching` fallback path — a
        // timeout is never a "not found", so it must always land in
        // `fetch_failed` (and count toward `failed_count`, S2).
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct FallbackTimeoutRegistry;

        impl Registry for FallbackTimeoutRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(FallbackTimeoutRegistry);
        let packages = vec![PackageName::new("slow-fallback")];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(result.versions.is_empty());
        assert_eq!(
            result.fetch_failed,
            HashMap::from([(PackageName::new("slow-fallback"), FetchFailure::Transient)])
        );
        assert_eq!(result.failed_count, 1);
    }

    #[tokio::test]
    async fn test_first_error_prefers_actionable_error_over_not_found_regardless_of_race_order() {
        // #480: before this fix, `first_error` was simply whichever concurrent fetch
        // finished first, so a fast not-found could outrank a slower but more actionable
        // error. Here not-found resolves immediately and the actionable error resolves
        // after a delay, winning the race — `priority_error` must still make it win.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct MixedErrorRegistry;

        impl Registry for MixedErrorRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    if name.as_str() == "typo-pkg" {
                        Err(deps_core::error::DepsError::PackageNotFound {
                            package: name.as_str().into(),
                            registry: "mock",
                        })
                    } else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Err(deps_core::error::DepsError::CacheError(
                            "rate limit exceeded".to_string(),
                        ))
                    }
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(MixedErrorRegistry);
        let packages = vec![
            PackageName::new("typo-pkg"),
            PackageName::new("rate-limited"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        let err = result
            .first_error
            .expect("an actionable failure occurred and must be reported");
        assert!(
            err.contains("rate limit exceeded"),
            "the actionable error must win the toast over the faster-finishing not-found, \
             got: {err}"
        );
        assert!(
            !err.contains("not found"),
            "a not-found error must never outrank an actionable error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_first_error_falls_back_to_not_found_when_no_actionable_error_occurred() {
        // #480 fallback path: `priority_error` is only populated by errors that also
        // count toward `fetch_failed` (non-not-found). A batch whose only failures are
        // not-found ones must still surface one via `first_error` instead of silently
        // reporting nothing.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct AllNotFoundRegistry;

        impl Registry for AllNotFoundRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::PackageNotFound {
                        package: name.as_str().into(),
                        registry: "mock",
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(AllNotFoundRegistry);
        let packages = vec![
            PackageName::new("typo-pkg-1"),
            PackageName::new("typo-pkg-2"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert!(
            result.fetch_failed.is_empty(),
            "not-found errors must never be recorded in fetch_failed"
        );
        let err = result
            .first_error
            .expect("a not-found-only batch must still fall back to reporting one via first_error");
        assert!(err.contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_timeout_only_batch_reports_first_error_alongside_failed_count() {
        // #480 S1: the toast used to special-case a populated `first_error`, dropping
        // `failed_count` from the message — a timeout batch silently lost its count. Now
        // built unconditionally from both fields (#490): asserts `FetchResult` reports
        // `failed_count` equal to batch size *and* a populated `first_error` together.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct AlwaysTimesOutRegistry;

        impl Registry for AlwaysTimesOutRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(AlwaysTimesOutRegistry);
        let packages = vec![
            PackageName::new("slow-1"),
            PackageName::new("slow-2"),
            PackageName::new("slow-3"),
        ];

        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            &SelectionContext::none(),
        )
        .await;

        assert_eq!(
            result.failed_count, 3,
            "all 3 packages must count toward failed_count"
        );
        let err = result
            .first_error
            .expect("a timeout is actionable and must populate first_error, not just failed_count");
        assert!(
            err.contains("timed out"),
            "first_error must be the actionable timeout message, got: {err}"
        );
    }

    // Composer-specific tests
    #[cfg(feature = "composer")]
    mod composer_tests {
        use super::*;

        /// #1433: `prepare_fetch` must surface the manifest's `minimum-stability` field via
        /// the real `deps_composer::parser::parse_composer_json` -> `ComposerParseResult` ->
        /// `deps_core::ParseResult::selection_context` path, not just a hand-built fixture —
        /// this is the actual production call path from the fetch task.
        #[tokio::test]
        async fn test_prepare_fetch_selection_context_extracts_from_real_parse_result() {
            let json = r#"{
  "minimum-stability": "beta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = crate::setup::parse_composer_json(json, &uri).unwrap();
            let formatter = deps_composer::ComposerFormatter;

            let prep = prepare_fetch(
                &parse_result as &dyn deps_core::ParseResult,
                &formatter,
                deps_core::EcosystemId::Composer,
                &HashMap::new(),
                &HashMap::new(),
            );

            assert_eq!(
                prep.selection_context.minimum_stability(),
                Some(deps_core::StabilityFloor::Beta)
            );
        }

        /// #1433: a `composer.json` with no `minimum-stability` field surfaces an empty
        /// `SelectionContext`, not a fabricated `"stable"`.
        #[tokio::test]
        async fn test_prepare_fetch_selection_context_none_when_absent() {
            let json = r#"{"require": {"symfony/console": "^6.0"}}"#;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = crate::setup::parse_composer_json(json, &uri).unwrap();
            let formatter = deps_composer::ComposerFormatter;

            let prep = prepare_fetch(
                &parse_result as &dyn deps_core::ParseResult,
                &formatter,
                deps_core::EcosystemId::Composer,
                &HashMap::new(),
                &HashMap::new(),
            );

            assert_eq!(prep.selection_context.minimum_stability(), None);
        }
    }
    mod yanked_check_tests {
        use super::*;
        use deps_core::{Metadata, Version};
        use std::any::Any;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug, Clone)]
        struct MockYankVersion {
            version: ConcreteVersion,
            yanked: bool,
        }

        impl Version for MockYankVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn removal_status(&self) -> deps_core::RemovalStatus {
                deps_core::RemovalStatus::from_yanked(self.yanked)
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Per-package outcome for the primary (and, under #206, only)
        /// `get_versions` fetch.
        enum FetchOutcome {
            Versions(Vec<(&'static str, bool)>),
            Error,
            Timeout,
        }

        /// Configurable mock registry for exercising the yanked-check wiring
        /// in `fetch_latest_versions_parallel`. Under #206's single-fetch
        /// design, `get_versions` is both the source of "latest" (via
        /// `select_latest_matching`, mirrored here by picking the first
        /// non-yanked entry) and, in the same in-memory list, the source of
        /// the yanked check — there is no second registry call to mock.
        /// `latest_fallback` only feeds the `get_latest_matching` fallback
        /// path, exercised when `select_latest_matching` finds nothing (all
        /// yanked, or an empty list).
        struct MockRegistry {
            reports_yanked: bool,
            versions: HashMap<&'static str, FetchOutcome>,
            latest_fallback: HashMap<&'static str, (&'static str, bool)>,
            fetch_calls: Arc<AtomicUsize>,
        }

        impl Registry for MockRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                self.fetch_calls.fetch_add(1, Ordering::Relaxed);
                let outcome = self.versions.get(name.as_str());
                Box::pin(async move {
                    match outcome {
                        Some(FetchOutcome::Versions(vs)) => Ok(vs
                            .iter()
                            .map(|(v, y)| {
                                Box::new(MockYankVersion {
                                    version: (*v).into(),
                                    yanked: *y,
                                }) as Box<dyn Version>
                            })
                            .collect()),
                        Some(FetchOutcome::Error) => Err(deps_core::error::DepsError::CacheError(
                            "mock fetch error".to_string(),
                        )),
                        Some(FetchOutcome::Timeout) => {
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                            Ok(vec![])
                        }
                        None => Ok(vec![]),
                    }
                })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution())
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let outcome = self.latest_fallback.get(name.as_str()).copied();
                Box::pin(async move {
                    Ok(outcome.map(|(v, y)| {
                        Box::new(MockYankVersion {
                            version: v.into(),
                            yanked: y,
                        }) as Box<dyn Version>
                    }))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn reports_yanked(&self) -> bool {
                self.reports_yanked
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[tokio::test]
        async fn reports_yanked_false_never_recorded() {
            // The fetched list carries a yanked in-use entry, but
            // `reports_yanked() == false` means `removal_status()` must never be
            // trusted, even though the data is already in hand for free.
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: false,
                versions: HashMap::from([(
                    "pkg",
                    FetchOutcome::Versions(vec![("2.0.0", false), ("1.0.0", true)]),
                )]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert!(result.yanked_versions.is_empty());
        }

        #[tokio::test]
        async fn in_use_equal_to_latest_not_yanked() {
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", false)]))]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert!(result.yanked_versions.is_empty());
        }

        #[tokio::test]
        async fn no_known_in_use_version_skips_the_check() {
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("2.0.0", false)]))]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert!(result.yanked_versions.is_empty());
        }

        #[tokio::test]
        async fn in_use_differs_and_yanked_is_recorded() {
            // No second registry call under #206: the in-use check is a
            // search over the same `versions` list already fetched for
            // "latest" — `fetch_calls` stays at 1.
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([(
                    "pkg",
                    FetchOutcome::Versions(vec![("2.0.0", false), ("1.0.0", true)]),
                )]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked))
            );
        }

        #[tokio::test]
        async fn in_use_differs_and_not_yanked_is_not_recorded() {
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([(
                    "pkg",
                    FetchOutcome::Versions(vec![("2.0.0", false), ("1.0.0", false)]),
                )]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert!(result.yanked_versions.is_empty());
        }

        #[tokio::test]
        async fn every_version_yanked_still_checks_in_use() {
            // Critique M2: every version filtered out by the wildcard
            // requirement (here, all yanked) is the most severe case, not a
            // silent skip. `select_latest_matching` finds nothing, the
            // `get_latest_matching` fallback also finds nothing (no entry in
            // `latest_fallback`), so `result.versions` stays empty — but the
            // yanked check still runs against the originally fetched list.
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", true)]))]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked))
            );
            assert!(result.versions.is_empty());
        }

        #[tokio::test]
        async fn latest_pick_needs_fallback_in_use_yanked_still_found() {
            // When the list-based pick fails (all yanked) and the
            // `get_latest_matching` fallback succeeds with a *different*,
            // non-yanked version, `result.versions` is populated from the
            // fallback — but the in-use yanked check still searches the
            // originally fetched list, not the fallback's single version.
            let fetch_calls = Arc::new(AtomicUsize::new(0));
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", true)]))]),
                latest_fallback: HashMap::from([("pkg", ("2.0.0", false))]),
                fetch_calls: Arc::clone(&fetch_calls),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert_eq!(
                result
                    .versions
                    .get(&PackageName::new("pkg"))
                    .map(|v| v.latest.as_str()),
                Some("2.0.0")
            );
            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked))
            );
        }

        #[tokio::test]
        async fn in_use_checks_every_occurrence_of_a_duplicate_name() {
            // Regression guard for #394: a package can appear more than once
            // in a manifest under the same name (e.g. `[dependencies]` +
            // `[dev-dependencies]`), each pinned to a different in-use
            // version. Only one occurrence ("2.0.0") is yanked; the other
            // ("3.0.0", not fetched here, not yanked) must not shadow it.
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([(
                    "pkg",
                    FetchOutcome::Versions(vec![
                        ("3.0.0", false),
                        ("2.0.0", true),
                        ("1.0.0", false),
                    ]),
                )]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });
            let mut in_use = HashMap::new();
            in_use.insert(
                PackageName::new("pkg"),
                vec!["1.0.0".to_string(), "2.0.0".to_string()],
            );

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("2.0.0"), RemovalStatus::Yanked)),
                "the yanked occurrence must be found even though a name-keyed \
                 single-value map could have kept only the non-yanked \"1.0.0\" pin"
            );
        }

        #[tokio::test]
        async fn latest_is_yanked_recorded_as_defense_in_depth() {
            // §4.7 row 1: a contract-violating registry (its wildcard
            // `get_latest_matching` fallback returns a yanked version) still
            // gets recorded, at zero extra cost. `select_latest_matching`
            // filters yanked entries by construction, so the list-based pick
            // finds nothing here and the fallback is what "lies".
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", true)]))]),
                latest_fallback: HashMap::from([("pkg", ("1.0.0", true))]),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked))
            );
        }

        #[tokio::test]
        async fn latest_is_yanked_not_recorded_when_reports_yanked_false() {
            // impl-critic M1: row 1 must respect the same `reports_yanked()`
            // gate as the in-memory in-use check. Harmless today only
            // because every opt-out registry also hardcodes `removal_status`
            // to `Available` — this guards against a follow-up (§8.2/§8.3)
            // making an opt-out registry's `removal_status()` real without
            // also flipping `reports_yanked()`, which would otherwise
            // silently reintroduce a #233-class bug through this exact row.
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: false,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", true)]))]),
                latest_fallback: HashMap::from([("pkg", ("1.0.0", true))]),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert!(
                result.yanked_versions.is_empty(),
                "a `reports_yanked() == false` registry's `removal_status()` must never be \
                 trusted, even on the zero-cost row-1 path"
            );
            assert!(
                result
                    .versions
                    .get(&PackageName::new("pkg"))
                    .expect("pkg was fetched")
                    .yanked
                    .is_empty(),
                "`PackageVersions::yanked` must stay empty for a `reports_yanked() == false` \
                 registry, even though the fetched version is itself flagged"
            );
        }

        #[tokio::test]
        async fn primary_fetch_error_counts_as_failed_no_yanked_data() {
            // Under #206's single-fetch design there is no separate "probe"
            // that can fail independently of the primary fetch — a
            // `get_versions` failure loses both the "latest" and the yanked
            // data together, and is counted as a real fetch failure (unlike
            // the pre-#206 best-effort probe).
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Error)]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert!(result.yanked_versions.is_empty());
            assert_eq!(result.failed_count, 1);
            assert!(result.versions.is_empty());
        }

        #[tokio::test]
        async fn primary_fetch_timeout_counts_as_failed_no_yanked_data() {
            // Same reasoning as the error case above, for the timeout path.
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: true,
                versions: HashMap::from([("pkg", FetchOutcome::Timeout)]),
                latest_fallback: HashMap::new(),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                1,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert!(result.yanked_versions.is_empty());
            assert_eq!(result.failed_count, 1);
            assert!(result.versions.is_empty());
        }
    }

    /// #205: the `fetch_latest_versions_parallel` wiring that derives `FetchResult::deprecations`
    /// from the `resolved`/"latest" pick, self-contained rather than extending
    /// `yanked_check_tests`'s shared `MockYankVersion`/`FetchOutcome` (whose tuple shape has
    /// no room for a per-version `Deprecation` payload without touching its many existing
    /// call sites).
    mod deprecation_derivation_tests {
        use super::*;
        use deps_core::{Metadata, Version};
        use std::any::Any;

        struct MockDeprecatedVersion {
            version: ConcreteVersion,
            deprecation: Option<Deprecation>,
        }

        impl Version for MockDeprecatedVersion {
            fn version_string(&self) -> &ConcreteVersion {
                &self.version
            }
            fn removal_status(&self) -> RemovalStatus {
                RemovalStatus::from_advisory(self.deprecation.is_some())
            }
            fn deprecation(&self) -> Option<&Deprecation> {
                self.deprecation.as_ref()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Always resolves to its single configured version.
        struct SingleVersionRegistry {
            deprecation: Option<Deprecation>,
        }

        impl Registry for SingleVersionRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let deprecation = self.deprecation.clone();
                Box::pin(async move {
                    Ok(vec![Box::new(MockDeprecatedVersion {
                        version: "1.0.0".into(),
                        deprecation,
                    }) as Box<dyn Version>])
                })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &VersionReq,
                _selection_context: &deps_core::SelectionContext,
            ) -> Option<usize> {
                (!versions.is_empty()).then_some(0)
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[tokio::test]
        async fn fetch_result_carries_deprecation_from_resolved_pick() {
            let registry: Arc<dyn Registry> = Arc::new(SingleVersionRegistry {
                deprecation: Some(Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: Some("other/pkg".to_string()),
                }),
            });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert_eq!(
                result.deprecations.get(&PackageName::new("pkg")),
                Some(&Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: Some("other/pkg".to_string()),
                })
            );
        }

        #[tokio::test]
        async fn fetch_result_has_no_deprecation_when_resolved_pick_is_clean() {
            let registry: Arc<dyn Registry> = Arc::new(SingleVersionRegistry { deprecation: None });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &HashMap::new(),
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
            )
            .await;

            assert!(result.deprecations.is_empty());
        }
    }
}
