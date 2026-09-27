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
use deps_core::Version;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
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
    /// Toast-ready summary of this round's failures, or `None` when every package either
    /// resolved or fetched cleanly with no comparable versions. Replaces the previously
    /// independent `failed_count`/`first_error` field pair (#480, #490): both bugs were
    /// hand-kept invariants (`failed_count > 0` implies `first_error.is_some()`) rather
    /// than type-enforced ones. `failure_summary`'s count still counts both a genuine
    /// fetch failure (recorded in `fetch_failed` above) and a not-found lookup (the
    /// registry answered "no such package", never recorded in `fetch_failed`, see #267
    /// C1) — only the `fetch_failed` subset produces an inline "Registry lookup failed"
    /// diagnostic, so this count can still exceed `fetch_failed.len()` (#276 S2).
    pub failure_summary: Option<FailureSummary>,
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

/// Toast-ready summary of a fetch batch's failures: how many packages did not resolve and
/// the first actionable failure message, in fetch-completion order.
///
/// Replaces [`FetchResult`]'s previously independent `failed_count`/`first_error` field
/// pair, whose only invariant (a nonzero count implies a message) was kept by convention
/// rather than the type system — two prior bugs (#480, #490) were both hand-patches on top
/// of that convention rather than fixes to the underlying representation. A `count` of zero
/// and a missing message are now unrepresentable: this type only exists as `Some` when at
/// least one package failed, and its message is always present.
///
/// # Examples
///
/// ```
/// use deps_engine::classify::fetch::FailureSummary;
/// use std::num::NonZeroUsize;
///
/// let summary = FailureSummary::new(NonZeroUsize::new(2).unwrap(), "HTTP 503".to_string());
/// assert_eq!(summary.count(), 2);
/// assert_eq!(summary.message(), "HTTP 503");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSummary {
    count: NonZeroUsize,
    message: String,
}

impl FailureSummary {
    /// Builds a `FailureSummary` from its already-computed count and message.
    #[must_use]
    pub fn new(count: NonZeroUsize, message: String) -> Self {
        Self { count, message }
    }

    /// Number of packages whose registry fetch did not succeed this round (see
    /// [`FetchResult::failure_summary`] for what counts).
    #[must_use]
    pub fn count(&self) -> usize {
        self.count.get()
    }

    /// The first actionable failure message, in fetch-completion order.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
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
    ///     None,
    ///     HashMap::new(),
    /// );
    /// assert_eq!(result.failed_count(), 0);
    /// ```
    ///
    /// Parameters, in declaration order (see each field's own doc above for the full
    /// rationale — this is a quick cross-check against accidental transposition, several
    /// share the same `HashMap<PackageName, _>`/`HashSet<PackageName>` shape):
    /// `versions` (successful fetches), `yanked_versions` (yank findings),
    /// `deprecations` (package-level deprecation findings), `fetch_failed` (errored/timed-out
    /// packages), `no_comparable_versions` (fetched clean but nothing to compare),
    /// `failure_summary`, `licenses`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        versions: HashMap<PackageName, PackageVersions>,
        yanked_versions: HashMap<PackageName, (ConcreteVersion, RemovalStatus)>,
        deprecations: HashMap<PackageName, Deprecation>,
        fetch_failed: HashMap<PackageName, FetchFailure>,
        no_comparable_versions: HashSet<PackageName>,
        failure_summary: Option<FailureSummary>,
        licenses: HashMap<PackageName, Vec<String>>,
    ) -> Self {
        Self {
            versions,
            yanked_versions,
            deprecations,
            fetch_failed,
            no_comparable_versions,
            failure_summary,
            licenses,
        }
    }

    /// Total packages whose fetch did not succeed this round (mirrors the old
    /// `failed_count` field). Requires `self` not yet partially moved out of — a caller
    /// that has already moved another field (e.g. `versions`) out of a owned `FetchResult`
    /// should read `failure_summary` directly instead, since a partial move blocks any
    /// further whole-`self` method call.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.failure_summary
            .as_ref()
            .map_or(0, FailureSummary::count)
    }

    /// The first actionable failure message for this round (mirrors the old `first_error`
    /// field). Same partial-move caveat as [`Self::failed_count`].
    #[must_use]
    pub fn failure_message(&self) -> Option<&str> {
        self.failure_summary.as_ref().map(FailureSummary::message)
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
///         None,
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
    gossip: Option<&HashMap<PackageName, deps_core::GossipFindings>>,
) -> FetchResult {
    use futures::stream::{self, StreamExt};
    use std::time::Duration;

    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let timeout = Duration::from_secs(timeout_secs);
    let wildcard_req = deps_core::VersionReq::new("*");
    let check_yanked = registry.reports_yanked();

    let results: Vec<_> = stream::iter(package_sources)
        .map(|(name, source)| {
            let registry = Arc::clone(&registry);
            let fetched = Arc::clone(&fetched);
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
                    gossip,
                    &fetched,
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
    let mut failed_count: usize = 0;
    // `fallback_message`'s tie-break among multiple not-found-only packages is completion
    // order, not the old mutex-write order — a difference only observable in an artificial
    // race, since every not-found message is interchangeable in the toast anyway (#480).
    let mut priority_message: Option<String> = None;
    let mut fallback_message: Option<String> = None;
    for PackageOutcome {
        name,
        status,
        yanked,
    } in results
    {
        if let Some(y) = yanked {
            yanked_versions.insert(name.clone(), y);
        }
        match status {
            PackageStatus::Resolved {
                versions: v,
                deprecation,
                license,
            } => {
                if let Some(d) = deprecation {
                    deprecations.insert(name.clone(), d);
                }
                if let Some(lic) = license {
                    licenses.insert(name.clone(), lic);
                }
                versions.insert(name, v);
            }
            PackageStatus::NoComparableVersions => {
                no_comparable_versions.insert(name);
            }
            PackageStatus::NotFound { message } => {
                failed_count += 1;
                if fallback_message.is_none() {
                    fallback_message = Some(message);
                }
            }
            PackageStatus::Failed { failure, message } => {
                failed_count += 1;
                fetch_failed.insert(name, failure);
                if priority_message.is_none() {
                    priority_message = Some(message.clone());
                }
                if fallback_message.is_none() {
                    fallback_message = Some(message);
                }
            }
        }
    }

    let failure_summary = NonZeroUsize::new(failed_count).map(|count| {
        #[allow(clippy::expect_used)]
        let message = priority_message.or(fallback_message).expect(
            "every branch that increments failed_count also sets fallback_message \
             in the same match arm",
        );
        FailureSummary::new(count, message)
    });

    FetchResult {
        versions,
        yanked_versions,
        deprecations,
        fetch_failed,
        no_comparable_versions,
        failure_summary,
        licenses,
    }
}

/// One package's terminal registry-fetch status (issue #1470): replaces a 6-tuple of
/// independent `Option`s whose illegal combinations (e.g. a resolved version alongside a
/// fetch failure, or `NoComparableVersions` alongside a resolved version) were previously
/// prevented only by careful match-arm discipline in [`fetch_latest_versions_parallel`]'s
/// aggregation fold, not by the type system. Exactly one variant applies per package.
///
/// The license carried by [`Self::Resolved`] comes from `select_latest_matching`'s pick
/// (critic S1: previously documented as "the resolved version's license", which was
/// wrong — this function never reads `resolved_versions` at all, it picks the latest
/// version matching the requirement/stability floor, same as `PackageVersions.latest`).
enum PackageStatus {
    /// The list-based pick (or its `get_latest_matching` fallback) resolved to a usable
    /// version.
    Resolved {
        versions: PackageVersions,
        /// Package-level deprecation finding (#205), derived from the resolved pick.
        deprecation: Option<Deprecation>,
        /// SPDX license identifier(s) (issue #660/#661 tier-1 backfill), `None` when the
        /// ecosystem's `Version::license` was empty.
        license: Option<Vec<String>>,
    },
    /// Both the list-based pick and the `get_latest_matching` fallback succeeded but found
    /// nothing comparable (#550), e.g. tags that don't parse as full semver.
    NoComparableVersions,
    /// The registry answered "no such package" (#267 C1) — never counted in
    /// [`FetchResult::fetch_failed`], but still counted toward the batch's failure total.
    NotFound { message: String },
    /// The fetch (or its fallback) errored for a reason other than not-found, or timed out.
    Failed {
        failure: FetchFailure,
        message: String,
    },
}

/// One package's fetch result: its terminal [`PackageStatus`] plus an independent
/// in-use-version yank finding, folded into [`fetch_latest_versions_parallel`]'s aggregate
/// `FetchResult` once every package in the stream has finished.
///
/// `yanked` is independent of `status` (not one of its variants) because it is sourced
/// from the full version list fetched by the *initial* `get_versions_from` round trip
/// (see the `check_yanked` block in [`fetch_and_classify_package`]), which can succeed even
/// when the subsequent `get_latest_matching_from` fallback pick fails — so a package can be
/// both [`PackageStatus::Failed`] and carry a yanked in-use-version finding at once.
struct PackageOutcome {
    name: PackageName,
    status: PackageStatus,
    yanked: Option<(ConcreteVersion, RemovalStatus)>,
}

/// A successfully picked "latest" version's extracted fields — [`Pick::Resolved`]'s payload,
/// named so the yanked/deprecation/license extraction in [`fetch_and_classify_package`] reads
/// as field access (`r.removal_status`, `&r.license`) rather than a positional tuple whose
/// members are distinguished only by comment.
struct ResolvedPick {
    version: ConcreteVersion,
    removal_status: RemovalStatus,
    published_at: Option<deps_core::freshness::PublishTime>,
    deprecation: Option<Deprecation>,
    license: Vec<String>,
}

/// The list-based pick's outcome, or the `get_latest_matching` fallback's outcome when the
/// list-based pick found nothing — an intermediate result [`fetch_and_classify_package`]
/// uses to run the yanked/deprecation/license extraction once, uniformly, before it settles
/// on a final [`PackageStatus`].
enum Pick {
    Resolved(ResolvedPick),
    Unresolved(PackageStatus),
}

impl Pick {
    /// Builds [`Self::Resolved`] from a picked `Version`, shared by the list-based pick and
    /// the `get_latest_matching` fallback pick so the two success arms can't drift.
    fn resolved(v: &dyn Version) -> Self {
        Self::Resolved(ResolvedPick {
            version: v.version_string().clone(),
            removal_status: v.removal_status(),
            published_at: v.published_at(),
            deprecation: v.deprecation().cloned(),
            license: v.license().to_vec(),
        })
    }
}

/// Fetches, classifies, and version-selects a single package within
/// [`fetch_latest_versions_parallel`]'s concurrent stream: one round trip for the full
/// version list, an in-memory "latest" pick with a `get_latest_matching_from` fallback
/// when the list-based pick fails on a non-empty list, yanked/deprecation extraction, and
/// an update to the shared `fetched` progress counter.
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
    gossip: Option<&HashMap<PackageName, deps_core::GossipFindings>>,
    fetched: &std::sync::atomic::AtomicUsize,
    progress_sender: Option<&ProgressSender>,
) -> PackageOutcome {
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

    let mut yanked: Option<(ConcreteVersion, RemovalStatus)> = None;

    let status = match result {
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

            // Row 2/3 (§4.7, revised under #206) computed eagerly, against the full
            // unfiltered `versions` list, before the GOSSIP-cooldown filter below consumes
            // it — see that filter's own comment for why. Multiple occurrences of the same
            // name (#394) can carry different in-use versions — every one is checked so a
            // yanked pin on any occurrence is never missed. Filters on `is_flagged()` inside
            // `find` itself (not a separate `.filter()`) so a response with multiple entries
            // sharing `iv`'s version string still finds a flagged one if any exists (mirrors
            // the pre-#205 `.any` scan).
            let in_use_yanked: Option<(ConcreteVersion, RemovalStatus)> = check_yanked
                .then(|| {
                    in_use_versions.iter().find_map(|iv| {
                        versions
                            .iter()
                            .find(|v| {
                                v.version_string() == iv.as_str() && v.removal_status().is_flagged()
                            })
                            .map(|v| (iv.as_str().into(), v.removal_status()))
                    })
                })
                .flatten();

            // GOSSIP-cooldown floor-protected filter (spec 074 FR-003) — history in
            // specs/074-deps-cli-gossip-parity/spec.md, not restated here.
            //
            // Computed first so the common case (not flagged) reuses this index below with
            // zero extra `select_latest_matching` calls; captured as an owned `ConcreteVersion`
            // since `Version` has no `clone_box` and `versions` is moved further down.
            let unfiltered_pick_idx =
                registry.select_latest_matching(&versions, wildcard_req, selection_context);
            let unfiltered_pick_version: Option<ConcreteVersion> = unfiltered_pick_idx
                .and_then(|idx| versions.get(idx))
                .map(|v| v.version_string().clone());

            // `now` read once per fetch call.
            let now = deps_core::freshness::PublishTime::now();
            // Shared gate (spec 075 FR-005/T000, DRY) — already required `Some` + active, so
            // behavior here is unchanged; only the ad-hoc closure is replaced.
            let unfiltered_pick_flagged = unfiltered_pick_version.as_ref().is_some_and(|version| {
                deps_core::lsp_helpers::gossip_cooldown_for(gossip, &name, version.as_str(), now)
                    == deps_core::lsp_helpers::GossipCooldownLookup::Active
            });

            // Spec 075 FR-001/FR-002 (T001): computed unconditionally whenever freshness is
            // enabled, before `versions` is consumed below — read-time disposition
            // (`deps_core::lsp_helpers::cooldown_disposition`) decides later whether `latest`
            // is actually blocked and this candidate is needed. `compute_cooldown_fallback`
            // itself short-circuits on `unfiltered_pick_idx` when that pick isn't cooldown-
            // blocked (issue #1551 finding 4).
            let cooldown_fallback = compute_cooldown_fallback(
                registry,
                &versions,
                &name,
                &in_use_versions,
                wildcard_req,
                *selection_context,
                freshness,
                gossip,
                now,
                unfiltered_pick_idx,
            );

            // The resolved pick (or `None`, meaning the `get_latest_matching_from` fallback
            // below runs) and the FR-005 attribution field.
            let (list_pick, gossip_excluded_version) = gossip_floor_protected_pick(
                registry,
                versions,
                &in_use_versions,
                wildcard_req,
                *selection_context,
                unfiltered_pick_idx,
                unfiltered_pick_version,
                unfiltered_pick_flagged,
                gossip,
                &name,
                now,
            );

            // `selection_context` is threaded through so a registry with manifest-level
            // stability state (Composer's `minimum-stability`, #424 S1) can apply it — already
            // accounted for by `list_pick`'s own `select_latest_matching` call(s) above; no
            // further selection call happens here.
            let pick = if let Some(v) = list_pick.as_deref() {
                tracing::debug!(
                    package = %name.for_tracing(),
                    version = %v.version_string(),
                    "fetched"
                );
                Pick::resolved(v)
            } else {
                // The list-based pick found nothing — usually a genuine "no version", but
                // a registry with an incomplete list endpoint (Go's `/@v/list`, which never
                // enumerates pseudo-versions) may need the more complete `get_latest_matching`
                // (Go's `/@latest`). Costs a second network call, only in this rare case.
                get_latest_matching_fallback(
                    registry,
                    &name,
                    &source,
                    wildcard_req,
                    *selection_context,
                    timeout,
                )
                .await
            };

            let resolved: Option<&ResolvedPick> = match &pick {
                Pick::Resolved(r) => Some(r),
                Pick::Unresolved(_) => None,
            };

            if check_yanked {
                // Row 1 (§4.7): the picked "latest" itself yanked — free, already in hand.
                // Unreachable in production under today's hardcoded wildcard, but stays
                // correct as a defense-in-depth check.
                if let Some(r) = resolved
                    && r.removal_status.is_flagged()
                {
                    yanked = Some((r.version.clone(), r.removal_status));
                }

                // A yanked in-use version wins over an already-recorded yanked `latest`
                // since it's the version the user actually has — see `in_use_yanked`'s own
                // comment above for why this is computed ahead of the GOSSIP filter.
                if let Some(iv_yanked) = in_use_yanked {
                    yanked = Some(iv_yanked);
                }
            }

            // #205: the deprecation finding is derived from `resolved` (already picked as
            // "latest"), covering the fallback branch too, whose `Version` isn't a member
            // of `versions` at all — see `FetchResult::deprecations`'s doc for why this
            // must not scan `versions` instead.
            let deprecation = resolved.and_then(|r| r.deprecation.clone());

            // #660/#661 tier-1 backfill. Filtered here so an empty license list —
            // indistinguishable from "no data" once merged into
            // `DocumentState::signals.licenses` — never gets inserted.
            let license = resolved
                .map(|r| &r.license)
                .filter(|lic| !lic.is_empty())
                .cloned();

            match pick {
                Pick::Resolved(ResolvedPick {
                    version,
                    published_at,
                    ..
                }) => {
                    let mut versions =
                        PackageVersions::new(version, available).with_yanked(yanked_list);
                    if let Some(published_at) = published_at {
                        versions = versions.with_published_at(published_at);
                    }
                    if let Some(excluded) = gossip_excluded_version {
                        versions = versions.with_gossip_excluded_version(excluded);
                    }
                    if let Some(fallback) = cooldown_fallback {
                        versions = versions.with_cooldown_fallback(fallback);
                    }
                    PackageStatus::Resolved {
                        versions,
                        deprecation,
                        license,
                    }
                }
                Pick::Unresolved(status) => status,
            }
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
            // A genuine not-found is not a fetch failure — only an unanswerable request is
            // (#267 C1). Marking it here would report "Registry lookup failed" for a
            // typo'd name instead of "Unknown package", inverting the bug this fixes.
            if e.is_not_found() {
                PackageStatus::NotFound {
                    message: e.to_string(),
                }
            } else {
                PackageStatus::Failed {
                    failure: e.fetch_failure(),
                    message: e.to_string(),
                }
            }
        }
        Err(_) => {
            tracing::warn!(package = %name.for_tracing(), "fetch timed out ({}s)", timeout.as_secs());
            PackageStatus::Failed {
                failure: FetchFailure::Transient,
                message: format!(
                    "{}: registry request timed out after {}s",
                    name.for_tracing(),
                    timeout.as_secs()
                ),
            }
        }
    };

    let count = fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if let Some(sender) = progress_sender {
        sender.send(count);
    }

    PackageOutcome {
        name,
        status,
        yanked,
    }
}

/// GOSSIP-cooldown floor-protected re-filter of the list-based pick (spec 074 FR-003),
/// extracted from [`fetch_and_classify_package`] (issue #1560): when the unfiltered pick
/// isn't cooldown-flagged, it is returned unchanged; otherwise candidates below the in-use
/// floor are filtered out and re-ranked, falling back to the unfiltered pick when no
/// acceptable filtered candidate remains (FR-003d/e). History in
/// specs/074-deps-cli-gossip-parity/spec.md, not restated here.
///
/// Returns the final list-based pick (`None` means the `get_latest_matching_from` fallback
/// must run) and the FR-005 attribution field (the version excluded by the floor filter, when
/// one was).
#[allow(
    clippy::too_many_arguments,
    reason = "every parameter is either data already owned by the caller (versions, the \
              in-use floor inputs) or a piece of the unfiltered pick the caller computed \
              once and must not recompute here — grouping into a struct would only move, \
              not reduce, the parameter count"
)]
fn gossip_floor_protected_pick(
    registry: &dyn Registry,
    versions: Vec<Box<dyn Version>>,
    in_use_versions: &[String],
    wildcard_req: &VersionReq,
    selection_context: deps_core::SelectionContext,
    unfiltered_pick_idx: Option<usize>,
    unfiltered_pick_version: Option<ConcreteVersion>,
    unfiltered_pick_flagged: bool,
    gossip: Option<&HashMap<PackageName, deps_core::GossipFindings>>,
    name: &PackageName,
    now: deps_core::freshness::PublishTime,
) -> (Option<Box<dyn Version>>, Option<ConcreteVersion>) {
    if !unfiltered_pick_flagged {
        return (
            unfiltered_pick_idx.and_then(|idx| versions.into_iter().nth(idx)),
            None,
        );
    }

    let is_gossip_cooldown = |version: &ConcreteVersion| {
        deps_core::lsp_helpers::gossip_cooldown_for(gossip, name, version.as_str(), now)
            == deps_core::lsp_helpers::GossipCooldownLookup::Active
    };

    // Protect floor (FR-003b: no-op when no in-use version resolved) — shared with
    // `compute_cooldown_fallback`'s own D2 floor (issue #1551 finding 2). Spec 076 FR-018:
    // this GOSSIP site floors at `newest_located` even under `Unlocatable` (byte-identical
    // to the pre-`InUseFloor` behavior) — `compute_cooldown_fallback` alone tightens further.
    let floor = match in_use_floor(in_use_versions, &versions) {
        InUseFloor::Located(floor)
        | InUseFloor::Unlocatable {
            newest_located: Some(floor),
        } => floor,
        InUseFloor::Absent
        | InUseFloor::Unlocatable {
            newest_located: None,
        } => {
            return (
                unfiltered_pick_idx.and_then(|idx| versions.into_iter().nth(idx)),
                None,
            );
        }
    };

    // Keep each candidate's original index alongside it (parallel
    // `filtered_indices`/`filtered_versions`, since `select_latest_matching` needs a plain
    // slice) so the final pick's position can be checked against `floor` (FR-003e) and the
    // unfiltered pick recovered by index, not version string (avoids matching the wrong
    // duplicate-string entry).
    type IndexedVersion = (usize, Box<dyn Version>);
    let mut filtered_indices: Vec<usize> = Vec::new();
    let mut filtered_versions: Vec<Box<dyn Version>> = Vec::new();
    let mut dropped: Vec<IndexedVersion> = Vec::new();
    for (idx, v) in versions.into_iter().enumerate() {
        if idx >= floor || !is_gossip_cooldown(v.version_string()) {
            filtered_indices.push(idx);
            filtered_versions.push(v);
        } else {
            dropped.push((idx, v));
        }
    }

    let filtered_pick_idx =
        registry.select_latest_matching(&filtered_versions, wildcard_req, &selection_context);
    // Reject a filtered pick older than the floor (FR-003e) — a downgrade.
    let pick_at_or_above_floor = filtered_pick_idx
        .and_then(|idx| filtered_indices.get(idx))
        .is_some_and(|original_idx| *original_idx <= floor);

    if pick_at_or_above_floor {
        let filtered_pick_version = filtered_pick_idx
            .and_then(|idx| filtered_versions.get(idx))
            .map(|v| v.version_string().clone());
        let excluded = (filtered_pick_version != unfiltered_pick_version)
            .then(|| unfiltered_pick_version.clone())
            .flatten();
        (
            filtered_pick_idx.and_then(|idx| filtered_versions.into_iter().nth(idx)),
            excluded,
        )
    } else {
        // No acceptable pick (FR-003d/e) — recover the unfiltered pick by its original
        // index (dropped, or defensively filtered_versions).
        let recovered = unfiltered_pick_idx.and_then(|target| {
            dropped
                .iter()
                .position(|(idx, _)| *idx == target)
                .map(|i| dropped.swap_remove(i).1)
                .or_else(|| {
                    filtered_indices
                        .iter()
                        .position(|idx| *idx == target)
                        .map(|i| filtered_versions.swap_remove(i))
                })
        });
        (recovered, None)
    }
}

/// `get_latest_matching_from` network fallback, extracted from
/// [`fetch_and_classify_package`] (issue #1560): run only when the list-based pick found
/// nothing, for a registry with an incomplete list endpoint (Go's `/@v/list`, which never
/// enumerates pseudo-versions) that may still answer through the more complete
/// `get_latest_matching` (Go's `/@latest`). Costs a second network call, only in this rare
/// case.
async fn get_latest_matching_fallback(
    registry: &dyn Registry,
    name: &PackageName,
    source: &deps_core::parser::DependencySource,
    wildcard_req: &VersionReq,
    selection_context: deps_core::SelectionContext,
    timeout: Duration,
) -> Pick {
    let fallback = tokio::time::timeout(
        timeout,
        registry.get_latest_matching_from(name, source, wildcard_req, &selection_context),
    )
    .await;
    match fallback {
        Ok(Ok(Some(v))) => {
            tracing::debug!(
                package = %name.for_tracing(),
                version = %v.version_string(),
                "fetched via get_latest_matching fallback"
            );
            Pick::resolved(v.as_ref())
        }
        Ok(Ok(None)) => {
            tracing::debug!(package = %name.for_tracing(), "no version found");
            // Both the list-based pick and this fallback succeeded and found nothing — the
            // package exists but has zero comparable versions (#550). Distinct from every
            // branch below that produces `Failed`.
            Pick::Unresolved(PackageStatus::NoComparableVersions)
        }
        Ok(Err(e)) => {
            tracing::warn!(
                package = %name.for_tracing(),
                error = %e,
                "fetch fallback failed"
            );
            // A genuine not-found (the registry was successfully asked and said "no such
            // package") is not a fetch failure — only an unanswerable request is (#267 C1).
            if e.is_not_found() {
                Pick::Unresolved(PackageStatus::NotFound {
                    message: e.to_string(),
                })
            } else {
                Pick::Unresolved(PackageStatus::Failed {
                    failure: e.fetch_failure(),
                    message: e.to_string(),
                })
            }
        }
        Err(_) => {
            tracing::warn!(package = %name.for_tracing(), "fetch fallback timed out ({}s)", timeout.as_secs());
            Pick::Unresolved(PackageStatus::Failed {
                failure: FetchFailure::Transient,
                message: format!(
                    "{}: registry request timed out after {}s",
                    name.for_tracing(),
                    timeout.as_secs()
                ),
            })
        }
    }
}

/// A cheap, cloneable [`Version`] carrying just the fields [`compute_cooldown_fallback`]'s
/// re-ranking pass needs — lets it build an owned candidate list for
/// [`Registry::select_latest_matching`] from borrowed data, since `Version` trait objects have
/// no `clone_box` (fetch.rs's own `IndexedVersion` comment explains why: `versions` is moved
/// further down this same function and no ecosystem needs to duplicate a real `Version` impl).
#[derive(Debug, Clone)]
struct CooldownCandidate {
    version: ConcreteVersion,
    published_at: deps_core::freshness::PublishTime,
    removal_status: RemovalStatus,
    prerelease: bool,
}

impl Version for CooldownCandidate {
    fn version_string(&self) -> &ConcreteVersion {
        &self.version
    }
    fn published_at(&self) -> Option<deps_core::freshness::PublishTime> {
        Some(self.published_at)
    }
    fn removal_status(&self) -> RemovalStatus {
        self.removal_status
    }
    fn is_prerelease(&self) -> bool {
        self.prerelease
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// D2 in-use floor classification (spec 074 FR-003b / spec 075 OQ1 / spec 076 FR-016/FR-017):
/// position of the newest `in_use_versions` entry within `versions` (newest-first, so the
/// smallest index is newest), distinguishing "no in-use version at all" from "an in-use version
/// exists but could not be placed in `versions`" — a partial match (one entry locatable, one
/// not) previously silently floored at the locatable entry and ignored the unplaceable one
/// (round-1 critic M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InUseFloor {
    /// `in_use_versions` is empty.
    Absent,
    /// Every resolvable `in_use_versions` entry maps to a position in `versions`; the `usize`
    /// is the newest (smallest index).
    Located(usize),
    /// At least one `in_use_versions` entry does not map to any position in `versions` (a Go
    /// pseudo-version, a private-registry pin, or a stale lockfile entry). `newest_located`
    /// carries the newest position among the entries that DID resolve, or `None` if none did.
    Unlocatable {
        /// Newest position among the entries that did resolve, if any.
        newest_located: Option<usize>,
    },
}

/// Shared by [`fetch_and_classify_package`]'s GOSSIP floor-protected filter and
/// [`compute_cooldown_fallback`]'s own floor (issue #1551 finding 2). Both agree on
/// `Absent`/`Located`, but deliberately diverge on `Unlocatable { newest_located: Some(_) }`
/// (spec 076 FR-018): the GOSSIP filter still floors at `newest_located`, while
/// `compute_cooldown_fallback` fails closed to no fallback at all — stricter than silently
/// flooring at only the locatable entries and ignoring the unplaceable one.
fn in_use_floor(in_use_versions: &[String], versions: &[Box<dyn Version>]) -> InUseFloor {
    if in_use_versions.is_empty() {
        return InUseFloor::Absent;
    }

    let mut newest_located: Option<usize> = None;
    let mut all_located = true;
    for iv in in_use_versions {
        match versions
            .iter()
            .position(|v| v.version_string().as_str() == iv.as_str())
        {
            Some(idx) => newest_located = Some(newest_located.map_or(idx, |cur| cur.min(idx))),
            None => all_located = false,
        }
    }

    match (all_located, newest_located) {
        // Non-empty `in_use_versions` with every entry located always yields a position; the
        // `None` arm is unreachable in practice but falls back to `Unlocatable` (fail closed)
        // rather than panicking.
        (true, Some(idx)) => InUseFloor::Located(idx),
        (true, None) | (false, _) => InUseFloor::Unlocatable { newest_located },
    }
}

/// Spec 075 FR-001/FR-002: computes the cooldown-fallback candidate for one dependency.
///
/// (Fix-cycle item 5/S5): the cooled subset is ranked through `registry`'s own
/// `select_latest_matching` — the exact same selection algorithm that picks `latest` itself —
/// rather than by raw newest-first list position. A naive "first cooldown-cleared entry by
/// date" pick can land on a prerelease/canary release a frequent publisher ships between
/// stable releases; FR-001's ecosystem-safety guard would then reject it with no retry,
/// reopening the starvation this feature exists to close. Delegating the ranking itself to
/// `select_latest_matching` means the pick is already ecosystem-preferred by construction; the
/// explicit `ecosystem_safe` check below is defense in depth against `select_latest_matching`'s
/// own wildcard-existence fallback (which may prefer a yanked version to answer "does this
/// package exist" rather than ever returning `None` — never appropriate for a fallback write
/// target).
///
/// `unfiltered_pick_idx` is the same list-based pick [`fetch_and_classify_package`] computed
/// over the full, unfiltered `versions` (before any GOSSIP floor-protected filtering) — issue
/// #1551 finding 4: when that pick is known (`Some`) AND isn't itself cooldown-blocked, the
/// full-history GOSSIP/local-heuristic loop below is skipped entirely, since
/// `cooldown_disposition` only ever surfaces a stored fallback candidate from inside its
/// `Blocked` arm — a candidate computed here for an already-cleared pick would never be read.
/// `None` (the list-based pick found nothing, e.g. Go's incomplete `/@v/list` endpoint that
/// never enumerates pseudo-versions, while the network `get_latest_matching_from` fallback
/// still resolves a real `latest`) never short-circuits — the full search below always ran in
/// that case before this finding, and still does.
///
/// Timing caveat (impl-critic M1): the short-circuit's `cooldown_precedence` check runs at
/// fetch time (`now`, captured once per package in [`fetch_and_classify_package`], strictly
/// *after* `deps-cli`'s `ManifestAnalysis::now` — the earlier instant the later read-time
/// `cooldown_disposition` call actually evaluates against). Since age only grows between the
/// two captures, this can only make the fetch-time check see a version as *more* cleared than
/// the read-time check would — never the reverse. So a version whose cooldown boundary falls
/// between the two instants can short-circuit to `None` here even though `cooldown_disposition`
/// still finds it `Blocked` moments later, silently losing a fallback candidate the pre-#1551
/// code would have computed (surfacing as an unnecessary `WithinFreshnessCooldown` skip rather
/// than an applied fallback). This window is bounded by one package's own fetch latency, not the
/// whole batch's, and never causes the reverse mistake (writing a candidate that is actually
/// still cooldown-blocked) — but it means this short-circuit is a narrow, real divergence from
/// the prior always-compute behavior, not a proven-identical optimization.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors fetch_and_classify_package's own identical rationale — every parameter \
              is either registry/selection-rule plumbing already threaded through that \
              function or a planning knob this helper alone needs"
)]
fn compute_cooldown_fallback(
    registry: &dyn Registry,
    versions: &[Box<dyn Version>],
    name: &PackageName,
    in_use_versions: &[String],
    wildcard_req: &VersionReq,
    selection_context: deps_core::SelectionContext,
    freshness: deps_core::freshness::FreshnessSettings,
    gossip: Option<&HashMap<PackageName, deps_core::GossipFindings>>,
    now: deps_core::freshness::PublishTime,
    unfiltered_pick_idx: Option<usize>,
) -> Option<deps_core::lsp_helpers::CooldownFallback> {
    let deps_core::freshness::FreshnessSettings::Enabled { cooldown } = freshness else {
        return None;
    };

    let unfiltered_pick = unfiltered_pick_idx.and_then(|idx| versions.get(idx));
    let latest_is_prerelease = unfiltered_pick.is_some_and(|v| v.is_prerelease());
    // Tester finding: only short-circuit when the pick is known (`Some`) — an unknown pick
    // (`None`) must fall through to the full search below exactly like the pre-#1551 code,
    // never treated as "cleared".
    if let Some(pick) = unfiltered_pick {
        let cleared = matches!(
            deps_core::lsp_helpers::cooldown_precedence(
                gossip,
                name,
                pick.version_string().as_str(),
                pick.published_at(),
                cooldown,
                now,
            ),
            deps_core::lsp_helpers::CooldownPrecedence::Cleared
        );
        if cleared {
            return None;
        }
    }

    // D2 floor (spec 076 FR-018): `Located` sets the floor unchanged from spec 075; `Absent`
    // (no in-use version resolved at all) computes the fallback with NO positional floor —
    // spec 076's core no-lockfile feature; `Unlocatable` (at least one in-use version could not
    // be placed) yields no fallback at all — stricter than the prior `.min()?` behavior, which
    // silently floored at only the locatable entries and ignored the unplaceable one.
    let floor: Option<usize> = match in_use_floor(in_use_versions, versions) {
        InUseFloor::Located(idx) => Some(idx),
        InUseFloor::Absent => None,
        InUseFloor::Unlocatable { .. } => return None,
    };

    // Every candidate that clears cooldown via the same shared precedence rule (an
    // authoritative GOSSIP answer wins, the local heuristic applies otherwise) — fail-closed
    // when `published_at` is unknown (OQ2) — paired with its original index into `versions`.
    let (cleared_indices, cleared_versions): (Vec<usize>, Vec<Box<dyn Version>>) = versions
        .iter()
        .enumerate()
        .filter_map(|(idx, v)| {
            let published_at = v.published_at()?;
            let cleared = matches!(
                deps_core::lsp_helpers::cooldown_precedence(
                    gossip,
                    name,
                    v.version_string().as_str(),
                    Some(published_at),
                    cooldown,
                    now,
                ),
                deps_core::lsp_helpers::CooldownPrecedence::Cleared
            );
            cleared.then(|| {
                let candidate: Box<dyn Version> = Box::new(CooldownCandidate {
                    version: v.version_string().clone(),
                    published_at,
                    removal_status: v.removal_status(),
                    prerelease: v.is_prerelease(),
                });
                (idx, candidate)
            })
        })
        .unzip();

    // FR-001: the ecosystem's own selection-rule pick over the cooled subset — checked only
    // against this single pick, no retry further down the list on failure.
    let pick =
        registry.select_latest_matching(&cleared_versions, wildcard_req, &selection_context)?;
    let idx = *cleared_indices.get(pick)?;
    let candidate = versions.get(idx)?;
    let published_at = candidate.published_at()?;
    let ecosystem_safe = !candidate.removal_status().blocks_resolution()
        && (!candidate.is_prerelease() || latest_is_prerelease);
    let above_floor = floor.is_none_or(|floor| idx < floor);

    (ecosystem_safe && above_floor).then(|| {
        deps_core::lsp_helpers::CooldownFallback::new(
            candidate.version_string().clone(),
            published_at,
        )
    })
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
            None,
        )
        .await;

        assert!(result.versions.is_empty(), "Slow package should timeout");
        assert_eq!(result.failed_count(), 1, "Should track 1 failed package");
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
            None,
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
            result.failed_count(),
            1,
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
            None,
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
        use deps_core::Registry;
        let registry: Arc<dyn Registry> = Arc::new(deps_core::test_util::MockRegistry::new());
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
                None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct MixedOutcomeRegistry;

        impl Registry for MixedOutcomeRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    match name.as_str() {
                        "package-fast" => {
                            Ok(vec![
                                Box::new(MockVersion::new("1.0.0").with_prerelease(false))
                                    as Box<dyn Version>,
                            ])
                        }
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
                        "package-fast" => Ok(Some(Box::new(
                            MockVersion::new("1.0.0").with_prerelease(false),
                        ) as Box<dyn Version>)),
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
            None,
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
        use deps_core::Registry;
        use deps_core::test_util::MockVersion;

        let registry: Arc<dyn Registry> = Arc::new(
            deps_core::test_util::MockRegistry::new().with_versions(vec![
                MockVersion::new("1.0.214"),
                MockVersion::new("1.0.213").yanked(true),
            ]),
        );
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
            None,
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
        use deps_core::Registry;
        use deps_core::freshness::PublishTime;
        use deps_core::test_util::MockVersion;

        let registry: Arc<dyn Registry> = Arc::new(
            deps_core::test_util::MockRegistry::new().with_versions(vec![
                MockVersion::new("1.0.214").with_published_at(PublishTime::from_unix_secs(2_000)),
                // Deliberately a different timestamp — proves the fetch loop never
                // accidentally attaches this entry's age to `latest`.
                MockVersion::new("1.0.213")
                    .yanked(true)
                    .with_published_at(PublishTime::from_unix_secs(1_000)),
            ]),
        );
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
            None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

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
                    Ok(vec![
                        Box::new(MockVersion::new("1.0.0").with_license(license))
                            as Box<dyn Version>,
                    ])
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
            None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

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
                    Ok(vec![Box::new(MockVersion::new("1.0.0")) as Box<dyn Version>])
                })
            }

            fn get_versions_with<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                freshness: FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let version = MockVersion::new("1.0.0");
                let version = match freshness
                    .is_enabled()
                    .then(|| PublishTime::from_unix_secs(5_000))
                {
                    Some(published_at) => version.with_published_at(published_at),
                    None => version,
                };
                Box::pin(async move { Ok(vec![Box::new(version) as Box<dyn Version>]) })
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
            None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, StabilityFloor, Version};
        use std::any::Any;
        use std::sync::Mutex;

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
                    Ok(vec![Box::new(MockVersion::new("1.0.0")) as Box<dyn Version>])
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
            None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, StabilityFloor, Version};
        use std::any::Any;
        use std::sync::Mutex;

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
                    Ok(Some(
                        Box::new(MockVersion::new("2.0.0-beta1")) as Box<dyn Version>
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
            None,
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

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
                    Ok(Some(
                        Box::new(MockVersion::new("v0.0.0-20191109021931-daa7c04131f5"))
                            as Box<dyn Version>,
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
            None,
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
            None,
        )
        .await;

        assert!(
            result.versions.is_empty(),
            "All packages with errors should be omitted from results"
        );
        assert_eq!(
            result.failed_count(),
            3,
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
                    None,
                )
                .await;
                assert_eq!(result.failed_count(), 1);
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
            None,
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
        use deps_core::Registry;

        let registry: Arc<dyn Registry> = Arc::new(deps_core::test_util::MockRegistry::new());
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
            None,
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
            None,
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
            None,
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
            result.failed_count(),
            2,
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
            None,
        )
        .await;

        assert!(result.versions.is_empty());
        assert_eq!(
            result.fetch_failed,
            HashMap::from([(PackageName::new("slow-fallback"), FetchFailure::Transient)])
        );
        assert_eq!(result.failed_count(), 1);
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
            None,
        )
        .await;

        let err = result
            .failure_message()
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
            None,
        )
        .await;

        assert!(
            result.fetch_failed.is_empty(),
            "not-found errors must never be recorded in fetch_failed"
        );
        let err = result
            .failure_message()
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
            None,
        )
        .await;

        assert_eq!(
            result.failed_count(),
            3,
            "all 3 packages must count toward failed_count"
        );
        let err = result
            .failure_message()
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
        use deps_core::test_util::MockVersion;
        use deps_core::{Metadata, Version};
        use std::any::Any;
        use std::sync::atomic::{AtomicUsize, Ordering};

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
                                Box::new(MockVersion::new(*v).yanked(*y)) as Box<dyn Version>
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
                    Ok(outcome
                        .map(|(v, y)| Box::new(MockVersion::new(v).yanked(y)) as Box<dyn Version>))
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
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

        /// Dedicated registry (not the shared `MockRegistry`, whose `latest_fallback` can
        /// only express `Ok(Some(_))`/`Ok(None)`): the initial `get_versions` fetch succeeds
        /// with an all-yanked list (forcing the `get_latest_matching` fallback), and that
        /// fallback then genuinely errors — exercising `PackageOutcome::yanked` being `Some`
        /// alongside `PackageStatus::Failed` (issue #1470's own doc rationale for keeping the
        /// two independent, previously untested).
        struct YankedThenFallbackErrorRegistry;

        impl Registry for YankedThenFallbackErrorRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockVersion::new("1.0.0").yanked(true)) as Box<dyn Version>
                    ])
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
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::CacheError(
                        "mock fallback failure".to_string(),
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

            fn reports_yanked(&self) -> bool {
                true
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[tokio::test]
        async fn fallback_error_does_not_suppress_an_already_found_yanked_in_use_version() {
            let mut in_use = HashMap::new();
            in_use.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);

            let result = fetch_latest_versions_parallel(
                Arc::new(YankedThenFallbackErrorRegistry),
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
                None,
            )
            .await;

            assert!(
                result.versions.is_empty(),
                "the fallback errored, so no version was resolved"
            );
            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&(ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked)),
                "the yanked in-use finding must survive even though the fallback pick failed"
            );
            assert_eq!(
                result.fetch_failed.get(&PackageName::new("pkg")),
                Some(&FetchFailure::Transient)
            );
            assert_eq!(result.failed_count(), 1);
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
                None,
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
                None,
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
                None,
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
                None,
            )
            .await;

            assert!(result.yanked_versions.is_empty());
            assert_eq!(result.failed_count(), 1);
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
                None,
            )
            .await;

            assert!(result.yanked_versions.is_empty());
            assert_eq!(result.failed_count(), 1);
            assert!(result.versions.is_empty());
        }
    }

    /// #205: the `fetch_latest_versions_parallel` wiring that derives `FetchResult::deprecations`
    /// from the `resolved`/"latest" pick, self-contained rather than extending
    /// `yanked_check_tests`'s shared `MockRegistry`/`FetchOutcome` (whose tuple shape has
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
                None,
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
                None,
            )
            .await;

            assert!(result.deprecations.is_empty());
        }
    }

    /// Spec 074 FR-003/FR-005: the fetch-level GOSSIP-cooldown filter and its attribution
    /// field, exercised through the public [`fetch_latest_versions_parallel`] entry point
    /// rather than the private [`fetch_and_classify_package`] directly.
    mod gossip_cooldown_filter_tests {
        use super::*;
        use deps_core::test_util::{MockVersion, stub_gossip_findings};
        use deps_core::{
            GossipCooldown, GossipRiskLevel, Metadata, PublishTime, Registry, Version,
        };
        use std::any::Any;

        /// Returns a fixed, newest-first version list regardless of the queried package name.
        ///
        /// `fallback`, when set, is what `get_latest_matching` (the `get_latest_matching_from`
        /// registry endpoint the fetch loop falls back to when the list-based pick comes up
        /// empty) returns — used by the S1-residual test to model deps.dev's cooldown being
        /// silently bypassed when GOSSIP excludes the sole candidate and no in-use version
        /// protects it (spec 074 §6's documented, not-fixed residual gap).
        struct FixedListRegistry {
            versions: Vec<&'static str>,
            fallback: Option<&'static str>,
            /// When set, `select_latest_matching` rejects any version string containing `-`
            /// (a bare stand-in for a prerelease marker) — mirrors an ecosystem's own
            /// selection rules refusing to pick a prerelease as "latest" (Go's
            /// `select_latest_matching_impl`, registry.rs:926), used to model the round-2 S1
            /// scenario where a floor-filtered candidate set still yields no pick.
            reject_prerelease: bool,
            /// Counts calls to `get_latest_matching` (the `get_latest_matching_from` fallback
            /// endpoint) — used to assert it is never invoked as a consequence of GOSSIP's
            /// own filtering (round-2 S1 closure).
            fallback_calls: std::sync::atomic::AtomicUsize,
        }

        impl FixedListRegistry {
            fn new(versions: Vec<&'static str>) -> Self {
                Self {
                    versions,
                    fallback: None,
                    reject_prerelease: false,
                    fallback_calls: std::sync::atomic::AtomicUsize::new(0),
                }
            }

            fn with_fallback(versions: Vec<&'static str>, fallback: &'static str) -> Self {
                Self {
                    versions,
                    fallback: Some(fallback),
                    reject_prerelease: false,
                    fallback_calls: std::sync::atomic::AtomicUsize::new(0),
                }
            }

            fn with_prerelease_rejection(versions: Vec<&'static str>) -> Self {
                Self {
                    versions,
                    fallback: None,
                    reject_prerelease: true,
                    fallback_calls: std::sync::atomic::AtomicUsize::new(0),
                }
            }

            fn fallback_call_count(&self) -> usize {
                self.fallback_calls
                    .load(std::sync::atomic::Ordering::SeqCst)
            }
        }

        impl Registry for FixedListRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let versions = self.versions.clone();
                Box::pin(async move {
                    Ok(versions
                        .into_iter()
                        .map(|v| Box::new(MockVersion::new(v)) as Box<dyn Version>)
                        .collect())
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                // Exercised only if the list-based pick finds nothing — not GOSSIP-aware,
                // exactly like the real `get_latest_matching_from` endpoints this models.
                self.fallback_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let fallback = self.fallback;
                Box::pin(async move {
                    Ok(fallback.map(|v| Box::new(MockVersion::new(v)) as Box<dyn Version>))
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
                _req: &VersionReq,
                _selection_context: &SelectionContext,
            ) -> Option<usize> {
                if self.reject_prerelease {
                    versions
                        .iter()
                        .position(|v| !v.version_string().as_str().contains('-'))
                } else if versions.is_empty() {
                    None
                } else {
                    // Mirrors every real registry's contract: the list is already
                    // newest-first, so the first surviving entry (post-GOSSIP-filter) is
                    // "latest".
                    Some(0)
                }
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn active_cooldown() -> GossipCooldown {
            GossipCooldown::new(
                PublishTime::from_unix_secs(i64::MAX / 2),
                GossipRiskLevel::High,
            )
        }

        fn expired_cooldown() -> GossipCooldown {
            GossipCooldown::new(PublishTime::from_unix_secs(1), GossipRiskLevel::High)
        }

        async fn fetch_pkg(
            registry: Arc<FixedListRegistry>,
            in_use: Vec<&'static str>,
            gossip: HashMap<PackageName, deps_core::GossipFindings>,
        ) -> Option<PackageVersions> {
            let registry: Arc<dyn Registry> = registry;
            let mut in_use_map = HashMap::new();
            if !in_use.is_empty() {
                in_use_map.insert(
                    PackageName::new("pkg"),
                    in_use.into_iter().map(String::from).collect(),
                );
            }
            let result = fetch_latest_versions_parallel(
                registry,
                with_registry_source(vec![PackageName::new("pkg")]),
                &in_use_map,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                &SelectionContext::none(),
                Some(&gossip),
            )
            .await;
            result.versions.get(&PackageName::new("pkg")).cloned()
        }

        /// GOSSIP-only exclusion, floor-protected (round 2): a real in-use version (`1.0.0`)
        /// provides the protect floor, the newer registry-latest (`2.0.0`) is flagged with an
        /// active cooldown, so the floor's own version wins, and the attribution field names
        /// the excluded version (FR-005). The minimal 2-entry complement to
        /// `safe_intermediate_release_above_the_floor_is_picked`'s 3-entry case.
        #[tokio::test]
        async fn active_cooldown_on_the_latest_version_excludes_it() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("2.0.0", Some(active_cooldown())),
            );

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec!["1.0.0"],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(versions.latest.as_str(), "1.0.0");
            assert_eq!(
                versions
                    .gossip_excluded_version
                    .as_ref()
                    .map(ConcreteVersion::as_str),
                Some("2.0.0")
            );
        }

        /// Neither: no GOSSIP finding for this package at all — a no-op.
        #[tokio::test]
        async fn no_finding_for_package_is_a_no_op() {
            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec![],
                HashMap::new(),
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(versions.latest.as_str(), "2.0.0");
            assert!(versions.gossip_excluded_version.is_none());
        }

        /// A finding with no cooldown at all (e.g. only a `low_usage` signal) is a no-op —
        /// mirrors [`GossipCooldown::is_active`]'s contract of only ever gating on a `Some`
        /// cooldown.
        #[tokio::test]
        async fn finding_without_a_cooldown_is_a_no_op() {
            let mut gossip = HashMap::new();
            gossip.insert(PackageName::new("pkg"), stub_gossip_findings("2.0.0", None));

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec![],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(versions.latest.as_str(), "2.0.0");
            assert!(versions.gossip_excluded_version.is_none());
        }

        /// An expired cooldown (`end` in the past) is a no-op — `GossipCooldown::is_active`
        /// returns `false`.
        #[tokio::test]
        async fn expired_cooldown_is_a_no_op() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("2.0.0", Some(expired_cooldown())),
            );

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec![],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(versions.latest.as_str(), "2.0.0");
            assert!(versions.gossip_excluded_version.is_none());
        }

        /// Version-string mismatch: GOSSIP's flagged version isn't in this registry's list at
        /// all (deps.dev's view of "latest" lagging or leading the registry) — treated as no
        /// signal (spec 074 edge case table), never a fuzzy fallback match.
        #[tokio::test]
        async fn version_string_mismatch_is_a_no_op() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("3.0.0", Some(active_cooldown())),
            );

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec![],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(versions.latest.as_str(), "2.0.0");
            assert!(versions.gossip_excluded_version.is_none());
        }

        /// **C1 regression** (spec 074 round-1 critique): the in-use/already-declared version
        /// is itself the one GOSSIP flags, and it is also the true registry-latest. The
        /// protect floor covers this version's own position, so the exclusion is fully
        /// neutralized — the pick must stay exactly what it already was, `deps-cli update`
        /// must never see a downgrade target, and no attribution is set (nothing was actually
        /// held back).
        #[tokio::test]
        async fn in_use_version_itself_flagged_neutralizes_the_exclusion() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("2.0.0", Some(active_cooldown())),
            );

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["2.0.0", "1.0.0"])),
                vec!["2.0.0"],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(
                versions.latest.as_str(),
                "2.0.0",
                "must never regress below the already-declared/in-use version"
            );
            assert!(
                versions.gossip_excluded_version.is_none(),
                "the floor neutralized the exclusion — nothing was actually held back"
            );
        }

        /// **T2** (spec 074 round-1 edge case table): the in-use version is older and safe,
        /// but GOSSIP flags only the newest release, while a safe intermediate release exists
        /// above the protect floor. The flagged release alone is excluded; the safe
        /// intermediate release is picked, never the in-use version itself (this is forward
        /// progress, not a no-op).
        #[tokio::test]
        async fn safe_intermediate_release_above_the_floor_is_picked() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("3.0.0", Some(active_cooldown())),
            );

            let versions = fetch_pkg(
                Arc::new(FixedListRegistry::new(vec!["3.0.0", "2.0.0", "1.0.0"])),
                vec!["1.0.0"],
                gossip,
            )
            .await
            .expect("pkg must resolve");

            assert_eq!(
                versions.latest.as_str(),
                "2.0.0",
                "the safe intermediate release must win, not the flagged 3.0.0 nor a regression to the in-use 1.0.0"
            );
            assert_eq!(
                versions
                    .gossip_excluded_version
                    .as_ref()
                    .map(ConcreteVersion::as_str),
                Some("3.0.0")
            );
        }

        /// **C1b** (spec 074 round 2): no in-use version is found in the fetched list at all —
        /// the common case for a range requirement with no lockfile (a fresh dependency add,
        /// Cargo's `AlwaysRange` policy, an unlocked npm/PyPI range) — and GOSSIP flags the
        /// sole list-based candidate. There is no floor to construct any protection from, so
        /// round 2 makes this a **deliberate no-op**: GOSSIP excludes nothing this fetch, the
        /// unfiltered pick is used exactly as it would be without this feature, and the
        /// network fallback (`get_latest_matching_from`) is never even invoked — this
        /// replaces round 1's "documented residual fallback-bypass" premise, which
        /// independent re-verification found was actually the common case, not a rare edge.
        ///
        /// This test hand-feeds an empty `in_use` to [`fetch_pkg`] rather than going through
        /// the real `prepare_fetch`/`collect_in_use_versions` path (`classify/resolved.rs`) —
        /// that upstream function's own, already-existing test suite
        /// (`collect_in_use_versions_skips_non_concrete_requirement_with_no_lockfile`,
        /// `classify/osv.rs`) independently proves it returns an empty map for exactly this
        /// scenario (Cargo `AlwaysRange`, a bare/range requirement, no lockfile). Composed
        /// together, the two suites cover the full C1b path end to end without needing a
        /// third, heavier integration test through a real ecosystem parser — flagged in the
        /// handoff in case an integration test is still wanted for extra confidence.
        #[tokio::test]
        async fn no_in_use_version_at_all_is_a_deliberate_no_op() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("2.0.0", Some(active_cooldown())),
            );

            let registry = Arc::new(FixedListRegistry::with_fallback(vec!["2.0.0"], "2.0.0"));
            let versions = fetch_pkg(Arc::clone(&registry), vec![], gossip)
                .await
                .expect("pkg must resolve from the unfiltered list-based pick");

            assert_eq!(
                versions.latest.as_str(),
                "2.0.0",
                "no floor exists, so GOSSIP must not exclude anything this run"
            );
            assert!(
                versions.gossip_excluded_version.is_none(),
                "nothing was actually excluded — no attribution"
            );
            assert_eq!(
                registry.fallback_call_count(),
                0,
                "the network fallback must never be invoked as a consequence of GOSSIP's own \
                 filtering when the unfiltered list-based pick already succeeded"
            );
        }

        /// **S1, round 2**: a real protect floor exists (in-use `1.0.0-rc.1`), but after
        /// filtering out the flagged stable release above it, only a prerelease remains —
        /// which this mock registry's own selection rules (mirroring Go's
        /// `select_latest_matching_impl` refusing to pick a prerelease as "latest") reject.
        /// The filtered pick therefore comes back `None` for a reason unrelated to "no floor"
        /// at all. THE SYSTEM must fall back to the unfiltered pick, set no attribution, and
        /// never invoke the network fallback on GOSSIP's account.
        #[tokio::test]
        async fn floor_exists_but_ecosystem_selection_rejects_the_remainder_is_a_no_op() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("1.0.0", Some(active_cooldown())),
            );

            let registry = Arc::new(FixedListRegistry::with_prerelease_rejection(vec![
                "1.0.0",
                "1.0.0-rc.1",
            ]));
            let versions = fetch_pkg(Arc::clone(&registry), vec!["1.0.0-rc.1"], gossip)
                .await
                .expect("pkg must resolve via the recovered unfiltered pick");

            assert_eq!(
                versions.latest.as_str(),
                "1.0.0",
                "the ecosystem rejected the filtered remainder (an all-prerelease set), so the \
                 unfiltered pick must be used instead"
            );
            assert!(
                versions.gossip_excluded_version.is_none(),
                "nothing was actually excluded from the final pick — no attribution"
            );
            assert_eq!(
                registry.fallback_call_count(),
                0,
                "the network fallback must never be invoked as a consequence of GOSSIP's own \
                 filtering — only when the unfiltered pick itself finds nothing, which it did not"
            );
        }

        /// **S4** (spec 074 round 3): the floor itself survives filtering (its own position
        /// always satisfies `idx >= floor`) but is rejected by the ecosystem's own selection
        /// rules (an in-use prerelease), and an even-older stable release exists below it. A
        /// filtered pick that lands there would be a genuine downgrade below the floor —
        /// distinct from `floor_exists_but_ecosystem_selection_rejects_the_remainder_is_a_no_op`,
        /// where filtering leaves nothing selectable at all. THE SYSTEM must treat the floor as
        /// a hard lower bound on the *final* pick, not merely on what gets excluded: recover
        /// the unfiltered pick instead of ever accepting a pick older than the floor.
        #[tokio::test]
        async fn filtered_pick_below_the_floor_is_rejected_in_favor_of_the_unfiltered_pick() {
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                stub_gossip_findings("1.0.0", Some(active_cooldown())),
            );

            let registry = Arc::new(FixedListRegistry::with_prerelease_rejection(vec![
                "1.0.0",
                "1.0.0-rc.1",
                "0.9.0",
            ]));
            let versions = fetch_pkg(Arc::clone(&registry), vec!["1.0.0-rc.1"], gossip)
                .await
                .expect("pkg must resolve via the recovered unfiltered pick");

            assert_eq!(
                versions.latest.as_str(),
                "1.0.0",
                "must never regress to 0.9.0 — a downgrade below the floor (1.0.0-rc.1) — even \
                 though 0.9.0 is a legitimate, ecosystem-selectable filtered pick"
            );
            assert!(
                versions.gossip_excluded_version.is_none(),
                "no attribution — the recovered pick is identical to the unfiltered one"
            );
            assert_eq!(
                registry.fallback_call_count(),
                0,
                "the network fallback must never be invoked as a consequence of GOSSIP's own filtering"
            );
        }
    }

    /// Spec 075 (`deps-cli update` cooldown fallback): `PackageVersions::cooldown_fallback`
    /// computation (FR-001/FR-002), tested through the same `fetch_latest_versions_parallel`
    /// entry point `gossip_cooldown_filter_tests` uses for its sibling spec 074 feature.
    mod cooldown_fallback_tests {
        use super::*;
        use deps_core::test_util::MockVersion;
        use deps_core::{PublishTime, Registry, Version};
        use std::any::Any;

        /// A fixed, newest-first version list — `select_latest_matching` mirrors a real
        /// ecosystem's own selection rules (skip yanked/prerelease), same contract
        /// `gossip_cooldown_filter_tests::FixedListRegistry` documents for its own mock.
        struct FixedRegistry(Vec<MockVersion>);

        impl Registry for FixedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let versions: Vec<Box<dyn Version>> = self
                    .0
                    .iter()
                    .cloned()
                    .map(|v| Box::new(v) as Box<dyn Version>)
                    .collect();
                Box::pin(async move { Ok(versions) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>,
            > {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &VersionReq,
                _selection_context: &SelectionContext,
            ) -> Option<usize> {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution() && !v.is_prerelease())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        async fn fetch_pkg(
            versions: Vec<MockVersion>,
            in_use: Vec<&'static str>,
            cooldown_secs: u64,
        ) -> Option<PackageVersions> {
            fetch_pkg_with_registry(Arc::new(FixedRegistry(versions)), in_use, cooldown_secs).await
        }

        /// Shared by [`fetch_pkg`] and the finding-4 regression test below, which needs a
        /// registry other than [`FixedRegistry`].
        async fn fetch_pkg_with_registry(
            registry: Arc<dyn Registry>,
            in_use: Vec<&'static str>,
            cooldown_secs: u64,
        ) -> Option<PackageVersions> {
            let mut in_use_map = HashMap::new();
            if !in_use.is_empty() {
                in_use_map.insert(
                    PackageName::new("pkg"),
                    in_use.into_iter().map(String::from).collect(),
                );
            }
            let result = fetch_latest_versions_parallel(
                registry,
                with_registry_source(vec![PackageName::new("pkg")]),
                &in_use_map,
                None,
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(cooldown_secs),
                },
                5,
                10,
                &SelectionContext::none(),
                None,
            )
            .await;
            result.versions.get(&PackageName::new("pkg")).cloned()
        }

        /// A registry whose list-based `select_latest_matching` rejects the ACTUAL fetched
        /// [`Version`] objects it's asked to pick from (mirroring Go's real `/@v/list`-vs-
        /// `/@latest` split, issue #1551 finding 4's tester regression): the list-based pick can
        /// find nothing over the genuine fetched entries even though a cooldown-cleared,
        /// ecosystem-safe candidate exists among them, and the network `get_latest_matching`
        /// fallback still resolves a real `latest`.
        ///
        /// `compute_cooldown_fallback`'s own cleared-subset search re-ranks through synthetic
        /// `CooldownCandidate` values (this file's own type, never [`MockVersion`]), so this
        /// mock discriminates by concrete type via `as_any()` — refusing outright whenever ANY
        /// candidate downcasts to [`MockVersion`] (the full, unfiltered list), falling back to
        /// the ordinary yanked/prerelease rule otherwise (the re-ranked cleared subset) — to
        /// reproduce the real divergence without depending on `deps-go`'s own internals.
        struct NoListPickRegistry(Vec<MockVersion>);

        impl Registry for NoListPickRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let versions: Vec<Box<dyn Version>> = self
                    .0
                    .iter()
                    .cloned()
                    .map(|v| Box::new(v) as Box<dyn Version>)
                    .collect();
                Box::pin(async move { Ok(versions) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let resolved = self.0.first().cloned();
                Box::pin(async move { Ok(resolved.map(|v| Box::new(v) as Box<dyn Version>)) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>,
            > {
                Box::pin(async move { Ok(vec![]) })
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &VersionReq,
                _selection_context: &SelectionContext,
            ) -> Option<usize> {
                if versions
                    .iter()
                    .any(|v| v.as_any().downcast_ref::<MockVersion>().is_some())
                {
                    return None;
                }
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution() && !v.is_prerelease())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Spec 075 SC-003/FR-001 (S1 repro): the newest cooldown-cleared candidate (1.1.0) is
        /// yanked — the ecosystem-safety guard rejects it with no retry down to a further,
        /// also-cooldown-cleared candidate (1.0.0, itself yanked and the in-use floor).
        #[tokio::test]
        async fn yanked_top_ranked_cleared_candidate_yields_no_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60); // within cooldown
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60); // cleared

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0")
                    .with_published_at(old)
                    .yanked(true),
                MockVersion::new("1.0.0")
                    .with_published_at(old)
                    .yanked(true),
            ];

            let package_versions = fetch_pkg(versions, vec!["1.0.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            assert!(
                package_versions.cooldown_fallback.is_none(),
                "a yanked top-ranked cooldown-cleared candidate must not be recovered by \
                 retrying further down the list: {:?}",
                package_versions.cooldown_fallback
            );
        }

        /// The positive case sanity check: with the same shape but the newest cleared
        /// candidate NOT yanked, a fallback is computed.
        #[tokio::test]
        async fn cleared_safe_candidate_above_the_floor_is_the_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
                MockVersion::new("1.0.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg(versions, vec!["1.0.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            let fallback = package_versions
                .cooldown_fallback
                .expect("a safe, cooldown-cleared, above-floor candidate must be recovered");
            assert_eq!(fallback.version.as_str(), "1.1.0");
        }

        /// Issue #1564 repro (crates.io `bevy_brp_mcp`-shaped): a prerelease newest (excluded),
        /// a within-cooldown stable `latest` candidate, a cleared candidate one patch below it,
        /// and the in-use floor. Empirically confirms/refutes the reporter's hypothesis that
        /// `compute_cooldown_fallback` itself never finds a fallback here — it does; the actual
        /// bug (fixed separately) was downstream in `deps-cli update`'s own
        /// `fallback_satisfies_requirement` planner guard, not this engine-level computation.
        #[tokio::test]
        async fn permissive_range_repro_1564_still_computes_the_cleared_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60); // within cooldown
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60); // cleared

            let versions = vec![
                MockVersion::new("0.23.0-rc.1")
                    .with_published_at(recent)
                    .with_prerelease(true),
                MockVersion::new("0.22.8").with_published_at(recent),
                MockVersion::new("0.22.7").with_published_at(old),
                MockVersion::new("0.22.6").with_published_at(old), // in-use floor
            ];

            let package_versions = fetch_pkg(versions, vec!["0.22.6"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            let fallback = package_versions
                .cooldown_fallback
                .expect("a safe, cooldown-cleared, above-floor candidate must be recovered");
            assert_eq!(fallback.version.as_str(), "0.22.7");
        }

        /// Fix-cycle item 5/S5: the newest cooldown-cleared candidate by publish date is a
        /// prerelease (a canary/nightly a frequent publisher ships between stable releases).
        /// Ranking through `registry.select_latest_matching` over the cooled subset — instead
        /// of the old "first cleared entry by raw list position, no retry" — naturally skips
        /// it and lands on the next cooled, stable release, closing the exact starvation
        /// scenario FR-001 exists to prevent (a naive by-date pick would have rejected the
        /// prerelease with no retry and returned `None`).
        #[tokio::test]
        async fn prerelease_top_ranked_by_date_is_skipped_for_the_next_cooled_stable_release() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);
            let older = PublishTime::from_unix_secs(now.as_unix_secs() - 31 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("2.0.0").with_published_at(recent), // fresh, not cooled
                MockVersion::new("2.0.0-rc.1")
                    .with_published_at(old)
                    .with_prerelease(true), // cooled, but a prerelease
                MockVersion::new("1.9.0").with_published_at(older),  // cooled, stable
                MockVersion::new("1.8.0").with_published_at(older),  // in-use floor
            ];

            let package_versions = fetch_pkg(versions, vec!["1.8.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            let fallback = package_versions.cooldown_fallback.expect(
                "the prerelease must be skipped in favor of the next cooled stable release",
            );
            assert_eq!(fallback.version.as_str(), "1.9.0");
        }

        /// Spec 076 FR-017/FR-018 (inverts spec 075's
        /// `no_in_use_version_yields_no_fallback_even_with_a_safe_cleared_candidate`, SC-021):
        /// no lockfile-resolved in-use version now classifies as `InUseFloor::Absent`, which
        /// computes the fallback with NO positional floor rather than yielding `None` — the
        /// #1544 fix this spec exists to deliver. The engine-level candidate is unconditional;
        /// `deps-cli`'s `fallback_edit_excludes_newer` guard (spec 076 FR-023), not this floor,
        /// is what fails closed for an auto-following ecosystem's in-range case.
        #[tokio::test]
        async fn no_in_use_version_yields_a_fallback_when_a_safe_cleared_candidate_exists() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg(versions, Vec::new(), cooldown_secs)
                .await
                .expect("pkg must resolve");

            let fallback = package_versions
                .cooldown_fallback
                .expect("Absent floor must no longer suppress a safe, cleared candidate");
            assert_eq!(fallback.version.as_str(), "1.1.0");
        }

        /// Spec 076 FR-018/SC-010 (round-1 critic M2): a partial in-use-version match — one
        /// entry locatable in `versions`, one not (e.g. a mixed Go pseudo-version alongside a
        /// resolvable one) — classifies as `InUseFloor::Unlocatable`, which yields NO fallback
        /// at all, stricter than the prior `.min()?` behavior that silently floored at only the
        /// locatable entry and ignored the unplaceable one.
        #[tokio::test]
        async fn partial_in_use_version_match_yields_no_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg(
                versions,
                vec!["1.1.0", "not-a-resolvable-pseudo-version"],
                cooldown_secs,
            )
            .await
            .expect("pkg must resolve");

            assert!(
                package_versions.cooldown_fallback.is_none(),
                "a partial in-use-version match (one locatable, one not) must fail closed, not \
                 silently floor at the locatable entry: {:?}",
                package_versions.cooldown_fallback
            );
        }

        /// Spec 076 SC-018/M5 (fix-cycle, tester gap): a non-normalized lockfile-resolved
        /// in-use pin (e.g. a bare `1.0` against the registry's own `1.0.0` spelling) fails
        /// string equality in `in_use_floor`, landing in `InUseFloor::Unlocatable` — no
        /// fallback, fail closed. `in_use_floor` compares raw version strings and has no
        /// ecosystem-specific normalization step, so this single test proves the mechanism for
        /// every `Concrete`-policy ecosystem's non-normalized-pin case uniformly (spec 076
        /// SC-018's per-ecosystem requirement is satisfied by construction here, not by
        /// duplicating this fixture 7 times — `InUseFloor` is `deps-engine`-private and never
        /// sees which ecosystem produced the in-use string).
        #[tokio::test]
        async fn non_normalized_in_use_pin_yields_no_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
                MockVersion::new("1.0.0").with_published_at(old),
            ];

            // The lockfile/manifest pin is the non-normalized bare "1.0" — the registry's own
            // list spells the same release "1.0.0". `in_use_floor` does raw string equality,
            // so this never resolves to a position.
            let package_versions = fetch_pkg(versions, vec!["1.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            assert!(
                package_versions.cooldown_fallback.is_none(),
                "a non-normalized in-use pin must fail closed (Unlocatable), never silently \
                 treated as Absent or matched loosely: {:?}",
                package_versions.cooldown_fallback
            );
        }

        /// Tester regression (issue #1551 finding 4): when the list-based pick finds nothing
        /// (`unfiltered_pick_idx` is `None`, e.g. Go's `/@v/list` never enumerating
        /// pseudo-versions) but the network `get_latest_matching` fallback still resolves a
        /// real `latest`, the full floor+cleared-candidates search must still run — a `None`
        /// pick must never be treated as "cleared" and short-circuit to no fallback.
        #[tokio::test]
        async fn unknown_list_based_pick_still_runs_the_full_fallback_search() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60); // within cooldown
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60); // cleared

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
                MockVersion::new("1.0.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg_with_registry(
                Arc::new(NoListPickRegistry(versions)),
                vec!["1.0.0"],
                cooldown_secs,
            )
            .await
            .expect("pkg must resolve via the get_latest_matching network fallback");

            assert_eq!(
                package_versions.latest.as_str(),
                "1.2.0",
                "latest must come from the get_latest_matching fallback, not the list-based pick"
            );
            let fallback = package_versions.cooldown_fallback.expect(
                "an unknown list-based pick must still run the full search and find the \
                 cooldown-cleared, above-floor candidate",
            );
            assert_eq!(fallback.version.as_str(), "1.1.0");
        }

        /// Spec 076 SC-012 (T001): confirms #1553's shipped fetch-time gate — a known
        /// unfiltered pick already `Cleared` by [`deps_core::lsp_helpers::cooldown_precedence`]
        /// skips the full fallback scan (`cooldown_fallback: None`), even though an older,
        /// separately cooldown-cleared candidate exists below it.
        #[tokio::test]
        async fn known_cleared_unfiltered_pick_yields_no_fallback() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60); // cleared

            // `latest` (1.2.0) is itself already cooldown-cleared, so the gate must skip the
            // scan entirely rather than compute a (redundant) fallback below it.
            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(old),
                MockVersion::new("1.1.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg(versions, vec!["1.1.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");

            assert!(
                package_versions.cooldown_fallback.is_none(),
                "a known, already-cleared unfiltered pick must skip the fallback scan: {:?}",
                package_versions.cooldown_fallback
            );
        }

        /// Spec 076 SC-013 (FR-021 gate-superset invariant, proof case "unfiltered pick is
        /// latest"): with `now_read == now_fetch` and an unchanged `cooldown_secs`, a fetch-time
        /// gate that saw `latest` as `Cleared` (no fallback stored) must never read back as
        /// `Blocked` — the fetch-time and read-time precedence share the same
        /// `cooldown_precedence` primitive and the same inputs, so they cannot diverge.
        #[tokio::test]
        async fn read_time_disposition_agrees_with_a_cleared_fetch_time_gate() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(old),
                MockVersion::new("1.1.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg(versions, vec!["1.1.0"], cooldown_secs)
                .await
                .expect("pkg must resolve");
            assert!(package_versions.cooldown_fallback.is_none());

            let disposition = deps_core::lsp_helpers::cooldown_disposition(
                &package_versions,
                &PackageName::new("pkg"),
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(cooldown_secs),
                },
                None,
                now,
            );
            assert_eq!(
                disposition,
                deps_core::lsp_helpers::CooldownDisposition::Cleared,
                "read time must agree with the fetch-time gate under unchanged inputs: {disposition:?}"
            );
        }

        /// Spec 076 SC-013 (FR-021's one permitted exception): a `cooldown_secs` narrowed
        /// between fetch and read can flip a fetch-time `Cleared` pick to read-time `Blocked` —
        /// but since the fetch-time gate skipped the scan, there is no stored fallback to
        /// unsafely surface. The outcome is a stricter skip, never an unsafe write.
        #[tokio::test]
        async fn narrowed_cooldown_window_between_fetch_and_read_yields_a_safe_skip_not_a_write() {
            let now = PublishTime::now();
            let fetch_cooldown_secs = 3 * 24 * 60 * 60;
            // Published 1 day ago: cleared under a 3-day window at fetch time, but still
            // within a narrowed 2-day window at read time.
            let one_day_ago = PublishTime::from_unix_secs(now.as_unix_secs() - 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(one_day_ago),
                MockVersion::new("1.1.0").with_published_at(one_day_ago),
            ];

            let package_versions = fetch_pkg(versions, vec!["1.1.0"], fetch_cooldown_secs)
                .await
                .expect("pkg must resolve");
            assert!(
                package_versions.cooldown_fallback.is_none(),
                "the fetch-time gate saw latest as Cleared under the wider window, so no \
                 fallback was ever computed or stored"
            );

            let narrowed_cooldown_secs = 2 * 24 * 60 * 60;
            let disposition = deps_core::lsp_helpers::cooldown_disposition(
                &package_versions,
                &PackageName::new("pkg"),
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(narrowed_cooldown_secs),
                },
                None,
                now,
            );
            match disposition {
                deps_core::lsp_helpers::CooldownDisposition::Blocked { fallback, .. } => {
                    assert!(
                        fallback.is_none(),
                        "a narrowed window must never surface a fallback the fetch-time gate \
                         never computed — that would be an unsafe write, not a stricter skip"
                    );
                }
                other => panic!("expected a stricter read-time Blocked skip, got {other:?}"),
            }
        }

        /// Spec 076 SC-013 (FR-021 gate-superset invariant, proof case "`get_latest_matching_from`
        /// branch"): when the list-based pick is unknown and `latest` is resolved via the
        /// network fallback instead, the fallback candidate the fetch-time full scan stored
        /// still agrees with the read-time disposition under unchanged inputs.
        #[tokio::test]
        async fn read_time_disposition_agrees_with_the_network_fallback_branch() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            let versions = vec![
                MockVersion::new("1.2.0").with_published_at(recent),
                MockVersion::new("1.1.0").with_published_at(old),
                MockVersion::new("1.0.0").with_published_at(old),
            ];

            let package_versions = fetch_pkg_with_registry(
                Arc::new(NoListPickRegistry(versions)),
                vec!["1.0.0"],
                cooldown_secs,
            )
            .await
            .expect("pkg must resolve via the get_latest_matching network fallback");

            let disposition = deps_core::lsp_helpers::cooldown_disposition(
                &package_versions,
                &PackageName::new("pkg"),
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(cooldown_secs),
                },
                None,
                now,
            );
            match disposition {
                deps_core::lsp_helpers::CooldownDisposition::Blocked {
                    fallback: Some(fallback),
                    ..
                } => {
                    assert_eq!(fallback.version.as_str(), "1.1.0");
                }
                other => panic!(
                    "expected read time to agree with the fetch-time-stored fallback, got {other:?}"
                ),
            }
        }

        /// Fix-cycle (tester gap, SC-013's 3rd named proof case): the "spec-074-substituted-latest"
        /// branch — the unfiltered top pick is GOSSIP-`Active` (flagged), so `fetch_and_classify_package`
        /// substitutes a floor-protected, GOSSIP-cleared filtered pick as `latest` instead. Since the
        /// RAW unfiltered pick's `cooldown_precedence` is `Blocked(Gossip)`, SC-012's short-circuit never
        /// fires (`unfiltered_pick_flagged` implies not-cleared), so the fetch-time full scan always runs
        /// here — proven directly, not by code-reading alone: the substituted `latest` ("2.0.0") is
        /// itself locally within-cooldown (fresh, no GOSSIP finding of its own), and read-time
        /// `cooldown_disposition` evaluated against THAT substituted `latest` must agree with the
        /// fetch-time-computed fallback ("1.5.0", above the "1.0.0" floor).
        #[tokio::test]
        async fn read_time_disposition_agrees_with_the_gossip_substituted_latest_branch() {
            let now = PublishTime::now();
            let cooldown_secs = 3 * 24 * 60 * 60;
            let recent = PublishTime::from_unix_secs(now.as_unix_secs() - 60);
            let old = PublishTime::from_unix_secs(now.as_unix_secs() - 30 * 24 * 60 * 60);

            // Newest-first: "3.0.0" (GOSSIP-flagged, excluded), "2.0.0" (fresh, no GOSSIP finding,
            // locally within cooldown once substituted in as `latest`), "1.5.0" (cleared, the
            // expected fallback), "1.0.0" (the in-use floor).
            let versions = vec![
                MockVersion::new("3.0.0").with_published_at(recent),
                MockVersion::new("2.0.0").with_published_at(recent),
                MockVersion::new("1.5.0").with_published_at(old),
                MockVersion::new("1.0.0").with_published_at(old),
            ];
            let mut gossip = HashMap::new();
            gossip.insert(
                PackageName::new("pkg"),
                deps_core::test_util::stub_gossip_findings(
                    "3.0.0",
                    Some(deps_core::GossipCooldown::new(
                        PublishTime::from_unix_secs(i64::MAX / 2),
                        deps_core::GossipRiskLevel::High,
                    )),
                ),
            );

            let registry: Arc<dyn Registry> = Arc::new(FixedRegistry(versions));
            let mut in_use_map = HashMap::new();
            in_use_map.insert(PackageName::new("pkg"), vec!["1.0.0".to_string()]);
            let result = fetch_latest_versions_parallel(
                registry,
                with_registry_source(vec![PackageName::new("pkg")]),
                &in_use_map,
                None,
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(cooldown_secs),
                },
                5,
                10,
                &SelectionContext::none(),
                Some(&gossip),
            )
            .await;
            let package_versions = result
                .versions
                .get(&PackageName::new("pkg"))
                .cloned()
                .expect("pkg must resolve");

            assert_eq!(
                package_versions.latest.as_str(),
                "2.0.0",
                "the GOSSIP floor-protected filter must substitute the filtered pick as latest"
            );
            assert_eq!(
                package_versions
                    .gossip_excluded_version
                    .as_ref()
                    .map(ConcreteVersion::as_str),
                Some("3.0.0")
            );
            let fetch_time_fallback = package_versions
                .cooldown_fallback
                .as_ref()
                .expect("the full scan must have run (SC-012's short-circuit cannot fire here)");
            assert_eq!(fetch_time_fallback.version.as_str(), "1.5.0");

            let disposition = deps_core::lsp_helpers::cooldown_disposition(
                &package_versions,
                &PackageName::new("pkg"),
                deps_core::freshness::FreshnessSettings::Enabled {
                    cooldown: deps_core::CooldownWindow::from_secs(cooldown_secs),
                },
                Some(&gossip),
                now,
            );
            match disposition {
                deps_core::lsp_helpers::CooldownDisposition::Blocked {
                    fallback: Some(fallback),
                    ..
                } => {
                    assert_eq!(
                        fallback.version.as_str(),
                        "1.5.0",
                        "read time, evaluated against the substituted latest, must agree with \
                         the fetch-time-computed fallback"
                    );
                }
                other => panic!(
                    "expected read time to agree with the fetch-time-stored fallback for the \
                     substituted latest, got {other:?}"
                ),
            }
        }
    }
}
