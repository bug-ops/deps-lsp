//! Registry fetch fan-out: concurrent version fetching, per-package
//! classification, and dependency-source routing for the document
//! lifecycle.

use super::diff::{
    drop_cache_for_forced_refetch, merge_deprecations_after_fetch,
    merge_no_comparable_versions_after_fetch,
};
use super::resolved::{RefetchPolicy, collect_in_use_versions};
use super::state::ServerState;
use crate::progress::{ProgressSender, RegistryProgress};
use deps_core::ConcreteVersion;
use deps_core::Deprecation;
use deps_core::Ecosystem;
use deps_core::FetchFailure;
use deps_core::PackageName;
use deps_core::PackageVersions;
use deps_core::Registry;
use deps_core::RemovalStatus;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

/// A dependency name paired with the resolved source to route its registry fetch through
/// (spec FR-001), as built by [`dedup_dependencies_by_source`].
pub(crate) type DepSources = Vec<(PackageName, deps_core::parser::DependencySource)>;

/// Pairs each distinct dependency name in `parse_result` with the source its occurrence(s)
/// resolve to, for the background registry fetch to route through
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
/// merged into `DocumentState::outcomes`' fetch-failure channel by the caller so
/// `generate_diagnostics_from_cache` reports "lookup could not be determined" rather than
/// a false "Unknown package" for a dependency that was never actually queried.
pub(crate) fn dedup_dependencies_by_source(
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
                        package = %name,
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

/// Composer's own `minimum-stability` manifest setting, when `parse_result` is a parsed
/// `composer.json` (#424 S1).
///
/// Downcasts via [`deps_core::ParseResult::as_any`] rather than widening the generic
/// `ParseResult`/`Registry` traits with an ecosystem-specific field: every other ecosystem has
/// no equivalent manifest-level stability floor, so this stays local to the one call site
/// (`fetch_latest_versions_parallel`'s caller) that needs to bridge a Composer-specific
/// manifest value into the generic `Registry::*_with_context` trait hook.
#[cfg(feature = "composer")]
pub(crate) fn composer_minimum_stability(
    parse_result: &dyn deps_core::ParseResult,
) -> Option<String> {
    parse_result
        .as_any()
        .downcast_ref::<crate::ComposerParseResult>()
        .and_then(|r| r.minimum_stability.clone())
}

/// No-op when the `composer` feature is disabled — `crate::ComposerParseResult` does not
/// exist in that build, so `parse_result` can never downcast to it.
#[cfg(not(feature = "composer"))]
pub(crate) fn composer_minimum_stability(
    _parse_result: &dyn deps_core::ParseResult,
) -> Option<String> {
    None
}

/// Result of parallel version fetching.
pub(crate) struct FetchResult {
    /// Successfully fetched versions (package -> latest + full version list)
    pub(crate) versions: HashMap<PackageName, PackageVersions>,
    /// Yanked-version findings, keyed by **raw** package name (unlike
    /// `DocumentState::outcomes`, which is normalized-keyed — see
    /// §3.1 of the design), to (the version string found yanked, its
    /// `RemovalStatus`). The status rides alongside so #205's package-level
    /// deprecation diagnostic can gate its yanked-check suppression on
    /// `AdvisoryDeprecated` specifically, never a genuine `Yanked` finding.
    /// Callers must re-key through `EcosystemFormatter::normalize_package_name`
    /// before merging into document state.
    pub(crate) yanked_versions: HashMap<PackageName, (ConcreteVersion, RemovalStatus)>,
    /// Package-level deprecation findings (issue #205), keyed by **raw** package name
    /// (same raw/normalized split as `yanked_versions` above). Derived from the
    /// `resolved`/"latest" pick in the fetch loop below, not by scanning the full
    /// `versions` list — see that loop's comments for why.
    pub(crate) deprecations: HashMap<PackageName, Deprecation>,
    /// Packages whose registry fetch errored or timed out, keyed by **raw**
    /// package name (same raw/normalized split as `yanked_versions` above).
    /// Lets diagnostic generation (#267) distinguish "the registry said this
    /// package doesn't exist" from "the registry couldn't be asked" instead
    /// of conflating both into a misleading "Unknown package" diagnostic.
    pub(crate) fetch_failed: HashMap<PackageName, FetchFailure>,
    /// Packages whose registry fetch succeeded but produced zero comparable versions
    /// (#550), keyed by **raw** package name (same raw/normalized split as
    /// `yanked_versions` above). Distinct from `fetch_failed`: the registry was
    /// successfully asked and the package demonstrably exists — it just has nothing a
    /// version-comparison rule can use — so `generate_diagnostics_from_cache` must
    /// report neither "Registry lookup failed" nor "Unknown package" for it.
    pub(crate) no_comparable_versions: HashSet<PackageName>,
    /// Number of packages whose registry fetch did not succeed, counting both a genuine
    /// fetch failure (timeout, error — recorded in `fetch_failed` above) and a not-found
    /// lookup (the registry answered "no such package", never recorded in `fetch_failed`,
    /// see #267 C1). Only the `fetch_failed` subset produces an inline "Registry lookup
    /// failed" diagnostic, so this count can exceed `fetch_failed.len()` (#276 S2, #490).
    pub(crate) failed_count: usize,
    /// First actionable error message (shown to user via `window/showMessage`)
    pub(crate) first_error: Option<String>,
    /// SPDX license identifier(s) for the resolved/"latest" pick, for every package
    /// whose `Version::license` on the already-fetched version-list entry is
    /// non-empty (issue #660/#661 tier-1 backfill) — today, only the native-list
    /// ecosystems (PyPI, Composer) ever populate this; every other ecosystem's
    /// `Version::license` default is empty, so this map stays empty for them.
    /// Deliberately *not* threaded into [`PackageVersions`] itself (that type is
    /// constructed identically across ~40 call sites throughout the workspace,
    /// including files outside this crate's ownership for this change) —
    /// `merge_registry_fetch_result` merges this map directly into
    /// [`crate::document::DocumentState::licenses`] instead, the same map the tier-3
    /// background pre-fetch (`run_license_prefetch`) already populates for
    /// Dart/Swift/Gradle/Deno. A merge (not replace), since the two sources are
    /// always disjoint per document (one ecosystem per document) but run as
    /// independent, non-ordered background tasks.
    pub(crate) licenses: HashMap<PackageName, Vec<String>>,
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
#[allow(
    clippy::too_many_arguments,
    reason = "internal (non-pub) call-site-controlled fetch tuning + ecosystem-context \
              parameters; grouping into a config struct would only move, not reduce, the \
              per-call-site churn across this module's ~15 production and test call sites"
)]
pub(crate) async fn fetch_latest_versions_parallel(
    registry: Arc<dyn Registry>,
    package_sources: DepSources,
    in_use: &HashMap<PackageName, Vec<String>>,
    progress_sender: Option<ProgressSender>,
    freshness: deps_core::freshness::FreshnessSettings,
    timeout_secs: u64,
    max_concurrent: usize,
    minimum_stability: Option<&str>,
) -> FetchResult {
    use futures::stream::{self, StreamExt};
    use std::time::Duration;

    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    // Separate from `first_error` (#480): a not-found error is deliberately excluded
    // from `fetch_failed` below (it isn't evidence of a registry-side problem), but
    // without this, whichever concurrent fetch happened to finish first could still win
    // the `first_error` race and put a misleading "not found" message in the one-time
    // toast even when the batch's real, actionable failure is e.g. a rate limit hit by
    // 20 other dependencies. Any error that *does* count toward `fetch_failed`
    // (including a timeout) always wins the toast over a not-found, regardless of
    // finishing order; only a not-found-only batch falls back to `first_error`.
    //
    // Unlike `first_error`, this is not a shared `Arc<Mutex>` written from inside the
    // four match arms below — each task instead returns its own `(name, message)` via
    // `failed_name`, and the priority error is derived by folding those in completion
    // order once every task has finished (see the loop below). `fetch_failed` and the
    // priority error are thereby always in sync by construction: both come from the
    // same `failed_name` value, so a future edit to one can no longer silently drift
    // from the other, which two independently hand-maintained writes could (#480).
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
                    minimum_stability,
                    check_yanked,
                    &fetched,
                    &failed,
                    &first_error,
                    progress_sender.as_ref(),
                )
                .await
            }
        })
        // `.max(1)`: `CacheConfig.max_concurrent_fetches` is a `pub` field, so an in-crate
        // direct field assignment (see the test setup at `server.rs:1680`) bypasses
        // `with_max_concurrent_fetches`'s own clamp; this is defence-in-depth against a
        // future in-crate caller doing the same with `0`. `buffer_unordered(0)` never
        // polls its source stream — it returns `Pending` forever instead of erroring,
        // hanging every fetch through this document indefinitely (issue #833).
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
/// The license entry specifically comes from `select_latest_matching_with_context`'s
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
    minimum_stability: Option<&str>,
    check_yanked: bool,
    fetched: &std::sync::atomic::AtomicUsize,
    failed: &std::sync::atomic::AtomicUsize,
    first_error: &std::sync::Mutex<Option<String>>,
    progress_sender: Option<&ProgressSender>,
) -> PackageFetchOutcome {
    // Single round trip: the full version list is fetched once, and "latest"
    // is a pure in-memory pick over it (`Registry::select_latest_matching`) —
    // no second registry call, so the retained full list costs nothing extra
    // over the network (see `PackageVersions`). `get_versions_from` (source-
    // aware, spec FR-001) rather than `get_versions`: this populates
    // `published_at` for registries that support it (#339), matching hover's
    // existing freshness-aware call, AND routes a resolved
    // `DependencySource::AlternateRegistry` to its own index instead of the
    // ecosystem's default registry — registries with no override forward
    // straight to `get_versions` at zero extra cost either way.
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
            // Retained alongside `available` so `generate_diagnostics_from_cache`
            // can flag a requirement satisfiable only by a yanked version — see
            // `PackageVersions::yanked`. Gated on `check_yanked`: a registry that
            // cannot answer `removal_status()` (§#298) must not populate this list
            // with an untrustworthy always-`Available` signal. Carries each
            // entry's own `RemovalStatus` (#437) so the #247 diagnostic path can
            // gate its package-level-deprecation suppression on `AdvisoryDeprecated`
            // specifically, never on a genuine `Yanked` finding.
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
            // `.get(idx)` rather than `versions[idx]`: `select_latest_matching`
            // is a public `Registry` trait method, so an out-of-tree
            // implementation returning a stale index must not panic this task.
            // `_with_context` (not the plain method) so a registry with
            // manifest-level stability state (Composer's `minimum-stability`,
            // #424 S1) can apply it — every other registry's default
            // implementation just forwards to the plain method unchanged.
            let resolved = if let Some(v) = registry
                .select_latest_matching_with_context(&versions, wildcard_req, minimum_stability)
                .and_then(|idx| versions.get(idx))
            {
                let latest = v.version_string().clone();
                tracing::debug!(package = %name, version = %latest, "fetched");
                Some((
                    latest,
                    v.removal_status(),
                    v.published_at(),
                    v.deprecation().cloned(),
                    v.license().to_vec(),
                ))
            } else {
                // The pure list-based pick found nothing — for most
                // ecosystems this genuinely means "no version found", but
                // for a registry whose list endpoint can be incomplete
                // (e.g. Go's `/@v/list`, which never enumerates
                // pseudo-versions and can be entirely empty for an
                // untagged module) it may just mean the list alone isn't
                // enough. Fall back to the registry's own
                // `get_latest_matching`, which some registries answer from
                // a different, more complete source (Go's `/@latest`). This
                // costs a second network call, but only in this already-rare
                // "list-based pick failed" case, not the common path.
                let fallback = tokio::time::timeout(
                    timeout,
                    registry.get_latest_matching_from(
                        &name,
                        &source,
                        wildcard_req,
                        minimum_stability,
                    ),
                )
                .await;
                match fallback {
                    Ok(Ok(Some(v))) => {
                        let latest = v.version_string().clone();
                        tracing::debug!(
                            package = %name,
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
                        tracing::debug!(package = %name, "no version found");
                        // Both the list-based pick and this fallback
                        // genuinely succeeded and found nothing — the
                        // package demonstrably exists (the fetch itself
                        // never errored), it just has zero versions this
                        // registry can compare against (#550), e.g. a
                        // repository whose only tags don't parse as full
                        // semver. Distinct from every branch below that
                        // sets `failed_name`.
                        no_comparable_versions = true;
                        None
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            package = %name,
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
                            package = %name,
                            "fetch fallback timed out ({}s)",
                            timeout.as_secs()
                        );
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        failed_name = Some((
                            name.clone(),
                            FetchFailure::Transient,
                            format!(
                                "{name}: registry request timed out after {}s",
                                timeout.as_secs()
                            ),
                        ));
                        None
                    }
                }
            };

            if check_yanked {
                // Row 1 (§4.7): the picked "latest" itself yanked —
                // zero extra cost, since it's already in hand.
                // Unreachable in production for an *enabled*
                // registry under today's hardcoded wildcard (one
                // never returns a yanked version for `*`), but
                // stays correct as a defense-in-depth check.
                if let Some((latest, status, _, _, _)) = &resolved
                    && status.is_flagged()
                {
                    yanked = Some((name.clone(), latest.clone(), *status));
                }

                // Row 2/3 (§4.7, revised under #206): `versions`
                // is the full, already-fetched, unfiltered list —
                // no second registry round trip is needed to
                // check whether the in-use version was yanked,
                // unlike the pre-#206 probe design. Checked for
                // every dependency with a known in-use version,
                // not just when it differs from `latest`, since
                // it's now a free in-memory lookup either way. A
                // yanked in-use version wins over an already
                // -recorded yanked `latest` — it's the version
                // the user actually has.
                //
                // Multiple occurrences of the same name (#394,
                // e.g. under both `[dependencies]` and
                // `[target.*.dependencies]`) can carry different
                // in-use versions — every one is checked so a
                // yanked pin on any occurrence is never missed
                // just because another occurrence happens to
                // share the registry lookup.
                // Filters on `is_flagged()` inside the `find` predicate itself
                // (not via a separate `.filter()` on the first version-string
                // match) so a registry response with more than one entry sharing
                // `iv`'s version string still finds a flagged one if any exists —
                // mirroring the pre-#205 `.any(matches && flagged)` scan rather
                // than narrowing to "is the *first* same-string entry flagged".
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

            // #205: the package-level deprecation finding is derived from the
            // same `Version` `resolved` already picked as "latest" — covering
            // the `get_latest_matching_with_context` fallback branch above too,
            // whose returned `Version` is not a member of `versions` at all. See
            // `FetchResult::deprecations`'s docs for why this must not instead
            // scan `versions`.
            if let Some((_, _, _, dep_info, _)) = &resolved
                && let Some(dep_info) = dep_info
            {
                deprecation = Some((name.clone(), dep_info.clone()));
            }

            // Issue #660/#661 tier-1 backfill: extracted from the same `resolved` pick
            // before `.map()` below consumes it — non-empty only for the native-list
            // ecosystems whose `Version::license` isn't the default empty (PyPI,
            // Composer today). Filtered here (not left to the aggregation loop) so a
            // `Some((name, vec![]))` entry — indistinguishable from "no data" once
            // merged into `DocumentState::licenses` — never gets inserted.
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
                tracing::debug!(package = %name, "fetch skipped: offline");
            } else {
                tracing::warn!(package = %name, error = %e, "fetch failed");
            }
            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut fe = first_error.lock().unwrap_or_else(|p| p.into_inner());
            if fe.is_none() {
                *fe = Some(e.to_string());
            }
            drop(fe);
            // A genuine not-found (the registry was successfully
            // asked and said "no such package") is not a fetch
            // failure — only an unanswerable request is (#267
            // C1). Marking it `fetch_failed` here would make
            // `generate_diagnostics_from_cache` report "Registry
            // lookup failed" for the common typo'd-name case
            // instead of "Unknown package", inverting the bug
            // this field exists to fix.
            if !e.is_not_found() {
                failed_name = Some((name.clone(), e.fetch_failure(), e.to_string()));
            }
            None
        }
        Err(_) => {
            tracing::warn!(package = %name, "fetch timed out ({}s)", timeout.as_secs());
            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            failed_name = Some((
                name.clone(),
                FetchFailure::Transient,
                format!(
                    "{name}: registry request timed out after {}s",
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

/// Decides whether a fetch-failure toast should be shown for this fetch cycle, and what
/// its message should be — a pure decision, factored out of the two call sites in
/// `handle_document_open` and `handle_document_change` so both share one policy and the
/// policy itself is unit-testable without an LSP transport.
///
/// `failed_count` counts both genuine fetch failures and not-found lookups (see #276 S2),
/// so the message deliberately says "could not be resolved" rather than "failed to fetch"
/// or anything containing "lookup failed" — that phrasing is the exact inline "Registry
/// lookup failed" diagnostic text, which excludes not-found by design (#267 C1), so reusing
/// it here would recreate the same overcount confusion in different words. "could not be
/// resolved" covers both the "Registry lookup failed" and "Unknown package" diagnostic
/// outcomes, so the count stays checkable against their union (#490).
///
/// Returns `None` when there were no failures at all, or when `offline` is set (issue
/// #483): every fetch fails by design while `network.offline` is set, so toasting on every
/// document open/change would make offline mode unusable.
pub(crate) fn fetch_failure_toast(
    failed_count: usize,
    first_error: Option<&str>,
    offline: bool,
) -> Option<String> {
    if failed_count == 0 || offline {
        return None;
    }
    Some(format!(
        "deps-lsp: {failed_count} package(s) could not be resolved: {}",
        first_error.unwrap_or("timeout or network error")
    ))
}

/// Fans the registry fetch out for the added/version-changed dependencies determined by the
/// caller's diff: marks the document loading, opens an LSP progress notification when the
/// client supports it, resolves each dependency occurrence to a fetchable source (deduping
/// same-name collisions across different resolved sources), and fetches latest versions in
/// parallel. Returns everything the caller needs to merge the result and end the progress
/// notification, without exposing the intermediate `in_use`/`dep_sources` bookkeeping.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_registry_versions_for_change(
    uri: &Uri,
    state: &ServerState,
    client: &Client,
    ecosystem: &dyn Ecosystem,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    deps_to_fetch: Vec<PackageName>,
    freshness_settings: deps_core::FreshnessSettings,
    fetch_timeout_secs: u64,
    max_concurrent_fetches: usize,
    refetch: RefetchPolicy,
) -> (
    Option<RegistryProgress>,
    FetchResult,
    Vec<PackageName>,
    HashSet<PackageName>,
) {
    tracing::info!(
        count = deps_to_fetch.len(),
        "fetching versions for added/version-changed dependencies"
    );

    // Mark as loading and start progress. Under `RefetchPolicy::AllDependencies` the
    // routing itself changed (issue #592), not just the manifest, so the cache built under
    // the *old* routing can no longer be vouched for — drop it under the same lock that
    // sets `Loading`, so no reader ever observes a half-updated state (critic M2: this
    // replaces a separate drop-then-set_loading sequence, which would leave a window
    // between two independent `get_mut` acquisitions).
    if let Some(mut doc) = state.documents.get_mut(uri) {
        if refetch == RefetchPolicy::AllDependencies {
            drop_cache_for_forced_refetch(&mut doc, &deps_to_fetch, ecosystem.formatter());
        }
        doc.set_loading();
    }

    let (progress, progress_sender) = if state.supports_progress() {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(client.clone(), uri.as_str(), deps_to_fetch.len()),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    // Build the in-use-version map (§4.6) and the added/changed dependencies' resolved
    // sources (spec FR-001/FR-011) from the freshly-committed parse result and the
    // resolved versions just loaded above.
    let (in_use, minimum_stability, dep_sources, collided_names): (
        HashMap<PackageName, Vec<String>>,
        Option<String>,
        DepSources,
        HashSet<PackageName>,
    ) = match state.get_document(uri) {
        Some(doc) => match doc.parse_result() {
            Some(pr) => {
                let (sources, collided_names) =
                    dedup_dependencies_by_source(pr, ecosystem.formatter());
                let dep_sources = deps_to_fetch
                    .iter()
                    .filter_map(|name| sources.get(name).map(|s| (name.clone(), s.clone())))
                    .collect();
                (
                    collect_in_use_versions(
                        pr,
                        resolved_versions,
                        resolved_version_candidates,
                        ecosystem.formatter(),
                        ecosystem.ecosystem_id(),
                    ),
                    composer_minimum_stability(pr),
                    dep_sources,
                    collided_names,
                )
            }
            None => (HashMap::new(), None, Vec::new(), HashSet::new()),
        },
        None => (HashMap::new(), None, Vec::new(), HashSet::new()),
    };

    // Fetch latest versions only for NEW dependencies
    //
    // Captured before `dep_sources` is moved into the call below: every raw name a
    // fetch was actually attempted for this round, used by the #550
    // no-comparable-versions merge further down to distinguish "attempted and
    // resolved fine this round" (clear any stale marker) from "not attempted this
    // round" (leave any existing marker untouched) — unlike `fetched_names` in the
    // merge step, this can't be derived from `fetch_result.versions`'s keys, since a
    // no-comparable-versions package is by definition never one of them.
    let attempted_names: Vec<PackageName> =
        dep_sources.iter().map(|(name, _)| name.clone()).collect();
    let registry = ecosystem.registry();
    let fetch_result = fetch_latest_versions_parallel(
        registry,
        dep_sources,
        &in_use,
        progress_sender,
        freshness_settings,
        fetch_timeout_secs,
        max_concurrent_fetches,
        minimum_stability.as_deref(),
    )
    .await;

    (progress, fetch_result, attempted_names, collided_names)
}

/// Merges a completed registry fetch into the document's cache and outcome maps —
/// newly fetched versions, yanked/fetch-failure markers (re-keyed raw -> normalized),
/// collided names recorded as not-attempted, and deprecation / no-comparable-versions
/// bookkeeping — then marks the document loaded or failed depending on `success`. Returns
/// `(failed_count, first_error)`, the two `FetchResult` fields this function does not
/// consume, so the caller can still raise the fetch-failure toast after `fetch_result`
/// itself has been moved in here.
pub(crate) fn merge_registry_fetch_result(
    state: &ServerState,
    uri: &Uri,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    fetch_result: FetchResult,
    attempted_names: &[PackageName],
    collided_names: HashSet<PackageName>,
    success: bool,
) -> (usize, Option<String>) {
    if let Some(mut doc) = state.documents.get_mut(uri) {
        // Captured before `fetch_result.versions` is consumed below: every name
        // successfully fetched this round, used by the S1 deprecation-clearing
        // loop further down to distinguish "fetched and clean" from "not fetched
        // this round" — only the former may clear a stale finding.
        let fetched_names: Vec<PackageName> = fetch_result.versions.keys().cloned().collect();
        for (name, version) in fetch_result.versions {
            doc.cached_versions.insert(name, version);
        }
        // Issue #660/#661 tier-1 backfill: merge (never replace — see
        // `DocumentState::merge_licenses`'s docs), so this coexists safely with the
        // independent tier-3 background pre-fetch's own write to the same map.
        doc.merge_licenses(fetch_result.licenses);
        // Re-key raw -> normalized (§3.1), same as the didOpen path.
        for (name, version) in fetch_result.yanked_versions {
            doc.outcomes
                .set_yanked(formatter.normalize_package_name(&name), version);
        }
        for (name, failure) in fetch_result.fetch_failed {
            doc.outcomes
                .set_fetch_failure(formatter.normalize_package_name(&name), failure);
        }
        // `set_fetch_failure_if_absent` (not `set_fetch_failure`): a collided name
        // normalizing to the same key as a genuine failure just recorded above must
        // not clobber it (impl-critic M2).
        for name in collided_names {
            doc.outcomes.set_fetch_failure_if_absent(
                formatter.normalize_package_name(&name),
                FetchFailure::NotAttempted,
            );
        }
        merge_deprecations_after_fetch(
            &mut doc,
            &fetched_names,
            fetch_result.deprecations,
            formatter,
        );
        merge_no_comparable_versions_after_fetch(
            &mut doc,
            attempted_names,
            fetch_result.no_comparable_versions,
            formatter,
        );
        if success {
            doc.set_loaded();
        } else {
            doc.set_failed();
        }
    }

    (fetch_result.failed_count, fetch_result.first_error)
}

#[cfg(test)]
mod tests {
    use super::super::state::DocumentState;
    use super::*;
    use deps_core::DependencyOutcomes;
    use deps_core::EcosystemId;
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

    /// Issue #483: `fetch_failure_toast` is the pure decision both `handle_document_open`
    /// and `handle_document_change` delegate to, factored out specifically so the
    /// suppress-while-offline policy is unit-testable without an LSP transport to capture
    /// `show_message` calls over.
    mod fetch_failure_toast_tests {
        use super::*;

        #[test]
        fn test_no_failures_produces_no_toast_regardless_of_offline() {
            assert_eq!(fetch_failure_toast(0, None, false), None);
            assert_eq!(fetch_failure_toast(0, Some("ignored"), true), None);
        }

        #[test]
        fn test_offline_suppresses_toast_even_with_failures() {
            assert_eq!(
                fetch_failure_toast(3, Some("offline: request to https://x was blocked"), true),
                None,
                "every fetch fails by design while offline; toasting would make it unusable"
            );
        }

        #[test]
        fn test_online_failure_with_first_error_uses_it_verbatim() {
            assert_eq!(
                fetch_failure_toast(1, Some("HTTP 503 for https://example.com"), false),
                Some(
                    "deps-lsp: 1 package(s) could not be resolved: HTTP 503 for https://example.com"
                        .to_string()
                )
            );
        }

        #[test]
        fn test_online_failure_with_no_first_error_uses_count_fallback() {
            assert_eq!(
                fetch_failure_toast(5, None, false),
                Some(
                    "deps-lsp: 5 package(s) could not be resolved: timeout or network error"
                        .to_string()
                )
            );
        }
    }

    /// FR-011's actual collision bail-out, exercised directly against
    /// `dedup_dependencies_by_source` (review finding #6): two occurrences of the same
    /// name resolving to two different, both-resolvable sources must be dropped from the
    /// result and recorded in the returned collision set — not silently picked, and not
    /// simply absent with no trace.
    mod dedup_by_source_collision_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::{Position, Range};

        /// Unlike the real `CargoFormatter`, treats *both* `Registry` and
        /// `AlternateRegistry` as resolvable — needed so two distinct source values can
        /// both pass gate 1 (resolvability) and reach gate 2 (collision) in the same test.
        struct AlternateAwareFormatter;
        impl PackageNaming for AlternateAwareFormatter {}

        impl PackageRendering for AlternateAwareFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for AlternateAwareFormatter {}

        impl DiagnosticMessages for AlternateAwareFormatter {}

        impl DiagnosticPolicy for AlternateAwareFormatter {}

        impl SourcePolicy for AlternateAwareFormatter {
            fn can_resolve_source(&self, source: &DependencySource) -> bool {
                matches!(
                    source,
                    DependencySource::Registry | DependencySource::AlternateRegistry { .. }
                )
            }
        }

        impl OsvNaming for AlternateAwareFormatter {}

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
            fn uri(&self) -> &Uri {
                static URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
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
                dedup_dependencies_by_source(&parse_result, &AlternateAwareFormatter);

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
                dedup_dependencies_by_source(&parse_result, &AlternateAwareFormatter);

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
                dedup_dependencies_by_source(&parse_result, &AlternateAwareFormatter);

            assert!(sources.is_empty());
            assert!(collided.is_empty());
        }
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_with_timeout() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        // Mock registry that always times out
        struct TimeoutRegistry;

        impl Registry for TimeoutRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    // Sleep longer than timeout (10s default)
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    // Sleep longer than timeout
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search<'a>(
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

        // Use 1 second timeout for test speed
        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            None,
        )
        .await;

        // Should return empty (timeout, not success)
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

        // Mock registry with one slow, one fast package
        struct MixedRegistry;

        impl Registry for MixedRegistry {
            fn get_versions<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    if name == "slow-package" {
                        // Sleep longer than timeout
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    // Fast package or unknown: return immediately
                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    if name == "slow-package" {
                        // Sleep longer than timeout
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    // Fast package or unknown: return immediately (no versions)
                    Ok(None)
                })
            }

            fn search<'a>(
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
            None,
        )
        .await;
        let elapsed = start.elapsed();

        // Should complete in ~1s (timeout), not 10s (slow package duration)
        assert!(
            elapsed < Duration::from_secs(3),
            "Should not wait for slow package: {:?}",
            elapsed
        );

        // Fast package processed (no versions), slow package timed out
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

        // Mock registry that tracks concurrent requests
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
                    // Increment concurrent counter
                    let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;

                    // Track max concurrent
                    self.max_seen.fetch_max(current, Ordering::SeqCst);

                    // Simulate work
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Decrement counter
                    self.current.fetch_sub(1, Ordering::SeqCst);

                    Ok(vec![])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    // Increment concurrent counter
                    let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;

                    // Track max concurrent
                    self.max_seen.fetch_max(current, Ordering::SeqCst);

                    // Simulate work
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Decrement counter
                    self.current.fetch_sub(1, Ordering::SeqCst);

                    Ok(None)
                })
            }

            fn search<'a>(
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

        // Create 50 packages, limit concurrency to 20
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
            None,
        )
        .await;

        // Max concurrent should not exceed limit (allow small margin for timing)
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        // Mock version for successful fetches
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

        // Mock registry with mixed outcomes:
        // - "package-fast" returns quickly with version
        // - "package-slow" times out
        // - "package-error" returns error
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
                            // Return immediately with a stable version
                            Ok(vec![Box::new(MockVersion {
                                version: "1.0.0".into(),
                            }) as Box<dyn Version>])
                        }
                        "package-slow" => {
                            // Sleep longer than timeout (test uses 1s timeout)
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            Ok(vec![])
                        }
                        "package-error" => {
                            // Return cache error (simpler for testing)
                            Err(deps_core::error::DepsError::CacheError(
                                "Mock registry error".to_string(),
                            ))
                        }
                        _ => Ok(vec![]),
                    }
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
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

            fn search<'a>(
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
            ) -> Option<usize> {
                // The fetch loop no longer calls `get_latest_matching` — it derives
                // "latest" from `get_versions` via this method instead, so this mock
                // must implement it too (rather than relying on the `None` default) to
                // keep exercising "package-fast" as a successful fetch.
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

        // Use 1 second timeout for test speed
        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            None,
        )
        .await;

        // Only the fast package should be in results
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
    /// `merge_registry_fetch_result` then merges into `DocumentState::licenses`,
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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

    /// #424 S1: `fetch_latest_versions_parallel` must call `select_latest_matching_with_context`
    /// with the `minimum_stability` value it was given, not the plain `select_latest_matching`
    /// — otherwise a registry with manifest-level stability state (e.g. Composer's
    /// `minimum-stability`) never actually sees it, and #424's S1 fix stays unreachable dead
    /// code from the live LSP fetch path's perspective (critic S3/tester's reachability gap).
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_threads_minimum_stability_into_select_latest_matching_with_context()
     {
        use deps_core::{Metadata, Registry, Version};
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
            // `Vec` after the fetch means the `_with_context` method was never invoked.
            seen_minimum_stability: Mutex<Vec<Option<String>>>,
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            // Deliberately NOT overridden: if the fetch loop ever calls the plain
            // `select_latest_matching` instead of the `_with_context` variant, this default
            // (`None`) makes the pick fail, which the fallback below records as "not found" —
            // distinguishable from the success path this test asserts on.
            fn select_latest_matching_with_context(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
                minimum_stability: Option<&str>,
            ) -> Option<usize> {
                self.seen_minimum_stability
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(minimum_stability.map(str::to_string));
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
            Some("beta"),
        )
        .await;

        assert_eq!(
            *registry
                .seen_minimum_stability
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            vec![Some("beta".to_string())],
            "select_latest_matching_with_context must receive the caller's minimum_stability"
        );
        assert!(
            result.versions.contains_key("vendor/pkg"),
            "the pick must still succeed via the _with_context path"
        );
    }

    /// #424 S1: the `get_latest_matching` fallback path (used when the pure list-based pick
    /// finds nothing) must also thread `minimum_stability` through its own `_with_context`
    /// variant.
    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_threads_minimum_stability_into_get_latest_matching_with_context()
     {
        use deps_core::{Metadata, Registry, Version};
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
            // `Vec` after the fetch means the `_with_context` method was never invoked.
            seen_minimum_stability: Mutex<Vec<Option<String>>>,
        }

        impl Registry for FallbackContextAwareRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                // Empty list forces the fetch loop's `get_latest_matching_with_context`
                // fallback (the pure list-based pick over an empty list finds nothing).
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn get_latest_matching_with_context<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
                minimum_stability: Option<&'a str>,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                self.seen_minimum_stability
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(minimum_stability.map(str::to_string));
                Box::pin(async move {
                    Ok(Some(Box::new(MockVersion {
                        version: "2.0.0-beta1".into(),
                    }) as Box<dyn Version>))
                })
            }

            fn search<'a>(
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
            Some("beta"),
        )
        .await;

        assert_eq!(
            *registry
                .seen_minimum_stability
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            vec![Some("beta".to_string())],
            "get_latest_matching_with_context must receive the caller's minimum_stability"
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Ok(Some(Box::new(MockVersion {
                        version: "v0.0.0-20191109021931-daa7c04131f5".into(),
                    }) as Box<dyn Version>))
                })
            }

            fn search<'a>(
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

        // Mock registry that returns errors for all packages
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
                        name
                    )))
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::CacheError(format!(
                        "Failed to fetch package: {}",
                        name
                    )))
                })
            }

            fn search<'a>(
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

        // Should not panic, just return empty result
        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            5,
            10,
            None,
        )
        .await;

        // All packages failed, result should be empty
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
                        package: name.to_string(),
                        registry: "mock",
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: "mock",
                    })
                })
            }

            fn search<'a>(
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
                        url: format!("https://example.com/{name}").into(),
                        status: 404,
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    Err(deps_core::error::DepsError::HttpStatus {
                        url: format!("https://example.com/{name}").into(),
                        status: 404,
                    })
                })
            }

            fn search<'a>(
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let name = name.clone();
                Box::pin(async move {
                    if name.as_str() == "not-found" {
                        Err(deps_core::error::DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "mock",
                        })
                    } else {
                        Err(deps_core::error::DepsError::CacheError(
                            "mock fallback failure".to_string(),
                        ))
                    }
                })
            }

            fn search<'a>(
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
            result.failed_count, 2,
            "both fallback failures count toward failed_count regardless of cause (S2)"
        );
    }

    /// #490: this is the real-world shape of the toast-overcount bug — a mixed batch of
    /// one not-found package and one genuinely-failed package leaves `failed_count` (2)
    /// exceeding `fetch_failed.len()` (1), since the not-found package never gets a
    /// "Registry lookup failed" diagnostic. The toast must still report the full count
    /// without wording itself as if both packages failed a fetch. Uses the same fixture
    /// shape as `test_fetch_fallback_error_recorded_as_fetch_failed_unless_not_found`
    /// (kept separate, and that test kept byte-identical, so the #276 S2 contract stays
    /// pinned independently of this wording assertion).
    #[tokio::test]
    async fn test_fetch_failure_toast_wording_for_mixed_not_found_and_genuine_failure_batch() {
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let name = name.clone();
                Box::pin(async move {
                    if name.as_str() == "not-found" {
                        Err(deps_core::error::DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "mock",
                        })
                    } else {
                        Err(deps_core::error::DepsError::CacheError(
                            "mock fallback failure".to_string(),
                        ))
                    }
                })
            }

            fn search<'a>(
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
            None,
        )
        .await;

        assert_eq!(result.failed_count, 2);
        assert_eq!(
            result.fetch_failed.len(),
            1,
            "not-found must not be in fetch_failed"
        );

        let toast = fetch_failure_toast(result.failed_count, result.first_error.as_deref(), false)
            .expect("failed_count > 0 and not offline, so a toast must be produced");
        assert!(
            toast.starts_with("deps-lsp: 2 package(s) could not be resolved:"),
            "got: {toast}"
        );
        assert!(
            !toast.contains("lookup failed"),
            "must not reuse the 'Registry lookup failed' diagnostic wording, which \
             excludes not-found and would misrepresent this mixed batch: {toast}"
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search<'a>(
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

        // 1s timeout for test speed.
        let result = fetch_latest_versions_parallel(
            registry,
            with_registry_source(packages),
            &HashMap::new(),
            None,
            deps_core::freshness::FreshnessSettings::default(),
            1,
            10,
            None,
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
        // #480: `first_error` is the batch's one-shot toast message. Before this fix it
        // was simply whichever concurrent fetch finished first — so a fast not-found
        // ("Unknown package") could outrank a slower but far more actionable error
        // (e.g. a rate limit hit by every other package in the batch). Here the
        // not-found resolves immediately while the actionable error resolves after a
        // short delay, so it wins the finishing race; `priority_error` must still make
        // the actionable error win the reported `first_error`.
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
                            package: name.to_string(),
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
            None,
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
                        package: name.to_string(),
                        registry: "mock",
                    })
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
            None,
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
        // #480 S1: the toast used to special-case a populated `first_error` as
        // `format!("deps-lsp: {err}")`, entirely dropping `failed_count` from the
        // message whenever `first_error` was `Some` — so a multi-package timeout batch
        // (which always populates `first_error` via `priority_error`, unlike the
        // not-found-only case) silently lost its count. The toast is now built
        // unconditionally from both fields (`"{failed_count} package(s) could not be
        // resolved: {first_error}"`, see #490), so this asserts the `FetchResult` data
        // that feeds it: a batch where every package times out must report `failed_count`
        // equal to the batch size *and* a populated, actionable `first_error` — both
        // fields together, not one masking the other.
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
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok(None)
                })
            }

            fn search<'a>(
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
            None,
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

        /// #424 S1: `composer_minimum_stability` must extract the manifest's
        /// `minimum-stability` field via the real `deps_composer::parser::parse_composer_json`
        /// → `ComposerParseResult` → `deps_core::ParseResult` downcast path, not just a
        /// hand-built fixture — this is the actual production call path from the fetch task.
        #[tokio::test]
        async fn test_composer_minimum_stability_extracts_from_real_parse_result() {
            let json = r#"{
  "minimum-stability": "beta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = crate::parse_composer_json(json, &uri).unwrap();

            assert_eq!(
                composer_minimum_stability(&parse_result as &dyn deps_core::ParseResult),
                Some("beta".to_string())
            );
        }

        /// #424 S1: a `composer.json` with no `minimum-stability` field extracts to `None`,
        /// not a fabricated `"stable"`.
        #[tokio::test]
        async fn test_composer_minimum_stability_none_when_absent() {
            let json = r#"{"require": {"symfony/console": "^6.0"}}"#;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = crate::parse_composer_json(json, &uri).unwrap();

            assert_eq!(
                composer_minimum_stability(&parse_result as &dyn deps_core::ParseResult),
                None
            );
        }

        /// #424 S1: a non-Composer `ParseResult` (the downcast target type mismatches) must
        /// extract to `None` rather than panicking — this is what every other ecosystem's
        /// document hits on every fetch cycle.
        #[test]
        fn test_composer_minimum_stability_none_for_non_composer_parse_result() {
            struct OtherParseResult;
            impl deps_core::ParseResult for OtherParseResult {
                fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
                    vec![]
                }
                fn workspace_root(&self) -> Option<&std::path::Path> {
                    None
                }
                fn uri(&self) -> &Uri {
                    unimplemented!("not exercised by this test")
                }
                fn as_any(&self) -> &dyn std::any::Any {
                    self
                }
            }

            assert_eq!(
                composer_minimum_stability(&OtherParseResult as &dyn deps_core::ParseResult),
                None
            );
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let pypi_uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            assert!(state.ecosystem_registry.get_for_uri(&pypi_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("pypi ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Pypi,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id(), "pypi");
        }
    }

    /// End-to-end PyPI key guard (critic S4): drives the *real* pypi parser
    /// and formatter (not a hand-rolled mock) through the full
    /// fetch -> re-key -> store -> diagnostic pipeline for an `==`-pinned
    /// dependency with no lock file, declared as a Poetry
    /// `[tool.poetry.dependencies]` table key. Poetry's table-key path keeps
    /// `Dependency::name()` exactly as written in the manifest (unlike a PEP
    /// 508 requirement *string* — `pyproject.toml`'s PEP 621 array or
    /// `requirements.txt` — where `pep508_rs::PackageName` already
    /// PEP 503-normalizes at construction, so raw and normalized already
    /// coincide there and could not exercise this guard); the Poetry path is
    /// therefore the one place a manifest-declared underscore/dotted name
    /// genuinely reaches `FetchResult::yanked_versions` unnormalized (§3.1).
    /// Asserts BOTH that `DocumentState::yanked_versions` ends up keyed by
    /// the *normalized* name and that the diagnostic actually reaches
    /// `generate_diagnostics_from_cache`'s output — either alone would miss
    /// a regression the other half could hide (a normalized key with a
    /// diagnostic-generation bug that never reads it, or a working
    /// diagnostic built by accident on a raw key that happens to already be
    /// normalized).
    #[cfg(feature = "pypi")]
    mod pypi_yanked_key_guard_tests {
        use super::*;
        use deps_core::{DiagnosticSeverities, Metadata, Version, VersionData};
        use std::any::Any;

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

        /// Reports `pinned_version` as yanked and a different, non-yanked
        /// `"9.9.9"` as latest, for every package name it's asked about —
        /// good enough for a single-dependency guard case.
        struct MockYankedRegistry {
            pinned_version: &'static str,
        }

        impl Registry for MockYankedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                let versions = vec![
                    Box::new(MockYankVersion {
                        version: "9.9.9".into(),
                        yanked: false,
                    }) as Box<dyn Version>,
                    Box::new(MockYankVersion {
                        version: self.pinned_version.into(),
                        yanked: true,
                    }) as Box<dyn Version>,
                ];
                Box::pin(async move { Ok(versions) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                let latest = Box::new(MockYankVersion {
                    version: "9.9.9".into(),
                    yanked: false,
                }) as Box<dyn Version>;
                Box::pin(async move { Ok(Some(latest)) })
            }

            fn search<'a>(
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

        /// Runs the full pipeline for one Poetry `[tool.poetry.dependencies]`
        /// table-key dependency, declared with an `==pinned_version` pin and
        /// no lock file, and returns the generated diagnostics plus the
        /// stored (normalized-keyed) yanked map.
        async fn run_pipeline(
            raw_name: &str,
            pinned_version: &'static str,
        ) -> (
            Vec<tower_lsp_server::ls_types::Diagnostic>,
            HashMap<String, (ConcreteVersion, RemovalStatus)>,
        ) {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            // The TOML key is quoted so a dotted name (e.g. `zope.interface`)
            // is a literal key rather than TOML's dotted-key table-nesting
            // syntax.
            let content =
                format!("[tool.poetry.dependencies]\n\"{raw_name}\" = \"=={pinned_version}\"\n");

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("pypi ecosystem not found");
            let formatter = ecosystem.formatter();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("a single Poetry table-key dependency must parse");
            assert_eq!(
                parse_result
                    .dependencies()
                    .iter()
                    .map(|d| d.name().to_string())
                    .collect::<Vec<_>>(),
                vec![raw_name.to_string()],
                "Poetry table-key parsing must keep the manifest-declared name as-is"
            );

            let resolved_versions = HashMap::new();
            let dep_names: Vec<PackageName> = parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().clone())
                .collect();
            let in_use = collect_in_use_versions(
                parse_result.as_ref(),
                &resolved_versions,
                &HashMap::new(),
                formatter,
                EcosystemId::Pypi,
            );
            // Sanity check on the fix this guard exists for: the pep440
            // `==` comparator must already be stripped here.
            assert_eq!(
                in_use.get(&PackageName::new(raw_name)),
                Some(&vec![pinned_version.to_string()])
            );

            let registry: Arc<dyn Registry> = Arc::new(MockYankedRegistry { pinned_version });
            let fetch_result = fetch_latest_versions_parallel(
                registry,
                with_registry_source(dep_names),
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                5,
                10,
                None,
            )
            .await;

            let yanked_versions: HashMap<String, (ConcreteVersion, RemovalStatus)> = fetch_result
                .yanked_versions
                .into_iter()
                .map(|(name, v)| (formatter.normalize_package_name(&name), v))
                .collect();

            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Pypi,
                content.clone(),
                parse_result,
            );
            doc_state.update_cached_versions(fetch_result.versions);
            let mut outcomes = DependencyOutcomes::new();
            for (name, v) in yanked_versions.clone() {
                outcomes.set_yanked(name, v);
            }
            doc_state.replace_outcomes(outcomes);
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            let diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                doc.parse_result().unwrap(),
                VersionData::new(&doc.cached_versions, &doc.resolved_versions)
                    .with_outcomes(&doc.outcomes),
                formatter,
                &uri,
                deps_core::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                deps_core::PublishTime::now(),
            );

            (diagnostics, yanked_versions)
        }

        #[tokio::test]
        async fn typing_extensions_underscore_name_resolves_via_normalized_key() {
            let (diagnostics, yanked_versions) = run_pipeline("typing_extensions", "4.9.0").await;

            assert_eq!(
                yanked_versions.get("typing-extensions"),
                Some(&(ConcreteVersion::new("4.9.0"), RemovalStatus::Yanked)),
                "must be keyed by the normalized (dash) name, not the raw manifest name"
            );
            assert!(
                diagnostics.iter().any(|d| d.message.contains("4.9.0")),
                "yanked diagnostic must reach the generated output: {diagnostics:?}"
            );
        }

        #[tokio::test]
        async fn zope_interface_dotted_name_resolves_via_normalized_key() {
            let (diagnostics, yanked_versions) = run_pipeline("zope.interface", "5.0.0").await;

            assert_eq!(
                yanked_versions.get("zope-interface"),
                Some(&(ConcreteVersion::new("5.0.0"), RemovalStatus::Yanked)),
                "must be keyed by the normalized (dotted -> dash) name"
            );
            assert!(
                diagnostics.iter().any(|d| d.message.contains("5.0.0")),
                "yanked diagnostic must reach the generated output: {diagnostics:?}"
            );
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
            ) -> Option<usize> {
                versions
                    .iter()
                    .position(|v| !v.removal_status().blocks_resolution())
            }

            fn get_latest_matching<'a>(
                &'a self,
                name: &'a PackageName,
                _req: &'a VersionReq,
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

            fn search<'a>(
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
                None,
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

            // 1 second timeout for test speed.
            let result = fetch_latest_versions_parallel(
                registry,
                vec![(PackageName::new("pkg"), DependencySource::Registry)],
                &in_use,
                None,
                deps_core::freshness::FreshnessSettings::default(),
                1,
                10,
                None,
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
            ) -> Option<usize> {
                (!versions.is_empty()).then_some(0)
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
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
                None,
            )
            .await;

            assert!(result.deprecations.is_empty());
        }
    }
}
