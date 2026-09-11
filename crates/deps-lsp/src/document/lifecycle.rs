//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::diff::{DependencyDiff, preserve_cache};
use super::fetch::{
    DepSources, composer_minimum_stability, dedup_dependencies_by_source, fetch_failure_toast,
    fetch_latest_versions_parallel, fetch_registry_versions_for_change,
    merge_registry_fetch_result,
};
use super::loader::{MAX_FILE_SIZE, load_document_from_disk};
use super::osv_scan::{
    OsvScanResult, run_license_prefetch, run_osv_phase_b_and_commit, run_osv_scan_phase_a,
};
use super::resolved::{
    RefetchPolicy, cached_versions_from_lockfile, collect_in_use_versions, dependency_version_map,
    load_resolved_versions,
};
use super::state::{DocumentState, ServerState};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use crate::progress::RegistryProgress;
use deps_core::ConcreteVersion;
use deps_core::DependencyOutcomes;
use deps_core::Ecosystem;
use deps_core::FetchFailure;
use deps_core::PackageName;
use deps_core::Result;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{MessageType, Uri};
use tracing::Instrument;

/// Rejects document content larger than [`MAX_FILE_SIZE`].
///
/// Content from `textDocument/didOpen`/`didChange` reaches this crate directly
/// over the LSP protocol, with no filesystem `metadata()` size check to gate on
/// beforehand (unlike [`load_document_from_disk`], which checks before reading).
/// This applies the same bound so an oversized payload is rejected before it
/// ever reaches `ecosystem.parse_manifest`.
///
/// # Errors
///
/// Returns `Err(DepsError::CacheError)` if `content` exceeds `MAX_FILE_SIZE`.
fn check_content_size(content: &str, uri: &Uri) -> Result<()> {
    let size = content.len() as u64;
    if size > MAX_FILE_SIZE {
        tracing::error!(
            "Document content exceeds maximum size: {} bytes (limit: {} bytes) for {:?}",
            size,
            MAX_FILE_SIZE,
            uri
        );
        return Err(deps_core::error::DepsError::CacheError(format!(
            "document too large: {size} bytes (max: {MAX_FILE_SIZE} bytes)"
        )));
    }
    Ok(())
}

/// Generic document open handler using ecosystem registry.
///
/// Parses manifest using the ecosystem's parser, creates document state,
/// and spawns a background task to fetch version information from the registry.
///
/// # Errors
///
/// Returns an error if no ecosystem handler matches `uri`, or if `content` exceeds
/// the configured maximum manifest size. A manifest-parse failure is not an error
/// here: the document is stored without a parse result instead.
#[tracing::instrument(
    skip_all,
    fields(uri = ?uri, ecosystem = tracing::field::Empty, doc_version = ?version)
)]
pub async fn handle_document_open(
    uri: Uri,
    content: String,
    version: Option<i32>,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {:?}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
                "{uri:?}"
            )));
        }
    };
    tracing::Span::current().record("ecosystem", ecosystem.id());

    check_content_size(&content, &uri)?;

    tracing::info!(
        "Opening {:?} with ecosystem: {}",
        uri,
        ecosystem.display_name()
    );

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = deps_core::ecosystem::parse_manifest_blocking(&ecosystem, &content, &uri)
        .await
        .ok();

    // Create document state (parse_result may be None)
    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(ecosystem.ecosystem_id(), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(ecosystem.ecosystem_id(), content)
    };
    doc_state.set_version(version);

    state.update_document(uri.clone(), doc_state);

    // Clone cache, diagnostics, and freshness config before spawning background task
    // (all read here, before any OSV request is built, so disabling the feature
    // suppresses the network call itself — FR-011).
    let (cache_config, vulnerabilities_enabled, freshness_settings, diagnostic_severities, offline) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
            cfg.diagnostics.to_severities(),
            cfg.network.offline,
        )
    };

    // Spawn background task to fetch versions. Captured before `tokio::spawn` so this
    // task's own span (and everything it spawns in turn) nests under whichever request
    // span triggered this open, instead of opening as an unparented root span (#756 S1).
    let span = tracing::Span::current();
    let task = tokio::spawn(
        run_document_open_background_task(
            uri.clone(),
            Arc::clone(&state),
            Arc::clone(&ecosystem),
            client.clone(),
            cache_config,
            vulnerabilities_enabled,
            freshness_settings,
            diagnostic_severities,
            offline,
        )
        .instrument(span),
    );

    Ok(task)
}

/// The background task [`handle_document_open`] spawns: loads lockfile-resolved
/// versions instantly (no network), seeds them as cached versions, kicks off the OSV
/// Phase A scan concurrently with the registry fetch, runs the registry fetch,
/// commits its results (cached versions, outcomes, loading state), then refreshes
/// inlay hints, joins OSV Phase B, and publishes diagnostics.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the async move closure this was extracted from — every parameter \
              is config already read (and thus fixed) before the task was spawned in \
              handle_document_open, so a config struct here would only relocate, not \
              reduce, the parameter list"
)]
#[tracing::instrument(skip_all, fields(uri = ?uri, ecosystem = ecosystem.id()))]
async fn run_document_open_background_task(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    client: Client,
    cache_config: crate::config::CacheConfig,
    vulnerabilities_enabled: bool,
    freshness_settings: deps_core::freshness::FreshnessSettings,
    diagnostic_severities: deps_core::DiagnosticSeverities,
    offline: bool,
) {
    tracing::debug!("background task started");

    // Load resolved versions from lock file first (instant, no network)
    let (resolved_versions, resolved_version_candidates) =
        load_resolved_versions(&uri, &state, ecosystem.as_ref()).await;

    // Update document state with resolved versions immediately
    if !resolved_versions.is_empty()
        && let Some(mut doc) = state.documents.get_mut(&uri)
    {
        doc.update_resolved_versions(
            resolved_versions.clone(),
            resolved_version_candidates.clone(),
        );

        // Use resolved versions as cached versions for instant display,
        // except for a dependency whose manifest requirement is itself
        // already the resolved version (Go's `require` lines) — for
        // those, go.sum can hold a stale, no-longer-selected version
        // (#235), so seeding it as the "latest" comparison operand would
        // desync hover/inlay-hint status against the go.mod-accurate
        // `resolved` value during the cold-open window before the
        // registry fetch completes (critique S1).
        let formatter = ecosystem.formatter();
        let instant_resolved: HashMap<PackageName, ConcreteVersion> = match doc.parse_result() {
            Some(parse_result) => {
                let deps = parse_result.dependencies();
                resolved_versions
                    .iter()
                    .filter(|(name, _)| {
                        deps.iter()
                            .find(|d| d.name() == *name)
                            .is_none_or(|d| !formatter.manifest_requirement_is_resolved_version(*d))
                    })
                    .map(|(name, version)| (name.clone(), version.clone()))
                    .collect()
            }
            None => resolved_versions.clone(),
        };
        doc.update_cached_versions(cached_versions_from_lockfile(&instant_resolved));
    }

    // Phase A OSV scan, spawned so it runs concurrently with the
    // registry fetch below rather than gating the inlay-hint refresh
    // that must happen immediately after it (critique S2).
    let osv_task = vulnerabilities_enabled.then(|| {
        tokio::spawn(
            run_osv_scan_phase_a(
                uri.clone(),
                Arc::clone(&state),
                Arc::clone(&ecosystem),
                cache_config.fetch_timeout_secs,
            )
            .instrument(tracing::Span::current()),
        )
    });

    // Tier-3 license pre-fetch (issue #660), spawned concurrently with the registry
    // fetch below, same shape as OSV phase A — joined (round 3 finding #3) just before
    // this function's diagnostics publish so a tier-3 license-policy violation can
    // appear in the *first* publish after this open, not only whenever some later,
    // unrelated event happens to regenerate diagnostics. No-op for every ecosystem but
    // Dart/Swift/Gradle/Deno.
    let license_task = tokio::spawn(
        run_license_prefetch(
            uri.clone(),
            Arc::clone(&state),
            Arc::clone(&ecosystem),
            cache_config.fetch_timeout_secs,
        )
        .instrument(tracing::Span::current()),
    );

    // Collect dependency names+sources and the in-use-version map (§4.6) in one
    // pass while holding the reference (can't hold across await).
    let (dep_sources, in_use, minimum_stability, collided_names): (
        DepSources,
        HashMap<PackageName, Vec<String>>,
        Option<String>,
        HashSet<PackageName>,
    ) = {
        let doc = match state.get_document(&uri) {
            Some(d) => d,
            None => {
                tracing::warn!("document not found, aborting fetch");
                return;
            }
        };
        let parse_result = match doc.parse_result() {
            Some(p) => p,
            None => {
                tracing::warn!("no parse result, aborting fetch");
                return;
            }
        };
        // Deduped by name (critique M3): a duplicated name shares one
        // registry fetch across all its occurrences — the result is
        // name-keyed anyway (`FetchResult::versions`), so fetching it
        // more than once would only issue wasted extra registry calls
        // and inflate `RegistryProgress`'s total. A non-resolvable source is
        // dropped entirely, and two occurrences of the same name resolving to
        // *different* sources are dropped and recorded as collided instead
        // (spec FR-011) — see `dedup_dependencies_by_source`.
        let (sources_map, collided_names) =
            dedup_dependencies_by_source(parse_result, ecosystem.formatter());
        let dep_sources: Vec<_> = sources_map.into_iter().collect();
        let in_use = collect_in_use_versions(
            parse_result,
            &resolved_versions,
            &resolved_version_candidates,
            ecosystem.formatter(),
            ecosystem.ecosystem_id(),
        );
        let minimum_stability = composer_minimum_stability(parse_result);
        (dep_sources, in_use, minimum_stability, collided_names)
    };

    let dep_count = dep_sources.len();
    tracing::debug!(count = dep_count, "starting registry fetch");

    // Bounds total outbound fetch concurrency across every open/changed document
    // server-wide (issue #592 critic S2/M1). Acquired *before* `set_loading()`/
    // `RegistryProgress::start` below, not just around the fetch: acquiring only around
    // the fetch would set every queued document to `Loading` (and open a progress bar for
    // each) up front during a cold-start burst, before any permit arrives — reproducing
    // the same diagnostic-suppression shape this cap exists to bound, plus N stuck
    // progress notifications. `P` is deliberately independent of
    // `cache.max_concurrent_fetches` (that bounds dependencies within one document's
    // fetch; this bounds documents fetching at once).
    // `state.fetch_permits` is never `.close()`d anywhere in deps-lsp, so `acquire()`
    // cannot return `Closed`.
    #[allow(clippy::expect_used)]
    let fetch_permit = state
        .fetch_permits
        .acquire()
        .await
        .expect("fetch_permits semaphore is never closed");

    // Mark as loading and start progress
    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.set_loading();
    }

    let (progress, progress_sender) = if state.supports_progress() {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(client.clone(), uri.as_str(), dep_sources.len()),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    tracing::debug!("progress started, fetching versions");

    // Fetch latest versions from registry in parallel (for update hints)
    let registry = ecosystem.registry();
    let fetch_result = fetch_latest_versions_parallel(
        registry,
        dep_sources,
        &in_use,
        progress_sender,
        freshness_settings,
        cache_config.fetch_timeout_secs,
        cache_config.max_concurrent_fetches,
        minimum_stability.as_deref(),
    )
    .await;
    drop(fetch_permit);

    let success = !fetch_result.versions.is_empty();
    tracing::debug!(
        fetched = fetch_result.versions.len(),
        failed = fetch_result.failed_count,
        yanked = fetch_result.yanked_versions.len(),
        "registry fetch complete"
    );

    // Update document state with cached versions (latest from registry)
    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.update_cached_versions(fetch_result.versions);
        // Re-key raw -> normalized (§3.1): `FetchResult`'s three fields are
        // raw-keyed, `DocumentState::outcomes` is normalized.
        let formatter = ecosystem.formatter();
        let mut outcomes = DependencyOutcomes::new();
        for (name, d) in fetch_result.deprecations {
            outcomes.set_deprecation(formatter.normalize_package_name(&name), d);
        }
        for (name, v) in fetch_result.yanked_versions {
            outcomes.set_yanked(formatter.normalize_package_name(&name), v);
        }
        for (name, failure) in fetch_result.fetch_failed {
            outcomes.set_fetch_failure(formatter.normalize_package_name(&name), failure);
        }
        for name in fetch_result.no_comparable_versions {
            outcomes.set_no_comparable_versions(formatter.normalize_package_name(&name));
        }
        // `collided_names` (spec FR-011) are merged in alongside genuine fetch
        // failures so `generate_diagnostics_from_cache` reports "lookup could not
        // be determined" rather than a false "Unknown package" for a name that
        // was deliberately never queried, not one that doesn't exist. Genuine
        // failures are inserted first and `collided_names` uses
        // `set_fetch_failure_if_absent` so a collided name that normalizes to the
        // same key as a genuine `Actionable`/`Transient` failure never clobbers it
        // (impl-critic M2).
        for name in collided_names {
            outcomes.set_fetch_failure_if_absent(
                formatter.normalize_package_name(&name),
                FetchFailure::NotAttempted,
            );
        }
        doc.replace_outcomes(outcomes);
        if success {
            doc.set_loaded();
        } else {
            doc.set_failed();
        }
    }

    // End progress
    if let Some(progress) = progress {
        progress.end(success).await;
    }

    // Notify user about failed packages — suppressed when offline, see
    // `fetch_failure_toast`'s docs. `fetch_result.first_error` is always populated
    // by `fetch_latest_versions_parallel` whenever `failed_count > 0` (#480: every
    // site that increments `failed_count` also sets either `priority_error` or
    // `first_error`, and the two are merged into this field before returning).
    match fetch_failure_toast(
        fetch_result.failed_count,
        fetch_result.first_error.as_deref(),
        state.cache.is_offline(),
    ) {
        Some(message) => {
            client.show_message(MessageType::WARNING, message).await;
        }
        None if fetch_result.failed_count > 0 => {
            tracing::debug!(
                failed_count = fetch_result.failed_count,
                "suppressing fetch-failure toast: offline"
            );
        }
        None => {}
    }

    // Kick off inlay hint / code lens refresh as soon as loading completes, so
    // clients see updated hints as early as possible — typically before
    // diagnostics, which may take longer due to additional network calls, though
    // that ordering is scheduler-dependent, not guaranteed, since the requests
    // are detached (issue #493: nothing downstream depends on their result, and a
    // client that never declared refresh support, or stops replying, must not
    // hang this task's critical path — including the OSV commit and diagnostics
    // publish below — forever).
    state.spawn_refresh_requests(&client);

    // Join phase A (already running concurrently since it was spawned
    // above) and, only now that `cached_versions` holds the registry's
    // actual latest (not the lockfile-seeded placeholder — critique S1),
    // run phase B and commit before generating diagnostics.
    if let Some(osv_task) = osv_task {
        match osv_task.await {
            Ok(Some(phase_a_result)) => {
                let ecosystem_id = ecosystem.ecosystem_id();
                run_osv_phase_b_and_commit(
                    &uri,
                    &state,
                    ecosystem_id,
                    ecosystem.formatter(),
                    cache_config.fetch_timeout_secs,
                    phase_a_result,
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("OSV scan task failed: {e}"),
        }
    }

    // Join the tier-3 license pre-fetch too (round 3 finding #3), for the same reason:
    // its commit must land before this publish, not after.
    await_license_prefetch(Some(license_task)).await;

    // Publish diagnostics (may be slower, runs after hints are already visible)
    let diags = diagnostics::generate_diagnostics_internal(
        Arc::clone(&state),
        &uri,
        freshness_settings,
        diagnostic_severities,
        offline,
        diagnostics::loading_ceiling(
            cache_config.fetch_timeout_secs,
            dep_count,
            cache_config.max_concurrent_fetches,
        ),
    )
    .await;

    client.publish_diagnostics(uri.clone(), diags, None).await;
}

/// Parses the freshly-edited manifest content and diffs its dependencies against the
/// document's previously stored parse result, so the caller can react to what actually
/// changed (added/removed/version-changed) instead of unconditionally re-fetching and
/// re-scanning everything on every keystroke.
async fn parse_and_diff_manifest(
    uri: &Uri,
    content: &str,
    state: &ServerState,
    ecosystem: &Arc<dyn Ecosystem>,
) -> (Option<Box<dyn deps_core::ParseResult>>, DependencyDiff) {
    // Extract old dependency name -> version_requirement map before parsing
    // (for diff computation)
    let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
        state.get_document(uri).map_or_else(HashMap::new, |doc| {
            doc.parse_result()
                .map(dependency_version_map)
                .unwrap_or_default()
        });

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = deps_core::ecosystem::parse_manifest_blocking(ecosystem, content, uri)
        .await
        .ok();

    // Extract new dependency name -> version_requirement map for diff
    let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> = parse_result
        .as_ref()
        .map(|pr| dependency_version_map(pr.as_ref()))
        .unwrap_or_default();

    // Compute dependency diff
    let diff = DependencyDiff::compute(&old_deps, &new_deps);
    tracing::debug!(
        added = diff.added.len(),
        removed = diff.removed.len(),
        version_changed = diff.version_changed.len(),
        "dependency diff"
    );

    (parse_result, diff)
}

/// Whether [`commit_parsed_document`] should verify the document's current version before
/// committing — see that function's doc for why this exists.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CommitGuard {
    /// Always commit — a real edit's own version is authoritative, nothing to guard against.
    Unconditional,
    /// Commit only if the document's *current* version in `state` still equals this value;
    /// otherwise skip the commit entirely (impl-critic S1).
    ExpectVersion(Option<i32>),
}

/// Bundles [`commit_parsed_document`]'s two commit-behavior parameters — kept as one struct
/// (rather than two more positional parameters) to stay under `clippy::too_many_arguments`.
struct CommitOptions<'a> {
    diff: &'a DependencyDiff,
    guard: CommitGuard,
}

/// Builds the new `DocumentState` from the parsed manifest (or a parse-result-less
/// placeholder when parsing failed), carries over cache entries the previous state already
/// held, prunes/invalidates entries `options.diff` says are now stale, and commits the result
/// into `state` — unless `options.guard` is [`CommitGuard::ExpectVersion`] and the document's
/// *current* version in `state` no longer matches, in which case the commit is skipped
/// entirely and `false` is returned.
///
/// The guard exists for a reparse whose trigger is *not* the document's own edit stream —
/// e.g. [`crate::server::Backend::handle_watched_config_change`] (issue #590), which reparses
/// every open document of an ecosystem using content it snapshotted before the (awaited)
/// re-parse ran. Without this check, a `did_change` notification landing while that reparse
/// is in flight gets silently reverted: this function would otherwise commit unconditionally,
/// overwriting the newer edit with the older, watched-config-triggered content (impl-critic
/// S1). [`handle_document_change`] passes [`CommitGuard::Unconditional`] — a real edit's own
/// version is authoritative, there is nothing to guard against.
fn commit_parsed_document(
    uri: &Uri,
    ecosystem: &dyn Ecosystem,
    content: String,
    parse_result: Option<Box<dyn deps_core::ParseResult>>,
    version: Option<i32>,
    state: &ServerState,
    options: CommitOptions<'_>,
) -> bool {
    let diff = options.diff;
    if let CommitGuard::ExpectVersion(expected) = options.guard {
        let current = state.with_document(uri, |doc| doc.version);
        if current != Some(expected) {
            tracing::debug!(
                ?uri,
                ?expected,
                ?current,
                "skipping stale reparse commit: document version changed since this reparse started"
            );
            return false;
        }
    }

    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(ecosystem.ecosystem_id(), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(ecosystem.ecosystem_id(), content)
    };
    doc_state.set_version(version);

    if let Some(old_doc) = state.get_document(uri) {
        preserve_cache(&mut doc_state, &old_doc);
    }

    // Prune stale cache entries for removed dependencies. `vulnerabilities`
    // is keyed by the *normalized* name (unlike `cached_versions`/
    // `resolved_versions`, which are raw-`dep.name()`-keyed), so pruning it
    // with the raw name would silently no-op for Composer/Swift/NuGet-style
    // ecosystems where normalization changes the string (critique M4).
    let formatter = ecosystem.formatter();
    for removed_dep in &diff.removed {
        doc_state.cached_versions.remove(removed_dep);
        doc_state.resolved_versions.remove(removed_dep);
        // Raw-`dep.name()`-keyed, same as `resolved_versions` above (issue #649) — must be
        // pruned alongside it so a removed dependency's stale candidates never linger.
        doc_state.resolved_version_candidates.remove(removed_dep);
        // Raw-`dep.name()`-keyed, same as `resolved_versions`/`resolved_version_candidates`
        // above (see `DocumentState::licenses`' doc) — round 3 finding #5: previously
        // missing from this loop, so a document with dependencies repeatedly added and
        // removed while staying open accumulated an ever-growing set of orphaned license
        // entries never reclaimed until the document closed.
        doc_state.licenses.remove(removed_dep);
        doc_state
            .vulnerabilities
            .remove(&formatter.normalize_package_name(removed_dep));
        doc_state
            .outcomes
            .remove(&formatter.normalize_package_name(removed_dep));
    }

    // A version-only edit (name unchanged, requirement changed) invalidates
    // any yanked finding recorded against the dependency's *old* version —
    // e.g. editing a yanked pin to a safe one must not leave a stale
    // diagnostic anchored on the new range (security F1 / impl-critic S1).
    // Drop rather than try to refresh in place; the registry re-fetch that
    // follows in the caller (`deps_to_fetch` includes `version_changed`)
    // repopulates the entry if the *new* version also turns out to be
    // yanked. Same for `fetch_failed` (#267): a stale fetch-error marker
    // must not survive an edit that gets re-fetched below.
    //
    // Deliberately NOT mirrored for `deprecations`: #205's finding is
    // package-level, derived from `latest`, not the dependency's declared
    // version — editing which version is pinned does not make the package
    // any less (or more) deprecated, so there is nothing stale to drop here.
    for changed_dep in &diff.version_changed {
        let normalized = formatter.normalize_package_name(changed_dep);
        doc_state.outcomes.clear_yanked(&normalized);
        doc_state.outcomes.clear_fetch_failure(&normalized);
    }

    state.update_document(uri.clone(), doc_state);
    true
}

/// Generic document change handler using ecosystem registry.
///
/// Re-parses manifest when document content changes and spawns a debounced
/// task to update diagnostics and request inlay hint refresh.
///
/// # Errors
///
/// Returns an error if no ecosystem handler matches `uri`, or if `content` exceeds
/// the configured maximum manifest size. A manifest-parse failure is not an error
/// here: the document is stored without a parse result instead.
#[tracing::instrument(skip_all, fields(uri = ?uri, doc_version = ?version))]
pub async fn handle_document_change(
    uri: Uri,
    content: String,
    version: Option<i32>,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    let task = handle_document_change_guarded(
        uri,
        content,
        version,
        CommitGuard::Unconditional,
        RefetchPolicy::Diff,
        state,
        client,
        config,
    )
    .await?;
    // `CommitGuard::Unconditional` always commits, so `handle_document_change_guarded`
    // never returns `Ok(None)` for it.
    #[allow(clippy::expect_used)]
    Ok(task.expect("CommitGuard::Unconditional never skips the commit"))
}

/// Like [`handle_document_change`], but skips committing the reparse — and spawning its
/// diagnostics-refresh background task — if `guard` is [`CommitGuard::ExpectVersion`] and the
/// document's version in `state` no longer matches by the time this reparse finishes; see
/// [`commit_parsed_document`]'s doc for why.
///
/// Returns `Ok(None)` on a skip, never a sentinel/no-op `JoinHandle` (impl-critic S3): the
/// caller ([`crate::server::Backend::handle_watched_config_change`]) feeds the returned handle
/// straight into [`ServerState::spawn_background_task`], which unconditionally **aborts** any
/// existing task registered for the URI before installing the new one. A sentinel handle for
/// a skipped, superseded reparse would therefore abort the concurrent edit's *real* background
/// task (registry fetch, OSV rescan, `publish_diagnostics`) that a matching-version commit
/// already installed — silently dropping that newer edit's diagnostics until the next
/// keystroke. The caller must treat `None` as "do not touch the task registry for this URI at
/// all", not as "install a no-op task".
///
/// [`handle_document_change`] passes [`CommitGuard::Unconditional`] and unwraps the `Some`
/// unconditionally (preserving its exact prior behavior and `Result<JoinHandle<()>>` return
/// type) — only a reparse triggered by something other than the document's own edit stream
/// needs a real guard, and therefore ever observes `None`.
#[allow(
    clippy::too_many_arguments,
    reason = "issue #592 added `refetch: RefetchPolicy` alongside the pre-existing `guard: \
              CommitGuard` — both are commit/fetch-behavior switches the caller must set \
              independently; bundling them into one struct would only relocate, not reduce, \
              the parameter list"
)]
#[tracing::instrument(
    skip_all,
    fields(uri = ?uri, ecosystem = tracing::field::Empty, doc_version = ?version)
)]
pub(crate) async fn handle_document_change_guarded(
    uri: Uri,
    content: String,
    version: Option<i32>,
    guard: CommitGuard,
    refetch: RefetchPolicy,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<Option<JoinHandle<()>>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {:?}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
                "{uri:?}"
            )));
        }
    };
    tracing::Span::current().record("ecosystem", ecosystem.id());

    check_content_size(&content, &uri)?;

    let (parse_result, diff) = parse_and_diff_manifest(&uri, &content, &state, &ecosystem).await;

    // Captured before `commit_parsed_document` consumes `parse_result` — only needed under
    // `RefetchPolicy::AllDependencies` (issue #592), where the fetch must cover every
    // dependency in the new manifest rather than only what `diff` calls for: a
    // routing-only config change leaves the manifest's dependency set unchanged, so `diff`
    // alone would see nothing to fetch.
    let all_dependency_names: Vec<PackageName> = match refetch {
        RefetchPolicy::Diff => Vec::new(),
        RefetchPolicy::AllDependencies => parse_result
            .as_deref()
            .map(|pr| dependency_version_map(pr).into_keys().collect())
            .unwrap_or_default(),
    };

    if !commit_parsed_document(
        &uri,
        ecosystem.as_ref(),
        content,
        parse_result,
        version,
        &state,
        CommitOptions { diff: &diff, guard },
    ) {
        return Ok(None);
    }

    // Clone cache, diagnostics, and freshness config before spawning background task
    // (all read here, before any OSV request is built — FR-011).
    let (cache_config, vulnerabilities_enabled, freshness_settings, diagnostic_severities, offline) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
            cfg.diagnostics.to_severities(),
            cfg.network.offline,
        )
    };

    let needs_osv_rescan = diff.needs_osv_rescan();
    let deps_to_fetch = match refetch {
        RefetchPolicy::Diff => {
            // The yanked probe must also re-run for a version-only edit, not just a
            // newly added dependency — otherwise editing a dependency's pin from a
            // safe version to a yanked one would never be checked, since an empty
            // `deps_to_fetch` skips the entire registry fetch below (security F1).
            let mut v = diff.added;
            v.extend(diff.version_changed);
            v
        }
        RefetchPolicy::AllDependencies => all_dependency_names,
    };

    // Spawn background task to update diagnostics. Captured before `tokio::spawn` so
    // this task's own span (and everything it spawns in turn) nests under whichever
    // request span triggered this change, instead of opening as an unparented root
    // span (#756 S1).
    let span = tracing::Span::current();
    let task = tokio::spawn(
        run_document_change_task(
            uri,
            state,
            ecosystem,
            client,
            ChangeTaskConfig {
                cache: cache_config,
                vulnerabilities_enabled,
                freshness: freshness_settings,
                diagnostic_severities,
                offline,
                refetch,
            },
            needs_osv_rescan,
            deps_to_fetch,
        )
        .instrument(span),
    );

    Ok(Some(task))
}

/// Config values snapshotted from `DepsConfig` before spawning [`run_document_change_task`]
/// (FR-011: all read before any OSV request is built), so the task never needs to hold the
/// config lock itself. Bundled into one struct rather than five parameters since every field
/// is captured together by the same snapshot in [`handle_document_change`].
struct ChangeTaskConfig {
    cache: crate::config::CacheConfig,
    vulnerabilities_enabled: bool,
    freshness: deps_core::FreshnessSettings,
    diagnostic_severities: deps_core::DiagnosticSeverities,
    offline: bool,
    refetch: RefetchPolicy,
}

/// Background task spawned by [`handle_document_change`] once the new document state has
/// been committed: reloads lock-file-resolved versions, then runs the OSV rescan
/// concurrently with any registry fetch the diff calls for, and finally publishes the
/// resulting diagnostics.
#[tracing::instrument(skip_all, fields(uri = ?uri, ecosystem = ecosystem.id()))]
async fn run_document_change_task(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    client: Client,
    config: ChangeTaskConfig,
    needs_osv_rescan: bool,
    deps_to_fetch: Vec<PackageName>,
) {
    // Small debounce delay
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Load resolved versions from lock file first (instant, no network)
    let (resolved_versions, resolved_version_candidates) =
        load_resolved_versions(&uri, &state, ecosystem.as_ref()).await;

    // Update document state with resolved versions only
    // Do NOT touch cached_versions - they contain latest registry versions
    if !resolved_versions.is_empty()
        && let Some(mut doc) = state.documents.get_mut(&uri)
    {
        doc.update_resolved_versions(
            resolved_versions.clone(),
            resolved_version_candidates.clone(),
        );
    }

    // Phase A OSV scan (only when a dependency was added or an existing
    // one's version changed — critique S1), spawned so it runs
    // concurrently with the registry fetch below.
    let osv_task = (config.vulnerabilities_enabled && needs_osv_rescan).then(|| {
        tokio::spawn(
            run_osv_scan_phase_a(
                uri.clone(),
                Arc::clone(&state),
                Arc::clone(&ecosystem),
                config.cache.fetch_timeout_secs,
            )
            .instrument(tracing::Span::current()),
        )
    });

    // Tier-3 license pre-fetch (issue #660), re-run on the same trigger as the OSV
    // rescan above (a dependency was added or an existing one's version changed) —
    // an edit that touches neither has no new resolved version to fetch a license
    // for, so re-running would just repeat the previous pre-fetch's result. Joined
    // (round 3 finding #3) via `await_license_prefetch` below, same shape as
    // `osv_task`, so its commit lands before either of this function's diagnostics
    // publishes below, not after.
    let license_task = needs_osv_rescan.then(|| {
        tokio::spawn(
            run_license_prefetch(
                uri.clone(),
                Arc::clone(&state),
                Arc::clone(&ecosystem),
                config.cache.fetch_timeout_secs,
            )
            .instrument(tracing::Span::current()),
        )
    });

    // Skip registry fetch if nothing new was added and no existing
    // dependency's version changed.
    //
    // Known limitation (#424 N2): editing composer.json's `minimum-stability` field alone
    // adds no dependency and changes no requirement string, so `deps_to_fetch` stays empty
    // and this early-return skips the fetch — existing dependencies keep their
    // `cached_versions` computed under the *previous* stability floor until the document
    // is closed and reopened. Not fixed here: doing so would mean treating a
    // `minimum_stability` change as its own full-refetch trigger in the diff above, a
    // separate concern from #424's parse+thread scope.
    if deps_to_fetch.is_empty() {
        tracing::debug!("no added or version-changed dependencies, skipping registry fetch");

        if let Some(mut doc) = state.documents.get_mut(&uri) {
            doc.set_loaded();
        }

        // Detached, capability-gated, timeout-bounded (issue #493): see
        // `ServerState::spawn_refresh_requests` for rationale.
        state.spawn_refresh_requests(&client);

        await_and_commit_osv_phase_b(
            osv_task,
            &uri,
            &state,
            ecosystem.as_ref(),
            config.cache.fetch_timeout_secs,
        )
        .await;
        await_license_prefetch(license_task).await;

        generate_and_publish_diagnostics(&state, &uri, &client, &config, 0).await;
        return;
    }

    // Bounds total outbound fetch concurrency across every open/changed document
    // server-wide (issue #592 S2/S3). Held across the fetch and the merge below, released
    // before the failure toast / OSV phase B / diagnostics publish — none of those take a
    // permit themselves, and OSV phase A (spawned separately, above) never does either, so
    // there is no permit-holder-awaits-permit-taker deadlock shape here.
    // `state.fetch_permits` is never `.close()`d anywhere in deps-lsp, so `acquire()`
    // cannot return `Closed`.
    #[allow(clippy::expect_used)]
    let fetch_permit = state
        .fetch_permits
        .acquire()
        .await
        .expect("fetch_permits semaphore is never closed");

    let dep_count = deps_to_fetch.len();
    let (progress, fetch_result, attempted_names, collided_names) =
        fetch_registry_versions_for_change(
            &uri,
            &state,
            &client,
            ecosystem.as_ref(),
            &resolved_versions,
            &resolved_version_candidates,
            deps_to_fetch,
            config.freshness,
            config.cache.fetch_timeout_secs,
            config.cache.max_concurrent_fetches,
            config.refetch,
        )
        .await;

    let success = !fetch_result.versions.is_empty();

    // Merge new versions into existing cache
    let (failed_count, first_error) = merge_registry_fetch_result(
        &state,
        &uri,
        ecosystem.formatter(),
        fetch_result,
        &attempted_names,
        collided_names,
        success,
    );
    drop(fetch_permit);

    if let Some(progress) = progress {
        progress.end(success).await;
    }

    // Notify user about failed packages — suppressed when offline, see
    // `fetch_failure_toast`'s docs. `fetch_result.first_error` is always populated
    // by `fetch_latest_versions_parallel` whenever `failed_count > 0` (#480: every
    // site that increments `failed_count` also sets either `priority_error` or
    // `first_error`, and the two are merged into this field before returning).
    match fetch_failure_toast(
        failed_count,
        first_error.as_deref(),
        state.cache.is_offline(),
    ) {
        Some(message) => {
            client.show_message(MessageType::WARNING, message).await;
        }
        None if failed_count > 0 => {
            tracing::debug!(failed_count, "suppressing fetch-failure toast: offline");
        }
        None => {}
    }

    // Detached, capability-gated, timeout-bounded (issue #493): see
    // `ServerState::spawn_refresh_requests` for rationale.
    state.spawn_refresh_requests(&client);

    await_and_commit_osv_phase_b(
        osv_task,
        &uri,
        &state,
        ecosystem.as_ref(),
        config.cache.fetch_timeout_secs,
    )
    .await;
    await_license_prefetch(license_task).await;

    generate_and_publish_diagnostics(&state, &uri, &client, &config, dep_count).await;
}

/// Awaits the concurrently-spawned OSV phase-A scan, if one was started, and — when it
/// produced a result — runs phase B against the now-resolved registry versions and commits
/// the outcome. Shared by both branches of [`run_document_change_task`] (nothing to fetch
/// vs. a full registry fetch), which otherwise diverge before OSV handling but must treat
/// it identically.
async fn await_and_commit_osv_phase_b(
    osv_task: Option<JoinHandle<Option<OsvScanResult>>>,
    uri: &Uri,
    state: &Arc<ServerState>,
    ecosystem: &dyn Ecosystem,
    fetch_timeout_secs: u64,
) {
    let Some(osv_task) = osv_task else {
        return;
    };
    match osv_task.await {
        Ok(Some(phase_a_result)) => {
            let ecosystem_id = ecosystem.ecosystem_id();
            run_osv_phase_b_and_commit(
                uri,
                state,
                ecosystem_id,
                ecosystem.formatter(),
                fetch_timeout_secs,
                phase_a_result,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("OSV scan task failed: {e}"),
    }
}

/// Awaits a concurrently-spawned [`run_license_prefetch`] task, if one was started, so
/// its commit lands before the caller's own diagnostics publish (round 3 finding #3) —
/// mirrors [`await_and_commit_osv_phase_b`]'s join shape, minus the phase-B step
/// `run_license_prefetch` doesn't have (it commits directly, no separate phase). `task`
/// is `Option`-wrapped for the change-path call site, which only spawns the pre-fetch
/// when a rescan is actually needed; the open-path call site always spawns one, so it
/// wraps its `JoinHandle` in `Some` itself.
async fn await_license_prefetch(task: Option<JoinHandle<()>>) {
    let Some(task) = task else {
        return;
    };
    if let Err(e) = task.await {
        tracing::warn!("license pre-fetch task failed: {e}");
    }
}

/// Generates diagnostics from the current document/cache state and publishes them to the
/// client. Shared by both branches of [`run_document_change_task`], each of which must end
/// with an up-to-date publish regardless of whether a registry fetch actually ran.
///
/// Takes `&ChangeTaskConfig` rather than its individual fields (both call sites already hold
/// one) plus `dep_count`, the one value that isn't part of that snapshot — a fetch-batch size
/// only the caller knows.
async fn generate_and_publish_diagnostics(
    state: &Arc<ServerState>,
    uri: &Uri,
    client: &Client,
    config: &ChangeTaskConfig,
    dep_count: usize,
) {
    let diags = diagnostics::generate_diagnostics_internal(
        Arc::clone(state),
        uri,
        config.freshness,
        config.diagnostic_severities,
        config.offline,
        diagnostics::loading_ceiling(
            config.cache.fetch_timeout_secs,
            dep_count,
            config.cache.max_concurrent_fetches,
        ),
    )
    .await;
    client.publish_diagnostics(uri.clone(), diags, None).await;
}

/// Ensures a document is loaded in state.
///
/// If the document is not already in state, loads it from disk,
/// parses it, and spawns a background task to fetch version information.
///
/// This function is idempotent - calling it multiple times with the
/// same URI is safe and will only load once.
///
/// # Arguments
///
/// * `uri` - Document URI
/// * `state` - Server state
/// * `client` - LSP client for notifications
/// * `config` - Server configuration
///
/// # Returns
///
/// * `true` - Document is now loaded (either already existed or was just loaded)
/// * `false` - Document could not be loaded (unsupported file type, read error, etc.)
///
/// # Behavior
///
/// - If document exists in state → Return true immediately (no-op)
/// - If document doesn't exist → Load from disk, parse, update state, spawn bg task
/// - If load fails → Log warning and return false (graceful degradation)
///
/// # Examples
///
/// ```no_run
/// use deps_lsp::document::ensure_document_loaded;
/// use deps_lsp::document::ServerState;
/// use tower_lsp_server::ls_types::Uri;
/// use std::sync::Arc;
///
/// # async fn example(
/// #     uri: &Uri,
/// #     state: Arc<ServerState>,
/// #     client: tower_lsp_server::Client,
/// #     config: Arc<tokio::sync::RwLock<deps_lsp::config::DepsConfig>>,
/// # ) {
/// let loaded = ensure_document_loaded(uri, state, client, config).await;
/// if loaded {
///     println!("Document is available for processing");
/// }
/// # }
/// ```
#[tracing::instrument(skip_all, fields(uri = ?uri), level = "debug")]
pub async fn ensure_document_loaded(
    uri: &Uri,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> bool {
    // Fast path: document already loaded
    if state.get_document(uri).is_some() {
        tracing::debug!("Document already loaded: {:?}", uri);
        return true;
    }

    // Clone cold start config before async operations to release lock
    let cold_start_config = { config.read().await.cold_start.clone() };

    // Check if cold start is enabled
    if !cold_start_config.enabled {
        tracing::debug!("Cold start disabled via configuration");
        return false;
    }

    // Rate limiting check
    if !state.cold_start_limiter.allow_cold_start(uri) {
        tracing::warn!("Cold start rate limited: {:?}", uri);
        return false;
    }

    // Check if we support this file type
    if state.ecosystem_registry.get_for_uri(uri).is_none() {
        tracing::debug!("Unsupported file type: {:?}", uri);
        return false;
    }

    // Load from disk
    tracing::info!("Loading document from disk (cold start): {:?}", uri);
    let content = match load_document_from_disk(uri).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to load document {:?}: {}", uri, e);
            client
                .log_message(MessageType::WARNING, format!("Could not load file: {e}"))
                .await;
            return false;
        }
    };

    // Reuse existing handle_document_open logic. `version: None` — content came from
    // disk, not an LSP didOpen, so there is no client-tracked version to record (see
    // `DocumentState::version` and the cold-start refusal in `handlers::code_lens`).
    match handle_document_open(
        uri.clone(),
        content,
        None,
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    {
        Ok(task) => {
            state.spawn_background_task(uri.clone(), task).await;
            tracing::info!("Document loaded successfully from disk: {:?}", uri);
            true
        }
        Err(e) => {
            tracing::warn!("Failed to process loaded document {:?}: {}", uri, e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::diff::drop_cache_for_forced_refetch;
    use super::super::fetch::FetchResult;
    use super::*;
    use deps_core::EcosystemId;
    use deps_core::Registry;
    use deps_core::RemovalStatus;
    use std::time::Duration;

    /// #796: the dependency-count ceiling applies through the full `deps-lsp`
    /// document-open pipeline for a real ecosystem parser (Cargo), not just the
    /// `deps-core` wrapper in isolation (`deps_core::dependency_cap`'s own tests) —
    /// `DocumentState` only ever tracks the capped subset, and the informational ceiling
    /// diagnostic is published alongside it.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_document_over_dependency_ceiling_is_capped_and_reports_a_diagnostic() {
        // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `parse_manifest_blocking`
        // (cargo) transitively touches fs_probe (via `discover_workspace`), and this test
        // runs in the same binary as `document/loader.rs`'s diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/over-ceiling/Cargo.toml");

        let cap = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut content = String::from("[dependencies]\n");
        for i in 0..=cap {
            content.push_str(&format!("dep-{i} = \"1.0.0\"\n"));
        }

        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = deps_core::parse_manifest_blocking(&ecosystem, &content, &uri)
            .await
            .unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            cap,
            "a manifest declaring cap + 1 dependencies must be truncated to the cap"
        );

        let doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let diags = diagnostics::generate_diagnostics_internal(
            Arc::clone(&state),
            &uri,
            deps_core::FreshnessSettings::default(),
            deps_core::DiagnosticSeverities::default(),
            false,
            diagnostics::loading_ceiling(
                crate::config::CacheConfig::default().fetch_timeout_secs,
                cap,
                crate::config::CacheConfig::default().max_concurrent_fetches,
            ),
        )
        .await;

        assert!(
            diags.iter().any(|d| d
                .message
                .contains("exceeding deps-lsp's per-document limit")),
            "expected the dependency-ceiling informational diagnostic, got: {diags:?}"
        );
    }

    /// #796 (impl-critic M3): a manifest declaring exactly the ceiling — not `cap + 1` —
    /// through a real ecosystem parser (Cargo) must be parsed in full, untruncated, with no
    /// ceiling diagnostic. Companion to the over-ceiling test above; the `== cap` boundary
    /// was previously covered only by `deps_core::dependency_cap`'s stub-based unit test,
    /// never through a real parser's own dependency-collecting loop.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_document_at_exactly_the_dependency_ceiling_is_not_truncated() {
        // See the comment in `test_document_over_dependency_ceiling_is_capped_and_reports_a_diagnostic`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/at-ceiling/Cargo.toml");

        let cap = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut content = String::from("[dependencies]\n");
        for i in 0..cap {
            content.push_str(&format!("dep-{i} = \"1.0.0\"\n"));
        }

        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = deps_core::parse_manifest_blocking(&ecosystem, &content, &uri)
            .await
            .unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            cap,
            "a manifest declaring exactly the cap must not lose any dependency"
        );
        assert_eq!(
            parse_result.dependency_truncation(),
            None,
            "a manifest declaring exactly the cap must not be reported as truncated"
        );

        let doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let diags = diagnostics::generate_diagnostics_internal(
            Arc::clone(&state),
            &uri,
            deps_core::FreshnessSettings::default(),
            deps_core::DiagnosticSeverities::default(),
            false,
            diagnostics::loading_ceiling(
                crate::config::CacheConfig::default().fetch_timeout_secs,
                cap,
                crate::config::CacheConfig::default().max_concurrent_fetches,
            ),
        )
        .await;

        assert!(
            !diags.iter().any(|d| d
                .message
                .contains("exceeding deps-lsp's per-document limit")),
            "a manifest at exactly the ceiling must get no ceiling diagnostic, got: {diags:?}"
        );
    }

    /// Issue #592: `RefetchPolicy::AllDependencies`'s cache-drop mechanism, and the
    /// residual risk it accepts (forced-refetch-then-total-failure must render "Registry
    /// lookup failed", never "Unknown package").
    mod refetch_policy_tests {
        use super::*;
        use deps_core::PackageVersions;

        /// A no-op formatter with identity name normalization — no ecosystem-specific
        /// behavior is under test here, just `drop_cache_for_forced_refetch`'s own
        /// bookkeeping. Mirrors `test_utils::blocking_ecosystem::NoopFormatter`.
        struct IdentityFormatter;
        impl deps_core::lsp_helpers::PackageNaming for IdentityFormatter {}
        impl deps_core::lsp_helpers::PackageRendering for IdentityFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
        }
        impl deps_core::lsp_helpers::RequirementResolution for IdentityFormatter {}
        impl deps_core::lsp_helpers::DiagnosticMessages for IdentityFormatter {}
        impl deps_core::lsp_helpers::DiagnosticPolicy for IdentityFormatter {}
        impl deps_core::lsp_helpers::SourcePolicy for IdentityFormatter {}
        impl deps_core::lsp_helpers::OsvNaming for IdentityFormatter {}

        /// Critic S1 fix: a dependency about to be refetched is marked
        /// `FetchFailure::NotAttempted` (a placeholder, not left absent) — see
        /// `drop_cache_for_forced_refetch`'s doc for why an absent entry is unsafe.
        #[test]
        fn test_drop_cache_for_forced_refetch_marks_pending_deps_not_attempted() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                PackageVersions::latest_only("1.0.0"),
            )]));
            doc.update_resolved_versions(
                HashMap::from([(PackageName::new("serde"), ConcreteVersion::new("1.0.0"))]),
                HashMap::new(),
            );
            doc.replace_outcomes(
                DependencyOutcomes::new()
                    .with_fetch_failure("serde", FetchFailure::Transient)
                    .with_yanked(
                        "other",
                        (ConcreteVersion::new("2.0.0"), RemovalStatus::Yanked),
                    ),
            );

            drop_cache_for_forced_refetch(
                &mut doc,
                &[PackageName::new("serde")],
                &IdentityFormatter,
            );

            assert!(
                doc.cached_versions.is_empty(),
                "cached_versions must be dropped"
            );
            assert_eq!(
                doc.outcomes.fetch_failure("serde"),
                Some(&FetchFailure::NotAttempted),
                "the stale fetch-failure finding must be replaced with a NotAttempted \
                 placeholder, not left absent (S1: an absent entry surviving into a \
                 concurrent empty-diff commit renders as the misleading 'Unknown package')"
            );
            assert!(
                doc.outcomes.yanked("other").is_some(),
                "a yanked finding on a different package must survive untouched"
            );
            assert_eq!(
                doc.resolved_versions.len(),
                1,
                "resolved_versions (lockfile-derived, registry-independent) must survive"
            );
        }

        /// A dependency NOT in `deps_to_fetch` (e.g. one the diff-based path wouldn't have
        /// touched) must not gain a placeholder it was never asked to carry.
        #[test]
        fn test_drop_cache_for_forced_refetch_does_not_mark_deps_outside_the_fetch_list() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                PackageVersions::latest_only("1.0.0"),
            )]));

            drop_cache_for_forced_refetch(&mut doc, &[], &IdentityFormatter);

            assert!(doc.cached_versions.is_empty());
            assert!(
                doc.outcomes.fetch_failure("serde").is_none(),
                "a dependency outside deps_to_fetch must not be given a placeholder"
            );
        }

        /// Residual risk 4 (accepted, per the #592 design review): after a forced
        /// refetch drops the document's cache, a *total* fetch failure must render
        /// "Registry lookup failed" for the affected dependency, never "Unknown
        /// package" — an empty cache must not be conflated with "genuinely not found".
        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn test_forced_refetch_total_failure_renders_lookup_failed_not_unknown_package() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `ecosystem.parse_manifest`
            // transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.set_version(Some(1));
            // Stale cache from before the forced refetch — must not survive to be
            // conflated with fresh data, and must not leak into the "not found" path
            // either once dropped.
            doc_state.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                PackageVersions::latest_only("1.0.999"),
            )]));
            state.update_document(uri.clone(), doc_state);

            // Simulate `fetch_registry_versions_for_change`'s `AllDependencies` drop.
            if let Some(mut doc) = state.documents.get_mut(&uri) {
                drop_cache_for_forced_refetch(
                    &mut doc,
                    &[PackageName::new("serde")],
                    ecosystem.formatter(),
                );
            }

            // Simulate a total registry outage: the one dependency in the manifest failed,
            // nothing was fetched — exactly what `ErrorRegistry` produces in
            // `fetch_latest_versions_parallel`'s own tests.
            let fetch_result = FetchResult {
                versions: HashMap::new(),
                yanked_versions: HashMap::new(),
                fetch_failed: HashMap::from([(PackageName::new("serde"), FetchFailure::Transient)]),
                deprecations: HashMap::new(),
                no_comparable_versions: HashSet::new(),
                failed_count: 1,
                first_error: Some("network down".to_string()),
                licenses: HashMap::new(),
            };

            let (failed_count, _) = merge_registry_fetch_result(
                &state,
                &uri,
                ecosystem.formatter(),
                fetch_result,
                &[PackageName::new("serde")],
                HashSet::new(),
                false,
            );
            assert_eq!(failed_count, 1);

            let diags = diagnostics::generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
                false,
                diagnostics::loading_ceiling(
                    crate::config::CacheConfig::default().fetch_timeout_secs,
                    1,
                    crate::config::CacheConfig::default().max_concurrent_fetches,
                ),
            )
            .await;

            assert!(
                diags
                    .iter()
                    .any(|d| d.message.contains("Registry lookup failed")),
                "expected a 'Registry lookup failed' diagnostic, got: {diags:?}"
            );
            assert!(
                diags.iter().all(|d| !d.message.contains("Unknown package")),
                "must never render 'Unknown package' when the cache was dropped by a \
                 forced refetch, got: {diags:?}"
            );
        }

        /// Critic S1 (blocking): the gap this fix actually closes, not just the drop
        /// mechanism in isolation. After `RefetchPolicy::AllDependencies` drops the cache
        /// (real fetch not yet complete — it's behind a debounce plus network latency), a
        /// concurrent or subsequent plain edit with *unchanged* content
        /// (`RefetchPolicy::Diff`) can commit before that fetch ever merges real results.
        /// Its diff is empty (nothing textually changed), so `deps_to_fetch` stays empty and
        /// `run_document_change_task`'s early-return path never touches the outcome map —
        /// `preserve_cache` alone decides what survives into the new `DocumentState`. Without
        /// the S1 placeholder, that would carry forward an outcomes map with no entry for the
        /// dropped dependency, indistinguishable from "checked, nothing found", and render
        /// the misleading "Unknown package" indefinitely (until the *original* forced
        /// refetch's own task eventually completes and overwrites it — an unbounded window
        /// for a document with no lockfile, since the `in_lockfile` guard doesn't apply).
        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn test_concurrent_diff_edit_after_forced_refetch_drop_does_not_render_unknown_package()
         {
            // See the comment in `test_forced_refetch_total_failure_renders_lookup_failed_not_unknown_package` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            // No lock file for this manifest path — the `in_lockfile` guard in
            // `handlers::diagnostics` must not be what's saving this test; it's specifically
            // exercising the case that guard cannot help with (NuGet `.csproj`, a fresh
            // Cargo checkout without `Cargo.lock`, a lock-less `package.json`/`pyproject.toml`).
            let uri = deps_core::test_util::test_uri("/test/no-lockfile/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.clone(),
                parse_result,
            );
            doc_state.set_version(Some(1));
            doc_state.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                PackageVersions::latest_only("1.0.999"),
            )]));
            state.update_document(uri.clone(), doc_state);

            // Step 1: the forced refetch's drop has run, but (in this test) its own fetch
            // never gets a chance to complete before step 2 lands — the exact race S1
            // describes.
            if let Some(mut doc) = state.documents.get_mut(&uri) {
                drop_cache_for_forced_refetch(
                    &mut doc,
                    &[PackageName::new("serde")],
                    ecosystem.formatter(),
                );
            }

            // Step 2: a plain edit with unchanged content commits — empty diff, so
            // `RefetchPolicy::Diff`'s `deps_to_fetch` stays empty and the early-return path
            // runs, never touching `outcomes` itself; only `preserve_cache` decides what
            // carries forward.
            let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();
            let task = handle_document_change_guarded(
                uri.clone(),
                content,
                Some(2),
                CommitGuard::Unconditional,
                RefetchPolicy::Diff,
                Arc::clone(&state),
                client,
                config,
            )
            .await
            .unwrap()
            .expect("CommitGuard::Unconditional never skips the commit");
            task.await.unwrap();

            let diags = diagnostics::generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
                false,
                diagnostics::loading_ceiling(
                    crate::config::CacheConfig::default().fetch_timeout_secs,
                    1,
                    crate::config::CacheConfig::default().max_concurrent_fetches,
                ),
            )
            .await;

            assert!(
                diags.iter().all(|d| !d.message.contains("Unknown package")),
                "S1 regression: a dropped-cache entry surviving preserve_cache into an \
                 empty-diff commit must never render as 'Unknown package', got: {diags:?}"
            );
        }
    }

    /// Issue #592 critic S2/M1: proves `fetch_permits` actually bounds concurrency when
    /// driven through the real `handle_document_open` entry point (not just the isolated
    /// semaphore primitive tested in `document::state`), and that a cold-start burst past
    /// the permit limit never flips a queued document to `Loading` before its permit
    /// arrives (the exact defect M1 fixed by moving the permit acquisition ahead of
    /// `set_loading()`/`RegistryProgress::start`).
    mod open_path_semaphore_e2e_tests {
        use super::*;
        use deps_core::ecosystem::BoxFuture;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticSeverities, EcosystemConfig, EcosystemFormatter,
            FreshnessSettings, Metadata, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy, Version, VersionData, completion::Completions,
        };
        use std::any::Any;
        use std::path::Path;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tokio::sync::Barrier;
        use tower_lsp_server::ls_types::{CodeLens, Diagnostic, InlayHint, Position, Range};

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}
        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }
        impl RequirementResolution for NoopFormatter {}
        impl deps_core::lsp_helpers::DiagnosticMessages for NoopFormatter {}
        impl deps_core::lsp_helpers::DiagnosticPolicy for NoopFormatter {}
        impl SourcePolicy for NoopFormatter {}
        impl OsvNaming for NoopFormatter {}

        struct FakeDependency {
            name: PackageName,
            version_requirement: VersionReq,
        }
        impl Dependency for FakeDependency {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::new(Position::new(0, 0), Position::new(0, 1))
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                Some(&self.version_requirement)
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> deps_core::parser::DependencySource {
                deps_core::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct FakeParseResult {
            uri: Uri,
            dep: FakeDependency,
        }
        impl deps_core::ParseResult for FakeParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![&self.dep]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Tracks concurrent holders and sleeps `delay` per call, standing in for a slow
        /// (but never-failing) registry — mirrors `ConcurrencyTrackingRegistry` above, but
        /// wired through a full `Ecosystem` so the real `run_document_open_background_task`
        /// entry point (permit acquisition included) is what's under test, not just
        /// `fetch_latest_versions_parallel` in isolation.
        struct SlowRegistry {
            current: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
            delay: Duration,
        }
        impl Registry for SlowRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>> {
                Box::pin(async move {
                    let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
                    self.max_seen.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(self.delay).await;
                    self.current.fetch_sub(1, Ordering::SeqCst);
                    Ok(vec![])
                })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
            ) -> BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>> {
                Box::pin(async move {
                    let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
                    self.max_seen.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(self.delay).await;
                    self.current.fetch_sub(1, Ordering::SeqCst);
                    Ok(None)
                })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>> {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct SlowFetchEcosystem {
            registry: Arc<SlowRegistry>,
        }
        impl Sealed for SlowFetchEcosystem {}
        impl Ecosystem for SlowFetchEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                uri: &'a Uri,
            ) -> BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>> {
                let uri = uri.clone();
                Box::pin(async move {
                    let parse_result: Box<dyn deps_core::ParseResult> = Box::new(FakeParseResult {
                        uri: uri.clone(),
                        dep: FakeDependency {
                            name: PackageName::new("pkg"),
                            version_requirement: VersionReq::new("*"),
                        },
                    });
                    Ok(parse_result)
                })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::clone(&self.registry) as Arc<dyn Registry>
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn generate_inlay_hints<'a>(
                &'a self,
                _parse_result: &'a dyn deps_core::ParseResult,
                _versions: VersionData<'a>,
                _loading_state: deps_core::LoadingState,
                _config: &'a EcosystemConfig,
            ) -> BoxFuture<'a, Vec<InlayHint>> {
                Box::pin(async move { vec![] })
            }
            fn generate_diagnostics<'a>(
                &'a self,
                _parse_result: &'a dyn deps_core::ParseResult,
                _versions: VersionData<'a>,
                _uri: &'a Uri,
                _freshness: FreshnessSettings,
                _severities: DiagnosticSeverities,
            ) -> BoxFuture<'a, Vec<Diagnostic>> {
                Box::pin(async move { vec![] })
            }
            fn generate_code_lenses<'a>(
                &'a self,
                _parse_result: &'a dyn deps_core::ParseResult,
                _content: &'a str,
                _versions: VersionData<'a>,
                _uri: &'a Uri,
                _command_id: &'a str,
                _severities: DiagnosticSeverities,
            ) -> BoxFuture<'a, Vec<CodeLens>> {
                Box::pin(async move { vec![] })
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn deps_core::ParseResult,
                _position: Position,
                _content: &'a str,
                _freshness: FreshnessSettings,
            ) -> BoxFuture<'a, Completions> {
                Box::pin(async move { Completions::default() })
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> BoxFuture<'a, Completions> {
                unimplemented!()
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[cfg(feature = "cargo")]
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        #[allow(
            clippy::async_yields_async,
            reason = "each spawned task deliberately returns handle_document_open's own \
                      JoinHandle so the test can await the outer spawn (proving the burst was \
                      actually launched) and the inner background task (its real fetch) \
                      separately, in two passes below"
        )]
        async fn test_fetch_permits_bound_holds_through_open_entry_point_with_no_premature_loading()
        {
            const N: usize = 8;
            const FETCH_PERMITS: usize = 4; // mirrors document::state's private FETCH_PERMITS

            let state = Arc::new(ServerState::new());
            let current = Arc::new(AtomicUsize::new(0));
            let max_seen = Arc::new(AtomicUsize::new(0));
            let registry = Arc::new(SlowRegistry {
                current: Arc::clone(&current),
                max_seen: Arc::clone(&max_seen),
                delay: Duration::from_millis(80),
            });
            // Overrides the real "cargo" registration (same id) with one whose registry is
            // slow-but-observable, so the burst below actually contends on `fetch_permits`
            // instead of resolving before any two calls could overlap.
            state
                .ecosystem_registry
                .register(Arc::new(SlowFetchEcosystem { registry }));

            let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();

            let uris: Vec<Uri> = (0..N)
                .map(|i| deps_core::test_util::test_uri(&format!("/test/pkg{i}/Cargo.toml")))
                .collect();

            // Polls `state.documents` for as long as fetches are in flight, tracking the
            // peak number simultaneously `Loading`. A violation of M1 (permit acquired only
            // around the fetch, not before `set_loading`) would flip every one of the N
            // documents to `Loading` immediately, well before any permit is granted.
            let max_loading = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let poller = tokio::spawn({
                let state = Arc::clone(&state);
                let uris = uris.clone();
                let max_loading = Arc::clone(&max_loading);
                let stop = Arc::clone(&stop);
                async move {
                    while !stop.load(Ordering::SeqCst) {
                        let loading_now = uris
                            .iter()
                            .filter(|uri| {
                                state.get_document(uri).is_some_and(|d| {
                                    d.loading_state == deps_core::LoadingState::Loading
                                })
                            })
                            .count();
                        max_loading.fetch_max(loading_now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
            });

            let barrier = Arc::new(Barrier::new(N));
            let mut handles = Vec::new();
            for uri in &uris {
                let uri = uri.clone();
                let state = Arc::clone(&state);
                let client = client.clone();
                let config = Arc::clone(&config);
                let barrier = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    barrier.wait().await;
                    handle_document_open(
                        uri,
                        "irrelevant-content".to_string(),
                        Some(1),
                        state,
                        client,
                        config,
                    )
                    .await
                    .unwrap()
                }));
            }

            let mut bg_tasks = Vec::new();
            for handle in handles {
                bg_tasks.push(handle.await.unwrap());
            }
            for task in bg_tasks {
                task.await.unwrap();
            }

            stop.store(true, Ordering::SeqCst);
            poller.await.unwrap();

            assert_eq!(
                max_seen.load(Ordering::SeqCst),
                FETCH_PERMITS,
                "fetch_permits must bound real concurrent registry calls through \
                 run_document_open_background_task to exactly P=4, neither more (unbounded) \
                 nor less (under-contended, meaning this test isn't exercising the bound)"
            );
            assert!(
                max_loading.load(Ordering::SeqCst) <= FETCH_PERMITS,
                "M1 regression: at most FETCH_PERMITS documents may be Loading at once — a \
                 cold-start burst must not flip every queued document to Loading before its \
                 permit arrives (observed peak: {})",
                max_loading.load(Ordering::SeqCst)
            );
            for uri in &uris {
                let doc = state.get_document(uri).unwrap();
                assert_ne!(
                    doc.loading_state,
                    deps_core::LoadingState::Loading,
                    "no document may be left stuck in Loading once every fetch has completed"
                );
            }
        }
    }

    // Generic tests (no feature flag required)

    #[test]
    fn test_ecosystem_registry_unknown_file() {
        let state = ServerState::new();
        let unknown_uri = deps_core::test_util::test_uri("/test/unknown.txt");
        assert!(state.ecosystem_registry.get_for_uri(&unknown_uri).is_none());
    }

    #[test]
    fn test_check_content_size_accepts_content_within_limit() {
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "a".repeat(MAX_FILE_SIZE as usize);
        assert!(check_content_size(&content, &uri).is_ok());
    }

    #[test]
    fn test_check_content_size_rejects_content_over_limit() {
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "a".repeat(MAX_FILE_SIZE as usize + 1);
        let result = check_content_size(&content, &uri);
        match result {
            Err(deps_core::error::DepsError::CacheError(msg)) => {
                assert!(msg.contains("too large"), "unexpected message: {msg}");
            }
            other => panic!("Expected CacheError, got {other:?}"),
        }
    }

    /// Round 3 code-review finding #5: `licenses` (raw-name-keyed, same as
    /// `resolved_version_candidates`) was missing from `commit_parsed_document`'s
    /// removed-dependency pruning loop entirely — a document with dependencies
    /// repeatedly added and removed while staying open would accumulate an
    /// ever-growing set of orphaned license entries never reclaimed until the
    /// document closed. Calls the real `commit_parsed_document` (not a hand-copied
    /// pruning loop, unlike the sibling tests above) so this actually exercises the
    /// fixed function, not a re-implementation of it.
    #[tokio::test]
    async fn test_licenses_pruned_on_dependency_removal() {
        // See the comment in `test_forced_refetch_total_failure_renders_lookup_failed_not_unknown_package` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let content1 = r#"[dependencies]
serde = "1.0"
anyhow = "1.0"
"#;
        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
        let doc_state1 = DocumentState::new_from_parse_result(
            EcosystemId::Cargo,
            content1.to_string(),
            parse_result1,
        );
        state.update_document(uri.clone(), doc_state1);

        {
            let mut doc = state.documents.get_mut(&uri).unwrap();
            doc.licenses
                .insert(PackageName::new("serde"), vec!["MIT".to_string()]);
            doc.licenses
                .insert(PackageName::new("anyhow"), vec!["Apache-2.0".to_string()]);
        }

        // `anyhow` removed from the manifest — its license entry must be pruned
        // along with it, not left behind as an orphaned entry.
        let content2 = "[dependencies]\nserde = \"1.0\"\n";
        let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> = ["serde", "anyhow"]
            .iter()
            .map(|s| (PackageName::new(*s), vec![None]))
            .collect();
        let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
            std::iter::once((PackageName::new("serde"), vec![None])).collect();
        let diff = DependencyDiff::compute(&old_deps, &new_deps);
        assert_eq!(diff.removed, vec![PackageName::new("anyhow")]);

        let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
        let committed = commit_parsed_document(
            &uri,
            ecosystem.as_ref(),
            content2.to_string(),
            Some(parse_result2),
            None,
            &state,
            CommitOptions {
                diff: &diff,
                guard: CommitGuard::Unconditional,
            },
        );
        assert!(committed);

        let doc = state.get_document(&uri).unwrap();
        assert!(
            !doc.licenses.contains_key(&PackageName::new("anyhow")),
            "removed dependency's license entry must be pruned, got: {:?}",
            doc.licenses
        );
        assert_eq!(
            doc.licenses.get(&PackageName::new("serde")),
            Some(&vec!["MIT".to_string()]),
            "surviving dependency's license entry must be preserved"
        );
    }

    #[tokio::test]
    async fn test_ensure_document_loaded_unsupported_file_check() {
        // Returns false for unknown file types (e.g., README.md)
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/README.md");

        // Verify ecosystem registry correctly identifies unsupported files
        assert!(
            state.ecosystem_registry.get_for_uri(&uri).is_none(),
            "README.md should not have an ecosystem handler"
        );

        // This would cause ensure_document_loaded to return false
        // We test the underlying condition without needing Client
    }

    #[tokio::test]
    async fn test_ensure_document_loaded_file_not_found_check() {
        // Test that load_document_from_disk fails gracefully for missing files
        use super::load_document_from_disk;

        // Held per `fs_probe::snapshot_guard`'s doc: any fs_probe-touching test in this
        // binary must hold it, not just document/loader.rs's own diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let uri = deps_core::test_util::test_uri("/nonexistent/Cargo.toml");
        let result = load_document_from_disk(&uri).await;

        assert!(result.is_err(), "Should fail for missing files");

        // This error would cause ensure_document_loaded to return false
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let cargo_uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            assert!(state.ecosystem_registry.get_for_uri(&cargo_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `ecosystem.parse_manifest`
            // (cargo) transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            assert_eq!(state.document_count(), 1);
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id(), "cargo");
        }

        #[tokio::test]
        async fn test_document_stored_even_when_parsing_fails() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            // Invalid TOML that will fail parsing
            let content = r#"[dependencies
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem not found");

            // Try to parse (will fail)
            let parse_result = ecosystem.parse_manifest(content, &uri).await.ok();
            assert!(
                parse_result.is_none(),
                "Parsing should fail for invalid TOML"
            );

            // Create document state without parse result
            let doc_state = if let Some(pr) = parse_result {
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content.to_string(), pr)
            } else {
                DocumentState::new_without_parse_result(EcosystemId::Cargo, content.to_string())
            };

            state.update_document(uri.clone(), doc_state);

            // Document should be stored despite parse failure
            let doc = state.get_document(&uri);
            assert!(
                doc.is_some(),
                "Document should be stored even when parsing fails"
            );

            let doc = doc.unwrap();
            assert_eq!(doc.ecosystem_id(), "cargo");
            assert_eq!(doc.content, content);
            assert!(
                doc.parse_result().is_none(),
                "Parse result should be None for failed parse"
            );
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_fast_path() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Fast path: document already loaded, should return true without loading
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = r#"[dependencies]
serde = "1.0""#;

            // Pre-populate state with document
            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            // Fast path check: document exists
            assert!(
                state.get_document(&uri).is_some(),
                "Document should exist in state"
            );
            assert_eq!(state.document_count(), 1, "Document count should be 1");

            // The fast path in ensure_document_loaded would return true here without
            // requiring a Client. We test the condition directly since creating a test
            // Client requires complex tower-lsp-server internals (ServerState, ClientSocket).
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_successful_disk_load() {
            // Test successful load from filesystem with temp file
            use super::super::load_document_from_disk;
            use std::fs;
            use tempfile::TempDir;

            // Held per `fs_probe::snapshot_guard`'s doc: any fs_probe-touching test in this
            // binary must hold it, not just document/loader.rs's own diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;

            // Create a temporary directory with a Cargo.toml file
            let temp_dir = TempDir::new().unwrap();
            let cargo_toml_path = temp_dir.path().join("Cargo.toml");
            let content = r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
            fs::write(&cargo_toml_path, content).unwrap();

            let uri = Uri::from_file_path(&cargo_toml_path).unwrap();

            // Test that load_document_from_disk succeeds
            let loaded_content = load_document_from_disk(&uri).await.unwrap();
            assert_eq!(loaded_content, content);

            // Test that parsing succeeds
            let state = Arc::new(ServerState::new());
            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(&loaded_content, &uri).await;
            assert!(parse_result.is_ok(), "Should parse successfully");

            // These successful operations are the building blocks of ensure_document_loaded
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_idempotent_check() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Test that repeated loads are idempotent at the state level
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = r#"[dependencies]
serde = "1.0""#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");

            // Parse twice to simulate idempotent loads
            let parse_result1 = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let parse_result2 = ecosystem.parse_manifest(content, &uri).await.unwrap();

            // First update
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);
            assert_eq!(state.document_count(), 1);

            // Second update (idempotent)
            let doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result2,
            );
            state.update_document(uri.clone(), doc_state2);
            assert_eq!(
                state.document_count(),
                1,
                "Should still have only 1 document"
            );
        }

        #[tokio::test]
        async fn test_handle_document_open_rejects_oversized_content() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let oversized_content = "a".repeat(MAX_FILE_SIZE as usize + 1);
            let (client, config) = create_test_client_and_config();

            let result = handle_document_open(
                uri.clone(),
                oversized_content,
                Some(1),
                state.clone(),
                client,
                config,
            )
            .await;

            assert!(result.is_err(), "Oversized content should be rejected");
            match result {
                Err(deps_core::error::DepsError::CacheError(msg)) => {
                    assert!(
                        msg.contains("too large"),
                        "Error message should indicate size issue: {msg}"
                    );
                }
                other => panic!("Expected CacheError for oversized content, got {other:?}"),
            }
            assert_eq!(
                state.document_count(),
                0,
                "Oversized content must not be stored/parsed"
            );
        }

        #[tokio::test]
        async fn test_handle_document_open_accepts_normal_sized_content() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = r#"[dependencies]
serde = "1.0"
"#
            .to_string();
            let (client, config) = create_test_client_and_config();

            let result =
                handle_document_open(uri.clone(), content, Some(1), state.clone(), client, config)
                    .await;

            assert!(result.is_ok(), "Normal-sized content should be accepted");
            assert_eq!(state.document_count(), 1);
        }

        #[tokio::test]
        async fn test_handle_document_change_rejects_oversized_content() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let oversized_content = "a".repeat(MAX_FILE_SIZE as usize + 1);
            let (client, config) = create_test_client_and_config();

            let result = handle_document_change(
                uri.clone(),
                oversized_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await;

            assert!(result.is_err(), "Oversized content should be rejected");
            match result {
                Err(deps_core::error::DepsError::CacheError(msg)) => {
                    assert!(
                        msg.contains("too large"),
                        "Error message should indicate size issue: {msg}"
                    );
                }
                other => panic!("Expected CacheError for oversized content, got {other:?}"),
            }
            assert_eq!(
                state.document_count(),
                0,
                "Oversized content must not be stored/parsed"
            );
        }

        #[tokio::test]
        async fn test_handle_document_change_rejects_oversized_content_preserves_existing_document()
        {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let original_content = r#"[dependencies]
serde = "1.0"
"#
            .to_string();

            // Open a valid document first (mirrors an already-open editor buffer).
            let (client, config) = create_test_client_and_config();
            handle_document_open(
                uri.clone(),
                original_content.clone(),
                Some(1),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("initial open should succeed");
            assert_eq!(state.document_count(), 1);

            // An oversized didChange must be rejected without touching the stored document.
            let oversized_content = "a".repeat(MAX_FILE_SIZE as usize + 1);
            let (client, config) = create_test_client_and_config();
            let result = handle_document_change(
                uri.clone(),
                oversized_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await;

            assert!(result.is_err(), "Oversized change should be rejected");
            assert_eq!(
                state.document_count(),
                1,
                "The previously stored document must survive a rejected change"
            );
            let doc = state
                .get_document(&uri)
                .expect("original document should still be present");
            assert_eq!(
                doc.content, original_content,
                "Document content must be unchanged by the rejected change"
            );
        }

        /// Issue #493 regression: before the fix, `inlay_hint_refresh`/`code_lens_refresh`
        /// were awaited inline in the spawned background task, ahead of the OSV
        /// vulnerability commit and diagnostics publish. A client that declares refresh
        /// support (`ServerState`'s cached flag is `true`) but whose request never
        /// resolves must not be able to stall that commit — the calls are fire-and-forget
        /// now, so the background task must still reach a terminal loading state and
        /// return within a bounded time regardless of what the refresh call does.
        #[tokio::test]
        async fn test_handle_document_open_completes_promptly_with_refresh_support_enabled() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            state.set_inlay_hint_refresh_supported(true);
            state.set_code_lens_refresh_supported(true);

            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = r#"[dependencies]
serde = "1.0"
"#
            .to_string();
            let (client, config) = create_test_client_and_config();

            let task =
                handle_document_open(uri.clone(), content, Some(1), state.clone(), client, config)
                    .await
                    .expect("normal-sized content should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect(
                    "background task must complete promptly even with refresh support \
                     enabled (issue #493 regression: an inline refresh await could hang here)",
                )
                .expect("background task must not panic");

            let doc = state.get_document(&uri).expect("document should be stored");
            assert!(
                matches!(
                    doc.loading_state,
                    deps_core::LoadingState::Loaded | deps_core::LoadingState::Failed
                ),
                "document loading must reach a terminal state, proving the pipeline ran \
                 past the refresh call sites to commit OSV results and diagnostics: {:?}",
                doc.loading_state
            );
        }

        #[tokio::test]
        async fn test_handle_document_change_completes_promptly_with_refresh_support_enabled() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            state.set_inlay_hint_refresh_supported(true);
            state.set_code_lens_refresh_supported(true);

            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let original_content = r#"[dependencies]
serde = "1.0"
"#
            .to_string();
            let (client, config) = create_test_client_and_config();
            handle_document_open(
                uri.clone(),
                original_content,
                Some(1),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("initial open should succeed")
            .await
            .expect("initial open's background task must not panic");

            let changed_content = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#
            .to_string();
            let (client, config) = create_test_client_and_config();
            let task = handle_document_change(
                uri.clone(),
                changed_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("normal-sized change should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect(
                    "background task must complete promptly even with refresh support \
                     enabled (issue #493 regression: an inline refresh await could hang here)",
                )
                .expect("background task must not panic");

            let doc = state.get_document(&uri).expect("document should be stored");
            assert!(
                matches!(
                    doc.loading_state,
                    deps_core::LoadingState::Loaded | deps_core::LoadingState::Failed
                ),
                "document loading must reach a terminal state, proving the pipeline ran \
                 past the refresh call sites to commit OSV results and diagnostics: {:?}",
                doc.loading_state
            );
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let npm_uri = deps_core::test_util::test_uri("/test/package.json");
            assert!(state.ecosystem_registry.get_for_uri(&npm_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            // See the comment in `test_document_parsing` (cargo module) on why this guard
            // is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("npm ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Npm,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id(), "npm");
        }

        /// Impl-critic S1 regression: a version-guarded reparse whose `expected_version` no
        /// longer matches the document's *current* version (a concurrent `did_change` already
        /// landed) must not commit — the older, guarded reparse would otherwise silently
        /// revert the newer edit.
        #[tokio::test]
        async fn test_handle_document_change_guarded_skips_commit_when_version_changed() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let original_content = r#"{"dependencies": {"express": "^4.18.0"}}"#.to_string();
            let (client, config) = create_test_client_and_config();

            handle_document_open(
                uri.clone(),
                original_content,
                Some(1),
                Arc::clone(&state),
                client.clone(),
                Arc::clone(&config),
            )
            .await
            .unwrap();

            // A real, concurrent `did_change` lands and commits version 2 — simulating this
            // landing while a watched-config-triggered reparse (still snapshotted at version
            // 1) is in flight.
            let concurrent_content = r#"{"dependencies": {"express": "^4.19.0"}}"#.to_string();
            handle_document_change(
                uri.clone(),
                concurrent_content.clone(),
                Some(2),
                Arc::clone(&state),
                client.clone(),
                Arc::clone(&config),
            )
            .await
            .unwrap();

            // The watched-config-triggered reparse now runs, still expecting version 1 (its
            // stale pre-race snapshot) and carrying content from before the concurrent edit.
            let stale_content =
                r#"{"dependencies": {"express": "^4.18.0", "lodash": "^4.0.0"}}"#.to_string();
            let task = handle_document_change_guarded(
                uri.clone(),
                stale_content,
                Some(3),
                CommitGuard::ExpectVersion(Some(1)),
                RefetchPolicy::Diff,
                Arc::clone(&state),
                client,
                config,
            )
            .await
            .unwrap();
            assert!(
                task.is_none(),
                "a version mismatch must skip the commit and return None, never a sentinel \
                 task (impl-critic S3)"
            );

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.content, concurrent_content,
                "a stale guarded reparse must not overwrite content committed after its snapshot"
            );
            assert_eq!(doc.version, Some(2));
        }

        /// The mirror case: `expected_version` still matches the document's current version,
        /// so the guarded reparse must commit normally.
        #[tokio::test]
        async fn test_handle_document_change_guarded_commits_when_version_matches() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let original_content = r#"{"dependencies": {"express": "^4.18.0"}}"#.to_string();
            let (client, config) = create_test_client_and_config();

            handle_document_open(
                uri.clone(),
                original_content,
                Some(1),
                Arc::clone(&state),
                client.clone(),
                Arc::clone(&config),
            )
            .await
            .unwrap();

            let new_content = r#"{"dependencies": {"express": "^4.19.0"}}"#.to_string();
            let task = handle_document_change_guarded(
                uri.clone(),
                new_content.clone(),
                Some(1),
                CommitGuard::ExpectVersion(Some(1)),
                RefetchPolicy::Diff,
                Arc::clone(&state),
                client,
                config,
            )
            .await
            .unwrap();
            task.expect("a matching version must commit and spawn a real task")
                .await
                .unwrap();

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.content, new_content);
        }

        /// Impl-critic S3 regression: a skipped guarded reparse must never register a
        /// sentinel task via `spawn_background_task` — doing so would abort whatever real
        /// background task (e.g. a concurrent edit's own registry fetch + diagnostics
        /// publish) is already registered for that URI. Unlike the two tests above, this one
        /// exercises the actual task registry (`ServerState::spawn_background_task`), not
        /// just the returned handle directly.
        #[tokio::test]
        async fn test_guarded_reparse_skip_does_not_abort_pre_existing_background_task() {
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use std::sync::atomic::{AtomicBool, Ordering};

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let original_content = r#"{"dependencies": {"express": "^4.18.0"}}"#.to_string();
            let (client, config) = create_test_client_and_config();

            handle_document_open(
                uri.clone(),
                original_content,
                Some(1),
                Arc::clone(&state),
                client.clone(),
                Arc::clone(&config),
            )
            .await
            .unwrap();

            // Stands in for the real background task a concurrent `did_change` would already
            // have installed by the time a stale, guarded reparse runs.
            let ran_to_completion = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&ran_to_completion);
            let pre_existing_task = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                flag.store(true, Ordering::SeqCst);
            });
            state
                .spawn_background_task(uri.clone(), pre_existing_task)
                .await;

            // A guarded reparse whose expected version no longer matches — must skip. Mirrors
            // `Backend::handle_watched_config_change`'s exact branching: `spawn_background_task`
            // is called only on `Some`, never on a skip.
            let stale_content = r#"{"dependencies": {"express": "^4.19.0"}}"#.to_string();
            let result = handle_document_change_guarded(
                uri.clone(),
                stale_content,
                Some(2),
                CommitGuard::ExpectVersion(Some(999)),
                RefetchPolicy::Diff,
                Arc::clone(&state),
                client,
                config,
            )
            .await
            .unwrap();
            assert!(result.is_none(), "a version mismatch must skip the commit");
            if let Some(task) = result {
                state.spawn_background_task(uri.clone(), task).await;
            }

            // If the pre-existing task had instead been aborted, it would never reach the
            // `store(true, ...)` line above; give it well past its 50ms sleep to prove it ran
            // to completion undisturbed.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(
                ran_to_completion.load(Ordering::SeqCst),
                "the pre-existing background task must not be aborted by a skipped guarded reparse"
            );
        }
    }

    // Go-specific tests
    #[cfg(feature = "go")]
    mod go_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let go_uri = deps_core::test_util::test_uri("/test/go.mod");
            assert!(state.ecosystem_registry.get_for_uri(&go_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/go.mod");
            let content = r"module example.com/mymodule

go 1.21

require github.com/gorilla/mux v1.8.0
";

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("go ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Go,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id(), "go");
        }

        /// Regression test for critique S1 (`.local/handoff/2026-08-23T20-55-32-critic.md`):
        /// go.mod's `require` line is the exact MVS-selected version, but go.sum only ever
        /// gets appended to, so a stale higher version left over from a downgrade can still
        /// be recorded there and win last-occurrence-wins parsing (#235). The instant-cache
        /// seed in `handle_document_open` must not copy that stale value into
        /// `cached_versions` (the "latest" comparison operand) for such a dependency, or it
        /// would desync against the go.mod-accurate `resolved_versions` value during the
        /// cold-open window before the registry fetch completes.
        #[tokio::test]
        async fn test_handle_document_open_go_instant_cache_excludes_stale_require_version() {
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use std::fs;
            use tempfile::TempDir;
            use tokio::time::{Duration, sleep};

            let temp_dir = TempDir::new().unwrap();
            let go_mod_path = temp_dir.path().join("go.mod");
            let go_sum_path = temp_dir.path().join("go.sum");

            // go.mod was downgraded back to v1.8.0 after having briefly required v1.8.1.
            let go_mod_content = r"module example.com/mymodule

go 1.21

require github.com/gorilla/mux v1.8.0
";
            fs::write(&go_mod_path, go_mod_content).unwrap();

            // go.sum is a checksum ledger, not pruned on downgrade: it still carries the
            // higher v1.8.1 entry appended before the downgrade, which sorts last and wins
            // naive last-occurrence-wins parsing.
            let go_sum_content = r"github.com/gorilla/mux v1.8.0 h1:hash1=
github.com/gorilla/mux v1.8.1 h1:hash2=
";
            fs::write(&go_sum_path, go_sum_content).unwrap();

            let uri = Uri::from_file_path(&go_mod_path).unwrap();
            let state = Arc::new(ServerState::new());
            let (client, config) = create_test_client_and_config();

            handle_document_open(
                uri.clone(),
                go_mod_content.to_string(),
                Some(1),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("go.mod should open successfully");

            let dep_name = PackageName::new("github.com/gorilla/mux");

            // The instant-cache seed is disk-only (go.sum read) and runs before any
            // registry network call, but it happens in a spawned background task — poll
            // briefly instead of assuming a fixed delay.
            let mut resolved_seen = false;
            for _ in 0..200 {
                if state
                    .get_document(&uri)
                    .is_some_and(|doc| doc.resolved_versions.contains_key(&dep_name))
                {
                    resolved_seen = true;
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
            assert!(
                resolved_seen,
                "resolved_versions should be seeded from go.sum shortly after open"
            );

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.resolved_versions.get(&dep_name),
                Some(&ConcreteVersion::new("v1.8.1")),
                "sanity check: go.sum's last-occurrence-wins parsing does surface the stale version"
            );
            assert!(
                !doc.cached_versions.contains_key(&dep_name),
                "S1: a Go `require` dependency's stale go.sum version must not be seeded into \
                 cached_versions (the 'latest' comparison operand) during the cold-open window — \
                 doing so would desync it against the go.mod-accurate resolved value and produce \
                 a false 'outdated, update to the version you downgraded away from' signal"
            );
        }
    }
}
