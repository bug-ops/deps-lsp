//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::diff::{DependencyDiff, preserve_cache, reload_resolved_versions};
use super::fetch::{
    fetch_failure_toast, fetch_registry_versions_for_change, merge_registry_fetch_result,
};
use super::loader::{MAX_FILE_SIZE, load_document_from_disk};
use super::osv_scan::{
    OsvScanResult, run_license_prefetch, run_osv_phase_b_and_commit, run_osv_scan_phase_a,
};
use super::resolved::RefetchPolicy;
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
use deps_engine::classify::fetch::{fetch_latest_versions_parallel, prepare_fetch};
use deps_engine::classify::resolved::{
    cached_versions_from_lockfile, dependency_version_map, load_resolved_versions,
};
use std::collections::HashMap;
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
    // `from_lsp_uri` returning `None` (a URI shape `url::Url` rejects) is treated the
    // same as "no ecosystem handles this URI" — see its own doc for why this happens.
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
        tracing::debug!("URI is not representable as a url::Url: {:?}", uri);
        return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
            "{uri:?}"
        )));
    };

    let ecosystem = match state.ecosystem_registry.for_uri(&domain_uri) {
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

    let parse_result =
        deps_core::ecosystem::parse_manifest_blocking(&ecosystem, &content, &domain_uri)
            .await
            .inspect_err(|e| {
                tracing::debug!(
                    error = %e,
                    "Failed to parse manifest, storing document without parse result"
                );
            })
            .ok();

    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(ecosystem.ecosystem_id(), content, pr)
    } else {
        DocumentState::new_without_parse_result(ecosystem.ecosystem_id(), content)
    };
    doc_state.set_version(version);

    state.update_document(uri.clone(), doc_state);

    // Read before any OSV request is built, so disabling the feature suppresses the
    // network call itself (FR-011).
    let (diagnostics_snapshot, vulnerabilities_enabled) = {
        let cfg = config.read().await;
        (
            diagnostics::DiagnosticsSnapshot::from_config(&cfg),
            cfg.policy.diagnostics.vulnerabilities_enabled,
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
            diagnostics_snapshot,
            vulnerabilities_enabled,
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
    diagnostics_snapshot: diagnostics::DiagnosticsSnapshot,
    vulnerabilities_enabled: bool,
) {
    tracing::debug!("background task started");

    // `handle_document_open` already validated this exact `uri` converts successfully
    // before spawning this task, so `None` here is unreachable in practice — handled
    // defensively rather than unwrapped.
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
        tracing::warn!(
            "URI is not representable as a url::Url, aborting fetch: {:?}",
            uri
        );
        return;
    };

    // Lock file read is instant and network-free, so it runs before the registry fetch below.
    // The reload-ok signal (issue #1407) isn't needed on this cold-open path: there is no
    // prior in-memory `resolved_versions` yet for a transient parse failure to clobber.
    let (resolved_versions, resolved_version_candidates) =
        load_resolved_versions(&domain_uri, &state.lockfile_cache, ecosystem.as_ref())
            .await
            .into_maps();

    if !resolved_versions.is_empty()
        && let Some(mut doc) = state.documents.get_mut(&uri)
    {
        doc.update_resolved_versions(
            resolved_versions.clone(),
            resolved_version_candidates.clone(),
            state.next_resolved_versions_generation(),
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
                diagnostics_snapshot.fetch_timeout_secs,
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
            diagnostics_snapshot.fetch_timeout_secs,
        )
        .instrument(tracing::Span::current()),
    );

    // Collect dependency names+sources, the in-use-version map (§4.6), and the manifest's own
    // `SelectionContext` (#1433) in one pass while holding the reference (can't hold across
    // await). Deduped by name (critique M3): a duplicated name shares one registry fetch
    // across all its occurrences — the result is name-keyed anyway (`FetchResult::versions`),
    // so fetching it more than once would only issue wasted extra registry calls and inflate
    // `RegistryProgress`'s total. A non-resolvable source is dropped entirely, and two
    // occurrences of the same name resolving to *different* sources are dropped and recorded
    // as collided instead (spec FR-011) — see `prepare_fetch`/`dedup_dependencies_by_source`.
    let deps_engine::classify::fetch::FetchPreparation {
        dep_sources,
        in_use,
        selection_context,
        collided_names,
        ..
    } = {
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
        prepare_fetch(
            parse_result,
            ecosystem.formatter(),
            ecosystem.ecosystem_id(),
            &resolved_versions,
            &resolved_version_candidates,
        )
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

    let registry = ecosystem.registry();
    let fetch_result = fetch_latest_versions_parallel(
        registry,
        dep_sources,
        &in_use,
        progress_sender,
        diagnostics_snapshot.freshness,
        diagnostics_snapshot.fetch_timeout_secs,
        diagnostics_snapshot.max_concurrent_fetches,
        &selection_context,
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
                    diagnostics_snapshot.fetch_timeout_secs,
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
    diagnostics::publish_document_diagnostics(
        &state,
        &client,
        &uri,
        &diagnostics_snapshot,
        dep_count,
    )
    .await;
}

/// Parses the freshly-edited manifest content and diffs its dependencies against the
/// document's previously stored parse result, so the caller can react to what actually
/// changed (added/removed/version-changed) instead of unconditionally re-fetching and
/// re-scanning everything on every keystroke.
///
/// The returned `bool` is whether the manifest's own [`deps_core::SelectionContext`] (e.g.
/// Composer's `minimum-stability`, #1433) changed between the old and new parse — `diff`
/// alone cannot see this: editing only `minimum-stability` changes neither the dependency
/// name set nor any single dependency's version requirement, so it would otherwise report an
/// empty diff even though every dependency's "latest" pick may have just changed. The caller
/// must escalate to [`RefetchPolicy::AllDependencies`] when this is `true`, or hover/
/// completion/code-actions (which read the freshly committed parse result's context
/// immediately) would disagree with diagnostics/inlay-hints (which stay on `cached_versions`
/// from before the edit) until the next unrelated refetch.
async fn parse_and_diff_manifest(
    uri: &Uri,
    content: &str,
    state: &ServerState,
    ecosystem: &Arc<dyn Ecosystem>,
) -> (
    Option<Box<dyn deps_core::ParseResult>>,
    DependencyDiff,
    bool,
) {
    let (old_deps, old_selection_context): (
        HashMap<PackageName, Vec<Option<VersionReq>>>,
        deps_core::SelectionContext,
    ) = state.get_document(uri).map_or_else(
        || (HashMap::new(), deps_core::SelectionContext::none()),
        |doc| match doc.parse_result() {
            Some(pr) => (dependency_version_map(pr), pr.selection_context()),
            None => (HashMap::new(), deps_core::SelectionContext::none()),
        },
    );

    // Try to parse manifest (may fail for incomplete syntax, or for a URI shape
    // `url::Url` rejects — both are treated the same as "no parse result").
    let parse_result = match crate::lsp_types_interop::from_lsp_uri(uri) {
        Some(domain_uri) => {
            deps_core::ecosystem::parse_manifest_blocking(ecosystem, content, &domain_uri)
                .await
                .inspect_err(|e| {
                    tracing::debug!(
                        error = %e,
                        "Failed to parse manifest, storing document without parse result"
                    );
                })
                .ok()
        }
        None => {
            tracing::debug!("URI is not representable as a url::Url: {:?}", uri);
            None
        }
    };

    let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> = parse_result
        .as_ref()
        .map(|pr| dependency_version_map(pr.as_ref()))
        .unwrap_or_default();
    let new_selection_context = parse_result
        .as_deref()
        .map_or_else(deps_core::SelectionContext::none, |pr| {
            pr.selection_context()
        });
    let selection_context_changed = old_selection_context != new_selection_context;

    let diff = DependencyDiff::compute(&old_deps, &new_deps);
    tracing::debug!(
        added = diff.added.len(),
        removed = diff.removed.len(),
        version_changed = diff.version_changed.len(),
        selection_context_changed,
        "dependency diff"
    );

    (parse_result, diff, selection_context_changed)
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
        let removed_normalized_name = formatter.normalize_package_name(removed_dep);
        doc_state
            .vulnerabilities
            .retain(|key, _| key.as_str() != removed_normalized_name);
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

    // Issue #1424 (impl-critic round 2, S2): a manifest edit that changes a dependency's
    // version requirement is this document's *only* resolved-version-move signal for
    // Gradle/Deno (no `LockFileProvider`, so `document::diff::reload_resolved_versions`'s
    // lock-file-driven eviction never runs for them) and can also race a Dart/Swift
    // lock-file-driven eviction for the same dependency. Same tier-3-only gate and rationale
    // as `document::diff::reload_resolved_versions`'s own license eviction — raw-name-keyed,
    // like `DocumentState::licenses` itself.
    if ecosystem.license_source().requires_dedicated_fetch() {
        for changed_dep in &diff.version_changed {
            doc_state.licenses.remove(changed_dep);
        }
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
    mut refetch: RefetchPolicy,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<Option<JoinHandle<()>>> {
    // `from_lsp_uri` returning `None` (a URI shape `url::Url` rejects) is treated the
    // same as "no ecosystem handles this URI".
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
        tracing::debug!("URI is not representable as a url::Url: {:?}", uri);
        return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
            "{uri:?}"
        )));
    };
    let ecosystem = match state.ecosystem_registry.for_uri(&domain_uri) {
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

    let (parse_result, diff, selection_context_changed) =
        parse_and_diff_manifest(&uri, &content, &state, &ecosystem).await;

    // #1433: a `minimum-stability`-only edit changes no dependency name/version, so `diff`
    // alone would see nothing to fetch — escalate so every dependency's "latest" pick is
    // refetched under the new context, matching what hover/completion/code-actions already
    // compute live against the freshly committed parse result (see `parse_and_diff_manifest`'s
    // doc).
    if selection_context_changed {
        refetch = RefetchPolicy::AllDependencies;
    }

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

    // Read before any OSV request is built (FR-011).
    let (diagnostics_snapshot, vulnerabilities_enabled) = {
        let cfg = config.read().await;
        (
            diagnostics::DiagnosticsSnapshot::from_config(&cfg),
            cfg.policy.diagnostics.vulnerabilities_enabled,
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
                diagnostics: diagnostics_snapshot,
                vulnerabilities_enabled,
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
/// config lock itself. Bundled into one struct rather than four parameters since every field
/// is captured together by the same snapshot in [`handle_document_change`].
///
/// `diagnostics` (issue #1399 critic M6) doubles as this task's fetch-timeout/concurrency
/// source, not just its diagnostics-ceiling one: `CacheConfig`'s only other field,
/// `enabled`, isn't read anywhere in [`run_document_change_task`], so keeping a separate
/// `CacheConfig` snapshot here would only duplicate `diagnostics.fetch_timeout_secs`/
/// `max_concurrent_fetches` under a second name.
struct ChangeTaskConfig {
    diagnostics: diagnostics::DiagnosticsSnapshot,
    vulnerabilities_enabled: bool,
    refetch: RefetchPolicy,
}

/// Debounce window before [`run_document_change_task`] starts its fetch work. This is a
/// *debounce*, not a plain delay: a newer `did_change` for the same URI aborts the prior
/// task (see [`crate::document::ServerState::spawn_background_task`]) while it is still
/// parked in this sleep, so a keystroke burst costs one fetch round instead of one per edit.
pub(crate) const DID_CHANGE_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether this debounced edit observed a resolved-version move, from either signal
/// (`clippy::struct_excessive_bools` splits [`change_task_triggers`]'s bools into this
/// plus [`ChangeTaskTriggerGates`]).
///
/// `pub(crate)`: shared with `server::handle_lockfile_change`, which computes the same
/// triggers for its own lock-file-only path (issue #1407 code-review should-fix — the
/// two call sites were duplicating this formula by hand, with no shared test coverage
/// for the duplicate).
pub(crate) struct ResolvedVersionMove {
    /// The manifest-diff-derived flag (this function's own `needs_osv_rescan`
    /// parameter) — fires from the manifest text alone, independent of whether a
    /// lock file was resolved at all. `server::handle_lockfile_change` has no manifest
    /// diff of its own, so it always passes `false` here.
    pub(crate) diff_needs_rescan: bool,
    /// Whether the lock-file reload changed a resolved version, only ever computed
    /// when one was actually resolved (see the caller).
    pub(crate) resolved_changed: bool,
}

/// The independent config/ecosystem gates [`change_task_triggers`] applies on top of a
/// [`ResolvedVersionMove`] (split out from it too, for the same
/// `clippy::struct_excessive_bools` reason). `pub(crate)`: see [`ResolvedVersionMove`]'s
/// doc.
///
/// Deliberately does *not* carry a license-policy-non-empty gate (issue #1407
/// code-review should-fix): that precondition now lives as a second early-return inside
/// [`super::osv_scan::run_license_prefetch`] itself, rather than being duplicated at
/// every call site that used to check it before deciding whether to trigger a refresh.
pub(crate) struct ChangeTaskTriggerGates {
    pub(crate) vulnerabilities_enabled: bool,
    pub(crate) requires_dedicated_fetch: bool,
}

/// Computes [`run_document_change_task`]'s OSV-rescan and license-refresh triggers
/// (and, by extension, whether `resolved_versions_generation` should bump) from the
/// raw manifest-diff flag and whether the lock-file reload itself changed anything —
/// pulled out as a pure function (issue #1407 R1) so every combination of inputs is
/// covered by a truth-table unit test instead of only whichever paths a live edit
/// happens to exercise. Shared with `server::handle_lockfile_change` (issue #1407
/// code-review should-fix), which is algebraically this function with
/// `diff_needs_rescan` fixed to `false` (it has no manifest diff of its own).
///
/// `diff_needs_rescan` and `resolved_changed` are deliberately independent: either one
/// alone must be able to trigger a rescan/refresh, since `resolved_changed` is only
/// ever computed when a lock file resolved something, while `diff_needs_rescan` is the
/// *only* signal available for the ecosystems that have no lock file to reload at all.
///
/// Returns `(needs_osv_rescan, needs_license_refresh)`.
pub(crate) fn change_task_triggers(
    mv: ResolvedVersionMove,
    gates: ChangeTaskTriggerGates,
) -> (bool, bool) {
    let any_resolved_move = mv.diff_needs_rescan || mv.resolved_changed;
    let needs_osv_rescan = gates.vulnerabilities_enabled && any_resolved_move;
    let needs_license_refresh = any_resolved_move && gates.requires_dedicated_fetch;
    (needs_osv_rescan, needs_license_refresh)
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
    tokio::time::sleep(DID_CHANGE_DEBOUNCE).await;

    // `handle_document_change_guarded` already validated this exact `uri` converts
    // successfully before spawning this task, so `None` here is unreachable in
    // practice — handled defensively rather than unwrapped.
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
        tracing::warn!(
            "URI is not representable as a url::Url, aborting fetch: {:?}",
            uri
        );
        return;
    };

    // Lock file read is instant and network-free, so it runs before the registry fetch below.
    // `lockfile_reload_ok` (issue #1407 E1) distinguishes a lock file that genuinely
    // resolved to nothing (or doesn't apply to this ecosystem) from one that was found
    // but failed to parse — e.g. caught mid-rewrite by the package manager while this
    // edit's own change event was in flight. See its use below.
    let load = load_resolved_versions(&domain_uri, &state.lockfile_cache, ecosystem.as_ref()).await;
    let lockfile_reload_ok = load.reload_ok();
    let (resolved_versions, resolved_version_candidates) = load.into_maps();

    // Must not touch cached_versions here — it holds the latest registry versions.
    //
    // Issue #1399/#1407 S1: a lock-file rewrite observed here (e.g. a `cargo build`
    // racing this debounced edit) must trigger an OSV rescan/license refresh even when
    // the edit itself touches no dependency (`diff_needs_rescan == false`) — mirrors
    // `server::handle_lockfile_change`'s own drift check for the lock-file-watcher path.
    // `reload_resolved_versions` (issue #1398/#1399 code review) shares the diff-and-write
    // sequence with that other call site.
    //
    // Gated on `lockfile_reload_ok` alone (issue #1407 R1/E1), not
    // `!resolved_versions.is_empty()`: `load_resolved_versions` only ever returns `false`
    // alongside empty maps (a parse failure — e.g. a lock file caught mid-rewrite by the
    // package manager racing this same debounced edit), so `lockfile_reload_ok` is `true`
    // whenever the reload was a genuine success — including to zero packages, which
    // covers Gradle/Deno's permanent no-`LockFileProvider` state and Dart/Swift before
    // their first resolve (R1: a manifest edit on those ecosystems must still reach
    // `change_task_triggers` below via `diff_needs_rescan`, not be skipped because there
    // was never any lock data to diff) — or `resolved_versions` is non-empty (which
    // itself implies success). Gating on `lockfile_reload_ok` alone therefore both fires
    // the diff/write on a genuine populated-to-empty transition (a lock file deleted,
    // `cargo clean`, a VCS checkout mid-edit — `reload_resolved_versions`'s internal
    // comparison already falls back to each dependency's manifest-declared pin and
    // detects this correctly) and skips it entirely on an actual parse failure, so a
    // transient error never wipes known-good `doc.resolved_versions` or bumps the
    // generation off untrustworthy data (E1 — the exact #1395 M1 failure mode the
    // watcher path's own `lockfile_reload_ok` already guards against).
    let diff_needs_rescan = needs_osv_rescan;
    let resolved_changed = if lockfile_reload_ok {
        reload_resolved_versions(
            &uri,
            &state,
            ecosystem.as_ref(),
            &resolved_versions,
            &resolved_version_candidates,
        )
    } else {
        false
    };

    let (needs_osv_rescan, needs_license_refresh) = change_task_triggers(
        ResolvedVersionMove {
            diff_needs_rescan,
            resolved_changed,
        },
        ChangeTaskTriggerGates {
            vulnerabilities_enabled: config.vulnerabilities_enabled,
            requires_dedicated_fetch: ecosystem.license_source().requires_dedicated_fetch(),
        },
    );

    // Bump only when a rescan/refresh below is actually about to spawn (issue #1395
    // critic bidirectional-race finding, N2 invariant): this function runs on *every*
    // debounced edit, including ones that touch no dependency at all and have no
    // lock-file drift either — an unconditional bump here would silently invalidate any
    // *other* in-flight OSV scan or license pre-fetch for this same document (e.g. a
    // concurrent lock-file-triggered rescan, `server::handle_lockfile_change`) via their
    // shared staleness guards, with no rescan of this call's own to pair with it and
    // produce a fresh replacement. Also covers the reparse path (`reparse.rs`), which
    // reuses this same function: a reparse's `DependencyDiff` is always empty (the
    // manifest text itself is untouched), so it now correctly never bumps unless the
    // lock file itself drifted.
    if (needs_osv_rescan || needs_license_refresh)
        && let Some(mut doc) = state.documents.get_mut(&uri)
    {
        doc.bump_resolved_generation(state.next_resolved_versions_generation());
    }

    // Phase A OSV scan (only when a dependency was added or an existing one's version
    // changed, or the lock file moved a resolved version underneath this edit — critique
    // S1, issue #1399), spawned so it runs concurrently with the registry fetch below.
    let osv_task = needs_osv_rescan.then(|| {
        tokio::spawn(
            run_osv_scan_phase_a(
                uri.clone(),
                Arc::clone(&state),
                Arc::clone(&ecosystem),
                config.diagnostics.fetch_timeout_secs,
            )
            .instrument(tracing::Span::current()),
        )
    });

    // Tier-3 license pre-fetch (issue #660/#1407), gated on `needs_license_refresh` —
    // fires from either a manifest-diff-level dependency add/version-change or a
    // lock-only drift (`change_task_triggers`'s `any_resolved_move`), same trigger shape
    // as `osv_task` above but independently gated on ecosystem/policy instead of
    // `vulnerabilities_enabled`. Joined (round 3 finding #3) via `await_license_prefetch`
    // below, same shape as `osv_task`, so its commit lands before either of this
    // function's diagnostics publishes below, not after.
    let license_task = needs_license_refresh.then(|| {
        tokio::spawn(
            run_license_prefetch(
                uri.clone(),
                Arc::clone(&state),
                Arc::clone(&ecosystem),
                config.diagnostics.fetch_timeout_secs,
            )
            .instrument(tracing::Span::current()),
        )
    });

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
            config.diagnostics.fetch_timeout_secs,
        )
        .await;
        await_license_prefetch(license_task).await;

        diagnostics::publish_document_diagnostics(&state, &client, &uri, &config.diagnostics, 0)
            .await;
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
            config.diagnostics.freshness,
            config.diagnostics.fetch_timeout_secs,
            config.diagnostics.max_concurrent_fetches,
            config.refetch,
        )
        .await;

    let success = !fetch_result.versions.is_empty();

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
        config.diagnostics.fetch_timeout_secs,
    )
    .await;
    await_license_prefetch(license_task).await;

    diagnostics::publish_document_diagnostics(
        &state,
        &client,
        &uri,
        &config.diagnostics,
        dep_count,
    )
    .await;
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
    if state.get_document(uri).is_some() {
        tracing::debug!("Document already loaded: {:?}", uri);
        return true;
    }

    // Clone cold start config before async operations to release lock
    let cold_start_config = { config.read().await.cold_start.clone() };

    if !cold_start_config.enabled {
        tracing::debug!("Cold start disabled via configuration");
        return false;
    }

    if !state.cold_start_limiter.allow_cold_start(uri) {
        tracing::warn!("Cold start rate limited: {:?}", uri);
        return false;
    }

    // `from_lsp_uri` returning `None` (a URI shape `url::Url` rejects) is treated the
    // same as "no ecosystem handles this URI".
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(uri) else {
        tracing::debug!("URI is not representable as a url::Url: {:?}", uri);
        return false;
    };
    if state.ecosystem_registry.for_uri(&domain_uri).is_none() {
        tracing::debug!("Unsupported file type: {:?}", uri);
        return false;
    }

    tracing::info!("Loading document from disk (cold start): {:?}", uri);
    let content = match load_document_from_disk(&domain_uri).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to load document {:?}: {}", uri, e);
            client
                .log_message(MessageType::WARNING, format!("Could not load file: {e}"))
                .await;
            return false;
        }
    };

    // `version: None` — content came from disk, not an LSP didOpen, so there is no
    // client-tracked version to record (see `DocumentState::version` and the
    // cold-start refusal in `handlers::code_lens`).
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
    use super::*;
    use deps_core::EcosystemId;
    #[cfg(feature = "cargo")]
    use deps_core::Registry;
    use deps_core::RemovalStatus;
    #[cfg(feature = "cargo")]
    use deps_engine::classify::fetch::FetchResult;
    // Only the cargo-gated tests below sleep or time out on a bare `Duration`
    // (go_tests imports its own `tokio::time::Duration` locally instead).
    #[cfg(feature = "cargo")]
    use std::collections::HashSet;
    #[cfg(feature = "cargo")]
    use std::time::Duration;

    /// Issue #1407 R1: exhaustive truth table over `change_task_triggers`'s four
    /// boolean inputs, so a future edit can't silently reintroduce the regression
    /// this fix closed (a trigger nested inside the "lock file resolved something"
    /// guard, which is always false for Gradle/Deno and for Dart/Swift before their
    /// first resolve). No feature gate needed — pure function, no ecosystem I/O.
    ///
    /// No `license_policy_non_empty` input any more (code-review should-fix): that
    /// precondition moved inside `run_license_prefetch` itself, so it is no longer
    /// part of this function's own formula.
    #[test]
    fn change_task_triggers_truth_table() {
        for diff_needs_rescan in [false, true] {
            for resolved_changed in [false, true] {
                for vulnerabilities_enabled in [false, true] {
                    for requires_dedicated_fetch in [false, true] {
                        let (osv, license) = change_task_triggers(
                            ResolvedVersionMove {
                                diff_needs_rescan,
                                resolved_changed,
                            },
                            ChangeTaskTriggerGates {
                                vulnerabilities_enabled,
                                requires_dedicated_fetch,
                            },
                        );
                        let any_resolved_move = diff_needs_rescan || resolved_changed;
                        assert_eq!(
                            osv,
                            vulnerabilities_enabled && any_resolved_move,
                            "osv mismatch for diff={diff_needs_rescan} resolved={resolved_changed} \
                             vulns={vulnerabilities_enabled} tier3={requires_dedicated_fetch}"
                        );
                        assert_eq!(
                            license,
                            any_resolved_move && requires_dedicated_fetch,
                            "license mismatch for diff={diff_needs_rescan} resolved={resolved_changed} \
                             vulns={vulnerabilities_enabled} tier3={requires_dedicated_fetch}"
                        );
                    }
                }
            }
        }
    }

    /// impl-critic S1 (#1433): a `minimum-stability`-only edit changes no dependency
    /// name/version, so `DependencyDiff` alone reports nothing to fetch — proves
    /// `parse_and_diff_manifest`'s own `selection_context_changed` signal catches this case
    /// regardless, which `handle_document_change_guarded` escalates to
    /// `RefetchPolicy::AllDependencies` on (see that function's own comment at the call site).
    #[cfg(feature = "composer")]
    #[tokio::test]
    async fn test_parse_and_diff_manifest_detects_minimum_stability_only_change() {
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/composer.json");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Composer)
            .expect("composer ecosystem registered under the composer feature");

        let content1 = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
        let doc_state1 = DocumentState::new_from_parse_result(
            EcosystemId::Composer,
            content1.to_string(),
            parse_result1,
        );
        state.update_document(uri.clone(), doc_state1);

        // Same single dependency, same requirement — only `minimum-stability` is new.
        let content2 = r#"{"minimum-stability": "alpha", "require": {"symfony/console": "^6.0"}}"#;
        let (_, diff, selection_context_changed) =
            parse_and_diff_manifest(&uri, content2, &state, &ecosystem).await;

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.version_changed.is_empty());
        assert!(
            selection_context_changed,
            "a minimum-stability-only edit must be detected as a selection-context change \
             even though the dependency diff itself is empty"
        );
    }

    /// impl-critic S1 (#1433) mirror case: an edit that touches neither `minimum-stability`
    /// nor any dependency must not spuriously report a selection-context change (which would
    /// force an unnecessary `RefetchPolicy::AllDependencies` on every keystroke).
    #[cfg(feature = "composer")]
    #[tokio::test]
    async fn test_parse_and_diff_manifest_no_selection_context_change_for_unrelated_edit() {
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/composer.json");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Composer)
            .expect("composer ecosystem registered under the composer feature");

        let content1 = r#"{"name": "acme/app", "require": {"symfony/console": "^6.0"}}"#;
        let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
        let doc_state1 = DocumentState::new_from_parse_result(
            EcosystemId::Composer,
            content1.to_string(),
            parse_result1,
        );
        state.update_document(uri.clone(), doc_state1);

        // `name` changes, `minimum-stability` stays absent, the dependency is untouched.
        let content2 = r#"{"name": "acme/renamed", "require": {"symfony/console": "^6.0"}}"#;
        let (_, diff, selection_context_changed) =
            parse_and_diff_manifest(&uri, content2, &state, &ecosystem).await;

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.version_changed.is_empty());
        assert!(
            !selection_context_changed,
            "an edit unrelated to minimum-stability must not report a selection-context change"
        );
    }

    /// Issue #1407 R1 regression case (a)/(c): a pure manifest edit
    /// (`diff_needs_rescan == true`) with no lock file resolved at all (Gradle/Deno's
    /// permanent state, or Dart/Swift before their first resolve) must still trigger
    /// the license refresh — before this fix, the trigger was computed only inside
    /// the `!resolved_versions.is_empty()` guard, so it silently stayed `false`
    /// forever for these ecosystems.
    #[test]
    fn change_task_triggers_manifest_edit_alone_triggers_license_with_no_lock_file() {
        let (osv, license) = change_task_triggers(
            ResolvedVersionMove {
                diff_needs_rescan: true, // manifest edit added/changed a dependency
                resolved_changed: false, // no lock file was resolved at all
            },
            ChangeTaskTriggerGates {
                vulnerabilities_enabled: false, // off (R1 case (c))
                requires_dedicated_fetch: true, // a tier-3 ecosystem
            },
        );
        assert!(
            !osv,
            "vulnerabilities disabled must suppress the OSV rescan"
        );
        assert!(
            license,
            "a manifest-only edit must still trigger the license refresh even with no \
             lock file resolved and vulnerabilities disabled"
        );
    }

    /// Issue #1407 R1, critic M1: call-site regression guard, exercised through the real
    /// `handle_document_open`/`handle_document_change` pipeline rather than
    /// `change_task_triggers` in isolation — protects the *placement* of the trigger
    /// computation inside `run_document_change_task`, not just its formula. Gradle has
    /// no `LockFileProvider` (`load_resolved_versions` always returns empty maps for
    /// it), so before this fix the trigger — nested inside the
    /// `!resolved_versions.is_empty()` guard — could never fire for a Gradle manifest
    /// edit; a future refactor that reintroduced that nesting would keep
    /// `change_task_triggers`'s own unit tests green while silently regressing this.
    ///
    /// Network-free: the added dependency uses Gradle's `4.+` dynamic-version syntax,
    /// which `resolve_in_use_version`'s `concrete_pin_version` fallback rejects (it
    /// contains `+`, see `deps_core::lsp_helpers::in_use_version::looks_like_a_single_version`),
    /// so `tier3_license_targets` produces zero targets and `run_license_prefetch`
    /// returns before any network call — this test only needs the generation bump that
    /// precedes that call, not the fetch itself.
    #[cfg(feature = "gradle")]
    #[tokio::test]
    async fn test_gradle_manifest_edit_bumps_generation_with_vulnerabilities_disabled() {
        // See the comment in `test_document_parsing` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use crate::test_utils::test_helpers::create_test_client_and_config;
        use std::time::Duration;

        let state = Arc::new(ServerState::new());
        state.set_license_policy(deps_core::LicensePolicy::new(
            vec!["MIT".to_string()],
            vec![],
        ));

        let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let original_content = "dependencies {\n}\n".to_string();

        let (client, config) = create_test_client_and_config();
        config
            .write()
            .await
            .policy
            .diagnostics
            .vulnerabilities_enabled = false;
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

        let generation_before = state
            .get_document(&uri)
            .unwrap()
            .resolved_versions_generation;

        let edited_content =
            "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:4.+\")\n}\n"
                .to_string();
        let (client, config) = create_test_client_and_config();
        config
            .write()
            .await
            .policy
            .diagnostics
            .vulnerabilities_enabled = false;
        let task = handle_document_change(
            uri.clone(),
            edited_content,
            Some(2),
            state.clone(),
            client,
            config,
        )
        .await
        .expect("manifest edit adding a dependency should be accepted");

        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect(
                "background task must complete promptly (network-free: the dynamic \
                 version resolves no license target)",
            )
            .expect("background task must not panic");

        let generation_after = state
            .get_document(&uri)
            .unwrap()
            .resolved_versions_generation;
        assert_ne!(
            generation_before, generation_after,
            "a manifest edit adding a dependency to a lockless Gradle document, with \
             vulnerabilities disabled, must still bump resolved_versions_generation for \
             its license refresh (issue #1407 R1) — even though the OSV rescan itself \
             stays off and Gradle has no lock file to resolve from"
        );
    }

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
        let url = deps_core::test_util::test_uri("/test/over-ceiling/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let cap = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut content = String::from("[dependencies]\n");
        for i in 0..=cap {
            content.push_str(&format!("dep-{i} = \"1.0.0\"\n"));
        }

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Cargo)
            .unwrap();
        let parse_result = deps_core::parse_manifest_blocking(&ecosystem, &content, &url)
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
        let url = deps_core::test_util::test_uri("/test/at-ceiling/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let cap = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut content = String::from("[dependencies]\n");
        for i in 0..cap {
            content.push_str(&format!("dep-{i} = \"1.0.0\"\n"));
        }

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Cargo)
            .unwrap();
        let parse_result = deps_core::parse_manifest_blocking(&ecosystem, &content, &url)
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

        /// A no-op formatter with identity name normalization and a bare (unprefixed)
        /// package URL — no ecosystem-specific behavior is under test here, just
        /// `drop_cache_for_forced_refetch`'s own bookkeeping.
        const IDENTITY_FORMATTER: deps_core::test_util::StubFormatter =
            deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

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
            doc.set_resolved_versions_without_bump(
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
                &IDENTITY_FORMATTER,
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

            drop_cache_for_forced_refetch(&mut doc, &[], &IDENTITY_FORMATTER);

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
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
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
            let fetch_result = FetchResult::new(
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(PackageName::new("serde"), FetchFailure::Transient)]),
                HashSet::new(),
                1,
                Some("network down".to_string()),
                HashMap::new(),
            );

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
            let url = deps_core::test_util::test_uri("/test/no-lockfile/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
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
    ///
    /// The whole module is gated on `feature = "cargo"`: its sole test overrides the real
    /// "cargo" ecosystem registration with a fake slow one, so it needs that registration to
    /// exist to override in the first place.
    #[cfg(feature = "cargo")]
    mod open_path_semaphore_e2e_tests {
        use super::*;
        use deps_core::ecosystem::BoxFuture;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticSeverities, EcosystemConfig, EcosystemFormatter,
            FreshnessSettings, Metadata, Version, VersionData, completion::Completions,
        };
        use std::any::Any;
        use std::path::Path;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tokio::sync::Barrier;
        use tower_lsp_server::ls_types::{CodeLens, InlayHint, Position};

        struct FakeDependency {
            name: PackageName,
            version_requirement: VersionReq,
        }
        impl Dependency for FakeDependency {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> deps_core::position::Range {
                deps_core::position::Range::new(
                    deps_core::position::Position::new(0, 0),
                    deps_core::position::Position::new(0, 1),
                )
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                Some(&self.version_requirement)
            }
            fn version_range(&self) -> Option<deps_core::position::Range> {
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
            uri: url::Url,
            dep: FakeDependency,
        }
        impl deps_core::ParseResult for FakeParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![&self.dep]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>> {
                Box::pin(async move {
                    let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
                    self.max_seen.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(self.delay).await;
                    self.current.fetch_sub(1, Ordering::SeqCst);
                    Ok(None)
                })
            }
            fn search_raw<'a>(
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
                uri: &'a url::Url,
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
                &deps_core::test_util::StubFormatter::DEFAULT
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
                _uri: &'a url::Url,
                _freshness: FreshnessSettings,
                _severities: DiagnosticSeverities,
            ) -> BoxFuture<'a, Vec<deps_core::diagnostic::Diagnostic>> {
                Box::pin(async move { vec![] })
            }
            fn generate_code_lenses<'a>(
                &'a self,
                _parse_result: &'a dyn deps_core::ParseResult,
                _content: &'a str,
                _versions: VersionData<'a>,
                _uri: &'a url::Url,
                _command_id: &'a str,
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
                .map(|i| {
                    crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(&format!(
                        "/test/pkg{i}/Cargo.toml"
                    )))
                })
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
        assert!(state.ecosystem_registry.for_uri(&unknown_uri).is_none());
    }

    #[test]
    fn test_check_content_size_accepts_content_within_limit() {
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let content = "a".repeat(MAX_FILE_SIZE as usize);
        assert!(check_content_size(&content, &uri).is_ok());
    }

    #[test]
    fn test_check_content_size_rejects_content_over_limit() {
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_licenses_pruned_on_dependency_removal() {
        // See the comment in `test_forced_refetch_total_failure_renders_lookup_failed_not_unknown_package` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let content1 = r#"[dependencies]
serde = "1.0"
anyhow = "1.0"
"#;
        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Cargo)
            .unwrap();
        let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
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

        let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
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
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/README.md");

        assert!(
            state.ecosystem_registry.for_uri(&url).is_none(),
            "README.md should not have an ecosystem handler"
        );

        // ensure_document_loaded itself needs a Client, so this only exercises the
        // underlying condition it would check.
    }

    #[tokio::test]
    async fn test_ensure_document_loaded_file_not_found_check() {
        use super::load_document_from_disk;

        // Held per `fs_probe::snapshot_guard`'s doc: any fs_probe-touching test in this
        // binary must hold it, not just document/loader.rs's own diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let url = deps_core::test_util::test_uri("/nonexistent/Cargo.toml");
        let result = load_document_from_disk(&url).await;

        assert!(result.is_err(), "Should fail for missing files");
    }

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let cargo_uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            assert!(state.ecosystem_registry.for_uri(&cargo_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `ecosystem.parse_manifest`
            // (cargo) transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &url).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            assert_eq!(state.document_count(), 1);
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem, EcosystemId::Cargo);
        }

        #[tokio::test]
        async fn test_document_stored_even_when_parsing_fails() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"[dependencies
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &url).await.ok();
            assert!(
                parse_result.is_none(),
                "Parsing should fail for invalid TOML"
            );

            let doc_state = if let Some(pr) = parse_result {
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content.to_string(), pr)
            } else {
                DocumentState::new_without_parse_result(EcosystemId::Cargo, content.to_string())
            };

            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri);
            assert!(
                doc.is_some(),
                "Document should be stored even when parsing fails"
            );

            let doc = doc.unwrap();
            assert_eq!(doc.ecosystem, EcosystemId::Cargo);
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
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"[dependencies]
serde = "1.0""#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            assert!(
                state.get_document(&uri).is_some(),
                "Document should exist in state"
            );
            assert_eq!(state.document_count(), 1, "Document count should be 1");

            // ensure_document_loaded's fast path would return true here; tested directly
            // since a test Client needs complex tower-lsp-server internals.
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_successful_disk_load() {
            use super::super::load_document_from_disk;
            use std::fs;
            use tempfile::TempDir;

            // Held per `fs_probe::snapshot_guard`'s doc: any fs_probe-touching test in this
            // binary must hold it, not just document/loader.rs's own diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;

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
            let url = crate::lsp_types_interop::from_lsp_uri(&uri).unwrap();

            let loaded_content = load_document_from_disk(&url).await.unwrap();
            assert_eq!(loaded_content, content);

            let state = Arc::new(ServerState::new());
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(&loaded_content, &url).await;
            assert!(parse_result.is_ok(), "Should parse successfully");

            // These are the same building blocks ensure_document_loaded's disk path uses.
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_idempotent_check() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"[dependencies]
serde = "1.0""#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem");

            let parse_result1 = ecosystem.parse_manifest(content, &url).await.unwrap();
            let parse_result2 = ecosystem.parse_manifest(content, &url).await.unwrap();

            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);
            assert_eq!(state.document_count(), 1);

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
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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

        /// Regression guard for issue #1395's bidirectional-generation-race finding
        /// (surfaced by code-review after N1/N2): a debounced edit that changes no
        /// dependency (`needs_osv_rescan == false`) must not bump
        /// `resolved_versions_generation`, even though the lock-file reload it also does
        /// is non-empty — an unconditional bump here would silently invalidate a
        /// concurrently in-flight OSV scan for this same document from an unrelated
        /// source (e.g. `server::handle_lockfile_change`'s own rescan) with nothing of
        /// this edit's own to produce a fresh replacement commit.
        #[tokio::test]
        async fn test_dependency_unrelated_edit_does_not_bump_resolved_generation() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            std::fs::write(
                temp_dir.path().join("Cargo.lock"),
                "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"alpha-dep\"\nversion = \"0.1.0\"\n\
                 source = \"git+https://github.com/example/alpha-dep\
                 #abcdef1234567890abcdef1234567890abcdef12\"\n",
            )
            .unwrap();
            let manifest_dir = temp_dir.path().join("crate");
            std::fs::create_dir(&manifest_dir).unwrap();
            let manifest_path = manifest_dir.join("Cargo.toml");
            let original_content =
                "[dependencies]\nalpha-dep = { git = \"https://github.com/example/alpha-dep\" }\n"
                    .to_string();
            std::fs::write(&manifest_path, &original_content).unwrap();
            let uri = Uri::from_file_path(&manifest_path).unwrap();

            let state = Arc::new(ServerState::new());
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
            .expect("initial open should succeed")
            .await
            .expect("initial open's background task must not panic");

            let generation_before = state
                .get_document(&uri)
                .unwrap()
                .resolved_versions_generation;
            assert!(
                !generation_before.is_initial(),
                "the open path is expected to have resolved (and bumped once) from the real \
                 lock file on disk"
            );

            // Comment-only edit — touches no dependency, so `needs_osv_rescan` is false.
            let edited_content = format!("{original_content}# a comment\n");
            let (client, config) = create_test_client_and_config();
            let task = handle_document_change(
                uri.clone(),
                edited_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("comment-only edit should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("background task must complete promptly")
                .expect("background task must not panic");

            let generation_after = state
                .get_document(&uri)
                .unwrap()
                .resolved_versions_generation;
            assert_eq!(
                generation_after, generation_before,
                "a debounced edit that changes no dependency must not bump \
                 resolved_versions_generation, even though the lock-file reload it also \
                 performs is non-empty"
            );
        }

        /// Regression guard for issue #1399 (`run_document_change_task`'s `lifecycle.rs:909`
        /// TODO): the inverse of the test above — a debounced edit that changes no
        /// dependency itself (`needs_osv_rescan == false`) must still bump
        /// `resolved_versions_generation` and trigger an OSV rescan when the lock file
        /// moved a resolved version underneath it in the meantime, mirroring
        /// `server::handle_lockfile_change`'s own `resolved_versions_changed` check.
        #[tokio::test]
        async fn test_lock_file_change_under_unrelated_edit_bumps_resolved_generation() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let lock_path = temp_dir.path().join("Cargo.lock");
            std::fs::write(
                &lock_path,
                "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"alpha-dep\"\nversion = \"0.1.0\"\n\
                 source = \"git+https://github.com/example/alpha-dep\
                 #abcdef1234567890abcdef1234567890abcdef12\"\n",
            )
            .unwrap();
            let manifest_dir = temp_dir.path().join("crate");
            std::fs::create_dir(&manifest_dir).unwrap();
            let manifest_path = manifest_dir.join("Cargo.toml");
            let original_content =
                "[dependencies]\nalpha-dep = { git = \"https://github.com/example/alpha-dep\" }\n"
                    .to_string();
            std::fs::write(&manifest_path, &original_content).unwrap();
            let uri = Uri::from_file_path(&manifest_path).unwrap();

            let state = Arc::new(ServerState::new());
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
            .expect("initial open should succeed")
            .await
            .expect("initial open's background task must not panic");

            let generation_before = state
                .get_document(&uri)
                .unwrap()
                .resolved_versions_generation;
            assert!(
                !generation_before.is_initial(),
                "the open path is expected to have resolved (and bumped once) from the real \
                 lock file on disk"
            );
            assert_eq!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .resolved_versions
                    .get(&PackageName::new("alpha-dep")),
                Some(&ConcreteVersion::new("0.1.0")),
                "sanity check: the open path must have resolved the original locked version"
            );

            // Rewrite the lock file to a different resolved version for the same
            // git-sourced dependency — critic M3: the lockfile cache is mtime-validated
            // with a `<=` comparison (`deps_core::lockfile::LockFileCache::get_or_parse`),
            // so the mtime must be forced strictly forward, or this rewrite can land as an
            // undetected cache hit on a coarse-mtime filesystem and make this test flaky.
            std::fs::write(
                &lock_path,
                "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"alpha-dep\"\nversion = \"0.2.0\"\n\
                 source = \"git+https://github.com/example/alpha-dep\
                 #abcdef1234567890abcdef1234567890abcdef12\"\n",
            )
            .unwrap();
            // `write(true)`, not a read-only `File::open`: on Windows, `set_modified` calls
            // `SetFileTime`, which needs `FILE_WRITE_ATTRIBUTES` access — a plain
            // `GENERIC_READ` handle is denied that with `ERROR_ACCESS_DENIED` (Unix's
            // `futimens` has no such requirement, so this only surfaces on Windows CI).
            let lock_file = std::fs::OpenOptions::new()
                .write(true)
                .open(&lock_path)
                .unwrap();
            let new_mtime =
                lock_file.metadata().unwrap().modified().unwrap() + Duration::from_secs(2);
            lock_file.set_modified(new_mtime).unwrap();
            drop(lock_file);

            // Comment-only edit — touches no dependency, so `needs_osv_rescan` (the
            // diff-level flag `run_document_change_task` receives) is false; any rescan
            // must instead come from the lock-file drift the fixed code now also detects.
            let edited_content = format!("{original_content}# a comment\n");
            let (client, config) = create_test_client_and_config();
            let task = handle_document_change(
                uri.clone(),
                edited_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("comment-only edit should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("background task must complete promptly")
                .expect("background task must not panic");

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.resolved_versions.get(&PackageName::new("alpha-dep")),
                Some(&ConcreteVersion::new("0.2.0")),
                "the lock-file rewrite must have been picked up by the debounced edit's own \
                 reload — otherwise the generation assertion below would be vacuous"
            );
            assert_ne!(
                doc.resolved_versions_generation, generation_before,
                "a debounced edit that changes no dependency itself must still bump \
                 resolved_versions_generation when the lock file moved a resolved version \
                 underneath it (issue #1399)"
            );
        }

        /// Issue #1407 code-review must-fix: the opposite transition from the test
        /// above — a lock file that goes from resolved to empty (deleted, `cargo
        /// clean`, a VCS checkout mid-edit, a build tool regenerating it) must still be
        /// detected as a resolved-version move, even for a comment-only edit that adds
        /// or changes no dependency in the manifest text itself
        /// (`diff_needs_rescan == false`). Before this fix, the trigger computation
        /// (and the map overwrite it sits alongside) were skipped whenever the
        /// *reloaded* map was empty, so `doc.resolved_versions` stayed stuck on the
        /// stale, now-invalid data forever and `resolved_versions_generation` never
        /// bumped.
        #[tokio::test]
        async fn test_lockfile_becoming_empty_bumps_resolved_generation() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let lockfile_path = temp_dir.path().join("Cargo.lock");
            std::fs::write(
                &lockfile_path,
                "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"alpha-dep\"\nversion = \"0.1.0\"\n\
                 source = \"git+https://github.com/example/alpha-dep\
                 #abcdef1234567890abcdef1234567890abcdef12\"\n",
            )
            .unwrap();
            let manifest_dir = temp_dir.path().join("crate");
            std::fs::create_dir(&manifest_dir).unwrap();
            let manifest_path = manifest_dir.join("Cargo.toml");
            let original_content =
                "[dependencies]\nalpha-dep = { git = \"https://github.com/example/alpha-dep\" }\n"
                    .to_string();
            std::fs::write(&manifest_path, &original_content).unwrap();
            let uri = Uri::from_file_path(&manifest_path).unwrap();

            let state = Arc::new(ServerState::new());
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
            .expect("initial open should succeed")
            .await
            .expect("initial open's background task must not panic");

            // `with_document` (not `get_document`) so the `DashMap` shard-lock guard is
            // released immediately, before the `.await`s below (`clippy::await_holding_invalid_type`).
            let (generation_before, resolved_non_empty_after_open) = state
                .with_document(&uri, |doc| {
                    (
                        doc.resolved_versions_generation,
                        !doc.resolved_versions.is_empty(),
                    )
                })
                .unwrap();
            assert!(
                resolved_non_empty_after_open,
                "the open path is expected to have resolved from the real lock file on disk"
            );

            // The lock file loses its only entry — same shape of change a `cargo clean`
            // or a VCS checkout mid-edit produces.
            std::fs::write(
                &lockfile_path,
                "# This file is automatically @generated by Cargo.\nversion = 3\n",
            )
            .unwrap();
            // Ensure a distinguishable mtime on filesystems with coarse timestamp
            // resolution (issue #1407 M3, matches `server.rs`'s
            // `test_watched_config_change_reparses_open_document_with_catalog_dependency`
            // and `mtime_cache::tests::forward_mtime_bump_invalidates`) — without this,
            // the lock-file cache can serve the stale, pre-rewrite entry on a coarse
            // filesystem, making this test flake instead of reliably re-reading.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&lockfile_path)
                .unwrap()
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(2))
                .unwrap();

            // Comment-only edit — touches no dependency, so `diff_needs_rescan` is
            // false; only the lock-file-emptying transition itself can trigger a bump.
            let edited_content = format!("{original_content}# a comment\n");
            let (client, config) = create_test_client_and_config();
            let task = handle_document_change(
                uri.clone(),
                edited_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("comment-only edit should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("background task must complete promptly")
                .expect("background task must not panic");

            let (resolved_empty_after_edit, generation_after_edit) = state
                .with_document(&uri, |doc| {
                    (
                        doc.resolved_versions.is_empty(),
                        doc.resolved_versions_generation,
                    )
                })
                .unwrap();
            assert!(
                resolved_empty_after_edit,
                "resolved_versions must reflect the now-empty lock file, not stay stuck \
                 on the stale pre-deletion data"
            );
            assert_ne!(
                generation_after_edit, generation_before,
                "a lock file transitioning from resolved to empty must bump \
                 resolved_versions_generation, even for a comment-only edit with no \
                 manifest-text diff of its own (issue #1407 code-review must-fix)"
            );
        }

        /// Issue #1407 E1 (regression caught in critic's fourth pass): the must-fix
        /// test above (`test_lockfile_becoming_empty_bumps_resolved_generation`) must
        /// NOT fire when the lock file's empty read-back is a *parse failure* rather
        /// than a genuine absence — a lock file caught mid-rewrite by the package
        /// manager while this same debounced edit is in flight is a very real race, not
        /// an edge case. Mirrors `server::handle_lockfile_change`'s own
        /// `test_handle_lockfile_change_skips_osv_rescan_on_lockfile_reload_error`
        /// (issue #1395 M1) for the edit path.
        #[tokio::test]
        async fn test_lockfile_parse_error_does_not_bump_resolved_generation() {
            // See the comment in `test_document_parsing` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::test_utils::test_helpers::create_test_client_and_config;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let lockfile_path = temp_dir.path().join("Cargo.lock");
            std::fs::write(
                &lockfile_path,
                "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"alpha-dep\"\nversion = \"0.1.0\"\n\
                 source = \"git+https://github.com/example/alpha-dep\
                 #abcdef1234567890abcdef1234567890abcdef12\"\n",
            )
            .unwrap();
            let manifest_dir = temp_dir.path().join("crate");
            std::fs::create_dir(&manifest_dir).unwrap();
            let manifest_path = manifest_dir.join("Cargo.toml");
            let original_content =
                "[dependencies]\nalpha-dep = { git = \"https://github.com/example/alpha-dep\" }\n"
                    .to_string();
            std::fs::write(&manifest_path, &original_content).unwrap();
            let uri = Uri::from_file_path(&manifest_path).unwrap();

            let state = Arc::new(ServerState::new());
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
            .expect("initial open should succeed")
            .await
            .expect("initial open's background task must not panic");

            let (generation_before, resolved_versions_before) = state
                .with_document(&uri, |doc| {
                    (
                        doc.resolved_versions_generation,
                        doc.resolved_versions.clone(),
                    )
                })
                .unwrap();
            assert!(
                !resolved_versions_before.is_empty(),
                "the open path is expected to have resolved from the real lock file on disk"
            );

            // Present (so the reload finds it) but malformed, so the reload fails to
            // parse — not the same as the lock file being genuinely absent/empty.
            std::fs::write(&lockfile_path, "not valid toml [[[\n").unwrap();
            // Ensure a distinguishable mtime on filesystems with coarse timestamp
            // resolution (issue #1407 M3) — without this, the lock-file cache can
            // serve the stale, pre-rewrite entry on a coarse filesystem, making this
            // parse-error assertion pass vacuously (the reload never actually re-reads
            // the malformed content).
            std::fs::OpenOptions::new()
                .write(true)
                .open(&lockfile_path)
                .unwrap()
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(2))
                .unwrap();

            // Comment-only edit — touches no dependency, so `diff_needs_rescan` is
            // false; only the (incorrectly-treated-as-a-transition) parse failure could
            // trigger a bump if this guard were missing.
            let edited_content = format!("{original_content}# a comment\n");
            let (client, config) = create_test_client_and_config();
            let task = handle_document_change(
                uri.clone(),
                edited_content,
                Some(2),
                state.clone(),
                client,
                config,
            )
            .await
            .expect("comment-only edit should be accepted");

            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("background task must complete promptly")
                .expect("background task must not panic");

            let (resolved_versions_after, generation_after) = state
                .with_document(&uri, |doc| {
                    (
                        doc.resolved_versions.clone(),
                        doc.resolved_versions_generation,
                    )
                })
                .unwrap();
            assert_eq!(
                resolved_versions_after, resolved_versions_before,
                "a lock-file parse error must not clobber the known-good resolved \
                 versions already in memory (issue #1407 E1)"
            );
            assert_eq!(
                generation_after, generation_before,
                "a lock-file parse error must not bump resolved_versions_generation — \
                 a bump here, paired with no rescan of this call's own, would invalidate \
                 an unrelated in-flight scan's staleness guard with nothing to \
                 re-trigger a fresh commit (issue #1407 E1, mirroring #1395 M1)"
            );
        }
    }

    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let npm_uri = deps_core::test_util::test_uri("/test/package.json");
            assert!(state.ecosystem_registry.for_uri(&npm_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            // See the comment in `test_document_parsing` (cargo module) on why this guard
            // is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("npm ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &url).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Npm,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem, EcosystemId::Npm);
        }

        /// Impl-critic S1 regression: a version-guarded reparse whose `expected_version` no
        /// longer matches the document's *current* version (a concurrent `did_change` already
        /// landed) must not commit — the older, guarded reparse would otherwise silently
        /// revert the newer edit.
        #[tokio::test]
        async fn test_handle_document_change_guarded_skips_commit_when_version_changed() {
            use crate::test_utils::test_helpers::create_test_client_and_config;

            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
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
            // `store(true, ...)` line above. Poll rather than a single fixed sleep: a flat
            // 200ms margin over the task's own 50ms sleep flaked under CI-runner scheduling
            // load (#1337) — polling exits as soon as the flag is set while still tolerating
            // a slow scheduler up to a generous ceiling.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            while !ran_to_completion.load(Ordering::SeqCst)
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(
                ran_to_completion.load(Ordering::SeqCst),
                "the pre-existing background task must not be aborted by a skipped guarded reparse"
            );
        }
    }

    #[cfg(feature = "go")]
    mod go_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let go_uri = deps_core::test_util::test_uri("/test/go.mod");
            assert!(state.ecosystem_registry.for_uri(&go_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/go.mod");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r"module example.com/mymodule

go 1.21

require github.com/gorilla/mux v1.8.0
";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("go ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &url).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Go,
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem, EcosystemId::Go);
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
