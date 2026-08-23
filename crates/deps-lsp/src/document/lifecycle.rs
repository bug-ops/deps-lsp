//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::loader::{MAX_FILE_SIZE, load_document_from_disk};
use super::state::{DocumentState, ServerState};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use crate::progress::{ProgressSender, RegistryProgress};
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::Registry;
use deps_core::Result;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{MessageType, Uri};

/// Resolves the typed `EcosystemId` for an ecosystem trait object.
///
/// `ecosystem.id()` always originates from a statically registered ecosystem
/// (see `crate::register_ecosystems`), so parsing it back to `EcosystemId` can
/// only fail on an internal registration bug, not on user input.
fn resolve_ecosystem_id(ecosystem: &dyn Ecosystem) -> EcosystemId {
    ecosystem
        .id()
        .parse()
        .expect("ecosystem.id() must be a registered EcosystemId")
}

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

/// Preserves cached version data from old document state to new state.
/// Called during document updates to avoid re-fetching versions for unchanged deps.
fn preserve_cache(new_state: &mut DocumentState, old_state: &DocumentState) {
    tracing::trace!(
        cached = old_state.cached_versions.len(),
        resolved = old_state.resolved_versions.len(),
        vulnerabilities = old_state.vulnerabilities.len(),
        "preserving version cache"
    );
    new_state
        .cached_versions
        .clone_from(&old_state.cached_versions);
    new_state
        .resolved_versions
        .clone_from(&old_state.resolved_versions);
    // DocumentState is rebuilt on every change, so without this the OSV scan
    // result would be wiped on every keystroke — `run_osv_scan` overwrites it
    // once the (cheap, cache-backed) rescan completes, see §4.
    new_state
        .vulnerabilities
        .clone_from(&old_state.vulnerabilities);
}

/// Ceiling on the OSV scan timeout, independent of the configured
/// `fetch_timeout_secs`: the shared `reqwest` client behind `HttpCache`
/// already imposes its own client-wide 30s timeout (`cache.rs`), so a
/// per-phase timeout longer than that would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

/// Ecosystems whose *bare* (no explicit pin marker) version requirement is a
/// range under that ecosystem's own default semantics — Cargo's implicit
/// caret, npm/Composer's implicit caret. For these, [`is_concrete_version`]
/// requires an explicit `=`/`==` (or an exact-bracket wrap) before treating a
/// requirement as concrete; a bare `"1.2.3"` alone is not enough evidence
/// (critique C2).
///
/// Gradle is deliberately excluded: a bare Gradle coordinate version (e.g.
/// `"2.14.1"`) is an exact match under `GradleFormatter`'s own
/// `version_satisfies_requirement` unless it uses the `+` dynamic-version
/// suffix, which [`looks_like_a_single_version`] already rejects via its
/// reject-char set — Gradle has no implicit-caret default the way
/// Cargo/npm/Composer do.
const fn bare_version_is_a_range(ecosystem: EcosystemId) -> bool {
    matches!(
        ecosystem,
        EcosystemId::Cargo | EcosystemId::Npm | EcosystemId::Composer
    )
}

/// Returns `true` if `s` (already stripped of any pin marker) has the shape
/// of a single concrete version: non-empty, no wildcard/range-operator
/// character, and starting with a digit (after an optional `v`/`V` prefix,
/// e.g. Go's `v1.9.1`).
///
/// Deliberately conservative — see [`is_concrete_version`]'s doc for why a
/// false positive here is worse than a false negative.
fn looks_like_a_single_version(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains([
        '^', '~', '*', '<', '>', ',', '|', '(', ')', '[', ']', ' ', '\t', ':', '+', 'x', 'X',
    ]) {
        return false;
    }
    let core = s.strip_prefix(['v', 'V']).unwrap_or(s);
    core.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Returns `true` if `requirement` denotes a single concrete version — the
/// only shape safe to query OSV with directly (§3 step 2). A wrong answer
/// here is invisible in testing (OSV silently returns `{}` for a fabricated
/// version), so getting this right matters more than covering every
/// ecosystem's full range grammar.
///
/// An explicit pin marker (`=`/`==`, or a single-value bracket wrap like
/// NuGet's `[1.0.0]`) is always accepted. A *bare* requirement (no marker)
/// is accepted only for ecosystems where a bare version is not itself a
/// range by default (critique C2) — see [`bare_version_is_a_range`].
fn is_concrete_version(requirement: &str, ecosystem: EcosystemId) -> bool {
    let trimmed = requirement.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("latest") {
        return false;
    }

    let pinned = trimmed
        .strip_prefix("==")
        .or_else(|| trimmed.strip_prefix('='));
    let bracket_pinned = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .filter(|inner| !inner.contains(','));

    match pinned.or(bracket_pinned) {
        Some(body) => looks_like_a_single_version(body),
        None if bare_version_is_a_range(ecosystem) => false,
        None => looks_like_a_single_version(trimmed),
    }
}

/// Builds the OSV scan targets for one manifest's dependencies, applying the
/// version-selection policy from `architecture.md` §3 in order:
///
/// 0. Skip unless `dep.source() == DependencySource::Registry` — a patched
///    git/path fork must never be flagged with a CVE for a version it does
///    not actually contain.
/// 1. Use the lock-file-resolved version if present.
/// 2. Otherwise use the declared requirement, if it is already concrete.
/// 3. Otherwise skip — querying a fabricated version is a silent false
///    negative, which is worse than not scanning at all.
///
/// Every dependency that does **not** become a [`deps_core::osv::ScanTarget`]
/// gets an explicit [`deps_core::osv::ScanOutcome::Skipped`] entry in the
/// returned map instead of silently vanishing (critique C1) — absence from
/// [`deps_core::osv::VulnerabilityMap`] must never happen for an input this
/// function considered.
fn build_scan_targets(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> (
    Vec<deps_core::osv::ScanTarget>,
    deps_core::osv::VulnerabilityMap,
) {
    use deps_core::osv::{ScanOutcome, SkipReason};

    let mut targets = Vec::new();
    let mut skipped = deps_core::osv::VulnerabilityMap::new();

    for dep in parse_result.dependencies() {
        let key = formatter.normalize_package_name(dep.name());

        if dep.source() != deps_core::parser::DependencySource::Registry {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NonRegistrySource));
            continue;
        }

        let version = resolved_versions
            .get(key.as_str())
            .or_else(|| resolved_versions.get(dep.name()))
            .cloned()
            .or_else(|| {
                dep.version_requirement()
                    .filter(|req| is_concrete_version(req.as_str(), ecosystem))
                    .map(|req| req.as_str().to_string())
            });

        let Some(version) = version else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NoConcreteVersion));
            continue;
        };

        let Some(osv_name) = formatter.osv_package_name(dep) else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::UnmappableName));
            continue;
        };

        targets.push(deps_core::osv::ScanTarget {
            key,
            osv_name,
            version,
        });
    }

    (targets, skipped)
}

/// Logs the per-document scan summary unconditionally (critique C1) —
/// including when every dependency was filtered out before ever reaching
/// [`deps_core::osv::OsvClient::scan`], which previously produced no log line
/// at all and defeated §8 invariant 0's purpose of making "not scanned"
/// observable.
fn log_osv_run_summary(vulnerabilities: &deps_core::osv::VulnerabilityMap) {
    let mut clean = 0usize;
    let mut vulnerable = 0usize;
    let mut skipped = 0usize;
    for outcome in vulnerabilities.values() {
        match outcome {
            deps_core::osv::ScanOutcome::Clean => clean += 1,
            deps_core::osv::ScanOutcome::Vulnerable(_) => vulnerable += 1,
            deps_core::osv::ScanOutcome::Skipped(_) => skipped += 1,
        }
    }
    tracing::info!(
        "OSV: document scan complete, {} dependencies considered, {clean} clean, {vulnerable} vulnerable, {skipped} skipped",
        vulnerabilities.len(),
    );
}

/// Phase A output, carried from the concurrently-spawned scan task into
/// phase B (run later, after the registry fetch resolves — critique S1).
struct OsvScanResult {
    /// Document content at the moment the scan started, to guard the
    /// eventual write against a cross-generation stale commit (critique M4).
    content_snapshot: String,
    vulnerabilities: deps_core::osv::VulnerabilityMap,
    /// `key -> osv_name`, needed to build phase B candidates.
    osv_name_by_key: HashMap<String, String>,
    /// `key -> dep.name()` (raw, pre-normalization), the fallback
    /// `cached_versions` lookup needs since that map is keyed by the raw
    /// name while `key` is normalized (critique S2) — they differ for
    /// Composer/Swift/NuGet-style ecosystems.
    raw_name_by_key: HashMap<String, String>,
}

/// Phase A: builds scan targets, runs [`deps_core::osv::OsvClient::scan`], and
/// merges in the pre-filter skips — all before the registry fetch is known
/// to have completed, so this must be `tokio::spawn`ed by the caller and run
/// concurrently with it, never awaited inline (critique S2/original design
/// note: joining here would gate the inlay-hint refresh that must happen
/// immediately after the registry fetch).
///
/// Returns `None` only when there is nothing to report at all (no
/// dependencies reached any of steps 0-3, including the pre-filter skips —
/// i.e. an empty manifest).
async fn run_osv_scan_phase_a(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> Option<OsvScanResult> {
    let ecosystem_id = resolve_ecosystem_id(ecosystem.as_ref());

    let (content_snapshot, targets, mut vulnerabilities, raw_name_by_key) = {
        let doc = state.get_document(&uri)?;
        let parse_result = doc.parse_result()?;
        let (targets, skipped) = build_scan_targets(
            parse_result,
            &doc.resolved_versions,
            ecosystem.formatter(),
            ecosystem_id,
        );
        let raw_name_by_key: HashMap<String, String> = parse_result
            .dependencies()
            .into_iter()
            .map(|d| {
                (
                    ecosystem.formatter().normalize_package_name(d.name()),
                    d.name().to_string(),
                )
            })
            .collect();
        (doc.content.clone(), targets, skipped, raw_name_by_key)
    };

    if targets.is_empty() && vulnerabilities.is_empty() {
        return None;
    }

    let osv_name_by_key: HashMap<String, String> = targets
        .iter()
        .map(|t| (t.key.clone(), t.osv_name.clone()))
        .collect();

    if !targets.is_empty() {
        let timeout_duration =
            Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));
        let scanned = state
            .osv
            .scan(ecosystem_id, &targets, timeout_duration)
            .await;
        vulnerabilities.extend(scanned);
    }

    log_osv_run_summary(&vulnerabilities);

    Some(OsvScanResult {
        content_snapshot,
        vulnerabilities,
        osv_name_by_key,
        raw_name_by_key,
    })
}

/// Phase B: for every dependency phase A flagged [`deps_core::osv::ScanOutcome::Vulnerable`],
/// checks whether the version currently recommended (the registry's latest,
/// now that the registry fetch has resolved — critique S1) is itself
/// affected, then commits the result into `DocumentState.vulnerabilities`.
///
/// Must be called only *after* the registry fetch has updated
/// `doc.cached_versions`: calling it concurrently with that fetch (as the
/// original implementation did, by folding phase B into the same spawned
/// task as phase A) reads `cached_versions` before it holds the registry's
/// actual latest version, so hover could report the *already-installed*
/// version as "also affected" instead of the true latest.
///
/// The write is guarded against a cross-generation stale commit (critique
/// M4): `spawn_background_task` aborts the *previous* task only after the
/// new `DocumentState` is already installed, so an in-flight scan from stale
/// content could otherwise commit advisories computed against content the
/// document no longer has.
async fn run_osv_phase_b_and_commit(
    uri: &Uri,
    state: &Arc<ServerState>,
    ecosystem_id: EcosystemId,
    fetch_timeout_secs: u64,
    mut result: OsvScanResult,
) {
    let vulnerable_keys: Vec<String> = result
        .vulnerabilities
        .iter()
        .filter(|(_, outcome)| matches!(outcome, deps_core::osv::ScanOutcome::Vulnerable(_)))
        .map(|(key, _)| key.clone())
        .collect();

    if !vulnerable_keys.is_empty() {
        // TODO(critic): phase B checks registry-latest only; the fix target F is
        // never scanned — see #216 critique D1
        let candidates: Vec<deps_core::osv::ScanTarget> = {
            let Some(doc) = state.get_document(uri) else {
                return;
            };
            vulnerable_keys
                .iter()
                .filter_map(|key| {
                    let osv_name = result.osv_name_by_key.get(key)?.clone();
                    let latest = doc
                        .cached_versions
                        .get(key.as_str())
                        .or_else(|| {
                            let raw = result.raw_name_by_key.get(key)?;
                            doc.cached_versions.get(raw.as_str())
                        })?
                        .clone();
                    Some(deps_core::osv::ScanTarget {
                        key: key.clone(),
                        osv_name,
                        version: latest,
                    })
                })
                .collect()
        };

        if !candidates.is_empty() {
            let timeout_duration =
                Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));
            let statuses = state
                .osv
                .check_candidates(ecosystem_id, &candidates, timeout_duration)
                .await;
            for (key, status) in statuses {
                if let Some(deps_core::osv::ScanOutcome::Vulnerable(dv)) =
                    result.vulnerabilities.get_mut(&key)
                {
                    dv.upgrade_status = status;
                }
            }
        }
    }

    if let Some(mut doc) = state.documents.get_mut(uri) {
        if doc.content == result.content_snapshot {
            doc.update_vulnerabilities(result.vulnerabilities);
        } else {
            tracing::debug!("dropping stale OSV scan result: document content changed mid-scan");
        }
    }
}

/// Diff between old and new dependency sets.
///
/// `version_changed` exists because [`Self::added`]/[`Self::removed`] alone
/// are name-set diffs: editing a dependency's version requirement in place
/// (e.g. `time = "0.1.43"` -> `"0.1.44"`) changes neither set, so gating the
/// OSV rescan on `added` alone would silently skip re-scanning the one
/// dependency whose version just changed (critique S1).
#[derive(Debug, Clone, Default)]
struct DependencyDiff {
    added: Vec<PackageName>,
    removed: Vec<PackageName>,
    version_changed: Vec<PackageName>,
}

impl DependencyDiff {
    /// `old`/`new` map each dependency name to its declared version
    /// requirement (`Dependency::version_requirement()`) at parse time.
    fn compute(
        old: &HashMap<PackageName, Option<VersionReq>>,
        new: &HashMap<PackageName, Option<VersionReq>>,
    ) -> Self {
        let old_names: HashSet<&PackageName> = old.keys().collect();
        let new_names: HashSet<&PackageName> = new.keys().collect();

        let added = new_names
            .difference(&old_names)
            .map(|s| (*s).clone())
            .collect();
        let removed = old_names
            .difference(&new_names)
            .map(|s| (*s).clone())
            .collect();
        let version_changed = new_names
            .intersection(&old_names)
            .filter(|name| old.get(**name) != new.get(**name))
            .map(|s| (*s).clone())
            .collect();

        Self {
            added,
            removed,
            version_changed,
        }
    }

    #[cfg(test)]
    fn needs_fetch(&self) -> bool {
        !self.added.is_empty()
    }

    /// Whether the OSV rescan (§4) has any reason to run: a new dependency,
    /// or an existing one whose declared version changed. Kept separate from
    /// [`Self::needs_fetch`] (registry-fetch gating) since a version-only
    /// edit needs no registry request but does need a rescan.
    fn needs_osv_rescan(&self) -> bool {
        !self.added.is_empty() || !self.version_changed.is_empty()
    }
}

/// Builds `name -> version_requirement` for every dependency in `pr`, the
/// shape [`DependencyDiff::compute`] needs.
fn dependency_version_map(
    pr: &dyn deps_core::ParseResult,
) -> HashMap<PackageName, Option<VersionReq>> {
    pr.dependencies()
        .into_iter()
        .map(|d| (d.name().clone(), d.version_requirement().cloned()))
        .collect()
}

/// Result of parallel version fetching.
struct FetchResult {
    /// Successfully fetched versions (package -> latest version)
    versions: HashMap<PackageName, String>,
    /// Number of packages that failed to fetch (timeout or error)
    failed_count: usize,
    /// First actionable error message (shown to user via `window/showMessage`)
    first_error: Option<String>,
}

/// Fetches latest versions for multiple packages in parallel with progress reporting.
///
/// Returns a [`FetchResult`] containing successfully fetched versions and failure count.
/// Packages that fail to fetch are omitted from the versions map.
///
/// This function executes all registry requests concurrently with per-dependency
/// timeout isolation, preventing slow packages from blocking others.
///
/// # Arguments
///
/// * `registry` - Package registry to fetch from
/// * `package_names` - List of package names to fetch
/// * `progress` - Optional progress tracker (will be updated after each fetch)
/// * `timeout_secs` - Timeout for each individual package fetch (default: 10s)
/// * `max_concurrent` - Maximum concurrent fetches (default: 20)
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
async fn fetch_latest_versions_parallel(
    registry: Arc<dyn Registry>,
    package_names: Vec<PackageName>,
    progress_sender: Option<ProgressSender>,
    timeout_secs: u64,
    max_concurrent: usize,
) -> FetchResult {
    use futures::stream::{self, StreamExt};
    use std::time::Duration;

    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let timeout = Duration::from_secs(timeout_secs);
    let wildcard_req = deps_core::VersionReq::new("*");

    let results: Vec<_> = stream::iter(package_names)
        .map(|name| {
            let registry = Arc::clone(&registry);
            let fetched = Arc::clone(&fetched);
            let failed = Arc::clone(&failed);
            let first_error = Arc::clone(&first_error);
            let progress_sender = progress_sender.clone();
            let wildcard_req = &wildcard_req;
            async move {
                let result = tokio::time::timeout(
                    timeout,
                    registry.get_latest_matching(&name, wildcard_req),
                )
                .await;

                let version = match result {
                    Ok(Ok(Some(v))) => {
                        tracing::debug!(package = %name, version = %v.version_string(), "fetched");
                        Some((name.clone(), v.version_string().to_string()))
                    }
                    Ok(Ok(None)) => {
                        tracing::debug!(package = %name, "no version found");
                        None
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(package = %name, error = %e, "fetch failed");
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let mut fe = first_error.lock().unwrap_or_else(|p| p.into_inner());
                        if fe.is_none() {
                            *fe = Some(e.to_string());
                        }
                        None
                    }
                    Err(_) => {
                        tracing::warn!(package = %name, "fetch timed out ({}s)", timeout.as_secs());
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        None
                    }
                };

                let count = fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(ref sender) = progress_sender {
                    sender.send(count);
                }

                version
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    FetchResult {
        versions: results.into_iter().flatten().collect(),
        failed_count: failed.load(std::sync::atomic::Ordering::Relaxed),
        first_error: first_error.lock().unwrap_or_else(|p| p.into_inner()).take(),
    }
}

/// Generic document open handler using ecosystem registry.
///
/// Parses manifest using the ecosystem's parser, creates document state,
/// and spawns a background task to fetch version information from the registry.
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

    check_content_size(&content, &uri)?;

    tracing::info!(
        "Opening {:?} with ecosystem: {}",
        uri,
        ecosystem.display_name()
    );

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = ecosystem.parse_manifest(&content, &uri).await.ok();

    // Create document state (parse_result may be None)
    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(resolve_ecosystem_id(&*ecosystem), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(resolve_ecosystem_id(&*ecosystem), content)
    };
    doc_state.set_version(version);

    state.update_document(uri.clone(), doc_state);

    // Clone cache, diagnostics, and freshness config before spawning background task
    // (all read here, before any OSV request is built, so disabling the feature
    // suppresses the network call itself — FR-011).
    let (cache_config, vulnerabilities_enabled, freshness_settings) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
        )
    };

    // Spawn background task to fetch versions
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let client_clone = client.clone();

    let task = tokio::spawn(async move {
        tracing::debug!("background task started");

        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Update document state with resolved versions immediately
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
            // Use resolved versions as cached versions for instant display
            doc.update_cached_versions(resolved_versions.clone());
        }

        // Phase A OSV scan, spawned so it runs concurrently with the
        // registry fetch below rather than gating the inlay-hint refresh
        // that must happen immediately after it (critique S2).
        let osv_task = vulnerabilities_enabled.then(|| {
            tokio::spawn(run_osv_scan_phase_a(
                uri_clone.clone(),
                Arc::clone(&state_clone),
                Arc::clone(&ecosystem_clone),
                cache_config.fetch_timeout_secs,
            ))
        });

        // Collect dependency names while holding reference (can't hold across await)
        let dep_names: Vec<PackageName> = {
            let doc = match state_clone.get_document(&uri_clone) {
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
            parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().clone())
                .collect()
        };

        tracing::debug!(count = dep_names.len(), "starting registry fetch");

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(client_clone.clone(), uri_clone.as_str(), dep_names.len()),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        };

        tracing::debug!("progress started, fetching versions");

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            dep_names,
            progress_sender,
            cache_config.fetch_timeout_secs,
            cache_config.max_concurrent_fetches,
        )
        .await;

        let success = !fetch_result.versions.is_empty();
        tracing::debug!(
            fetched = fetch_result.versions.len(),
            failed = fetch_result.failed_count,
            "registry fetch complete"
        );

        // Update document state with cached versions (latest from registry)
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.update_cached_versions(fetch_result.versions);
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

        // Notify user about failed packages
        if fetch_result.failed_count > 0 {
            let message = if let Some(err) = &fetch_result.first_error {
                format!("deps-lsp: {err}")
            } else {
                format!(
                    "deps-lsp: {} package(s) failed to fetch (timeout or network error)",
                    fetch_result.failed_count
                )
            };
            client_clone
                .show_message(MessageType::WARNING, message)
                .await;
        }

        // Refresh inlay hints IMMEDIATELY after loading completes
        // (before diagnostics which may take longer due to additional network calls)
        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
        if let Err(e) = client_clone.code_lens_refresh().await {
            tracing::debug!("code_lens_refresh not supported: {:?}", e);
        }

        // Join phase A (already running concurrently since it was spawned
        // above) and, only now that `cached_versions` holds the registry's
        // actual latest (not the lockfile-seeded placeholder — critique S1),
        // run phase B and commit before generating diagnostics.
        if let Some(osv_task) = osv_task {
            match osv_task.await {
                Ok(Some(phase_a_result)) => {
                    let ecosystem_id = resolve_ecosystem_id(ecosystem_clone.as_ref());
                    run_osv_phase_b_and_commit(
                        &uri_clone,
                        &state_clone,
                        ecosystem_id,
                        cache_config.fetch_timeout_secs,
                        phase_a_result,
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("OSV scan task failed: {e}"),
            }
        }

        // Publish diagnostics (may be slower, runs after hints are already visible)
        let diags = diagnostics::generate_diagnostics_internal(
            Arc::clone(&state_clone),
            &uri_clone,
            freshness_settings,
        )
        .await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;
    });

    Ok(task)
}

/// Generic document change handler using ecosystem registry.
///
/// Re-parses manifest when document content changes and spawns a debounced
/// task to update diagnostics and request inlay hint refresh.
pub async fn handle_document_change(
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

    check_content_size(&content, &uri)?;

    // Extract old dependency name -> version_requirement map before parsing
    // (for diff computation)
    let old_deps: HashMap<PackageName, Option<VersionReq>> =
        state.get_document(&uri).map_or_else(HashMap::new, |doc| {
            doc.parse_result()
                .map(dependency_version_map)
                .unwrap_or_default()
        });

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = ecosystem.parse_manifest(&content, &uri).await.ok();

    // Extract new dependency name -> version_requirement map for diff
    let new_deps: HashMap<PackageName, Option<VersionReq>> = parse_result
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

    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(resolve_ecosystem_id(&*ecosystem), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(resolve_ecosystem_id(&*ecosystem), content)
    };
    doc_state.set_version(version);

    if let Some(old_doc) = state.get_document(&uri) {
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
        doc_state
            .vulnerabilities
            .remove(&formatter.normalize_package_name(removed_dep));
    }

    state.update_document(uri.clone(), doc_state);

    // Clone cache, diagnostics, and freshness config before spawning background task
    // (all read here, before any OSV request is built — FR-011).
    let (cache_config, vulnerabilities_enabled, freshness_settings) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
        )
    };

    // Spawn background task to update diagnostics
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let client_clone = client.clone();
    let needs_osv_rescan = diff.needs_osv_rescan();
    let deps_to_fetch = diff.added;

    let task = tokio::spawn(async move {
        // Small debounce delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Update document state with resolved versions only
        // Do NOT touch cached_versions - they contain latest registry versions
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
        }

        // Phase A OSV scan (only when a dependency was added or an existing
        // one's version changed — critique S1), spawned so it runs
        // concurrently with the registry fetch below.
        let osv_task = (vulnerabilities_enabled && needs_osv_rescan).then(|| {
            tokio::spawn(run_osv_scan_phase_a(
                uri_clone.clone(),
                Arc::clone(&state_clone),
                Arc::clone(&ecosystem_clone),
                cache_config.fetch_timeout_secs,
            ))
        });

        // Skip registry fetch if no new dependencies
        if deps_to_fetch.is_empty() {
            tracing::debug!("no new dependencies, skipping registry fetch");

            if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
                doc.set_loaded();
            }

            if let Err(e) = client_clone.inlay_hint_refresh().await {
                tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
            }
            if let Err(e) = client_clone.code_lens_refresh().await {
                tracing::debug!("code_lens_refresh not supported: {:?}", e);
            }

            if let Some(osv_task) = osv_task {
                match osv_task.await {
                    Ok(Some(phase_a_result)) => {
                        let ecosystem_id = resolve_ecosystem_id(ecosystem_clone.as_ref());
                        run_osv_phase_b_and_commit(
                            &uri_clone,
                            &state_clone,
                            ecosystem_id,
                            cache_config.fetch_timeout_secs,
                            phase_a_result,
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!("OSV scan task failed: {e}"),
                }
            }

            let diags = diagnostics::generate_diagnostics_internal(
                Arc::clone(&state_clone),
                &uri_clone,
                freshness_settings,
            )
            .await;
            client_clone
                .publish_diagnostics(uri_clone.clone(), diags, None)
                .await;
            return;
        }

        tracing::info!(
            count = deps_to_fetch.len(),
            "fetching versions for new dependencies"
        );

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(
                client_clone.clone(),
                uri_clone.as_str(),
                deps_to_fetch.len(),
            ),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        };

        // Fetch latest versions only for NEW dependencies
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            deps_to_fetch,
            progress_sender,
            cache_config.fetch_timeout_secs,
            cache_config.max_concurrent_fetches,
        )
        .await;

        let success = !fetch_result.versions.is_empty();

        // Merge new versions into existing cache
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            for (name, version) in fetch_result.versions {
                doc.cached_versions.insert(name, version);
            }
            if success {
                doc.set_loaded();
            } else {
                doc.set_failed();
            }
        }

        if let Some(progress) = progress {
            progress.end(success).await;
        }

        // Notify user about failed packages
        if fetch_result.failed_count > 0 {
            let message = if let Some(err) = &fetch_result.first_error {
                format!("deps-lsp: {err}")
            } else {
                format!(
                    "deps-lsp: {} package(s) failed to fetch (timeout or network error)",
                    fetch_result.failed_count
                )
            };
            client_clone
                .show_message(MessageType::WARNING, message)
                .await;
        }

        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
        if let Err(e) = client_clone.code_lens_refresh().await {
            tracing::debug!("code_lens_refresh not supported: {:?}", e);
        }

        if let Some(osv_task) = osv_task {
            match osv_task.await {
                Ok(Some(phase_a_result)) => {
                    let ecosystem_id = resolve_ecosystem_id(ecosystem_clone.as_ref());
                    run_osv_phase_b_and_commit(
                        &uri_clone,
                        &state_clone,
                        ecosystem_id,
                        cache_config.fetch_timeout_secs,
                        phase_a_result,
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("OSV scan task failed: {e}"),
            }
        }

        let diags = diagnostics::generate_diagnostics_internal(
            Arc::clone(&state_clone),
            &uri_clone,
            freshness_settings,
        )
        .await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;
    });

    Ok(task)
}

/// Loads resolved versions from lock file for a given manifest URI.
///
/// Uses the ecosystem's lockfile provider to parse the lock file.
/// Returns a HashMap mapping package names to their resolved versions.
/// Returns an empty HashMap if no lock file is found or parsing fails.
async fn load_resolved_versions(
    uri: &Uri,
    state: &ServerState,
    ecosystem: &dyn Ecosystem,
) -> HashMap<PackageName, String> {
    let lock_provider = match ecosystem.lockfile_provider() {
        Some(p) => p,
        None => {
            tracing::debug!("No lock file provider for ecosystem {}", ecosystem.id());
            return HashMap::new();
        }
    };

    let lockfile_path = match lock_provider.locate_lockfile(uri) {
        Some(path) => path,
        None => {
            tracing::debug!("No lock file found for {:?}", uri);
            return HashMap::new();
        }
    };

    match state
        .lockfile_cache
        .get_or_parse(lock_provider.as_ref(), &lockfile_path)
        .await
    {
        Ok(resolved) => {
            tracing::info!(
                "Loaded {} resolved versions from {}",
                resolved.len(),
                lockfile_path.display()
            );
            resolved
                .iter()
                .map(|(name, pkg)| (PackageName::new(name.as_str()), pkg.version.clone()))
                .collect()
        }
        Err(e) => {
            tracing::warn!("Failed to parse lock file: {}", e);
            HashMap::new()
        }
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
    use super::*;

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

        let uri = deps_core::test_util::test_uri("/nonexistent/Cargo.toml");
        let result = load_document_from_disk(&uri).await;

        assert!(result.is_err(), "Should fail for missing files");

        // This error would cause ensure_document_loaded to return false
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(TimeoutRegistry);
        let packages = vec![PackageName::new("slow-package")];

        // Use 1 second timeout for test speed
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;

        // Should return empty (timeout, not success)
        assert!(result.versions.is_empty(), "Slow package should timeout");
        assert_eq!(result.failed_count, 1, "Should track 1 failed package");
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
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
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
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

        fetch_latest_versions_parallel(registry, packages, None, 5, 20).await;

        // Max concurrent should not exceed limit (allow small margin for timing)
        let max = max_seen.load(Ordering::SeqCst);
        assert!(
            max <= 22,
            "Concurrency limit violated: {} concurrent requests (limit: 20)",
            max
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
            version: String,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &str {
                &self.version
            }

            fn is_prerelease(&self) -> bool {
                false
            }

            fn is_yanked(&self) -> bool {
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
                                version: "1.0.0".to_string(),
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
                            version: "1.0.0".to_string(),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
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
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;

        // Only the fast package should be in results
        assert_eq!(
            result.versions.len(),
            1,
            "Should have exactly 1 successful package"
        );
        assert_eq!(
            result.versions.get("package-fast"),
            Some(&"1.0.0".to_string()),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
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
        let result = fetch_latest_versions_parallel(registry, packages, None, 5, 10).await;

        // All packages failed, result should be empty
        assert!(
            result.versions.is_empty(),
            "All packages with errors should be omitted from results"
        );
        assert_eq!(
            result.failed_count, 3,
            "All 3 packages should be marked as failed"
        );
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
    }

    // Phase 1: Cache Preservation Tests
    #[cfg(feature = "cargo")]
    mod incremental_fetch_tests {
        use super::*;

        #[tokio::test]
        async fn test_preserve_cached_versions_on_change() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Initial document with 2 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Manually populate cache (simulating background fetch)
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".into(), "1.0.210".to_string());
                doc.cached_versions
                    .insert("tokio".into(), "1.40.0".to_string());
                doc.resolved_versions
                    .insert("serde".into(), "1.0.195".to_string());
                doc.resolved_versions
                    .insert("tokio".into(), "1.35.0".to_string());
            }

            // Verify cache populated
            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(doc.cached_versions.len(), 2);
                assert_eq!(doc.resolved_versions.len(), 2);
            }

            // Change document (modify serde version)
            let content2 = r#"[dependencies]
serde = "1.0.210"
tokio = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache preserved after update
            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(
                    doc.cached_versions.len(),
                    2,
                    "Cached versions should be preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("serde"),
                    Some(&"1.0.210".to_string()),
                    "serde cache preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("tokio"),
                    Some(&"1.40.0".to_string()),
                    "tokio cache preserved"
                );
                assert_eq!(
                    doc.resolved_versions.len(),
                    2,
                    "Resolved versions should be preserved"
                );
            }
        }

        #[tokio::test]
        async fn test_preserve_cache_carries_vulnerabilities_across_edit() {
            use deps_core::osv::{ScanOutcome, VulnerabilityMap};

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            let mut vulns = VulnerabilityMap::new();
            vulns.insert("time".to_string(), ScanOutcome::Clean);
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_vulnerabilities(vulns);
            }

            // A whitespace-only edit: DocumentState is rebuilt from scratch,
            // which would silently wipe `vulnerabilities` on every keystroke
            // without preserve_cache carrying it through (§4).
            let content2 = r#"[dependencies]
time = "0.1.43"

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(matches!(
                doc.vulnerabilities.get("time"),
                Some(ScanOutcome::Clean)
            ));
        }

        #[tokio::test]
        async fn test_first_open_has_empty_cache() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            // First open: cache should be empty (no old state to preserve)
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                0,
                "First open should have empty cache"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_on_parse_failure() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Valid initial document
            let content1 = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Populate cache
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".into(), "1.0.210".to_string());
            }

            // Invalid TOML (parse will fail)
            let content2 = r#"[dependencies
serde = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.ok();
            assert!(
                parse_result2.is_none(),
                "Parse should fail for invalid TOML"
            );

            let mut doc_state2 =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, content2.to_string());

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            // Cache should be preserved despite parse failure
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                1,
                "Cache should be preserved on parse failure"
            );
            assert_eq!(
                doc.cached_versions.get("serde"),
                Some(&"1.0.210".to_string())
            );
        }

        fn versions(pairs: &[(&str, Option<&str>)]) -> HashMap<PackageName, Option<VersionReq>> {
            pairs
                .iter()
                .map(|(name, req)| (PackageName::new(*name), req.map(VersionReq::new)))
                .collect()
        }

        #[test]
        fn test_dependency_diff_detects_additions() {
            let old = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);
            let new = versions(&[
                ("serde", Some("1.0")),
                ("tokio", Some("1.0")),
                ("anyhow", Some("1.0")),
            ]);

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 1);
            assert!(diff.added.contains(&PackageName::new("anyhow")));
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
            assert!(diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_detects_removals() {
            let old = versions(&[
                ("serde", Some("1.0")),
                ("tokio", Some("1.0")),
                ("anyhow", Some("1.0")),
            ]);
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert_eq!(diff.removed.len(), 1);
            assert!(diff.removed.contains(&PackageName::new("anyhow")));
            assert!(!diff.needs_fetch());
            assert!(!diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_no_changes() {
            let old = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert!(diff.version_changed.is_empty());
            assert!(!diff.needs_fetch());
            assert!(!diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_empty_to_new() {
            let old: HashMap<PackageName, Option<VersionReq>> = HashMap::new();
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 2);
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
        }

        #[test]
        fn test_dependency_diff_detects_version_change_without_name_set_change() {
            // Regression guard for critique S1: editing only a dependency's
            // version must be detected even though the name set is unchanged.
            let old = versions(&[("time", Some("0.1.43"))]);
            let new = versions(&[("time", Some("0.1.44"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);
            assert!(!diff.needs_fetch(), "registry fetch is name-set gated only");
            assert!(
                diff.needs_osv_rescan(),
                "a version-only edit must still trigger an OSV rescan"
            );
        }

        #[tokio::test]
        async fn test_cache_pruned_on_dependency_removal() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Initial document with 3 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
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

            // Populate cache for all 3 deps
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert(PackageName::new("serde"), "1.0.210".to_string());
                doc.cached_versions
                    .insert(PackageName::new("tokio"), "1.40.0".to_string());
                doc.cached_versions
                    .insert(PackageName::new("anyhow"), "1.0.89".to_string());
            }

            // Remove anyhow from manifest
            let content2 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            // Compute diff and apply cache pruning
            let old_deps: HashMap<PackageName, Option<VersionReq>> = ["serde", "tokio", "anyhow"]
                .iter()
                .map(|s| (PackageName::new(*s), None))
                .collect();
            let new_deps: HashMap<PackageName, Option<VersionReq>> = ["serde", "tokio"]
                .iter()
                .map(|s| (PackageName::new(*s), None))
                .collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            // Prune removed dependencies
            for removed_dep in &diff.removed {
                doc_state2.cached_versions.remove(removed_dep);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache was pruned
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                2,
                "anyhow should be removed from cache"
            );
            assert!(doc.cached_versions.contains_key("serde"));
            assert!(doc.cached_versions.contains_key("tokio"));
            assert!(!doc.cached_versions.contains_key("anyhow"));
        }
    }

    mod osv_scan_target_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::lsp_helpers::EcosystemFormatter;
        use deps_core::parser::DependencySource;
        use std::any::Any;
        use tower_lsp_server::ls_types::{Position, Range};

        struct MockFormatter;
        impl EcosystemFormatter for MockFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

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
                Range::new(Position::new(0, 0), Position::new(0, 1))
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
            fn uri(&self) -> &Uri {
                static URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
                URI.get_or_init(|| deps_core::test_util::test_uri("/test/Cargo.toml"))
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        use deps_core::osv::{ScanOutcome, SkipReason};

        #[test]
        fn is_concrete_version_accepts_explicit_pins_in_any_ecosystem() {
            for eco in [EcosystemId::Cargo, EcosystemId::Npm, EcosystemId::Go] {
                assert!(is_concrete_version("=1.2.3", eco), "{eco:?}");
            }
            // Go's go.mod bare `v1.9.1` style: Go is not in the
            // range-default set, so the bare form (with its `v` prefix) is
            // accepted without needing an explicit `=`.
            assert!(is_concrete_version("v1.9.1", EcosystemId::Go));
        }

        #[test]
        fn is_concrete_version_pep440_double_equals_is_a_pin() {
            // Critique C2: `strip_prefix('=')` alone turns PEP 440 `"==2.28.0"`
            // into `"=2.28.0"`, whose first char then fails the digit check.
            assert!(is_concrete_version("==2.28.0", EcosystemId::Pypi));
        }

        #[test]
        fn is_concrete_version_bare_digit_accepted_for_non_range_default_ecosystems() {
            // Maven/Go/Bundler/Dart/Gradle/NuGet: a bare version is already
            // exact (or, for NuGet's PackageReference floor, resolves to
            // exactly that version in practice). Gradle in particular has no
            // implicit-caret default for a plain coordinate version like
            // `"2.14.1"` — only the `+` dynamic-version suffix is a range,
            // and that's rejected separately by `looks_like_a_single_version`.
            for eco in [
                EcosystemId::Maven,
                EcosystemId::Go,
                EcosystemId::Bundler,
                EcosystemId::Dart,
                EcosystemId::Gradle,
                EcosystemId::NuGet,
            ] {
                assert!(is_concrete_version("2.14.1", eco), "{eco:?}");
            }
        }

        #[test]
        fn is_concrete_version_bare_digit_rejected_for_range_default_ecosystems() {
            // Critique C2: Cargo's bare "1.2.3" is a caret range under
            // Cargo's own default operator, not a pin — same for npm and
            // Composer's implicit range notations.
            for eco in [EcosystemId::Cargo, EcosystemId::Npm, EcosystemId::Composer] {
                assert!(!is_concrete_version("1.2.3", eco), "{eco:?}");
                // ...but an explicit pin is still accepted.
                assert!(is_concrete_version("=1.2.3", eco), "{eco:?}");
            }
        }

        #[test]
        fn is_concrete_version_rejects_partials_and_wildcards() {
            // Critique C2: npm/Composer "1.x"/"1.2.x" and bare partials like
            // "1.2" are ranges, and Gradle's "1.+" is a dynamic version —
            // none of these contained a previously-rejected character.
            for eco in [EcosystemId::Npm, EcosystemId::Composer] {
                assert!(!is_concrete_version("1.x", eco), "{eco:?}");
                assert!(!is_concrete_version("1.2.x", eco), "{eco:?}");
                assert!(!is_concrete_version("1.2", eco), "{eco:?}");
            }
            assert!(!is_concrete_version("1.+", EcosystemId::Gradle));
        }

        #[test]
        fn is_concrete_version_rejects_ranges_and_wildcards() {
            for eco in [EcosystemId::Maven, EcosystemId::Go] {
                assert!(!is_concrete_version("^1.0", eco));
                assert!(!is_concrete_version("~1.2", eco));
                assert!(!is_concrete_version("*", eco));
                assert!(!is_concrete_version(">=1.0", eco));
                assert!(!is_concrete_version(">=1.0 <2.0", eco));
                assert!(!is_concrete_version("1.0.*", eco));
                assert!(!is_concrete_version("", eco));
            }
        }

        #[test]
        fn is_concrete_version_rejects_non_version_schemes() {
            let eco = EcosystemId::Go;
            assert!(!is_concrete_version("latest", eco));
            assert!(!is_concrete_version("github:user/repo", eco));
            assert!(!is_concrete_version("file:../x", eco));
            assert!(!is_concrete_version("main", eco));
        }

        #[test]
        fn build_scan_targets_step0_skips_non_registry_source_even_with_lockfile_version() {
            // A git/path/patched fork must never be flagged with a CVE for a
            // version it does not actually contain, even when its lockfile
            // entry carries a plausible-looking version (critique C2).
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("0.1.43")),
                    source: DependencySource::Git {
                        url: "https://github.com/example/time".to_string(),
                        rev: None,
                    },
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("time"), "0.1.43".to_string());

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Cargo);
            assert!(targets.is_empty());
            assert!(matches!(
                skipped.get("time"),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            ));
        }

        #[test]
        fn build_scan_targets_step1_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".to_string());

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Cargo);
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step2_uses_concrete_requirement_verbatim() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Maven);
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "2.14.1");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step3_skips_caret_range_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Cargo);
            assert!(targets.is_empty());
            assert!(matches!(
                skipped.get("serde"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            ));
        }

        #[test]
        fn build_scan_targets_step3_skips_wildcard_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("*")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Cargo);
            assert!(targets.is_empty());
            assert!(matches!(
                skipped.get("serde"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            ));
        }

        #[test]
        fn build_scan_targets_all_non_registry_sources_are_skipped() {
            let sources = vec![
                DependencySource::Path {
                    path: "../local".to_string(),
                },
                DependencySource::Url {
                    url: "https://example.com/pkg.tgz".to_string(),
                },
                DependencySource::Sdk {
                    sdk: "flutter".to_string(),
                },
                DependencySource::Workspace,
                DependencySource::CustomRegistry {
                    url: "https://private.example.com".to_string(),
                },
            ];

            for source in sources {
                let parse_result = MockParseResult {
                    deps: vec![MockDep {
                        name: PackageName::new("pkg"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: source.clone(),
                    }],
                };
                let mut resolved = HashMap::new();
                resolved.insert(PackageName::new("pkg"), "1.0.0".to_string());

                let (targets, skipped) = build_scan_targets(
                    &parse_result,
                    &resolved,
                    &MockFormatter,
                    EcosystemId::Cargo,
                );
                assert!(targets.is_empty(), "{source:?} must be skipped (step 0)");
                assert!(matches!(
                    skipped.get("pkg"),
                    Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
                ));
            }
        }

        #[test]
        fn build_scan_targets_never_drops_a_dependency_silently() {
            // Critique C1: every dependency considered must end up in either
            // `targets` or `skipped` — never absent from both.
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("concrete"),
                        version_req: Some(VersionReq::new("2.14.1")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("range-only"),
                        version_req: Some(VersionReq::new("^1.0")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("git-dep"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: DependencySource::Git {
                            url: "https://example.com/git-dep".to_string(),
                            rev: None,
                        },
                    },
                ],
            };
            let resolved = HashMap::new();

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockFormatter, EcosystemId::Maven);

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].key, "concrete");
            assert_eq!(skipped.len(), 2);
            assert!(matches!(
                skipped.get("range-only"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            ));
            assert!(matches!(
                skipped.get("git-dep"),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            ));
        }
    }
}
