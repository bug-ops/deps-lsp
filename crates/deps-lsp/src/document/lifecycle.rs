//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::loader::{MAX_FILE_SIZE, load_document_from_disk};
use super::state::{DocumentState, ServerState};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use crate::progress::{ProgressSender, RegistryProgress};
use deps_core::Dependency;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::PackageVersions;
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
        yanked = old_state.yanked_versions.len(),
        fetch_failed = old_state.fetch_failed.len(),
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
    // Same rationale as `vulnerabilities` above — without this the yanked
    // diagnostic would flicker off on every keystroke until the next fetch.
    new_state
        .yanked_versions
        .clone_from(&old_state.yanked_versions);
    // Same rationale — without this a registry-outage package would flip
    // back to a misleading "Unknown package" diagnostic on every keystroke
    // until the next fetch cycle re-populates it (#267).
    new_state.fetch_failed.clone_from(&old_state.fetch_failed);
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
/// Deno reuses npm's exact grammar for both its `jsr:` and `npm:` specifiers
/// (`DenoFormatter::compile_requirement` compiles both through the same
/// `node_semver::Range` npm itself uses), so it gets the same treatment here.
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
        EcosystemId::Cargo | EcosystemId::Npm | EcosystemId::Composer | EcosystemId::Deno
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

/// Returns the concrete version text `requirement` denotes — with any pin
/// marker (`=`/`==`, or a single-value bracket wrap like NuGet's `[1.0.0]`)
/// stripped off — or `None` if `requirement` is not the shape of a single
/// concrete version. The only shape safe to query OSV with directly (§3
/// step 2), and, for #233, the only shape safe to compare against a real
/// registry version string in the yanked-version probe. A wrong answer here
/// is invisible in testing (OSV silently returns `{}` for a fabricated
/// version; the yanked probe silently finds no match), so getting this
/// right matters more than covering every ecosystem's full range grammar.
///
/// An explicit pin marker is always accepted, and its marker is stripped
/// from the returned text — required because PyPI's parser retains the
/// pep440 comparator in `Dependency::version_requirement()` (an exact pin
/// parses to `"==4.9.0"`, not `"4.9.0"`; confirmed by
/// `deps-pypi`'s `test_basic_pinned`), so comparing the *unstripped* text
/// against a real registry version string (`"4.9.0"`) would never match. A
/// *bare* requirement (no marker) is returned verbatim, and is accepted only
/// for ecosystems where a bare version is not itself a range by default
/// (critique C2) — see [`bare_version_is_a_range`].
fn concrete_pin_version(requirement: &str, ecosystem: EcosystemId) -> Option<&str> {
    let trimmed = requirement.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("latest") {
        return None;
    }

    let pinned = trimmed
        .strip_prefix("==")
        .or_else(|| trimmed.strip_prefix('='));
    let bracket_pinned = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .filter(|inner| !inner.contains(','));

    match pinned.or(bracket_pinned) {
        Some(body) => looks_like_a_single_version(body).then_some(body),
        None if bare_version_is_a_range(ecosystem) => None,
        None => looks_like_a_single_version(trimmed).then_some(trimmed),
    }
}

/// Returns `true` if `requirement` denotes a single concrete version. See
/// [`concrete_pin_version`], whose boolean projection this is, for the
/// acceptance rules. Test-only: production code needs the stripped text
/// from `concrete_pin_version` itself, not just the boolean.
#[cfg(test)]
fn is_concrete_version(requirement: &str, ecosystem: EcosystemId) -> bool {
    concrete_pin_version(requirement, ecosystem).is_some()
}

/// The version of `dep` this project treats as actually in use: the
/// lock-file-resolved version, else the declared requirement when it is
/// already concrete ([`concrete_pin_version`]). `None` when neither applies.
///
/// A dependency whose manifest requirement is itself the resolved version
/// ([`deps_core::lsp_helpers::EcosystemFormatter::manifest_requirement_is_resolved_version`]
/// — a Go `require`-directive dependency) skips the lockfile step entirely,
/// going straight to the declared requirement — see [`build_scan_targets`]
/// for why go.sum is unreliable here. Shared by `build_scan_targets` (OSV
/// targets) and the yanked-version check (`fetch_latest_versions_parallel`),
/// both of which need "what version does the user actually have" for the
/// same reason: querying a fabricated version produces a silent false
/// negative.
fn in_use_version(
    dep: &dyn Dependency,
    normalized_name: &str,
    resolved_versions: &HashMap<PackageName, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> Option<String> {
    if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement()
            .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
            .map(str::to_string)
    } else {
        resolved_versions
            .get(normalized_name)
            .or_else(|| resolved_versions.get(dep.name()))
            .cloned()
            .or_else(|| {
                dep.version_requirement()
                    .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
                    .map(str::to_string)
            })
    }
}

/// Builds `dep_name -> in_use_version` (§4.5/§4.6) for every dependency with
/// a known in-use version, for the yanked-check probe in
/// `fetch_latest_versions_parallel`. Skips non-registry dependencies
/// (git/path forks, step 0 of [`build_scan_targets`]'s ladder) so a patched
/// fork is never flagged for a registry version it does not contain.
fn collect_in_use_versions(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> HashMap<PackageName, String> {
    parse_result
        .dependencies()
        .into_iter()
        .filter(|dep| dep.source() == deps_core::parser::DependencySource::Registry)
        .filter_map(|dep| {
            let normalized_name = formatter.normalize_package_name(dep.name());
            in_use_version(
                dep,
                &normalized_name,
                resolved_versions,
                formatter,
                ecosystem,
            )
            .map(|v| (dep.name().clone(), v))
        })
        .collect()
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
/// **Go exception** (#228 follow-up, unified with #235's
/// [`deps_core::lsp_helpers::EcosystemFormatter::manifest_requirement_is_resolved_version`]):
/// step 1 is skipped entirely for a dependency whose manifest requirement is
/// itself the resolved version (a Go `require`-directive dependency), going
/// straight to step 2. Go's `go.mod` `require` line is already an exact
/// pinned version, never a range, unlike Cargo/npm where the manifest is a
/// range and the lockfile holds the pin. go.sum-derived `resolved_versions`
/// is unreliable here: go.sum is a checksum ledger that `go get`/`go build`
/// only ever append to (only `go mod tidy` prunes it), so its
/// last-occurrence-wins parse can surface a version still recorded in the
/// file but no longer selected by Go's MVS — silently querying OSV against
/// the wrong version. Routing through the formatter hook (rather than a bare
/// `ecosystem == EcosystemId::Go` check) also excludes Go's `exclude`/
/// `replace` directive pseudo-dependencies, whose `version_requirement()` is
/// not an in-use version.
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

        // lockfile holds the pin) — so for a Go `require` dependency the
        // manifest itself is the authoritative version, not go.sum. go.sum is
        // a checksum ledger that `go get`/`go build` only ever append to
        // (only `go mod tidy` prunes it), so its last-occurrence-wins parse
        // can yield a stale version still recorded in the file but no longer
        // selected by Go's MVS, silently mismatching whatever's actually in
        // use. Skipping the lockfile lookup avoids feeding that stale version
        // to OSV (excludes/replaces fall through to the lockfile lookup below
        // like any other ecosystem, since their `version_requirement()` is
        // not an in-use version — see `manifest_requirement_is_resolved_version`).
        let version = in_use_version(dep, &key, resolved_versions, formatter, ecosystem);

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
            version: formatter.osv_version(&version),
            display_version: version,
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
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
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
                        .latest
                        .clone();
                    Some(deps_core::osv::ScanTarget {
                        key: key.clone(),
                        osv_name,
                        version: formatter.osv_version(&latest),
                        display_version: latest,
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

    /// Whether the registry fetch (and therefore the yanked-version probe,
    /// #233) has any reason to run: a new dependency, or an existing one
    /// whose declared version changed. A version-only edit still needs the
    /// fetch — the "latest" value itself does not change, but a dependency
    /// edited from a safe pin to a yanked one (or vice versa) must be
    /// re-probed against its new in-use version, and any stale finding
    /// against the *old* version must not linger (security F1 / impl-critic
    /// S1).
    #[cfg(test)]
    fn needs_fetch(&self) -> bool {
        !self.added.is_empty() || !self.version_changed.is_empty()
    }

    /// Whether the OSV rescan (§4) has any reason to run: a new dependency,
    /// or an existing one whose declared version changed. Identical to
    /// [`Self::needs_fetch`] today (both gate on `added`/`version_changed`);
    /// kept as separate methods since they answer different questions and
    /// could diverge again if either gate changes independently.
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
    /// Successfully fetched versions (package -> latest + full version list)
    versions: HashMap<PackageName, PackageVersions>,
    /// Yanked-version findings, keyed by **raw** package name (unlike
    /// `DocumentState::yanked_versions`, which is normalized-keyed — see
    /// §3.1 of the design). Callers must re-key through
    /// `EcosystemFormatter::normalize_package_name` before merging into
    /// document state.
    yanked_versions: HashMap<PackageName, String>,
    /// Packages whose registry fetch errored or timed out, keyed by **raw**
    /// package name (same raw/normalized split as `yanked_versions` above).
    /// Lets diagnostic generation (#267) distinguish "the registry said this
    /// package doesn't exist" from "the registry couldn't be asked" instead
    /// of conflating both into a misleading "Unknown package" diagnostic.
    fetch_failed: HashSet<PackageName>,
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
/// * `in_use` - Raw dependency name -> the version this project actually
///   has (lockfile-resolved or a concrete pin), checked against the fetched
///   version list for yank status
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
    in_use: &HashMap<PackageName, String>,
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
    let check_yanked = registry.reports_yanked();

    let results: Vec<_> = stream::iter(package_names)
        .map(|name| {
            let registry = Arc::clone(&registry);
            let fetched = Arc::clone(&fetched);
            let failed = Arc::clone(&failed);
            let first_error = Arc::clone(&first_error);
            let progress_sender = progress_sender.clone();
            let wildcard_req = &wildcard_req;
            let in_use_version = in_use.get(&name).cloned();
            async move {
                // Single round trip: the full version list is fetched once, and "latest"
                // is a pure in-memory pick over it (`Registry::select_latest_matching`) —
                // no second registry call, so the retained full list costs nothing extra
                // over the network (see `PackageVersions`).
                let result = tokio::time::timeout(timeout, registry.get_versions(&name)).await;

                let mut yanked: Option<(PackageName, String)> = None;
                let mut failed_name: Option<PackageName> = None;
                let version = match result {
                    Ok(Ok(versions)) => {
                        let available: Arc<[String]> = versions
                            .iter()
                            .map(|v| v.version_string().to_string())
                            .collect();
                        // Retained alongside `available` so `generate_diagnostics_from_cache`
                        // can flag a requirement satisfiable only by a yanked version — see
                        // `PackageVersions::yanked`. Gated on `check_yanked`: a registry that
                        // cannot answer `is_yanked()` (§#298) must not populate this list with
                        // an untrustworthy always-false signal.
                        let yanked_list: Arc<[String]> = if check_yanked {
                            versions
                                .iter()
                                .filter(|v| v.is_yanked())
                                .map(|v| v.version_string().to_string())
                                .collect()
                        } else {
                            Arc::from([])
                        };
                        // `.get(idx)` rather than `versions[idx]`: `select_latest_matching`
                        // is a public `Registry` trait method, so an out-of-tree
                        // implementation returning a stale index must not panic this task.
                        let resolved = if let Some(v) = registry
                            .select_latest_matching(&versions, wildcard_req)
                            .and_then(|idx| versions.get(idx))
                        {
                            let latest = v.version_string().to_string();
                            tracing::debug!(package = %name, version = %latest, "fetched");
                            Some((latest, v.is_yanked()))
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
                                registry.get_latest_matching(&name, wildcard_req),
                            )
                            .await;
                            match fallback {
                                Ok(Ok(Some(v))) => {
                                    let latest = v.version_string().to_string();
                                    tracing::debug!(
                                        package = %name,
                                        version = %latest,
                                        "fetched via get_latest_matching fallback"
                                    );
                                    Some((latest, v.is_yanked()))
                                }
                                Ok(Ok(None)) => {
                                    tracing::debug!(package = %name, "no version found");
                                    None
                                }
                                Ok(Err(e)) => {
                                    tracing::warn!(
                                        package = %name,
                                        error = %e,
                                        "fetch fallback failed"
                                    );
                                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    let mut fe =
                                        first_error.lock().unwrap_or_else(|p| p.into_inner());
                                    if fe.is_none() {
                                        *fe = Some(e.to_string());
                                    }
                                    drop(fe);
                                    // A genuine not-found (the registry was
                                    // successfully asked and said "no such
                                    // package") is not a fetch failure — only
                                    // an unanswerable request is (#267 C1).
                                    if !e.is_not_found() {
                                        failed_name = Some(name.clone());
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
                                    failed_name = Some(name.clone());
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
                            if let Some((latest, true)) = &resolved {
                                yanked = Some((name.clone(), latest.clone()));
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
                            if let Some(iv) = in_use_version.as_deref()
                                && let Some(found) =
                                    versions.iter().find(|v| v.version_string() == iv)
                                && found.is_yanked()
                            {
                                yanked = Some((name.clone(), iv.to_string()));
                            }
                        }

                        resolved.map(|(latest, _)| {
                            (
                                name.clone(),
                                PackageVersions {
                                    latest,
                                    available,
                                    yanked: yanked_list,
                                },
                            )
                        })
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(package = %name, error = %e, "fetch failed");
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
                            failed_name = Some(name.clone());
                        }
                        None
                    }
                    Err(_) => {
                        tracing::warn!(package = %name, "fetch timed out ({}s)", timeout.as_secs());
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        failed_name = Some(name.clone());
                        None
                    }
                };

                let count = fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(ref sender) = progress_sender {
                    sender.send(count);
                }

                (version, yanked, failed_name)
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    let mut versions = HashMap::with_capacity(results.len());
    let mut yanked_versions = HashMap::new();
    let mut fetch_failed = HashSet::new();
    for (version, yanked, failed_name) in results {
        if let Some((name, v)) = version {
            versions.insert(name, v);
        }
        if let Some((name, v)) = yanked {
            yanked_versions.insert(name, v);
        }
        if let Some(name) = failed_name {
            fetch_failed.insert(name);
        }
    }

    FetchResult {
        versions,
        yanked_versions,
        fetch_failed,
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
    let (cache_config, vulnerabilities_enabled, freshness_settings, diagnostic_severities) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
            cfg.diagnostics.to_severities(),
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

            // Use resolved versions as cached versions for instant display,
            // except for a dependency whose manifest requirement is itself
            // already the resolved version (Go's `require` lines) — for
            // those, go.sum can hold a stale, no-longer-selected version
            // (#235), so seeding it as the "latest" comparison operand would
            // desync hover/inlay-hint status against the go.mod-accurate
            // `resolved` value during the cold-open window before the
            // registry fetch completes (critique S1).
            let formatter = ecosystem_clone.formatter();
            let instant_resolved: HashMap<PackageName, String> = match doc.parse_result() {
                Some(parse_result) => {
                    let deps = parse_result.dependencies();
                    resolved_versions
                        .iter()
                        .filter(|(name, _)| {
                            deps.iter().find(|d| d.name() == *name).is_none_or(|d| {
                                !formatter.manifest_requirement_is_resolved_version(*d)
                            })
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
            tokio::spawn(run_osv_scan_phase_a(
                uri_clone.clone(),
                Arc::clone(&state_clone),
                Arc::clone(&ecosystem_clone),
                cache_config.fetch_timeout_secs,
            ))
        });

        // Collect dependency names and the in-use-version map (§4.6) in one
        // pass while holding the reference (can't hold across await).
        let (dep_names, in_use): (Vec<PackageName>, HashMap<PackageName, String>) = {
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
            let dep_names = parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().clone())
                .collect();
            let in_use = collect_in_use_versions(
                parse_result,
                &resolved_versions,
                ecosystem_clone.formatter(),
                resolve_ecosystem_id(ecosystem_clone.as_ref()),
            );
            (dep_names, in_use)
        };

        tracing::debug!(count = dep_names.len(), "starting registry fetch");

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = if state_clone.supports_progress() {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                RegistryProgress::start(client_clone.clone(), uri_clone.as_str(), dep_names.len()),
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
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            dep_names,
            &in_use,
            progress_sender,
            cache_config.fetch_timeout_secs,
            cache_config.max_concurrent_fetches,
        )
        .await;

        let success = !fetch_result.versions.is_empty();
        tracing::debug!(
            fetched = fetch_result.versions.len(),
            failed = fetch_result.failed_count,
            yanked = fetch_result.yanked_versions.len(),
            "registry fetch complete"
        );

        // Update document state with cached versions (latest from registry)
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.update_cached_versions(fetch_result.versions);
            // Re-key raw -> normalized (§3.1): `FetchResult::yanked_versions`
            // is raw-keyed, `DocumentState::yanked_versions` is normalized.
            let formatter = ecosystem_clone.formatter();
            doc.update_yanked_versions(
                fetch_result
                    .yanked_versions
                    .into_iter()
                    .map(|(name, v)| (formatter.normalize_package_name(&name), v))
                    .collect(),
            );
            doc.update_fetch_failed(
                fetch_result
                    .fetch_failed
                    .into_iter()
                    .map(|name| formatter.normalize_package_name(&name))
                    .collect(),
            );
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
                        ecosystem_clone.formatter(),
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
            diagnostic_severities,
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
        doc_state
            .yanked_versions
            .remove(&formatter.normalize_package_name(removed_dep));
        doc_state
            .fetch_failed
            .remove(&formatter.normalize_package_name(removed_dep));
    }

    // A version-only edit (name unchanged, requirement changed) invalidates
    // any yanked finding recorded against the dependency's *old* version —
    // e.g. editing a yanked pin to a safe one must not leave a stale
    // diagnostic anchored on the new range (security F1 / impl-critic S1).
    // Drop rather than try to refresh in place; the registry re-fetch below
    // (`deps_to_fetch` includes `version_changed`) repopulates the entry if
    // the *new* version also turns out to be yanked. Same for `fetch_failed`
    // (#267): a stale fetch-error marker must not survive an edit that gets
    // re-fetched below.
    for changed_dep in &diff.version_changed {
        doc_state
            .yanked_versions
            .remove(&formatter.normalize_package_name(changed_dep));
        doc_state
            .fetch_failed
            .remove(&formatter.normalize_package_name(changed_dep));
    }

    state.update_document(uri.clone(), doc_state);

    // Clone cache, diagnostics, and freshness config before spawning background task
    // (all read here, before any OSV request is built — FR-011).
    let (cache_config, vulnerabilities_enabled, freshness_settings, diagnostic_severities) = {
        let cfg = config.read().await;
        (
            cfg.cache.clone(),
            cfg.diagnostics.vulnerabilities_enabled,
            cfg.freshness.to_settings(),
            cfg.diagnostics.to_severities(),
        )
    };

    // Spawn background task to update diagnostics
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let client_clone = client.clone();
    let needs_osv_rescan = diff.needs_osv_rescan();
    // The yanked probe must also re-run for a version-only edit, not just a
    // newly added dependency — otherwise editing a dependency's pin from a
    // safe version to a yanked one would never be checked, since an empty
    // `deps_to_fetch` skips the entire registry fetch below (security F1).
    let mut deps_to_fetch = diff.added;
    deps_to_fetch.extend(diff.version_changed);

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

        // Skip registry fetch if nothing new was added and no existing
        // dependency's version changed.
        if deps_to_fetch.is_empty() {
            tracing::debug!("no added or version-changed dependencies, skipping registry fetch");

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
                            ecosystem_clone.formatter(),
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
                diagnostic_severities,
            )
            .await;
            client_clone
                .publish_diagnostics(uri_clone.clone(), diags, None)
                .await;
            return;
        }

        tracing::info!(
            count = deps_to_fetch.len(),
            "fetching versions for added/version-changed dependencies"
        );

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = if state_clone.supports_progress() {
            match tokio::time::timeout(
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
            }
        } else {
            (None, None)
        };

        // Build the in-use-version map (§4.6) from the freshly-committed parse
        // result and the resolved versions just loaded above.
        let in_use: HashMap<PackageName, String> = match state_clone.get_document(&uri_clone) {
            Some(doc) => match doc.parse_result() {
                Some(pr) => collect_in_use_versions(
                    pr,
                    &resolved_versions,
                    ecosystem_clone.formatter(),
                    resolve_ecosystem_id(ecosystem_clone.as_ref()),
                ),
                None => HashMap::new(),
            },
            None => HashMap::new(),
        };

        // Fetch latest versions only for NEW dependencies
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            deps_to_fetch,
            &in_use,
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
            // Re-key raw -> normalized (§3.1), same as the didOpen path.
            let formatter = ecosystem_clone.formatter();
            for (name, version) in fetch_result.yanked_versions {
                doc.yanked_versions
                    .insert(formatter.normalize_package_name(&name), version);
            }
            for name in fetch_result.fetch_failed {
                doc.fetch_failed
                    .insert(formatter.normalize_package_name(&name));
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
                        ecosystem_clone.formatter(),
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
            diagnostic_severities,
        )
        .await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;
    });

    Ok(task)
}

/// Builds a `cached_versions` map from lock-file-resolved versions, ahead of any registry
/// fetch.
///
/// `available` is deliberately left empty (`PackageVersions::latest_without_list`, not a
/// plausible-looking one-element list) — this runs before any registry fetch, and
/// `requirement_is_unsatisfiable` treats an empty `available` as "still loading, skip"
/// (FR-004). Using `latest_only` here instead would populate a bogus single-entry list and
/// let the unsatisfiable-requirement check compute a false verdict on every document open,
/// before the fetch that's supposed to suppress it has a chance to run.
fn cached_versions_from_lockfile(
    resolved: &HashMap<PackageName, String>,
) -> HashMap<PackageName, PackageVersions> {
    resolved
        .iter()
        .map(|(name, version)| {
            (
                name.clone(),
                PackageVersions::latest_without_list(version.clone()),
            )
        })
        .collect()
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

    /// N5 regression guard: the lock-file-population path must build every
    /// `PackageVersions` with an **empty** `available` list, never a populated one — an
    /// empty `available` is what makes `requirement_is_unsatisfiable`'s FR-004 guard
    /// suppress the check before any registry fetch has run. This is the exact function
    /// `handle_document_open`'s background task calls, so a regression here (e.g.
    /// swapping `latest_without_list` for `latest_only`) is caught directly, without
    /// racing the background task.
    #[test]
    fn test_cached_versions_from_lockfile_has_empty_available() {
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("serde"), "1.0.195".to_string());
        resolved.insert(PackageName::new("tokio"), "1.35.0".to_string());

        let cached = cached_versions_from_lockfile(&resolved);

        assert_eq!(cached.len(), 2);
        let serde = cached.get(&PackageName::new("serde")).unwrap();
        assert_eq!(serde.latest, "1.0.195");
        assert!(
            serde.available.is_empty(),
            "lock-file-populated entries must have an empty available list, got: {:?}",
            serde.available
        );
        let tokio = cached.get(&PackageName::new("tokio")).unwrap();
        assert_eq!(tokio.latest, "1.35.0");
        assert!(tokio.available.is_empty());
    }

    #[test]
    fn test_cached_versions_from_lockfile_empty_input_is_empty_output() {
        let resolved = HashMap::new();
        assert!(cached_versions_from_lockfile(&resolved).is_empty());
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
        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 1, 10).await;

        // Should return empty (timeout, not success)
        assert!(result.versions.is_empty(), "Slow package should timeout");
        assert_eq!(result.failed_count, 1, "Should track 1 failed package");
        // #267: a timeout is also a fetch failure, not a "not found" — must
        // be recorded the same way as a hard registry error.
        assert_eq!(
            result.fetch_failed,
            HashSet::from([PackageName::new("slow-package")]),
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
        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 1, 10).await;
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

        fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 20).await;

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
        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 1, 10).await;

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
            version: String,
            yanked: bool,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &str {
                &self.version
            }
            fn is_yanked(&self) -> bool {
                self.yanked
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
                            version: "1.0.214".to_string(),
                            yanked: false,
                        }) as Box<dyn Version>,
                        Box::new(MockVersion {
                            version: "1.0.213".to_string(),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn select_latest_matching(
                &self,
                versions: &[Box<dyn Version>],
                _req: &deps_core::VersionReq,
            ) -> Option<usize> {
                versions.iter().position(|v| !v.is_yanked())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(YankedRegistry);
        let packages = vec![PackageName::new("serde")];

        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 10, 10).await;

        let serde = result
            .versions
            .get("serde")
            .expect("serde should be fetched");
        assert_eq!(serde.latest, "1.0.214", "latest must skip the yanked entry");
        assert_eq!(
            &*serde.available,
            &["1.0.214".to_string(), "1.0.213".to_string()],
            "available must remain unfiltered"
        );
        assert_eq!(
            &*serde.yanked,
            &["1.0.213".to_string()],
            "yanked must carry only the entries reported as yanked"
        );
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
            version: String,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &str {
                &self.version
            }
            fn is_yanked(&self) -> bool {
                false
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
                        version: "v0.0.0-20191109021931-daa7c04131f5".to_string(),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(UntaggedModuleRegistry);
        let packages = vec![PackageName::new("golang.org/x/exp")];

        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 10).await;

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
        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 10).await;

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
            HashSet::from([
                PackageName::new("package-1"),
                PackageName::new("package-2"),
                PackageName::new("package-3"),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(NotFoundRegistry);
        let packages = vec![PackageName::new("typo-pkg")];

        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 10).await;

        assert!(result.versions.is_empty());
        assert!(
            result.fetch_failed.is_empty(),
            "a genuine not-found must not be recorded in fetch_failed, or \
             generate_diagnostics_from_cache would report it as a registry \
             error instead of Unknown package"
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
                        url: format!("https://example.com/{name}"),
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
                        url: format!("https://example.com/{name}"),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(Http404Registry);
        let packages = vec![PackageName::new("typo-pkg")];

        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 10).await;

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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(FallbackErrorRegistry);
        let packages = vec![PackageName::new("flaky"), PackageName::new("not-found")];

        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 5, 10).await;

        assert!(result.versions.is_empty());
        assert_eq!(
            result.fetch_failed,
            HashSet::from([PackageName::new("flaky")]),
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

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(FallbackTimeoutRegistry);
        let packages = vec![PackageName::new("slow-fallback")];

        // 1s timeout for test speed.
        let result =
            fetch_latest_versions_parallel(registry, packages, &HashMap::new(), None, 1, 10).await;

        assert!(result.versions.is_empty());
        assert_eq!(
            result.fetch_failed,
            HashSet::from([PackageName::new("slow-fallback")])
        );
        assert_eq!(result.failed_count, 1);
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
            version: String,
            yanked: bool,
        }

        impl Version for MockYankVersion {
            fn version_string(&self) -> &str {
                &self.version
            }
            fn is_yanked(&self) -> bool {
                self.yanked
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
                        version: "9.9.9".to_string(),
                        yanked: false,
                    }) as Box<dyn Version>,
                    Box::new(MockYankVersion {
                        version: self.pinned_version.to_string(),
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
                    version: "9.9.9".to_string(),
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

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pypi.org/project/{name}")
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
            HashMap<String, String>,
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
                formatter,
                EcosystemId::Pypi,
            );
            // Sanity check on the fix this guard exists for: the pep440
            // `==` comparator must already be stripped here.
            assert_eq!(
                in_use.get(&PackageName::new(raw_name)),
                Some(&pinned_version.to_string())
            );

            let registry: Arc<dyn Registry> = Arc::new(MockYankedRegistry { pinned_version });
            let fetch_result =
                fetch_latest_versions_parallel(registry, dep_names, &in_use, None, 5, 10).await;

            let yanked_versions: HashMap<String, String> = fetch_result
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
            doc_state.update_yanked_versions(yanked_versions.clone());
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            let diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                doc.parse_result().unwrap(),
                VersionData::new(&doc.cached_versions, &doc.resolved_versions)
                    .with_yanked(&doc.yanked_versions),
                formatter,
                deps_core::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
            );

            (diagnostics, yanked_versions)
        }

        #[tokio::test]
        async fn typing_extensions_underscore_name_resolves_via_normalized_key() {
            let (diagnostics, yanked_versions) = run_pipeline("typing_extensions", "4.9.0").await;

            assert_eq!(
                yanked_versions.get("typing-extensions"),
                Some(&"4.9.0".to_string()),
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
                Some(&"5.0.0".to_string()),
                "must be keyed by the normalized (dotted -> dash) name"
            );
            assert!(
                diagnostics.iter().any(|d| d.message.contains("5.0.0")),
                "yanked diagnostic must reach the generated output: {diagnostics:?}"
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
                Some(&"v1.8.1".to_string()),
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
                    .insert("serde".into(), PackageVersions::latest_only("1.0.210"));
                doc.cached_versions
                    .insert("tokio".into(), PackageVersions::latest_only("1.40.0"));
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
                    doc.cached_versions.get("serde").map(|v| v.latest.as_str()),
                    Some("1.0.210"),
                    "serde cache preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("tokio").map(|v| v.latest.as_str()),
                    Some("1.40.0"),
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
        async fn test_preserve_cache_carries_yanked_versions_across_edit() {
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

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_yanked_versions(HashMap::from([(
                    "time".to_string(),
                    "0.1.43".to_string(),
                )]));
            }

            // A whitespace-only edit: DocumentState is rebuilt from scratch,
            // which would silently flicker the yanked diagnostic off on
            // every keystroke without preserve_cache carrying it through.
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
            assert_eq!(doc.yanked_versions.get("time"), Some(&"0.1.43".to_string()));
        }

        #[tokio::test]
        async fn test_yanked_versions_pruned_on_dependency_removal_by_normalized_name() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
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

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_yanked_versions(HashMap::from([(
                    "time".to_string(),
                    "0.1.43".to_string(),
                )]));
            }

            let content2 = r#"[dependencies]
serde = "1.0"
"#;
            let old_deps: HashMap<PackageName, Option<VersionReq>> =
                [("serde", None), ("time", None)]
                    .into_iter()
                    .map(|(n, r)| (PackageName::new(n), r))
                    .collect();
            let new_deps: HashMap<PackageName, Option<VersionReq>> =
                std::iter::once((PackageName::new("serde"), None)).collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for removed_dep in &diff.removed {
                doc_state2
                    .yanked_versions
                    .remove(&formatter.normalize_package_name(removed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                !doc.yanked_versions.contains_key("time"),
                "removed dependency's yanked entry must be pruned"
            );
        }

        #[tokio::test]
        async fn test_yanked_versions_pruned_on_version_change_by_normalized_name() {
            // Security F1 / impl-critic S1 (false positive direction):
            // editing a dependency from a yanked pin to a safe one, with no
            // lock file, must not leave the stale yanked diagnostic
            // anchored on the new version's range. Editing in place (not
            // add+remove) means the pruning loop for `diff.removed` alone
            // would miss this — the name never leaves `diff.removed`, it's
            // in `diff.version_changed` instead.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "=0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // `time` was found yanked at its old pin, "=0.1.43".
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_yanked_versions(HashMap::from([(
                    "time".to_string(),
                    "0.1.43".to_string(),
                )]));
            }

            // Edited to a different, safe pin — same dependency, in place.
            let content2 = r#"[dependencies]
time = "=0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for changed_dep in &diff.version_changed {
                doc_state2
                    .yanked_versions
                    .remove(&formatter.normalize_package_name(changed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                !doc.yanked_versions.contains_key("time"),
                "stale yanked entry against the OLD version must not survive an in-place edit"
            );
        }

        #[tokio::test]
        async fn test_fetch_failed_pruned_on_dependency_removal_by_normalized_name() {
            // Mirrors `test_yanked_versions_pruned_on_dependency_removal_by_normalized_name`
            // for `fetch_failed` (#267): a stale fetch-error marker for a
            // dependency the user has since deleted must not linger.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
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

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_fetch_failed(HashSet::from(["time".to_string()]));
            }

            let content2 = r#"[dependencies]
serde = "1.0"
"#;
            let old_deps: HashMap<PackageName, Option<VersionReq>> =
                [("serde", None), ("time", None)]
                    .into_iter()
                    .map(|(n, r)| (PackageName::new(n), r))
                    .collect();
            let new_deps: HashMap<PackageName, Option<VersionReq>> =
                std::iter::once((PackageName::new("serde"), None)).collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            // Preserved before pruning: proves `preserve_cache` itself
            // carries `fetch_failed` across the edit, not just the final
            // (already-pruned) state below.
            assert!(
                doc_state2.fetch_failed.contains("time"),
                "preserve_cache must carry fetch_failed across an edit"
            );

            let formatter = ecosystem.formatter();
            for removed_dep in &diff.removed {
                doc_state2
                    .fetch_failed
                    .remove(&formatter.normalize_package_name(removed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                !doc.fetch_failed.contains("time"),
                "removed dependency's fetch_failed entry must be pruned"
            );
        }

        #[test]
        fn test_deps_to_fetch_includes_version_changed_dependencies() {
            // Security F1 (false negative direction): editing a dependency
            // from a safe pin to a yanked one, with no lock file, must
            // still trigger the registry fetch (and therefore the probe) —
            // otherwise the yanked pin is never checked at all, since
            // `deps_to_fetch.is_empty()` would skip the fetch entirely if
            // it only ever contained `diff.added`.
            let old = versions(&[("time", Some("=0.1.44"))]);
            let new = versions(&[("time", Some("=0.1.43"))]);

            let diff = DependencyDiff::compute(&old, &new);
            assert!(diff.added.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);
            assert!(
                diff.needs_fetch(),
                "a version-only edit must trigger the registry fetch"
            );

            // Mirrors the production construction at the `deps_to_fetch`
            // site in `handle_document_change`.
            let mut deps_to_fetch = diff.added;
            deps_to_fetch.extend(diff.version_changed);
            assert_eq!(
                deps_to_fetch,
                vec![PackageName::new("time")],
                "the version-changed dependency must be included in the fetch list"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_yanked_versions_stale_after_lockfile_only_change() {
            // R3 (accepted, not fixed): the yanked map is computed during the
            // registry fetch. A didChange that adds no dependencies skips the
            // fetch entirely, so `preserve_cache` carries the *old* yanked
            // map forward verbatim even if a lockfile edited underneath (e.g.
            // `cargo update` pulling in a newly-yanked release) would have
            // changed the answer. This documents the existing behavior,
            // identical to `cached_versions`' staleness.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Stale: `time` was yanked as of the last fetch.
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_yanked_versions(HashMap::from([(
                    "time".to_string(),
                    "0.1.43".to_string(),
                )]));
            }

            // Identical manifest content re-parsed (as happens on a
            // didChangeWatchedFiles-less lockfile edit that doesn't touch the
            // manifest text) — no dependency added or removed, so the real
            // handler would skip the registry fetch and never re-run the
            // yanked probe.
            let parse_result2 = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result2,
            );
            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            // The stale entry survives verbatim — even if `time` were
            // un-yanked (or a different version newly yanked) in the
            // lockfile in the meantime, nothing here would know.
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.yanked_versions.get("time"), Some(&"0.1.43".to_string()));
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
                    .insert("serde".into(), PackageVersions::latest_only("1.0.210"));
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
                doc.cached_versions.get("serde").map(|v| v.latest.as_str()),
                Some("1.0.210")
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
            assert!(
                diff.needs_fetch(),
                "a version-only edit must still trigger the registry fetch, \
                 so the yanked probe re-runs against the new version"
            );
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
                doc.cached_versions.insert(
                    PackageName::new("serde"),
                    PackageVersions::latest_only("1.0.210"),
                );
                doc.cached_versions.insert(
                    PackageName::new("tokio"),
                    PackageVersions::latest_only("1.40.0"),
                );
                doc.cached_versions.insert(
                    PackageName::new("anyhow"),
                    PackageVersions::latest_only("1.0.89"),
                );
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
            // Composer's implicit range notations. Deno reuses npm's exact
            // grammar for both `jsr:` and `npm:` requirements, so it gets the
            // same treatment (`bare_version_is_a_range`'s doc comment).
            for eco in [
                EcosystemId::Cargo,
                EcosystemId::Npm,
                EcosystemId::Composer,
                EcosystemId::Deno,
            ] {
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

        /// Formatter stub mirroring `GoFormatter`'s override: every
        /// dependency's manifest requirement is itself the resolved version
        /// (#235's `manifest_requirement_is_resolved_version` unification).
        struct MockGoFormatter;
        impl EcosystemFormatter for MockGoFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pkg.go.dev/{name}")
            }
            fn manifest_requirement_is_resolved_version(&self, _dep: &dyn Dependency) -> bool {
                true
            }
        }

        struct MockVPrefixFormatter;
        impl EcosystemFormatter for MockVPrefixFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn osv_version(&self, version: &str) -> String {
                version.strip_prefix('v').unwrap_or(version).to_string()
            }
        }

        #[test]
        fn build_scan_targets_normalizes_version_via_formatter_osv_version_hook() {
            // Go module versions carry a mandatory "v" prefix that OSV's
            // SEMVER range matching forbids (#228) — build_scan_targets must
            // route the resolved version through the formatter hook rather
            // than sending the native spelling on the wire.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/gin-gonic/gin"),
                    version_req: Some(VersionReq::new("v1.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(
                PackageName::new("github.com/gin-gonic/gin"),
                "v1.9.0".to_string(),
            );

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &MockVPrefixFormatter,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.9.0");
            // display_version keeps the ecosystem-native "v" spelling (S1
            // regression guard) — only the wire-format `version` is stripped.
            assert_eq!(targets[0].display_version, "v1.9.0");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_leaves_version_unaffected_for_default_identity_formatter() {
            // Regression guard: ecosystems that do not override osv_version
            // must keep sending the native spelling verbatim (no regression
            // from introducing the hook).
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
            assert_eq!(targets[0].display_version, "1.0.195");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_go_ignores_stale_lockfile_version_uses_go_mod_requirement() {
            // go.sum is a checksum ledger that `go get`/`go build` only ever
            // append to — a stale, no-longer-selected higher version can
            // remain recorded there after a downgrade (only `go mod tidy`
            // prunes it), and since go.sum is written sorted ascending by
            // semver, that stale entry always sorts last and wins
            // last-occurrence-wins parsing. Unlike Cargo/npm, go.mod's
            // `require` line is already an exact pinned version, so for Go
            // the manifest itself — not the lockfile-derived
            // `resolved_versions` — must be authoritative for OSV scanning.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/pkg/errors"),
                    version_req: Some(VersionReq::new("v0.8.1")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            // Stale entry: go.sum still records v0.9.1 from before a
            // downgrade back to v0.8.1 that only `go get` (not `go mod
            // tidy`) performed.
            resolved.insert(
                PackageName::new("github.com/pkg/errors"),
                "v0.9.1".to_string(),
            );

            let (targets, skipped) =
                build_scan_targets(&parse_result, &resolved, &MockGoFormatter, EcosystemId::Go);
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "v0.8.1");
            assert_eq!(targets[0].display_version, "v0.8.1");
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
        fn build_scan_targets_step2_strips_pin_marker_for_operator_prefixed_requirements() {
            // impl-critic M2: the `concrete_pin_version` fix (originally
            // scoped to the PyPI `==` case) also strips Cargo's `=` and
            // NuGet's `[..]` exact-pin markers, since both callers share the
            // same helper — a strict improvement over the old verbatim
            // `"=1.2.3"`/`"[1.0.0]"` OSV scan targets, which would never
            // have matched a real advisory's affected-version range anyway.
            let cargo_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("=1.2.3")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &cargo_result,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.2.3");
            assert!(skipped.is_empty());

            let nuget_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("Newtonsoft.Json"),
                    version_req: Some(VersionReq::new("[1.0.0]")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &nuget_result,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::NuGet,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.0");
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

        // `collect_in_use_versions` (§4.6) reuses the same `in_use_version`
        // ladder as `build_scan_targets` above, plus its own step-0 filter —
        // these tests exercise that reuse directly.

        #[test]
        fn collect_in_use_versions_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".to_string());

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("serde")),
                Some(&"1.0.195".to_string())
            );
        }

        #[test]
        fn collect_in_use_versions_concrete_pin_without_lockfile() {
            // Closes the former R4 gap: an exact pin with no lock file must
            // still produce an in-use version for the yanked probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &MockFormatter,
                EcosystemId::Maven,
            );
            assert_eq!(
                in_use.get(&PackageName::new("log4j-core")),
                Some(&"2.14.1".to_string())
            );
        }

        #[test]
        fn concrete_pin_version_strips_pep440_double_equals_comparator() {
            // Regression guard: PyPI's parser retains the pep440 comparator
            // in `version_requirement().as_str()` (`"==4.9.0"`, not
            // `"4.9.0"` — confirmed by deps-pypi's `test_basic_pinned`). The
            // verbatim string was silently unusable against real registry
            // version strings in the yanked probe; `concrete_pin_version`
            // must strip it.
            assert_eq!(
                concrete_pin_version("==4.9.0", EcosystemId::Pypi),
                Some("4.9.0")
            );
        }

        #[test]
        fn concrete_pin_version_strips_single_equals_and_bracket_pins() {
            assert_eq!(
                concrete_pin_version("=1.2.3", EcosystemId::Cargo),
                Some("1.2.3")
            );
            assert_eq!(
                concrete_pin_version("[1.0.0]", EcosystemId::NuGet),
                Some("1.0.0")
            );
        }

        #[test]
        fn concrete_pin_version_bare_version_returned_verbatim() {
            // No operator to strip: Maven/Go/Bundler/Dart/Gradle/NuGet treat
            // a bare version as already exact.
            assert_eq!(
                concrete_pin_version("2.14.1", EcosystemId::Maven),
                Some("2.14.1")
            );
        }

        #[test]
        fn concrete_pin_version_rejects_ranges_and_partials() {
            assert_eq!(concrete_pin_version("^1.0", EcosystemId::Cargo), None);
            assert_eq!(concrete_pin_version("1.2.3", EcosystemId::Cargo), None);
            assert_eq!(concrete_pin_version(">=1.0,<2.0", EcosystemId::Pypi), None);
        }

        #[test]
        fn collect_in_use_versions_strips_pep440_double_equals_pin_for_pypi() {
            // The scenario the plan's R4 closure claim actually targets:
            // a PyPI `requirements.txt`-style `==` exact pin with no lock
            // file. `in_use.get(..)` must be the bare `"4.9.0"` so it can
            // ever match a real registry version string during the probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("typing_extensions"),
                    version_req: Some(VersionReq::new("==4.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &MockFormatter,
                EcosystemId::Pypi,
            );
            assert_eq!(
                in_use.get(&PackageName::new("typing_extensions")),
                Some(&"4.9.0".to_string()),
                "pep440 '==' comparator must be stripped, not carried into the in-use version"
            );
        }

        #[test]
        fn collect_in_use_versions_skips_non_concrete_requirement_with_no_lockfile() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_excludes_non_registry_source_even_with_lockfile_version() {
            // Step 0 (§4.5): a patched git/path fork must never be flagged
            // for a registry version it does not contain.
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

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }
    }

    mod yanked_check_tests {
        use super::*;
        use deps_core::{Metadata, Version};
        use std::any::Any;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug, Clone)]
        struct MockYankVersion {
            version: String,
            yanked: bool,
        }

        impl Version for MockYankVersion {
            fn version_string(&self) -> &str {
                &self.version
            }
            fn is_yanked(&self) -> bool {
                self.yanked
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
                                    version: (*v).to_string(),
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
                versions.iter().position(|v| !v.is_yanked())
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
                            version: v.to_string(),
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

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
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
            // `reports_yanked() == false` means `is_yanked()` must never be
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
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
                vec![PackageName::new("pkg")],
                &HashMap::new(),
                None,
                5,
                10,
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
            )
            .await;

            assert_eq!(fetch_calls.load(Ordering::Relaxed), 1);
            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&"1.0.0".to_string())
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
            )
            .await;

            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&"1.0.0".to_string())
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
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
                Some(&"1.0.0".to_string())
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
                vec![PackageName::new("pkg")],
                &HashMap::new(),
                None,
                5,
                10,
            )
            .await;

            assert_eq!(
                result.yanked_versions.get(&PackageName::new("pkg")),
                Some(&"1.0.0".to_string())
            );
        }

        #[tokio::test]
        async fn latest_is_yanked_not_recorded_when_reports_yanked_false() {
            // impl-critic M1: row 1 must respect the same `reports_yanked()`
            // gate as the in-memory in-use check. Harmless today only
            // because every opt-out registry also hardcodes `is_yanked` to
            // `false` — this guards against a follow-up (§8.2/§8.3) making
            // an opt-out registry's `is_yanked()` real without also
            // flipping `reports_yanked()`, which would otherwise silently
            // reintroduce a #233-class bug through this exact row.
            let registry: Arc<dyn Registry> = Arc::new(MockRegistry {
                reports_yanked: false,
                versions: HashMap::from([("pkg", FetchOutcome::Versions(vec![("1.0.0", true)]))]),
                latest_fallback: HashMap::from([("pkg", ("1.0.0", true))]),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
            });

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &HashMap::new(),
                None,
                5,
                10,
            )
            .await;

            assert!(
                result.yanked_versions.is_empty(),
                "a `reports_yanked() == false` registry's `is_yanked()` must never be trusted, \
                 even on the zero-cost row-1 path"
            );
            assert!(
                result
                    .versions
                    .get(&PackageName::new("pkg"))
                    .expect("pkg was fetched")
                    .yanked
                    .is_empty(),
                "`PackageVersions::yanked` must stay empty for a `reports_yanked() == false` \
                 registry, even though the fetched version is itself flagged `is_yanked`"
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                5,
                10,
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
            in_use.insert(PackageName::new("pkg"), "1.0.0".to_string());

            // 1 second timeout for test speed.
            let result = fetch_latest_versions_parallel(
                registry,
                vec![PackageName::new("pkg")],
                &in_use,
                None,
                1,
                10,
            )
            .await;

            assert!(result.yanked_versions.is_empty());
            assert_eq!(result.failed_count, 1);
            assert!(result.versions.is_empty());
        }
    }
}
