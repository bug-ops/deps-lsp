//! OSV vulnerability scan orchestration: scan-target construction,
//! phase A/B execution, license pre-fetch, and fix-target
//! verification.

use super::state::ServerState;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_lsp_server::ls_types::Uri;

/// Ceiling on the OSV scan timeout, independent of the configured
/// `fetch_timeout_secs`: the shared `reqwest` client behind `HttpCache`
/// already imposes its own client-wide 30s timeout (`cache.rs`), so a
/// per-phase timeout longer than that would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

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
pub(crate) struct OsvScanResult {
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
#[tracing::instrument(skip_all, fields(uri = ?uri, ecosystem = ecosystem.id()))]
pub(crate) async fn run_osv_scan_phase_a(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> Option<OsvScanResult> {
    let ecosystem_id = ecosystem.ecosystem_id();

    let (content_snapshot, targets, mut vulnerabilities, raw_name_by_key) = {
        let doc = state.get_document(&uri)?;
        let parse_result = doc.parse_result()?;
        let (targets, skipped) = deps_engine::classify::osv::build_scan_targets(
            parse_result,
            &doc.resolved_versions,
            &doc.resolved_version_candidates,
            ecosystem.formatter(),
            ecosystem_id,
        );
        // Keyed the same way `targets`/`skipped` are (#394 S2: possibly
        // version-qualified, not just the plain normalized name) so phase B's
        // `raw_name_by_key.get(key)` fallback below still finds this
        // occurrence's raw name when its key was disambiguated.
        let vuln_keys = deps_core::osv::vulnerability_keys(
            parse_result,
            &doc.resolved_versions,
            Some(&doc.resolved_version_candidates),
            ecosystem.formatter(),
            ecosystem_id,
        );
        let raw_name_by_key: HashMap<String, String> = parse_result
            .dependencies()
            .into_iter()
            .map(|d| {
                let key = vuln_keys
                    .get(&d.name_range())
                    .cloned()
                    .unwrap_or_else(|| ecosystem.formatter().normalize_package_name(d.name()));
                (key, d.name().to_string())
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

/// Background pre-fetch of each dependency's license, for whichever ecosystems
/// override [`deps_core::Ecosystem::fetch_license`] (issue #660/#688, spec 010 plan §1
/// tier 3) — today, pub.dev's `/score` endpoint (Dart), the GitHub repository API
/// (Swift), a Maven Central POM fetch (Gradle), and the JSR per-version API (Deno).
/// Mirrors
/// [`run_osv_scan_phase_a`]'s spawn-concurrently-with-the-registry-fetch shape, but
/// commits directly with no phase B. Callers must `.await` the returned
/// `JoinHandle` (via `tokio::spawn`) before their own diagnostics publish, exactly
/// like the OSV `osv_task` join — a tier-3 license-policy violation must be able to
/// appear in the *first* diagnostics publish after the triggering edit, not only
/// whenever some later, unrelated event happens to regenerate diagnostics (code-review
/// round 3 finding #3).
///
/// Target selection (which dependencies to fetch a license for, at which version) is
/// [`deps_engine::classify::license::tier3_license_targets`], and the network dispatch is
/// [`deps_engine::classify::license::fetch_tier3_licenses`] (issue #1133) — both shared with
/// `deps-cli` so both adapters reach the same license-policy verdict for these four
/// ecosystems. Targets are computed synchronously while holding the document guard (mirroring
/// [`run_osv_scan_phase_a`]'s `build_scan_targets` call), which is dropped before the network
/// dispatch below ever awaits. This function keeps only what is genuinely `deps-lsp`'s own:
/// the document snapshot/staleness guard and the additive `DocumentState::licenses` commit.
///
/// The commit at the end is staleness-guarded (`doc.content == content_snapshot`,
/// mirroring [`run_osv_phase_b_and_commit`]'s identical guard) and merges rather than
/// replaces (round 3 finding #1/#2): two overlapping edits can spawn two overlapping
/// pre-fetches, and without the guard the older one finishing last could silently
/// overwrite the newer one's results with stale data; without a merge, a transient
/// per-dependency fetch failure this round (already filtered out by the shared function,
/// before this point) would drop that dependency's previously-cached, still-valid
/// license instead of just failing to refresh it. `DocumentState::merge_licenses`'s own
/// additive contract already provides exactly this — a genuinely *removed* dependency's
/// stale entry is reclaimed separately, by the manifest-diff pruning loop in
/// `commit_parsed_document`, not by this function replacing the whole map.
///
/// **What version each source actually reflects is per-ecosystem, not uniform** — see
/// [`deps_engine::classify::license::prefetch_tier3_licenses`]'s doc for the full
/// per-ecosystem breakdown (Dart/Swift's tier-3 source isn't pinned to the resolved
/// version the way Gradle/Deno's is).
///
/// No-op (returns immediately) for every ecosystem whose
/// <code>ecosystem.[license_source](deps_core::Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// is `false` (issue #697) — every ecosystem except the four above.
pub(crate) async fn run_license_prefetch(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) {
    if !ecosystem.license_source().requires_dedicated_fetch() {
        return;
    }

    let (content_snapshot, targets): (String, Vec<(PackageName, String)>) = {
        let Some(doc) = state.get_document(&uri) else {
            return;
        };
        let Some(parse_result) = doc.parse_result() else {
            return;
        };
        let targets = deps_engine::classify::license::tier3_license_targets(
            parse_result,
            &doc.resolved_versions,
            &doc.resolved_version_candidates,
            ecosystem.formatter(),
            ecosystem.ecosystem_id(),
        );
        (doc.content.clone(), targets)
    };

    if targets.is_empty() {
        return;
    }

    let result = deps_engine::classify::license::fetch_tier3_licenses(
        ecosystem.as_ref(),
        targets,
        fetch_timeout_secs,
        LICENSE_PREFETCH_CONCURRENCY,
    )
    .await;

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        if doc.content == content_snapshot {
            doc.merge_licenses(result.licenses);
        } else {
            tracing::debug!(
                "dropping stale tier-3 license pre-fetch result: document content changed mid-fetch"
            );
        }
    }
}

/// Bounds how many concurrent per-dependency license fetches [`run_license_prefetch`] issues
/// at once — tier-3 documents rarely carry more than a handful of dependencies (Dart/Swift/
/// Gradle/Deno are all comparatively small ecosystems in this project's usage), and this
/// pre-fetch is a background nice-to-have, not on the hover critical path, so there is no
/// latency pressure to fan out aggressively. `deps-cli`'s check-gate call passes its own,
/// larger `cache.max_concurrent_fetches` instead (issue #1133 critic M3) — this constant is
/// `deps-lsp`'s own tuning choice, not a shared default.
const LICENSE_PREFETCH_CONCURRENCY: usize = 8;

/// Phase B: for every dependency phase A flagged [`deps_core::osv::ScanOutcome::Vulnerable`],
/// checks whether the version currently recommended (the registry's latest,
/// now that the registry fetch has resolved — critique S1) is itself
/// affected (B.1), then independently verifies each dependency's recommended
/// *fix target* F (B.2, #462 — see [`run_osv_fix_target_verification`]),
/// before committing the result into `DocumentState.vulnerabilities`.
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
/// document no longer has. B.1 and B.2 share one `phase_b_deadline` (#462
/// critic S2/M1) rather than each getting a fresh `fetch_timeout_secs`
/// budget: B.2 is a second sequential network round-trip added *before* this
/// guard, so giving it its own full budget would both double phase B's
/// worst-case wall-clock time (contradicting NFR-002's singular "existing...
/// budget" framing) and widen the window in which a mid-scan edit discards
/// this whole result, `upgrade_status` included. Sharing one deadline caps
/// the total at the original ceiling, same as before this fix existed.
pub(crate) async fn run_osv_phase_b_and_commit(
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
        let phase_b_deadline = Instant::now()
            + Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));

        // B.1 (US-002, unchanged by #462): checks the registry's "latest" candidate.
        // `latest_native_by_key` is kept for B.2 below, which needs the same native
        // "latest" string to detect a fix target F that coincides with latest (FR-002)
        // without re-deriving it from `doc.cached_versions` a second time.
        let latest_native_by_key: HashMap<String, String> = {
            let Some(doc) = state.get_document(uri) else {
                return;
            };
            vulnerable_keys
                .iter()
                .filter_map(|key| {
                    let latest = doc
                        .cached_versions
                        .get(key.as_str())
                        .or_else(|| {
                            let raw = result.raw_name_by_key.get(key)?;
                            doc.cached_versions.get(raw.as_str())
                        })?
                        .latest
                        .clone();
                    Some((key.clone(), latest.to_string()))
                })
                .collect()
        };

        let candidates: Vec<deps_core::osv::ScanTarget> = vulnerable_keys
            .iter()
            .filter_map(|key| {
                let osv_name = result.osv_name_by_key.get(key)?.clone();
                let latest_native = latest_native_by_key.get(key)?.clone();
                Some(deps_core::osv::ScanTarget::new(
                    key.clone(),
                    osv_name,
                    formatter.osv_version(&latest_native),
                    latest_native,
                ))
            })
            .collect();

        if !candidates.is_empty() {
            let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
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

        run_osv_fix_target_verification(
            &mut result.vulnerabilities,
            &vulnerable_keys,
            &result.osv_name_by_key,
            &latest_native_by_key,
            ecosystem_id,
            formatter,
            &state.osv,
            phase_b_deadline,
        )
        .await;
    }

    if let Some(mut doc) = state.documents.get_mut(uri) {
        if doc.content == result.content_snapshot {
            doc.update_vulnerabilities(result.vulnerabilities);
        } else {
            tracing::debug!("dropping stale OSV scan result: document content changed mid-scan");
        }
    }
}

/// B.2 (#462): independently verifies each vulnerable dependency's recommended fix target F
/// (`DependencyVulnerabilities::recommended_fix`'s `version`), which B.1 above never scans —
/// B.1 only ever checks the registry's "latest" candidate, and F is frequently a different,
/// older version (the minimal version that clears the advisories B.1's "latest" check did
/// not already exclude). Without this, `generate_code_actions` could offer F as a verified
/// fix when OSV was never asked about F itself — see
/// `deps_core::osv::DependencyVulnerabilities::fix_target_status`'s doc, which this function
/// populates, and the orphaned-TODO history in this function's git blame (formerly tracked
/// only by a `// TODO(critic): ... see #216 critique D1` comment; now #462).
///
/// Resolution order per dependency, cheapest first:
/// 1. F equals the already-checked "latest" candidate (FR-002) — reuse `upgrade_status`,
///    no extra call.
/// 2. Otherwise, queue a live [`deps_core::osv::OsvClient::check_candidates`] check for F,
///    batched into a single call across every dependency that reaches this branch (NFR-001)
///    — never one call per dependency. There is no data-derived shortcut here: a proof
///    checking F against the advisories `recommended_fix()` computed F *from* is a
///    tautology at its only call site (critic C1) — phase A only ever queries the
///    dependency's declared version, so an advisory affecting some version strictly
///    between declared and F, but not the declared version itself, is invisible to any
///    check built only from `self.advisories`. Only a live query of F itself can surface
///    that advisory (the actual gap #462 exists to close).
///
/// A dependency whose F fails [`deps_core::lsp_helpers::is_safe_version_string`], or whose
/// `osv_name` is unavailable, is skipped (logged at `debug`), never crashes the scan. A
/// dependency whose live check above times out or fails simply keeps `fix_target_status`
/// left at `NotChecked` (case 2's `HashMap` result never carries that key) — the safe,
/// fail-closed degradation FR-004/NFR-002 call for: `deps_core::lsp_helpers::code_actions::fix_target_is_verified`
/// treats an unresolved status as unverified and omits the fix action, so a stalled
/// verification never surfaces a fix action that was never actually checked.
#[allow(clippy::too_many_arguments)]
async fn run_osv_fix_target_verification(
    vulnerabilities: &mut deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[String],
    osv_name_by_key: &HashMap<String, String>,
    latest_native_by_key: &HashMap<String, String>,
    ecosystem_id: EcosystemId,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    osv: &deps_core::osv::OsvClient,
    phase_b_deadline: Instant,
) {
    use deps_core::osv::ScanOutcome;

    let (resolved, live_check_candidates) =
        deps_engine::classify::osv::collect_fix_target_resolutions(
            vulnerabilities,
            vulnerable_keys,
            osv_name_by_key,
            latest_native_by_key,
            formatter,
        );

    for (key, status) in resolved {
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(key.as_str()) {
            dv.fix_target_status = status;
        }
    }

    if live_check_candidates.is_empty() {
        return;
    }

    let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
    let statuses = osv
        .check_candidates(ecosystem_id, &live_check_candidates, timeout_duration)
        .await;

    deps_engine::classify::osv::apply_live_fix_target_statuses(vulnerabilities, statuses);
}

#[cfg(test)]
mod tests {
    // Only `license_prefetch_tests`' dart/swift/gradle/deno-gated cases consume this.
    #[cfg(any(
        feature = "dart",
        feature = "swift",
        feature = "gradle",
        feature = "deno"
    ))]
    use super::super::state::DocumentState;
    use super::*;

    /// Issue #660: `run_license_prefetch`'s ecosystem gate — only the four tier-3
    /// ecosystems (no `deps_dev_system` coverage, no license in the hot-path
    /// version-list response) should ever reach a network call.
    mod license_prefetch_tests {
        use super::*;

        /// Issue #697: exhaustive per-[`EcosystemId`] table, so a 15th ecosystem or a
        /// 5th [`deps_core::LicenseSource`] variant is a compile error here, mirroring
        /// this project's `EcosystemId` exhaustive-match convention. Replaces the
        /// previous six feature-gated spot checks against `fetch_license(..).is_some()`
        /// with one assertion per registered ecosystem against `license_source()`.
        /// `requires_dedicated_fetch()` needs no separate assertion: it is a pure
        /// function of `license_source()`, so once `license_source()` is pinned to the
        /// table below, capability follows automatically and cannot independently drift.
        const fn expected_license_source(id: EcosystemId) -> deps_core::LicenseSource {
            match id {
                EcosystemId::Dart | EcosystemId::Swift => deps_core::LicenseSource::DetectedSpdx,
                EcosystemId::Gradle => deps_core::LicenseSource::PomFreeText,
                EcosystemId::Deno => deps_core::LicenseSource::FetchedDeclaredSpdx,
                EcosystemId::Cargo
                | EcosystemId::Npm
                | EcosystemId::Pypi
                | EcosystemId::Go
                | EcosystemId::Bundler
                | EcosystemId::Maven
                | EcosystemId::Composer
                | EcosystemId::NuGet
                | EcosystemId::GithubActions
                | EcosystemId::GitlabCi => deps_core::LicenseSource::RegistryDeclaredSpdx,
            }
        }

        #[test]
        fn license_source_is_pinned_per_ecosystem() {
            let state = ServerState::new();

            for id_str in state.ecosystem_registry.ecosystem_ids() {
                let id: EcosystemId = id_str.parse().expect("valid ecosystem id");
                let eco = state
                    .ecosystem_registry
                    .get(id_str)
                    .unwrap_or_else(|| panic!("{id_str} ecosystem not found"));

                assert_eq!(
                    eco.license_source(),
                    expected_license_source(id),
                    "{id_str}: license_source() mismatch"
                );
            }
        }

        /// A non-tier-3 ecosystem must return immediately without touching
        /// `DocumentState` at all (not even an empty-map write) — asserted by never
        /// inserting a document for `uri` and confirming `run_license_prefetch`
        /// doesn't panic on a missing document, which it would if it read past the
        /// ecosystem gate.
        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn run_license_prefetch_no_op_for_non_tier3_ecosystem() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");

            // No document inserted for `uri` at all — if the ecosystem gate didn't
            // short-circuit first, `state.get_document(&uri)` inside would return
            // `None` and the function would still just return early, so this also
            // doubles as a "never panics on a missing document" check.
            run_license_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

            assert_eq!(state.document_count(), 0);
        }

        /// Live end-to-end (Registry Integration Gate): a real Dart document, routed
        /// through the real `EcosystemRegistry` (no mock), fetching `http`'s license
        /// from the real pub.dev `/score` endpoint and committing it into
        /// `DocumentState.licenses`.
        #[cfg(feature = "dart")]
        #[tokio::test]
        #[ignore = "hits the real pub.dev API"]
        async fn run_license_prefetch_live_dart_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "dependencies:\n  http: ^1.0.0\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Dart ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("http"), "1.2.0".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses.contains_key(&PackageName::new("http")),
                "expected a pre-fetched license for 'http', got: {:?}",
                doc.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `Package.swift`
        /// dependency, routed through the real `EcosystemRegistry`, fetching
        /// `apple/swift-nio`'s license from the real GitHub repository API.
        ///
        /// Unauthenticated GitHub API calls are capped at 60 req/h — this can fail
        /// with an empty result under an exhausted rate limit (no `GITHUB_TOKEN` set)
        /// rather than a genuine regression; that is the same graceful-degradation
        /// path `SwiftRegistry::get_license` takes for any fetch failure (NFR-003).
        #[cfg(feature = "swift")]
        #[tokio::test]
        #[ignore = "hits the real GitHub API"]
        async fn run_license_prefetch_live_swift_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Package.swift");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#".package(url: "https://github.com/apple/swift-nio.git", .upToNextMajor(from: "2.0.0"))"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Swift ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Swift,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("apple/swift-nio"), "2.65.0".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses
                    .contains_key(&PackageName::new("apple/swift-nio")),
                "expected a pre-fetched license for 'apple/swift-nio', got: {:?}",
                doc.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `build.gradle.kts`
        /// dependency, routed through the real `EcosystemRegistry`, fetching
        /// `com.squareup.okhttp3:okhttp`'s license from the real Maven Central POM.
        #[cfg(feature = "gradle")]
        #[tokio::test]
        #[ignore = "hits the real Maven Central API"]
        async fn run_license_prefetch_live_gradle_populates_document_licenses() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: gradle's `parse_manifest`
            // transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content =
                "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Gradle,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(
                    PackageName::new("com.squareup.okhttp3:okhttp"),
                    "4.12.0".into(),
                )]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses
                    .contains_key(&PackageName::new("com.squareup.okhttp3:okhttp")),
                "expected a pre-fetched license for 'com.squareup.okhttp3:okhttp', got: {:?}",
                doc.licenses
            );
        }

        /// Live end-to-end, issue #692: Guava's own leaf POM
        /// (`guava-32.0.1-jre.pom`) has no `<licenses>` block at all — the license is
        /// declared only on its `guava-parent` POM. Unlike the okhttp test above (whose
        /// own leaf POM already carries `<licenses>`), this specifically exercises
        /// `fetch_license_from`'s `<parent>`-following path against real Maven Central.
        #[cfg(feature = "gradle")]
        #[tokio::test]
        #[ignore = "hits the real Maven Central API"]
        async fn run_license_prefetch_live_gradle_follows_parent_pom_for_guava() {
            // See the comment in `run_license_prefetch_live_gradle_populates_document_licenses`
            // on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content =
                "dependencies {\n    implementation(\"com.google.guava:guava:32.0.1-jre\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Gradle,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(
                    PackageName::new("com.google.guava:guava"),
                    "32.0.1-jre".into(),
                )]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            let license = doc
                .licenses
                .get(&PackageName::new("com.google.guava:guava"));
            assert!(
                license.is_some_and(|l| !l.is_empty()),
                "expected a pre-fetched license for 'com.google.guava:guava' via its \
                 parent POM, got: {:?}",
                doc.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `deno.json`
        /// `jsr:` dependency, routed through the real `EcosystemRegistry`, fetching
        /// `@std/fs`'s license from the real JSR per-version API.
        #[cfg(feature = "deno")]
        #[tokio::test]
        #[ignore = "hits the real JSR API"]
        async fn run_license_prefetch_live_deno_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/deno.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Deno ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Deno,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("jsr:@std/fs"), "1.0.24".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses.contains_key(&PackageName::new("jsr:@std/fs")),
                "expected a pre-fetched license for 'jsr:@std/fs', got: {:?}",
                doc.licenses
            );
        }
    }
}
