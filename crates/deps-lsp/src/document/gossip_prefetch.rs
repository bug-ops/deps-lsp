//! Background pre-fetch of deps.dev GOSSIP cooldown/low-usage findings per declared
//! dependency (issue #1456, spec 072) — mirrors `document::osv_scan::run_typosquat_prefetch`'s
//! shape closely, but issues one `GetFindingsBatch` POST for the whole document (via
//! [`deps_core::lsp_helpers::fetch_gossip_findings_batch`]) rather than one call per
//! dependency.

use super::state::ServerState;
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use deps_core::{Ecosystem, GossipFindings, PackageName};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;
use tracing::Instrument;

/// Ceiling on the GOSSIP pre-fetch's overall timeout, independent of the configured
/// `fetch_timeout_secs` — mirrors [`super::osv_scan`]'s `TYPOSQUAT_PREFETCH_TIMEOUT_CEILING_SECS`
/// exactly, bounding one document's whole batch call so a pathological manifest or a slow
/// deps.dev response can't leave this background task running indefinitely.
const GOSSIP_PREFETCH_TIMEOUT_CEILING_SECS: u64 = 30;

/// Background pre-fetch of GOSSIP cooldown/low-usage findings for a document's declared
/// dependencies (issue #1456, spec 072), gated on [`ServerState::is_gossip_enabled`] and
/// `network.offline` — both checked here, before the document guard is even taken, so a
/// disabled/offline server does zero work per document lifecycle event.
///
/// The network dispatch goes through
/// [`deps_core::lsp_helpers::fetch_gossip_findings_batch`], which resolves ecosystem
/// coverage and the public-registry-source gate internally (mirrors
/// `run_typosquat_prefetch`'s identical division of responsibility with
/// `fetch_typosquat_signals`) — this function only owns the document guard, staleness
/// check, and merge.
///
/// Checks `content` only, not `resolved_versions_generation` — a GOSSIP finding depends
/// only on declared package *names* (`gossip_findings_batch` is package-scoped, not
/// version-scoped), mirroring `run_typosquat_prefetch`'s identical reasoning for the
/// typosquat signal.
///
/// **Not** joined before the main diagnostics publish (mirrors `run_typosquat_prefetch`'s
/// NFR-001-driven design): the caller (`spawn_gossip_prefetch_and_republish`) lets the main
/// publish proceed on its existing schedule and issues a second, later publish only if this
/// returns `true`.
///
/// Returns whether the merge actually *changed* [`super::state::DocumentState::gossip_findings`]
/// (security/impl-critic review M3) — `false` covers every early-out (disabled, offline, no
/// document, no parse result, timeout, every fetched name filtered out by a mid-fetch
/// content change) *and* the case where the fetch found only data the document already had,
/// so a caller can skip a pointless republish.
pub(crate) async fn run_gossip_prefetch(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> bool {
    if !state.is_gossip_enabled() || state.cache.is_offline() {
        return false;
    }

    let (content_snapshot, parse_result): (String, Arc<dyn deps_core::ParseResult>) = {
        let Some(doc) = state.get_document(&uri) else {
            return false;
        };
        let Some(parse_result) = doc.parse_result_arc() else {
            return false;
        };
        (doc.content.clone(), parse_result)
    };

    let timeout_duration =
        Duration::from_secs(fetch_timeout_secs.min(GOSSIP_PREFETCH_TIMEOUT_CEILING_SECS));
    let findings = match tokio::time::timeout(
        timeout_duration,
        deps_core::lsp_helpers::fetch_gossip_findings_batch(
            ecosystem.ecosystem_id(),
            parse_result.as_ref(),
            ecosystem.formatter(),
            false, // already checked `state.cache.is_offline()` above.
            Some(&state.deps_dev),
        ),
    )
    .await
    {
        Ok(findings) => findings,
        Err(_) => {
            tracing::debug!("GOSSIP pre-fetch timed out");
            return false;
        }
    };

    if findings.is_empty() {
        return false;
    }

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        let findings = if doc.content == content_snapshot {
            findings
        } else {
            // Security/impl-critic review S1: don't drop the whole result just because the
            // document was edited mid-fetch — filter it down to only names still actually
            // declared in the document's *current* (already re-parsed) content, and merge
            // those. Safe because `GossipFindings` is keyed by package name and every read
            // site (`gossip_cooldown_for`) re-validates the exact version match at read
            // time (FR-008) regardless — an intervening edit that doesn't remove the
            // dependency doesn't invalidate the fetched data's correctness. Dropping
            // everything here (the original design) combined with the in-flight
            // skip-and-defer behavior in `DepsDevClient::gossip_findings_batch` could
            // otherwise leave a document with zero GOSSIP data indefinitely: an
            // open-triggered prefetch claims all names, a change-triggered prefetch racing
            // it skips those already-claimed names and merges nothing, and the original
            // prefetch then finishes only to drop its own (otherwise-good) result here.
            let current_names: std::collections::HashSet<PackageName> = doc
                .parse_result()
                .map(|parse_result| {
                    parse_result
                        .dependencies()
                        .into_iter()
                        .map(|dep| dep.name().clone())
                        .collect()
                })
                .unwrap_or_default();
            let filtered: HashMap<PackageName, GossipFindings> = findings
                .into_iter()
                .filter(|(name, _)| current_names.contains(name))
                .collect();
            if filtered.is_empty() {
                tracing::debug!(
                    "dropping stale GOSSIP pre-fetch result: no still-declared names survive \
                     the content-change filter"
                );
                return false;
            }
            filtered
        };

        // Security/impl-critic review M3: only report a change (triggering the caller's
        // diagnostics republish) when the merge actually adds new or different data — a
        // memo hit for a package this document already has byte-identical data for must
        // not cause a wasted republish on every debounced edit.
        let changed = findings
            .iter()
            .any(|(name, value)| doc.gossip_findings.get(name) != Some(value));
        doc.merge_gossip_findings(findings);
        return changed;
    }
    false
}

/// Detects a GOSSIP version-equality mismatch (spec 072 FR-008) for `uri`'s document
/// immediately after a registry-version fetch has landed, and — if any dependency's already-
/// cached `gossip_findings` no longer matches the freshly-fetched registry latest — spawns a
/// detached, throttled force-refetch that republishes diagnostics for **every** open
/// document declaring the affected package(s), not just `uri` (issue #1456, spec 072
/// FR-011/M21).
///
/// Called from `document::lifecycle`'s registry-fetch-completion path (both the document-open
/// and document-change flows), never from `deps-core`'s synchronous hover/diagnostics render
/// functions (M21b) — those have no ability to spawn background work. The detection itself
/// (this function's synchronous prefix, before the `tokio::spawn`) is a plain in-memory
/// comparison, no network call: a document with no `gossip_findings` yet (the common case —
/// most documents never had a chance to be stale before this check even runs) short-circuits
/// immediately.
///
/// The actual refetch goes through
/// [`deps_core::lsp_helpers::force_refresh_gossip_findings`] (M21a — bypasses the memo,
/// unlike the normal prefetch path, and internally resolves `ecosystem`'s deps.dev
/// `system` the same way [`deps_core::lsp_helpers::fetch_gossip_findings_batch`] does) and
/// is itself throttled per-package to at most once every 15 minutes, so calling this on
/// every registry fetch (rather than only occasionally) is safe and does not need its own
/// additional rate-limiting here.
pub(crate) fn spawn_gossip_mismatch_refetch_if_needed(
    uri: &Uri,
    state: &Arc<ServerState>,
    client: &Client,
    ecosystem: &Arc<dyn Ecosystem>,
    config: &Arc<RwLock<DepsConfig>>,
) {
    if !state.is_gossip_enabled() || state.cache.is_offline() {
        return;
    }

    let formatter = ecosystem.formatter();
    let mismatched: Vec<String> = state
        .with_document(uri, |doc| {
            // Code-review finding #2: a name's *current* declared source, not whatever it
            // was when `gossip_findings` was last populated — a dependency edited to point
            // at a private/scoped source under the same name must not be force-refreshed
            // (the normal prefetch path, `fetch_gossip_findings_batch`, already applies
            // this same `source_is_public_registry_content` gate per-dependency).
            let dep_sources: HashMap<PackageName, deps_core::DependencySource> = doc
                .parse_result()
                .map(|parse_result| {
                    parse_result
                        .dependencies()
                        .into_iter()
                        .map(|dep| (dep.name().clone(), dep.source()))
                        .collect()
                })
                .unwrap_or_default();

            doc.gossip_findings
                .iter()
                .filter_map(|(name, findings)| {
                    let latest = &doc.cached_versions.get(name)?.latest;
                    if latest.as_str() == findings.version {
                        return None;
                    }
                    let source = dep_sources.get(name)?;
                    formatter
                        .source_is_public_registry_content(source)
                        .then(|| name.as_str().to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    if mismatched.is_empty() {
        return;
    }

    tokio::spawn(
        run_gossip_mismatch_refetch(
            Arc::clone(state),
            client.clone(),
            ecosystem.ecosystem_id(),
            Arc::clone(config),
            mismatched,
        )
        .instrument(tracing::Span::current()),
    );
}

/// The awaitable body [`spawn_gossip_mismatch_refetch_if_needed`] detaches via `tokio::spawn`
/// — split out so a test can await it directly with a pre-computed `mismatched` list, rather
/// than needing to race a detached background task (issue #1456, spec 072 M21 regression
/// coverage).
async fn run_gossip_mismatch_refetch(
    state: Arc<ServerState>,
    client: Client,
    ecosystem_id: deps_core::EcosystemId,
    config: Arc<RwLock<DepsConfig>>,
    mismatched: Vec<String>,
) {
    // Code-review finding #5: the caller's own enabled/offline gate was checked once,
    // synchronously, before this body was ever spawned — a config reload disabling GOSSIP
    // (or a network-mode flip to offline) while this detached task is still in flight (it
    // can outlive the fetch that triggered it by up to the batch call's own timeout) must
    // not still force-refresh and republish.
    if !state.is_gossip_enabled() || state.cache.is_offline() {
        return;
    }

    let keyed: HashMap<PackageName, GossipFindings> =
        deps_core::lsp_helpers::force_refresh_gossip_findings(
            ecosystem_id,
            &mismatched,
            &state.deps_dev,
        )
        .await;
    if keyed.is_empty() {
        return;
    }

    // M21c: every open document declaring any refreshed package gets the merge and a
    // republish — not just the document that happened to detect the mismatch.
    let uris: Vec<Uri> = state
        .documents
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    for doc_uri in uris {
        // Code-review finding #1: filter `keyed` down to this specific document's own
        // declared packages, and skip documents on a different ecosystem entirely — package
        // names are not globally unique across ecosystems (e.g. npm "vite" vs a same-named
        // Cargo crate), so a blanket `keyed.clone()` merge could otherwise attribute one
        // ecosystem's GOSSIP data to an unrelated document that merely happens to cache a
        // same-named package on a different registry.
        let filtered = state.with_document(&doc_uri, |doc| {
            if doc.ecosystem != ecosystem_id {
                return HashMap::new();
            }
            keyed
                .iter()
                .filter(|(name, _)| doc.cached_versions.contains_key(*name))
                .map(|(name, findings)| (name.clone(), findings.clone()))
                .collect::<HashMap<_, _>>()
        });
        let Some(filtered) = filtered.filter(|filtered| !filtered.is_empty()) else {
            continue;
        };

        if let Some(mut doc) = state.documents.get_mut(&doc_uri) {
            doc.merge_gossip_findings(filtered);
        } else {
            continue;
        }

        let snapshot = {
            let cfg = config.read().await;
            diagnostics::DiagnosticsSnapshot::from_config(&cfg)
        };
        let dep_count = diagnostics::document_dependency_count(&state, &doc_uri);
        diagnostics::publish_document_diagnostics(&state, &client, &doc_uri, &snapshot, dep_count)
            .await;
    }
}

/// Issue #1456: `run_gossip_prefetch`'s own gates, mirroring
/// `osv_scan::typosquat_prefetch_tests`'s "never touches `DocumentState` at all" style for
/// the disabled/offline/missing-document no-op cases.
#[cfg(all(test, feature = "npm"))]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use deps_core::EcosystemId;
    use deps_core::test_util::test_uri;

    /// Default `ServerState` starts with `policy.gossip.enabled == false` — no document
    /// inserted for `uri` at all, so if the enabled-gate didn't short-circuit first,
    /// `state.get_document(&uri)` would return `None` and the function would still just
    /// return early; this also doubles as a "never panics on a missing document" check.
    #[tokio::test]
    async fn run_gossip_prefetch_no_op_when_disabled() {
        let state = Arc::new(ServerState::new());
        let uri = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/package.json"));
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Npm)
            .expect("npm ecosystem not found");

        let changed = run_gossip_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

        assert!(!changed);
        assert_eq!(state.document_count(), 0);
    }

    /// Same shape as the disabled case, for the offline gate.
    #[tokio::test]
    async fn run_gossip_prefetch_no_op_when_offline() {
        let state = Arc::new(ServerState::new());
        state.set_gossip_enabled(true);
        state.cache.set_offline(deps_core::NetworkMode::Offline);
        let uri = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/package.json"));
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Npm)
            .expect("npm ecosystem not found");

        let changed = run_gossip_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

        assert!(!changed);
        assert_eq!(state.document_count(), 0);
    }

    /// Issue #1456, spec 072 FR-011/M21c regression: a force-refetch triggered by one
    /// document's mismatch must merge into and be visible from **every** open document
    /// declaring the same package, not only the one whose `run_gossip_mismatch_refetch`
    /// call happened to detect the staleness.
    #[tokio::test]
    async fn run_gossip_mismatch_refetch_updates_every_document_declaring_the_package() {
        let mut server = mockito::Server::new_async().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(
                r#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                    "findings":{"packageKey":{"system":"NPM","name":"vite"},
                        "recommendedVersions":[],
                        "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.4.0"},
                            "isDefault":true,
                            "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                        "packageFindings":[]}}],
                    "nextPageToken":""}"#,
            )
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let mut state = ServerState::new();
        state.deps_dev = mocked_deps_dev;
        state.set_gossip_enabled(true);
        let state = Arc::new(state);

        let uri_a = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/a/package.json"));
        let uri_b = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/b/package.json"));
        for uri in [&uri_a, &uri_b] {
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Npm, String::new());
            doc.update_cached_versions(HashMap::from([(
                PackageName::new("vite"),
                deps_core::PackageVersions::latest_only("8.4.0"),
            )]));
            state.documents.insert(uri.clone(), doc);
        }

        let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();

        run_gossip_mismatch_refetch(
            Arc::clone(&state),
            client,
            EcosystemId::Npm,
            config,
            vec!["vite".to_string()],
        )
        .await;

        for uri in [&uri_a, &uri_b] {
            let has_entry = state
                .with_document(uri, |doc| {
                    doc.gossip_findings.contains_key(&PackageName::new("vite"))
                })
                .unwrap_or(false);
            assert!(
                has_entry,
                "document {uri:?} must have the refreshed gossip finding"
            );
        }
    }

    /// Code-review finding #1 regression: the fan-out loop must merge only into documents
    /// that actually declare the refreshed package, and must skip a document on a different
    /// ecosystem outright — package names are not globally unique across ecosystems, so a
    /// Cargo document that happens to cache a same-named "vite" package must not receive
    /// npm's GOSSIP data, and an npm document that never declared "vite" at all must not
    /// either.
    #[tokio::test]
    async fn run_gossip_mismatch_refetch_filters_per_document_and_skips_other_ecosystems() {
        let mut server = mockito::Server::new_async().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(
                r#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                    "findings":{"packageKey":{"system":"NPM","name":"vite"},
                        "recommendedVersions":[],
                        "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.4.0"},
                            "isDefault":true,
                            "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                        "packageFindings":[]}}],
                    "nextPageToken":""}"#,
            )
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let mut state = ServerState::new();
        state.deps_dev = mocked_deps_dev;
        state.set_gossip_enabled(true);
        let state = Arc::new(state);

        let uri_declares_vite =
            crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/a/package.json"));
        let mut doc_declares_vite =
            DocumentState::new_without_parse_result(EcosystemId::Npm, String::new());
        doc_declares_vite.update_cached_versions(HashMap::from([(
            PackageName::new("vite"),
            deps_core::PackageVersions::latest_only("8.4.0"),
        )]));
        state
            .documents
            .insert(uri_declares_vite.clone(), doc_declares_vite);

        let uri_other_npm_package =
            crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/b/package.json"));
        let mut doc_other_npm_package =
            DocumentState::new_without_parse_result(EcosystemId::Npm, String::new());
        doc_other_npm_package.update_cached_versions(HashMap::from([(
            PackageName::new("left-pad"),
            deps_core::PackageVersions::latest_only("1.3.0"),
        )]));
        state
            .documents
            .insert(uri_other_npm_package.clone(), doc_other_npm_package);

        let uri_cargo_same_name =
            crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/c/Cargo.toml"));
        let mut doc_cargo_same_name =
            DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
        doc_cargo_same_name.update_cached_versions(HashMap::from([(
            PackageName::new("vite"),
            deps_core::PackageVersions::latest_only("1.0.0"),
        )]));
        state
            .documents
            .insert(uri_cargo_same_name.clone(), doc_cargo_same_name);

        let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();

        run_gossip_mismatch_refetch(
            Arc::clone(&state),
            client,
            EcosystemId::Npm,
            config,
            vec!["vite".to_string()],
        )
        .await;

        let declares_vite_has_entry = state
            .with_document(&uri_declares_vite, |doc| {
                doc.gossip_findings.contains_key(&PackageName::new("vite"))
            })
            .unwrap_or(false);
        assert!(
            declares_vite_has_entry,
            "the document that actually declares \"vite\" must receive the refreshed finding"
        );

        let other_npm_untouched = state
            .with_document(&uri_other_npm_package, |doc| doc.gossip_findings.is_empty())
            .unwrap_or(false);
        assert!(
            other_npm_untouched,
            "an npm document that never declared \"vite\" must not receive its finding"
        );

        let cargo_untouched = state
            .with_document(&uri_cargo_same_name, |doc| doc.gossip_findings.is_empty())
            .unwrap_or(false);
        assert!(
            cargo_untouched,
            "a Cargo document caching a same-named \"vite\" package must not receive npm's \
             GOSSIP finding"
        );
    }

    /// Code-review finding #5 regression: the spawned body must re-check
    /// `is_gossip_enabled` for itself — a config reload disabling GOSSIP while this task is
    /// still in flight (or, as tested here, simply called with the gate already off) must
    /// not perform the refetch at all.
    #[tokio::test]
    async fn run_gossip_mismatch_refetch_no_op_when_disabled() {
        let mut server = mockito::Server::new_async().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .expect(0)
            .with_status(200)
            .with_body(
                r#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                    "findings":{"packageKey":{"system":"NPM","name":"vite"},
                        "recommendedVersions":[],
                        "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.4.0"},
                            "isDefault":true,
                            "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                        "packageFindings":[]}}],
                    "nextPageToken":""}"#,
            )
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let mut state = ServerState::new();
        state.deps_dev = mocked_deps_dev;
        // Deliberately left disabled (default).
        let state = Arc::new(state);

        let uri = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/package.json"));
        let mut doc = DocumentState::new_without_parse_result(EcosystemId::Npm, String::new());
        doc.update_cached_versions(HashMap::from([(
            PackageName::new("vite"),
            deps_core::PackageVersions::latest_only("8.4.0"),
        )]));
        state.documents.insert(uri.clone(), doc);

        let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();

        run_gossip_mismatch_refetch(
            Arc::clone(&state),
            client,
            EcosystemId::Npm,
            config,
            vec!["vite".to_string()],
        )
        .await;

        batch.assert_async().await;
        let untouched = state
            .with_document(&uri, |doc| doc.gossip_findings.is_empty())
            .unwrap_or(false);
        assert!(
            untouched,
            "the disabled gate must short-circuit before any network call or merge"
        );
    }

    /// Security/impl-critic review S1 regression: a document edited mid-fetch (removing
    /// "left-pad" from its dependencies while the fetch is still in flight) must NOT drop
    /// the whole result — the still-declared "vite" finding must survive, filtered against
    /// the document's current (already re-parsed) content, and the removed "left-pad"
    /// finding must not.
    #[tokio::test]
    async fn run_gossip_prefetch_content_changed_mid_fetch_filters_to_still_declared_names() {
        let mut server = mockito::Server::new_async().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(|_req| {
                // Long enough for the test to mutate the document's content after this
                // request starts but before it returns.
                std::thread::sleep(std::time::Duration::from_millis(80));
                br#"{"responses":[
                    {"request":{"packageKey":{"system":"NPM","name":"vite"}},
                     "findings":{"packageKey":{"system":"NPM","name":"vite"},
                         "recommendedVersions":[],
                         "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                             "isDefault":true,
                             "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                 "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                         "packageFindings":[]}},
                    {"request":{"packageKey":{"system":"NPM","name":"left-pad"}},
                     "findings":{"packageKey":{"system":"NPM","name":"left-pad"},
                         "recommendedVersions":[],
                         "defaultVersion":{"versionKey":{"system":"NPM","name":"left-pad","version":"1.3.0"},
                             "isDefault":true,
                             "findings":[{"type":"LOW_USAGE","risk":"RISK_MEDIUM"}]},
                         "packageFindings":[]}}
                ],"nextPageToken":""}"#
                    .to_vec()
            })
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let mut state = ServerState::new();
        state.deps_dev = mocked_deps_dev;
        state.set_gossip_enabled(true);
        let state = Arc::new(state);

        let uri = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/package.json"));
        let domain_uri = crate::lsp_types_interop::from_lsp_uri(&uri).expect("valid uri");
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Npm)
            .expect("npm ecosystem not found");

        let content_v1 = r#"{"dependencies":{"vite":"^8.0.0","left-pad":"^1.0.0"}}"#.to_string();
        let parse_result_v1 = ecosystem
            .parse_manifest(&content_v1, &domain_uri)
            .await
            .expect("v1 manifest must parse");
        state.documents.insert(
            uri.clone(),
            DocumentState::new_from_parse_result(EcosystemId::Npm, content_v1, parse_result_v1),
        );

        let prefetch = tokio::spawn(run_gossip_prefetch(
            uri.clone(),
            Arc::clone(&state),
            Arc::clone(&ecosystem),
            5,
        ));

        // Let the fetch start (and enter its 80ms sleep) before simulating an edit that
        // drops "left-pad" — mirrors a real edit rebuilding `DocumentState` wholesale.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let content_v2 = r#"{"dependencies":{"vite":"^8.0.0"}}"#.to_string();
        let parse_result_v2 = ecosystem
            .parse_manifest(&content_v2, &domain_uri)
            .await
            .expect("v2 manifest must parse");
        if let Some(mut doc) = state.documents.get_mut(&uri) {
            *doc =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content_v2, parse_result_v2);
        }

        let changed = prefetch.await.expect("prefetch task must not panic");
        assert!(
            changed,
            "the surviving \"vite\" finding must count as a change"
        );

        let doc = state.get_document(&uri).expect("document must still exist");
        assert!(
            doc.gossip_findings.contains_key(&PackageName::new("vite")),
            "still-declared \"vite\" must survive the content-change filter"
        );
        assert!(
            !doc.gossip_findings
                .contains_key(&PackageName::new("left-pad")),
            "removed \"left-pad\" must not be merged in despite being in the fetch result"
        );
    }

    /// Code-review finding #2 regression: a dependency's stale, previously-fetched
    /// `gossip_findings` entry surviving edit-to-edit (mirrors `diff::preserve_cache`'s
    /// carry-forward) must not be force-refreshed once the same-named dependency's *current*
    /// declared source is no longer a public registry — re-sourcing "vite" to a git URL
    /// between the fetch that populated `gossip_findings` and the version-mismatch check
    /// must exclude it from the mismatched list, so only one `findingsbatch` call (the
    /// original, legitimate registry-sourced prefetch) ever happens.
    #[tokio::test]
    async fn spawn_gossip_mismatch_refetch_skips_dependency_resourced_off_registry() {
        let mut server = mockito::Server::new_async().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                    "findings":{"packageKey":{"system":"NPM","name":"vite"},
                        "recommendedVersions":[],
                        "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.4.0"},
                            "isDefault":true,
                            "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                        "packageFindings":[]}}],
                    "nextPageToken":""}"#,
            )
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let mut state = ServerState::new();
        state.deps_dev = mocked_deps_dev;
        state.set_gossip_enabled(true);
        let state = Arc::new(state);

        let uri = crate::lsp_types_interop::to_lsp_uri(&test_uri("/test/package.json"));
        let domain_uri = crate::lsp_types_interop::from_lsp_uri(&uri).expect("valid uri");
        let ecosystem = state
            .ecosystem_registry
            .get(EcosystemId::Npm)
            .expect("npm ecosystem not found");

        let content_registry = r#"{"dependencies":{"vite":"^8.0.0"}}"#.to_string();
        let parse_result_registry = ecosystem
            .parse_manifest(&content_registry, &domain_uri)
            .await
            .expect("registry-sourced manifest must parse");
        let mut doc = DocumentState::new_from_parse_result(
            EcosystemId::Npm,
            content_registry,
            parse_result_registry,
        );
        doc.update_cached_versions(HashMap::from([(
            PackageName::new("vite"),
            deps_core::PackageVersions::latest_only("8.4.0"),
        )]));
        state.documents.insert(uri.clone(), doc);

        // Legitimate prefetch while "vite" is still registry-sourced: populates
        // `gossip_findings` with version "8.4.0", matching `cached_versions.latest` — no
        // mismatch yet.
        run_gossip_prefetch(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5).await;
        let seeded = state
            .with_document(&uri, |doc| {
                doc.gossip_findings.contains_key(&PackageName::new("vite"))
            })
            .unwrap_or(false);
        assert!(
            seeded,
            "the registry-sourced prefetch must have seeded \"vite\""
        );

        // Re-source "vite" to a git URL (content edit), carrying `gossip_findings` forward
        // exactly as `diff::preserve_cache` does across a real edit, then land a new
        // registry-version fetch that makes the carried-forward entry mismatched.
        let content_git =
            r#"{"dependencies":{"vite":"git+https://github.com/example/vite.git"}}"#.to_string();
        let parse_result_git = ecosystem
            .parse_manifest(&content_git, &domain_uri)
            .await
            .expect("git-sourced manifest must parse");
        let mut new_doc =
            DocumentState::new_from_parse_result(EcosystemId::Npm, content_git, parse_result_git);
        if let Some(old_doc) = state.get_document(&uri) {
            new_doc.gossip_findings.clone_from(&old_doc.gossip_findings);
        }
        new_doc.update_cached_versions(HashMap::from([(
            PackageName::new("vite"),
            deps_core::PackageVersions::latest_only("9.0.0"),
        )]));
        state.documents.insert(uri.clone(), new_doc);

        let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();
        spawn_gossip_mismatch_refetch_if_needed(&uri, &state, &client, &ecosystem, &config);

        // Give a wrongly-spawned refetch a chance to run before asserting the call count.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        batch.assert_async().await;
    }
}
