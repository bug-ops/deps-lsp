//! Registry fetch orchestration: fans a document-change diff out to the classification
//! layer's concurrent fetch, then merges the result back into `DocumentState`.
//!
//! The pure fetch/classify decisions themselves (`dedup_dependencies_by_source`,
//! `composer_minimum_stability`, `fetch_latest_versions_parallel`, `fetch_and_classify_package`)
//! live in `deps_engine::classify::fetch` (issue #1059) — this module owns only what depends on
//! `ServerState`/`DocumentState`/`Client`: marking a document loading, opening an LSP progress
//! notification, and merging a completed fetch's result back into document state.

use super::diff::drop_cache_for_forced_refetch;
use super::resolved::RefetchPolicy;
use super::state::ServerState;
use crate::progress::RegistryProgress;
use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::PackageName;
use deps_engine::classify::diff::{
    merge_deprecations_after_fetch, merge_no_comparable_versions_after_fetch,
};
use deps_engine::classify::fetch::{
    DepSources, FetchResult, apply_fetch_outcomes, composer_minimum_stability,
    dedup_dependencies_by_source, fetch_latest_versions_parallel,
};
use deps_engine::classify::resolved::collect_in_use_versions;
use std::collections::{HashMap, HashSet};
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

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
        apply_fetch_outcomes(
            &mut doc.outcomes,
            fetch_result.yanked_versions,
            fetch_result.fetch_failed,
            collided_names,
            formatter,
        );
        merge_deprecations_after_fetch(
            &mut doc.outcomes,
            &fetched_names,
            fetch_result.deprecations,
            formatter,
        );
        merge_no_comparable_versions_after_fetch(
            &mut doc.outcomes,
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
    // Only `pypi_tests`/`pypi_yanked_key_guard_tests` below consume these.
    #[cfg(feature = "pypi")]
    use super::super::state::DocumentState;
    use super::*;
    #[cfg(feature = "pypi")]
    use deps_core::DependencyOutcomes;
    #[cfg(feature = "pypi")]
    use deps_core::EcosystemId;
    #[cfg(feature = "pypi")]
    use deps_core::Registry;
    #[cfg(feature = "pypi")]
    use deps_core::RemovalStatus;
    #[cfg(feature = "pypi")]
    use deps_core::VersionReq;
    use deps_core::parser::DependencySource;
    use std::sync::Arc;

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

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let pypi_uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            assert!(state.ecosystem_registry.for_uri(&pypi_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/pyproject.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("pypi ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &url).await;
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
            let url = deps_core::test_util::test_uri("/test/pyproject.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            // The TOML key is quoted so a dotted name (e.g. `zope.interface`)
            // is a literal key rather than TOML's dotted-key table-nesting
            // syntax.
            let content =
                format!("[tool.poetry.dependencies]\n\"{raw_name}\" = \"=={pinned_version}\"\n");

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("pypi ecosystem not found");
            let formatter = ecosystem.formatter();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
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
                &url,
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
}
