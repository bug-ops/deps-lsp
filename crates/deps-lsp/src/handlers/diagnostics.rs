//! Diagnostics handler using ecosystem trait delegation.

use crate::config::{DepsConfig, DiagnosticsConfig};
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Diagnostic, Uri};

/// Handles diagnostic requests using trait-based delegation.
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Uri,
    config: &DiagnosticsConfig,
    client: Client,
    full_config: Arc<RwLock<DepsConfig>>,
) -> Vec<Diagnostic> {
    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&full_config)).await {
        tracing::warn!("Could not load document for diagnostics: {:?}", uri);
        return vec![];
    }

    // Snapshot before generating diagnostics (Copy value, no lock held across the call)
    let freshness = { full_config.read().await.freshness.to_settings() };
    let severities = config.to_severities();

    generate_diagnostics_internal(state, uri, freshness, severities).await
}

/// Internal diagnostic generation without cold start support.
///
/// This is used when we know the document is already loaded (e.g., from background tasks).
pub(crate) async fn generate_diagnostics_internal(
    state: Arc<ServerState>,
    uri: &Uri,
    freshness: deps_core::FreshnessSettings,
    severities: deps_core::DiagnosticSeverities,
) -> Vec<Diagnostic> {
    // Own everything `generate_diagnostics` needs and release the DashMap shard `Ref`
    // before awaiting it (#333): `with_document` only ever hands `extract` a borrowed
    // `&DocumentState` synchronously, so the guard can't leak across the `.await` below.
    let Some(extracted) = state.with_document(uri, |doc| {
        let Some(ecosystem) = state.ecosystem_registry.get(doc.ecosystem_id()) else {
            tracing::warn!(
                "Ecosystem not found for diagnostics: {}",
                doc.ecosystem_id()
            );
            return None;
        };

        // Skip diagnostics while versions are still loading to avoid
        // false "Unknown package" warnings from empty cache
        if doc.loading_state == deps_core::LoadingState::Loading {
            return None;
        }

        let parse_result = doc.parse_result_arc()?;
        Some((
            ecosystem,
            doc.ecosystem,
            parse_result,
            doc.cached_versions.clone(),
            doc.resolved_versions.clone(),
            doc.vulnerabilities.clone(),
            doc.yanked_versions.clone(),
            doc.deprecations.clone(),
            doc.fetch_failed.clone(),
        ))
    }) else {
        tracing::warn!("Document not found for diagnostics: {:?}", uri);
        return vec![];
    };

    let Some((
        ecosystem,
        ecosystem_id,
        parse_result,
        cached_versions,
        resolved_versions,
        vulnerabilities,
        yanked_versions,
        deprecations,
        fetch_failed,
    )) = extracted
    else {
        return vec![];
    };

    ecosystem
        .generate_diagnostics(
            parse_result.as_ref(),
            VersionData::new(&cached_versions, &resolved_versions)
                .with_vulnerabilities(&vulnerabilities)
                .with_yanked(&yanked_versions)
                .with_deprecations(&deprecations)
                .with_fetch_failed(&fetch_failed)
                .with_ecosystem(ecosystem_id),
            uri,
            freshness,
            severities,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiagnosticsConfig;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;

    // Generic tests (no feature flag required)

    #[tokio::test]
    async fn test_handle_diagnostics_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let config = DiagnosticsConfig::default();

        let (client, full_config) = create_test_client_and_config();
        let result = handle_diagnostics(state, &uri, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    /// #333 liveness regression: `handle_diagnostics` must release the DashMap shard
    /// `Ref` on the document *before* awaiting `Ecosystem::generate_diagnostics`, so a
    /// concurrent `documents.get_mut` on the same URI (e.g. a `didChange`) is never
    /// blocked behind an in-flight (or stuck) diagnostics generation.
    ///
    /// `BlockingEcosystem::generate_diagnostics` waits on a `Barrier` before blocking
    /// forever (`std::future::pending`), standing in for an override that performs real
    /// I/O — the worst case for a shard `Ref` held across the call. The test only
    /// proceeds to race the writer once that future has demonstrably started executing
    /// (via the barrier); a concurrent write racing here must complete almost
    /// immediately, proving the `Ref` was already dropped before the call was awaited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_document_write_not_blocked_by_in_flight_diagnostics() {
        use crate::document::DocumentState;
        use crate::test_utils::blocking_ecosystem::{
            BlockingEcosystem, BlockingHook, MockParseResult,
        };
        use deps_core::ParseResult;
        use tokio::sync::Barrier;

        let state = Arc::new(ServerState::new());
        let started = Arc::new(Barrier::new(2));
        state
            .ecosystem_registry
            .register(Arc::new(BlockingEcosystem {
                started: Arc::clone(&started),
                hook: BlockingHook::Diagnostics,
            }));

        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let config = DiagnosticsConfig::default();
        let (client, full_config) = create_test_client_and_config();

        let handler_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move { handle_diagnostics(state, &uri, &config, client, full_config).await }
        });

        // Block until `generate_diagnostics` has actually started executing — i.e.
        // `handle_diagnostics` has reached (and is now inside) the await — before
        // racing the writer below. Timeout-wrapped so a regression that makes the
        // handler never reach the awaited call fails loudly instead of hanging forever.
        tokio::time::timeout(std::time::Duration::from_secs(5), started.wait())
            .await
            .expect("handle_diagnostics did not reach generate_diagnostics within 5s");

        // Spawned onto its own task (rather than awaited inline) deliberately: see
        // `completion.rs`'s equivalent #319 regression test for why `DashMap::get_mut`
        // needs a real async yield point to race against `tokio::time::timeout`.
        let write_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                state.documents.get_mut(&uri).unwrap().set_loading();
            }
        });
        let write_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), write_task).await;

        handler_task.abort();

        assert!(
            write_result.is_ok(),
            "#333 regression: a concurrent documents.get_mut on the same URI must not \
             block on an in-flight generate_diagnostics call — the DashMap shard Ref \
             must be dropped before the call is awaited, not after it"
        );
    }

    // Severity wiring tests (issue #224): confirm `DiagnosticsConfig`'s
    // outdated/unknown severity fields actually reach the emitted diagnostics,
    // and that default config preserves the pre-existing hardcoded severities.
    #[cfg(feature = "cargo")]
    mod severity_wiring_tests {
        use super::*;
        use crate::document::DocumentState;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::DiagnosticSeverity;

        #[tokio::test]
        async fn test_unknown_package_uses_configured_severity() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig {
                unknown_severity: DiagnosticSeverity::ERROR,
                ..DiagnosticsConfig::default()
            };

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
        }

        #[tokio::test]
        async fn test_unknown_package_default_severity_unchanged() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::WARNING));
        }

        #[tokio::test]
        async fn test_outdated_dependency_uses_configured_severity() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig {
                outdated_severity: DiagnosticSeverity::ERROR,
                ..DiagnosticsConfig::default()
            };

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            // `available` must include the declared "1.0.0" alongside "2.0.0" — a
            // `latest_only` single-element list containing only "2.0.0" would make the
            // declared requirement look unsatisfiable (no published version matches "1.0.0")
            // and fire the mutually-exclusive WARNING instead of this outdated HINT/ERROR.
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "2.0.0".into(),
                    available: std::sync::Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
            assert!(result[0].message.contains("Newer version available"));
        }

        #[tokio::test]
        async fn test_outdated_dependency_default_severity_unchanged() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            // See the sibling test above for why `available` must include "1.0.0", not
            // just "2.0.0".
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "2.0.0".into(),
                    available: std::sync::Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::HINT));
        }

        #[tokio::test]
        async fn test_unsatisfiable_requirement_uses_configured_severity() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig {
                unsatisfiable_severity: DiagnosticSeverity::ERROR,
                ..DiagnosticsConfig::default()
            };

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "1.0.214".into(),
                    available: std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
            assert!(result[0].message.contains("No published version satisfies"));
        }
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_diagnostics_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            assert!(result.is_empty());
        }

        /// End-to-end coverage for issue #206's unsatisfiable-requirement diagnostic,
        /// through the real `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `CargoFormatter::compile_requirement` path
        /// (not just the pure `requirement_is_unsatisfiable` function).
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_requirement_yields_one_warning() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "1.0.214".into(),
                    available: std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1, "expected exactly one diagnostic");
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert!(result[0].message.contains("No published version satisfies"));
            assert!(
                !result
                    .iter()
                    .any(|d| d.message.contains("Newer version available")),
                "the unsatisfiable WARNING must replace the outdated HINT, not add to it"
            );
        }

        /// SC-005: an empty `available` list (still loading, or a registry that never
        /// populated it) must suppress the check entirely rather than treating "nothing
        /// fetched yet" as "nothing published".
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_requirement_empty_available_yields_nothing()
        {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::latest_without_list("1.0.214"),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            assert!(
                !result
                    .iter()
                    .any(|d| d.message.contains("No published version satisfies")),
                "an empty available list must suppress the unsatisfiable check, got: {result:?}"
            );
        }

        /// NFR-004: a satisfiable-but-outdated dependency alongside an unsatisfiable one
        /// must still get its usual "Newer version available" HINT.
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_and_outdated_side_by_side() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"99\"\ntokio = \"1.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "1.0.214".into(),
                    available: std::sync::Arc::from(vec!["1.0.214".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            cached.insert(
                "tokio".into(),
                deps_core::PackageVersions {
                    latest: "2.0.0".into(),
                    // Includes an older version satisfying "1.0" (^1.0) so this dependency
                    // is genuinely outdated-but-satisfiable, not unsatisfiable — an
                    // available list containing only `latest` would make every requirement
                    // that latest doesn't itself satisfy look unsatisfiable.
                    available: std::sync::Arc::from(vec!["2.0.0".into(), "1.5.0".into()]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 2, "expected one warning and one hint");
            assert!(
                result
                    .iter()
                    .any(|d| d.message.contains("No published version satisfies"))
            );
            assert!(
                result
                    .iter()
                    .any(|d| d.message.contains("Newer version available"))
            );
        }

        /// End-to-end coverage for issue #247: a dependency pinned to an exact version that
        /// the registry reports as yanked must produce the yanked diagnostic through the real
        /// `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `CargoFormatter::compile_requirement` path —
        /// the same live path the LSP server actually calls, not just the pure
        /// `requirement_matches_only_yanked` function.
        #[tokio::test]
        async fn test_handle_diagnostics_yanked_only_match_yields_one_warning() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"=1.0.213\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "1.0.214".into(),
                    available: std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                    yanked: std::sync::Arc::from(vec![(
                        "1.0.213".into(),
                        deps_core::RemovalStatus::Yanked,
                    )]),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1, "expected exactly one diagnostic");
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert_eq!(
                result[0].message,
                "This version has been yanked; latest is 1.0.214"
            );
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::EcosystemFormatter;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }

        /// #436 S1 regression: after #436 narrowed npm's fix to only suppress the
        /// manifest-requirement-level yanked diagnostic (`NpmFormatter::yanked_diagnostic_applies_to`
        /// now unconditionally `false`), the independent #263 in-use-version yanked diagnostic
        /// must still fire through the real `DocumentState` -> `Ecosystem::generate_diagnostics`
        /// -> `generate_diagnostics_from_cache` path — the same live path the LSP server
        /// actually calls, using the real `NpmFormatter`/`NpmRegistry`-backed npm ecosystem
        /// (not a generic `MockRegistry`).
        ///
        /// Mirrors the canonical `npm deprecate left-pad@"<1.0.2" "..."` scenario: the
        /// manifest declares a range (`^1.0.0`), `latest` (1.0.2) is clean, but the
        /// lockfile-resolved in-use version (1.0.1) is flagged. This is exactly the coverage
        /// the critic's S1 finding said `Registry::reports_yanked() == false` would have
        /// silently killed had npm's first #436 pass gone unrevised.
        #[tokio::test]
        async fn test_handle_diagnostics_in_use_version_yanked_still_fires_post_436() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"left-pad": "^1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "left-pad".into(),
                deps_core::PackageVersions {
                    latest: "1.0.2".into(),
                    available: std::sync::Arc::from(vec![
                        "1.0.2".into(),
                        "1.0.1".into(),
                        "1.0.0".into(),
                    ]),
                    yanked: std::sync::Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);

            // Lockfile resolves the "^1.0.0" range to the old, flagged 1.0.1 — `latest`
            // itself is clean, so this is only reachable via the lockfile-resolved
            // in-use-version check (#263), not the manifest-requirement check (#247).
            let mut resolved = std::collections::HashMap::new();
            resolved.insert("left-pad".into(), "1.0.1".into());
            doc_state.update_resolved_versions(resolved);

            let mut yanked_versions = std::collections::HashMap::new();
            yanked_versions.insert(
                "left-pad".to_string(),
                ("1.0.1".into(), deps_core::RemovalStatus::AdvisoryDeprecated),
            );
            doc_state.update_yanked_versions(yanked_versions);

            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic, got {result:?}"
            );
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert_eq!(
                result[0].message,
                format!("{} (1.0.1)", deps_npm::NpmFormatter.yanked_message())
            );
        }

        /// #436 S1 companion: the manifest-requirement-level yanked diagnostic (#247) must
        /// stay suppressed for npm even for an exact-pin requirement — the one shape the
        /// pre-#436 restriction still let through. Deliberately isolated from the #263 path
        /// (no `resolved_versions`/`yanked_versions` set) so this proves
        /// `NpmFormatter::yanked_diagnostic_applies_to`'s unconditional `false` is doing real
        /// work here, not merely benefiting from the `yanked_263_diagnostic_pushed` dedup
        /// guard the sibling test above would also satisfy on its own.
        #[tokio::test]
        async fn test_handle_diagnostics_manifest_requirement_yanked_stays_suppressed_for_exact_pin()
         {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            // Bare exact pin (npm's ordinary package.json style, no `=` marker) — the
            // shape `yanked_diagnostic_applies_to` still allowed through pre-#436.
            let content = r#"{"dependencies": {"old-pkg": "1.0.1"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "old-pkg".into(),
                deps_core::PackageVersions {
                    // The pin is satisfiable only by a flagged version — pre-#436, this
                    // exact shape fired the #247 "yanked" diagnostic.
                    latest: "1.0.1".into(),
                    available: std::sync::Arc::from(vec!["1.0.1".into()]),
                    yanked: std::sync::Arc::from(vec![(
                        "1.0.1".into(),
                        deps_core::RemovalStatus::AdvisoryDeprecated,
                    )]),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — the #263 in-use-version path has
            // nothing to match against, isolating this assertion to the #247 path alone.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert!(
                result.is_empty(),
                "expected no diagnostics for an exact pin satisfiable only by a flagged \
                 version — the #247 manifest-requirement diagnostic must stay suppressed for \
                 npm regardless of requirement shape (#436), got {result:?}"
            );
        }
    }

    // Deno-specific tests
    #[cfg(feature = "deno")]
    mod deno_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::EcosystemFormatter;

        /// #448 regression: mirrors npm_tests'
        /// `test_handle_diagnostics_manifest_requirement_yanked_stays_suppressed_for_exact_pin`
        /// through the real `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `DenoFormatter::yanked_diagnostic_applies_to`
        /// path — an exact-pin `npm:` specifier in `deno.json` satisfiable only by a flagged
        /// version must NOT surface the #247 manifest-requirement yanked diagnostic, exactly
        /// like the equivalent `package.json` dependency (fixes the #436 M1 divergence).
        #[tokio::test]
        async fn test_handle_diagnostics_npm_scheme_exact_pin_yanked_stays_suppressed() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/deno.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("deno").unwrap();
            let content = r#"{"imports": {"lodash": "npm:lodash@4.17.20"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "npm:lodash".into(),
                deps_core::PackageVersions {
                    // The pin is satisfiable only by a flagged version — for `package.json`
                    // this exact shape used to fire the #247 "yanked" diagnostic pre-#436.
                    latest: "4.17.20".into(),
                    available: std::sync::Arc::from(vec!["4.17.20".into()]),
                    yanked: std::sync::Arc::from(vec![(
                        "4.17.20".into(),
                        deps_core::RemovalStatus::AdvisoryDeprecated,
                    )]),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — isolates this assertion to the #247
            // manifest-requirement path, same as the npm companion test.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert!(
                result.is_empty(),
                "expected no diagnostics for an exact-pin npm: specifier satisfiable only by a \
                 flagged version — the #247 manifest-requirement diagnostic must stay \
                 suppressed for deno's npm: scheme (#448), got {result:?}"
            );
        }

        /// #448/#454: an exact-pin `jsr:` specifier satisfiable only by a flagged version
        /// fires the #247 diagnostic, proving the scheme split actually discriminates
        /// `jsr:` from `npm:` end-to-end, not just in the isolated
        /// `yanked_diagnostic_applies_to` unit tests.
        #[tokio::test]
        async fn test_handle_diagnostics_jsr_scheme_exact_pin_yanked_still_fires() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/deno.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("deno").unwrap();
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "jsr:@std/fs".into(),
                deps_core::PackageVersions {
                    latest: "1.0.1".into(),
                    available: std::sync::Arc::from(vec!["1.0.1".into(), "1.0.0".into()]),
                    yanked: std::sync::Arc::from(vec![(
                        "1.0.0".into(),
                        deps_core::RemovalStatus::Yanked,
                    )]),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected the #247 diagnostic to still fire for an exact-pin jsr: specifier, \
                 got {result:?}"
            );
            assert_eq!(
                result[0].message,
                format!(
                    "{}; latest is 1.0.1",
                    deps_deno::DenoFormatter.yanked_message()
                )
            );
        }

        /// #454: the actual bug fix, proven end-to-end — a `jsr:` *range* requirement
        /// satisfiable only by yanked versions must now surface the #247
        /// manifest-requirement diagnostic too, matching Cargo/PyPI/Dart's behavior for the
        /// equivalent case (previously this was silent: `yanked_diagnostic_applies_to`
        /// rejected any non-exact-pin `jsr:` requirement). Exactly one diagnostic fires,
        /// confirming this does not double up with any package-level deprecation (#205)
        /// signal — deno has no such diagnostic for `jsr:` in the first place.
        #[tokio::test]
        async fn test_handle_diagnostics_jsr_scheme_range_yanked_only_now_fires() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/deno.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("deno").unwrap();
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "jsr:@std/fs".into(),
                deps_core::PackageVersions {
                    // Every version matching "^1.0.0" is yanked — the concrete #454 bug
                    // scenario, which previously produced zero diagnostic signal.
                    latest: "1.0.1".into(),
                    available: std::sync::Arc::from(vec!["1.0.1".into(), "1.0.0".into()]),
                    yanked: std::sync::Arc::from(vec![
                        ("1.0.1".into(), deps_core::RemovalStatus::Yanked),
                        ("1.0.0".into(), deps_core::RemovalStatus::Yanked),
                    ]),
                    published_at: None,
                },
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — isolates this assertion to the #247
            // manifest-requirement path, same as the sibling exact-pin test.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic for a jsr: range satisfiable only by yanked \
                 versions (#454), got {result:?}"
            );
            assert_eq!(
                result[0].message,
                format!(
                    "{}; latest is 1.0.1",
                    deps_deno::DenoFormatter.yanked_message()
                )
            );
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("pypi").unwrap();
            let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Pypi, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }
}
