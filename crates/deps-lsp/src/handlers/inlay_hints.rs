//! Inlay hints handler using ecosystem trait delegation.
//!
//! This handler uses the ecosystem registry to delegate inlay hint generation
//! to the appropriate ecosystem implementation.

use crate::config::{DepsConfig, InlayHintsConfig};
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::{EcosystemConfig, VersionData};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{InlayHint, InlayHintParams};

/// Handles inlay hint requests using trait-based delegation.
///
/// Returns version status hints for all registry dependencies in the document.
/// Gracefully degrades by returning empty vec on any errors.
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
    client: Client,
    full_config: Arc<RwLock<DepsConfig>>,
) -> Vec<InlayHint> {
    if !config.enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&full_config)).await {
        tracing::warn!("Could not load document for inlay hints: {:?}", uri);
        return vec![];
    }

    // Snapshot config before the document lookup (Copy value, no lock held across the call)
    let loading_config = { full_config.read().await.loading_indicator.clone() };

    // Own everything `generate_inlay_hints` needs and release the DashMap shard `Ref`
    // before awaiting it (#333): `with_document` only ever hands `extract` a borrowed
    // `&DocumentState` synchronously, so the guard can't leak across the `.await` below.
    let Some(extracted) = state.with_document(uri, |doc| {
        let Some(ecosystem) = state.ecosystem_registry.get(doc.ecosystem_id()) else {
            tracing::warn!("Ecosystem not found: {}", doc.ecosystem_id());
            return None;
        };
        let parse_result = doc.parse_result_arc()?;
        Some((
            ecosystem,
            parse_result,
            doc.cached_versions.clone(),
            doc.resolved_versions.clone(),
            doc.loading_state,
        ))
    }) else {
        tracing::warn!("Document not found: {:?}", uri);
        return vec![];
    };

    let Some((ecosystem, parse_result, cached_versions, resolved_versions, loading_state)) =
        extracted
    else {
        return vec![];
    };

    let ecosystem_config = EcosystemConfig {
        show_up_to_date_hints: true,
        up_to_date_text: config.up_to_date_text.clone(),
        needs_update_text: config.needs_update_text.clone(),
        loading_text: loading_config.loading_text,
        show_loading_hints: loading_config.enabled && loading_config.fallback_to_hints,
    };

    ecosystem
        .generate_inlay_hints(
            parse_result.as_ref(),
            VersionData::new(&cached_versions, &resolved_versions),
            loading_state,
            &ecosystem_config,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::TextDocumentIdentifier;

    // Generic tests (no feature flag required)

    #[test]
    fn test_handle_inlay_hints_disabled() {
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        assert!(!config.enabled);
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_disabled_returns_empty() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(100, 0),
            ),
        };

        let (client, full_config) = create_test_client_and_config();
        let result = handle_inlay_hints(state, params, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(100, 0),
            ),
        };

        let (client, full_config) = create_test_client_and_config();
        let result = handle_inlay_hints(state, params, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    /// #333 liveness regression: `handle_inlay_hints` must release the DashMap shard
    /// `Ref` on the document *before* awaiting `Ecosystem::generate_inlay_hints`, so a
    /// concurrent `documents.get_mut` on the same URI (e.g. a `didChange`) is never
    /// blocked behind an in-flight (or stuck) hint generation.
    ///
    /// `BlockingEcosystem::generate_inlay_hints` waits on a `Barrier` before blocking
    /// forever (`std::future::pending`), standing in for an override that performs real
    /// I/O — the worst case for a shard `Ref` held across the call. The test only
    /// proceeds to race the writer once that future has demonstrably started executing
    /// (via the barrier); a concurrent write racing here must complete almost
    /// immediately, proving the `Ref` was already dropped before the call was awaited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_document_write_not_blocked_by_in_flight_inlay_hints() {
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
                hook: BlockingHook::InlayHints,
            }));

        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = crate::document::DocumentState::new_from_parse_result(
            EcosystemId::Cargo,
            content,
            parse_result,
        );
        state.update_document(uri.clone(), doc);

        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "up to date".to_string(),
            needs_update_text: "outdated: {}".to_string(),
        };
        let (client, full_config) = create_test_client_and_config();

        let handler_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                let params = InlayHintParams {
                    text_document: TextDocumentIdentifier { uri },
                    work_done_progress_params: Default::default(),
                    range: tower_lsp_server::ls_types::Range::new(
                        tower_lsp_server::ls_types::Position::new(0, 0),
                        tower_lsp_server::ls_types::Position::new(100, 0),
                    ),
                };
                handle_inlay_hints(state, params, &config, client, full_config).await
            }
        });

        // Block until `generate_inlay_hints` has actually started executing —
        // i.e. `handle_inlay_hints` has reached (and is now inside) the await — before
        // racing the writer below. Timeout-wrapped so a regression that makes the
        // handler never reach the awaited call fails loudly instead of hanging forever.
        tokio::time::timeout(std::time::Duration::from_secs(5), started.wait())
            .await
            .expect("handle_inlay_hints did not reach generate_inlay_hints within 5s");

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
             block on an in-flight generate_inlay_hints call — the DashMap shard Ref \
             must be dropped before the call is awaited, not after it"
        );
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_inlay_hints_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let result = handle_inlay_hints(state, params, &config, client, full_config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_inlay_hints_custom_config() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "OK".to_string(),
                needs_update_text: "UPDATE: {}".to_string(),
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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }
}
