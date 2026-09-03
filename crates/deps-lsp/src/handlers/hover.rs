//! Hover handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
pub async fn handle_hover(
    state: Arc<ServerState>,
    params: HoverParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&config)).await {
        tracing::warn!("Could not load document for hover: {:?}", uri);
        return None;
    }

    // Snapshot before the document lookup, matching diagnostics.rs's ordering — this
    // acquires the config RwLock before the DashMap shard guard, never the reverse.
    let (freshness, offline, supply_chain_enabled) = {
        let config = config.read().await;
        (
            config.freshness.to_settings(),
            config.network.offline,
            config.supply_chain.enabled,
        )
    };

    // Own everything `generate_hover` needs and release the DashMap shard `Ref`
    // before awaiting it: the default impl awaits a real registry fetch
    // (`Registry::get_versions_with`), so holding the guard across that await would
    // block a concurrent `documents.get_mut` on the same shard for the duration (#319).
    // `with_document` makes this structural rather than a convention to remember (#333).
    let (
        ecosystem,
        ecosystem_id,
        parse_result,
        cached_versions,
        resolved_versions,
        vulnerabilities,
        outcomes,
    ) = state
        .with_document(uri, |doc| {
            let ecosystem = state.ecosystem_registry.get(doc.ecosystem_id())?;
            let parse_result = doc.parse_result_arc()?;
            Some((
                ecosystem,
                doc.ecosystem,
                parse_result,
                doc.cached_versions.clone(),
                doc.resolved_versions.clone(),
                doc.vulnerabilities.clone(),
                doc.outcomes.clone(),
            ))
        })
        .flatten()?;

    let mut versions = VersionData::new(&cached_versions, &resolved_versions)
        .with_vulnerabilities(&vulnerabilities)
        .with_outcomes(&outcomes)
        .with_ecosystem(ecosystem_id)
        .with_offline(offline);
    // The only call site that ever sets `VersionData::trust` (deps-core's
    // `lsp_helpers::hover` module docs) — this is what makes the supply-chain
    // trust signal hover-only by construction (FR-010): diagnostics, code
    // actions, inlay hints, and code lenses never reach this code path.
    if supply_chain_enabled {
        versions = versions.with_trust(&state.deps_dev);
    }

    ecosystem
        .generate_hover(parse_result.as_ref(), position, versions, freshness)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    // Generic tests (no feature flag required)

    #[tokio::test]
    async fn test_handle_hover_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let (client, config) = create_test_client_and_config();

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params, client, config).await;
        assert!(result.is_none());
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_hover() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

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

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(1, 0),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_hover(state, params, client, config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_hover_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 0),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let result = handle_hover(state, params, client, config).await;
            assert!(result.is_none());
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_hover() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 20),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_hover(state, params, client, config).await;
            // Test passes if no panic occurs
        }
    }
}
