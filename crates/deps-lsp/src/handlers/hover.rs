//! Hover handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{PrefetchVisibility, ServerState, ensure_document_loaded};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
#[tracing::instrument(
    skip(state, params, client, config),
    fields(uri = ?params.text_document_position_params.text_document.uri, ecosystem = tracing::field::Empty)
)]
pub async fn handle_hover(
    state: Arc<ServerState>,
    params: HoverParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&config)).await {
        tracing::warn!("Could not load document for hover: {:?}", uri);
        return None;
    }

    // Acquires the config RwLock before the DashMap shard guard, never the reverse (matches diagnostics.rs).
    let (freshness, offline, supply_chain_enabled, gossip_enabled) = {
        let config = config.read().await;
        (
            config.policy.freshness.to_settings(),
            config.policy.network.offline,
            config.policy.supply_chain.enabled,
            config.policy.gossip.enabled,
        )
    };

    // Release the DashMap shard `Ref` before awaiting `generate_hover`'s registry fetch —
    // holding it across the await would block a concurrent `documents.get_mut` on the same
    // shard (#319); `with_document` makes this structural rather than a convention (#333).
    // Issue #1456, spec 072: `gossip_visibility` is resolved to `Suppress` (rather than
    // simply omitting the dimension) so a disabled or offline transition stops rendering a
    // previously-populated `gossip_findings` map immediately, not merely stops refreshing it.
    let gossip_visibility = if gossip_enabled && !offline {
        PrefetchVisibility::Render
    } else {
        PrefetchVisibility::Suppress
    };
    let (ecosystem, ecosystem_id, parse_result, snapshot) = state
        .with_document(uri, |doc| {
            let ecosystem = state.ecosystem_registry.get(doc.ecosystem)?;
            let parse_result = doc.parse_result_arc()?;
            let snapshot = doc
                .signals
                .snapshot()
                .with_resolved_version_candidates()
                .with_vulnerabilities()
                .with_outcomes()
                .with_license_prefetch()
                .with_gossip_prefetch(gossip_visibility)
                .finish();
            Some((ecosystem, doc.ecosystem, parse_result, snapshot))
        })
        .flatten()?;

    tracing::Span::current().record("ecosystem", ecosystem_id.id());

    let mut versions = snapshot
        .version_data()
        .with_ecosystem(ecosystem_id)
        .with_offline(offline)
        .with_license_source(ecosystem.license_source());
    // The only call site that sets `VersionData::trust` (see lsp_helpers::hover docs) —
    // makes the supply-chain trust signal hover-only by construction (FR-010).
    if supply_chain_enabled {
        versions = versions.with_trust(&state.deps_dev);
    }
    // Issue #1456, spec 072 FR-009: a separate gate from `supply_chain_enabled` above —
    // see `VersionData::gossip_client`'s doc for why the two must not be conflated.
    if gossip_enabled && !offline {
        versions = versions.with_gossip_client(&state.deps_dev);
    }

    ecosystem
        .generate_hover(parse_result.as_ref(), position, versions, freshness)
        .await
        .map(crate::lsp_types_interop::to_lsp_hover)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    #[cfg(any(feature = "cargo", feature = "npm"))]
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    #[tokio::test]
    async fn test_handle_hover_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));
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

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_hover() {
            // Held per fs_probe::snapshot_guard's doc: parse_manifest touches fs_probe and
            // this test shares a binary with document/loader.rs's diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
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
        }

        #[tokio::test]
        async fn test_handle_hover_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

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

    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_hover() {
            // See the comment in `test_handle_hover` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Npm)
                .unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
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
        }
    }
}
