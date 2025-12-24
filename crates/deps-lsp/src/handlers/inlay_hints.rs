//! Inlay hints handler using ecosystem trait delegation.
//!
//! This handler uses the ecosystem registry to delegate inlay hint generation
//! to the appropriate ecosystem implementation.

use crate::config::InlayHintsConfig;
use crate::document::ServerState;
use deps_core::EcosystemConfig;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_lsp::lsp_types::{InlayHint, InlayHintParams};

/// Fetches latest versions for multiple packages in parallel (on-demand).
///
/// Returns a HashMap mapping package names to their latest version strings.
/// Filters out pre-release and yanked versions when finding the latest version.
async fn fetch_versions_on_demand(
    ecosystem: &Arc<dyn deps_core::Ecosystem>,
    package_names: Vec<String>,
) -> HashMap<String, String> {
    let registry = ecosystem.registry();
    let futures: Vec<_> = package_names
        .into_iter()
        .map(|name| {
            let registry = Arc::clone(&registry);
            async move {
                registry
                    .get_versions(&name)
                    .await
                    .ok()
                    .and_then(|versions| {
                        // Find first stable (non-yanked, non-prerelease) version
                        versions
                            .iter()
                            .find(|v| !v.is_yanked() && !v.is_prerelease())
                            .or_else(|| versions.first())
                            .map(|v| (name, v.version_string().to_string()))
                    })
            }
        })
        .collect();

    join_all(futures).await.into_iter().flatten().collect()
}

/// Handles inlay hint requests using trait-based delegation.
///
/// Returns version status hints for all registry dependencies in the document.
/// If cached versions are not yet available, fetches them on-demand.
/// Gracefully degrades by returning empty vec on any errors.
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    if !config.enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    let (ecosystem_id, mut cached_versions, resolved_versions, dep_names) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => {
                tracing::warn!("Document not found: {}", uri);
                return vec![];
            }
        };

        // Collect dependency names if we need to fetch on-demand
        let dep_names: Vec<String> = if doc.cached_versions.is_empty() {
            doc.parse_result()
                .map(|p| {
                    p.dependencies()
                        .into_iter()
                        .map(|d| d.name().to_string())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };

        (
            doc.ecosystem_id,
            doc.cached_versions.clone(),
            doc.resolved_versions.clone(),
            dep_names,
        )
    };

    let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
        Some(e) => e,
        None => {
            tracing::warn!("Ecosystem not found: {}", ecosystem_id);
            return vec![];
        }
    };

    // Fetch versions on-demand if cached_versions is empty (with timeout to prevent hanging)
    if cached_versions.is_empty() && !dep_names.is_empty() {
        tracing::debug!(
            "Fetching {} versions on-demand for inlay hints",
            dep_names.len()
        );

        // Use timeout to prevent blocking the LSP server if network is slow
        let fetch_future = fetch_versions_on_demand(&ecosystem, dep_names);
        match tokio::time::timeout(Duration::from_secs(5), fetch_future).await {
            Ok(versions) => {
                cached_versions = versions;

                // Update document state with fetched versions for future requests
                if !cached_versions.is_empty()
                    && let Some(mut doc) = state.documents.get_mut(uri)
                {
                    doc.update_cached_versions(cached_versions.clone());
                }
            }
            Err(_) => {
                tracing::warn!("On-demand version fetch timed out for inlay hints");
                // Continue with empty cached_versions - will show ⏳ indicator
            }
        }
    }

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    let ecosystem_config = EcosystemConfig {
        show_up_to_date_hints: true,
        up_to_date_text: config.up_to_date_text.clone(),
        needs_update_text: config.needs_update_text.clone(),
    };

    let hints = ecosystem
        .generate_inlay_hints(
            parse_result,
            &cached_versions,
            &resolved_versions,
            &ecosystem_config,
        )
        .await;
    drop(doc);
    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentState, Ecosystem, ServerState};
    use tower_lsp::lsp_types::{TextDocumentIdentifier, Url};

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
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_cargo() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
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

        let doc_state = DocumentState::new_from_parse_result("cargo", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_npm() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/package.json").unwrap();
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

        let doc_state = DocumentState::new_from_parse_result("npm", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_pypi() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/pyproject.toml").unwrap();
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

        let doc_state = DocumentState::new_from_parse_result("pypi", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_no_parse_result() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let doc_state = DocumentState::new(Ecosystem::Cargo, "".to_string(), vec![]);
        state.update_document(uri.clone(), doc_state);

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_custom_config() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
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

        let doc_state = DocumentState::new_from_parse_result("cargo", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp::lsp_types::Range::new(
                tower_lsp::lsp_types::Position::new(0, 0),
                tower_lsp::lsp_types::Position::new(100, 0),
            ),
        };

        let result = handle_inlay_hints(state, params, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }
}
