//! Document link handler using ecosystem trait delegation.
//!
//! Purely local (no registry access, no `versions`/`freshness` inputs) — see
//! `Ecosystem::generate_document_links`, whose default is an empty `Vec` for
//! every ecosystem that has no intra-manifest file references. PyPI is
//! currently the only implementor, surfacing pip's `-r`/`-c` targets.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{DocumentLink, DocumentLinkParams};

/// Handles `textDocument/documentLink` requests using trait-based delegation.
pub async fn handle_document_link(
    state: Arc<ServerState>,
    params: DocumentLinkParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Vec<DocumentLink> {
    let uri = &params.text_document.uri;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, config).await {
        tracing::warn!("Could not load document for document link: {:?}", uri);
        return vec![];
    }

    // Release the DashMap shard `Ref` before calling out to the ecosystem (#333):
    // `generate_document_links` is synchronous today, but keeping the same
    // own-then-release shape as the other handlers avoids reintroducing the
    // shard-blocking bug if it ever grows an async fast path.
    let Some((ecosystem, parse_result)) = state
        .with_document(uri, |doc| {
            let ecosystem = state.ecosystem_registry.get(doc.ecosystem_id())?;
            let parse_result = doc.parse_result_arc()?;
            Some((ecosystem, parse_result))
        })
        .flatten()
    else {
        return vec![];
    };

    ecosystem.generate_document_links(parse_result.as_ref(), uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::TextDocumentIdentifier;

    #[tokio::test]
    async fn test_handle_document_link_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/requirements.txt");
        let (client, config) = create_test_client_and_config();

        let params = DocumentLinkParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let result = handle_document_link(state, params, client, config).await;
        assert!(result.is_empty());
    }

    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::EcosystemId;

        #[tokio::test]
        async fn test_handle_document_link_requirements_reference() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/requirements.txt");

            let ecosystem = state.ecosystem_registry.get("pypi").unwrap();
            let content = "-r other-requirements.txt\nrequests==2.31.0\n".to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Pypi, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let params = DocumentLinkParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let links = handle_document_link(state, params, client, config).await;

            assert_eq!(links.len(), 1);
            let target = links[0].target.as_ref().expect("link must have a target");
            assert!(
                target
                    .path()
                    .as_str()
                    .ends_with("/test/other-requirements.txt")
            );
        }
    }
}
