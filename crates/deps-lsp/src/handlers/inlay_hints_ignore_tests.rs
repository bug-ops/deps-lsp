//! `diagnostics.ignore` never hides an OSV-flagged inlay hint (#1967, spec 094 FR-010): only
//! the plain version label is dropped, never an in-use advisory flag or a flagged latest.

#![cfg(all(test, feature = "cargo"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::test_utils::test_helpers::{ADVISORY_ID, advisory_state, create_test_client_and_config};
use deps_core::ConcreteVersion;
use deps_core::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

fn labels(hints: &[InlayHint]) -> Vec<String> {
    hints
        .iter()
        .map(|hint| match &hint.label {
            tower_lsp_server::ls_types::InlayHintLabel::String(label) => label.clone(),
            tower_lsp_server::ls_types::InlayHintLabel::LabelParts(_) => String::new(),
        })
        .collect()
}

async fn hints_with_ignore(
    state: Arc<ServerState>,
    uri: tower_lsp_server::ls_types::Uri,
) -> Vec<InlayHint> {
    let (client, config) = create_test_client_and_config();
    config.write().await.policy.diagnostics =
        serde_json::from_value(serde_json::json!({"ignore": ["serde"]})).unwrap();
    let params = InlayHintParams {
        text_document: tower_lsp_server::ls_types::TextDocumentIdentifier { uri },
        work_done_progress_params: Default::default(),
        range: tower_lsp_server::ls_types::Range::new(
            tower_lsp_server::ls_types::Position::new(0, 0),
            tower_lsp_server::ls_types::Position::new(10, 0),
        ),
    };
    let inlay = config.read().await.inlay_hints.clone();
    handle_inlay_hints(state, params, &inlay, client, config).await
}

#[tokio::test]
async fn ignored_package_keeps_its_in_use_advisory_flag() {
    let (state, uri) = advisory_state().await;
    let hints = hints_with_ignore(state, uri).await;
    let labels = labels(&hints);
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert!(labels[0].starts_with('\u{26a0}'), "{labels:?}");
    let tooltip = format!("{:?}", hints[0].tooltip);
    assert!(tooltip.contains(ADVISORY_ID), "{tooltip}");
}

#[tokio::test]
async fn ignored_package_keeps_its_flagged_latest_hint() {
    let (state, uri) = advisory_state().await;
    {
        let mut doc = state.documents.get_mut(&uri).expect("document");
        doc.signals.vulnerabilities.clear();
        let mut status = LatestStatusMap::new();
        status.insert(
            deps_core::test_util::vuln_key("serde"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.0.5"),
                advisory_ids: Capped::new(vec![deps_core::test_util::osv_id(ADVISORY_ID)], 1),
                worst_severity: Some(VulnSeverity::High),
                via_sibling_tags: None,
            },
        );
        doc.signals.latest_status = status;
    }
    let hints = hints_with_ignore(state, uri).await;
    let labels = labels(&hints);
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert!(labels[0].contains("flagged"), "{labels:?}");
}

#[tokio::test]
async fn ignored_clean_package_shows_no_hint() {
    let (state, uri) = advisory_state().await;
    state
        .documents
        .get_mut(&uri)
        .expect("document")
        .signals
        .vulnerabilities
        .clear();
    assert!(hints_with_ignore(state, uri).await.is_empty());
}
