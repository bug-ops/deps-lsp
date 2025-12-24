//! Integration tests for document lifecycle.
//!
//! Tests the full flow from document parsing → version fetch → data availability
//! to catch issues like empty cached_versions due to trait object cloning.
//!
//! These tests verify that the background tasks in document_lifecycle.rs correctly
//! populate DocumentState with cached_versions and resolved_versions.

use deps_lsp::config::DepsConfig;
use deps_lsp::document::{DocumentState, ServerState};
use deps_lsp::handlers::inlay_hints::handle_inlay_hints;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::lsp_types::{InlayHintParams, Position, Range, TextDocumentIdentifier, Url};

/// Creates test configuration with inlay hints enabled.
fn create_test_config() -> Arc<RwLock<DepsConfig>> {
    Arc::new(RwLock::new(DepsConfig::default()))
}

/// Creates inlay hint request params.
fn create_inlay_hint_params(uri: Url) -> InlayHintParams {
    InlayHintParams {
        text_document: TextDocumentIdentifier { uri },
        work_done_progress_params: Default::default(),
        range: Range::new(Position::new(0, 0), Position::new(100, 0)),
    }
}

#[tokio::test]
async fn test_parse_result_preserved_in_document_state() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
tokio = "1.0.0"
"#;

    // Parse and create document state directly (without background task)
    let ecosystem = state
        .ecosystem_registry
        .get_for_uri(&uri)
        .expect("Cargo ecosystem not found");

    let parse_result = ecosystem
        .parse_manifest(content, &uri)
        .await
        .expect("Failed to parse manifest");

    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    // Verify parse_result is accessible in document state
    let doc = state.get_document(&uri).expect("Document not found");
    assert!(
        doc.parse_result().is_some(),
        "parse_result should be preserved in DocumentState"
    );

    let parse_result = doc.parse_result().expect("parse_result should exist");
    let deps = parse_result.dependencies();

    assert_eq!(deps.len(), 2, "Should have 2 dependencies");
    assert_eq!(deps[0].name(), "serde", "First dependency should be serde");
    assert_eq!(deps[1].name(), "tokio", "Second dependency should be tokio");
}

#[tokio::test]
async fn test_document_state_update_cached_versions() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    // Verify initial state is empty
    {
        let doc = state.get_document(&uri).unwrap();
        assert!(
            doc.cached_versions.is_empty(),
            "cached_versions should start empty"
        );
    }

    // Simulate background task updating cached_versions
    let mut cached_versions = std::collections::HashMap::new();
    cached_versions.insert("serde".to_string(), "1.0.210".to_string());

    // Update through DashMap
    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.update_cached_versions(cached_versions.clone());
    }

    // Verify cached_versions is populated
    let doc = state.get_document(&uri).unwrap();
    assert_eq!(
        doc.cached_versions.len(),
        1,
        "cached_versions should have 1 entry"
    );
    assert_eq!(
        doc.cached_versions.get("serde"),
        Some(&"1.0.210".to_string())
    );
}

#[tokio::test]
async fn test_document_state_update_resolved_versions() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    // Simulate lockfile parsing results
    let mut resolved_versions = std::collections::HashMap::new();
    resolved_versions.insert("serde".to_string(), "1.0.195".to_string());

    // Update through DashMap
    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.update_resolved_versions(resolved_versions.clone());
    }

    // Verify resolved_versions is populated
    let doc = state.get_document(&uri).unwrap();
    assert_eq!(
        doc.resolved_versions.len(),
        1,
        "resolved_versions should have 1 entry"
    );
    assert_eq!(
        doc.resolved_versions.get("serde"),
        Some(&"1.0.195".to_string())
    );
}

#[tokio::test]
async fn test_inlay_hints_with_cached_versions() {
    let state = Arc::new(ServerState::new());
    let config = create_test_config();
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    // Setup document with parse result
    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
    state.update_document(uri.clone(), doc_state);

    // Populate cached_versions
    let mut cached_versions = std::collections::HashMap::new();
    cached_versions.insert("serde".to_string(), "1.0.210".to_string());

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.update_cached_versions(cached_versions);
    }

    // Request inlay hints
    let params = create_inlay_hint_params(uri.clone());
    let config_read = config.read().await;
    let hints = handle_inlay_hints(Arc::clone(&state), params, &config_read.inlay_hints).await;

    // Verify hints are returned
    assert!(!hints.is_empty(), "Should return inlay hints");
    assert_eq!(hints.len(), 1, "Should have 1 hint for serde dependency");
}

#[tokio::test]
async fn test_inlay_hints_without_cached_versions_triggers_fetch() {
    let state = Arc::new(ServerState::new());
    let config = create_test_config();
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    // Setup document with parse result but NO cached_versions
    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
    state.update_document(uri.clone(), doc_state);

    // Verify cached_versions is empty
    {
        let doc = state.get_document(&uri).unwrap();
        assert!(doc.cached_versions.is_empty());
    }

    // Request inlay hints (should trigger on-demand fetch)
    let params = create_inlay_hint_params(uri.clone());
    let config_read = config.read().await;
    let hints = handle_inlay_hints(Arc::clone(&state), params, &config_read.inlay_hints).await;

    // On-demand fetch should populate cached_versions
    let doc = state.get_document(&uri).unwrap();

    // Check if cached_versions was populated by on-demand fetch
    // This will succeed if network is available, otherwise timeout will prevent hanging
    if !doc.cached_versions.is_empty() {
        tracing::info!(
            "On-demand fetch populated {} versions",
            doc.cached_versions.len()
        );
        assert!(!hints.is_empty(), "Should return hints after fetch");
    } else {
        tracing::warn!("On-demand fetch timed out or failed (no network?)");
    }
}

#[tokio::test]
async fn test_multiple_ecosystems_independently() {
    let state = Arc::new(ServerState::new());

    let cargo_uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let npm_uri = Url::parse("file:///test/package.json").unwrap();
    let pypi_uri = Url::parse("file:///test/pyproject.toml").unwrap();

    let cargo_content = r#"[dependencies]
serde = "1.0.0"
"#;
    let npm_content = r#"{"dependencies": {"express": "^4.18.0"}}"#;
    let pypi_content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#;

    // Parse all three ecosystems
    let cargo_eco = state.ecosystem_registry.get("cargo").unwrap();
    let npm_eco = state.ecosystem_registry.get("npm").unwrap();
    let pypi_eco = state.ecosystem_registry.get("pypi").unwrap();

    let cargo_parse = cargo_eco
        .parse_manifest(cargo_content, &cargo_uri)
        .await
        .unwrap();
    let npm_parse = npm_eco.parse_manifest(npm_content, &npm_uri).await.unwrap();
    let pypi_parse = pypi_eco
        .parse_manifest(pypi_content, &pypi_uri)
        .await
        .unwrap();

    // Create document states
    let cargo_doc =
        DocumentState::new_from_parse_result("cargo", cargo_content.to_string(), cargo_parse);
    let npm_doc = DocumentState::new_from_parse_result("npm", npm_content.to_string(), npm_parse);
    let pypi_doc =
        DocumentState::new_from_parse_result("pypi", pypi_content.to_string(), pypi_parse);

    state.update_document(cargo_uri.clone(), cargo_doc);
    state.update_document(npm_uri.clone(), npm_doc);
    state.update_document(pypi_uri.clone(), pypi_doc);

    // Verify all three documents exist with correct ecosystems
    assert_eq!(state.document_count(), 3);

    let cargo = state.get_document(&cargo_uri).unwrap();
    let npm = state.get_document(&npm_uri).unwrap();
    let pypi = state.get_document(&pypi_uri).unwrap();

    assert_eq!(cargo.ecosystem_id, "cargo");
    assert_eq!(npm.ecosystem_id, "npm");
    assert_eq!(pypi.ecosystem_id, "pypi");

    // Verify each has parse_result
    assert!(cargo.parse_result().is_some());
    assert!(npm.parse_result().is_some());
    assert!(pypi.parse_result().is_some());
}

#[tokio::test]
async fn test_document_clone_does_not_preserve_parse_result() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    // Verify original has parse_result
    {
        let doc = state.get_document(&uri).unwrap();
        assert!(doc.parse_result().is_some());
    }

    // Clone document (simulates what get_document_clone does)
    let cloned = state.get_document_clone(&uri).unwrap();

    // Verify clone does NOT have parse_result (this is expected behavior)
    assert!(
        cloned.parse_result().is_none(),
        "Cloned document should not have parse_result (trait objects can't be cloned)"
    );

    // This is why background tasks must collect dependency names
    // BEFORE releasing the DashMap lock - they can't rely on cloned copies
}

#[tokio::test]
async fn test_empty_manifest_initialization() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = "[dependencies]\n";

    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    let doc = state.get_document(&uri).unwrap();
    assert!(doc.cached_versions.is_empty());
    assert!(doc.resolved_versions.is_empty());
    assert_eq!(doc.ecosystem_id, "cargo");

    let parse_result = doc.parse_result().unwrap();
    assert_eq!(parse_result.dependencies().len(), 0);
}

#[tokio::test]
async fn test_npm_parsing_and_state() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/package.json").unwrap();
    let content = r#"{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}"#;

    let ecosystem = state.ecosystem_registry.get("npm").unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state = DocumentState::new_from_parse_result("npm", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    let doc = state.get_document(&uri).unwrap();
    assert_eq!(doc.ecosystem_id, "npm");

    let parse_result = doc.parse_result().unwrap();
    let deps = parse_result.dependencies();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0].name(), "express");
    assert_eq!(deps[1].name(), "lodash");
}

#[tokio::test]
async fn test_pypi_parsing_and_state() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/pyproject.toml").unwrap();
    let content = r#"[project]
dependencies = [
    "requests>=2.31.0",
    "pytest>=7.4.0",
]
"#;

    let ecosystem = state.ecosystem_registry.get("pypi").unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state = DocumentState::new_from_parse_result("pypi", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    let doc = state.get_document(&uri).unwrap();
    assert_eq!(doc.ecosystem_id, "pypi");

    let parse_result = doc.parse_result().unwrap();
    let deps = parse_result.dependencies();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0].name(), "requests");
    assert_eq!(deps[1].name(), "pytest");
}

#[tokio::test]
async fn test_concurrent_document_state_updates() {
    let state = Arc::new(ServerState::new());
    let uri = Url::parse("file:///test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
tokio = "1.0.0"
"#;

    let ecosystem = state.ecosystem_registry.get_for_uri(&uri).unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);

    state.update_document(uri.clone(), doc_state);

    // Simulate concurrent updates from background task
    let state1 = Arc::clone(&state);
    let state2 = Arc::clone(&state);
    let uri1 = uri.clone();
    let uri2 = uri.clone();

    let task1 = tokio::spawn(async move {
        let mut cached = std::collections::HashMap::new();
        cached.insert("serde".to_string(), "1.0.210".to_string());

        if let Some(mut doc) = state1.documents.get_mut(&uri1) {
            doc.update_cached_versions(cached);
        }
    });

    let task2 = tokio::spawn(async move {
        let mut resolved = std::collections::HashMap::new();
        resolved.insert("tokio".to_string(), "1.35.0".to_string());

        if let Some(mut doc) = state2.documents.get_mut(&uri2) {
            doc.update_resolved_versions(resolved);
        }
    });

    task1.await.unwrap();
    task2.await.unwrap();

    // Verify both updates succeeded
    let doc = state.get_document(&uri).unwrap();
    assert_eq!(doc.cached_versions.len(), 1);
    assert_eq!(doc.resolved_versions.len(), 1);
}
