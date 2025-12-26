//! End-to-end integration tests for loading indicator feature.
//!
//! Tests the complete flow from document open through loading state
//! transitions to final hint display across all ecosystems.

use deps_lsp::config::{DepsConfig, LoadingIndicatorConfig};
use deps_lsp::document::{DocumentState, LoadingState, ServerState};
use std::sync::Arc;
use std::time::Duration;
use tower_lsp_server::ls_types::Uri;

/// Test loading state lifecycle for Cargo ecosystem.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn test_loading_state_lifecycle_cargo() {
    let state = Arc::new(ServerState::new());
    let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
    let content = r#"[dependencies]
serde = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
"#;

    let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
    let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

    // Phase 1: Initial state - document created with Idle loading state
    let doc = DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
    assert_eq!(doc.loading_state, LoadingState::Idle);
    assert!(doc.loading_started_at.is_none());
    state.update_document(uri.clone(), doc);

    // Phase 2: Simulate loading - transition to Loading state
    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.set_loading();
        assert_eq!(doc.loading_state, LoadingState::Loading);
        assert!(doc.loading_started_at.is_some());
    }

    // Phase 3: Simulate successful load - wait briefly then mark loaded
    tokio::time::sleep(Duration::from_millis(10)).await;

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        doc.set_loaded();
        assert_eq!(doc.loading_state, LoadingState::Loaded);
        assert!(doc.loading_started_at.is_none());
    }

    // Phase 4: Verify final state - document is fully loaded
    let doc = state.get_document(&uri).unwrap();
    assert_eq!(doc.loading_state, LoadingState::Loaded);
}

/// Test configuration integration with loading indicator.
#[test]
fn test_loading_indicator_config_integration() {
    let config_json = r#"{
        "loading_indicator": {
            "enabled": true,
            "fallback_to_hints": true,
            "loading_text": "🔄"
        },
        "inlay_hints": {
            "enabled": true,
            "up_to_date_text": "✅",
            "needs_update_text": "❌ {}"
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert!(config.loading_indicator.enabled);
    assert!(config.loading_indicator.fallback_to_hints);
    assert_eq!(config.loading_indicator.loading_text, "🔄");
    assert!(config.inlay_hints.enabled);
}

/// Test disabled loading indicator configuration.
#[test]
fn test_loading_indicator_disabled() {
    let config_json = r#"{
        "loading_indicator": {
            "enabled": false
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert!(!config.loading_indicator.enabled);
    // Other fields should have defaults
    assert!(config.loading_indicator.fallback_to_hints);
    assert_eq!(config.loading_indicator.loading_text, "⏳");
}

/// Test custom loading text configuration.
#[test]
fn test_custom_loading_text() {
    let config_json = r#"{
        "loading_indicator": {
            "loading_text": "Loading..."
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert_eq!(config.loading_indicator.loading_text, "Loading...");
}

/// Test progress only mode (fallback disabled).
#[test]
fn test_progress_only_mode() {
    let config_json = r#"{
        "loading_indicator": {
            "enabled": true,
            "fallback_to_hints": false
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert!(config.loading_indicator.enabled);
    assert!(!config.loading_indicator.fallback_to_hints);
}

/// Test concurrent loading for multiple documents.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn test_concurrent_loading_multiple_documents() {
    let state = Arc::new(ServerState::new());

    let uri1 = Uri::from_file_path("/test/Cargo1.toml").unwrap();
    let uri2 = Uri::from_file_path("/test/Cargo2.toml").unwrap();

    let content = r#"[dependencies]
serde = "1.0.0"
"#;

    let ecosystem = state.ecosystem_registry.get("cargo").unwrap();

    // Create two documents
    let parse1 = ecosystem.parse_manifest(content, &uri1).await.unwrap();
    let parse2 = ecosystem.parse_manifest(content, &uri2).await.unwrap();

    let mut doc1 = DocumentState::new_from_parse_result("cargo", content.to_string(), parse1);
    let mut doc2 = DocumentState::new_from_parse_result("cargo", content.to_string(), parse2);

    // Both start loading
    doc1.set_loading();
    doc2.set_loading();

    state.update_document(uri1.clone(), doc1);
    state.update_document(uri2.clone(), doc2);

    // Verify both are loading
    assert_eq!(
        state.get_document(&uri1).unwrap().loading_state,
        LoadingState::Loading
    );
    assert_eq!(
        state.get_document(&uri2).unwrap().loading_state,
        LoadingState::Loading
    );

    // Simulate doc1 finishes first
    if let Some(mut doc) = state.documents.get_mut(&uri1) {
        doc.set_loaded();
    }

    // Verify independent states - doc1 loaded, doc2 still loading
    assert_eq!(
        state.get_document(&uri1).unwrap().loading_state,
        LoadingState::Loaded
    );
    assert_eq!(
        state.get_document(&uri2).unwrap().loading_state,
        LoadingState::Loading
    );
}

/// Test loading duration tracking.
#[tokio::test]
async fn test_loading_duration_tracking() {
    let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

    // Not loading initially - no duration
    assert!(doc.loading_duration().is_none());

    // Start loading - duration should be available
    doc.set_loading();
    assert!(doc.loading_duration().is_some());

    // Wait and verify duration increases
    tokio::time::sleep(Duration::from_millis(50)).await;
    let duration = doc.loading_duration().unwrap();
    assert!(duration >= Duration::from_millis(50));

    // Finish loading - duration should be None again
    doc.set_loaded();
    assert!(doc.loading_duration().is_none());
}

/// Test failed loading state.
#[tokio::test]
async fn test_failed_loading_state() {
    let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

    doc.set_loading();
    assert_eq!(doc.loading_state, LoadingState::Loading);

    // Simulate failure - state transitions to Failed
    doc.set_failed();
    assert_eq!(doc.loading_state, LoadingState::Failed);
    assert!(doc.loading_started_at.is_none());
}

/// Test that set_loading resets the timer on repeated calls.
#[test]
fn test_set_loading_resets_timer() {
    let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

    // Multiple set_loading calls should be safe
    doc.set_loading();
    let first_start = doc.loading_started_at;
    doc.set_loading();
    let second_start = doc.loading_started_at;

    assert!(first_start.is_some());
    assert!(second_start.is_some());
    // Second call resets the timer
    assert!(second_start >= first_start);

    // Multiple set_loaded calls should be safe
    doc.set_loaded();
    doc.set_loaded();
    assert_eq!(doc.loading_state, LoadingState::Loaded);
    assert!(doc.loading_started_at.is_none());
}

/// Test loading indicator config defaults.
#[test]
fn test_loading_indicator_config_defaults() {
    let config = LoadingIndicatorConfig::default();

    assert!(config.enabled);
    assert!(config.fallback_to_hints);
    assert_eq!(config.loading_text, "⏳");
}

/// Test partial loading indicator config deserialization.
#[test]
fn test_partial_loading_indicator_config() {
    let config_json = r#"{
        "loading_indicator": {
            "enabled": false
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    // Explicitly set field
    assert!(!config.loading_indicator.enabled);
    // Default fields
    assert!(config.loading_indicator.fallback_to_hints);
    assert_eq!(config.loading_indicator.loading_text, "⏳");
}

/// Test loading text truncation to prevent abuse.
#[test]
fn test_loading_text_truncation() {
    let long_text = "a".repeat(150);
    let config_json = format!(
        r#"{{
        "loading_indicator": {{
            "loading_text": "{}"
        }}
    }}"#,
        long_text
    );

    let config: DepsConfig = serde_json::from_str(&config_json).unwrap();

    // Should be truncated to 100 characters
    assert_eq!(config.loading_indicator.loading_text.len(), 100);
    assert_eq!(config.loading_indicator.loading_text, "a".repeat(100));
}

/// Test loading text at exactly 100 characters (boundary).
#[test]
fn test_loading_text_exactly_100_chars() {
    let text = "a".repeat(100);
    let config_json = format!(
        r#"{{
        "loading_indicator": {{
            "loading_text": "{}"
        }}
    }}"#,
        text
    );

    let config: DepsConfig = serde_json::from_str(&config_json).unwrap();

    assert_eq!(config.loading_indicator.loading_text.len(), 100);
    assert_eq!(config.loading_indicator.loading_text, text);
}

/// Test loading text well under limit.
#[test]
fn test_loading_text_under_limit() {
    let config_json = r#"{
        "loading_indicator": {
            "loading_text": "⏳ Loading dependencies..."
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert_eq!(
        config.loading_indicator.loading_text,
        "⏳ Loading dependencies..."
    );
    assert!(config.loading_indicator.loading_text.len() < 100);
}

/// Test inlay hints config remains unchanged.
#[test]
fn test_inlay_hints_config_unchanged() {
    let config_json = r#"{
        "inlay_hints": {
            "enabled": true,
            "up_to_date_text": "OK",
            "needs_update_text": "UPDATE {}"
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    assert!(config.inlay_hints.enabled);
    assert_eq!(config.inlay_hints.up_to_date_text, "OK");
    assert_eq!(config.inlay_hints.needs_update_text, "UPDATE {}");
}

/// Test combined loading indicator and inlay hints config.
#[test]
fn test_combined_config() {
    let config_json = r#"{
        "loading_indicator": {
            "enabled": true,
            "fallback_to_hints": true,
            "loading_text": "⏳"
        },
        "inlay_hints": {
            "enabled": true,
            "up_to_date_text": "✅",
            "needs_update_text": "⚠️  {}"
        }
    }"#;

    let config: DepsConfig = serde_json::from_str(config_json).unwrap();

    // Loading indicator settings
    assert!(config.loading_indicator.enabled);
    assert!(config.loading_indicator.fallback_to_hints);
    assert_eq!(config.loading_indicator.loading_text, "⏳");

    // Inlay hints settings
    assert!(config.inlay_hints.enabled);
    assert_eq!(config.inlay_hints.up_to_date_text, "✅");
    assert_eq!(config.inlay_hints.needs_update_text, "⚠️  {}");
}

/// Test server state initialization includes loading state.
#[test]
fn test_server_state_document_has_loading_state() {
    let state = ServerState::new();
    let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

    let doc = DocumentState::new_without_parse_result("cargo", String::new());

    // New document should start in Idle state
    assert_eq!(doc.loading_state, LoadingState::Idle);
    assert!(doc.loading_started_at.is_none());

    state.update_document(uri.clone(), doc);

    let retrieved = state.get_document(&uri).unwrap();
    assert_eq!(retrieved.loading_state, LoadingState::Idle);
}

/// Test document state cloning preserves loading state.
#[test]
fn test_document_state_clone_preserves_loading() {
    let mut original = DocumentState::new_without_parse_result("cargo", String::new());
    original.set_loading();

    let cloned = original.clone();

    assert_eq!(cloned.loading_state, LoadingState::Loading);
    assert_eq!(cloned.loading_started_at, original.loading_started_at);
}

/// Test loading state transitions in correct order.
#[test]
fn test_loading_state_transition_order() {
    let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

    // 1. Start in Idle
    assert_eq!(doc.loading_state, LoadingState::Idle);

    // 2. Transition to Loading
    doc.set_loading();
    assert_eq!(doc.loading_state, LoadingState::Loading);
    assert!(doc.loading_started_at.is_some());

    // 3. Transition to Loaded
    doc.set_loaded();
    assert_eq!(doc.loading_state, LoadingState::Loaded);
    assert!(doc.loading_started_at.is_none());

    // 4. Can transition back to Loading
    doc.set_loading();
    assert_eq!(doc.loading_state, LoadingState::Loading);
    assert!(doc.loading_started_at.is_some());

    // 5. Can transition to Failed
    doc.set_failed();
    assert_eq!(doc.loading_state, LoadingState::Failed);
    assert!(doc.loading_started_at.is_none());
}

/// Test loading timeout scenario (>5 seconds).
#[tokio::test]
async fn test_loading_timeout_scenario() {
    let mut doc = DocumentState::new_without_parse_result("cargo", String::new());
    doc.set_loading();

    // Wait a small amount to verify duration increases
    tokio::time::sleep(Duration::from_millis(100)).await;

    let duration = doc.loading_duration().unwrap();
    assert!(
        duration >= Duration::from_millis(100),
        "Expected duration >= 100ms, got {:?}",
        duration
    );

    // Mark as failed - this would happen in a real timeout scenario
    doc.set_failed();
    assert_eq!(doc.loading_state, LoadingState::Failed);
    assert!(doc.loading_started_at.is_none());
}

/// Test rapid set_loading() calls for race condition handling.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn test_rapid_set_loading_calls() {
    let state = Arc::new(ServerState::new());
    let uri = Uri::from_file_path("/test/rapid.toml").unwrap();

    let doc = DocumentState::new_without_parse_result("cargo", String::new());
    state.update_document(uri.clone(), doc);

    // Rapid fire set_loading() calls
    for _ in 0..10 {
        if let Some(mut doc) = state.documents.get_mut(&uri) {
            doc.set_loading();
        }
    }

    let doc = state.get_document(&uri).unwrap();
    assert_eq!(doc.loading_state, LoadingState::Loading);
}
