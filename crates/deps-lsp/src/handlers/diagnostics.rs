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
    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for diagnostics: {:?}", uri);
            return vec![];
        }
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id()) {
        Some(e) => e,
        None => {
            tracing::warn!(
                "Ecosystem not found for diagnostics: {}",
                doc.ecosystem_id()
            );
            return vec![];
        }
    };

    // Skip diagnostics while versions are still loading to avoid
    // false "Unknown package" warnings from empty cache
    if doc.loading_state == deps_core::LoadingState::Loading {
        return vec![];
    }

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    // Generate diagnostics while holding the lock
    ecosystem
        .generate_diagnostics(
            parse_result,
            VersionData::new(&doc.cached_versions, &doc.resolved_versions)
                .with_vulnerabilities(&doc.vulnerabilities),
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
            cached.insert("serde".into(), "2.0.0".to_string());
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
            cached.insert("serde".into(), "2.0.0".to_string());
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::HINT));
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
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

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
