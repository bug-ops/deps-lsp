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
                .with_vulnerabilities(&doc.vulnerabilities)
                .with_yanked(&doc.yanked_versions),
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
            // `available` must include the declared "1.0.0" alongside "2.0.0" — a
            // `latest_only` single-element list containing only "2.0.0" would make the
            // declared requirement look unsatisfiable (no published version matches "1.0.0")
            // and fire the mutually-exclusive WARNING instead of this outdated HINT/ERROR.
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions {
                    latest: "2.0.0".to_string(),
                    available: std::sync::Arc::from(vec!["2.0.0".to_string(), "1.0.0".to_string()]),
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
                    latest: "2.0.0".to_string(),
                    available: std::sync::Arc::from(vec!["2.0.0".to_string(), "1.0.0".to_string()]),
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
                    latest: "1.0.214".to_string(),
                    available: std::sync::Arc::from(vec![
                        "1.0.214".to_string(),
                        "1.0.213".to_string(),
                    ]),
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
                    latest: "1.0.214".to_string(),
                    available: std::sync::Arc::from(vec![
                        "1.0.214".to_string(),
                        "1.0.213".to_string(),
                    ]),
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
                    latest: "1.0.214".to_string(),
                    available: std::sync::Arc::from(vec!["1.0.214".to_string()]),
                },
            );
            cached.insert(
                "tokio".into(),
                deps_core::PackageVersions {
                    latest: "2.0.0".to_string(),
                    // Includes an older version satisfying "1.0" (^1.0) so this dependency
                    // is genuinely outdated-but-satisfiable, not unsatisfiable — an
                    // available list containing only `latest` would make every requirement
                    // that latest doesn't itself satisfy look unsatisfiable.
                    available: std::sync::Arc::from(vec!["2.0.0".to_string(), "1.5.0".to_string()]),
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
