//! Code actions handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Diagnostic, NumberOrString,
};

/// Handles code action requests using trait-based delegation.
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let position = params.range.start;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, config).await {
        tracing::warn!("Could not load document for code actions: {:?}", uri);
        return vec![];
    }

    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id()) {
        Some(e) => e,
        None => return vec![],
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    // Generate code actions while holding the lock
    let mut actions = ecosystem
        .generate_code_actions(
            parse_result,
            position,
            uri,
            VersionData::new(&doc.cached_versions, &doc.resolved_versions)
                .with_vulnerabilities(&doc.vulnerabilities),
        )
        .await;

    attach_vulnerability_diagnostics(&mut actions, &params.context.diagnostics);

    let actions = match params.context.only.as_deref() {
        Some(only) if !only.is_empty() => filter_by_requested_kinds(actions, only),
        _ => actions,
    };

    actions
        .into_iter()
        .map(CodeActionOrCommand::CodeAction)
        .collect()
}

/// Binds a vulnerability-fix action to the client-supplied diagnostics it
/// resolves, so editors can surface it from the advisory's own
/// lightbulb/quickfix affordance.
///
/// `deps-core` has no LSP request context, so [`deps_core::lsp_helpers::generate_code_actions`]
/// stashes the resolved advisory ids in `CodeAction::data` instead
/// (`{"advisory_ids": [...]}`). This matches those ids against `diagnostics`
/// — the same set the client already sent in `CodeActionParams.context`,
/// filtered to entries this server emitted (`source == "deps-lsp"`) whose
/// `code` names one of the ids — and moves the matches into
/// `CodeAction::diagnostics`. `data` is cleared afterward regardless of
/// whether a match was found, so a stale payload can never be mistaken for a
/// still-resolvable action.
fn attach_vulnerability_diagnostics(actions: &mut [CodeAction], diagnostics: &[Diagnostic]) {
    for action in actions {
        let Some(data) = action.data.take() else {
            continue;
        };
        let Some(advisory_ids) = data
            .get("advisory_ids")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let ids: Vec<&str> = advisory_ids.iter().filter_map(|v| v.as_str()).collect();

        let matches: Vec<Diagnostic> = diagnostics
            .iter()
            .filter(|d| {
                d.source.as_deref() == Some("deps-lsp")
                    && matches!(&d.code, Some(NumberOrString::String(code)) if ids.contains(&code.as_str()))
            })
            .cloned()
            .collect();

        if !matches.is_empty() {
            action.diagnostics = Some(matches);
        }
    }
}

/// Filters `actions` down to those matching one of the client-requested
/// `only` kinds, using LSP's hierarchical kind matching rather than plain
/// equality: a request for `refactor` also matches the more specific
/// `refactor.extract`. Without this, a client asking only for quickfixes
/// still received every plain "update to version X" `REFACTOR` action
/// alongside the vulnerability-fix `QUICKFIX`.
fn filter_by_requested_kinds(actions: Vec<CodeAction>, only: &[CodeActionKind]) -> Vec<CodeAction> {
    actions
        .into_iter()
        .filter(|action| {
            action
                .kind
                .as_ref()
                .is_some_and(|kind| only.iter().any(|filter| kind_matches(kind, filter)))
        })
        .collect()
}

/// Whether `kind` is `filter` itself or one of `filter`'s sub-kinds
/// (dot-separated, e.g. `refactor.extract` under `refactor`).
fn kind_matches(kind: &CodeActionKind, filter: &CodeActionKind) -> bool {
    let (kind, filter) = (kind.as_str(), filter.as_str());
    kind == filter
        || kind
            .strip_prefix(filter)
            .is_some_and(|rest| rest.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::{Position, Range, TextDocumentIdentifier};

    // Generic tests (no feature flag required)

    fn action(kind: CodeActionKind) -> CodeAction {
        CodeAction {
            title: "test action".to_string(),
            kind: Some(kind),
            ..Default::default()
        }
    }

    #[test]
    fn test_kind_matches_exact() {
        assert!(kind_matches(
            &CodeActionKind::QUICKFIX,
            &CodeActionKind::QUICKFIX
        ));
    }

    #[test]
    fn test_kind_matches_sub_kind() {
        assert!(kind_matches(
            &CodeActionKind::REFACTOR_EXTRACT,
            &CodeActionKind::REFACTOR
        ));
    }

    #[test]
    fn test_kind_matches_rejects_unrelated_prefix() {
        // "refactoring" must not match a filter of "refactor" just because it
        // shares a string prefix without a `.` boundary.
        assert!(!kind_matches(
            &CodeActionKind::from("refactoring"),
            &CodeActionKind::REFACTOR
        ));
        assert!(!kind_matches(
            &CodeActionKind::REFACTOR,
            &CodeActionKind::QUICKFIX
        ));
    }

    #[test]
    fn test_filter_by_requested_kinds_keeps_only_matching() {
        let actions = vec![
            action(CodeActionKind::QUICKFIX),
            action(CodeActionKind::REFACTOR),
        ];

        let filtered = filter_by_requested_kinds(actions, &[CodeActionKind::QUICKFIX]);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].kind, Some(CodeActionKind::QUICKFIX));
    }

    #[test]
    fn test_filter_by_requested_kinds_drops_actions_with_no_kind() {
        let actions = vec![CodeAction {
            title: "no kind".to_string(),
            kind: None,
            ..Default::default()
        }];

        let filtered = filter_by_requested_kinds(actions, &[CodeActionKind::QUICKFIX]);

        assert!(filtered.is_empty());
    }

    fn vuln_diagnostic(source: Option<&str>, code: Option<&str>) -> Diagnostic {
        Diagnostic {
            source: source.map(str::to_string),
            code: code.map(|c| NumberOrString::String(c.to_string())),
            ..Default::default()
        }
    }

    #[test]
    fn test_attach_vulnerability_diagnostics_matches_by_source_and_code() {
        let mut actions = vec![CodeAction {
            title: "fix".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            data: Some(serde_json::json!({ "advisory_ids": ["RUSTSEC-1", "RUSTSEC-2"] })),
            ..Default::default()
        }];
        let diagnostics = vec![
            vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-1")),
            vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-2")),
            // Not matched: different source.
            vuln_diagnostic(Some("other-source"), Some("RUSTSEC-1")),
            // Not matched: unrelated advisory id.
            vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-999")),
        ];

        attach_vulnerability_diagnostics(&mut actions, &diagnostics);

        let attached = actions[0].diagnostics.as_ref().expect("expected matches");
        assert_eq!(attached.len(), 2);
        // `data` is cleared once its ids have been transferred (critic M8).
        assert!(actions[0].data.is_none());
    }

    #[test]
    fn test_attach_vulnerability_diagnostics_no_match_clears_data_without_setting_diagnostics() {
        let mut actions = vec![CodeAction {
            title: "fix".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            data: Some(serde_json::json!({ "advisory_ids": ["RUSTSEC-1"] })),
            ..Default::default()
        }];
        let diagnostics = vec![vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-999"))];

        attach_vulnerability_diagnostics(&mut actions, &diagnostics);

        assert!(actions[0].diagnostics.is_none());
        assert!(actions[0].data.is_none());
    }

    #[test]
    fn test_attach_vulnerability_diagnostics_action_without_data_is_untouched() {
        let mut actions = vec![action(CodeActionKind::REFACTOR)];
        let diagnostics = vec![vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-1"))];

        attach_vulnerability_diagnostics(&mut actions, &diagnostics);

        assert!(actions[0].diagnostics.is_none());
    }

    #[tokio::test]
    async fn test_handle_code_actions_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_code_actions(state, params, client, config).await;
        assert!(result.is_empty());
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_code_actions() {
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

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(1, 9), Position::new(1, 16)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_code_actions(state, params, client, config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_code_actions_end_to_end_composition() {
            // Drives `handle_code_actions` itself with vulnerability data, a
            // `context.only` filter, and matching `context.diagnostics`
            // together, confirming the wiring order (generate -> attach ->
            // filter) end-to-end rather than only at the helper-unit level.
            use deps_core::osv::{
                Advisory, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
                VulnerabilityMap,
            };
            use tower_lsp_server::ls_types::{CodeActionContext, Diagnostic};

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

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);

            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "serde".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![Arc::new(Advisory {
                        id: "RUSTSEC-2020-0071".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["1.0.5".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
                }),
            );
            doc_state.vulnerabilities = vulnerabilities;
            state.update_document(uri.clone(), doc_state);

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(1, 9), Position::new(1, 16)),
                context: CodeActionContext {
                    diagnostics: vec![Diagnostic {
                        source: Some("deps-lsp".to_string()),
                        code: Some(NumberOrString::String("RUSTSEC-2020-0071".to_string())),
                        ..Default::default()
                    }],
                    only: Some(vec![CodeActionKind::QUICKFIX]),
                    ..Default::default()
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let result = handle_code_actions(state, params, client, config).await;

            assert_eq!(
                result.len(),
                1,
                "context.only=[quickfix] must filter out the plain REFACTOR items: {result:?}"
            );
            let CodeActionOrCommand::CodeAction(action) = &result[0] else {
                panic!("expected a CodeAction, got {:?}", result[0]);
            };
            assert_eq!(action.kind, Some(CodeActionKind::QUICKFIX));
            assert!(action.title.starts_with("Update to 1.0.5"));
            assert!(
                action.data.is_none(),
                "data must be cleared once its ids are transferred into diagnostics"
            );
            let diagnostics = action
                .diagnostics
                .as_ref()
                .expect("expected the matching client-supplied diagnostic to be bound");
            assert_eq!(diagnostics.len(), 1);
        }

        #[tokio::test]
        async fn test_handle_code_actions_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let result = handle_code_actions(state, params, client, config).await;
            assert!(result.is_empty());
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_code_actions() {
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

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(0, 25), Position::new(0, 32)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_code_actions(state, params, client, config).await;
            // Test passes if no panic occurs
        }
    }
}
