//! Code actions handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Diagnostic, NumberOrString,
    Range,
};

/// Handles code action requests using trait-based delegation.
#[tracing::instrument(
    skip(state, params, client, config),
    fields(uri = ?params.text_document.uri, ecosystem = tracing::field::Empty)
)]
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let position = params.range.start;

    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&config)).await {
        tracing::warn!("Could not load document for code actions: {:?}", uri);
        return vec![];
    }

    let offline = { config.read().await.policy.network.offline };

    // Release the DashMap shard `Ref` before awaiting `generate_code_actions`'s registry
    // fetch — holding it across the await would block a concurrent `documents.get_mut` on
    // the same shard (#319); `with_document` makes this structural rather than a convention (#333).
    let Some((
        ecosystem,
        ecosystem_id,
        parse_result,
        cached_versions,
        resolved_versions,
        resolved_version_candidates,
        vulnerabilities,
        outcomes,
        content,
    )) = state
        .with_document(uri, |doc| {
            let ecosystem = state.ecosystem_registry.get(doc.ecosystem)?;
            let parse_result = doc.parse_result_arc()?;
            Some((
                ecosystem,
                doc.ecosystem,
                parse_result,
                doc.cached_versions.clone(),
                doc.resolved_versions.clone(),
                doc.resolved_version_candidates.clone(),
                doc.vulnerabilities.clone(),
                doc.outcomes.clone(),
                doc.content.clone(),
            ))
        })
        .flatten()
    else {
        return vec![];
    };

    tracing::Span::current().record("ecosystem", ecosystem_id.id());

    // Unreachable in practice (the URI already converted in `ensure_document_loaded`);
    // handled defensively rather than unwrapped.
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(uri) else {
        tracing::warn!("URI is not representable as a url::Url: {:?}", uri);
        return vec![];
    };
    let mut actions = ecosystem
        .generate_code_actions(
            parse_result.as_ref(),
            position,
            &domain_uri,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_resolved_version_candidates(&resolved_version_candidates)
                .with_vulnerabilities(&vulnerabilities)
                .with_outcomes(&outcomes)
                .with_ecosystem(ecosystem_id)
                .with_offline(offline),
            &content,
        )
        .await;

    bind_diagnostics(&mut actions, &params.context.diagnostics);

    let actions = match params.context.only.as_deref() {
        Some(only) if !only.is_empty() => filter_by_requested_kinds(actions, only),
        _ => actions,
    };

    actions
        .into_iter()
        .map(CodeActionOrCommand::CodeAction)
        .collect()
}

/// Binds a code action to the client-supplied diagnostics it resolves, so editors can
/// surface it from the diagnostic's own lightbulb/quickfix affordance.
///
/// `deps-core` has no LSP request context, so a code-action producer in
/// [`deps_core::lsp_helpers::generate_code_actions`] (the vulnerability fix, or the
/// unsatisfiable-requirement fix) stashes `{"diagnostic_codes": [...], "diagnostic_range":
/// <Range>}` in `CodeAction::data` instead. This matches against `diagnostics` — the set
/// the client already sent in `CodeActionParams.context` — in three steps:
///
/// 1. Filter to entries this server emitted (`source == "deps-lsp"`) whose `code` names
///    one of `diagnostic_codes`.
/// 2. If at most one candidate remains, bind it with no further check. This is the common
///    case — every vulnerability fix (a unique advisory id) and every single-unsatisfiable
///    -dependency document — and matches today's behavior exactly, deliberately with no
///    range check: `context.diagnostics` are the diagnostics the *client* holds from its
///    last `publishDiagnostics`, which shift as the user types, while `diagnostic_range`
///    is recomputed from the freshly re-parsed buffer. Requiring equality here would make
///    an in-flight edit break a binding that works today.
/// 3. Only when two or more candidates remain — reachable because
///    `UNSATISFIABLE_DIAGNOSTIC_CODE` (and, since issue #473, GitHub Actions'
///    `MUTABLE_REF_PIN_DIAGNOSTIC_CODE` — the more frequent case in practice, since it
///    fires on every tag-pinned `uses:` step in a workflow) is a constant shared by
///    every matching dependency in a document, unlike a unique advisory id — narrow to
///    the candidates whose range *overlaps* `diagnostic_range`, so one action does not
///    claim every same-code dependency in the document. Overlap, not equality, so a
///    range shifted by an in-flight edit still matches. If the narrowing leaves nothing,
///    fall back to the full code-matched set rather than binding nothing.
///
/// `data` is cleared afterward regardless of whether a match was found, so a stale payload
/// can never be mistaken for a still-resolvable action.
///
/// Accepted tradeoff: because a diagnostic code can be a shared constant rather than a
/// per-instance id (`UNSATISFIABLE_DIAGNOSTIC_CODE`, `MUTABLE_REF_PIN_DIAGNOSTIC_CODE`), if
/// the client's diagnostic list happens to contain exactly one same-code diagnostic and it
/// belongs to a *different* dependency than the one this action targets, step 2 still binds
/// it (no range check on a single candidate). This is cosmetic mis-attribution of the
/// editor's "fix this problem" affordance only — the `TextEdit` itself always comes from
/// this action's own `dep.version_range()`, so no incorrect edit is possible.
fn bind_diagnostics(actions: &mut [CodeAction], diagnostics: &[Diagnostic]) {
    for action in actions {
        let Some(data) = action.data.take() else {
            continue;
        };
        let Some(codes) = data
            .get("diagnostic_codes")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let codes: Vec<&str> = codes.iter().filter_map(serde_json::Value::as_str).collect();

        let candidates: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|d| {
                d.source.as_deref() == Some("deps-lsp")
                    && matches!(&d.code, Some(NumberOrString::String(code)) if codes.contains(&code.as_str()))
            })
            .collect();

        let matches: Vec<Diagnostic> = if candidates.len() <= 1 {
            candidates.into_iter().cloned().collect()
        } else {
            let diagnostic_range = data
                .get("diagnostic_range")
                .and_then(|v| serde_json::from_value::<Range>(v.clone()).ok());

            let overlapping: Vec<Diagnostic> = diagnostic_range
                .map(|range| {
                    candidates
                        .iter()
                        .filter(|d| ranges_overlap(&d.range, &range))
                        .map(|d| (**d).clone())
                        .collect()
                })
                .unwrap_or_default();

            if overlapping.is_empty() {
                candidates.into_iter().cloned().collect()
            } else {
                overlapping
            }
        };

        if !matches.is_empty() {
            action.diagnostics = Some(matches);
        }
    }
}

/// Whether `a` and `b` overlap, under LSP `Position`'s line-then-character ordering.
fn ranges_overlap(a: &Range, b: &Range) -> bool {
    a.start <= b.end && b.start <= a.end
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
    #[cfg(any(feature = "cargo", feature = "npm", feature = "swift"))]
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::{Position, Range, TextDocumentIdentifier};

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
        // Must not match on a shared string prefix without a `.` boundary.
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

    fn ranged_diagnostic(source: &str, code: &str, range: Range) -> Diagnostic {
        Diagnostic {
            source: Some(source.to_string()),
            code: Some(NumberOrString::String(code.to_string())),
            range,
            ..Default::default()
        }
    }

    fn action_with_data(codes: &[&str], range: Range) -> CodeAction {
        CodeAction {
            title: "fix".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            data: Some(serde_json::json!({
                "diagnostic_codes": codes,
                "diagnostic_range": range,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_bind_diagnostics_matches_by_source_and_code() {
        let mut actions = vec![CodeAction {
            title: "fix".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            data: Some(serde_json::json!({ "diagnostic_codes": ["RUSTSEC-1", "RUSTSEC-2"] })),
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

        bind_diagnostics(&mut actions, &diagnostics);

        let attached = actions[0].diagnostics.as_ref().expect("expected matches");
        assert_eq!(attached.len(), 2);
        // `data` is cleared once its ids have been transferred (critic M8).
        assert!(actions[0].data.is_none());
    }

    #[test]
    fn test_bind_diagnostics_no_match_clears_data_without_setting_diagnostics() {
        let mut actions = vec![CodeAction {
            title: "fix".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            data: Some(serde_json::json!({ "diagnostic_codes": ["RUSTSEC-1"] })),
            ..Default::default()
        }];
        let diagnostics = vec![vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-999"))];

        bind_diagnostics(&mut actions, &diagnostics);

        assert!(actions[0].diagnostics.is_none());
        assert!(actions[0].data.is_none());
    }

    #[test]
    fn test_bind_diagnostics_action_without_data_is_untouched() {
        let mut actions = vec![action(CodeActionKind::REFACTOR)];
        let diagnostics = vec![vuln_diagnostic(Some("deps-lsp"), Some("RUSTSEC-1"))];

        bind_diagnostics(&mut actions, &diagnostics);

        assert!(actions[0].diagnostics.is_none());
    }

    #[test]
    fn test_bind_diagnostics_single_candidate_binds_despite_shifted_range() {
        // Must not regress (critic S2): a single code-matched candidate binds with no range
        // check, even when the client-held diagnostic's range has drifted from the recomputed one.
        let action_range = Range::new(Position::new(5, 0), Position::new(5, 10));
        let shifted_range = Range::new(Position::new(9, 0), Position::new(9, 10));
        let mut actions = vec![action_with_data(
            &["unsatisfiable-requirement"],
            action_range,
        )];
        let diagnostics = vec![ranged_diagnostic(
            "deps-lsp",
            "unsatisfiable-requirement",
            shifted_range,
        )];

        bind_diagnostics(&mut actions, &diagnostics);

        assert_eq!(
            actions[0]
                .diagnostics
                .as_ref()
                .expect("single candidate must bind with no range check")
                .len(),
            1
        );
    }

    #[test]
    fn test_bind_diagnostics_two_candidates_narrow_to_overlapping_one() {
        // Anti-fan-out: with two code-matched diagnostics sharing `UNSATISFIABLE_DIAGNOSTIC_CODE`,
        // only the one overlapping this action's own range binds.
        let action_range = Range::new(Position::new(5, 0), Position::new(5, 10));
        let overlapping = Range::new(Position::new(5, 2), Position::new(5, 8));
        let elsewhere = Range::new(Position::new(20, 0), Position::new(20, 10));
        let mut actions = vec![action_with_data(
            &["unsatisfiable-requirement"],
            action_range,
        )];
        let diagnostics = vec![
            ranged_diagnostic("deps-lsp", "unsatisfiable-requirement", overlapping),
            ranged_diagnostic("deps-lsp", "unsatisfiable-requirement", elsewhere),
        ];

        bind_diagnostics(&mut actions, &diagnostics);

        let attached = actions[0].diagnostics.as_ref().expect("expected a match");
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].range, overlapping);
    }

    #[test]
    fn test_bind_diagnostics_two_candidates_no_overlap_falls_back_to_full_set() {
        // If range-narrowing leaves nothing (both candidates drifted off), fall back to
        // binding the full code-matched set rather than nothing.
        let action_range = Range::new(Position::new(5, 0), Position::new(5, 10));
        let first = Range::new(Position::new(20, 0), Position::new(20, 10));
        let second = Range::new(Position::new(30, 0), Position::new(30, 10));
        let mut actions = vec![action_with_data(
            &["unsatisfiable-requirement"],
            action_range,
        )];
        let diagnostics = vec![
            ranged_diagnostic("deps-lsp", "unsatisfiable-requirement", first),
            ranged_diagnostic("deps-lsp", "unsatisfiable-requirement", second),
        ];

        bind_diagnostics(&mut actions, &diagnostics);

        assert_eq!(
            actions[0]
                .diagnostics
                .as_ref()
                .expect("expected the fallback full set")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_handle_code_actions_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));

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

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_code_actions() {
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

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(1, 9), Position::new(1, 16)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_code_actions(state, params, client, config).await;
        }

        #[tokio::test]
        async fn test_handle_code_actions_end_to_end_composition() {
            // See the comment in `test_handle_code_actions` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Confirms the wiring order (generate -> attach -> filter) end-to-end, not just
            // at the helper-unit level.
            use deps_core::osv::{
                Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus,
                VulnSeverity, VulnerabilityMap,
            };
            use tower_lsp_server::ls_types::{CodeActionContext, Diagnostic};

            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            // #1344: "0.9.0" (not "1.0.0"), so the fix action's own gate — the declared
            // requirement must not already admit the fix target ("1.0.5", which "^1.0.0"
            // would admit) — doesn't suppress the quickfix this test is exercising.
            let content = r#"[dependencies]
serde = "0.9.0"
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);

            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "serde".to_string(),
                ScanOutcome::Vulnerable(
                    DependencyVulnerabilities::new(Capped::new(
                        vec![Arc::new(
                            Advisory::new(
                                "RUSTSEC-2020-0071".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec!["1.0.5".to_string()]),
                        )],
                        1,
                    ))
                    .with_fix_target_status(UpgradeStatus::CandidateClean {
                        version: "1.0.5".to_string(),
                    }),
                ),
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

        /// #1344 C4: the deps-lsp-level sibling of
        /// `test_handle_code_actions_end_to_end_composition` — same wiring, but with the
        /// declared requirement ("1.0.0", whose "^1.0.0" range already admits the fix target
        /// "1.0.5") so the vulnerability-fix quickfix must be withheld end-to-end, not just at
        /// the `deps-core` unit level. Without this test, deleting the #1344 gate entirely
        /// would leave every deps-lsp test green.
        #[tokio::test]
        async fn test_handle_code_actions_withholds_quickfix_when_requirement_already_admits_fix() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use deps_core::osv::{
                Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus,
                VulnSeverity, VulnerabilityMap,
            };
            use tower_lsp_server::ls_types::{CodeActionContext, Diagnostic};

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

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);

            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "serde".to_string(),
                ScanOutcome::Vulnerable(
                    DependencyVulnerabilities::new(Capped::new(
                        vec![Arc::new(
                            Advisory::new(
                                "RUSTSEC-2020-0071".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec!["1.0.5".to_string()]),
                        )],
                        1,
                    ))
                    .with_fix_target_status(UpgradeStatus::CandidateClean {
                        version: "1.0.5".to_string(),
                    }),
                ),
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

            assert!(
                result.is_empty(),
                "the requirement (\"1.0.0\" -> \"^1.0.0\") already admits the fix target \
                 (\"1.0.5\"), so no quickfix should be offered: {result:?}"
            );
        }

        #[tokio::test]
        async fn test_handle_code_actions_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

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

        /// Canonical-in/canonical-out regression (issue #1086, replaces #1071's
        /// `rekey_edits_to_original_uri`): with `canonicalize_uri` applied once at the
        /// `server.rs` boundary before a document is ever stored or looked up, a
        /// `WorkspaceEdit.changes` key built via `single_file_edit`/`to_ls_uri`'s
        /// `url::Url` round trip already equals the canonical `Uri` the document is
        /// keyed by — no per-handler rekey is needed. Covers the four forms empirically
        /// confirmed to diverge from their canonical form: an explicit `localhost`
        /// authority, an uppercase scheme, a `.`/`..`-segment path, and a four-slash
        /// UNC-like authority. Each case starts from a raw client-style string (not
        /// `ls_types::Uri::from_file_path`, which is always already canonical and so
        /// cannot exercise this divergence), canonicalized exactly as `server.rs`'s
        /// `code_action` trait method would before calling this handler.
        ///
        /// Unix-only: every fixture path here is drive-letter-less, so
        /// `url::Url::to_file_path` (which `parse_manifest`'s workspace-root discovery
        /// calls internally) always fails on Windows regardless of the URI's spelling —
        /// this is a fixture-portability limit, not a difference in the canonicalization
        /// mechanism under test, which the cross-platform `lsp_types_interop` round-trip
        /// tests already cover on Windows.
        #[tokio::test]
        #[cfg(not(windows))]
        async fn test_handle_code_actions_keys_edit_by_canonical_uri_for_non_canonical_input() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let raw_uris = [
                "file://localhost/test/Cargo.toml",
                "FILE:///test/Cargo.toml",
                "file:///test/./a/../Cargo.toml",
                "file:////server/share/Cargo.toml",
            ];

            for raw in raw_uris {
                let state = Arc::new(ServerState::new());
                let raw_uri: tower_lsp_server::ls_types::Uri = raw
                    .parse()
                    .unwrap_or_else(|e| panic!("{raw:?} must parse as an ls_types::Uri: {e}"));
                // Mirrors the canonicalization `server.rs`'s `code_action` trait method
                // performs before this handler ever sees a `Uri`.
                let uri = crate::lsp_types_interop::canonicalize_uri(&raw_uri);
                let url = crate::lsp_types_interop::from_lsp_uri(&uri)
                    .unwrap_or_else(|| panic!("{raw:?} must canonicalize to a valid url::Url"));
                // Sanity: each of these is exactly a shape `canonicalize_uri` normalizes,
                // otherwise this case would pass vacuously.
                assert_ne!(
                    uri.as_str(),
                    raw_uri.as_str(),
                    "expected {raw:?} to be normalized by canonicalize_uri"
                );

                let ecosystem = state
                    .ecosystem_registry
                    .get(deps_core::EcosystemId::Cargo)
                    .unwrap();
                let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
                let parse_result = ecosystem
                    .parse_manifest(&content, &url)
                    .await
                    .unwrap_or_else(|e| panic!("{raw:?}: failed to parse manifest: {e}"));

                let doc_state =
                    DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
                state.update_document(uri.clone(), doc_state);

                let params = CodeActionParams {
                    text_document: TextDocumentIdentifier { uri: uri.clone() },
                    range: Range::new(Position::new(1, 9), Position::new(1, 16)),
                    context: Default::default(),
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                };

                let (client, config) = create_test_client_and_config();
                let result = handle_code_actions(state, params, client, config).await;

                let has_correctly_keyed_edit = result.iter().any(|action| {
                    let CodeActionOrCommand::CodeAction(action) = action else {
                        return false;
                    };
                    action
                        .edit
                        .as_ref()
                        .and_then(|e| e.changes.as_ref())
                        .is_some_and(|changes| changes.contains_key(&uri))
                });
                assert!(
                    has_correctly_keyed_edit,
                    "for input {raw:?}: expected at least one action whose edit is keyed \
                     by the canonical Uri: {result:?}"
                );
            }
        }
    }

    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_code_actions() {
            // See the comment in `test_handle_code_actions` on why this guard is needed here.
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

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(Position::new(0, 25), Position::new(0, 32)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_code_actions(state, params, client, config).await;
        }
    }

    #[cfg(feature = "swift")]
    mod swift_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_code_actions_exact_form_produces_vulnerability_fix() {
            // Regression for #367: real end-to-end through SwiftEcosystem, not the synthetic
            // fixture deps-core's own tests use. Uses OSV data instead of a live registry
            // fetch to keep the assertion deterministic and network-free.
            use deps_core::osv::{
                Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus,
                VulnSeverity, VulnerabilityMap,
            };
            use tower_lsp_server::ls_types::{CodeActionContext, Diagnostic};

            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Package.swift");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Swift)
                .unwrap();
            let content =
                r#".package(url: "https://github.com/vapor/vapor", .exact("4.50.0"))"#.to_string();
            let version_col = content.find("4.50.0").unwrap() as u32;

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Swift, content, parse_result);

            // Keyed by `SwiftFormatter::normalize_package_name` (`owner/repo`) — the lookup
            // `build_vulnerability_fix_action` uses, not `osv_package_name`'s wire-request format.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "vapor/vapor".to_string(),
                ScanOutcome::Vulnerable(
                    DependencyVulnerabilities::new(Capped::new(
                        vec![Arc::new(
                            Advisory::new(
                                "GHSA-test-0001".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec!["4.50.1".to_string()]),
                        )],
                        1,
                    ))
                    .with_fix_target_status(UpgradeStatus::CandidateClean {
                        version: "4.50.1".to_string(),
                    }),
                ),
            );
            doc_state.vulnerabilities = vulnerabilities;
            state.update_document(uri.clone(), doc_state);

            let params = CodeActionParams {
                text_document: TextDocumentIdentifier { uri },
                range: Range::new(
                    Position::new(0, version_col),
                    Position::new(0, version_col + "4.50.0".len() as u32),
                ),
                context: CodeActionContext {
                    diagnostics: vec![Diagnostic {
                        source: Some("deps-lsp".to_string()),
                        code: Some(NumberOrString::String("GHSA-test-0001".to_string())),
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
                "the literal-span guard must accept the .exact(...) form and produce the \
                 vulnerability-fix quickfix, the exact bug #367 reported: {result:?}"
            );
            let CodeActionOrCommand::CodeAction(action) = &result[0] else {
                panic!("expected a CodeAction, got {:?}", result[0]);
            };
            assert_eq!(action.kind, Some(CodeActionKind::QUICKFIX));
            assert!(action.title.starts_with("Update to 4.50.1"));
        }
    }
}
