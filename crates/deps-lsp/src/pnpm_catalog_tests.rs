//! Protocol-level tests of `pnpm-workspace.yaml` catalog support (spec 078): the file is a
//! dependency document of its own, and it is also a watched config of the `package.json`
//! documents that reference its catalogs, so a change on disk refreshes both (FR-003, FR-023).

#![allow(
    clippy::unwrap_used,
    clippy::string_slice,
    reason = "test code over ASCII fixtures"
)]

use std::path::Path;

use tower_lsp_server::LanguageServer;
use tower_lsp_server::ls_types::{
    DidChangeWatchedFilesParams, DidOpenTextDocumentParams, DocumentDiagnosticParams,
    DocumentDiagnosticReport, DocumentDiagnosticReportResult, FileChangeType, FileEvent,
    HoverContents, HoverParams, Position, TextDocumentIdentifier, TextDocumentItem,
    TextDocumentPositionParams, Uri,
};

use crate::server::Backend;

const WORKSPACE_FILE: &str = "pnpm-workspace.yaml";

async fn open(backend: &Backend, path: &Path, language_id: &str, text: &str) -> Uri {
    std::fs::write(path, text).unwrap();
    let uri = Uri::from_file_path(path).unwrap();
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: language_id.to_string(),
                version: 1,
                text: text.to_string(),
            },
        })
        .await;
    uri
}

async fn hover_text(backend: &Backend, uri: &Uri, position: Position) -> Option<String> {
    let hover = backend
        .hover(HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position,
            },
            work_done_progress_params: Default::default(),
        })
        .await
        .unwrap()?;
    let HoverContents::Markup(markup) = hover.contents else {
        panic!("expected markup hover contents");
    };
    Some(markup.value)
}

async fn diagnostic_codes(backend: &Backend, uri: &Uri) -> Vec<String> {
    let result = backend
        .diagnostic(DocumentDiagnosticParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            identifier: None,
            previous_result_id: None,
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        })
        .await
        .unwrap();
    let DocumentDiagnosticReportResult::Report(DocumentDiagnosticReport::Full(report)) = result
    else {
        panic!("expected a full diagnostic report");
    };
    report
        .full_document_diagnostic_report
        .items
        .into_iter()
        .filter_map(|d| match d.code? {
            tower_lsp_server::ls_types::NumberOrString::String(code) => Some(code),
            tower_lsp_server::ls_types::NumberOrString::Number(_) => None,
        })
        .collect()
}

async fn saved(backend: &Backend, path: &Path, contents: &str) {
    // A distinguishable mtime on filesystems with coarse timestamp resolution.
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
    std::fs::write(path, contents).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(future)
        .unwrap();
    backend
        .did_change_watched_files(DidChangeWatchedFilesParams {
            changes: vec![FileEvent {
                uri: Uri::from_file_path(path).unwrap(),
                typ: FileChangeType::CHANGED,
            }],
        })
        .await;
}

/// An opened `pnpm-workspace.yaml` is routed to npm and answers hover on a catalog entry.
#[tokio::test]
async fn opened_workspace_file_answers_hover_on_a_catalog_entry() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let dir = tempfile::tempdir().unwrap();
    let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
    let backend = service.inner();

    let uri = open(
        backend,
        &dir.path().join(WORKSPACE_FILE),
        "yaml",
        "catalog:\n  react: ^17.0.0\n",
    )
    .await;

    let hover = hover_text(backend, &uri, Position::new(1, 4))
        .await
        .expect("hover must fire on a catalog entry");
    assert!(hover.contains("react"), "{hover}");
    assert!(hover.contains("^17.0.0"), "{hover}");
}

/// FR-030: both default-catalog spellings yield one Error finding with its own code, and the
/// entries are still surfaced.
#[tokio::test]
async fn duplicate_default_catalog_is_reported_and_entries_survive() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let dir = tempfile::tempdir().unwrap();
    let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
    let backend = service.inner();

    let uri = open(
        backend,
        &dir.path().join(WORKSPACE_FILE),
        "yaml",
        "catalog:\n  react: ^17.0.0\ncatalogs:\n  default:\n    vue: ^3.0.0\n",
    )
    .await;

    let codes = diagnostic_codes(backend, &uri).await;
    assert_eq!(
        codes
            .iter()
            .filter(|code| *code == "pnpm-duplicate-default-catalog")
            .count(),
        1,
        "{codes:?}"
    );
    assert!(
        hover_text(backend, &uri, Position::new(1, 4))
            .await
            .is_some_and(|hover| hover.contains("react")),
        "entries must still be surfaced"
    );
}

/// FR-003 and FR-023: with both files open, saving a changed catalog entry refreshes the
/// referencing `package.json` and leaves the workspace file's own results available.
#[tokio::test]
async fn saving_the_workspace_file_refreshes_referencing_package_json_and_itself() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let dir = tempfile::tempdir().unwrap();
    let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
    let backend = service.inner();
    let workspace_path = dir.path().join(WORKSPACE_FILE);

    open(
        backend,
        &workspace_path,
        "yaml",
        "catalog:\n  react: ^17.0.0\n",
    )
    .await;
    let package = open(
        backend,
        &dir.path().join("package.json"),
        "json",
        r#"{"dependencies": {"react": "catalog:"}}"#,
    )
    .await;
    let name = Position::new(0, 20);
    assert!(
        hover_text(backend, &package, name)
            .await
            .is_some_and(|hover| hover.contains("^17.0.0"))
    );

    saved(backend, &workspace_path, "catalog:\n  react: ^18.3.0\n").await;

    let refreshed = hover_text(backend, &package, name).await.unwrap();
    assert!(refreshed.contains("^18.3.0"), "{refreshed}");
    let workspace = Uri::from_file_path(&workspace_path).unwrap();
    assert!(
        hover_text(backend, &workspace, Position::new(1, 4))
            .await
            .is_some(),
        "the workspace file keeps answering"
    );
}

// --- Documents installed straight into the server state, with registry data seeded, so the
// diagnostics, hints and code actions below depend on no network. ---

mod seeded {
    use std::collections::HashMap;

    use deps_core::{EcosystemId, NormalizedName, PackageVersions};
    use tower_lsp_server::ls_types::{
        CodeActionContext, CodeActionOrCommand, CodeActionParams, InlayHintParams, Range, TextEdit,
    };

    use super::*;

    fn seed(versions: &[(&str, &str)]) -> HashMap<NormalizedName, PackageVersions> {
        versions
            .iter()
            .map(|(name, latest)| {
                (
                    NormalizedName::for_test(*name),
                    PackageVersions::latest_only(*latest),
                )
            })
            .collect()
    }

    async fn install(backend: &Backend, path: &Path, text: &str, versions: &[(&str, &str)]) -> Uri {
        std::fs::write(path, text).unwrap();
        let url = url::Url::from_file_path(path).unwrap();
        let uri = Uri::from_file_path(path).unwrap();
        let ecosystem = backend
            .state()
            .ecosystem_registry
            .get(EcosystemId::Npm)
            .unwrap();
        let parse = ecosystem.parse_manifest(text, &url).await.unwrap();
        let mut doc = crate::document::DocumentState::new_from_parse_result(
            EcosystemId::Npm,
            text.into(),
            parse,
        );
        doc.set_version(Some(1));
        doc.update_cached_versions(seed(versions));
        backend.state().update_document(uri.clone(), doc);
        uri
    }

    fn offline_backend() -> (
        tower_lsp_server::LspService<Backend>,
        tower_lsp_server::ClientSocket,
    ) {
        let (service, socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        service
            .inner()
            .state()
            .cache
            .set_offline(deps_core::NetworkMode::Offline);
        (service, socket)
    }

    async fn messages(backend: &Backend, uri: &Uri) -> Vec<String> {
        let result = backend
            .diagnostic(DocumentDiagnosticParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                identifier: None,
                previous_result_id: None,
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap();
        let DocumentDiagnosticReportResult::Report(DocumentDiagnosticReport::Full(report)) = result
        else {
            panic!("expected a full diagnostic report");
        };
        report
            .full_document_diagnostic_report
            .items
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    fn apply(text: &str, edit: &TextEdit) -> String {
        let offset = |position: Position| {
            let line_start: usize = text
                .split_inclusive('\n')
                .take(position.line as usize)
                .map(str::len)
                .sum();
            line_start + position.character as usize
        };
        format!(
            "{}{}{}",
            &text[..offset(edit.range.start)],
            edit.new_text,
            &text[offset(edit.range.end)..]
        )
    }

    async fn update_edits(backend: &Backend, uri: &Uri, range: Range) -> Vec<TextEdit> {
        let actions = backend
            .code_action(CodeActionParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                range,
                context: CodeActionContext::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap()
            .unwrap_or_default();
        actions
            .into_iter()
            .filter_map(|action| match action {
                CodeActionOrCommand::CodeAction(action) => action.edit,
                CodeActionOrCommand::Command(_) => None,
            })
            .flat_map(|edit| edit.changes.unwrap_or_default().into_values().flatten())
            .collect()
    }

    /// FR-023: the DIAGNOSTIC of a referencing `package.json` follows a saved catalog edit, not
    /// only its hover.
    #[tokio::test]
    async fn saving_a_catalog_entry_updates_the_referencing_diagnostic() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let dir = tempfile::tempdir().unwrap();
        let (service, _socket) = offline_backend();
        let backend = service.inner();
        let workspace_path = dir.path().join(WORKSPACE_FILE);
        std::fs::write(&workspace_path, "catalog:\n  react: ^18.3.0\n").unwrap();
        let package = install(
            backend,
            &dir.path().join("package.json"),
            r#"{"dependencies": {"left-pad": "catalog:"}}"#,
            &[("left-pad", "1.3.0")],
        )
        .await;

        let before = messages(backend, &package).await;
        assert!(
            before
                .iter()
                .any(|m| m.contains("left-pad") && m.contains("catalog")),
            "a reference with no catalog entry must be reported: {before:?}"
        );

        saved(
            backend,
            &workspace_path,
            "catalog:\n  react: ^18.3.0\n  left-pad: ^1.3.0\n",
        )
        .await;
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let current = messages(backend, &package).await;
                if current.iter().all(|m| !m.contains("catalog")) {
                    break current;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            resolved.is_ok(),
            "the resolved reference must no longer be reported after the catalog is saved"
        );
    }

    const OUTDATED_CATALOG: &str = "catalog:\n  react: ^16.0.0\n  vue: \"^2.0.0\"\n";

    /// FR-017: the update rewrites only the version text of the entry and keeps its quoting. The
    /// written version is the bare exact one, as npm writes it in `package.json` (SC-007).
    #[tokio::test]
    async fn catalog_entry_update_action_rewrites_only_its_scalar() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let dir = tempfile::tempdir().unwrap();
        let (service, _socket) = offline_backend();
        let backend = service.inner();
        let workspace = install(
            backend,
            &dir.path().join(WORKSPACE_FILE),
            OUTDATED_CATALOG,
            &[("react", "18.3.0"), ("vue", "3.4.0")],
        )
        .await;

        let react = Range::new(Position::new(1, 9), Position::new(1, 16));
        let edits = update_edits(backend, &workspace, react).await;
        let [edit] = edits.as_slice() else {
            panic!("exactly one edit expected for the react entry: {edits:?}");
        };
        assert_eq!(
            apply(OUTDATED_CATALOG, edit),
            "catalog:\n  react: 18.3.0\n  vue: \"^2.0.0\"\n"
        );

        let vue = Range::new(Position::new(2, 9), Position::new(2, 12));
        let edits = update_edits(backend, &workspace, vue).await;
        let [edit] = edits.as_slice() else {
            panic!("exactly one edit expected for the vue entry: {edits:?}");
        };
        assert_eq!(
            apply(OUTDATED_CATALOG, edit),
            "catalog:\n  react: ^16.0.0\n  vue: \"3.4.0\"\n",
            "quoting style is preserved"
        );
    }

    /// US-002: a `catalog:` reference has no sound edit in `package.json`; the version lives in
    /// the workspace file.
    #[tokio::test]
    async fn catalog_reference_in_package_json_gets_no_version_edit() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let dir = tempfile::tempdir().unwrap();
        let (service, _socket) = offline_backend();
        let backend = service.inner();
        std::fs::write(dir.path().join(WORKSPACE_FILE), OUTDATED_CATALOG).unwrap();
        let text = r#"{"dependencies": {"react": "catalog:"}}"#;
        let package = install(
            backend,
            &dir.path().join("package.json"),
            text,
            &[("react", "18.3.0")],
        )
        .await;

        let edits = update_edits(
            backend,
            &package,
            Range::new(Position::new(0, 0), Position::new(0, text.len() as u32)),
        )
        .await;

        assert!(
            edits.iter().all(|edit| !edit.new_text.contains("18.3.0")),
            "no update edit may target the reference: {edits:?}"
        );
    }

    /// FR-014: inlay hints on catalog entries carry the same latest/outdated markers as a
    /// `package.json` dependency.
    #[tokio::test]
    async fn catalog_entries_get_inlay_hints_with_the_latest_version() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let dir = tempfile::tempdir().unwrap();
        let (service, _socket) = offline_backend();
        let backend = service.inner();
        let workspace = install(
            backend,
            &dir.path().join(WORKSPACE_FILE),
            OUTDATED_CATALOG,
            &[("react", "18.3.0"), ("vue", "3.4.0")],
        )
        .await;

        let hints = backend
            .inlay_hint(InlayHintParams {
                text_document: TextDocumentIdentifier { uri: workspace },
                range: Range::new(Position::new(0, 0), Position::new(10, 0)),
                work_done_progress_params: Default::default(),
            })
            .await
            .unwrap()
            .unwrap_or_default();

        let label_on = |line: u32| {
            hints
                .iter()
                .find(|hint| hint.position.line == line)
                .map(|hint| serde_json::to_string(&hint.label).unwrap())
        };
        assert!(
            label_on(1).is_some_and(|label| label.contains("18.3.0")),
            "{hints:?}"
        );
        assert!(
            label_on(2).is_some_and(|label| label.contains("3.4.0")),
            "{hints:?}"
        );
        assert!(
            label_on(0).is_none(),
            "the `catalog:` key itself gets no hint"
        );
    }
}
