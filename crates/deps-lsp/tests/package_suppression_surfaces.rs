//! Per-package suppression across hover, inlay hints, code lens, the update-all command and
//! diagnostics, plus `diagnostics.ignore` (#1967, spec 094 FR-009/FR-010 as amended: `ignore`
//! hides only the four suppressible kinds, never vulnerability, unknown-package, unsatisfiable
//! or typosquat diagnostics).
//!
//! Every case runs the real handlers over one npm manifest whose registry is a `mockito` server
//! reached through the fixture's `.npmrc`; settings go through the real `DepsConfig` parse.

#![cfg(feature = "npm")]
#![expect(clippy::expect_used, reason = "test code")]

use std::sync::Arc;
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, handle_document_open};
use deps_lsp::handlers::code_lens::handle_code_lens;
use deps_lsp::handlers::diagnostics::handle_diagnostics;
use deps_lsp::handlers::hover::handle_hover;
use deps_lsp::handlers::inlay_hints::handle_inlay_hints;
use deps_lsp::lsp_types_interop::to_lsp_uri;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower_lsp_server::ls_types::{CodeLens, Diagnostic, Hover, InlayHint, Uri};
use tower_lsp_server::{Client, LanguageServer, LspService};

const MANIFEST: &str = "{\n  \"name\": \"fixture\",\n  \"dependencies\": {\n    \"react\": \"^16.0.0\",\n    \"left-pad\": \"^1.0.0\",\n    \"ghost-pkg\": \"^1.0.0\",\n    \"stale-pin\": \"^9.0.0\"\n  }\n}\n";
const GHOST_LINE: u32 = 5;
const STALE_LINE: u32 = 6;
const REACT_LINE: u32 = 3;
const LEFT_PAD_LINE: u32 = 4;

const REACT_OUTDATED: &str = r#"{"versions": {"16.0.0": {}, "19.3.0": {}}}"#;
const REACT_DEPRECATED: &str = r#"{"versions": {"16.0.0": {"deprecated": "moved to preact"}, "19.3.0": {"deprecated": "moved to preact"}}}"#;
const LEFT_PAD_OUTDATED: &str = r#"{"versions": {"1.0.0": {}, "2.0.0": {}}}"#;

struct Fixture {
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
    client: Client,
    uri: Uri,
    _service: LspService<Backend>,
    _dir: tempfile::TempDir,
    _server: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
}

fn settings(diagnostics: Value) -> Value {
    let mut diagnostics = diagnostics;
    diagnostics
        .as_object_mut()
        .expect("diagnostics settings are a JSON object")
        .insert("vulnerabilities_enabled".to_owned(), json!(false));
    json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": diagnostics,
    })
}

fn suppress(package: &str, kinds: &[&str]) -> Value {
    json!({ "suppress": [{"package": package, "kinds": kinds}] })
}

async fn fixture(diagnostics: Value, react: &str) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let mut mocks = Vec::new();
    for (name, body) in [
        ("react", react),
        ("left-pad", LEFT_PAD_OUTDATED),
        ("stale-pin", r#"{"versions": {"1.0.0": {}}}"#),
    ] {
        mocks.push(
            server
                .mock("GET", format!("/{name}").as_str())
                .with_status(200)
                .with_body(body)
                .expect_at_least(0)
                .create_async()
                .await,
        );
    }
    mocks.push(
        server
            .mock("GET", "/ghost-pkg")
            .with_status(404)
            .with_body("{}")
            .expect_at_least(0)
            .create_async()
            .await,
    );
    let host = server.host_with_port();

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical temp dir");
    std::fs::write(root.join(".npmrc"), format!("registry=http://{host}/\n")).expect("npmrc");
    let path = root.join("package.json");
    std::fs::write(&path, MANIFEST).expect("manifest");

    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let state = Arc::new(ServerState::from_env_source(&env));
    state
        .cache
        .set_registry_policy(deps_core::policy_config::WorkspaceRegistriesSetting::All.to_policy());
    let config: DepsConfig =
        serde_json::from_value(settings(diagnostics)).expect("settings parse as DepsConfig");
    let config = Arc::new(RwLock::new(config));

    let slot = std::sync::Mutex::new(None);
    let (service, _socket) = LspService::new(|client| {
        *slot.lock().expect("slot") = Some(client.clone());
        Backend::new(client)
    });
    let client = slot.into_inner().expect("slot").expect("client");

    let url = url::Url::from_file_path(&path).expect("absolute path");
    let uri = to_lsp_uri(&url);
    let opened = handle_document_open(
        uri.clone(),
        MANIFEST.to_owned(),
        Some(1),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    .expect("document opens");
    assert!(opened, "the open must not lose a race");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !state
            .with_document(&uri, |doc| {
                matches!(
                    doc.loading_state(),
                    deps_core::LoadingState::Loaded | deps_core::LoadingState::Failed
                )
            })
            .unwrap_or(false)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("document load settles");

    Fixture {
        state,
        config,
        client,
        uri,
        _service: service,
        _dir: dir,
        _server: server,
        _mocks: mocks,
    }
}

impl Fixture {
    async fn hover(&self, line: u32) -> String {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
            "position": {"line": line, "character": 6},
        }))
        .expect("hover params");
        let hover: Option<Hover> = handle_hover(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        serde_json::to_string(&hover.expect("hover on a dependency name")).expect("serialize")
    }

    async fn inlay_labels(&self) -> Vec<(u32, String)> {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 50, "character": 0}},
        }))
        .expect("inlay params");
        let inlay = self.config.read().await.inlay_hints.clone();
        let hints: Vec<InlayHint> = handle_inlay_hints(
            Arc::clone(&self.state),
            params,
            &inlay,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        hints
            .into_iter()
            .map(|hint| {
                let label = serde_json::to_value(&hint.label).expect("label");
                (
                    hint.position.line,
                    label.as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }

    async fn code_lenses(&self) -> Vec<CodeLens> {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
        }))
        .expect("lens params");
        handle_code_lens(
            Arc::clone(&self.state),
            params,
            true,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
    }

    async fn diagnostics(&self) -> Vec<Diagnostic> {
        handle_diagnostics(
            Arc::clone(&self.state),
            &self.uri,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
    }
}

fn hint_on(labels: &[(u32, String)], line: u32) -> Option<&str> {
    labels
        .iter()
        .find(|(l, _)| *l == line)
        .map(|(_, label)| label.as_str())
}

fn lens_titles(lenses: &[CodeLens]) -> Vec<String> {
    lenses
        .iter()
        .filter_map(|lens| lens.command.as_ref().map(|c| c.title.clone()))
        .collect()
}

fn diagnostics_on(diagnostics: &[Diagnostic], line: u32) -> Vec<&Diagnostic> {
    diagnostics
        .iter()
        .filter(|d| d.range.start.line == line)
        .collect()
}

fn lens_count(lenses: &[CodeLens]) -> Option<usize> {
    let titles = lens_titles(lenses);
    let title = titles.first()?;
    title
        .split(|c: char| !c.is_ascii_digit())
        .find(|part| !part.is_empty())
        .and_then(|digits| digits.parse().ok())
}

const DEPRECATED_SECTION: &str = "This package is deprecated";
const LATEST_LINE: &str = "**Latest**: `19.3.0`";
const NEEDS_UPDATE_REACT: &str = "\u{274c} 19.3.0";
const NEEDS_UPDATE_LEFT_PAD: &str = "\u{274c} 2.0.0";
const UP_TO_DATE: &str = "\u{2705}";

fn has_message(diagnostics: &[Diagnostic], line: u32, needle: &str) -> bool {
    diagnostics_on(diagnostics, line)
        .iter()
        .any(|d| d.message.contains(needle))
}

fn has_code(diagnostics: &[Diagnostic], line: u32, code: &str) -> bool {
    diagnostics_on(diagnostics, line).iter().any(|d| {
        matches!(&d.code, Some(tower_lsp_server::ls_types::NumberOrString::String(c)) if c == code)
    })
}

// --- hover -----------------------------------------------------------------------------

#[tokio::test]
async fn hover_baseline_shows_deprecation_and_latest() {
    let fx = fixture(json!({}), REACT_DEPRECATED).await;
    let hover = fx.hover(REACT_LINE).await;
    assert!(hover.contains(DEPRECATED_SECTION), "{hover}");
    assert!(hover.contains(LATEST_LINE), "{hover}");
}

#[tokio::test]
async fn hover_deprecated_suppression_drops_deprecation_section_keeps_latest() {
    let fx = fixture(suppress("react", &["deprecated"]), REACT_DEPRECATED).await;
    let hover = fx.hover(REACT_LINE).await;
    assert!(!hover.contains(DEPRECATED_SECTION), "{hover}");
    assert!(hover.contains(LATEST_LINE), "{hover}");
}

#[tokio::test]
async fn hover_ignore_drops_deprecation_section_keeps_latest() {
    let fx = fixture(json!({"ignore": ["react"]}), REACT_DEPRECATED).await;
    let hover = fx.hover(REACT_LINE).await;
    assert!(!hover.contains(DEPRECATED_SECTION), "{hover}");
    assert!(hover.contains(LATEST_LINE), "{hover}");
}

#[tokio::test]
async fn hover_outdated_suppression_keeps_deprecation_section() {
    let fx = fixture(suppress("react", &["outdated"]), REACT_DEPRECATED).await;
    let hover = fx.hover(REACT_LINE).await;
    assert!(hover.contains(DEPRECATED_SECTION), "{hover}");
    assert!(hover.contains(LATEST_LINE), "{hover}");
}

#[tokio::test]
async fn hover_suppression_for_another_package_keeps_deprecation_section() {
    let fx = fixture(suppress("left-pad", &["deprecated"]), REACT_DEPRECATED).await;
    assert!(fx.hover(REACT_LINE).await.contains(DEPRECATED_SECTION));
}

// --- inlay hints -----------------------------------------------------------------------

#[tokio::test]
async fn inlay_baseline_marks_both_packages_outdated() {
    let fx = fixture(json!({}), REACT_OUTDATED).await;
    let labels = fx.inlay_labels().await;
    assert_eq!(hint_on(&labels, REACT_LINE), Some(NEEDS_UPDATE_REACT));
    assert_eq!(hint_on(&labels, LEFT_PAD_LINE), Some(NEEDS_UPDATE_LEFT_PAD));
}

#[tokio::test]
async fn inlay_outdated_suppression_renders_up_to_date_for_that_package_only() {
    let fx = fixture(suppress("react", &["outdated"]), REACT_OUTDATED).await;
    let labels = fx.inlay_labels().await;
    assert_eq!(hint_on(&labels, REACT_LINE), Some(UP_TO_DATE), "{labels:?}");
    assert_eq!(hint_on(&labels, LEFT_PAD_LINE), Some(NEEDS_UPDATE_LEFT_PAD));
}

#[tokio::test]
async fn inlay_outdated_suppression_removes_needs_update_hint_and_keeps_others() {
    let fx = fixture(suppress("react", &["outdated"]), REACT_OUTDATED).await;
    let labels = fx.inlay_labels().await;
    assert_ne!(
        hint_on(&labels, REACT_LINE),
        Some(NEEDS_UPDATE_REACT),
        "{labels:?}"
    );
    assert_eq!(
        hint_on(&labels, LEFT_PAD_LINE),
        Some(NEEDS_UPDATE_LEFT_PAD),
        "{labels:?}"
    );
}

#[tokio::test]
async fn inlay_other_kind_suppression_keeps_outdated_hint() {
    let fx = fixture(
        suppress("react", &["deprecated", "yanked", "license"]),
        REACT_OUTDATED,
    )
    .await;
    let labels = fx.inlay_labels().await;
    assert_eq!(hint_on(&labels, REACT_LINE), Some(NEEDS_UPDATE_REACT));
}

#[tokio::test]
async fn inlay_ignore_removes_the_hint_for_that_package_only() {
    let fx = fixture(json!({"ignore": ["react"]}), REACT_OUTDATED).await;
    let labels = fx.inlay_labels().await;
    assert_eq!(hint_on(&labels, REACT_LINE), None, "{labels:?}");
    assert_eq!(hint_on(&labels, LEFT_PAD_LINE), Some(NEEDS_UPDATE_LEFT_PAD));
}

// --- code lens (shares collect_update_all_edits with the update-all command) -----------

#[tokio::test]
async fn code_lens_baseline_counts_every_outdated_dependency() {
    let fx = fixture(json!({}), REACT_OUTDATED).await;
    assert_eq!(lens_count(&fx.code_lenses().await), Some(3));
}

#[tokio::test]
async fn code_lens_excludes_packages_with_outdated_suppressed() {
    let fx = fixture(suppress("react", &["outdated"]), REACT_OUTDATED).await;
    assert_eq!(lens_count(&fx.code_lenses().await), Some(2));
}

#[tokio::test]
async fn code_lens_excludes_packages_matched_by_glob_suppression() {
    let fx = fixture(suppress("*-pad", &["outdated"]), REACT_OUTDATED).await;
    assert_eq!(lens_count(&fx.code_lenses().await), Some(2));
}

#[tokio::test]
async fn code_lens_excludes_ignored_packages() {
    let fx = fixture(json!({"ignore": ["react", "left-pad"]}), REACT_OUTDATED).await;
    assert_eq!(lens_count(&fx.code_lenses().await), Some(1));
}

#[tokio::test]
async fn code_lens_is_absent_when_every_outdated_package_is_suppressed() {
    let fx = fixture(
        json!({"ignore": ["react", "left-pad", "stale-pin"]}),
        REACT_OUTDATED,
    )
    .await;
    assert_eq!(lens_count(&fx.code_lenses().await), None);
}

#[tokio::test]
async fn code_lens_keeps_package_when_only_other_kinds_are_suppressed() {
    let fx = fixture(
        suppress("react", &["deprecated", "yanked", "license"]),
        REACT_OUTDATED,
    )
    .await;
    assert_eq!(lens_count(&fx.code_lenses().await), Some(3));
}

// --- diagnostics.ignore -----------------------------------------------------------------

#[tokio::test]
async fn diagnostics_ignore_hides_deprecated_and_outdated_for_that_package() {
    let fx = fixture(json!({"ignore": ["react"]}), REACT_DEPRECATED).await;
    let diagnostics = fx.diagnostics().await;
    assert!(
        diagnostics_on(&diagnostics, REACT_LINE).is_empty(),
        "{diagnostics:?}"
    );
    assert!(has_message(
        &diagnostics,
        LEFT_PAD_LINE,
        "Newer version available"
    ));
}

#[tokio::test]
async fn diagnostics_ignore_glob_hides_matching_packages() {
    let fx = fixture(json!({"ignore": ["*-pad"]}), REACT_OUTDATED).await;
    let diagnostics = fx.diagnostics().await;
    assert!(
        diagnostics_on(&diagnostics, LEFT_PAD_LINE).is_empty(),
        "{diagnostics:?}"
    );
    assert!(has_message(
        &diagnostics,
        REACT_LINE,
        "Newer version available"
    ));
}

#[tokio::test]
async fn diagnostics_ignore_keeps_unknown_package_diagnostic() {
    let fx = fixture(json!({"ignore": ["ghost-pkg"]}), REACT_OUTDATED).await;
    let diagnostics = fx.diagnostics().await;
    assert!(
        has_message(&diagnostics, GHOST_LINE, "Unknown package"),
        "{diagnostics:?}"
    );
}

#[tokio::test]
async fn diagnostics_ignore_keeps_unsatisfiable_diagnostic() {
    let fx = fixture(json!({"ignore": ["stale-pin"]}), REACT_OUTDATED).await;
    let diagnostics = fx.diagnostics().await;
    assert!(
        has_code(&diagnostics, STALE_LINE, "unsatisfiable-requirement"),
        "{diagnostics:?}"
    );
}

#[tokio::test]
async fn diagnostics_suppress_alone_still_hides_only_its_kinds() {
    let fx = fixture(suppress("react", &["outdated"]), REACT_DEPRECATED).await;
    let diagnostics = fx.diagnostics().await;
    assert!(!has_message(
        &diagnostics,
        REACT_LINE,
        "Newer version available"
    ));
    assert!(has_code(&diagnostics, REACT_LINE, "deprecated-package"));
}

#[test]
fn config_with_bare_wildcard_ignore_is_rejected() {
    let result = serde_json::from_value::<DepsConfig>(settings(json!({"ignore": ["*"]})));
    assert!(result.is_err());
}

// --- update-all command -----------------------------------------------------------------

mod update_all {
    use super::*;
    use futures::StreamExt as _;
    use tower::Service as _;
    use tower_lsp_server::jsonrpc::Request;
    use tower_lsp_server::ls_types::{
        DidChangeConfigurationParams, DidOpenTextDocumentParams, ExecuteCommandParams,
        InitializeParams,
    };

    struct Session {
        service: LspService<Backend>,
        messages: tokio::sync::mpsc::UnboundedReceiver<Request>,
        uri: Uri,
        _dir: tempfile::TempDir,
        _server: mockito::ServerGuard,
        _mocks: Vec<mockito::Mock>,
    }

    async fn session(diagnostics: Value) -> Session {
        let mut server = mockito::Server::new_async().await;
        let mut mocks = Vec::new();
        for (name, body, status) in [
            ("react", REACT_OUTDATED, 200),
            ("left-pad", LEFT_PAD_OUTDATED, 200),
            ("stale-pin", r#"{"versions": {"1.0.0": {}}}"#, 200),
            ("ghost-pkg", "{}", 404),
        ] {
            mocks.push(
                server
                    .mock("GET", format!("/{name}").as_str())
                    .with_status(status)
                    .with_body(body)
                    .expect_at_least(0)
                    .create_async()
                    .await,
            );
        }
        let host = server.host_with_port();
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("canonical");
        std::fs::write(root.join(".npmrc"), format!("registry=http://{host}/\n")).expect("npmrc");
        let path = root.join("package.json");
        std::fs::write(&path, MANIFEST).expect("manifest");

        let env = MapEnv::new().with_var(
            PRIVATE_REGISTRY_HOSTS_ENV,
            host.split(':').next().expect("host"),
        );
        let (mut service, mut socket) = LspService::build(|client| {
            Backend::with_state(client, ServerState::from_env_source(&env))
        })
        .finish();
        let init = Request::build("initialize")
            .id(1_i64)
            .params(serde_json::to_value(InitializeParams::default()).expect("params"))
            .finish();
        let response = service.call(init).await.expect("initialize");
        assert!(response.is_some_and(|r| r.is_ok()));

        let (tx, messages) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = socket.next().await {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });

        let backend = service.inner();
        backend
            .did_change_configuration(DidChangeConfigurationParams {
                settings: settings(diagnostics),
            })
            .await;
        let url = url::Url::from_file_path(&path).expect("url");
        let uri = to_lsp_uri(&url);
        backend
            .did_open(
                serde_json::from_value::<DidOpenTextDocumentParams>(json!({
                    "textDocument": {
                        "uri": uri.as_str(),
                        "languageId": "json",
                        "version": 1,
                        "text": MANIFEST,
                    }
                }))
                .expect("did_open params"),
            )
            .await;
        Session {
            service,
            messages,
            uri,
            _dir: dir,
            _server: server,
            _mocks: mocks,
        }
    }

    async fn wait_for_lens(session: &Session) {
        let backend = session.service.inner();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let params = serde_json::from_value(json!({
                    "textDocument": {"uri": session.uri.as_str()},
                }))
                .expect("lens params");
                if backend
                    .code_lens(params)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|lenses| !lenses.is_empty())
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the document becomes ready for batch update");
    }

    async fn apply_edit_payload(session: &mut Session) -> String {
        let backend = session.service.inner();
        let command = backend.execute_command(
            serde_json::from_value::<ExecuteCommandParams>(json!({
                "command": "deps-lsp.updateAllOutdated",
                "arguments": [{"uri": session.uri.as_str()}],
            }))
            .expect("command params"),
        );
        let find_edit = async {
            while let Some(message) = session.messages.recv().await {
                if message.method() == "workspace/applyEdit" {
                    return message
                        .params()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                }
            }
            String::new()
        };
        tokio::select! {
            _ = command => panic!("update-all finished without sending workspace/applyEdit"),
            payload = tokio::time::timeout(Duration::from_secs(8), find_edit) => {
                payload.expect("workspace/applyEdit within the timeout")
            }
        }
    }

    #[tokio::test]
    async fn update_all_baseline_edits_every_outdated_dependency() {
        let mut session = session(json!({})).await;
        wait_for_lens(&session).await;
        let payload = apply_edit_payload(&mut session).await;
        for version in ["19.3.0", "2.0.0"] {
            assert!(payload.contains(version), "{payload}");
        }
    }

    #[tokio::test]
    async fn update_all_skips_packages_with_outdated_suppressed() {
        let mut session = session(suppress("react", &["outdated"])).await;
        wait_for_lens(&session).await;
        let payload = apply_edit_payload(&mut session).await;
        assert!(!payload.contains("19.3.0"), "{payload}");
        assert!(payload.contains("2.0.0"), "{payload}");
    }

    #[tokio::test]
    async fn update_all_skips_ignored_packages() {
        let mut session = session(json!({"ignore": ["react"]})).await;
        wait_for_lens(&session).await;
        let payload = apply_edit_payload(&mut session).await;
        assert!(!payload.contains("19.3.0"), "{payload}");
        assert!(payload.contains("2.0.0"), "{payload}");
    }
}
