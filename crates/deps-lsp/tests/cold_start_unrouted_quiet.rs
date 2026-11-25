//! #2172: a cold-start request (document never opened) for a file no ecosystem handles is logged
//! at debug, never WARN, including a burst that trips the cold-start limiter and a server with
//! cold start disabled. A routed file that fails to load still warns.
#![expect(clippy::unwrap_used, reason = "test code")]

mod log_capture;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::Service as _;
use tower_lsp_server::LanguageServer as _;
use tower_lsp_server::ls_types::{
    CodeLensParams, DocumentLinkParams, HoverParams, InitializeParams, InlayHintParams,
};

fn params<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

async fn server(
    init_options: Value,
) -> (
    tower_lsp_server::LspService<deps_lsp::Backend>,
    tower_lsp_server::ClientSocket,
) {
    let (mut service, socket) =
        tower_lsp_server::LspService::build(deps_lsp::Backend::new).finish();
    let init = InitializeParams {
        initialization_options: Some(init_options),
        ..InitializeParams::default()
    };
    let request = tower_lsp_server::jsonrpc::Request::build("initialize")
        .id(1_i64)
        .params(serde_json::to_value(init).unwrap())
        .finish();
    assert!(
        service
            .call(request)
            .await
            .unwrap()
            .is_some_and(|r| r.is_ok())
    );
    (service, socket)
}

/// Sends hover, inlay hint, code lens and document link for `uri`, `rounds` times.
async fn burst(backend: &deps_lsp::Backend, uri: &str, rounds: usize) {
    for _ in 0..rounds {
        let text_document = json!({ "uri": uri });
        let _ = backend
            .hover(params::<HoverParams>(json!({
                "textDocument": text_document,
                "position": { "line": 0, "character": 0 },
            })))
            .await;
        let _ = backend
            .inlay_hint(params::<InlayHintParams>(json!({
                "textDocument": text_document,
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 5, "character": 0 },
                },
            })))
            .await;
        let _ = backend
            .code_lens(params::<CodeLensParams>(
                json!({ "textDocument": text_document }),
            ))
            .await;
        let _ = backend
            .document_link(params::<DocumentLinkParams>(
                json!({ "textDocument": text_document }),
            ))
            .await;
    }
}

fn file_uri(dir: &tempfile::TempDir, name: &str, content: Option<&str>) -> String {
    let path = dir.path().canonicalize().unwrap().join(name);
    if let Some(content) = content {
        std::fs::write(&path, content).unwrap();
    }
    url::Url::from_file_path(path).unwrap().to_string()
}

#[tokio::test(flavor = "current_thread")]
async fn cold_start_burst_on_unrouted_file_logs_no_warning_and_routed_load_failure_still_warns() {
    let (logs, _guard) = log_capture::LogCapture::install();
    let dir = tempfile::tempdir().unwrap();
    let unrouted = file_uri(&dir, "rustfmt.toml", Some("max_width = 100\n"));
    let missing_routed = file_uri(&dir, "package.json", None);
    let (service, _socket) = server(json!({ "cold_start": { "rate_limit_ms": 60_000 } })).await;
    let backend = service.inner();

    burst(backend, &unrouted, 3).await;

    let warnings = logs.warnings_containing("rustfmt.toml");
    assert!(
        warnings.is_empty(),
        "unrouted cold start logged at WARN: {warnings:?}"
    );

    burst(backend, &missing_routed, 1).await;
    assert!(
        !logs.warnings_containing("package.json").is_empty(),
        "a routed file that fails to load must still warn"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cold_start_disabled_logs_no_warning_for_unrouted_or_routed_files() {
    let (logs, _guard) = log_capture::LogCapture::install();
    let dir = tempfile::tempdir().unwrap();
    let unrouted = file_uri(&dir, "rustfmt.toml", Some("max_width = 100\n"));
    let routed = file_uri(
        &dir,
        "package.json",
        Some(r#"{"dependencies": {"express": "^4.18.0"}}"#),
    );
    let (service, _socket) = server(json!({ "cold_start": { "enabled": false } })).await;
    let backend = service.inner();

    burst(backend, &unrouted, 2).await;
    burst(backend, &routed, 2).await;

    for name in ["rustfmt.toml", "package.json"] {
        let warnings = logs.warnings_containing(name);
        assert!(
            warnings.is_empty(),
            "cold start disabled by configuration logged at WARN for {name}: {warnings:?}"
        );
    }
    assert!(
        logs.debug_containing("package.json")
            .iter()
            .any(|line| line.contains("old start")),
        "the skipped routed load must be visible at debug and name the cold start (span fields \
         alone carry the uri)"
    );
}
