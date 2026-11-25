//! #2161: an LSP `didOpen` of a `*.toml` that `settings.gradle.kts` declares as a version catalog
//! is tracked as a Gradle document and keeps committing edits; an undeclared `*.toml` is rejected.
#![cfg(feature = "gradle")]
#![expect(clippy::unwrap_used, reason = "test code")]

use std::sync::Arc;

use deps_core::{DepsError, EcosystemId};
use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, handle_document_change, handle_document_open};
use deps_lsp::lsp_types_interop::to_lsp_uri;
use tokio::sync::RwLock;
use tower_lsp_server::LspService;
use tower_lsp_server::ls_types::Uri;

const SETTINGS: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";
const CATALOG: &str = "[versions]\nx = \"1\"\n";
const CHANGED: &str = "[versions]\nx = \"2\"\n";

struct Harness {
    _dir: tempfile::TempDir,
    declared: Uri,
    undeclared: Uri,
    state: Arc<ServerState>,
    client: tower_lsp_server::Client,
    config: Arc<RwLock<DepsConfig>>,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS).unwrap();
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).unwrap();
    std::fs::write(root.join("other.toml"), CATALOG).unwrap();
    let slot = std::sync::Mutex::new(None);
    let (_service, _socket) = LspService::new(|client| {
        *slot.lock().unwrap() = Some(client.clone());
        Backend::new(client)
    });
    Harness {
        declared: to_lsp_uri(&url::Url::from_file_path(root.join("gradle/deps.toml")).unwrap()),
        undeclared: to_lsp_uri(&url::Url::from_file_path(root.join("other.toml")).unwrap()),
        _dir: dir,
        state: Arc::new(ServerState::new()),
        client: slot.into_inner().unwrap().unwrap(),
        config: Arc::new(RwLock::new(DepsConfig::default())),
    }
}

#[tokio::test]
async fn open_of_a_declared_catalog_is_tracked_as_gradle_and_a_following_change_commits() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let h = harness();

    handle_document_open(
        h.declared.clone(),
        CATALOG.to_owned(),
        Some(1),
        Arc::clone(&h.state),
        h.client.clone(),
        Arc::clone(&h.config),
    )
    .await
    .unwrap();

    let ecosystem = h.state.get_document(&h.declared).unwrap().ecosystem;
    assert_eq!(ecosystem, EcosystemId::Gradle);

    let task = handle_document_change(
        h.declared.clone(),
        CHANGED.to_owned(),
        Some(2),
        Arc::clone(&h.state),
        h.client.clone(),
        Arc::clone(&h.config),
    )
    .await
    .unwrap();
    if let Some(task) = task {
        task.await.unwrap();
    }

    assert_eq!(h.state.get_document(&h.declared).unwrap().content, CHANGED);
}

#[tokio::test]
async fn open_of_an_undeclared_toml_is_rejected_as_unsupported() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let h = harness();

    let result = handle_document_open(
        h.undeclared.clone(),
        CATALOG.to_owned(),
        Some(1),
        Arc::clone(&h.state),
        h.client.clone(),
        Arc::clone(&h.config),
    )
    .await;

    assert!(matches!(result, Err(DepsError::UnsupportedEcosystem(_))));
    assert!(h.state.get_document(&h.undeclared).is_none());
}
