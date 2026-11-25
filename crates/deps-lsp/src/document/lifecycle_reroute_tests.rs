//! #2180: re-routing after a declaring settings file changes, against a `didClose` or unsaved
//! editor text racing it.
//!
//! The seam is `plan_reroute` / `apply_reroute`: a test runs the editor notification between the
//! claim snapshot and the changes made from it.

#![expect(clippy::unwrap_used, reason = "test code")]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;

const EDITOR_TEXT: &str = "[libraries]\nbad-alias = \"unsaved\"\n";
const DISK_TEXT: &str = "[libraries]\nbad-alias = \"on-disk\"\n";
const DECLARING: &str = "versionCatalogs { create(\"d\") { from(files(\"gradle/deps.toml\")) } }\n";

struct Fixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    uri: Uri,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("gradle")).unwrap();
        std::fs::write(root.join("gradle/deps.toml"), DISK_TEXT).unwrap();
        let url = url::Url::from_file_path(root.join("gradle/deps.toml")).unwrap();
        let (client, config) = create_test_client_and_config();
        let state = Arc::new(ServerState::new());
        state.set_workspace_folders(vec![root.clone()]);
        Self {
            _dir: dir,
            uri: crate::lsp_types_interop::to_lsp_uri(&url),
            root,
            state,
            client,
            config,
        }
    }

    fn declare(&self, declared: bool) {
        let settings = if declared { DECLARING } else { "" };
        std::fs::write(self.root.join("settings.gradle.kts"), settings).unwrap();
    }

    async fn open(&self, content: &str) {
        let opened = handle_document_open(
            self.uri.clone(),
            content.to_owned(),
            Some(1),
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        assert!(opened.is_ok_and(|opened| opened) || self.state.get_document(&self.uri).is_none());
    }

    async fn close(&self) {
        close_document(&self.state, &self.uri, |_, _| async {}).await;
    }

    async fn reroute(&self) {
        reroute_claimed_documents(&self.state, &self.client, &self.config).await;
    }

    fn content(&self) -> Option<String> {
        self.state
            .get_document(&self.uri)
            .map(|doc| doc.content.clone())
    }
}

#[tokio::test]
async fn a_close_during_the_probe_of_an_unrouted_open_does_not_open_it() {
    let fx = Fixture::new();
    fx.declare(false);
    fx.open(EDITOR_TEXT).await;
    fx.declare(true);
    let plan = plan_reroute(&fx.state).await.unwrap();

    fx.close().await;
    apply_reroute(plan, &fx.state, &fx.client, &fx.config).await;

    assert_eq!(fx.content(), None, "a closed file must stay untracked");
    assert!(fx.state.remembered_unrouted_opens().is_empty());
}

#[tokio::test]
async fn a_close_during_the_probe_of_a_claimed_document_does_not_remember_it() {
    let fx = Fixture::new();
    fx.declare(true);
    fx.open(EDITOR_TEXT).await;
    assert!(fx.content().is_some(), "precondition: claimed");
    fx.declare(false);
    let plan = plan_reroute(&fx.state).await.unwrap();

    fx.close().await;
    apply_reroute(plan, &fx.state, &fx.client, &fx.config).await;

    assert_eq!(fx.content(), None);
    assert!(
        fx.state.remembered_unrouted_opens().is_empty(),
        "a closed file must not be remembered"
    );
}

#[tokio::test]
async fn a_newly_claimed_open_keeps_the_editors_unsaved_text() {
    let fx = Fixture::new();
    fx.declare(false);
    fx.open(EDITOR_TEXT).await;
    fx.declare(true);

    fx.reroute().await;

    assert_eq!(fx.content().as_deref(), Some(EDITOR_TEXT));
}

#[tokio::test]
async fn an_edit_of_an_unrouted_document_is_what_a_later_claim_opens() {
    let fx = Fixture::new();
    fx.declare(false);
    fx.open(EDITOR_TEXT).await;
    let edited = "[libraries]\nbad-alias = \"edited\"\n";
    fx.state.update_unrouted_open(&fx.uri, edited, Some(2));
    fx.state.update_unrouted_open(&fx.uri, EDITOR_TEXT, Some(1));
    fx.declare(true);

    fx.reroute().await;

    assert_eq!(fx.content().as_deref(), Some(edited));
    assert_eq!(fx.state.get_document(&fx.uri).unwrap().version, Some(2));
}

#[tokio::test]
async fn a_dropped_claim_remembers_the_editor_text_for_the_next_declaration() {
    let fx = Fixture::new();
    fx.declare(true);
    fx.open(EDITOR_TEXT).await;
    fx.declare(false);
    fx.reroute().await;
    assert_eq!(fx.content(), None);

    fx.declare(true);
    fx.reroute().await;

    assert_eq!(fx.content().as_deref(), Some(EDITOR_TEXT));
}

#[test]
fn remembered_documents_are_bounded_in_count_and_text() {
    let state = ServerState::new();
    let uri = |n: usize| -> Uri { format!("file:///w/{n}.toml").parse().unwrap() };
    let huge = "x".repeat(super::super::state::MAX_UNROUTED_BYTES + 1);
    state.remember_unrouted_open(&uri(0), &huge, Some(1));
    assert!(state.unrouted_open(&uri(0)).is_none());

    let half = "x".repeat(super::super::state::MAX_UNROUTED_BYTES / 2);
    for n in 1..=3 {
        state.remember_unrouted_open(&uri(n), &half, Some(1));
    }
    assert!(
        state.unrouted_open(&uri(1)).is_none(),
        "the oldest made room"
    );
    assert!(state.unrouted_open(&uri(3)).is_some());

    for n in 10..=10 + super::super::state::MAX_UNROUTED_OPENS {
        state.remember_unrouted_open(&uri(n), "", Some(1));
    }
    assert_eq!(
        state.remembered_unrouted_opens().len(),
        super::super::state::MAX_UNROUTED_OPENS
    );
}
