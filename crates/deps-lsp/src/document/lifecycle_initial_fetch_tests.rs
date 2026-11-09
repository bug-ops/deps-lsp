//! Spec 100 / issue #1987: a `didChange` that lands while the initial registry fetch is in
//! flight must not lose that fetch. Each test drives the real open/change handlers and
//! `ServerState::spawn_background_task` (the abort path) against a mock registry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::{handle_document_change, handle_document_open};
use crate::config::DepsConfig;
#[cfg(feature = "npm")]
use crate::document::osv_scan::osv_scan_plan_is_stale;
use crate::document::state::ServerState;
use crate::handlers::diagnostics::handle_diagnostics;
use crate::lsp_types_interop::to_lsp_uri;
use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_core::osv::OsvClient;
use deps_core::policy_config::{RegistriesConfig, WorkspaceRegistriesSetting};
use deps_core::{Ecosystem, LoadingState};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

/// Upper bound on how long a gated response is held if the test never releases it.
const HOLD: Duration = Duration::from_secs(10);
const SETTLE_DEADLINE: Duration = Duration::from_secs(15);

/// A mock response that stays in flight until [`Self::release`] (or until the test fails and
/// drops it).
struct Gate {
    started: Arc<Mutex<mpsc::Receiver<()>>>,
    release: Option<mpsc::Sender<()>>,
}

impl Gate {
    async fn wait_started(&self) {
        let started = Arc::clone(&self.started);
        tokio::task::spawn_blocking(move || started.lock().unwrap().recv_timeout(HOLD))
            .await
            .unwrap()
            .expect("the gated registry request must arrive");
    }

    fn release(&mut self) {
        self.release.take();
    }

    /// Requests that reached the gated mock after the one [`Self::wait_started`] consumed.
    fn further_requests(&self) -> usize {
        let started = self.started.lock().unwrap();
        std::iter::from_fn(|| started.try_recv().ok()).count()
    }
}

/// Mocks `GET path` with `body`, holding every response until the returned gate is released.
fn gated_mock(
    server: &mut mockito::ServerGuard,
    path: &str,
    query_any: bool,
    body: String,
) -> (mockito::Mock, Gate) {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let mut mock = server.mock("GET", path);
    if query_any {
        mock = mock.match_query(mockito::Matcher::Any);
    }
    let mock = mock
        .with_status(200)
        .with_chunked_body(move |writer| {
            let _ = started_tx.send(());
            // `Err(Disconnected)` once the gate is released or dropped; the timeout bounds a
            // test that fails before releasing.
            let _ = release_rx.lock().unwrap().recv_timeout(HOLD);
            writer.write_all(body.as_bytes())
        })
        .expect_at_least(1)
        .create();
    (
        mock,
        Gate {
            started: Arc::new(Mutex::new(started_rx)),
            release: Some(release_tx),
        },
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    uri: Uri,
    content: String,
}

struct FixtureSpec<'a> {
    files: &'a [(&'a str, &'a str)],
    manifest_path: &'a str,
    manifest: String,
    ecosystem: Option<Arc<dyn Ecosystem>>,
    osv_url: Option<String>,
}

fn fixture(spec: FixtureSpec<'_>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    for (name, content) in spec.files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let manifest_file = root.join(spec.manifest_path);
    std::fs::create_dir_all(manifest_file.parent().unwrap()).unwrap();
    std::fs::write(&manifest_file, &spec.manifest).unwrap();

    let environment = MapEnv::new().with_var(PRIVATE_REGISTRY_HOSTS_ENV, "127.0.0.1/32");
    let mut state = ServerState::from_env_source(&environment);
    state
        .cache
        .set_registry_policy(WorkspaceRegistriesSetting::All.to_policy());
    if let Some(osv_url) = &spec.osv_url {
        state.osv = Arc::new(OsvClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            osv_url.clone(),
        ));
    }
    if let Some(ecosystem) = spec.ecosystem {
        state.ecosystem_registry.register(ecosystem);
    }

    let (client, _) = crate::test_utils::test_helpers::create_test_client_and_config();
    let mut config = DepsConfig::default();
    config.policy.registries =
        RegistriesConfig::new().with_workspace_registries(WorkspaceRegistriesSetting::All);
    config.policy.diagnostics.vulnerabilities_enabled = spec.osv_url.is_some();

    Fixture {
        _dir: dir,
        state: Arc::new(state),
        client,
        config: Arc::new(RwLock::new(config)),
        uri: to_lsp_uri(&url::Url::from_file_path(&manifest_file).unwrap()),
        content: spec.manifest,
    }
}

impl Fixture {
    async fn open(&self) -> tokio::task::JoinHandle<()> {
        handle_document_open(
            self.uri.clone(),
            self.content.clone(),
            Some(1),
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .unwrap()
    }

    async fn change(&self, content: String, version: i32) -> tokio::task::JoinHandle<()> {
        handle_document_change(
            self.uri.clone(),
            content,
            Some(version),
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .unwrap()
    }

    fn whitespace_edit(&self) -> String {
        format!("{}\n", self.content)
    }

    async fn settle(&self) {
        tokio::time::timeout(SETTLE_DEADLINE, async {
            while !self
                .state
                .with_document(&self.uri, |doc| {
                    matches!(
                        doc.loading_state(),
                        LoadingState::Loaded | LoadingState::Failed
                    )
                })
                .unwrap_or(false)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the document load settles");
    }

    async fn wait_for_cached_count(&self, expected: usize) {
        tokio::time::timeout(SETTLE_DEADLINE, async {
            while self.cached_count() != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the cached versions reach the expected count");
    }

    fn cached_count(&self) -> usize {
        self.state
            .with_document(&self.uri, |doc| doc.signals.cached_versions.len())
            .unwrap()
    }

    async fn diagnostics(&self) -> Vec<String> {
        handle_diagnostics(
            Arc::clone(&self.state),
            &self.uri,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .into_iter()
        .map(|d| d.message)
        .collect()
    }
}

/// RT-001/RT-002: the edit lands while the open task's only request is in flight.
async fn assert_edit_during_initial_fetch_keeps_registry_data(fixture: Fixture, mut gate: Gate) {
    let open = fixture.open().await;
    fixture
        .state
        .spawn_background_task(fixture.uri.clone(), open)
        .await;
    gate.wait_started().await;

    let change = fixture.change(fixture.whitespace_edit(), 2).await;
    fixture
        .state
        .spawn_background_task(fixture.uri.clone(), change)
        .await;
    gate.release();
    fixture.settle().await;

    assert_eq!(fixture.cached_count(), 1, "the aborted fetch was lost");
    let diagnostics = fixture.diagnostics().await;
    assert!(
        diagnostics.iter().all(|m| !m.contains("Unknown package")),
        "{diagnostics:?}"
    );
}

#[cfg(feature = "npm")]
mod npm_cases {
    use super::*;

    const MANIFEST: &str = r#"{"dependencies": {"@acme-corp/widget": "^1.0.0"}}"#;
    const PACKUMENT: &str =
        r#"{"versions": {"1.0.0": {}, "1.1.0": {}}, "dist-tags": {"latest": "1.1.0"}}"#;

    fn npmrc(registry: &str) -> String {
        format!("@acme-corp:registry={registry}\n")
    }

    pub(super) fn npm_fixture(registry: &str, osv_url: Option<String>) -> Fixture {
        npm_fixture_for(MANIFEST.to_owned(), registry, osv_url)
    }

    pub(super) fn npm_fixture_for(
        manifest: String,
        registry: &str,
        osv_url: Option<String>,
    ) -> Fixture {
        let npmrc = npmrc(registry);
        fixture(FixtureSpec {
            files: &[(".npmrc", npmrc.as_str())],
            manifest_path: "package.json",
            manifest,
            ecosystem: None,
            osv_url,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_002_npm_edit_during_initial_fetch_keeps_registry_data() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let (_mock, gate) =
            gated_mock(&mut registry, "/@acme-corp/widget", false, PACKUMENT.into());
        let fixture = npm_fixture(&registry.url(), None);
        assert_edit_during_initial_fetch_keeps_registry_data(fixture, gate).await;
    }

    const TWO_DEPENDENCIES: &str =
        r#"{"dependencies": {"@acme-corp/widget": "^1.0.0", "@acme-corp/gadget": "^1.0.0"}}"#;

    /// RT-003: a dependency with a committed outcome is not fetched again when an edit adds
    /// another one; only the new name is requested, and a later edit requests nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_003_edit_fetches_only_uncommitted_dependencies() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let widget = registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(200)
            .with_body(PACKUMENT)
            .expect(1)
            .create_async()
            .await;
        let gadget = registry
            .mock("GET", "/@acme-corp/gadget")
            .with_status(200)
            .with_body(PACKUMENT)
            .expect(1)
            .create_async()
            .await;
        let fixture = npm_fixture(&registry.url(), None);

        fixture.open().await.await.unwrap();
        assert_eq!(fixture.cached_count(), 1);

        fixture
            .change(TWO_DEPENDENCIES.to_owned(), 2)
            .await
            .await
            .unwrap();
        assert_eq!(fixture.cached_count(), 2);

        fixture
            .change(format!("{TWO_DEPENDENCIES}\n"), 3)
            .await
            .await
            .unwrap();

        assert_eq!(fixture.cached_count(), 2);
        widget.assert_async().await;
        gadget.assert_async().await;
    }

    /// RT-003 (abort): a change task aborted mid-fetch commits nothing; the next edit fetches
    /// the added dependency once more, caches it, and leaves the committed one alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_003_aborted_change_fetch_is_retried_by_the_next_edit() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let widget = registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(200)
            .with_body(PACKUMENT)
            .expect(1)
            .create_async()
            .await;
        let (_gadget, mut gate) =
            gated_mock(&mut registry, "/@acme-corp/gadget", false, PACKUMENT.into());
        let fixture = npm_fixture(&registry.url(), None);

        fixture.open().await.await.unwrap();
        assert_eq!(fixture.cached_count(), 1);

        let change = fixture.change(TWO_DEPENDENCIES.to_owned(), 2).await;
        fixture
            .state
            .spawn_background_task(fixture.uri.clone(), change)
            .await;
        gate.wait_started().await;

        let retry = fixture.change(format!("{TWO_DEPENDENCIES}\n"), 3).await;
        fixture
            .state
            .spawn_background_task(fixture.uri.clone(), retry)
            .await;
        gate.release();
        fixture.wait_for_cached_count(2).await;

        assert_eq!(
            gate.further_requests(),
            1,
            "gadget fetched more than once again"
        );
        widget.assert_async().await;
    }

    /// RT-004: a whitespace edit on a fully loaded document performs no registry request and
    /// leaves the OSV scan plan current. The `.npmrc` registry is a non-public route, so the OSV
    /// scan records a skip for the dependency instead of querying osv.dev.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_004_whitespace_edit_on_loaded_document_requests_nothing() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let widget = registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(200)
            .with_body(PACKUMENT)
            .expect(1)
            .create_async()
            .await;
        let osv = mockito::Server::new_async().await;
        let fixture = npm_fixture(&registry.url(), Some(osv.url()));

        fixture.open().await.await.unwrap();
        fixture
            .change(fixture.whitespace_edit(), 2)
            .await
            .await
            .unwrap();

        widget.assert_async().await;
        let ecosystem = fixture
            .state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Npm)
            .unwrap();
        let stale = fixture
            .state
            .with_document(&fixture.uri, |doc| {
                osv_scan_plan_is_stale(doc, ecosystem.as_ref())
            })
            .unwrap();
        assert!(
            !stale,
            "an unchanged, fully scanned document has a current plan"
        );
    }

    /// RT-005: the OSV outcome of an aborted task is rebuilt by the next edit even though no
    /// registry fetch is due.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_005_edit_rescans_osv_outcome_lost_to_an_aborted_task() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let widget = registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(200)
            .with_body(PACKUMENT)
            .expect(1)
            .create_async()
            .await;
        let osv = mockito::Server::new_async().await;
        let fixture = npm_fixture(&registry.url(), Some(osv.url()));

        fixture.open().await.await.unwrap();
        fixture
            .state
            .documents
            .get_mut(&fixture.uri)
            .unwrap()
            .signals
            .osv_scan_plan = crate::document::osv_scan::OsvScanPlan::default();
        fixture
            .state
            .documents
            .get_mut(&fixture.uri)
            .unwrap()
            .signals
            .vulnerabilities
            .clear();

        fixture
            .change(fixture.whitespace_edit(), 2)
            .await
            .await
            .unwrap();

        widget.assert_async().await;
        let restored = fixture
            .state
            .with_document(&fixture.uri, |doc| !doc.signals.vulnerabilities.is_empty())
            .unwrap();
        assert!(restored, "the OSV outcome was not rebuilt");
    }

    /// RT-006: a committed lookup miss is not requested again on a later edit and keeps
    /// reporting the unknown package.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rt_006_committed_miss_is_not_refetched() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut registry = mockito::Server::new_async().await;
        let widget = registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;
        let fixture = npm_fixture(&registry.url(), None);

        fixture.open().await.await.unwrap();
        fixture
            .change(fixture.whitespace_edit(), 2)
            .await
            .await
            .unwrap();

        widget.assert_async().await;
        let diagnostics = fixture.diagnostics().await;
        assert!(
            diagnostics.iter().any(|m| m.contains("Unknown package")),
            "{diagnostics:?}"
        );
    }
}

#[cfg(feature = "cargo")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt_002_cargo_edit_during_initial_fetch_keeps_registry_data() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let mut index = mockito::Server::new_async().await;
    let (_mock, gate) = gated_mock(
        &mut index,
        "/mo/ck/mockdep",
        false,
        "{\"name\":\"mockdep\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"0\",\"features\":{},\"yanked\":false}\n\
         {\"name\":\"mockdep\",\"vers\":\"2.0.0\",\"deps\":[],\"cksum\":\"0\",\"features\":{},\"yanked\":false}\n"
            .to_owned(),
    );
    let alias = format!(
        "deps-lsp-initial-fetch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let cargo_config = format!(
        "[registries.{alias}]\nindex = \"sparse+{}/\"\n",
        index.url()
    );
    let manifest = format!(
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
         mockdep = {{ version = \"1.0\", registry = \"{alias}\" }}\n"
    );
    let fixture = fixture(FixtureSpec {
        files: &[(".cargo/config.toml", cargo_config.as_str())],
        manifest_path: "Cargo.toml",
        manifest,
        ecosystem: None,
        osv_url: None,
    });
    assert_edit_during_initial_fetch_keeps_registry_data(fixture, gate).await;
}

#[cfg(feature = "github-actions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt_002_github_actions_edit_during_initial_fetch_keeps_registry_data() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let mut api = mockito::Server::new_async().await;
    let (_mock, gate) = gated_mock(
        &mut api,
        "/repos/acme/widget/tags",
        true,
        format!(
            r#"[{{"name": "v1.2.0", "commit": {{"sha": "{}"}}}}]"#,
            "a".repeat(40)
        ),
    );
    let ecosystem: Arc<dyn Ecosystem> =
        Arc::new(deps_github_actions::GithubActionsEcosystem::for_test(
            Arc::new(deps_core::HttpCache::new()),
            api.url(),
        ));
    let fixture = fixture(FixtureSpec {
        files: &[],
        manifest_path: ".github/workflows/ci.yml",
        manifest: "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/widget@v1\n"
            .to_owned(),
        ecosystem: Some(ecosystem),
        osv_url: None,
    });
    assert_edit_during_initial_fetch_keeps_registry_data(fixture, gate).await;
}

/// #1988: through the real handlers, the hover footer is present exactly when `codeAction`
/// returns something, in the states the unit-level table cannot model: a document still
/// loading, and a package deprecated at its latest version.
#[cfg(feature = "npm")]
mod footer_parity {
    use super::npm_cases::npm_fixture_for;
    use super::*;
    use crate::handlers::code_actions::handle_code_actions;
    use crate::handlers::hover::handle_hover;
    use tower_lsp_server::ls_types::{
        CodeActionParams, HoverContents, HoverParams, Position, Range, TextDocumentIdentifier,
        TextDocumentPositionParams,
    };

    const FOOTER: &str = "Cmd+.";
    const PACKUMENT_ALL_DEPRECATED: &str = r#"{"versions": {"1.0.0": {"deprecated": "old"}, "1.1.0": {"deprecated": "use another package"}}, "dist-tags": {"latest": "1.1.0"}}"#;
    const PACKUMENT_CURRENT: &str =
        r#"{"versions": {"1.0.0": {}, "1.1.0": {}}, "dist-tags": {"latest": "1.1.0"}}"#;
    const MANIFEST: &str = r#"{"dependencies": {"@acme-corp/widget": "^1.1.0"}}"#;

    impl Fixture {
        /// `(footer shown, code actions offered)` for the requirement `^1.1.0`.
        async fn footer_and_actions(&self) -> (bool, usize) {
            let column = u32::try_from(self.content.find("^1.1.0").unwrap() + 1).unwrap();
            let position = Position::new(0, column);
            let hover = handle_hover(
                Arc::clone(&self.state),
                HoverParams {
                    text_document_position_params: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier {
                            uri: self.uri.clone(),
                        },
                        position,
                    },
                    work_done_progress_params: Default::default(),
                },
                self.client.clone(),
                Arc::clone(&self.config),
            )
            .await
            .expect("hover");
            let footer = match hover.contents {
                HoverContents::Markup(markup) => markup.value.contains(FOOTER),
                other => panic!("unexpected hover contents {other:?}"),
            };
            let actions = handle_code_actions(
                Arc::clone(&self.state),
                CodeActionParams {
                    text_document: TextDocumentIdentifier {
                        uri: self.uri.clone(),
                    },
                    range: Range::new(position, position),
                    context: Default::default(),
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                },
                self.client.clone(),
                Arc::clone(&self.config),
            )
            .await;
            (footer, actions.len())
        }
    }

    async fn registry_serving(packument: &str) -> mockito::ServerGuard {
        let mut registry = mockito::Server::new_async().await;
        registry
            .mock("GET", "/@acme-corp/widget")
            .with_status(200)
            .with_body(packument)
            .expect_at_least(1)
            .create_async()
            .await;
        registry
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn footer_matches_code_actions_when_every_version_is_deprecated_at_latest() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let registry = registry_serving(PACKUMENT_ALL_DEPRECATED).await;
        let osv = mockito::Server::new_async().await;
        let fixture = npm_fixture_for(MANIFEST.to_owned(), &registry.url(), Some(osv.url()));
        fixture.open().await.await.unwrap();

        let (footer, actions) = fixture.footer_and_actions().await;

        assert_eq!(footer, actions > 0, "footer={footer} actions={actions}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn footer_matches_code_actions_while_the_document_is_still_loading() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let registry = registry_serving(PACKUMENT_CURRENT).await;
        let osv = mockito::Server::new_async().await;
        let fixture = npm_fixture_for(MANIFEST.to_owned(), &registry.url(), Some(osv.url()));
        let _open = fixture.open().await;

        let (footer, actions) = fixture.footer_and_actions().await;

        // The OSV phase keeps running between the two requests, so an action may appear
        // after the hover; a footer without an action must never be shown.
        assert!(!footer || actions > 0, "footer={footer} actions={actions}");
    }
}
