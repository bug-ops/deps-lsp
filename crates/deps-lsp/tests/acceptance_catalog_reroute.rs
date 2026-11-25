//! Acceptance tests (tester-owned) for #2180: a watched `settings.gradle.kts` change re-routes
//! open `*.toml` documents, through the real server binary. The catalog holds one invalid library,
//! so being routed to Gradle is observable offline as a published warning.

#![cfg(feature = "gradle")]
#![expect(clippy::expect_used, reason = "test code")]

#[expect(dead_code, reason = "shared harness; this file uses a subset")]
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::LspClient;
use serde_json::{Value, json};

const CATALOG: &str = "[libraries]\nbad-alias = \"not-a-coordinate\"\n";
const DECLARING: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";
const NOT_DECLARING: &str = "rootProject.name = \"fx\"\n";
const DEADLINE: Duration = Duration::from_secs(8);

fn file_uri(path: &Path) -> String {
    url::Url::from_file_path(path)
        .expect("file url")
        .to_string()
}

struct Session {
    _dir: tempfile::TempDir,
    settings: PathBuf,
    catalog_uri: String,
    client: LspClient,
    next_id: i64,
}

impl Session {
    fn start(settings_content: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        std::fs::create_dir_all(root.join("gradle")).expect("gradle dir");
        let settings = root.join("settings.gradle.kts");
        std::fs::write(&settings, settings_content).expect("settings");
        std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");
        let catalog_uri = file_uri(&root.join("gradle/deps.toml"));

        let mut client = LspClient::spawn();
        client.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": { "textDocument": { "publishDiagnostics": {} } },
                "rootUri": file_uri(&root),
                "workspaceFolders": [{ "uri": file_uri(&root), "name": "fx" }]
            }
        }));
        client.read_response(Some(1));
        client.send(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
        client.did_open(&catalog_uri, "toml", CATALOG);

        Self {
            _dir: dir,
            settings,
            catalog_uri,
            client,
            next_id: 100,
        }
    }

    fn flush(&mut self) {
        self.next_id += 1;
        self.client.workspace_symbol(self.next_id, "");
    }

    fn last_published(&self) -> Option<Vec<Value>> {
        self.client
            .get_notifications()
            .into_iter()
            .rfind(|n| {
                n.method == "textDocument/publishDiagnostics"
                    && n.params
                        .get("uri")
                        .is_some_and(|u| u == self.catalog_uri.as_str())
            })
            .and_then(|n| n.params.get("diagnostics")?.as_array().cloned())
    }

    fn wait_for(&mut self, what: &str, predicate: impl Fn(&[Value]) -> bool) {
        let started = Instant::now();
        loop {
            self.flush();
            if self.last_published().is_some_and(|d| predicate(&d)) {
                return;
            }
            assert!(
                started.elapsed() < DEADLINE,
                "{what}; last publish: {:?}",
                self.last_published()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn rewrite_settings(&mut self, content: &str) {
        std::fs::write(&self.settings, content).expect("settings");
        let uri = file_uri(&self.settings);
        self.client.send(&json!({
            "jsonrpc": "2.0", "method": "workspace/didChangeWatchedFiles",
            "params": { "changes": [{ "uri": uri, "type": 2 }] }
        }));
    }
}

fn names_alias(diagnostics: &[Value]) -> bool {
    diagnostics
        .iter()
        .any(|d| d.to_string().contains("bad-alias"))
}

#[test]
fn watched_settings_change_declaring_an_open_toml_publishes_its_diagnostics() {
    let mut session = Session::start(NOT_DECLARING);
    // An unrouted open publishes nothing to wait on; let it finish before the declaration appears.
    session.flush();
    std::thread::sleep(Duration::from_secs(1));
    session.flush();
    assert_eq!(session.last_published(), None, "precondition: unrouted");

    session.rewrite_settings(DECLARING);

    session.wait_for("the newly declared catalog was never routed", names_alias);
}

#[test]
fn watched_settings_change_dropping_the_declaration_clears_the_catalog_diagnostics() {
    let mut session = Session::start(DECLARING);
    session.wait_for(
        "precondition: the declared catalog is diagnosed",
        names_alias,
    );

    session.rewrite_settings(NOT_DECLARING);

    session.wait_for(
        "the dropped catalog kept its diagnostics",
        <[Value]>::is_empty,
    );
}
