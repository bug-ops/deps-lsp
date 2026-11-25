//! #2170/#2186: a version catalog whose only library is not a coordinate publishes the warning,
//! through the real server binary.

#![cfg(feature = "gradle")]

#[expect(dead_code, reason = "shared harness; this file uses a subset")]
mod common;

use std::time::{Duration, Instant};

use common::LspClient;
use serde_json::json;

const CATALOG: &str = "[libraries]\nbad-alias = \"not-a-coordinate\"\n";

#[test]
fn a_catalog_with_zero_valid_entries_publishes_the_invalid_coordinate_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .canonicalize()
        .expect("canonical")
        .join("libs.versions.toml");
    std::fs::write(&path, CATALOG).expect("catalog");
    let uri = url::Url::from_file_path(&path)
        .expect("file url")
        .to_string();

    let mut client = LspClient::spawn();
    client.send(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "processId": null,
            "capabilities": { "textDocument": { "publishDiagnostics": {} } }
        }
    }));
    client.read_response(Some(1));
    client.send(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    client.did_open(&uri, "toml", CATALOG);

    let started = Instant::now();
    let mut next_id = 100;
    loop {
        next_id += 1;
        client.workspace_symbol(next_id, "");
        let published = client.get_notifications().into_iter().any(|n| {
            n.method == "textDocument/publishDiagnostics"
                && n.params
                    .to_string()
                    .contains("not a well-formed coordinate")
        });
        if published {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the zero-entry catalog warning was never published"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
