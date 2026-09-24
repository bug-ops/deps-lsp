//! Integration tests for deps-lsp binary.
//!
//! These tests spawn the LSP server binary and verify correct
//! JSON-RPC message handling and LSP protocol compliance.

mod common;

use common::LspClient;
use serde_json::json;
use std::thread;
use std::time::Duration;

#[test]
fn test_initialize_response() {
    let mut client = LspClient::spawn();
    let response = client.initialize();

    assert!(
        response.get("result").is_some(),
        "Expected result in response"
    );

    let result = &response["result"];

    assert_eq!(result["serverInfo"]["name"], "deps-lsp");
    assert!(result["serverInfo"]["version"].is_string());

    let capabilities = &result["capabilities"];
    assert!(
        capabilities["hoverProvider"].as_bool().unwrap_or(false)
            || capabilities["hoverProvider"].is_object()
    );
    assert!(capabilities["completionProvider"].is_object());
    assert!(
        capabilities["inlayHintProvider"].as_bool().unwrap_or(false)
            || capabilities["inlayHintProvider"].is_object()
    );
    assert!(
        capabilities["textDocumentSync"].is_number()
            || capabilities["textDocumentSync"].is_object()
    );
}

#[test]
fn test_shutdown_response() {
    let mut client = LspClient::spawn();
    client.initialize();

    let response = client.shutdown();

    assert_eq!(response["result"], json!(null));
    assert_eq!(response["id"], json!(999));
}

#[test]
fn test_cargo_document_open() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/Cargo.toml",
        "toml",
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    );

    thread::sleep(Duration::from_millis(100));

    let hints = client.inlay_hints(10, "file:///test/Cargo.toml");
    assert!(
        hints.get("error").is_none(),
        "Inlay hints request should not error: {hints:?}"
    );
    assert!(
        hints.get("result").is_some(),
        "Inlay hints should return result"
    );
}

#[test]
fn test_package_json_document_open() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/package.json",
        "json",
        r#"{
  "name": "test",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}"#,
    );

    thread::sleep(Duration::from_millis(100));

    let hints = client.inlay_hints(10, "file:///test/package.json");
    assert!(
        hints.get("error").is_none(),
        "Inlay hints request should not error"
    );
}

#[test]
fn test_pyproject_document_open() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/pyproject.toml",
        "toml",
        r#"[project]
name = "test"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
]
"#,
    );

    thread::sleep(Duration::from_millis(100));

    let hints = client.inlay_hints(10, "file:///test/pyproject.toml");
    assert!(
        hints.get("error").is_none(),
        "Inlay hints request should not error"
    );
}

#[test]
fn test_hover_on_dependency_name() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/Cargo.toml",
        "toml",
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    );

    thread::sleep(Duration::from_millis(100));

    // Hover on "serde" (line 5, character 0-5)
    let hover = client.hover(20, "file:///test/Cargo.toml", 5, 2);

    // May be null if hover info isn't ready yet
    assert!(
        hover.get("error").is_none(),
        "Hover should not error: {hover:?}"
    );
}

#[test]
fn test_completion_in_dependencies_section() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/Cargo.toml",
        "toml",
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = ""
"#,
    );

    thread::sleep(Duration::from_millis(100));

    // Request completion after the opening quote
    let completion = client.completion(30, "file:///test/Cargo.toml", 5, 9);

    assert!(
        completion.get("error").is_none(),
        "Completion should not error: {completion:?}"
    );
}

#[test]
fn test_pep508_deeply_nested_marker_does_not_crash_server() {
    // Regression test for #146: a PEP 508 marker packs ~1 paren pair per 2
    // bytes, so a marker can nest ~1000 levels deep while staying under the
    // parser's 2048-byte length cap. Without a depth guard, handing this to
    // pep508_rs's unbounded recursive-descent parser aborts the whole
    // process with a stack overflow (not a catchable panic).
    let depth = 1000;
    let nested_marker = format!("{}os_name == 'a'{}", "(".repeat(depth), ")".repeat(depth));
    assert!(nested_marker.len() < 2048);

    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/pyproject.toml",
        "toml",
        &format!(
            r#"[project]
name = "test"
version = "0.1.0"
dependencies = [
    "numpy>=1.24; {nested_marker}",
]
"#
        ),
    );

    thread::sleep(Duration::from_millis(200));

    // Hover on the dependency name - if the server had overflowed the stack
    // while parsing the manifest, the process would already be dead and this
    // request would fail to get a response.
    let hover = client.hover(50, "file:///test/pyproject.toml", 4, 6);
    assert!(
        hover.get("error").is_none() || hover.get("result").is_some(),
        "Server should still be alive and respond to hover: {hover:?}"
    );

    let hints = client.inlay_hints(51, "file:///test/pyproject.toml");
    assert!(
        hints.get("result").is_some(),
        "Inlay hints request should not error: {hints:?}"
    );

    // Shutdown must round-trip - proves the server process is still running.
    let shutdown = client.shutdown();
    assert_eq!(shutdown["result"], json!(null));
}

#[test]
fn test_unknown_document_type() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open("file:///test/unknown.xyz", "unknown", "some random content");

    thread::sleep(Duration::from_millis(100));

    let hints = client.inlay_hints(40, "file:///test/unknown.xyz");

    assert!(
        hints.get("error").is_none(),
        "Should handle unknown document gracefully"
    );
}

#[test]
fn test_malformed_document_content() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///test/Cargo.toml",
        "toml",
        "this is not valid toml [[[",
    );

    thread::sleep(Duration::from_millis(100));

    let hints = client.inlay_hints(50, "file:///test/Cargo.toml");
    assert!(
        hints.get("error").is_none(),
        "Should handle malformed content gracefully"
    );
}

#[cfg(feature = "cargo")]
#[test]
fn test_oversized_did_change_notifies_client_and_keeps_stale_document() {
    let mut client = LspClient::spawn();
    client.initialize();

    let uri = "file:///test/Cargo.toml";
    let valid_content = r#"[package]
name = "test-package"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
    client.did_open(uri, "toml", valid_content);
    thread::sleep(Duration::from_millis(100));
    // Drain startup `window/logMessage` (from `initialized`) so it can't shadow
    // the rejection message searched for below.
    client.flush_notifications();
    client.clear_notifications();

    // Over the 10MB manifest size bound (issue #161) — must be rejected, not stored.
    let oversized_content = "a".repeat(10_000_001);
    client.did_change(uri, 2, &oversized_content);

    // tower-lsp-server's `buffer_unordered` dispatch means the logMessage and the
    // flush response can arrive in either order; poll instead of reading once.
    let rejection = client
        .wait_for_notification(10, |n| {
            n.method == "window/logMessage"
                && n.params["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("Change rejected"))
        })
        .expect("Server should notify the client that the change was rejected");
    let message = rejection.params["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Change rejected"),
        "Unexpected window/logMessage content: {message:?}"
    );

    // Must keep serving the last known-good (pre-rejection) document.
    let hints = client.inlay_hints(60, uri);
    assert!(
        hints.get("error").is_none(),
        "Server should still serve the stale-but-valid document after a rejected change"
    );
}

#[test]
fn test_multiple_documents() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.did_open(
        "file:///project1/Cargo.toml",
        "toml",
        r#"[package]
name = "project1"
version = "0.1.0"

[dependencies]
tokio = "1.0"
"#,
    );

    client.did_open(
        "file:///project2/package.json",
        "json",
        r#"{"name": "project2", "dependencies": {"lodash": "^4.0.0"}}"#,
    );

    thread::sleep(Duration::from_millis(100));

    let hints1 = client.inlay_hints(60, "file:///project1/Cargo.toml");
    let hints2 = client.inlay_hints(61, "file:///project2/package.json");

    assert!(hints1.get("error").is_none());
    assert!(hints2.get("error").is_none());
}

#[test]
fn test_jsonrpc_error_on_invalid_method() {
    let mut client = LspClient::spawn();
    client.initialize();

    client.send(&json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "unknownMethod/doesNotExist",
        "params": {}
    }));

    let response = client.read_response(Some(100));

    assert!(
        response.get("error").is_some(),
        "Should return error for unknown method"
    );
    assert_eq!(response["error"]["code"], json!(-32601)); // Method not found
}

// Cold Start Integration Tests

#[test]
fn test_cold_start_completion_without_didopen() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    let content = r#"[dependencies]
serde = ""
"#;
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let uri = tower_lsp_server::ls_types::Uri::from_file_path(temp_file.path())
        .unwrap()
        .to_string();

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen - cold start scenario

    // Cursor position after `serde = "`
    let completion = client.completion(100, &uri, 1, 9);

    assert!(
        completion.get("error").is_none(),
        "Cold start completion should not error: {completion:?}"
    );

    // May be empty if the network fetch fails
    assert!(completion.get("result").is_some(), "Should return result");
}

#[test]
fn test_cold_start_hover_without_didopen() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    let content = r#"[dependencies]
serde = "1.0"
"#;
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let uri = tower_lsp_server::ls_types::Uri::from_file_path(temp_file.path())
        .unwrap()
        .to_string();

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    let hover = client.hover(110, &uri, 1, 2);

    assert!(
        hover.get("error").is_none(),
        "Cold start hover should not error"
    );
}

#[test]
fn test_cold_start_inlay_hints_without_didopen() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    let content = r#"[dependencies]
tokio = "1.0"
serde = "1.0"
"#;
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let uri = tower_lsp_server::ls_types::Uri::from_file_path(temp_file.path())
        .unwrap()
        .to_string();

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    // Wait for background version fetch (inlay hints require version data)
    thread::sleep(Duration::from_millis(500));

    let hints = client.inlay_hints(120, &uri);

    assert!(
        hints.get("error").is_none(),
        "Cold start hints should not error"
    );

    // May be empty if the network fetch failed
    assert!(hints.get("result").is_some(), "Should return result");
}

#[test]
fn test_cold_start_diagnostics_without_didopen() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    let content = r#"[dependencies]
serde = "1.0"
"#;
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let uri = tower_lsp_server::ls_types::Uri::from_file_path(temp_file.path())
        .unwrap()
        .to_string();

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    client.send(&json!({
        "jsonrpc": "2.0",
        "id": 130,
        "method": "textDocument/diagnostic",
        "params": {
            "textDocument": {"uri": uri}
        }
    }));

    let response = client.read_response(Some(130));

    assert!(
        response.get("error").is_none(),
        "Cold start diagnostics should not error"
    );
}

#[test]
fn test_cold_start_file_not_found() {
    let uri = "file:///nonexistent/Cargo.toml";

    let mut client = LspClient::spawn();
    client.initialize();

    let hints = client.inlay_hints(140, uri);

    assert!(
        hints.get("error").is_none(),
        "Should handle missing file gracefully"
    );

    if let Some(result) = hints.get("result")
        && let Some(arr) = result.as_array()
    {
        assert!(arr.is_empty(), "Should return empty array for missing file");
    }
}

#[test]
fn test_cold_start_non_file_uri() {
    let uri = "http://example.com/Cargo.toml";

    let mut client = LspClient::spawn();
    client.initialize();

    let hints = client.inlay_hints(150, uri);

    assert!(
        hints.get("error").is_none(),
        "Should handle non-file URI gracefully"
    );
}

#[test]
#[ignore = "Flaky on macOS CI - cold start with network requests can timeout"]
fn test_cold_start_concurrent_requests() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    let content = r#"[dependencies]
serde = "1.0"
"#;
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let uri = tower_lsp_server::ls_types::Uri::from_file_path(temp_file.path())
        .unwrap()
        .to_string();

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    let hover1 = client.hover(200, &uri, 1, 2);
    let hover2 = client.hover(201, &uri, 1, 2);

    // null/empty is fine, but no error
    assert!(hover1.get("error").is_none());
    assert!(hover2.get("error").is_none());
}
