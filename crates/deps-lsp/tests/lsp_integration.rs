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

    // Verify response structure
    assert!(
        response.get("result").is_some(),
        "Expected result in response"
    );

    let result = &response["result"];

    // Check server info
    assert_eq!(result["serverInfo"]["name"], "deps-lsp");
    assert!(result["serverInfo"]["version"].is_string());

    // Check capabilities
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

    // Shutdown should return null result
    assert_eq!(response["result"], json!(null));
    assert_eq!(response["id"], json!(999));
}

#[test]
fn test_cargo_document_open() {
    let mut client = LspClient::spawn();
    client.initialize();

    // Open a Cargo.toml document
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

    // Give the server time to process (async operations)
    thread::sleep(Duration::from_millis(100));

    // Request inlay hints - should not error
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

    // Open a package.json document
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

    // Open a pyproject.toml document
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

    // Wait for document to be processed
    thread::sleep(Duration::from_millis(100));

    // Hover on "serde" (line 5, character 0-5)
    let hover = client.hover(20, "file:///test/Cargo.toml", 5, 2);

    // Should return a result (may be null if no hover info available yet)
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

    // Should not error
    assert!(
        completion.get("error").is_none(),
        "Completion should not error: {completion:?}"
    );
}

#[test]
fn test_unknown_document_type() {
    let mut client = LspClient::spawn();
    client.initialize();

    // Open an unsupported document type
    client.did_open("file:///test/unknown.xyz", "unknown", "some random content");

    thread::sleep(Duration::from_millis(100));

    // Should handle gracefully without crashing
    let hints = client.inlay_hints(40, "file:///test/unknown.xyz");

    // Should return empty result, not error
    assert!(
        hints.get("error").is_none(),
        "Should handle unknown document gracefully"
    );
}

#[test]
fn test_malformed_document_content() {
    let mut client = LspClient::spawn();
    client.initialize();

    // Open a Cargo.toml with malformed content
    client.did_open(
        "file:///test/Cargo.toml",
        "toml",
        "this is not valid toml [[[",
    );

    thread::sleep(Duration::from_millis(100));

    // Server should handle gracefully
    let hints = client.inlay_hints(50, "file:///test/Cargo.toml");
    assert!(
        hints.get("error").is_none(),
        "Should handle malformed content gracefully"
    );
}

#[test]
fn test_multiple_documents() {
    let mut client = LspClient::spawn();
    client.initialize();

    // Open multiple documents
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

    // Both should work independently
    let hints1 = client.inlay_hints(60, "file:///project1/Cargo.toml");
    let hints2 = client.inlay_hints(61, "file:///project2/package.json");

    assert!(hints1.get("error").is_none());
    assert!(hints2.get("error").is_none());
}

#[test]
fn test_jsonrpc_error_on_invalid_method() {
    let mut client = LspClient::spawn();
    client.initialize();

    // Send an unknown method
    client.send(&json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "unknownMethod/doesNotExist",
        "params": {}
    }));

    let response = client.read_response(Some(100));

    // Should return method not found error
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

    let uri = format!("file://{}", temp_file.path().display());

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen - cold start scenario

    // Request completion at cursor position after `serde = "`
    let completion = client.completion(100, &uri, 1, 9);

    // Should not error
    assert!(
        completion.get("error").is_none(),
        "Cold start completion should not error: {completion:?}"
    );

    // Should return some response (may be empty if network fails)
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

    let uri = format!("file://{}", temp_file.path().display());

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    // Hover over "serde" (line 1, character 2)
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

    let uri = format!("file://{}", temp_file.path().display());

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

    // Should return inlay hints (may be empty if network fetch failed)
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

    let uri = format!("file://{}", temp_file.path().display());

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    // Request diagnostics
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

    // Request on non-existent file
    let hints = client.inlay_hints(140, uri);

    // Should not crash, return empty result
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

    // Request on HTTP URI (not file://)
    let hints = client.inlay_hints(150, uri);

    // Should handle gracefully (return empty, not crash)
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

    let uri = format!("file://{}", temp_file.path().display());

    let mut client = LspClient::spawn();
    client.initialize();

    // NO didOpen

    // Test concurrent requests don't crash the server by sending hover twice
    let hover1 = client.hover(200, &uri, 1, 2);
    let hover2 = client.hover(201, &uri, 1, 2);

    // Both should succeed without errors (may return null/empty, but no error)
    assert!(hover1.get("error").is_none());
    assert!(hover2.get("error").is_none());
}
