//! Integration tests for deps-lsp binary.
//!
//! These tests spawn the LSP server binary and verify correct
//! JSON-RPC message handling and LSP protocol compliance.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// LSP test client for communicating with the server binary.
struct LspClient {
    process: Child,
}

impl LspClient {
    /// Spawn the deps-lsp binary.
    fn spawn() -> Self {
        let process = Command::new(env!("CARGO_BIN_EXE_deps-lsp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn deps-lsp binary");

        Self { process }
    }

    /// Send a JSON-RPC message to the server.
    fn send(&mut self, message: &Value) {
        let body = serde_json::to_string(message).unwrap();
        let header = format!("Content-Length: {}\r\n\r\n", body.len());

        let stdin = self.process.stdin.as_mut().expect("stdin not captured");
        stdin.write_all(header.as_bytes()).unwrap();
        stdin.write_all(body.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Read a JSON-RPC response from the server.
    ///
    /// Skips notifications and returns the first response with matching id,
    /// or any response/error if no id filter is provided.
    fn read_response(&mut self, expected_id: Option<i64>) -> Value {
        let stdout = self.process.stdout.as_mut().expect("stdout not captured");
        let mut reader = BufReader::new(stdout);

        loop {
            // Read headers
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).expect("Failed to read header");

                // EOF - server closed connection
                if bytes_read == 0 {
                    panic!("Server closed connection unexpectedly");
                }

                if line == "\r\n" || line == "\n" {
                    break;
                }

                if line.to_lowercase().starts_with("content-length:") {
                    content_length = line
                        .split(':')
                        .nth(1)
                        .unwrap()
                        .trim()
                        .parse()
                        .expect("Invalid content length");
                }
            }

            // Handle empty content (shouldn't happen in valid LSP)
            if content_length == 0 {
                continue;
            }

            // Read body
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).expect("Failed to read body");

            let message: Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
                panic!("Invalid JSON: {e} in: {:?}", String::from_utf8_lossy(&body))
            });

            // Check if this is a notification (no id field)
            if message.get("id").is_none() {
                // Skip notifications, continue reading
                continue;
            }

            // Check id if filter is specified
            if let Some(id) = expected_id {
                if message.get("id") == Some(&json!(id)) {
                    return message;
                }
                // Wrong id, keep reading
                continue;
            }

            return message;
        }
    }

    /// Initialize the LSP session.
    fn initialize(&mut self) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {
                    "textDocument": {
                        "hover": {
                            "contentFormat": ["markdown", "plaintext"]
                        },
                        "completion": {
                            "completionItem": {
                                "snippetSupport": true
                            }
                        }
                    }
                },
                "rootUri": "file:///tmp",
                "workspaceFolders": null
            }
        }));

        let response = self.read_response(Some(1));

        // Send initialized notification
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }));

        response
    }

    /// Open a text document.
    fn did_open(&mut self, uri: &str, language_id: &str, text: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": text
                }
            }
        }));
    }

    /// Request hover information.
    fn hover(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }
        }));
        self.read_response(Some(id))
    }

    /// Request inlay hints.
    fn inlay_hints(&mut self, id: i64, uri: &str) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/inlayHint",
            "params": {
                "textDocument": {"uri": uri},
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 100, "character": 0}
                }
            }
        }));
        self.read_response(Some(id))
    }

    /// Request completions.
    fn completion(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }
        }));
        self.read_response(Some(id))
    }

    /// Shutdown the server.
    fn shutdown(&mut self) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 999,
            "method": "shutdown"
        }));
        self.read_response(Some(999))
    }
}

impl Drop for LspClient {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

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
        "Inlay hints request should not error: {:?}",
        hints
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
        "Hover should not error: {:?}",
        hover
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
        "Completion should not error: {:?}",
        completion
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
