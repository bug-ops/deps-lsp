//! Common test utilities for integration tests.
//!
//! This module provides shared infrastructure for LSP integration tests,
//! including the `LspClient` for communicating with the server binary.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};

/// LSP test client for communicating with the server binary.
pub struct LspClient {
    process: Child,
}

impl LspClient {
    /// Spawn the deps-lsp binary.
    pub fn spawn() -> Self {
        let process = Command::new(env!("CARGO_BIN_EXE_deps-lsp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn deps-lsp binary");

        Self { process }
    }

    /// Send a JSON-RPC message to the server.
    pub fn send(&mut self, message: &Value) {
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
    pub fn read_response(&mut self, expected_id: Option<i64>) -> Value {
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
    pub fn initialize(&mut self) -> Value {
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
    pub fn did_open(&mut self, uri: &str, language_id: &str, text: &str) {
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
    pub fn hover(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
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
    pub fn inlay_hints(&mut self, id: i64, uri: &str) -> Value {
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
    pub fn completion(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
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
    pub fn shutdown(&mut self) -> Value {
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
