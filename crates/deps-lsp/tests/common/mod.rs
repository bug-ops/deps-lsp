//! Common test utilities for integration tests.
//!
//! This module provides shared infrastructure for LSP integration tests,
//! including the `LspClient` for communicating with the server binary.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// A captured notification with timing and ordering information.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in notification_ordering tests, not all tests
pub(crate) struct CapturedNotification {
    /// The LSP method name (e.g., "window/workDoneProgress/create").
    pub method: String,
    /// When this notification was received.
    pub timestamp: Instant,
    /// Sequence number for ordering (monotonically increasing).
    pub sequence: u64,
    /// The full notification parameters.
    pub params: Value,
}

/// LSP test client for communicating with the server binary.
pub(crate) struct LspClient {
    process: Child,
    /// Captured notifications in order received.
    notifications: Arc<RwLock<Vec<CapturedNotification>>>,
    /// Monotonic counter for notification ordering.
    notification_counter: Arc<AtomicU64>,
    /// Buffered reader for stdout (wrapped in Option for initialization).
    reader: Option<BufReader<std::process::ChildStdout>>,
}

impl LspClient {
    /// Spawn the deps-lsp binary.
    pub(crate) fn spawn() -> Self {
        let mut process = Command::new(env!("CARGO_BIN_EXE_deps-lsp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn deps-lsp binary");

        let stdout = process.stdout.take().expect("Failed to capture stdout");
        let reader = BufReader::new(stdout);

        Self {
            process,
            notifications: Arc::new(RwLock::new(Vec::new())),
            notification_counter: Arc::new(AtomicU64::new(0)),
            reader: Some(reader),
        }
    }

    /// Get all captured notifications.
    #[allow(dead_code)] // Used in notification_ordering tests
    pub(crate) fn get_notifications(&self) -> Vec<CapturedNotification> {
        self.notifications
            .read()
            .expect("Failed to acquire read lock")
            .clone()
    }

    /// Clear all captured notifications.
    #[allow(dead_code)] // Used in notification_ordering tests
    pub(crate) fn clear_notifications(&self) {
        self.notifications
            .write()
            .expect("Failed to acquire write lock")
            .clear();
        self.notification_counter.store(0, Ordering::SeqCst);
    }

    /// Trigger a read from the server stream by sending a dummy request.
    ///
    /// This forces `read_response()` to be called, which captures any pending
    /// notifications as a side effect. Use this after sending notifications
    /// (like `did_open`) to capture server-sent notifications.
    #[allow(dead_code)] // Used in notification_ordering tests
    pub(crate) fn flush_notifications(&mut self) {
        // Send a benign workspace/symbol request with empty query
        // This is guaranteed to succeed and return quickly
        let _ = self.workspace_symbol(999, "");
    }

    /// Find a notification by method name from already captured notifications.
    #[allow(dead_code)] // Used in notification_ordering tests
    pub(crate) fn find_notification(&self, method: &str) -> Option<CapturedNotification> {
        self.notifications
            .read()
            .expect("Failed to acquire read lock")
            .iter()
            .find(|n| n.method == method)
            .cloned()
    }

    /// Send a JSON-RPC message to the server.
    pub(crate) fn send(&mut self, message: &Value) {
        let body = serde_json::to_string(message).unwrap();
        let header = format!("Content-Length: {}\r\n\r\n", body.len());

        let stdin = self.process.stdin.as_mut().expect("stdin not captured");
        stdin.write_all(header.as_bytes()).unwrap();
        stdin.write_all(body.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Read a JSON-RPC response from the server.
    ///
    /// Captures notifications and returns the first response with matching id,
    /// or any response/error if no id filter is provided.
    pub(crate) fn read_response(&mut self, expected_id: Option<i64>) -> Value {
        let reader = self.reader.as_mut().expect("reader not initialized");

        loop {
            // Read headers
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).expect("Failed to read header");

                // EOF - server closed connection
                assert!(bytes_read != 0, "Server closed connection unexpectedly");

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
                // Capture the notification
                if let Some(method) = message.get("method").and_then(|m| m.as_str()) {
                    let params = message.get("params").cloned().unwrap_or(Value::Null);
                    let seq = self.notification_counter.fetch_add(1, Ordering::SeqCst);
                    let notification = CapturedNotification {
                        method: method.to_string(),
                        timestamp: Instant::now(),
                        sequence: seq,
                        params,
                    };
                    self.notifications
                        .write()
                        .expect("Failed to acquire write lock")
                        .push(notification);
                }
                // Continue reading for response
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
    pub(crate) fn initialize(&mut self) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {
                    "workspace": {
                        "inlayHint": {
                            "refreshSupport": true
                        }
                    },
                    "textDocument": {
                        "hover": {
                            "contentFormat": ["markdown", "plaintext"]
                        },
                        "completion": {
                            "completionItem": {
                                "snippetSupport": true
                            }
                        },
                        "publishDiagnostics": {}
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
    pub(crate) fn did_open(&mut self, uri: &str, language_id: &str, text: &str) {
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
    #[allow(dead_code)] // Not used in all tests
    pub(crate) fn hover(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
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
    #[allow(dead_code)] // Not used in all tests
    pub(crate) fn inlay_hints(&mut self, id: i64, uri: &str) -> Value {
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
    #[allow(dead_code)] // Not used in all tests
    pub(crate) fn completion(&mut self, id: i64, uri: &str, line: u32, character: u32) -> Value {
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

    /// Request workspace symbols.
    #[allow(dead_code)] // Used for flushing notifications
    pub(crate) fn workspace_symbol(&mut self, id: i64, query: &str) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "workspace/symbol",
            "params": {
                "query": query
            }
        }));
        self.read_response(Some(id))
    }

    /// Shutdown the server.
    pub(crate) fn shutdown(&mut self) -> Value {
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
