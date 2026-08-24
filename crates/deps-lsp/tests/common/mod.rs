//! Common test utilities for integration tests.
//!
//! This module provides shared infrastructure for LSP integration tests,
//! including the `LspClient` for communicating with the server binary.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// Deadline for a single server message: the server must emit its next
/// framed LSP message (response or notification) within this window.
/// A stalled/deadlocked server never sends another message, so this bounds
/// `read_response()` to a fast, clear failure instead of hanging until
/// nextest's external slow-timeout kills the whole test binary.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A single framed message read off the server's stdout, or a terminal
/// condition of the reader thread.
enum ReaderMessage {
    /// The raw JSON body of one Content-Length-framed LSP message.
    Frame(Vec<u8>),
    /// The server closed its stdout (process exited or pipe closed).
    Eof,
    /// The reader thread hit an I/O or framing error while parsing the stream.
    Error(String),
}

/// Blocks on `rx` until a message arrives or `deadline` passes, panicking
/// with the same message `LspClient::read_response` has always used on
/// timeout. Extracted so the panic branch can be exercised with a short
/// injected deadline in a unit test instead of waiting out a real
/// `READ_TIMEOUT`-length hang.
fn recv_before_deadline(
    rx: &mpsc::Receiver<ReaderMessage>,
    deadline: Instant,
    timeout: Duration,
) -> ReaderMessage {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(msg) => msg,
        Err(RecvTimeoutError::Timeout) => panic!(
            "Server did not respond within {}s (possible hang or deadlock)",
            timeout.as_secs()
        ),
        Err(RecvTimeoutError::Disconnected) => {
            panic!("Server closed connection unexpectedly")
        }
    }
}

/// Continuously read Content-Length-framed messages from `stdout` and push
/// them to `tx`, decoupling the blocking read from the caller so it can be
/// bounded with `Receiver::recv_timeout` instead of hanging indefinitely.
fn spawn_reader_thread(stdout: ChildStdout, tx: mpsc::Sender<ReaderMessage>) {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                let bytes_read = match reader.read_line(&mut line) {
                    Ok(n) => n,
                    Err(e) => {
                        let _ =
                            tx.send(ReaderMessage::Error(format!("failed to read header: {e}")));
                        return;
                    }
                };

                if bytes_read == 0 {
                    let _ = tx.send(ReaderMessage::Eof);
                    return;
                }

                if line == "\r\n" || line == "\n" {
                    break;
                }

                if line.to_lowercase().starts_with("content-length:") {
                    content_length = match line
                        .split(':')
                        .nth(1)
                        .and_then(|v| v.trim().parse::<usize>().ok())
                    {
                        Some(n) => n,
                        None => {
                            let _ = tx.send(ReaderMessage::Error(format!(
                                "invalid content-length header: {line:?}"
                            )));
                            return;
                        }
                    };
                }
            }

            if content_length == 0 {
                continue;
            }

            let mut body = vec![0u8; content_length];
            if let Err(e) = reader.read_exact(&mut body) {
                let _ = tx.send(ReaderMessage::Error(format!("failed to read body: {e}")));
                return;
            }

            if tx.send(ReaderMessage::Frame(body)).is_err() {
                // Receiver dropped (client gone) — stop reading.
                return;
            }
        }
    });
}

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
    /// Receives framed messages from the background stdout-reader thread,
    /// bounding each wait with `READ_TIMEOUT` via `recv_timeout`.
    message_rx: mpsc::Receiver<ReaderMessage>,
    /// Count of `window/workDoneProgress/create` requests auto-answered.
    /// Used by tests to prove the round trip actually happened, rather than
    /// just observing a `$/progress` notification that could in principle
    /// arrive some other way.
    progress_create_requests: u64,
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
        let (tx, rx) = mpsc::channel();
        spawn_reader_thread(stdout, tx);

        Self {
            process,
            notifications: Arc::new(RwLock::new(Vec::new())),
            notification_counter: Arc::new(AtomicU64::new(0)),
            message_rx: rx,
            progress_create_requests: 0,
        }
    }

    /// Number of `window/workDoneProgress/create` requests auto-answered so far.
    #[allow(dead_code)] // Used in notification_ordering tests
    pub(crate) fn progress_create_request_count(&self) -> u64 {
        self.progress_create_requests
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

    /// Poll for a notification matching `predicate`, retrying with bounded flushes.
    ///
    /// `flush_notifications()` drives a `workspace/symbol` round trip to capture
    /// any notification queued ahead of it, but `tower-lsp-server` dispatches
    /// handlers via `buffer_unordered`, so a notification from a concurrently
    /// handled request can still reach the stdout sink after that round trip's
    /// response — a single flush is not guaranteed to have captured it. This
    /// retries the flush-and-search cycle, sleeping briefly between attempts, to
    /// tolerate that without an unbounded wait. The first attempt flushes
    /// immediately with no preceding sleep, so a notification sent just before
    /// this call is captured with minimal added latency instead of waiting out
    /// a full 100ms for no reason. Measured against the real binary, the
    /// relevant notification typically lands within 35-155ms of being sent;
    /// the default budget here (10 attempts, ~100ms apart) leaves ample headroom.
    /// Intended for positive waits only — a `None` result after exhausting
    /// `max_attempts` does not prove the notification will never arrive.
    #[allow(dead_code)] // Used in size-bound integration tests
    pub(crate) fn wait_for_notification(
        &mut self,
        max_attempts: u32,
        mut predicate: impl FnMut(&CapturedNotification) -> bool,
    ) -> Option<CapturedNotification> {
        for attempt in 0..max_attempts {
            if let Some(found) = self.get_notifications().into_iter().find(|n| predicate(n)) {
                return Some(found);
            }
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(100));
            }
            self.flush_notifications();
        }
        self.get_notifications().into_iter().find(|n| predicate(n))
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
    /// Captures notifications, transparently answers server-initiated requests
    /// (see [`Self::auto_respond`]), and returns the first response with
    /// matching id, or any response/error if no id filter is provided. The
    /// *entire call* is bounded by `READ_TIMEOUT` from an absolute deadline
    /// computed once up front — not reset by each incoming frame — so a
    /// server that is alive but hung on the awaited response (deadlocked,
    /// infinite loop) still fails fast even while it keeps emitting unrelated
    /// traffic (e.g. `$/progress` reports, diagnostics) that would otherwise
    /// keep resetting a per-message timeout indefinitely.
    pub(crate) fn read_response(&mut self, expected_id: Option<i64>) -> Value {
        let deadline = Instant::now() + READ_TIMEOUT;
        loop {
            let msg = recv_before_deadline(&self.message_rx, deadline, READ_TIMEOUT);

            let body = match msg {
                ReaderMessage::Frame(body) => body,
                ReaderMessage::Eof => panic!("Server closed connection unexpectedly"),
                ReaderMessage::Error(e) => panic!("Failed to read from server: {e}"),
            };

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

            // A message with both "id" and "method" is a server-initiated
            // *request* (e.g. `window/workDoneProgress/create`), not a
            // response to one of our own requests. The server blocks
            // awaiting the reply, so the harness must answer it or requests
            // like progress-token creation hang until their own timeout.
            if let Some(method) = message.get("method").and_then(|m| m.as_str()) {
                self.auto_respond(method, &message);
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

    /// Answer a server-initiated request so the server's awaiting future can
    /// proceed. Dispatches per method rather than returning a blanket `null`
    /// result for everything: `workspace/applyEdit`'s result type
    /// (`ApplyWorkspaceEditResult { applied: bool, .. }`) is not nullable, so
    /// a fabricated `null` would fail to deserialize server-side and the
    /// server would read it as "client refused the edit" — a *new* silent
    /// failure of exactly the kind #286 exists to eliminate. An unrecognized
    /// method gets a JSON-RPC `MethodNotFound` error instead of a made-up
    /// success, so an unhandled server request surfaces as a visible test
    /// failure rather than a silently-accepted no-op.
    fn auto_respond(&mut self, method: &str, message: &Value) {
        let Some(id) = message.get("id").cloned() else {
            return;
        };

        let response = match method {
            "window/workDoneProgress/create" => {
                self.progress_create_requests += 1;
                json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null })
            }
            "workspace/inlayHint/refresh"
            | "workspace/codeLens/refresh"
            | "client/registerCapability" => {
                json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null })
            }
            "workspace/applyEdit" => {
                json!({ "jsonrpc": "2.0", "id": id, "result": { "applied": true } })
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("MethodNotFound: unhandled server-initiated request {method:?}")
                }
            }),
        };

        self.send(&response);
    }

    /// Initialize the LSP session, advertising `window.workDoneProgress` support.
    pub(crate) fn initialize(&mut self) -> Value {
        self.initialize_with_progress_support(true)
    }

    /// Initialize the LSP session with `window.workDoneProgress` support toggled.
    ///
    /// Used to test that the server does not send `window/workDoneProgress/create`
    /// requests to a client that declined the capability (see #290).
    #[allow(dead_code)] // Used by the #290 capability-gating regression test
    pub(crate) fn initialize_with_progress_support(&mut self, work_done_progress: bool) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {
                    "window": {
                        "workDoneProgress": work_done_progress
                    },
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

    /// Sends a full-document change (matches the server's negotiated `FULL` sync kind).
    #[allow(dead_code)] // Used in size-bound integration tests
    pub(crate) fn did_change(&mut self, uri: &str, version: i64, text: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "version": version
                },
                "contentChanges": [
                    { "text": text }
                ]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for #291: exercises `recv_before_deadline`'s panic
    /// branch — the one `LspClient::read_response` hits on a genuine 10s
    /// server hang — without spawning the real binary or waiting out a real
    /// 10-second timeout. A receiver nothing is ever sent on stands in for a
    /// hung server.
    #[test]
    fn test_recv_before_deadline_panics_on_timeout() {
        let (_tx, rx) = mpsc::channel::<ReaderMessage>();
        // Short deadline keeps the test fast; `READ_TIMEOUT` is passed
        // separately as the value used for message formatting, so this test
        // still asserts the exact production panic string rather than one
        // derived from the short deadline (which would truncate to "0s").
        let deadline = Instant::now() + Duration::from_millis(80);

        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recv_before_deadline(&rx, deadline, READ_TIMEOUT)
        }));
        let elapsed = start.elapsed();

        let Err(panic_payload) = result else {
            panic!("expected recv_before_deadline to panic on timeout");
        };
        let message = panic_payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
            })
            .unwrap_or_default();

        assert_eq!(
            message, "Server did not respond within 10s (possible hang or deadlock)",
            "unexpected panic message: {message:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout branch took too long: {elapsed:?}"
        );
    }
}
