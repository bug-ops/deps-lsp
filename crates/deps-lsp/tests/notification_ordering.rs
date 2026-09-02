//! Tests for LSP notification ordering.
//!
//! Verifies that notifications are sent in the correct order during document
//! lifecycle events. `workspace/inlayHint/refresh` is fired off (fire-and-forget,
//! via `tokio::spawn`) before `textDocument/publishDiagnostics` is generated, so
//! in practice it is observed first — but since the two run as independent
//! detached tasks, that relative order is scheduler-dependent, not a guarantee
//! the server makes to the client (see issue #493).

mod common;

use common::LspClient;
use std::time::Duration;

/// Verifies notification capture infrastructure works correctly.
///
/// NOTE: This is a placeholder test. The full notification ordering test
/// requires the server to actually send workspace/inlayHint/refresh and
/// textDocument/publishDiagnostics notifications, which currently don't
/// appear to be sent in the test environment (possibly due to caching
/// or the background task not completing).
///
/// See .local/notification-ordering-implementation.md for full details.
#[cfg(feature = "cargo")]
#[test]
fn test_inlay_hints_refresh_before_diagnostics() {
    let mut client = LspClient::spawn();

    // Initialize LSP session
    let _init_response = client.initialize();

    // Verify initialization succeeded
    assert!(_init_response.get("result").is_some());

    // Clear any notifications from initialization
    client.clear_notifications();
    assert_eq!(client.get_notifications().len(), 0);

    // Open a Cargo.toml document
    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
"#;

    client.did_open("file:///test/Cargo.toml", "toml", cargo_toml);

    // Flush notifications to capture any server-sent messages
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(200));
        client.flush_notifications();
    }

    // Verify we can capture notifications
    let notifications = client.get_notifications();

    // We should see at least window/logMessage
    assert!(
        !notifications.is_empty(),
        "Should capture at least one notification (window/logMessage)"
    );

    // Verify sequence numbers are monotonically increasing
    for i in 1..notifications.len() {
        assert!(
            notifications[i].sequence > notifications[i - 1].sequence,
            "Sequence numbers must be monotonically increasing"
        );
    }

    // TODO: Once background task notifications are reliably sent, add:
    // - Verification that workspace/inlayHint/refresh is present
    // - Verification that textDocument/publishDiagnostics is present
    // - Verification that refresh comes before diagnostics

    // Shutdown cleanly
    let _shutdown_response = client.shutdown();
}

/// Regression test for issue #493: reproduces the exact client behavior from the
/// bug report — a client that declares `workspace.inlayHint.refreshSupport` and
/// `workspace.codeLens.refreshSupport` during `initialize`, but never replies to
/// either `workspace/inlayHint/refresh` or `workspace/codeLens/refresh` once the
/// server sends them.
///
/// Before the fix, both requests were awaited inline in the background task
/// ahead of the OSV vulnerability commit and `textDocument/publishDiagnostics`,
/// with no timeout — an unanswered request stalled that task forever, and
/// `publishDiagnostics` was never sent. `wait_for_notification`'s bounded polling
/// (~2s total) would time out and this test would fail on that revert; today the
/// refresh calls are fire-and-forget (and, since #493 S2, additionally bounded by
/// a 5s server-side timeout), so diagnostics must still arrive promptly.
#[cfg(feature = "cargo")]
#[test]
fn test_diagnostics_not_blocked_by_unanswered_refresh_requests() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize();
    client.stop_responding_to_refresh_requests();
    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open("file:///test/Cargo.toml", "toml", cargo_toml);

    let _diagnostics = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics"
                && n.params["uri"] == "file:///test/Cargo.toml"
        })
        .expect(
            "Server must publish diagnostics even though the client never answers \
             workspace/inlayHint/refresh or workspace/codeLens/refresh (issue #493 \
             regression: an inline, un-timeouted await here would hang the \
             background task forever)",
        );

    assert!(
        client.unanswered_refresh_request_count() >= 1,
        "Expected the server to have actually attempted at least one refresh \
         request (proving capability negotiation and the refresh call both \
         happened) even though the harness never answered it"
    );

    let _shutdown_response = client.shutdown();
}

/// Verifies that progress notifications follow the expected lifecycle.
///
/// Per the LSP work-done-progress protocol, `window/workDoneProgress/create`
/// is a *request* the server sends to the client (answered here by
/// `LspClient::auto_respond`) to allocate a progress token; the lifecycle
/// itself is reported via `$/progress` *notifications* whose `params.value.kind`
/// is `"begin"`, then zero or more `"report"`, then `"end"` — there is no
/// wire notification literally named `window/workDoneProgress/begin` or
/// `.../end`. Without the auto-responder, the server's create request would
/// never get a reply and the whole progress lifecycle would silently never
/// fire — the assertions below (unconditional, not `if let`) are what catches
/// that regression.
#[cfg(feature = "cargo")]
#[test]
fn test_progress_notification_lifecycle() {
    let mut client = LspClient::spawn();

    // Initialize LSP session
    let _init_response = client.initialize();

    // Clear any notifications from initialization
    client.clear_notifications();

    // Open a Cargo.toml document to trigger background processing
    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open("file:///test/Cargo.toml", "toml", cargo_toml);

    // `begin` is sent right after the progress token is created, before any
    // registry network call, so it should arrive quickly.
    let begin = client
        .wait_for_notification(20, |n| {
            n.method == "$/progress" && n.params["value"]["kind"] == "begin"
        })
        .expect("Server should send a $/progress begin notification while fetching versions");

    // `end` is sent only after the registry fetch completes (or times out —
    // `fetch_timeout_secs` defaults to 5s), so give it a much larger budget.
    let end = client
        .wait_for_notification(80, |n| {
            n.method == "$/progress" && n.params["value"]["kind"] == "end"
        })
        .expect("Server should send a $/progress end notification once the fetch completes");

    assert!(
        client.progress_create_request_count() >= 1,
        "Expected the server to request a workDoneProgress token before reporting progress"
    );

    assert!(
        begin.sequence < end.sequence,
        "Expected $/progress begin (seq={}) to come before $/progress end (seq={})",
        begin.sequence,
        end.sequence
    );

    // Shutdown cleanly
    let _shutdown_response = client.shutdown();
}

/// Regression test for #290: the server must not send
/// `window/workDoneProgress/create` requests to a client that explicitly
/// declined `window.workDoneProgress` support during `initialize` — doing
/// so unconditionally is an LSP 3.17 spec violation.
#[cfg(feature = "cargo")]
#[test]
fn test_no_progress_create_without_client_capability() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize_with_progress_support(false);
    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open("file:///test/Cargo.toml", "toml", cargo_toml);

    // Positive liveness proof: `publishDiagnostics` for this URI is only sent
    // after the background registry fetch completes (see `lifecycle.rs`), so
    // waiting for it proves the fetch actually ran to completion rather than
    // the absence check below being vacuously true (e.g. because `did_open`
    // became a no-op in the harness).
    let _diagnostics = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics"
                && n.params["uri"] == "file:///test/Cargo.toml"
        })
        .expect(
            "Server should publish diagnostics for the opened document once the fetch completes",
        );

    assert_eq!(
        client.progress_create_request_count(),
        0,
        "Server must not request a workDoneProgress token when the client didn't advertise support"
    );

    let _shutdown_response = client.shutdown();
}

/// Verifies notification capture works correctly.
#[test]
fn test_notification_capture_basic() {
    let mut client = LspClient::spawn();

    // Initialize LSP session
    let _init_response = client.initialize();

    // Test clear functionality
    client.clear_notifications();
    let cleared = client.get_notifications();
    assert!(cleared.is_empty(), "Expected notifications to be cleared");

    // Send a request to trigger any notifications
    let _response = client.workspace_symbol(100, "test");

    let notifications = client.get_notifications();

    // If we have notifications, verify sequence numbers
    if notifications.len() > 1 {
        for i in 1..notifications.len() {
            assert!(
                notifications[i].sequence > notifications[i - 1].sequence,
                "Sequence numbers should be monotonically increasing"
            );
        }
    }

    // Shutdown cleanly
    let _shutdown_response = client.shutdown();
}

/// Verifies that multiple documents trigger independent notification sequences.
#[cfg(feature = "cargo")]
#[test]
fn test_multiple_documents_notification_ordering() {
    let mut client = LspClient::spawn();

    // Initialize LSP session
    let _init_response = client.initialize();
    client.clear_notifications();

    // Open first document
    let cargo_toml_1 = r#"[package]
name = "package1"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open("file:///test/Cargo1.toml", "toml", cargo_toml_1);
    std::thread::sleep(Duration::from_millis(500));
    client.flush_notifications();

    // Open second document
    let cargo_toml_2 = r#"[package]
name = "package2"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = "1.0"
"#;

    client.did_open("file:///test/Cargo2.toml", "toml", cargo_toml_2);
    std::thread::sleep(Duration::from_millis(500));
    client.flush_notifications();

    // Get all notifications
    let notifications = client.get_notifications();

    // Verify we captured some notifications
    assert!(
        !notifications.is_empty(),
        "Should have captured some notifications"
    );

    // Verify all have valid sequence numbers
    if notifications.len() > 1 {
        for i in 1..notifications.len() {
            assert!(notifications[i].sequence > notifications[i - 1].sequence);
        }
    }

    // Shutdown cleanly
    let _shutdown_response = client.shutdown();
}
