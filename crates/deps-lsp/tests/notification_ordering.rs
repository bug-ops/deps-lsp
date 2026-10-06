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
// Only the cargo-gated tests below sleep on a `Duration`.
#[cfg(feature = "cargo")]
use std::time::Duration;

/// Builds a platform-portable absolute `file://` URI string for a test fixture:
/// `url::Url::to_file_path` (which `parse_manifest`'s workspace-root discovery calls
/// internally) requires a drive-letter path segment to succeed on Windows, so a bare
/// `file:///test/...` fixture (valid on Unix) fails there — mirrors
/// `deps_core::test_util::test_uri`'s pattern for the `Url`-typed equivalent.
#[cfg(feature = "cargo")]
fn fixture_uri(name: &str) -> String {
    #[cfg(windows)]
    {
        format!("file:///C:/test/{name}")
    }
    #[cfg(not(windows))]
    {
        format!("file:///test/{name}")
    }
}

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

    let _init_response = client.initialize();

    assert!(_init_response.get("result").is_some());

    client.clear_notifications();
    assert_eq!(client.get_notifications().len(), 0);

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
"#;

    client.did_open(&fixture_uri("Cargo.toml"), "toml", cargo_toml);

    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(200));
        client.flush_notifications();
    }

    let notifications = client.get_notifications();

    // We should see at least window/logMessage
    assert!(
        !notifications.is_empty(),
        "Should capture at least one notification (window/logMessage)"
    );

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

    client.did_open(&fixture_uri("Cargo.toml"), "toml", cargo_toml);

    let _diagnostics = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics"
                && n.params["uri"] == fixture_uri("Cargo.toml").as_str()
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

/// LSP `DiagnosticSeverity::Hint`, the default `diagnostics.outdated_severity`.
#[cfg(feature = "cargo")]
const OLD_OUTDATED_SEVERITY: u64 = 4;

#[cfg(feature = "cargo")]
fn diagnostic_severities(notification: &common::CapturedNotification) -> Vec<u64> {
    notification
        .params
        .get("diagnostics")
        .and_then(|d| d.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|d| d.get("severity").and_then(|s| s.as_u64()))
                .collect()
        })
        .unwrap_or_default()
}

/// Regression test for #1794: a push-only client (no `workspace.diagnostics.refreshSupport`)
/// must receive a fresh `textDocument/publishDiagnostics` after a `didChangeConfiguration`
/// that changes no parse-affecting setting (here, a diagnostic severity).
#[cfg(feature = "cargo")]
#[test]
fn test_push_only_client_gets_republish_after_non_parse_config_change() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize();
    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;
    let uri = fixture_uri("Cargo.toml");
    client.did_open(&uri, "toml", cargo_toml);

    let _initial = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics" && n.params["uri"] == uri.as_str()
        })
        .expect("Server should publish diagnostics once the document's fetch completes");
    std::thread::sleep(Duration::from_secs(2));
    client.clear_notifications();

    client.did_change_configuration(serde_json::json!({
        "diagnostics": { "outdated_severity": 1 }
    }));

    let republish = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics" && n.params["uri"] == uri.as_str()
        })
        .expect(
            "Server must republish diagnostics to a push-only client after a non-parse-affecting \
             didChangeConfiguration (#1794)",
        );
    assert!(
        !diagnostic_severities(&republish).contains(&OLD_OUTDATED_SEVERITY),
        "the republish must carry the new severity, got {:?}",
        republish.params
    );

    let _shutdown_response = client.shutdown();
}

/// #1794: a configuration change that lands while a document is still loading must win over the
/// open task's spawn-time snapshot, and must not publish an empty set for the loading document.
#[cfg(feature = "cargo")]
#[test]
fn test_config_change_mid_load_publishes_new_severity() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize();
    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;
    let uri = fixture_uri("Cargo.toml");
    client.did_open(&uri, "toml", cargo_toml);
    client.did_change_configuration(serde_json::json!({
        "diagnostics": { "outdated_severity": 1 }
    }));

    let _ = client.wait_for_notification(60, |_| false);
    let published: Vec<_> = client
        .get_notifications()
        .into_iter()
        .filter(|n| {
            n.method == "textDocument/publishDiagnostics" && n.params["uri"] == uri.as_str()
        })
        .collect();
    let last = published.last().expect("diagnostics must be published");
    assert!(
        !diagnostic_severities(last).contains(&OLD_OUTDATED_SEVERITY),
        "the last publish must carry the new severity, got {:?}",
        last.params
    );

    let _shutdown_response = client.shutdown();
}

/// #1794: a pull-capable client is told to refresh and must not also get an unsolicited push.
#[cfg(feature = "cargo")]
#[test]
fn test_pull_client_gets_refresh_not_republish_after_non_parse_config_change() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize_with_diagnostic_refresh_support();
    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;
    let uri = fixture_uri("Cargo.toml");
    client.did_open(&uri, "toml", cargo_toml);
    let _initial = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics" && n.params["uri"] == uri.as_str()
        })
        .expect("Server should publish diagnostics once the document's fetch completes");
    std::thread::sleep(Duration::from_secs(2));
    client.clear_notifications();
    let refreshes_before = client.diagnostic_refresh_request_count();

    client.did_change_configuration(serde_json::json!({
        "diagnostics": { "outdated_severity": 1 }
    }));

    let _ = client.wait_for_notification(30, |_| false);
    assert!(
        client.diagnostic_refresh_request_count() > refreshes_before,
        "a pull client must get workspace/diagnostic/refresh"
    );
    assert!(
        client
            .get_notifications()
            .iter()
            .all(|n| n.method != "textDocument/publishDiagnostics"),
        "a pull client must not also receive a publishDiagnostics push"
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

    let _init_response = client.initialize();

    client.clear_notifications();

    let cargo_toml = r#"[package]
name = "test-package"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open(&fixture_uri("Cargo.toml"), "toml", cargo_toml);

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

    client.did_open(&fixture_uri("Cargo.toml"), "toml", cargo_toml);

    // Positive liveness proof: `publishDiagnostics` for this URI is only sent
    // after the background registry fetch completes (see `lifecycle.rs`), so
    // waiting for it proves the fetch actually ran to completion rather than
    // the absence check below being vacuously true (e.g. because `did_open`
    // became a no-op in the harness).
    let _diagnostics = client
        .wait_for_notification(20, |n| {
            n.method == "textDocument/publishDiagnostics"
                && n.params["uri"] == fixture_uri("Cargo.toml").as_str()
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

    let _init_response = client.initialize();

    client.clear_notifications();
    let cleared = client.get_notifications();
    assert!(cleared.is_empty(), "Expected notifications to be cleared");

    let _response = client.workspace_symbol(100, "test");

    let notifications = client.get_notifications();

    if notifications.len() > 1 {
        for i in 1..notifications.len() {
            assert!(
                notifications[i].sequence > notifications[i - 1].sequence,
                "Sequence numbers should be monotonically increasing"
            );
        }
    }

    let _shutdown_response = client.shutdown();
}

/// Verifies that multiple documents trigger independent notification sequences.
#[cfg(feature = "cargo")]
#[test]
fn test_multiple_documents_notification_ordering() {
    let mut client = LspClient::spawn();

    let _init_response = client.initialize();
    client.clear_notifications();

    let cargo_toml_1 = r#"[package]
name = "package1"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#;

    client.did_open(&fixture_uri("Cargo1.toml"), "toml", cargo_toml_1);
    std::thread::sleep(Duration::from_millis(500));
    client.flush_notifications();

    let cargo_toml_2 = r#"[package]
name = "package2"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = "1.0"
"#;

    client.did_open(&fixture_uri("Cargo2.toml"), "toml", cargo_toml_2);
    std::thread::sleep(Duration::from_millis(500));
    client.flush_notifications();

    let notifications = client.get_notifications();

    assert!(
        !notifications.is_empty(),
        "Should have captured some notifications"
    );

    if notifications.len() > 1 {
        for i in 1..notifications.len() {
            assert!(notifications[i].sequence > notifications[i - 1].sequence);
        }
    }

    let _shutdown_response = client.shutdown();
}
