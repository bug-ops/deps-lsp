//! `diagnostics.ignore` through the real `deps-cli check` binary (#1967, spec 094 FR-010). The
//! npm registry is a `mockito` server reached through the fixture's own `.npmrc`; an explicit
//! `--config` is trusted, an auto-discovered `deps.toml` must never hide findings (spec 062 F1)
//! and its dropped `ignore` is reported.

#![cfg(feature = "npm")]
#![allow(clippy::expect_used)]

use std::path::Path;

struct Run {
    stdout: String,
    stderr: String,
    success: bool,
}

/// `diagnostics` is the body of the `[diagnostics]` table; the registry section is fixed.
fn config_text(diagnostics: &str) -> String {
    format!(
        "[diagnostics]\nvulnerabilities_enabled = false\n{diagnostics}\n\n[registries]\nworkspace_registries = \"all\"\n"
    )
}

fn run_check(project: &Path, config: Option<&Path>, host: &str) -> Run {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"));
    command.args(["check", "--format", "json"]);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    let output = command
        .arg(project)
        .current_dir(project)
        .env(
            "DEPS_LSP_PRIVATE_REGISTRY_HOSTS",
            host.split(':').next().expect("host"),
        )
        .output()
        .expect("run the real deps-cli binary");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    }
}

enum ConfigPlacement {
    Explicit,
    AutoDiscovered,
}

async fn check(diagnostics: &str, placement: ConfigPlacement) -> Run {
    let mut server = mockito::Server::new_async().await;
    let _react = server
        .mock("GET", "/react")
        .with_status(200)
        .with_body(r#"{"versions": {"16.0.0": {}, "19.3.0": {}}}"#)
        .create_async()
        .await;
    let _left_pad = server
        .mock("GET", "/left-pad")
        .with_status(200)
        .with_body(r#"{"versions": {"1.0.0": {}, "2.0.0": {}}}"#)
        .create_async()
        .await;
    let host = server.host_with_port();

    let project = tempfile::tempdir().expect("create project dir");
    std::fs::write(
        project.path().join(".npmrc"),
        format!("registry=http://{host}/\n"),
    )
    .expect("write npmrc");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"fixture","dependencies":{"react":"^16.0.0","left-pad":"^1.0.0"}}"#,
    )
    .expect("write package.json");

    let text = match placement {
        ConfigPlacement::Explicit => config_text(diagnostics),
        // Nothing but `ignore` may differ from the defaults, or the "dropped section" warning
        // would fire for an unrelated field.
        ConfigPlacement::AutoDiscovered => format!("[diagnostics]\n{diagnostics}\n"),
    };
    let config_dir = tempfile::tempdir().expect("create config dir");
    let (config_path, explicit) = match placement {
        ConfigPlacement::Explicit => (config_dir.path().join("deps.toml"), true),
        ConfigPlacement::AutoDiscovered => (project.path().join("deps.toml"), false),
    };
    std::fs::write(&config_path, text).expect("write config");

    let project_path = project.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        run_check(
            &project_path,
            explicit.then_some(config_path.as_path()),
            &host,
        )
    })
    .await
    .expect("join check run")
}

#[tokio::test]
async fn test_explicit_config_baseline_reports_both_outdated_packages() {
    let run = check("", ConfigPlacement::Explicit).await;
    assert!(
        run.stdout.contains("19.3.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout.contains("2.0.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
}

#[tokio::test]
async fn test_explicit_config_ignore_hides_that_package_only() {
    let run = check("ignore = [\"react\"]", ConfigPlacement::Explicit).await;
    assert!(
        !run.stdout.contains("19.3.0"),
        "the ignored package must not be reported: {} / {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout.contains("2.0.0"),
        "an unlisted package stays reported: {} / {}",
        run.stdout,
        run.stderr
    );
}

#[tokio::test]
async fn test_explicit_config_ignore_glob_hides_matching_packages() {
    let run = check("ignore = [\"*-pad\"]", ConfigPlacement::Explicit).await;
    assert!(
        !run.stdout.contains("2.0.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout.contains("19.3.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
}

#[tokio::test]
async fn test_explicit_config_ignore_of_another_package_hides_nothing() {
    let run = check("ignore = [\"unrelated\"]", ConfigPlacement::Explicit).await;
    assert!(
        run.stdout.contains("19.3.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout.contains("2.0.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
}

#[tokio::test]
async fn test_explicit_config_with_bare_wildcard_ignore_is_rejected() {
    let run = check("ignore = [\"*\"]", ConfigPlacement::Explicit).await;
    assert!(!run.success, "{} / {}", run.stdout, run.stderr);
    assert!(
        !run.stdout.contains("19.3.0"),
        "{} / {}",
        run.stdout,
        run.stderr
    );
}

#[tokio::test]
async fn test_auto_discovered_config_ignore_is_dropped_and_warned() {
    let run = check("ignore = [\"react\"]", ConfigPlacement::AutoDiscovered).await;
    assert!(
        run.stderr
            .contains("[diagnostics] section was auto-discovered"),
        "an auto-discovered ignore must be reported as dropped: {} / {}",
        run.stdout,
        run.stderr
    );
}
