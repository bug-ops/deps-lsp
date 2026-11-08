//! `diagnostics.suppress` through the real `deps-cli check` binary and an explicit `--config`
//! (#1927, spec 094). The npm registry is a `mockito` server reached through the fixture's own
//! `.npmrc`; the config lives outside the scanned tree because an auto-discovered `deps.toml`
//! is never allowed to suppress findings (spec 062 F1).

#![allow(clippy::expect_used)]

use std::path::Path;

const SUPPRESS_OUTDATED: &str = r#"
[[diagnostics.suppress]]
package = "reac*"
kinds = ["outdated"]
"#;

const SUPPRESS_OTHER_KIND: &str = r#"
[[diagnostics.suppress]]
package = "react"
kinds = ["deprecated", "yanked"]
"#;

const BASE_CONFIG: &str = r#"
[diagnostics]
vulnerabilities_enabled = false

[registries]
workspace_registries = "all"
"#;

struct Run {
    stdout: String,
    stderr: String,
}

fn run_check(project: &Path, config: &Path, host: &str) -> Run {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["check", "--format", "json", "--config"])
        .arg(config)
        .arg(project)
        .env(
            "DEPS_LSP_PRIVATE_REGISTRY_HOSTS",
            host.split(':').next().expect("host"),
        )
        .output()
        .expect("run the real deps-cli binary");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

async fn outdated_react_stdout(extra_config: &str) -> Run {
    let mut server = mockito::Server::new_async().await;
    let _packument = server
        .mock("GET", "/react")
        .with_status(200)
        .with_body(r#"{"versions": {"16.0.0": {}, "19.3.0": {}}}"#)
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
        r#"{"name":"fixture","dependencies":{"react":"^16.0.0"}}"#,
    )
    .expect("write package.json");

    let config_dir = tempfile::tempdir().expect("create config dir");
    let config = config_dir.path().join("deps.toml");
    std::fs::write(&config, format!("{BASE_CONFIG}{extra_config}")).expect("write config");

    let project_path = project.path().to_path_buf();
    tokio::task::spawn_blocking(move || run_check(&project_path, &config, &host))
        .await
        .expect("join check run")
}

#[tokio::test]
async fn test_explicit_config_suppresses_the_listed_kind() {
    let baseline = outdated_react_stdout("").await;
    assert!(
        baseline.stdout.contains("19.3.0"),
        "control run must report the outdated dependency: {} / {}",
        baseline.stdout,
        baseline.stderr
    );

    let suppressed = outdated_react_stdout(SUPPRESS_OUTDATED).await;
    assert!(
        !suppressed.stdout.contains("19.3.0"),
        "outdated must be hidden: {} / {}",
        suppressed.stdout,
        suppressed.stderr
    );
}

#[tokio::test]
async fn test_explicit_config_leaves_other_kinds_visible() {
    let run = outdated_react_stdout(SUPPRESS_OTHER_KIND).await;
    assert!(
        run.stdout.contains("19.3.0"),
        "a rule for other kinds must not hide outdated: {} / {}",
        run.stdout,
        run.stderr
    );
}
