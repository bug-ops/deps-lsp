//! #2119 acceptance: the freshness wiring of `deps-cli update --security-only --lockfile
//! regenerate`, end to end through the real binary.
//!
//! The registry is a `mockito` server reached through the `test-util` seam
//! (`DEPS_CLI_TEST_NPM_PUBLIC_BASE`), OSV is a `mockito` server reached through
//! `DEPS_OSV_BASE_URL`, and `npm` is a shell-script fake on `PATH`. The fix target `1.0.0` is
//! old enough, but the version the fake npm resolves (`1.0.1`, the registry's `latest`) was
//! published a day ago, inside the default three-day window. The held fix must be withheld and
//! the manifest left as it was.
//!
//! Dropping `ctx.policy.freshness.to_freshness()` from the planner call leaves no version held,
//! so the manifest is rewritten; dropping `OriginalManifest::new(&content)` from the target
//! leaves the held edit in the manifest.

#![cfg(all(unix, feature = "npm", feature = "test-util"))]
#![expect(clippy::expect_used, reason = "test code")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Output;

use native_advisory::{AdvisoryFixture, DAY, now_secs, osv_with_advisory, rfc3339};

mod native_advisory;

const MANIFEST: &str =
    "{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"widget\":\"^0.9.0\"}}\n";
const LOCK_OLD: &str = "{\"name\":\"p\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"widget\":\"^0.9.0\"}},\"node_modules/widget\":{\"version\":\"0.9.0\"}}}\n";
const LOCK_NEW: &str = "{\"name\":\"p\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"widget\":\"^1.0.0\"}},\"node_modules/widget\":{\"version\":\"1.0.1\"}}}\n";

/// `(version, age in seconds)`, oldest first; the newest entry is `latest`.
const VERSIONS: [(&str, i64); 3] = [("0.9.0", 100 * DAY), ("1.0.0", 100 * DAY), ("1.0.1", DAY)];

/// An npm that answers `--version` and rewrites the lock file to resolve `widget` to `1.0.1`.
fn fake_npm(root: &Path) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo 11.6.0; exit 0;;\n  prefix) pwd; exit 0;;\nesac\ncat > '{}/package-lock.json' <<'EOF'\n{LOCK_NEW}EOF\n",
        root.display()
    )
}

async fn mock_registry() -> (mockito::ServerGuard, Vec<mockito::Mock>) {
    let mut registry = mockito::Server::new_async().await;
    let entries: Vec<String> = VERSIONS
        .iter()
        .map(|(version, _)| format!(r#""{version}":{{}}"#))
        .collect();
    let abbreviated = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body(format!(
            r#"{{"dist-tags":{{"latest":"1.0.1"}},"versions":{{{}}}}}"#,
            entries.join(",")
        ))
        .expect_at_least(0)
        .create_async()
        .await;
    let times: Vec<String> = VERSIONS
        .iter()
        .map(|(version, age)| format!(r#""{version}":"{}""#, rfc3339(now_secs() - age)))
        .collect();
    let full = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(format!(r#"{{"time":{{{}}}}}"#, times.join(",")))
        .expect_at_least(0)
        .create_async()
        .await;
    (registry, vec![abbreviated, full])
}

struct Run {
    output: Output,
    manifest: String,
    npm_calls: Vec<String>,
}

async fn run_update() -> Run {
    let (registry, _registry_mocks) = mock_registry().await;
    let (osv, _osv_mocks) = osv_with_advisory(&AdvisoryFixture {
        ecosystem: "npm",
        package: "widget",
        range_type: "SEMVER",
        vulnerable: "0.9.0",
        fixed: "1.0.0",
    })
    .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let project = root.join("project");
    let bin = root.join("bin");
    std::fs::create_dir_all(&project).expect("project dir");
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::write(project.join("package.json"), MANIFEST).expect("manifest");
    std::fs::write(project.join("package-lock.json"), LOCK_OLD).expect("lock");
    let log = bin.join("calls.log");
    let script = bin.join("npm");
    let body = fake_npm(&project).replacen(
        "case",
        &format!("echo \"$*\" >> '{}'\ncase", log.display()),
        1,
    );
    std::fs::write(&script, body).expect("fake npm");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args([
            "update",
            "--security-only",
            "--lockfile",
            "regenerate",
            "package.json",
        ])
        .current_dir(&project)
        .env("PATH", path)
        .env("DEPS_OSV_BASE_URL", osv.url())
        .env("DEPS_CLI_TEST_NPM_PUBLIC_BASE", registry.url())
        .output()
        .expect("run deps-cli");
    Run {
        output,
        manifest: std::fs::read_to_string(project.join("package.json")).expect("manifest"),
        npm_calls: std::fs::read_to_string(&log)
            .map(|log| log.lines().map(str::to_owned).collect())
            .unwrap_or_default(),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn held_security_fix_is_withheld_and_the_manifest_is_left_as_it_was() {
    let run = run_update().await;

    let (stdout, stderr) = (text(&run.output.stdout), text(&run.output.stderr));
    let context = format!("{stdout}\n{stderr}");
    assert_eq!(run.manifest, MANIFEST, "{context}");
    assert_eq!(run.output.status.code(), Some(1), "{context}");
    assert!(
        stdout.contains("[unfixable] widget 0.9.0 -> 1.0.0")
            && stdout.contains("inside the freshness cooldown window (3 days)"),
        "{context}"
    );
    assert_eq!(run.npm_calls.len(), 1, "{:?}", run.npm_calls);
}

#[test]
fn an_unusable_npm_public_base_is_reported_and_ignored() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("package.json"), MANIFEST).expect("manifest");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["update", "--offline", "--dry-run", "package.json"])
        .current_dir(dir.path())
        .env("DEPS_CLI_TEST_NPM_PUBLIC_BASE", "not a url")
        .output()
        .expect("run deps-cli");

    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("deps-cli: ignoring unusable DEPS_CLI_TEST_NPM_PUBLIC_BASE"),
        "{stderr}"
    );
    assert!(
        output.status.code().is_some_and(|code| code != 2),
        "the value is ignored, not fatal: {stderr}"
    );
}
