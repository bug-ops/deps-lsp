//! #2074 acceptance: `DEPS_OSV_BASE_URL` is validated at startup by every subcommand that builds
//! runtime handles (architect v2 Q5: even `--offline` runs), exits 2 on an invalid value, and a
//! valid value prints one stderr notice. Written tests-first; the variable is ignored today.

#![allow(clippy::expect_used)]

use std::process::Output;

const CARGO_MANIFEST: &str =
    "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n";

fn run(subcommand: &str, value: Option<&str>) -> Output {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("Cargo.toml"), CARGO_MANIFEST).expect("manifest");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"));
    command
        .args([subcommand, "--offline", "Cargo.toml"])
        .current_dir(dir.path())
        .env_remove("DEPS_OSV_BASE_URL");
    if let Some(value) = value {
        command.env("DEPS_OSV_BASE_URL", value);
    }
    command.output().expect("run deps-cli")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn invalid_osv_base_url_exits_2_naming_the_variable_for_every_subcommand() {
    for subcommand in ["update", "check"] {
        for value in [
            "http://example.com",
            "https://user:pw@osv.example.com",
            "not a url",
        ] {
            let output = run(subcommand, Some(value));

            assert_eq!(
                output.status.code(),
                Some(2),
                "{subcommand} {value}: {}",
                stderr(&output)
            );
            assert!(
                stderr(&output).contains("DEPS_OSV_BASE_URL"),
                "{subcommand} {value}: {}",
                stderr(&output)
            );
        }
    }
}

#[test]
fn loopback_osv_base_url_is_accepted_with_one_stderr_notice() {
    let output = run("update", Some("http://127.0.0.1:9"));

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let notices = stderr(&output)
        .lines()
        .filter(|line| line.contains("DEPS_OSV_BASE_URL"))
        .count();
    assert_eq!(notices, 1, "{}", stderr(&output));
}

#[test]
fn unset_or_empty_osv_base_url_prints_no_notice() {
    for value in [None, Some("")] {
        let output = run("update", value);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(
            !stderr(&output).contains("DEPS_OSV_BASE_URL"),
            "{}",
            stderr(&output)
        );
    }
}
