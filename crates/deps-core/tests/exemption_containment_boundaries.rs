//! #1964 / spec 101: the exemption file is refused when the repository, not just the opened
//! folder, contains it (monorepo subfolder workspaces, committed symlinks), and a user-config
//! file must be a regular file.

#![cfg(feature = "test-util")]
#![allow(clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::path::{Path, PathBuf};

use deps_core::config_trust::{EnvPath, OperatorEnvVar, OperatorPath};
use deps_core::lsp_helpers::exemption::{
    ExemptionFile, OperatorExemptions, UserConfigLookup, WorkspaceRoots,
};
use deps_core::net_policy::MapEnv;

const BODY: &str = "[[advisory]]\nid = \"GHSA-aaaa-bbbb-cccc\"\nreason = \"accepted risk\"\n";

fn operator_path(path: &Path) -> OperatorPath {
    let env = MapEnv::new().with_var("XDG_CONFIG_HOME", path.to_str().expect("utf8 path"));
    match OperatorPath::from_env(&env, OperatorEnvVar::XdgConfigHome) {
        EnvPath::Path(p) => p,
        other => panic!("absolute path must be accepted, got {other:?}"),
    }
}

fn write_exemption_file(config_dir: &Path) {
    let dir = config_dir.join("deps-lsp");
    std::fs::create_dir_all(&dir).expect("create deps-lsp dir");
    std::fs::write(dir.join("advisory-exemptions.toml"), BODY).expect("write file");
}

fn lookup(home: &Path, roots: Vec<PathBuf>, config: &Path) -> UserConfigLookup {
    let roots = WorkspaceRoots::new(roots, Some(&operator_path(home)));
    ExemptionFile::under_config_dir(operator_path(config), &roots)
}

/// Repo-root `.envrc` exports `XDG_CONFIG_HOME=$PWD/.config`, the editor opens `repo/app`.
#[test]
fn subfolder_workspace_of_a_git_repository_refuses_the_repository_file() {
    let h = tempfile::tempdir().expect("home");
    let repo = h.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    let app = repo.join("app");
    std::fs::create_dir_all(&app).expect("app");
    let config = repo.join(".config");
    write_exemption_file(&config);

    let found = lookup(h.path(), vec![app], &config);

    assert_matches!(found, UserConfigLookup::InsideWorkspace { .. }, "{found:?}");
}

/// A repository top level at or above home is not a repository boundary.
#[test]
fn git_directory_at_home_does_not_widen_the_workspace() {
    let h = tempfile::tempdir().expect("home");
    std::fs::create_dir_all(h.path().join(".git")).expect("git dir at home");
    let w = h.path().join("proj");
    std::fs::create_dir_all(&w).expect("workspace");
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let found = lookup(h.path(), vec![w], &config);

    assert_matches!(found, UserConfigLookup::Located(_), "{found:?}");
}

/// A workspace outside any git repository keeps the opened folder as its only boundary.
#[test]
fn workspace_without_a_git_repository_is_not_widened() {
    let h = tempfile::tempdir().expect("home");
    let w = h.path().join("proj");
    std::fs::create_dir_all(&w).expect("workspace");
    let config = h.path().join("elsewhere").join(".config");
    write_exemption_file(&config);

    let found = lookup(h.path(), vec![w], &config);

    assert_matches!(found, UserConfigLookup::Located(_), "{found:?}");
}

/// A committed `deps-lsp` directory symlink in the workspace pointing outside it.
#[cfg(unix)]
#[test]
fn committed_directory_symlink_out_of_the_workspace_is_refused() {
    let h = tempfile::tempdir().expect("home");
    let w = h.path().join("proj");
    let outside = h.path().join("elsewhere");
    write_exemption_file(&outside);
    std::fs::create_dir_all(w.join(".config")).expect("config dir");
    std::os::unix::fs::symlink(outside.join("deps-lsp"), w.join(".config").join("deps-lsp"))
        .expect("symlink");

    let found = lookup(h.path(), vec![w.clone()], &w.join(".config"));

    assert_matches!(found, UserConfigLookup::InsideWorkspace { .. }, "{found:?}");
}

/// A committed file symlink in the workspace pointing outside it.
#[cfg(unix)]
#[test]
fn committed_file_symlink_out_of_the_workspace_is_refused() {
    let h = tempfile::tempdir().expect("home");
    let w = h.path().join("proj");
    let outside = h.path().join("outside.toml");
    std::fs::write(&outside, BODY).expect("outside file");
    let dir = w.join(".config").join("deps-lsp");
    std::fs::create_dir_all(&dir).expect("config dir");
    std::os::unix::fs::symlink(&outside, dir.join("advisory-exemptions.toml")).expect("symlink");

    let found = lookup(h.path(), vec![w.clone()], &w.join(".config"));

    assert_matches!(found, UserConfigLookup::InsideWorkspace { .. }, "{found:?}");
}

#[cfg(unix)]
fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");
}

/// A user-config file that is a FIFO (as a symlink to `/dev/stdin` would be) is refused without
/// blocking on it.
#[cfg(unix)]
#[test]
fn user_config_fifo_is_not_a_regular_file_and_does_not_block() {
    let h = tempfile::tempdir().expect("home");
    let config = h.path().join(".config");
    let dir = config.join("deps-lsp");
    std::fs::create_dir_all(&dir).expect("config dir");
    make_fifo(&dir.join("advisory-exemptions.toml"));

    let found = lookup(h.path(), vec![], &config);
    let UserConfigLookup::Located(file) = found else {
        panic!("expected Located, got {found:?}");
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(OperatorExemptions::load(&file));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("load must not block on a FIFO");

    assert!(result.is_err(), "{result:?}");
}

/// The command-line source keeps allowing pipes (`--advisory-exemptions <(cmd)`).
#[cfg(unix)]
#[test]
fn command_line_fifo_is_still_read() {
    let dir = tempfile::tempdir().expect("dir");
    let fifo = dir.path().join("exemptions.fifo");
    make_fifo(&fifo);
    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || std::fs::write(writer_path, BODY));

    let loaded = OperatorExemptions::load(&ExemptionFile::for_test(fifo)).expect("valid");

    writer.join().expect("writer thread").expect("write fifo");
    assert_eq!(loaded.map(|e| e.len()), Some(1));
}
