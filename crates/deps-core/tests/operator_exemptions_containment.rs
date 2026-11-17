//! Acceptance tests for #1964 / spec 101: an advisory-exemption file located through the
//! operator's config directory is never honored when it sits inside a workspace root.
//!
//! Contracts (plan 2026-11-17T06-15-23-architect): `ExemptionFile::under_config_dir`,
//! `WorkspaceRoots::new`, `UserConfigLookup`.

#![cfg(feature = "test-util")]
#![allow(clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::path::{Path, PathBuf};

use deps_core::config_trust::{EnvPath, OperatorEnvVar, OperatorPath};
use deps_core::lsp_helpers::exemption::{ExemptionFile, UserConfigLookup, WorkspaceRoots};
use deps_core::net_policy::MapEnv;
use proptest::prelude::*;

const FILE_BODY: &str = "[[advisory]]\nid = \"GHSA-aaaa-bbbb-cccc\"\nreason = \"accepted risk\"\n";

/// `OperatorPath` has no public constructor from a raw path; `XDG_CONFIG_HOME` is the route
/// `deps-lsp` itself uses to obtain an absolute operator path.
fn operator_path(path: &Path) -> OperatorPath {
    let env = MapEnv::new().with_var("XDG_CONFIG_HOME", path.to_str().expect("utf8 path"));
    match OperatorPath::from_env(&env, OperatorEnvVar::XdgConfigHome) {
        EnvPath::Path(p) => p,
        other => panic!("absolute path must be accepted, got {other:?}"),
    }
}

fn write_exemption_file(config_dir: &Path) -> PathBuf {
    let dir = config_dir.join("deps-lsp");
    std::fs::create_dir_all(&dir).expect("create deps-lsp dir");
    let file = dir.join("advisory-exemptions.toml");
    std::fs::write(&file, FILE_BODY).expect("write exemption file");
    file
}

fn roots(home: &Path, roots: impl IntoIterator<Item = PathBuf>) -> WorkspaceRoots {
    WorkspaceRoots::new(roots, Some(&operator_path(home)))
}

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp home")
}

/// The filesystem root of the volume holding `dir` (`/` on Unix, `C:\` on Windows).
fn filesystem_root_of(dir: &Path) -> PathBuf {
    dir.ancestors()
        .last()
        .expect("a path has at least one ancestor")
        .to_path_buf()
}

/// (a) The direnv / devcontainer layout: an absolute `XDG_CONFIG_HOME` inside the workspace.
#[test]
fn under_config_dir_absolute_xdg_inside_workspace_is_inside_workspace() {
    let h = home();
    let w = h.path().join("proj");
    let config = w.join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [w]));

    assert_matches!(
        lookup,
        UserConfigLookup::InsideWorkspace { .. },
        "{lookup:?}"
    );
}

/// (b) `cwd = /` (macOS GUI launch, clients without a cwd) must not refuse the operator's file.
#[test]
fn under_config_dir_filesystem_root_workspace_is_ignored() {
    let h = home();
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(
        operator_path(&config),
        &roots(h.path(), [filesystem_root_of(h.path())]),
    );

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// (c) `cwd = $HOME` (Neovim default) must not refuse the operator's file.
#[test]
fn under_config_dir_home_as_workspace_is_ignored() {
    let h = home();
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(
        operator_path(&config),
        &roots(h.path(), [h.path().to_path_buf()]),
    );

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// A root that is an ancestor of home is dropped for the same reason as `$HOME` itself.
#[test]
fn under_config_dir_ancestor_of_home_as_workspace_is_ignored() {
    let h = home();
    let config = h.path().join(".config");
    write_exemption_file(&config);
    let parent = h
        .path()
        .parent()
        .expect("temp dir has a parent")
        .to_path_buf();

    let lookup =
        ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [parent]));

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// (d) A sibling workspace below home does not contain the operator's config dir.
#[test]
fn under_config_dir_sibling_workspace_is_located() {
    let h = home();
    let w = h.path().join("proj");
    std::fs::create_dir_all(&w).expect("create workspace");
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [w]));

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// (e) The (a) layout with no file: `Absent`, decided before containment (no warning path).
#[test]
fn under_config_dir_absent_file_inside_workspace_is_absent() {
    let h = home();
    let w = h.path().join("proj");
    let config = w.join(".config");
    std::fs::create_dir_all(&config).expect("create config dir");

    let lookup = ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [w]));

    assert_matches!(lookup, UserConfigLookup::Absent, "{lookup:?}");
}

#[test]
fn under_config_dir_without_home_still_drops_filesystem_root() {
    let h = home();
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(
        operator_path(&config),
        &WorkspaceRoots::new([filesystem_root_of(h.path())], None),
    );

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// A root that cannot be canonicalized is dropped, not treated as containing everything.
#[test]
fn under_config_dir_nonexistent_workspace_root_is_dropped() {
    let h = home();
    let config = h.path().join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(
        operator_path(&config),
        &roots(h.path(), [h.path().join("does-not-exist")]),
    );

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// Containment is component-wise: `/w/proj` does not contain `/w/proj-other/...`.
#[test]
fn under_config_dir_prefix_sibling_is_not_contained() {
    let h = home();
    let w = h.path().join("proj");
    std::fs::create_dir_all(&w).expect("create workspace");
    let config = h.path().join("proj-other").join(".config");
    write_exemption_file(&config);

    let lookup = ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [w]));

    assert_matches!(lookup, UserConfigLookup::Located(_), "{lookup:?}");
}

/// The decision is made on the canonical path: a config dir that is a symlink into the
/// workspace is inside it.
#[cfg(unix)]
#[test]
fn under_config_dir_symlink_into_workspace_is_inside_workspace() {
    let h = home();
    let w = h.path().join("proj");
    let real = w.join("real-config");
    write_exemption_file(&real);
    let link = h.path().join("link-config");
    std::os::unix::fs::symlink(&real, &link).expect("create symlink");

    let lookup = ExemptionFile::under_config_dir(operator_path(&link), &roots(h.path(), [w]));

    assert_matches!(
        lookup,
        UserConfigLookup::InsideWorkspace { .. },
        "{lookup:?}"
    );
}

/// R2: a canonicalize failure other than `NotFound` (here ENOTDIR: `deps-lsp` is a file)
/// fails closed. It is never `Absent` and never a usable `Located` file.
#[cfg(unix)]
#[test]
fn under_config_dir_non_notfound_canonicalize_error_fails_closed() {
    let h = home();
    let config = h.path().join(".config");
    std::fs::create_dir_all(&config).expect("create config dir");
    std::fs::write(config.join("deps-lsp"), "not a directory").expect("write blocker file");

    let lookup = ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), []));

    match lookup {
        UserConfigLookup::Absent => panic!("a non-NotFound error must not read as Absent"),
        UserConfigLookup::NoConfigDir => panic!("config dir was given"),
        UserConfigLookup::InsideWorkspace { .. } => {}
        UserConfigLookup::Located(file) => {
            assert!(
                deps_core::lsp_helpers::exemption::OperatorExemptions::load(&file).is_err(),
                "a Located file after a canonicalize error must fail to load"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Property: for any effective root R below home, a config dir derived as R/p with an
    /// existing file is never `Located`.
    #[test]
    fn under_config_dir_config_below_effective_root_is_never_located(
        segments in proptest::collection::vec("[a-z]{1,8}", 1..4),
        config_segments in proptest::collection::vec("[a-z]{1,8}", 0..3),
    ) {
        let h = home();
        let root: PathBuf = segments.iter().fold(h.path().to_path_buf(), |p, s| p.join(s));
        let config = config_segments.iter().fold(root.clone(), |p, s| p.join(s));
        write_exemption_file(&config);

        let lookup =
            ExemptionFile::under_config_dir(operator_path(&config), &roots(h.path(), [root]));

        let inside = matches!(lookup, UserConfigLookup::InsideWorkspace { .. });
        prop_assert!(inside, "{lookup:?}");
    }
}
