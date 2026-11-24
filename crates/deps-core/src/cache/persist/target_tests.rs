//! Acceptance tests for spec 051 T006: `PersistenceTarget::from_config`.
//!
//! `Memory` never resolves a directory; `Disk` resolves the user-default directory or falls
//! back to `Memory` with exactly one warning. Every environment below is unresolvable (or
//! resolvable) on every platform, so the tests are host-independent.

use super::PersistenceTarget;
use super::dir::CacheDir;
use crate::net_policy::MapEnv;
use crate::policy_config::CachePersistence;
use std::assert_matches;
use std::path::{Path, PathBuf};

fn abs(name: &str) -> PathBuf {
    std::env::temp_dir()
        .join("deps-lsp-target-tests")
        .join(name)
}

fn with_path(env: MapEnv, name: &str, path: &Path) -> MapEnv {
    env.with_var(name, path.to_str().expect("utf-8 path"))
}

fn resolvable_env() -> MapEnv {
    let env = with_path(MapEnv::new(), "HOME", &abs("home"));
    let env = with_path(env, "XDG_CACHE_HOME", &abs("xdg"));
    with_path(env, "LOCALAPPDATA", &abs("local"))
}

fn relative_env() -> MapEnv {
    MapEnv::new()
        .with_var("HOME", "rel/home")
        .with_var("XDG_CACHE_HOME", "rel/xdg")
        .with_var("LOCALAPPDATA", "rel/local")
}

#[test]
fn from_config_memory_is_memory() {
    assert_matches!(
        PersistenceTarget::from_config(CachePersistence::Memory, &resolvable_env()),
        PersistenceTarget::Memory
    );
    assert_matches!(
        PersistenceTarget::from_config(CachePersistence::Memory, &MapEnv::new()),
        PersistenceTarget::Memory
    );
}

#[test]
fn from_config_disk_resolvable_is_disk_with_user_default_dir() {
    let env = resolvable_env();
    let expected = CacheDir::user_default(&env).expect("resolvable env");
    match PersistenceTarget::from_config(CachePersistence::Disk, &env) {
        PersistenceTarget::Disk(dir) => assert_eq!(dir.as_path(), expected.as_path()),
        PersistenceTarget::Memory => panic!("resolvable directory must give Disk"),
    }
}

#[cfg(feature = "test-util")]
mod warnings {
    use super::*;
    use crate::test_util::capture_tracing_output;

    fn warn_lines(output: &str) -> usize {
        output.lines().filter(|line| line.contains("WARN")).count()
    }

    fn non_empty_lines(output: &str) -> usize {
        output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    }

    fn assert_memory_with_one_warn(env: &MapEnv) {
        let mut target = None;
        let output = capture_tracing_output(|| {
            target = Some(PersistenceTarget::from_config(CachePersistence::Disk, env));
        });
        assert_matches!(target, Some(PersistenceTarget::Memory));
        assert_eq!(
            warn_lines(&output),
            1,
            "expected exactly one warn: {output}"
        );
        assert_eq!(non_empty_lines(&output), 1, "no other output: {output}");
    }

    #[test]
    fn from_config_disk_without_home_is_memory_with_one_warn() {
        assert_memory_with_one_warn(&MapEnv::new());
    }

    #[test]
    fn from_config_disk_with_relative_dirs_is_memory_with_one_warn() {
        assert_memory_with_one_warn(&relative_env());
    }

    #[test]
    fn from_config_memory_logs_nothing() {
        let output = capture_tracing_output(|| {
            let _ = PersistenceTarget::from_config(CachePersistence::Memory, &MapEnv::new());
        });
        assert_eq!(non_empty_lines(&output), 0, "unexpected output: {output}");
    }

    #[test]
    fn from_config_disk_resolvable_logs_nothing() {
        let output = capture_tracing_output(|| {
            let _ = PersistenceTarget::from_config(CachePersistence::Disk, &resolvable_env());
        });
        assert_eq!(non_empty_lines(&output), 0, "unexpected output: {output}");
    }
}
