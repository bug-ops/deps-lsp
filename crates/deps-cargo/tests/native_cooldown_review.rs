//! Regression tests for the correctness-gate review of #1982: the by-name window map must not
//! assign a window to a name that some dependency declares without one, and the user's home
//! `.cargo/config.toml` must stay excluded when the manifest is reached through a symlink.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::Path;
use std::sync::Arc;

use deps_cargo::CargoEcosystem;
use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::CargoParseContext;
#[cfg(unix)]
use deps_cargo::parser::parse_cargo_toml_with_context;
use deps_core::native_cooldown::native_cooldowns_by_name;
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::policy_config::NativeCooldownMode;
#[cfg(unix)]
use deps_core::{Dependency, UserHome};
use deps_core::{Ecosystem, HttpCache};
use url::Url;

const WINDOW: &str = "[registry]\nglobal-min-publish-age = \"7 days\"\n";

fn context() -> CargoParseContext {
    CargoParseContext::new(
        Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
        Arc::new(ConfigFileCache::new()),
    )
    .with_native_cooldown(NativeCooldownMode::Honor)
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

async fn windows_by_name(manifest: &str) -> usize {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    write(&root.join(".cargo/config.toml"), WINDOW);
    let path = root.join("Cargo.toml");
    write(&path, manifest);
    let uri = Url::from_file_path(&path).unwrap();
    let eco = Arc::new(CargoEcosystem::with_context(
        Arc::new(HttpCache::new()),
        context(),
    ));
    let parsed = Ecosystem::parse_manifest(eco, manifest, &uri)
        .await
        .unwrap();
    native_cooldowns_by_name(parsed.as_ref()).len()
}

#[tokio::test]
async fn by_name_map_lists_a_name_declared_only_from_the_window_scope() {
    let both_registry = "[dependencies]\nfoo = \"1\"\n[dev-dependencies]\nfoo = \"1\"\n";
    assert_eq!(windows_by_name(both_registry).await, 1);
}

#[tokio::test]
async fn by_name_map_omits_a_name_another_dependency_declares_without_the_window() {
    let mixed = "[dependencies]\nfoo = \"1\"\n[dev-dependencies]\nfoo = { git = \"https://example.invalid/foo.git\" }\n";
    assert_eq!(windows_by_name(mixed).await, 0);
}

#[cfg(unix)]
#[test]
fn home_config_is_excluded_when_the_manifest_is_reached_through_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    write(&home.join(".cargo/config.toml"), WINDOW);
    let link = root.join("link");
    std::os::unix::fs::symlink(&home, &link).unwrap();

    let ctx = context().with_user_home_for_test(UserHome::resolve(home));
    let manifest = "[dependencies]\nserde = \"1\"\n";
    let path = link.join("Cargo.toml");
    let uri = Url::from_file_path(&path).unwrap();
    let result = parse_cargo_toml_with_context(manifest, &uri, &ctx).unwrap();
    let dep = result
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == "serde")
        .unwrap();
    assert_eq!(Dependency::native_cooldown(dep), None);
}

#[cfg(unix)]
#[test]
fn symlinked_config_pointing_at_the_home_config_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    write(&home.join(".cargo/config.toml"), WINDOW);
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".cargo")).unwrap();
    std::os::unix::fs::symlink(
        home.join(".cargo/config.toml"),
        repo.join(".cargo/config.toml"),
    )
    .unwrap();

    let ctx = context().with_user_home_for_test(UserHome::resolve(home));
    let manifest = "[dependencies]\nserde = \"1\"\n";
    let uri = Url::from_file_path(repo.join("Cargo.toml")).unwrap();
    let result = parse_cargo_toml_with_context(manifest, &uri, &ctx).unwrap();
    assert_eq!(Dependency::native_cooldown(&result.dependencies[0]), None);
}
