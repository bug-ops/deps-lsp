//! #1982 / spec 099 Phase 1 acceptance: reading Cargo's `min-publish-age` window from the
//! repository-level `.cargo/config.toml` hierarchy (FR-004, FR-005, FR-013, FR-014, S3).
//!
//! Written tests-first against plan v4. Assumed seams (not in the plan text, named here so the
//! developer can adapt them in one place): `CargoParseContext::with_native_cooldown(mode)` and the
//! test-only `CargoParseContext::with_user_home_for_test(UserHome)`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::{CargoParseContext, parse_cargo_toml_with_context};
use deps_core::net_policy::{MapEnv, RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{Dependency, UserHome};
use url::Url;

const GLOBAL: &str = "cargo registry.global-min-publish-age = ";

fn ctx(mode: NativeCooldownMode) -> CargoParseContext {
    CargoParseContext::new(
        Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
        Arc::new(ConfigFileCache::new()),
    )
    .with_native_cooldown(mode)
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn temp_root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

/// Writes `<dir>/Cargo.toml` with `[dependencies]` = `deps` and returns the window label of `name`.
fn label(ctx: &CargoParseContext, dir: &Path, deps: &str, name: &str) -> Option<String> {
    let manifest = format!("[dependencies]\n{deps}\n");
    let path = dir.join("Cargo.toml");
    write(&path, &manifest);
    let uri = Url::from_file_path(&path).unwrap();
    let result = parse_cargo_toml_with_context(&manifest, &uri, ctx).unwrap();
    let dep = result
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == name)
        .unwrap_or_else(|| panic!("dependency {name} not parsed"));
    Dependency::native_cooldown(dep).map(ToString::to_string)
}

fn serde_label(root: &Path, config: &str) -> Option<String> {
    write(&root.join(".cargo/config.toml"), config);
    label(
        &ctx(NativeCooldownMode::Honor),
        root,
        "serde = \"1\"",
        "serde",
    )
}

/// Guards negative tests against passing vacuously: a plain valid window must resolve.
fn assert_control_applies() {
    let (_g, root) = temp_root();
    assert_eq!(
        serde_label(&root, "[registry]\nglobal-min-publish-age = \"7 days\"\n").as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days"),
        "control: a valid window must resolve"
    );
}

#[test]
fn native_cooldown_global_window_applies_to_registry_dependency() {
    let (_g, root) = temp_root();
    let got = serde_label(&root, "[registry]\nglobal-min-publish-age = \"7 days\"\n");
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days")
    );
}

#[test]
fn native_cooldown_no_config_file_is_none() {
    assert_control_applies();
    let (_g, root) = temp_root();
    assert_eq!(
        label(
            &ctx(NativeCooldownMode::Honor),
            &root,
            "serde = \"1\"",
            "serde"
        ),
        None
    );
}

#[test]
fn native_cooldown_crates_io_registry_key_overrides_global() {
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[registries.crates-io]\nmin-publish-age = \"2 weeks\"\n",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registries.crates-io.min-publish-age = 2 weeks")
    );
}

#[test]
fn native_cooldown_per_registry_zero_disables_even_with_global_set() {
    assert_control_applies();
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[registries.crates-io]\nmin-publish-age = \"0\"\n",
    );
    assert_eq!(got, None);
}

#[test]
fn native_cooldown_global_zero_is_none() {
    assert_control_applies();
    let (_g, root) = temp_root();
    assert_eq!(
        serde_label(&root, "[registry]\nglobal-min-publish-age = \"0\"\n"),
        None
    );
}

#[test]
fn native_cooldown_incompatible_publish_age_allow_disables_window() {
    assert_control_applies();
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[resolver]\nincompatible-publish-age = \"allow\"\n",
    );
    assert_eq!(got, None);
}

#[test]
fn native_cooldown_incompatible_publish_age_deny_keeps_window() {
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[resolver]\nincompatible-publish-age = \"deny\"\n",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days")
    );
}

#[test]
fn native_cooldown_month_value_is_labelled_with_configured_text() {
    let (_g, root) = temp_root();
    let got = serde_label(&root, "[registry]\nglobal-min-publish-age = \"1 month\"\n");
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 1 month")
    );
}

#[test]
fn native_cooldown_malformed_value_is_ignored_with_exactly_one_warning_per_cached_file() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 fortnights\"\n",
    );
    let shared = ctx(NativeCooldownMode::Honor);
    let mut labels = Vec::new();
    let output = deps_core::test_util::capture_tracing_output(|| {
        for _ in 0..2 {
            labels.push(label(&shared, &root, "serde = \"1\"", "serde"));
        }
    });
    assert_eq!(
        labels,
        [None, None],
        "malformed value falls back to no window"
    );
    assert_eq!(
        output.matches("global-min-publish-age").count(),
        1,
        "one warning naming the key, not one per parse: {output}"
    );
}

#[test]
fn native_cooldown_overflowing_value_is_ignored() {
    assert_control_applies();
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"99999999999999999999 weeks\"\n",
    );
    assert_eq!(got, None);
}

#[test]
fn native_cooldown_non_string_value_is_ignored() {
    assert_control_applies();
    let (_g, root) = temp_root();
    assert_eq!(
        serde_label(&root, "[registry]\nglobal-min-publish-age = 7\n"),
        None
    );
}

#[test]
fn native_cooldown_malformed_per_registry_value_counts_as_absent_so_global_applies() {
    let (_g, root) = temp_root();
    let got = serde_label(
        &root,
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[registries.crates-io]\nmin-publish-age = \"soon\"\n",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days")
    );
}

#[test]
fn native_cooldown_ignore_mode_resolves_nothing_and_logs_nothing() {
    assert_control_applies();
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"bogus\"\n",
    );
    let ignore = ctx(NativeCooldownMode::Ignore);
    let mut got = Some(String::new());
    let output = deps_core::test_util::capture_tracing_output(|| {
        got = label(&ignore, &root, "serde = \"1\"", "serde");
    });
    assert_eq!(got, None);
    assert!(!output.contains("global-min-publish-age"), "{output}");

    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    assert_eq!(label(&ignore, &root, "serde = \"1\"", "serde"), None);
}

#[test]
fn native_cooldown_mode_switch_on_a_fresh_context_applies_without_stale_cache() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let cache = Arc::new(ConfigFileCache::new());
    let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
    let honor = CargoParseContext::new(Arc::clone(&policy), Arc::clone(&cache))
        .with_native_cooldown(NativeCooldownMode::Honor);
    let ignore =
        CargoParseContext::new(policy, cache).with_native_cooldown(NativeCooldownMode::Ignore);
    assert!(label(&honor, &root, "serde = \"1\"", "serde").is_some());
    assert_eq!(label(&ignore, &root, "serde = \"1\"", "serde"), None);
    assert!(label(&honor, &root, "serde = \"1\"", "serde").is_some());
}

fn workspace(root: &Path) -> PathBuf {
    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n",
    );
    root.join("member")
}

#[test]
fn native_cooldown_closest_config_wins_over_workspace_root_config() {
    let (_g, root) = temp_root();
    let member = workspace(&root);
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    write(
        &member.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"3 days\"\n",
    );
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &member,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 3 days")
    );
}

#[test]
fn native_cooldown_workspace_root_config_applies_to_member() {
    let (_g, root) = temp_root();
    let member = workspace(&root);
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &member,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days")
    );
}

#[test]
fn native_cooldown_config_above_the_workspace_root_is_ignored() {
    assert_control_applies();
    let (_g, outer) = temp_root();
    write(
        &outer.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let root = outer.join("repo");
    let member = workspace(&root);
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &member,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(got, None);
}

#[test]
fn native_cooldown_without_workspace_root_reads_only_the_manifest_directory() {
    let (_g, outer) = temp_root();
    write(
        &outer.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let project = outer.join("proj");
    let none = label(
        &ctx(NativeCooldownMode::Honor),
        &project,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(none, None, "parent config is outside the boundary");

    write(
        &project.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"2 days\"\n",
    );
    let some = label(
        &ctx(NativeCooldownMode::Honor),
        &project,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(
        some.as_deref(),
        Some("cargo registry.global-min-publish-age = 2 days")
    );
}

/// The user's own `~/.cargo/config.toml` is never read, with `CARGO_HOME` unset or set.
#[test]
fn native_cooldown_config_in_the_user_home_directory_is_ignored() {
    assert_control_applies();
    for cargo_home in [None, Some("/somewhere/else")] {
        let (_g, home) = temp_root();
        write(
            &home.join(".cargo/config.toml"),
            "[registry]\nglobal-min-publish-age = \"7 days\"\n",
        );
        let mut env = MapEnv::new();
        if let Some(value) = cargo_home {
            env = env.with_var("CARGO_HOME", value);
        }
        let context = ctx(NativeCooldownMode::Honor)
            .with_env_for_test(env)
            .with_user_home_for_test(UserHome::new(home.clone()));
        assert_eq!(
            label(&context, &home, "serde = \"1\"", "serde"),
            None,
            "CARGO_HOME={cargo_home:?}"
        );
    }
}

#[test]
fn native_cooldown_cargo_home_tier_and_cargo_env_are_never_read() {
    assert_control_applies();
    let (_g, root) = temp_root();
    let (_h, cargo_home) = temp_root();
    write(
        &cargo_home.join("config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let env = MapEnv::new()
        .with_var("CARGO_HOME", cargo_home.to_str().unwrap())
        .with_var("CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE", "9 days");
    let context = ctx(NativeCooldownMode::Honor).with_env_for_test(env);
    assert_eq!(label(&context, &root, "serde = \"1\"", "serde"), None);
}

#[test]
fn native_cooldown_git_path_and_workspace_dependencies_have_no_window() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let deps = "g = { git = \"https://example.invalid/g.git\" }\np = { path = \"../p\" }\nw = { workspace = true }\nr = \"1\"";
    let context = ctx(NativeCooldownMode::Honor);
    for name in ["g", "p", "w"] {
        assert_eq!(label(&context, &root, deps, name), None, "{name}");
    }
    assert_eq!(
        label(&context, &root, deps, "r").as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days")
    );
}

#[test]
fn native_cooldown_alias_registry_dependency_uses_its_own_registry_key() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registries.corp]\nindex = \"sparse+https://corp.example/index/\"\nmin-publish-age = \"2 weeks\"\n[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let deps = "inner = { version = \"1\", registry = \"corp\" }\nouter = \"1\"";
    let context = ctx(NativeCooldownMode::Honor);
    assert_eq!(
        label(&context, &root, deps, "inner").as_deref(),
        Some("cargo registries.corp.min-publish-age = 2 weeks")
    );
    assert_eq!(
        label(&context, &root, deps, "outer").as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days"),
        "the plain dependency keeps the crates-io scope"
    );
}

#[test]
fn native_cooldown_alias_registry_without_own_key_falls_back_to_global() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registries.corp]\nindex = \"sparse+https://corp.example/index/\"\n[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &root,
        "inner = { version = \"1\", registry = \"corp\" }",
        "inner",
    );
    assert_eq!(got.as_deref(), Some(&*format!("{GLOBAL}7 days")));
}

#[test]
fn native_cooldown_source_replaced_crates_io_uses_the_crates_io_key() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://mirror.example/index/\"\n[registries.crates-io]\nmin-publish-age = \"5 days\"\n",
    );
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &root,
        "serde = \"1\"",
        "serde",
    );
    assert_eq!(
        got.as_deref(),
        Some("cargo registries.crates-io.min-publish-age = 5 days")
    );
}

#[test]
fn native_cooldown_literal_index_dependency_gets_only_the_global_window() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registries.crates-io]\nmin-publish-age = \"5 days\"\n[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let got = label(
        &ctx(NativeCooldownMode::Honor),
        &root,
        "lit = { version = \"1\", registry-index = \"sparse+https://idx.example/\" }",
        "lit",
    );
    assert_eq!(got.as_deref(), Some(&*format!("{GLOBAL}7 days")));
}

#[test]
fn native_cooldown_window_label_window_matches_configured_span() {
    let (_g, root) = temp_root();
    write(
        &root.join(".cargo/config.toml"),
        "[registry]\nglobal-min-publish-age = \"7 days\"\n",
    );
    let manifest = "[dependencies]\nserde = \"1\"\n";
    let path = root.join("Cargo.toml");
    write(&path, manifest);
    let uri = Url::from_file_path(&path).unwrap();
    let result =
        parse_cargo_toml_with_context(manifest, &uri, &ctx(NativeCooldownMode::Honor)).unwrap();
    let window = Dependency::native_cooldown(&result.dependencies[0])
        .expect("window")
        .age_window()
        .expect("age window");
    assert!(window.contains(7 * 86_400 - 1));
    assert!(!window.contains(7 * 86_400));
}
