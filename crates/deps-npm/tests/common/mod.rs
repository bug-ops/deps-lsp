//! Shared fixtures for the native release-age acceptance tests (#2041).
//!
//! Assumed seam: `NpmParseContext::with_native_cooldown(NativeCooldownMode)`, mirroring
//! `deps_cargo::parser::CargoParseContext::with_native_cooldown`.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use deps_core::native_cooldown::{NativeCooldown, NativeHold};
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{ConcreteVersion, Dependency, PublishTime};
use deps_npm::config::NpmParseContext;
use deps_npm::parser::{NpmParseResult, parse_package_json_with_context};
use deps_npm::workspace::parse_pnpm_workspace_manifest;
use url::Url;

pub(crate) const DAY: i64 = 86_400;
pub(crate) const NOW: i64 = 1_800_000_000;

pub(crate) fn ctx(mode: NativeCooldownMode) -> NpmParseContext {
    NpmParseContext::default().with_native_cooldown(mode)
}

pub(crate) fn honor() -> NpmParseContext {
    ctx(NativeCooldownMode::Honor)
}

pub(crate) fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

pub(crate) fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

pub(crate) fn package_json(deps: &[(&str, &str)]) -> String {
    let body: Vec<String> = deps
        .iter()
        .map(|(name, spec)| format!("\"{name}\": \"{spec}\""))
        .collect();
    format!("{{\"dependencies\": {{{}}}}}", body.join(", "))
}

pub(crate) fn parse_manifest(
    dir: &Path,
    deps: &[(&str, &str)],
    ctx: &NpmParseContext,
) -> NpmParseResult {
    let content = package_json(deps);
    let path = dir.join("package.json");
    write(&path, &content);
    let uri = Url::from_file_path(&path).unwrap();
    parse_package_json_with_context(&content, &uri, ctx).unwrap()
}

pub(crate) fn parse_workspace_buffer(
    dir: &Path,
    buffer: &str,
    ctx: &NpmParseContext,
) -> NpmParseResult {
    let uri = Url::from_file_path(dir.join("pnpm-workspace.yaml")).unwrap();
    parse_pnpm_workspace_manifest(buffer, &uri, ctx).unwrap()
}

pub(crate) fn cooldown_of(result: &NpmParseResult, name: &str) -> Option<NativeCooldown> {
    let dep = result
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == name)
        .unwrap_or_else(|| panic!("dependency {name} not parsed"));
    Dependency::native_cooldown(dep).cloned()
}

pub(crate) fn label_of(result: &NpmParseResult, name: &str) -> Option<String> {
    cooldown_of(result, name).map(|c| c.to_string())
}

/// Hold of `version` published `age_secs` before [`NOW`] under `cooldown`.
pub(crate) fn hold_at_age(
    cooldown: &NativeCooldown,
    version: &str,
    age_secs: i64,
) -> Option<NativeHold> {
    cooldown.hold(
        Some(PublishTime::from_unix_secs(NOW - age_secs)),
        &ConcreteVersion::new(version),
        PublishTime::from_unix_secs(NOW),
    )
}
