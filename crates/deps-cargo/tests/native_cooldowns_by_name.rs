//! #1982: `native_cooldowns_by_name`, the by-name view of a manifest's native windows the CLI's
//! cooldown-fallback view reads. Kills the mutant that replaces it with an empty map.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::sync::Arc;

use deps_cargo::CargoEcosystem;
use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::CargoParseContext;
use deps_core::native_cooldown::native_cooldowns_by_name;
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{Ecosystem, HttpCache, PackageKey, PackageName, ParsedManifest};
use url::Url;

async fn parse(config: Option<&str>, dependencies: &str) -> Box<dyn ParsedManifest> {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    if let Some(config) = config {
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::write(root.join(".cargo/config.toml"), config).unwrap();
    }
    let manifest = format!("[dependencies]\n{dependencies}\n");
    let path = root.join("Cargo.toml");
    std::fs::write(&path, &manifest).unwrap();
    let ctx = CargoParseContext::new(
        Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
        Arc::new(ConfigFileCache::new()),
    )
    .with_native_cooldown(NativeCooldownMode::Honor);
    let eco = Arc::new(CargoEcosystem::with_context(
        Arc::new(HttpCache::new()),
        ctx,
    ));
    Ecosystem::parse_manifest(eco, &manifest, &Url::from_file_path(&path).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn native_cooldowns_by_name_maps_each_windowed_package_to_its_window() {
    let manifest = parse(
        Some("[registry]\nglobal-min-publish-age = \"7 days\"\n"),
        "serde = \"1\"\ntokio = \"1\"\nlocal = { path = \"../local\" }",
    )
    .await;
    let map = native_cooldowns_by_name(manifest.as_ref());
    assert_eq!(map.len(), 2, "path dependencies have no window: {map:?}");
    for name in ["serde", "tokio"] {
        let key = PackageKey::new(&PackageName::new(name), manifest.formatter());
        let cooldown = map
            .get(key.normalized())
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(
            cooldown.to_string(),
            "cargo registry.global-min-publish-age = 7 days"
        );
    }
}

#[tokio::test]
async fn native_cooldowns_by_name_is_empty_without_a_window() {
    let manifest = parse(None, "serde = \"1\"").await;
    assert!(native_cooldowns_by_name(manifest.as_ref()).is_empty());
}

#[tokio::test]
async fn native_cooldowns_by_name_first_occurrence_of_a_name_wins() {
    let manifest = parse(
        Some("[registry]\nglobal-min-publish-age = \"7 days\"\n"),
        "serde = \"1\"\n[dev-dependencies]\nserde = \"1\"",
    )
    .await;
    assert_eq!(native_cooldowns_by_name(manifest.as_ref()).len(), 1);
}
