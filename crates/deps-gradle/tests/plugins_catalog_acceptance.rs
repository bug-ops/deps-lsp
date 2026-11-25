//! #2151: a version catalog is any `*.versions.toml` under `gradle/`, not only `libs.versions.toml`.
//! Fixtures are named `plugins.versions.toml` so a `libs`-suffix rule cannot satisfy them.

#![expect(clippy::unwrap_used, reason = "test code")]

use deps_core::lockfile::LockFileProvider;
use deps_core::{EcosystemBase, HttpCache};
use deps_gradle::{GradleEcosystem, GradleLockParser, parse_gradle};
use std::sync::Arc;
use url::Url;

const CATALOG: &str = include_str!("fixtures/libs.versions.toml");

fn uri(path: &str) -> Url {
    deps_core::test_util::test_uri(path)
}

fn summary(path: &str, content: &str) -> Vec<(String, Option<String>)> {
    parse_gradle(content, &uri(path))
        .unwrap()
        .dependencies
        .into_iter()
        .map(|dep| {
            (
                format!("{:?}", dep.name),
                Some(format!("{:?}", dep.version_req)),
            )
        })
        .collect()
}

#[test]
fn parse_gradle_reads_a_plugins_catalog_like_a_libs_catalog() {
    let plugins = summary("/project/gradle/plugins.versions.toml", CATALOG);
    let libs = summary("/project/gradle/libs.versions.toml", CATALOG);
    assert!(plugins.len() >= 6);
    assert_eq!(plugins, libs);
}

#[test]
fn manifest_patterns_claim_every_versions_toml() {
    let ecosystem = GradleEcosystem::new(Arc::new(HttpCache::new()));
    assert!(ecosystem.manifest_patterns().iter().any(|pattern| {
        deps_core::ecosystem_registry::manifest_pattern_matches("plugins.versions.toml", pattern)
    }));
}

#[test]
fn locate_lockfile_for_a_plugins_catalog_in_gradle_dir_uses_the_root_lockfile() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("gradle.lockfile"), "").unwrap();
    let gradle_dir = root.path().join("gradle");
    std::fs::create_dir_all(&gradle_dir).unwrap();
    let catalog = Url::from_file_path(gradle_dir.join("plugins.versions.toml")).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&catalog),
        Some(root.path().join("gradle.lockfile"))
    );
}
