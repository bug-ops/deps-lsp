//! #2161 hardening: declaration paths that must stay rejected even when the candidate would match
//! their normalized form, ASCII case-insensitive `.toml` handling, and settings edits picked up
//! after a first probe (mtime-gated cache).

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use deps_core::{EcosystemBase, HttpCache};
use deps_gradle::{GradleEcosystem, parse_gradle};

fn declaring(path: &str) -> String {
    format!("versionCatalogs {{ create(\"d\") {{ from(files(\"{path}\")) }} }}\n")
}

fn ecosystem() -> GradleEcosystem {
    GradleEcosystem::new(Arc::new(HttpCache::new()))
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

fn write(root: &Path, rel: &str, content: &str) -> PathBuf {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path
}

fn bump_mtime(path: &Path, secs: u64) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn absolute_declaration_is_rejected_even_when_its_relative_form_names_the_candidate() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    write(
        &root,
        "settings.gradle.kts",
        &declaring("/etc/gradle/deps.toml"),
    );
    let candidate = write(&root, "etc/gradle/deps.toml", "[libraries]\n");

    assert!(!ecosystem().claims_unrouted_manifest(&candidate, None));
}

#[test]
fn interpolated_declaration_is_rejected_even_when_the_candidate_is_named_literally() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    write(&root, "settings.gradle.kts", &declaring("$x/deps.toml"));
    let candidate = write(&root, "$x/deps.toml", "[libraries]\n");

    assert!(!ecosystem().claims_unrouted_manifest(&candidate, None));
}

#[test]
fn empty_declaration_claims_nothing() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    write(&root, "settings.gradle.kts", &declaring(""));
    let candidate = write(&root, "gradle/deps.toml", "[libraries]\n");

    assert!(!ecosystem().claims_unrouted_manifest(&candidate, None));
}

#[test]
fn claim_matches_an_uppercase_toml_extension() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    write(&root, "settings.gradle.kts", &declaring("gradle/Deps.TOML"));
    let candidate = write(&root, "gradle/Deps.TOML", "[libraries]\n");

    assert!(ecosystem().claims_unrouted_manifest(&candidate, None));
}

#[test]
fn parse_gradle_treats_an_uppercase_toml_uri_as_a_catalog() {
    let uri = deps_core::test_util::test_uri("/project/gradle/Deps.TOML");
    let content =
        "[libraries]\nguava = { module = \"com.google.guava:guava\", version = \"33.0.0-jre\" }\n";

    let deps = parse_gradle(content, &uri).unwrap().dependencies;

    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "com.google.guava:guava");
}

#[test]
fn claim_honours_either_settings_file_in_the_same_directory() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    write(&root, "settings.gradle.kts", "rootProject.name = \"x\"\n");
    write(&root, "settings.gradle", &declaring("gradle/deps.toml"));
    let candidate = write(&root, "gradle/deps.toml", "[libraries]\n");

    assert!(ecosystem().claims_unrouted_manifest(&candidate, None));
}

#[test]
fn settings_edited_after_the_first_probe_is_picked_up() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    let settings = write(&root, "settings.gradle.kts", "rootProject.name = \"x\"\n");
    let candidate = write(&root, "gradle/deps.toml", "[libraries]\n");
    let ecosystem = ecosystem();

    assert!(
        !ecosystem.claims_unrouted_manifest(&candidate, None),
        "not declared yet"
    );

    std::fs::write(&settings, declaring("gradle/deps.toml")).unwrap();
    bump_mtime(&settings, 10);
    assert!(
        ecosystem.claims_unrouted_manifest(&candidate, None),
        "the new declaration must be seen"
    );

    std::fs::write(&settings, "rootProject.name = \"x\"\n").unwrap();
    bump_mtime(&settings, 20);
    assert!(
        !ecosystem.claims_unrouted_manifest(&candidate, None),
        "a removed declaration must stop claiming"
    );
}

#[test]
fn deleting_the_settings_file_stops_the_claim() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_dir, root) = root();
    let settings = write(&root, "settings.gradle.kts", &declaring("gradle/deps.toml"));
    let candidate = write(&root, "gradle/deps.toml", "[libraries]\n");
    let ecosystem = ecosystem();
    assert!(ecosystem.claims_unrouted_manifest(&candidate, None));

    std::fs::remove_file(&settings).unwrap();

    assert!(!ecosystem.claims_unrouted_manifest(&candidate, None));
}
