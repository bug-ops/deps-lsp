//! deno.lock edge cases (#1924, spec 091).

#![allow(clippy::unwrap_used)]

use deps_core::lockfile::{LockFileProvider, ResolvedPackages};
use deps_deno::DenoLockParser;

async fn parse(content: &str) -> deps_core::Result<ResolvedPackages> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deno.lock");
    tokio::fs::write(&path, content).await.unwrap();
    DenoLockParser.parse_lockfile(&path).await
}

#[tokio::test]
async fn parse_lockfile_tolerates_jsonc_comments() {
    let content = "{\n  // generated\n  \"version\": \"5\",\n  \"specifiers\": {\n    \"npm:chalk@5\": \"5.6.2\" /* pin */\n  }\n}";
    let packages = parse(content).await.unwrap();
    assert_eq!(packages.version("npm:chalk"), Some("5.6.2"));
}

#[tokio::test]
async fn parse_lockfile_v3_without_packages_section_is_empty() {
    let packages = parse(r#"{"version":"3","remote":{}}"#).await.unwrap();
    assert!(packages.is_empty());
}

#[tokio::test]
async fn parse_lockfile_v5_without_specifiers_is_empty() {
    let packages = parse(r#"{"version":"5"}"#).await.unwrap();
    assert!(packages.is_empty());
}

#[tokio::test]
async fn parse_lockfile_skips_entries_with_a_foreign_scheme() {
    let content = r#"{"version":"5","specifiers":{"https://deno.land/x/a.ts@1":"1.0.0","jsr:@std/path@1":"1.1.6"}}"#;
    let packages = parse(content).await.unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages.version("jsr:@std/path"), Some("1.1.6"));
}
