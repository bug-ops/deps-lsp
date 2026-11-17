//! gradle.lockfile edge cases (#1925, spec 092): only valid three-part coordinates count.

#![allow(clippy::unwrap_used)]

use deps_core::lockfile::{LockFileProvider, ResolvedPackages};
use deps_gradle::GradleLockParser;

async fn parse(content: &str) -> deps_core::Result<ResolvedPackages> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gradle.lockfile");
    tokio::fs::write(&path, content).await.unwrap();
    GradleLockParser.parse_lockfile(&path).await
}

#[tokio::test]
async fn parse_lockfile_handles_crlf_line_endings() {
    let content = "# comment\r\ncom.google.guava:guava:32.1.2-jre=compileClasspath\r\nempty=x\r\n";
    let packages = parse(content).await.unwrap();
    assert_eq!(
        packages.version("com.google.guava:guava"),
        Some("32.1.2-jre")
    );
    assert_eq!(packages.len(), 1);
}

#[tokio::test]
async fn parse_lockfile_trims_surrounding_whitespace() {
    let packages = parse("   org.slf4j:slf4j-api:2.0.9=runtimeClasspath   \n")
        .await
        .unwrap();
    assert_eq!(packages.version("org.slf4j:slf4j-api"), Some("2.0.9"));
}

#[tokio::test]
async fn parse_lockfile_skips_four_part_coordinates() {
    let content = "g:a:1.0:classifier=compileClasspath\ng:b:2.0=compileClasspath\n";
    let packages = parse(content).await.unwrap();
    assert!(packages.get("g:a").is_none());
    assert_eq!(packages.version("g:b"), Some("2.0"));
}

#[tokio::test]
async fn parse_lockfile_skips_empty_segments() {
    let content = ":a:1.0=x\ng::1.0=x\ng:a:=x\ng:ok:1.0=x\n";
    let packages = parse(content).await.unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages.version("g:ok"), Some("1.0"));
}
