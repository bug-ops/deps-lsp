//! Pipfile.lock edge cases (#1926, spec 093): an entry that is not an exact `==` pin is skipped,
//! never fabricated, and never fails the whole file.

#![expect(clippy::unwrap_used, reason = "test code")]

use deps_core::lockfile::{LockFileProvider, ResolvedPackages};
use deps_pypi::PypiLockParser;
use std::assert_matches;

async fn parse(content: &str) -> deps_core::Result<ResolvedPackages> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Pipfile.lock");
    tokio::fs::write(&path, content).await.unwrap();
    PypiLockParser.parse_lockfile(&path).await
}

#[tokio::test]
async fn parse_lockfile_pipfile_non_string_version_skips_only_that_entry() {
    let content = r#"{
        "_meta": {"pipfile-spec": 6},
        "default": {"weird": {"version": 1}, "requests": {"version": "==2.31.0"}},
        "develop": {}
    }"#;
    let packages = parse(content).await.unwrap();
    assert!(packages.get("weird").is_none());
    assert_eq!(packages.version("requests"), Some("2.31.0"));
}

#[tokio::test]
async fn parse_lockfile_pipfile_same_package_in_both_sections_is_kept_twice() {
    let content = r#"{
        "_meta": {"pipfile-spec": 6},
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {"requests": {"version": "==2.30.0"}}
    }"#;
    let packages = parse(content).await.unwrap();
    assert_eq!(packages.all("requests").map(<[_]>::len), Some(2));
}

#[tokio::test]
async fn parse_lockfile_pipfile_missing_meta_is_parse_error() {
    let content = r#"{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}"#;
    let err = parse(content).await.unwrap_err();
    assert_matches!(err, deps_core::DepsError::ParseError { .. }, "{err:?}");
}
