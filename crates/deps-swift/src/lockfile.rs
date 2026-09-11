//! Package.resolved lockfile parser.
//!
//! Supports Package.resolved format versions 1, 2, and 3.
//!
//! # Format Differences
//!
//! - v1: `object.pins[].package` + `repositoryURL`
//! - v2/v3: `pins[].identity` + `location` (v3 adds optional `originHash`)

use crate::parser::url_to_identity;
use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_and_parse_lockfile,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;

/// Package.resolved file parser.
pub struct SwiftLockParser;

impl SwiftLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["Package.resolved"];
}

#[derive(Deserialize)]
struct PackageResolved {
    version: u32,
    #[serde(default)]
    object: Option<PackageResolvedV1Object>,
    #[serde(default)]
    pins: Option<Vec<PinV2>>,
}

#[derive(Deserialize)]
struct PackageResolvedV1Object {
    pins: Vec<PinV1>,
}

#[derive(Deserialize)]
struct PinV1 {
    package: String,
    #[serde(rename = "repositoryURL")]
    repository_url: String,
    state: PinState,
}

#[derive(Deserialize)]
struct PinV2 {
    identity: String,
    #[serde(default)]
    kind: String,
    location: String,
    state: PinState,
}

#[derive(Deserialize)]
struct PinState {
    version: Option<String>,
    revision: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    branch: Option<String>,
}

impl LockFileProvider for SwiftLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing Package.resolved: {}", lockfile_path.display());

            let packages =
                read_and_parse_lockfile(lockfile_path, "Package.resolved", parse_package_resolved)
                    .await?;

            tracing::info!(
                "Parsed Package.resolved: {} packages from {}",
                packages.len(),
                lockfile_path.display()
            );

            Ok(packages)
        })
    }
}

/// Parses `Package.resolved` content (already read and size-capped) into resolved packages.
///
/// The CPU-bound half of [`SwiftLockParser::parse_lockfile`], run inside
/// [`deps_core::lockfile::read_and_parse_lockfile`]'s `spawn_blocking`.
fn parse_package_resolved(content: String) -> Result<ResolvedPackages> {
    let lock_data: PackageResolved =
        deps_core::parse_json_checked(content.as_bytes()).map_err(|e| DepsError::ParseError {
            file_type: "Package.resolved".into(),
            source: Box::new(e),
        })?;

    let mut packages = ResolvedPackages::new();

    match lock_data.version {
        1 => {
            let Some(obj) = lock_data.object else {
                return Ok(packages);
            };
            for pin in obj.pins {
                let name = url_to_identity(&pin.repository_url).unwrap_or(pin.package.clone());
                if let Some(version) = pin.state.version {
                    let version = version
                        .strip_prefix(['v', 'V'])
                        .unwrap_or(&version)
                        .to_string();
                    packages.insert(ResolvedPackage::new(
                        name,
                        version,
                        ResolvedSource::Git {
                            url: pin.repository_url,
                            rev: pin.state.revision.unwrap_or_default(),
                        },
                    ));
                }
            }
        }
        2 | 3 => {
            let Some(pins) = lock_data.pins else {
                return Ok(packages);
            };
            for pin in pins {
                // For fileSystem pins, location is a local path — use identity as name.
                // For remote pins, derive owner/repo from the URL.
                let name = if pin.kind == "fileSystem" {
                    pin.identity.clone()
                } else {
                    url_to_identity(&pin.location).unwrap_or(pin.identity.clone())
                };
                if let Some(version) = pin.state.version {
                    let version = version
                        .strip_prefix(['v', 'V'])
                        .unwrap_or(&version)
                        .to_string();
                    let source = if pin.kind == "fileSystem" {
                        ResolvedSource::Path {
                            path: pin.location.clone(),
                        }
                    } else {
                        ResolvedSource::Git {
                            url: pin.location,
                            rev: pin.state.revision.unwrap_or_default(),
                        }
                    };
                    packages.insert(ResolvedPackage::new(name, version, source));
                }
            }
        }
        v => {
            tracing::warn!("Unknown Package.resolved version: {}", v);
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lockfile::LockFileProvider;
    use std::assert_matches;

    #[tokio::test]
    async fn test_parse_v1() {
        let content = r#"{
  "object": {
    "pins": [
      {
        "package": "SwiftNIO",
        "repositoryURL": "https://github.com/apple/swift-nio.git",
        "state": {
          "branch": null,
          "revision": "cf4e6a20",
          "version": "2.62.0"
        }
      }
    ]
  },
  "version": 1
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.version("apple/swift-nio"), Some("2.62.0"));
    }

    #[tokio::test]
    async fn test_parse_v2() {
        let content = r#"{
  "pins": [
    {
      "identity": "swift-nio",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-nio.git",
      "state": {
        "revision": "cf4e6a20",
        "version": "2.62.0"
      }
    }
  ],
  "version": 2
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.version("apple/swift-nio"), Some("2.62.0"));
    }

    #[tokio::test]
    async fn test_parse_v3_with_origin_hash() {
        let content = r#"{
  "pins": [
    {
      "identity": "vapor",
      "kind": "remoteSourceControl",
      "location": "https://github.com/vapor/vapor",
      "state": {
        "revision": "abc123",
        "version": "4.89.3"
      },
      "originHash": "sha256:abc"
    }
  ],
  "version": 3
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.version("vapor/vapor"), Some("4.89.3"));
    }

    #[tokio::test]
    async fn test_parse_filesystem_kind() {
        let content = r#"{
  "pins": [
    {
      "identity": "local-pkg",
      "kind": "fileSystem",
      "location": "/path/to/local",
      "state": {
        "version": "1.0.0"
      }
    }
  ],
  "version": 2
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        let pkg = resolved.get("local-pkg").unwrap();
        assert_matches!(pkg.source, ResolvedSource::Path { .. });
    }

    // #758: shared `LockFileProvider` conformance, replacing test_invalid_json_returns_error
    // — also closes a real gap: this crate had no `locate_lockfile`/`is_lockfile_stale_*`
    // coverage at all before.
    deps_core::lockfile_conformance! {
        mod swift_lockfile_conformance;
        build: SwiftLockParser;
        manifest: "Package.swift" => "// empty";
        lockfiles: [
            "Package.resolved" => r#"{"version": 2, "pins": []}"#,
        ];
        malformed: "not valid json";
    }

    // #758: the shared JSON-nesting-depth cap, replacing test_nesting_at_max_depth_accepted/
    // test_nesting_over_max_depth_rejected — `parse_package_resolved` takes an owned
    // `String`, not `&[u8]`, so the closure re-owns the bytes via `String::from_utf8_lossy`.
    deps_core::json_depth_conformance! {
        mod swift_lockfile_json_depth_conformance;
        parse: |bytes: &[u8]| parse_package_resolved(String::from_utf8_lossy(bytes).into_owned());
        wrap: |nested: &str| format!(r#"{{"version": 1, "extra": {nested}}}"#);
    }

    #[tokio::test]
    async fn test_unknown_version_returns_empty() {
        let content = r#"{
  "pins": [
    {
      "identity": "some-pkg",
      "kind": "remoteSourceControl",
      "location": "https://github.com/foo/bar",
      "state": { "version": "1.0.0" }
    }
  ],
  "version": 99
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 0);
    }

    #[tokio::test]
    async fn test_v1_missing_object_returns_empty() {
        let content = r#"{"version": 1}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 0);
    }

    #[tokio::test]
    async fn test_v2_missing_pins_returns_empty() {
        let content = r#"{"version": 2}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 0);
    }

    #[tokio::test]
    async fn test_v1_strips_v_prefix() {
        let content = r#"{
  "object": {
    "pins": [
      {
        "package": "MyPkg",
        "repositoryURL": "https://github.com/org/mypkg.git",
        "state": {
          "revision": "abc",
          "version": "v3.1.4"
        }
      }
    ]
  },
  "version": 1
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.version("org/mypkg"), Some("3.1.4"));
    }

    #[tokio::test]
    async fn test_v2_strips_v_prefix() {
        let content = r#"{
  "pins": [
    {
      "identity": "mypkg",
      "kind": "remoteSourceControl",
      "location": "https://github.com/org/mypkg",
      "state": { "revision": "abc", "version": "v2.0.0" }
    }
  ],
  "version": 2
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.version("org/mypkg"), Some("2.0.0"));
    }

    #[tokio::test]
    async fn test_v1_fallback_to_package_name_when_url_has_no_identity() {
        // URL with single path segment → url_to_identity returns None → fallback to package field
        let content = r#"{
  "object": {
    "pins": [
      {
        "package": "FallbackName",
        "repositoryURL": "https://example.com/onlyone",
        "state": {
          "revision": "abc",
          "version": "1.0.0"
        }
      }
    ]
  },
  "version": 1
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.version("FallbackName"), Some("1.0.0"));
    }

    #[tokio::test]
    async fn test_skip_branch_only_pins() {
        let content = r#"{
  "pins": [
    {
      "identity": "tool",
      "kind": "remoteSourceControl",
      "location": "https://github.com/dev/tool",
      "state": {
        "branch": "main",
        "revision": "abc123"
      }
    }
  ],
  "version": 2
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = SwiftLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        // No version, should be skipped
        assert_eq!(resolved.len(), 0);
    }
}
