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
    locate_lockfile_for_manifest,
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

            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(|e| DepsError::ParseError {
                    file_type: format!("Package.resolved at {}", lockfile_path.display()),
                    source: Box::new(e),
                })?;

            let lock_data: PackageResolved =
                serde_json::from_str(&content).map_err(|e| DepsError::ParseError {
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
                        let name =
                            url_to_identity(&pin.repository_url).unwrap_or(pin.package.clone());
                        if let Some(version) = pin.state.version {
                            let version = version.strip_prefix('v').unwrap_or(&version).to_string();
                            packages.insert(ResolvedPackage {
                                name,
                                version,
                                source: ResolvedSource::Git {
                                    url: pin.repository_url,
                                    rev: pin.state.revision.unwrap_or_default(),
                                },
                                dependencies: vec![],
                            });
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
                            let version = version.strip_prefix('v').unwrap_or(&version).to_string();
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
                            packages.insert(ResolvedPackage {
                                name,
                                version,
                                source,
                                dependencies: vec![],
                            });
                        }
                    }
                }
                v => {
                    tracing::warn!("Unknown Package.resolved version: {}", v);
                }
            }

            tracing::info!(
                "Parsed Package.resolved: {} packages from {}",
                packages.len(),
                lockfile_path.display()
            );

            Ok(packages)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lockfile::LockFileProvider;

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
        assert_eq!(resolved.get_version("apple/swift-nio"), Some("2.62.0"));
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
        assert_eq!(resolved.get_version("apple/swift-nio"), Some("2.62.0"));
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
        assert_eq!(resolved.get_version("vapor/vapor"), Some("4.89.3"));
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
        assert!(matches!(pkg.source, ResolvedSource::Path { .. }));
    }

    #[tokio::test]
    async fn test_invalid_json_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Package.resolved");
        tokio::fs::write(&path, b"not valid json").await.unwrap();

        let parser = SwiftLockParser;
        let result = parser.parse_lockfile(&path).await;
        assert!(result.is_err());
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
        assert_eq!(resolved.get_version("org/mypkg"), Some("3.1.4"));
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
        assert_eq!(resolved.get_version("org/mypkg"), Some("2.0.0"));
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
        assert_eq!(resolved.get_version("FallbackName"), Some("1.0.0"));
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
