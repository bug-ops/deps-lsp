//! composer.lock parser.
//!
//! Parses composer.lock files to extract resolved dependency versions.
//! Supports both production (`packages`) and development (`packages-dev`) sections.

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;

/// composer.lock file parser.
///
/// Implements lock file parsing for the Composer package manager.
/// Supports project-level and workspace-level lock files.
///
/// # Lock File Location
///
/// The parser searches for composer.lock in the following order:
/// 1. Same directory as composer.json
/// 2. Parent directories (up to 5 levels) for workspace root
pub struct ComposerLockParser;

impl ComposerLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["composer.lock"];
}

/// composer.lock structure (partial).
#[derive(Debug, Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<LockPackage>,
    #[serde(rename = "packages-dev", default)]
    packages_dev: Vec<LockPackage>,
}

/// Individual package entry in composer.lock.
#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<LockSource>,
}

/// Source entry in composer.lock package.
#[derive(Debug, Deserialize)]
struct LockSource {
    #[serde(rename = "type")]
    source_type: String,
    url: String,
    reference: Option<String>,
}

impl LockFileProvider for ComposerLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing composer.lock: {}", lockfile_path.display());

            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(|e| DepsError::ParseError {
                    file_type: "composer.lock".into(),
                    source: Box::new(e),
                })?;

            let lock_data: ComposerLock =
                serde_json::from_str(&content).map_err(|e| DepsError::ParseError {
                    file_type: "composer.lock".into(),
                    source: Box::new(e),
                })?;

            let mut packages = ResolvedPackages::new();

            for pkg in lock_data.packages.into_iter().chain(lock_data.packages_dev) {
                let source = pkg.source.map_or(
                    ResolvedSource::Registry {
                        url: String::new(),
                        checksum: String::new(),
                    },
                    |s| match s.source_type.as_str() {
                        "git" => ResolvedSource::Git {
                            url: s.url,
                            rev: s.reference.unwrap_or_default(),
                        },
                        "path" => ResolvedSource::Path { path: s.url },
                        _ => ResolvedSource::Registry {
                            url: s.url,
                            checksum: String::new(),
                        },
                    },
                );

                packages.insert(ResolvedPackage {
                    name: pkg.name.to_lowercase(),
                    version: pkg.version,
                    source,
                    dependencies: Vec::new(),
                });
            }

            tracing::info!(
                "Parsed composer.lock: {} packages from {}",
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

    #[tokio::test]
    async fn test_parse_composer_lock() {
        let content = r#"{
  "packages": [
    {
      "name": "symfony/console",
      "version": "6.0.0",
      "source": {
        "type": "git",
        "url": "https://github.com/symfony/console.git",
        "reference": "abc123"
      }
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.0.0"
    }
  ]
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("composer.lock");
        tokio::fs::write(&lock_path, content).await.unwrap();

        let parser = ComposerLockParser;
        let resolved = parser.parse_lockfile(&lock_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved.get_version("symfony/console"), Some("6.0.0"));
        assert_eq!(resolved.get_version("phpunit/phpunit"), Some("10.0.0"));
    }

    #[tokio::test]
    async fn test_parse_git_source() {
        let content = r#"{
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.0.0",
      "source": {
        "type": "git",
        "url": "https://github.com/vendor/package.git",
        "reference": "deadbeef"
      }
    }
  ],
  "packages-dev": []
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("composer.lock");
        tokio::fs::write(&lock_path, content).await.unwrap();

        let parser = ComposerLockParser;
        let resolved = parser.parse_lockfile(&lock_path).await.unwrap();

        let pkg = resolved.get("vendor/package").unwrap();
        match &pkg.source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/vendor/package.git");
                assert_eq!(rev, "deadbeef");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_parse_malformed_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("composer.lock");
        tokio::fs::write(&lock_path, "not json").await.unwrap();

        let parser = ComposerLockParser;
        let result = parser.parse_lockfile(&lock_path).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_locate_lockfile() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let lock_path = temp_dir.path().join("composer.lock");

        std::fs::write(&manifest_path, r#"{"name": "test/project"}"#).unwrap();
        std::fs::write(&lock_path, r#"{"packages": [], "packages-dev": []}"#).unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = ComposerLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }
}
