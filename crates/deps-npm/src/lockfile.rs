//! package-lock.json file parsing.
//!
//! Parses package-lock.json files (versions 2 and 3) to extract resolved dependency
//! versions. Supports npm workspaces and proper path resolution.
//!
//! # package-lock.json Format
//!
//! package-lock.json uses JSON format with a "packages" object:
//!
//! ```json
//! {
//!   "name": "my-project",
//!   "lockfileVersion": 3,
//!   "packages": {
//!     "": {
//!       "name": "my-project",
//!       "dependencies": { "express": "^4.18.0" }
//!     },
//!     "node_modules/express": {
//!       "version": "4.18.2",
//!       "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
//!       "integrity": "sha512-..."
//!     }
//!   }
//! }
//! ```

use async_trait::async_trait;
use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tower_lsp::lsp_types::Url;

/// package-lock.json file parser.
///
/// Implements lock file parsing for npm package manager.
/// Supports both project-level and workspace-level lock files.
///
/// # Lock File Location
///
/// The parser searches for package-lock.json in the following order:
/// 1. Same directory as package.json
/// 2. Parent directories (up to 5 levels) for workspace root
///
/// # Examples
///
/// ```no_run
/// use deps_npm::lockfile::NpmLockParser;
/// use deps_core::lockfile::LockFileProvider;
/// use tower_lsp::lsp_types::Url;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let parser = NpmLockParser;
/// let manifest_uri = Url::parse("file:///path/to/package.json").unwrap();
///
/// if let Some(lockfile_path) = parser.locate_lockfile(&manifest_uri) {
///     let resolved = parser.parse_lockfile(&lockfile_path).await?;
///     println!("Found {} resolved packages", resolved.len());
/// }
/// # Ok(())
/// # }
/// ```
pub struct NpmLockParser;

impl NpmLockParser {
    /// Maximum depth to search for workspace root lock file.
    const MAX_WORKSPACE_DEPTH: usize = 5;
}

/// package-lock.json structure (partial, only fields we need).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageLockJson {
    /// Packages object with resolved dependencies
    #[serde(default)]
    packages: HashMap<String, PackageEntry>,
}

/// Individual package entry in the "packages" object.
#[derive(Debug, Deserialize)]
struct PackageEntry {
    /// Package version
    version: Option<String>,

    /// Registry URL where package was downloaded from
    resolved: Option<String>,

    /// Integrity hash (sha512-... format)
    integrity: Option<String>,

    /// True for local packages
    link: Option<bool>,

    /// Dependencies of this package (optional, for dependency tree)
    #[serde(default)]
    dependencies: HashMap<String, String>,
}

#[async_trait]
impl LockFileProvider for NpmLockParser {
    fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
        let manifest_path = manifest_uri.to_file_path().ok()?;

        // Try same directory as manifest
        let lock_path = manifest_path.with_file_name("package-lock.json");
        if lock_path.exists() {
            tracing::debug!("Found package-lock.json at: {}", lock_path.display());
            return Some(lock_path);
        }

        // Search up the directory tree for workspace root
        let mut current_dir = manifest_path.parent()?;

        for depth in 0..Self::MAX_WORKSPACE_DEPTH {
            let workspace_lock = current_dir.join("package-lock.json");
            if workspace_lock.exists() {
                tracing::debug!(
                    "Found workspace package-lock.json at depth {}: {}",
                    depth + 1,
                    workspace_lock.display()
                );
                return Some(workspace_lock);
            }

            current_dir = current_dir.parent()?;
        }

        tracing::debug!("No package-lock.json found for: {}", manifest_uri);
        None
    }

    async fn parse_lockfile(&self, lockfile_path: &Path) -> Result<ResolvedPackages> {
        tracing::debug!("Parsing package-lock.json: {}", lockfile_path.display());

        let content = tokio::fs::read_to_string(lockfile_path)
            .await
            .map_err(|e| DepsError::ParseError {
                file_type: format!("package-lock.json at {}", lockfile_path.display()),
                source: Box::new(e),
            })?;

        let lock_data: PackageLockJson =
            serde_json::from_str(&content).map_err(|e| DepsError::ParseError {
                file_type: "package-lock.json".into(),
                source: Box::new(e),
            })?;

        let mut packages = ResolvedPackages::new();

        for (key, entry) in lock_data.packages {
            // Skip root package (empty key)
            if key.is_empty() {
                continue;
            }

            // Extract package name from key (e.g., "node_modules/express" -> "express")
            let name = extract_package_name(&key);

            // Version is required for actual dependencies
            let Some(ref version) = entry.version else {
                tracing::debug!("Skipping package '{}' with no version", name);
                continue;
            };

            // Parse source based on link, resolved, and integrity fields
            let source = parse_npm_source(&entry);

            // Extract dependency names
            let dependencies: Vec<String> = entry.dependencies.keys().cloned().collect();

            packages.insert(ResolvedPackage {
                name: name.to_string(),
                version: version.clone(),
                source,
                dependencies,
            });
        }

        tracing::info!(
            "Parsed package-lock.json: {} packages from {}",
            packages.len(),
            lockfile_path.display()
        );

        Ok(packages)
    }
}

/// Extracts package name from lockfile key.
///
/// # Examples
///
/// - `"node_modules/express"` → `"express"`
/// - `"node_modules/@babel/core"` → `"@babel/core"`
/// - `"node_modules/express/node_modules/debug"` → `"debug"`
fn extract_package_name(key: &str) -> &str {
    // Find the last occurrence of "node_modules/"
    key.rsplit("node_modules/").next().unwrap_or(key)
}

/// Parses npm source information into ResolvedSource.
///
/// # Source Detection
///
/// - `link: true` → Path (local package)
/// - `resolved` URL with `integrity` → Registry
/// - `resolved` git URL → Git
/// - No `resolved` → Path (workspace dependency)
fn parse_npm_source(entry: &PackageEntry) -> ResolvedSource {
    // Local packages (link: true)
    if entry.link == Some(true) {
        return ResolvedSource::Path {
            path: String::new(),
        };
    }

    // Parse resolved URL
    if let Some(resolved_url) = &entry.resolved {
        // Git sources (various formats)
        if resolved_url.starts_with("git+")
            || resolved_url.starts_with("git://")
            || resolved_url.contains("github.com")
                && (resolved_url.contains(".git") || resolved_url.contains("/tarball/"))
        {
            return parse_git_source(resolved_url);
        }

        // Registry source with integrity
        if let Some(integrity) = &entry.integrity {
            return ResolvedSource::Registry {
                url: resolved_url.clone(),
                checksum: integrity.clone(),
            };
        }

        // Registry without integrity (shouldn't happen in v2+, but handle it)
        return ResolvedSource::Registry {
            url: resolved_url.clone(),
            checksum: String::new(),
        };
    }

    // No resolved URL means local/workspace dependency
    ResolvedSource::Path {
        path: String::new(),
    }
}

/// Parses Git source URL and extracts commit hash.
///
/// # Git URL Formats
///
/// - `git+https://github.com/user/repo.git#abc123` → rev: abc123
/// - `https://github.com/user/repo/tarball/abc123` → rev: abc123
/// - `git://github.com/user/repo.git#v1.0.0` → rev: v1.0.0
fn parse_git_source(url: &str) -> ResolvedSource {
    // Try to extract commit hash from URL
    let (clean_url, rev) = if let Some((base, hash)) = url.split_once('#') {
        (base.to_string(), hash.to_string())
    } else if url.contains("/tarball/") {
        // GitHub tarball URL: .../tarball/commitish
        if let Some(idx) = url.rfind("/tarball/") {
            let base = &url[..idx];
            let hash = &url[idx + 9..]; // len("/tarball/") = 9
            (base.to_string(), hash.to_string())
        } else {
            (url.to_string(), String::new())
        }
    } else {
        (url.to_string(), String::new())
    };

    // Remove git+ prefix if present
    let clean_url = clean_url
        .strip_prefix("git+")
        .unwrap_or(&clean_url)
        .to_string();

    ResolvedSource::Git {
        url: clean_url,
        rev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name_simple() {
        assert_eq!(extract_package_name("node_modules/express"), "express");
    }

    #[test]
    fn test_extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("node_modules/@babel/core"),
            "@babel/core"
        );
    }

    #[test]
    fn test_extract_package_name_nested() {
        assert_eq!(
            extract_package_name("node_modules/express/node_modules/debug"),
            "debug"
        );
    }

    #[test]
    fn test_parse_npm_source_registry() {
        let entry = PackageEntry {
            version: Some("4.18.2".into()),
            resolved: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".into()),
            integrity: Some("sha512-abc123".into()),
            link: None,
            dependencies: HashMap::new(),
        };

        let source = parse_npm_source(&entry);

        match source {
            ResolvedSource::Registry { url, checksum } => {
                assert_eq!(
                    url,
                    "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
                );
                assert_eq!(checksum, "sha512-abc123");
            }
            _ => panic!("Expected Registry source"),
        }
    }

    #[test]
    fn test_parse_npm_source_link() {
        let entry = PackageEntry {
            version: Some("1.0.0".into()),
            resolved: None,
            integrity: None,
            link: Some(true),
            dependencies: HashMap::new(),
        };

        let source = parse_npm_source(&entry);

        match source {
            ResolvedSource::Path { .. } => {}
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_parse_git_source_with_hash() {
        let source = parse_git_source("git+https://github.com/user/repo.git#abc123");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_git_source_tarball() {
        let source = parse_git_source("https://github.com/user/repo/tarball/abc123");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_git_source_no_hash() {
        let source = parse_git_source("git+https://github.com/user/repo.git");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert!(rev.is_empty());
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_parse_simple_package_lock() {
        let lockfile_content = r#"{
  "name": "my-project",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-project",
      "dependencies": {
        "express": "^4.18.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc123",
      "dependencies": {
        "body-parser": "1.20.1"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.1",
      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz",
      "integrity": "sha512-def456"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved.get_version("express"), Some("4.18.2"));
        assert_eq!(resolved.get_version("body-parser"), Some("1.20.1"));

        let express_pkg = resolved.get("express").unwrap();
        assert_eq!(express_pkg.dependencies.len(), 1);
        assert_eq!(express_pkg.dependencies[0], "body-parser");
    }

    #[tokio::test]
    async fn test_parse_package_lock_with_git() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "my-git-dep": "github:user/repo#abc123"
      }
    },
    "node_modules/my-git-dep": {
      "version": "0.1.0",
      "resolved": "git+https://github.com/user/repo.git#abc123"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        let pkg = resolved.get("my-git-dep").unwrap();
        assert_eq!(pkg.version, "0.1.0");

        match &pkg.source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_parse_package_lock_with_local() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "my-local": "file:../my-local"
      }
    },
    "node_modules/my-local": {
      "version": "1.0.0",
      "link": true
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        let pkg = resolved.get("my-local").unwrap();

        match &pkg.source {
            ResolvedSource::Path { .. } => {}
            _ => panic!("Expected Path source for local package"),
        }
    }

    #[tokio::test]
    async fn test_parse_empty_package_lock() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "empty-project"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 0);
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_parse_malformed_package_lock() {
        let lockfile_content = "not valid json {{{";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_locate_lockfile_same_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        let lock_path = temp_dir.path().join("package-lock.json");

        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();
        std::fs::write(&lock_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_workspace_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_lock = temp_dir.path().join("package-lock.json");
        let member_dir = temp_dir.path().join("packages").join("member");
        std::fs::create_dir_all(&member_dir).unwrap();
        let member_manifest = member_dir.join("package.json");

        std::fs::write(&workspace_lock, r#"{"lockfileVersion": 3}"#).unwrap();
        std::fs::write(&member_manifest, r#"{"name": "member"}"#).unwrap();

        let manifest_uri = Url::from_file_path(&member_manifest).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), workspace_lock);
    }

    #[test]
    fn test_locate_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_none());
    }

    #[test]
    fn test_is_lockfile_stale_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let mtime = std::fs::metadata(&lockfile_path)
            .unwrap()
            .modified()
            .unwrap();
        let parser = NpmLockParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, mtime),
            "Lock file should not be stale when mtime matches"
        );
    }

    #[test]
    fn test_is_lockfile_stale_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let old_time = std::time::UNIX_EPOCH;
        let parser = NpmLockParser;

        assert!(
            parser.is_lockfile_stale(&lockfile_path, old_time),
            "Lock file should be stale when last_modified is old"
        );
    }

    #[test]
    fn test_is_lockfile_stale_deleted() {
        let parser = NpmLockParser;
        let non_existent = std::path::Path::new("/nonexistent/package-lock.json");

        assert!(
            parser.is_lockfile_stale(non_existent, std::time::SystemTime::now()),
            "Non-existent lock file should be considered stale"
        );
    }

    #[test]
    fn test_is_lockfile_stale_future_time() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        // Use a time far in the future
        let future_time = std::time::SystemTime::now() + std::time::Duration::from_secs(86400); // +1 day
        let parser = NpmLockParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, future_time),
            "Lock file should not be stale when last_modified is in the future"
        );
    }
}
