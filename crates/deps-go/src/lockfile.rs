//! go.sum lock file parsing.
//!
//! Parses go.sum files to extract resolved dependency versions.
//! go.sum contains checksums for all modules used in a build, including
//! transitive dependencies and multiple versions.
//!
//! # go.sum Format
//!
//! Each line in go.sum has the format:
//! ```text
//! module_path version hash
//! ```
//!
//! Example:
//! ```text
//! github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
//! github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL9t9/HBtKc7e/Q7Nb2nqKqTW8mHZy6E7k8m4dLvs=
//! golang.org/x/sync v0.5.0 h1:60k92dhOjHxJkrq...
//! golang.org/x/sync v0.5.0/go.mod h1:RxMgew5V...
//! ```
//!
//! # Line Types
//!
//! - Lines ending with `/go.mod` are module file checksums (skipped for version resolution)
//! - Lines with `h1:hash` are actual module content checksums (used for version resolution)
//! - A module may appear multiple times with different versions

use async_trait::async_trait;
use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;

/// go.sum file parser.
///
/// Implements lock file parsing for Go modules.
/// Supports both project-level and workspace-level go.sum files.
///
/// # Lock File Location
///
/// The parser searches for go.sum in the following order:
/// 1. Same directory as go.mod
/// 2. Parent directories (up to 5 levels) for workspace root
///
/// # Examples
///
/// ```no_run
/// use deps_go::lockfile::GoSumParser;
/// use deps_core::lockfile::LockFileProvider;
/// use tower_lsp_server::ls_types::Uri;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let parser = GoSumParser;
/// let manifest_uri = Uri::from_file_path("/path/to/go.mod").unwrap();
///
/// if let Some(lockfile_path) = parser.locate_lockfile(&manifest_uri) {
///     let resolved = parser.parse_lockfile(&lockfile_path).await?;
///     println!("Found {} resolved packages", resolved.len());
/// }
/// # Ok(())
/// # }
/// ```
pub struct GoSumParser;

impl GoSumParser {
    /// Lock file names for Go ecosystem.
    const LOCKFILE_NAMES: &'static [&'static str] = &["go.sum"];
}

#[async_trait]
impl LockFileProvider for GoSumParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    async fn parse_lockfile(&self, lockfile_path: &Path) -> Result<ResolvedPackages> {
        tracing::debug!("Parsing go.sum: {}", lockfile_path.display());

        let content = tokio::fs::read_to_string(lockfile_path)
            .await
            .map_err(|e| DepsError::ParseError {
                file_type: format!("go.sum at {}", lockfile_path.display()),
                source: Box::new(e),
            })?;

        let packages = parse_go_sum(&content);

        tracing::info!(
            "Parsed go.sum: {} packages from {}",
            packages.len(),
            lockfile_path.display()
        );

        Ok(packages)
    }
}

/// Parses go.sum content and returns resolved packages.
///
/// Filters out `/go.mod` entries (module file checksums) and only processes
/// module content checksums (lines with `h1:` hashes).
///
/// When a module appears multiple times with different versions, the first
/// occurrence is used. This typically represents the version selected by
/// Go's minimal version selection algorithm.
///
/// # Arguments
///
/// * `content` - The go.sum file content
///
/// # Returns
///
/// A collection of resolved packages with their versions
///
/// # Examples
///
/// ```
/// use deps_go::lockfile::parse_go_sum;
///
/// let content = r#"
/// github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
/// github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL9t9/HBtKc7e/Q7Nb2nqKqTW8mHZy6E7k8m4dLvs=
/// "#;
///
/// let packages = parse_go_sum(content);
/// assert_eq!(packages.get_version("github.com/gin-gonic/gin"), Some("v1.9.1"));
/// ```
pub fn parse_go_sum(content: &str) -> ResolvedPackages {
    let mut packages = ResolvedPackages::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip /go.mod entries (we only want the h1: hash entries)
        if line.contains("/go.mod ") {
            continue;
        }

        // Parse: module_path version h1:hash
        // Valid go.sum lines must have at least 3 parts (module, version, hash)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let module_path = parts[0];
            let version = parts[1];
            let checksum = parts[2];

            // Validate that the hash starts with 'h1:' (standard Go checksum format)
            // This filters out malformed lines
            if !checksum.starts_with("h1:") {
                continue;
            }

            // Only insert if not already present (first occurrence wins)
            // This handles cases where multiple versions exist
            if packages.get(module_path).is_none() {
                packages.insert(ResolvedPackage {
                    name: module_path.to_string(),
                    version: version.to_string(),
                    source: ResolvedSource::Registry {
                        url: "https://proxy.golang.org".to_string(),
                        checksum: checksum.to_string(),
                    },
                    dependencies: vec![],
                });
            }
        }
    }

    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_go_sum() {
        let content = r#"
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL9t9/HBtKc7e/Q7Nb2nqKqTW8mHZy6E7k8m4dLvs=
"#;
        let packages = parse_go_sum(content);
        assert_eq!(
            packages.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
    }

    #[test]
    fn test_parse_multiple_modules() {
        let content = r#"
github.com/gin-gonic/gin v1.9.1 h1:hash1=
golang.org/x/sync v0.5.0 h1:hash2=
github.com/stretchr/testify v1.8.4 h1:hash3=
"#;
        let packages = parse_go_sum(content);
        assert_eq!(packages.len(), 3);
        assert_eq!(
            packages.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
        assert_eq!(packages.get_version("golang.org/x/sync"), Some("v0.5.0"));
        assert_eq!(
            packages.get_version("github.com/stretchr/testify"),
            Some("v1.8.4")
        );
    }

    #[test]
    fn test_skip_go_mod_entries() {
        let content = r#"
github.com/gin-gonic/gin v1.9.1/go.mod h1:mod_hash=
github.com/gin-gonic/gin v1.9.1 h1:actual_hash=
"#;
        let packages = parse_go_sum(content);
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
    }

    #[test]
    fn test_first_version_wins() {
        let content = r#"
github.com/pkg/errors v0.9.1 h1:hash1=
github.com/pkg/errors v0.8.0 h1:hash2=
"#;
        let packages = parse_go_sum(content);
        assert_eq!(packages.len(), 1);
        // First occurrence should win
        assert_eq!(
            packages.get_version("github.com/pkg/errors"),
            Some("v0.9.1")
        );
    }

    #[test]
    fn test_empty_content() {
        let packages = parse_go_sum("");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_whitespace_handling() {
        let content = "  github.com/gin-gonic/gin   v1.9.1   h1:hash=  \n";
        let packages = parse_go_sum(content);
        assert_eq!(
            packages.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
    }

    #[test]
    fn test_lockfile_provider_trait() {
        let parser = GoSumParser;
        let manifest_path = "/test/go.mod";
        let uri = Uri::from_file_path(manifest_path).unwrap();

        // Just verify the trait methods are callable
        let _ = parser.locate_lockfile(&uri);
    }

    #[test]
    fn test_pseudo_version() {
        let content = "golang.org/x/tools v0.0.0-20191109021931-daa7c04131f5 h1:hash=\n";
        let packages = parse_go_sum(content);
        assert_eq!(
            packages.get_version("golang.org/x/tools"),
            Some("v0.0.0-20191109021931-daa7c04131f5")
        );
    }

    #[test]
    fn test_incompatible_version() {
        let content = "github.com/some/module v2.0.0+incompatible h1:hash=\n";
        let packages = parse_go_sum(content);
        assert_eq!(
            packages.get_version("github.com/some/module"),
            Some("v2.0.0+incompatible")
        );
    }

    #[test]
    fn test_malformed_line_ignored() {
        let content = r#"
github.com/gin-gonic/gin v1.9.1 h1:hash=
invalid line with only one part
github.com/valid/pkg v1.0.0 h1:valid_hash=
"#;
        let packages = parse_go_sum(content);
        // Should only parse the valid lines
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
        assert_eq!(packages.get_version("github.com/valid/pkg"), Some("v1.0.0"));
    }

    #[tokio::test]
    async fn test_parse_lockfile_simple() {
        let lockfile_content = r#"
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL9t9/HBtKc7e/Q7Nb2nqKqTW8mHZy6E7k8m4dLvs=
golang.org/x/sync v0.5.0 h1:60k92dhOjHxJkrq=
golang.org/x/sync v0.5.0/go.mod h1:RxMgew5V=
"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("go.sum");
        std::fs::write(&lockfile_path, lockfile_content).unwrap();

        let parser = GoSumParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(
            resolved.get_version("github.com/gin-gonic/gin"),
            Some("v1.9.1")
        );
        assert_eq!(resolved.get_version("golang.org/x/sync"), Some("v0.5.0"));
    }

    #[tokio::test]
    async fn test_parse_lockfile_empty() {
        let lockfile_content = "";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("go.sum");
        std::fs::write(&lockfile_path, lockfile_content).unwrap();

        let parser = GoSumParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 0);
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_parse_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("nonexistent.sum");

        let parser = GoSumParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_locate_lockfile_same_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("go.mod");
        let lock_path = temp_dir.path().join("go.sum");

        std::fs::write(&manifest_path, "module test").unwrap();
        std::fs::write(&lock_path, "").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = GoSumParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_workspace_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_lock = temp_dir.path().join("go.sum");
        let member_dir = temp_dir.path().join("packages").join("member");
        std::fs::create_dir_all(&member_dir).unwrap();
        let member_manifest = member_dir.join("go.mod");

        std::fs::write(&workspace_lock, "").unwrap();
        std::fs::write(&member_manifest, "module member").unwrap();

        let manifest_uri = Uri::from_file_path(&member_manifest).unwrap();
        let parser = GoSumParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), workspace_lock);
    }

    #[test]
    fn test_locate_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("go.mod");
        std::fs::write(&manifest_path, "module test").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = GoSumParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_none());
    }

    #[test]
    fn test_is_lockfile_stale_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("go.sum");
        std::fs::write(&lockfile_path, "").unwrap();

        let mtime = std::fs::metadata(&lockfile_path)
            .unwrap()
            .modified()
            .unwrap();
        let parser = GoSumParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, mtime),
            "Lock file should not be stale when mtime matches"
        );
    }

    #[test]
    fn test_is_lockfile_stale_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("go.sum");
        std::fs::write(&lockfile_path, "").unwrap();

        let old_time = std::time::UNIX_EPOCH;
        let parser = GoSumParser;

        assert!(
            parser.is_lockfile_stale(&lockfile_path, old_time),
            "Lock file should be stale when last_modified is old"
        );
    }

    #[test]
    fn test_is_lockfile_stale_deleted() {
        let parser = GoSumParser;
        let non_existent = std::path::Path::new("/nonexistent/go.sum");

        assert!(
            parser.is_lockfile_stale(non_existent, std::time::SystemTime::now()),
            "Non-existent lock file should be considered stale"
        );
    }

    #[test]
    fn test_is_lockfile_stale_future_time() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("go.sum");
        std::fs::write(&lockfile_path, "").unwrap();

        // Use a time far in the future
        let future_time = std::time::SystemTime::now() + std::time::Duration::from_secs(86400); // +1 day
        let parser = GoSumParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, future_time),
            "Lock file should not be stale when last_modified is in the future"
        );
    }

    #[test]
    fn test_parse_go_sum_with_checksum() {
        let content =
            "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n";
        let packages = parse_go_sum(content);

        let pkg = packages.get("github.com/gin-gonic/gin").unwrap();
        assert_eq!(pkg.version, "v1.9.1");

        match &pkg.source {
            ResolvedSource::Registry { url, checksum } => {
                assert_eq!(url, "https://proxy.golang.org");
                assert_eq!(checksum, "h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=");
            }
            _ => panic!("Expected Registry source"),
        }
    }

    #[test]
    fn test_parse_go_sum_dependencies_empty() {
        let content = "github.com/gin-gonic/gin v1.9.1 h1:hash=\n";
        let packages = parse_go_sum(content);

        let pkg = packages.get("github.com/gin-gonic/gin").unwrap();
        assert!(pkg.dependencies.is_empty());
    }
}
