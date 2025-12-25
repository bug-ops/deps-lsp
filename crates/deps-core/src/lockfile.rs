//! Lock file parsing abstractions.
//!
//! Provides generic types and traits for parsing lock files across different
//! package ecosystems (Cargo.lock, package-lock.json, poetry.lock, etc.).
//!
//! Lock files contain resolved dependency versions, allowing instant display
//! without network requests to registries.

use crate::error::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};
use tower_lsp_server::ls_types::Uri;

/// Maximum depth to search for workspace root lock file.
const MAX_WORKSPACE_DEPTH: usize = 5;

/// Generic lock file locator.
///
/// Searches for lock files in the following order:
/// 1. Same directory as the manifest
/// 2. Parent directories (up to MAX_WORKSPACE_DEPTH levels) for workspace root
///
/// This function is ecosystem-agnostic and works with any lock file name.
///
/// # Arguments
///
/// * `manifest_uri` - URI of the manifest file
/// * `lockfile_names` - List of possible lock file names to search for
///
/// # Returns
///
/// Path to the first found lock file, or None if not found.
///
/// # Examples
///
/// ```no_run
/// use deps_core::lockfile::locate_lockfile_for_manifest;
/// use tower_lsp_server::ls_types::Uri;
///
/// let manifest_uri = Uri::from_file_path("/path/to/Cargo.toml").unwrap();
/// let lockfile_names = &["Cargo.lock"];
///
/// if let Some(path) = locate_lockfile_for_manifest(&manifest_uri, lockfile_names) {
///     println!("Found lock file at: {}", path.display());
/// }
/// ```
pub fn locate_lockfile_for_manifest(
    manifest_uri: &Uri,
    lockfile_names: &[&str],
) -> Option<PathBuf> {
    let manifest_path = manifest_uri.to_file_path()?;
    let manifest_dir = manifest_path.parent()?;

    // Reuse single PathBuf to avoid allocations in loops
    let mut lock_path = manifest_dir.to_path_buf();

    // Try same directory as manifest
    for &name in lockfile_names {
        lock_path.push(name);
        if lock_path.exists() {
            tracing::debug!("Found {} at: {}", name, lock_path.display());
            return Some(lock_path);
        }
        lock_path.pop();
    }

    // Search up the directory tree for workspace root
    let Some(mut current_dir) = manifest_dir.parent() else {
        tracing::debug!("No lock file found for: {:?}", manifest_uri);
        return None;
    };

    for depth in 0..MAX_WORKSPACE_DEPTH {
        lock_path.clear();
        lock_path.push(current_dir);

        for &name in lockfile_names {
            lock_path.push(name);
            if lock_path.exists() {
                tracing::debug!(
                    "Found workspace {} at depth {}: {}",
                    name,
                    depth + 1,
                    lock_path.display()
                );
                return Some(lock_path);
            }
            lock_path.pop();
        }

        match current_dir.parent() {
            Some(parent) => current_dir = parent,
            None => break,
        }
    }

    tracing::debug!("No lock file found for: {:?}", manifest_uri);
    None
}

/// Resolved package information from a lock file.
///
/// Contains the exact version and source information for a dependency
/// as resolved by the package manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    /// Package name
    pub name: String,
    /// Resolved version (exact version from lock file)
    pub version: String,
    /// Source information (registry URL, git commit, path)
    pub source: ResolvedSource,
    /// Dependencies of this package (for dependency tree analysis)
    pub dependencies: Vec<String>,
}

/// Source of a resolved dependency.
///
/// Indicates where the package was downloaded from or how it was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSource {
    /// From a registry with optional checksum
    Registry {
        /// Registry URL
        url: String,
        /// Checksum/integrity hash
        checksum: String,
    },
    /// From git with commit hash
    Git {
        /// Git repository URL
        url: String,
        /// Commit SHA or tag
        rev: String,
    },
    /// From local file system
    Path {
        /// Relative or absolute path
        path: String,
    },
}

/// Collection of resolved packages from a lock file.
///
/// Provides efficient lookup of resolved versions by package name.
///
/// # Examples
///
/// ```
/// use deps_core::lockfile::{ResolvedPackages, ResolvedPackage, ResolvedSource};
///
/// let mut packages = ResolvedPackages::new();
/// packages.insert(ResolvedPackage {
///     name: "serde".into(),
///     version: "1.0.195".into(),
///     source: ResolvedSource::Registry {
///         url: "https://github.com/rust-lang/crates.io-index".into(),
///         checksum: "abc123".into(),
///     },
///     dependencies: vec!["serde_derive".into()],
/// });
///
/// assert_eq!(packages.get_version("serde"), Some("1.0.195"));
/// assert_eq!(packages.len(), 1);
/// ```
#[derive(Debug, Default, Clone)]
pub struct ResolvedPackages {
    /// Map from package name to resolved package info
    packages: HashMap<String, ResolvedPackage>,
}

impl ResolvedPackages {
    /// Creates a new empty collection.
    pub fn new() -> Self {
        Self {
            packages: HashMap::new(),
        }
    }

    /// Inserts a resolved package.
    ///
    /// If a package with the same name already exists, it is replaced.
    pub fn insert(&mut self, package: ResolvedPackage) {
        self.packages.insert(package.name.clone(), package);
    }

    /// Gets a resolved package by name.
    ///
    /// Returns `None` if the package is not in the lock file.
    pub fn get(&self, name: &str) -> Option<&ResolvedPackage> {
        self.packages.get(name)
    }

    /// Gets the resolved version string for a package.
    ///
    /// Returns `None` if the package is not in the lock file.
    ///
    /// This is a convenience method equivalent to `get(name).map(|p| p.version.as_str())`.
    pub fn get_version(&self, name: &str) -> Option<&str> {
        self.packages.get(name).map(|p| p.version.as_str())
    }

    /// Returns the number of resolved packages.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Returns true if there are no resolved packages.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Returns an iterator over package names and their resolved info.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ResolvedPackage)> {
        self.packages.iter()
    }

    /// Converts into a HashMap for easier integration.
    pub fn into_map(self) -> HashMap<String, ResolvedPackage> {
        self.packages
    }
}

/// Lock file provider trait for ecosystem-specific implementations.
///
/// Implementations parse lock files for a specific package ecosystem
/// (Cargo.lock, package-lock.json, etc.) and extract resolved versions.
///
/// # Examples
///
/// ```no_run
/// use deps_core::lockfile::{LockFileProvider, ResolvedPackages};
/// use async_trait::async_trait;
/// use std::path::{Path, PathBuf};
/// use tower_lsp_server::ls_types::Uri;
///
/// struct MyLockParser;
///
/// #[async_trait]
/// impl LockFileProvider for MyLockParser {
///     fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
///         let manifest_path = manifest_uri.to_file_path()?;
///         let lock_path = manifest_path.with_file_name("my.lock");
///         lock_path.exists().then_some(lock_path)
///     }
///
///     async fn parse_lockfile(&self, lockfile_path: &Path) -> deps_core::error::Result<ResolvedPackages> {
///         // Parse lock file format and extract packages
///         Ok(ResolvedPackages::new())
///     }
/// }
/// ```
#[async_trait]
pub trait LockFileProvider: Send + Sync {
    /// Locates the lock file for a given manifest URI.
    ///
    /// Returns `None` if:
    /// - Lock file doesn't exist
    /// - Manifest path cannot be determined from URI
    /// - Workspace root search fails
    ///
    /// # Arguments
    ///
    /// * `manifest_uri` - URI of the manifest file (Cargo.toml, package.json, etc.)
    ///
    /// # Returns
    ///
    /// Path to lock file if found
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf>;

    /// Parses a lock file and extracts resolved packages.
    ///
    /// # Arguments
    ///
    /// * `lockfile_path` - Path to the lock file
    ///
    /// # Returns
    ///
    /// ResolvedPackages on success, error if parse fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be read
    /// - File format is invalid
    /// - Required fields are missing
    async fn parse_lockfile(&self, lockfile_path: &Path) -> Result<ResolvedPackages>;

    /// Checks if lock file has been modified since last parse.
    ///
    /// Used for cache invalidation. Default implementation compares
    /// file modification time.
    ///
    /// # Arguments
    ///
    /// * `lockfile_path` - Path to the lock file
    /// * `last_modified` - Last known modification time
    ///
    /// # Returns
    ///
    /// `true` if file has been modified or cannot be stat'd, `false` otherwise
    fn is_lockfile_stale(&self, lockfile_path: &Path, last_modified: SystemTime) -> bool {
        if let Ok(metadata) = std::fs::metadata(lockfile_path)
            && let Ok(mtime) = metadata.modified()
        {
            return mtime > last_modified;
        }
        true
    }
}

/// Cached lock file entry with staleness detection.
struct CachedLockFile {
    packages: ResolvedPackages,
    modified_at: SystemTime,
    #[allow(dead_code)]
    parsed_at: Instant,
}

/// Cache for parsed lock files with automatic staleness detection.
///
/// Caches parsed lock file contents and checks file modification time
/// to avoid re-parsing unchanged files. Thread-safe for concurrent access.
///
/// # Examples
///
/// ```no_run
/// use deps_core::lockfile::LockFileCache;
/// use std::path::Path;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let cache = LockFileCache::new();
/// // First call parses the file
/// // Second call returns cached result if file hasn't changed
/// # Ok(())
/// # }
/// ```
pub struct LockFileCache {
    entries: DashMap<PathBuf, CachedLockFile>,
}

impl LockFileCache {
    /// Creates a new empty lock file cache.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Gets parsed packages from cache or parses the lock file.
    ///
    /// Checks file modification time to detect changes. If the file
    /// has been modified since last parse, re-parses it. Otherwise,
    /// returns the cached result.
    ///
    /// # Arguments
    ///
    /// * `provider` - Lock file provider implementation
    /// * `lockfile_path` - Path to the lock file
    ///
    /// # Returns
    ///
    /// Resolved packages on success
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed
    pub async fn get_or_parse(
        &self,
        provider: &dyn LockFileProvider,
        lockfile_path: &Path,
    ) -> Result<ResolvedPackages> {
        // Check cache first
        if let Some(cached) = self.entries.get(lockfile_path)
            && let Ok(metadata) = tokio::fs::metadata(lockfile_path).await
            && let Ok(mtime) = metadata.modified()
            && mtime <= cached.modified_at
        {
            tracing::debug!("Lock file cache hit: {}", lockfile_path.display());
            return Ok(cached.packages.clone());
        }

        // Cache miss - parse and store
        tracing::debug!("Lock file cache miss: {}", lockfile_path.display());
        let packages = provider.parse_lockfile(lockfile_path).await?;

        let metadata = tokio::fs::metadata(lockfile_path).await?;
        let modified_at = metadata.modified()?;

        self.entries.insert(
            lockfile_path.to_path_buf(),
            CachedLockFile {
                packages: packages.clone(),
                modified_at,
                parsed_at: Instant::now(),
            },
        );

        Ok(packages)
    }

    /// Invalidates cached entry for a lock file.
    ///
    /// Forces next access to re-parse the file. Use when you know
    /// the file has changed but modification time might not reflect it.
    pub fn invalidate(&self, lockfile_path: &Path) {
        self.entries.remove(lockfile_path);
    }

    /// Returns the number of cached lock files.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for LockFileCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_packages_new() {
        let packages = ResolvedPackages::new();
        assert!(packages.is_empty());
        assert_eq!(packages.len(), 0);
    }

    #[test]
    fn test_resolved_packages_insert_and_get() {
        let mut packages = ResolvedPackages::new();

        let pkg = ResolvedPackage {
            name: "serde".into(),
            version: "1.0.195".into(),
            source: ResolvedSource::Registry {
                url: "https://github.com/rust-lang/crates.io-index".into(),
                checksum: "abc123".into(),
            },
            dependencies: vec!["serde_derive".into()],
        };

        packages.insert(pkg);

        assert_eq!(packages.len(), 1);
        assert!(!packages.is_empty());
        assert_eq!(packages.get_version("serde"), Some("1.0.195"));

        let retrieved = packages.get("serde");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "serde");
        assert_eq!(retrieved.unwrap().dependencies.len(), 1);
    }

    #[test]
    fn test_resolved_packages_get_nonexistent() {
        let packages = ResolvedPackages::new();
        assert_eq!(packages.get("nonexistent"), None);
        assert_eq!(packages.get_version("nonexistent"), None);
    }

    #[test]
    fn test_resolved_packages_replace() {
        let mut packages = ResolvedPackages::new();

        packages.insert(ResolvedPackage {
            name: "serde".into(),
            version: "1.0.0".into(),
            source: ResolvedSource::Registry {
                url: "test".into(),
                checksum: "old".into(),
            },
            dependencies: vec![],
        });

        packages.insert(ResolvedPackage {
            name: "serde".into(),
            version: "1.0.195".into(),
            source: ResolvedSource::Registry {
                url: "test".into(),
                checksum: "new".into(),
            },
            dependencies: vec![],
        });

        assert_eq!(packages.len(), 1);
        assert_eq!(packages.get_version("serde"), Some("1.0.195"));
    }

    #[test]
    fn test_resolved_source_equality() {
        let source1 = ResolvedSource::Registry {
            url: "https://test.com".into(),
            checksum: "abc".into(),
        };
        let source2 = ResolvedSource::Registry {
            url: "https://test.com".into(),
            checksum: "abc".into(),
        };
        let source3 = ResolvedSource::Git {
            url: "https://github.com/test".into(),
            rev: "abc123".into(),
        };

        assert_eq!(source1, source2);
        assert_ne!(source1, source3);
    }

    #[test]
    fn test_resolved_packages_iter() {
        let mut packages = ResolvedPackages::new();

        packages.insert(ResolvedPackage {
            name: "serde".into(),
            version: "1.0.0".into(),
            source: ResolvedSource::Registry {
                url: "test".into(),
                checksum: "a".into(),
            },
            dependencies: vec![],
        });

        packages.insert(ResolvedPackage {
            name: "tokio".into(),
            version: "1.0.0".into(),
            source: ResolvedSource::Registry {
                url: "test".into(),
                checksum: "b".into(),
            },
            dependencies: vec![],
        });

        let count = packages.iter().count();
        assert_eq!(count, 2);

        let names: Vec<_> = packages.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"tokio"));
    }

    #[test]
    fn test_resolved_packages_into_map() {
        let mut packages = ResolvedPackages::new();

        packages.insert(ResolvedPackage {
            name: "serde".into(),
            version: "1.0.0".into(),
            source: ResolvedSource::Registry {
                url: "test".into(),
                checksum: "a".into(),
            },
            dependencies: vec![],
        });

        let map = packages.into_map();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("serde"));
    }

    #[test]
    fn test_lockfile_cache_new() {
        let cache = LockFileCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_lockfile_cache_invalidate() {
        let cache = LockFileCache::new();
        let test_path = PathBuf::from("/test/Cargo.lock");

        cache.entries.insert(
            test_path.clone(),
            CachedLockFile {
                packages: ResolvedPackages::new(),
                modified_at: SystemTime::now(),
                parsed_at: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 1);

        cache.invalidate(&test_path);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_locate_lockfile_for_manifest_same_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Cargo.toml");
        let lock_path = temp_dir.path().join("Cargo.lock");

        std::fs::write(&manifest_path, "[package]\nname = \"test\"").unwrap();
        std::fs::write(&lock_path, "version = 4").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let located = locate_lockfile_for_manifest(&manifest_uri, &["Cargo.lock"]);

        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_for_manifest_workspace_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_lock = temp_dir.path().join("Cargo.lock");
        let member_dir = temp_dir.path().join("crates").join("member");
        std::fs::create_dir_all(&member_dir).unwrap();
        let member_manifest = member_dir.join("Cargo.toml");

        std::fs::write(&workspace_lock, "version = 4").unwrap();
        std::fs::write(&member_manifest, "[package]\nname = \"member\"").unwrap();

        let manifest_uri = Uri::from_file_path(&member_manifest).unwrap();
        let located = locate_lockfile_for_manifest(&manifest_uri, &["Cargo.lock"]);

        assert!(located.is_some());
        assert_eq!(located.unwrap(), workspace_lock);
    }

    #[test]
    fn test_locate_lockfile_for_manifest_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Cargo.toml");
        std::fs::write(&manifest_path, "[package]\nname = \"test\"").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let located = locate_lockfile_for_manifest(&manifest_uri, &["Cargo.lock"]);

        assert!(located.is_none());
    }

    #[test]
    fn test_locate_lockfile_for_manifest_multiple_names() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("pyproject.toml");
        let uv_lock = temp_dir.path().join("uv.lock");

        std::fs::write(&manifest_path, "[project]\nname = \"test\"").unwrap();
        std::fs::write(&uv_lock, "version = 1").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        // poetry.lock doesn't exist, but uv.lock does - should find uv.lock
        let located = locate_lockfile_for_manifest(&manifest_uri, &["poetry.lock", "uv.lock"]);

        assert!(located.is_some());
        assert_eq!(located.unwrap(), uv_lock);
    }

    #[test]
    fn test_locate_lockfile_for_manifest_first_match_wins() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("pyproject.toml");
        let poetry_lock = temp_dir.path().join("poetry.lock");
        let uv_lock = temp_dir.path().join("uv.lock");

        std::fs::write(&manifest_path, "[project]\nname = \"test\"").unwrap();
        std::fs::write(&poetry_lock, "# poetry lock").unwrap();
        std::fs::write(&uv_lock, "version = 1").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        // Both exist, poetry.lock should be found first (listed first)
        let located = locate_lockfile_for_manifest(&manifest_uri, &["poetry.lock", "uv.lock"]);

        assert!(located.is_some());
        assert_eq!(located.unwrap(), poetry_lock);
    }
}
