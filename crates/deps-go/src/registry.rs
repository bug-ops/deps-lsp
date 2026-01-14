//! proxy.golang.org registry client.
//!
//! Provides access to Go module proxy via:
//! - `/{module}/@v/list` - list all versions
//! - `/{module}/@v/{version}.info` - version metadata
//! - `/{module}/@v/{version}.mod` - go.mod file
//! - `/{module}/@latest` - latest version info
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.
//!
//! # Examples
//!
//! ```no_run
//! use deps_go::GoRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let registry = GoRegistry::new(cache);
//!
//!     let versions = registry.get_versions("github.com/gin-gonic/gin").await.unwrap();
//!     println!("Latest gin: {}", versions[0].version);
//! }
//! ```

use crate::error::{GoError, Result};
use crate::types::GoVersion;
use crate::version::{escape_module_path, is_pseudo_version};
use deps_core::HttpCache;
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PROXY_BASE: &str = "https://proxy.golang.org";

/// Base URL for Go package documentation
pub const PKG_GO_DEV_URL: &str = "https://pkg.go.dev";

/// Maximum allowed module path length to prevent DoS
const MAX_MODULE_PATH_LENGTH: usize = 500;

/// Maximum allowed version string length
const MAX_VERSION_LENGTH: usize = 128;

/// Validates a module path for length and basic format.
///
/// # Errors
///
/// Returns error if:
/// - Path is empty
/// - Path exceeds MAX_MODULE_PATH_LENGTH
fn validate_module_path(module_path: &str) -> Result<()> {
    if module_path.is_empty() {
        return Err(GoError::InvalidModulePath("module path is empty".into()));
    }

    if module_path.len() > MAX_MODULE_PATH_LENGTH {
        return Err(GoError::InvalidModulePath(format!(
            "module path exceeds maximum length of {MAX_MODULE_PATH_LENGTH} characters"
        )));
    }

    Ok(())
}

/// Validates a version string for length and basic format.
///
/// # Errors
///
/// Returns error if:
/// - Version is empty
/// - Version exceeds MAX_VERSION_LENGTH
/// - Version contains path traversal sequences
fn validate_version_string(version: &str) -> Result<()> {
    if version.is_empty() {
        return Err(GoError::InvalidVersionSpecifier {
            specifier: version.to_string(),
            message: "version string is empty".into(),
        });
    }

    if version.len() > MAX_VERSION_LENGTH {
        return Err(GoError::InvalidVersionSpecifier {
            specifier: version.to_string(),
            message: format!(
                "version string exceeds maximum length of {MAX_VERSION_LENGTH} characters"
            ),
        });
    }

    // Check for path traversal attempts
    if version.contains("..") || version.contains('/') || version.contains('\\') {
        return Err(GoError::InvalidVersionSpecifier {
            specifier: version.to_string(),
            message: "version string contains invalid characters".into(),
        });
    }

    Ok(())
}

/// Returns the URL for a module's documentation page on pkg.go.dev.
pub fn package_url(module_path: &str) -> String {
    format!("{PKG_GO_DEV_URL}/{module_path}")
}

/// Client for interacting with proxy.golang.org.
///
/// Uses the Go module proxy protocol for version lookups and metadata.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct GoRegistry {
    cache: Arc<HttpCache>,
}

impl GoRegistry {
    /// Creates a new Go registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a module from the `/@v/list` endpoint.
    ///
    /// Returns versions in registry order (not sorted). Includes pseudo-versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - Module does not exist (404)
    /// - Module path is invalid or too long
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("github.com/gin-gonic/gin").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, module_path: &str) -> Result<Vec<GoVersion>> {
        validate_module_path(module_path)?;

        let escaped = escape_module_path(module_path);
        let url = format!("{PROXY_BASE}/{escaped}/@v/list");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| GoError::RegistryError {
                module: module_path.to_string(),
                source: Box::new(e),
            })?;

        parse_version_list(&data)
    }

    /// Fetches version metadata from the `/@v/{version}.info` endpoint.
    ///
    /// Returns version with timestamp information.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    /// - Module path or version string is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let info = registry.get_version_info("github.com/gin-gonic/gin", "v1.9.1").await.unwrap();
    /// assert_eq!(info.version, "v1.9.1");
    /// # }
    /// ```
    pub async fn get_version_info(&self, module_path: &str, version: &str) -> Result<GoVersion> {
        validate_module_path(module_path)?;
        validate_version_string(version)?;

        let escaped = escape_module_path(module_path);
        let url = format!("{PROXY_BASE}/{escaped}/@v/{version}.info");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| GoError::RegistryError {
                module: module_path.to_string(),
                source: Box::new(e),
            })?;

        parse_version_info(&data)
    }

    /// Fetches latest version using the `/@latest` endpoint.
    ///
    /// Returns the latest stable version (non-pseudo).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    /// - Module path is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let latest = registry.get_latest("github.com/gin-gonic/gin").await.unwrap();
    /// assert!(!latest.is_pseudo);
    /// # }
    /// ```
    pub async fn get_latest(&self, module_path: &str) -> Result<GoVersion> {
        validate_module_path(module_path)?;

        let escaped = escape_module_path(module_path);
        let url = format!("{PROXY_BASE}/{escaped}/@latest");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| GoError::RegistryError {
                module: module_path.to_string(),
                source: Box::new(e),
            })?;

        parse_version_info(&data)
    }

    /// Fetches the go.mod file for a specific version.
    ///
    /// Returns the raw content of the go.mod file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - Module path or version string is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let go_mod = registry.get_go_mod("github.com/gin-gonic/gin", "v1.9.1").await.unwrap();
    /// assert!(go_mod.contains("module github.com/gin-gonic/gin"));
    /// # }
    /// ```
    pub async fn get_go_mod(&self, module_path: &str, version: &str) -> Result<String> {
        validate_module_path(module_path)?;
        validate_version_string(version)?;

        let escaped = escape_module_path(module_path);
        let url = format!("{PROXY_BASE}/{escaped}/@v/{version}.mod");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| GoError::RegistryError {
                module: module_path.to_string(),
                source: Box::new(e),
            })?;

        std::str::from_utf8(&data)
            .map(std::string::ToString::to_string)
            .map_err(|e| GoError::CacheError(format!("Invalid UTF-8 in go.mod: {e}")))
    }
}

/// Version info response from proxy.golang.org.
#[derive(Deserialize)]
struct VersionInfo {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time")]
    time: String,
}

/// Parses newline-separated version list from `/@v/list` endpoint.
///
/// Versions are sorted in descending order (newest first) to ensure
/// `find_latest_stable` returns the correct latest version.
fn parse_version_list(data: &[u8]) -> Result<Vec<GoVersion>> {
    let content = std::str::from_utf8(data).map_err(|e| GoError::InvalidVersionSpecifier {
        specifier: String::new(),
        message: format!("Invalid UTF-8 in version list response: {e}"),
    })?;

    // Parse versions with precomputed sort keys (Schwartzian transform)
    // This avoids repeated regex/semver parsing during sort comparisons
    let mut versions_with_keys: Vec<(GoVersion, Option<semver::Version>)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let is_pseudo = is_pseudo_version(line);
            let sort_key = parse_sort_key(line, is_pseudo);
            let version = GoVersion {
                version: line.to_string(),
                time: None,
                is_pseudo,
                retracted: false,
            };
            (version, sort_key)
        })
        .collect();

    // Sort by precomputed keys (descending - newest first)
    versions_with_keys.sort_by(|a, b| match (&b.1, &a.1) {
        (Some(v1), Some(v2)) => v1.cmp(v2),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => b.0.version.cmp(&a.0.version),
    });

    Ok(versions_with_keys.into_iter().map(|(v, _)| v).collect())
}

/// Parses a version string into a semver::Version for sorting.
/// Uses precomputed is_pseudo flag to avoid regex during sort.
fn parse_sort_key(version: &str, is_pseudo: bool) -> Option<semver::Version> {
    use crate::version::base_version_from_pseudo;

    let clean = version.trim_start_matches('v').replace("+incompatible", "");
    let cmp_str = if is_pseudo {
        base_version_from_pseudo(version).unwrap_or(clean)
    } else {
        clean
    };

    // Parse only the X.Y.Z part, ignoring prerelease suffix
    let base = cmp_str.split('-').next().unwrap_or(&cmp_str);
    semver::Version::parse(base.trim_start_matches('v')).ok()
}

/// Parses JSON version info from `/@v/{version}.info` or `/@latest` endpoint.
fn parse_version_info(data: &[u8]) -> Result<GoVersion> {
    let info: VersionInfo =
        serde_json::from_slice(data).map_err(|e| GoError::ApiResponseError {
            module: String::new(),
            source: e,
        })?;

    let is_pseudo = is_pseudo_version(&info.version);
    Ok(GoVersion {
        version: info.version,
        time: Some(info.time),
        is_pseudo,
        retracted: false,
    })
}

// Implement deps_core::Registry trait for trait object support
#[async_trait::async_trait]
impl deps_core::Registry for GoRegistry {
    async fn get_versions(
        &self,
        name: &str,
    ) -> deps_core::Result<Vec<Box<dyn deps_core::Version>>> {
        let versions = self.get_versions(name).await?;
        Ok(versions
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect())
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        _req: &str,
    ) -> deps_core::Result<Option<Box<dyn deps_core::Version>>> {
        // Try /@latest first (fast path)
        if let Ok(version) = self.get_latest(name).await {
            return Ok(Some(Box::new(version) as Box<dyn deps_core::Version>));
        }
        // Fallback to /@v/list (/@latest is optional per Go proxy spec)
        let versions = self.get_versions(name).await?;
        let latest = versions.into_iter().find(|v| !v.is_pseudo && !v.retracted);
        Ok(latest.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
    }

    async fn search(
        &self,
        _query: &str,
        _limit: usize,
    ) -> deps_core::Result<Vec<Box<dyn deps_core::Metadata>>> {
        // proxy.golang.org doesn't support search
        // Could integrate with pkg.go.dev API in future
        Ok(vec![])
    }

    fn package_url(&self, name: &str) -> String {
        package_url(name)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_list() {
        let data = b"v1.0.0\nv1.0.1\nv1.1.0\nv2.0.0\n";

        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 4);
        // Sorted descending (newest first)
        assert_eq!(versions[0].version, "v2.0.0");
        assert_eq!(versions[1].version, "v1.1.0");
        assert_eq!(versions[2].version, "v1.0.1");
        assert_eq!(versions[3].version, "v1.0.0");
        assert!(!versions[0].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_with_pseudo() {
        let data = b"v1.0.0\nv0.0.0-20191109021931-daa7c04131f5\nv1.1.0\n";

        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 3);
        // Sorted descending: v1.1.0, v1.0.0, v0.0.0-... (pseudo based on v0.0.0)
        assert_eq!(versions[0].version, "v1.1.0");
        assert!(!versions[0].is_pseudo);
        assert_eq!(versions[1].version, "v1.0.0");
        assert!(!versions[1].is_pseudo);
        assert!(versions[2].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_empty() {
        let data = b"";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_version_list_blank_lines() {
        let data = b"\n\n\n";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_version_info() {
        let json = r#"{"Version":"v1.9.1","Time":"2023-07-18T14:30:00Z"}"#;
        let version = parse_version_info(json.as_bytes()).unwrap();
        assert_eq!(version.version, "v1.9.1");
        assert_eq!(version.time, Some("2023-07-18T14:30:00Z".into()));
        assert!(!version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_pseudo() {
        let json =
            r#"{"Version":"v0.0.0-20191109021931-daa7c04131f5","Time":"2019-11-09T02:19:31Z"}"#;
        let version = parse_version_info(json.as_bytes()).unwrap();
        assert_eq!(version.version, "v0.0.0-20191109021931-daa7c04131f5");
        assert!(version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_invalid_json() {
        let json = b"not json";
        let result = parse_version_info(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_package_url() {
        assert_eq!(
            package_url("github.com/gin-gonic/gin"),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );
        assert_eq!(
            package_url("golang.org/x/crypto"),
            "https://pkg.go.dev/golang.org/x/crypto"
        );
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = GoRegistry::new(cache);
    }

    #[tokio::test]
    async fn test_registry_clone() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let _cloned = registry;
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_gin_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions = registry
            .get_versions("github.com/gin-gonic/gin")
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.version.starts_with("v1.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_version_info() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let info = registry
            .get_version_info("github.com/gin-gonic/gin", "v1.9.1")
            .await
            .unwrap();

        assert_eq!(info.version, "v1.9.1");
        assert!(info.time.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_latest() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let latest = registry
            .get_latest("github.com/gin-gonic/gin")
            .await
            .unwrap();

        assert!(latest.version.starts_with('v'));
        assert!(!latest.is_pseudo);
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_go_mod() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let go_mod = registry
            .get_go_mod("github.com/gin-gonic/gin", "v1.9.1")
            .await
            .unwrap();

        assert!(go_mod.contains("module github.com/gin-gonic/gin"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_module_not_found() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let result = registry
            .get_versions("github.com/nonexistent/module12345")
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_list_mixed_stable_and_pseudo() {
        let data = b"v1.0.0\nv1.1.0-0.20200101000000-abcdefabcdef\nv1.2.0\nv1.2.1-beta.1\n";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 4);
        // Sorted descending: v1.2.1-beta.1, v1.2.0, v1.1.0-0...(pseudo), v1.0.0
        assert_eq!(versions[0].version, "v1.2.1-beta.1");
        assert!(!versions[0].is_pseudo); // prerelease, not pseudo
        assert_eq!(versions[1].version, "v1.2.0");
        assert!(!versions[1].is_pseudo);
        assert!(versions[2].is_pseudo); // pseudo-version based on v1.1.0
        assert_eq!(versions[3].version, "v1.0.0");
        assert!(!versions[3].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_invalid_utf8() {
        let data = &[0xFF, 0xFE, 0xFD]; // Invalid UTF-8
        let result = parse_version_list(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_info_missing_fields() {
        let json = r#"{"Version":"v1.0.0"}"#; // Missing Time field
        let result = parse_version_info(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_module_path_empty() {
        let result = validate_module_path("");
        assert!(result.is_err());
        assert!(matches!(result, Err(GoError::InvalidModulePath(_))));
    }

    #[test]
    fn test_validate_module_path_too_long() {
        let long_path = "a".repeat(MAX_MODULE_PATH_LENGTH + 1);
        let result = validate_module_path(&long_path);
        assert!(result.is_err());
        assert!(matches!(result, Err(GoError::InvalidModulePath(_))));
    }

    #[test]
    fn test_validate_module_path_valid() {
        let result = validate_module_path("github.com/user/repo");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_version_string_empty() {
        let result = validate_version_string("");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GoError::InvalidVersionSpecifier { .. })
        ));
    }

    #[test]
    fn test_validate_version_string_too_long() {
        let long_version = "v".to_string() + &"1".repeat(MAX_VERSION_LENGTH);
        let result = validate_version_string(&long_version);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GoError::InvalidVersionSpecifier { .. })
        ));
    }

    #[test]
    fn test_validate_version_string_path_traversal() {
        let result = validate_version_string("v1.0.0/../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(GoError::InvalidVersionSpecifier { .. })
        ));
    }

    #[test]
    fn test_validate_version_string_slashes() {
        let result = validate_version_string("v1.0.0/malicious");
        assert!(result.is_err());

        let result = validate_version_string("v1.0.0\\malicious");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_version_string_valid() {
        let result = validate_version_string("v1.0.0");
        assert!(result.is_ok());

        let result = validate_version_string("v0.0.0-20191109021931-daa7c04131f5");
        assert!(result.is_ok());
    }
}
