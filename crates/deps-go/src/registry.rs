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

use crate::error::GoError;
use crate::types::GoVersion;
use crate::version::{escape_module_path, escape_version, is_pseudo_version};
use deps_core::{DepsError, HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PROXY_BASE: &str = "https://proxy.golang.org";

/// Display name for the Go module proxy used in not-found and API-response
/// error messages.
pub const REGISTRY: &str = "Go proxy";

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
fn validate_module_path(module_path: &str) -> crate::error::Result<()> {
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
fn validate_version_string(version: &str) -> crate::error::Result<()> {
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
///
/// Each `/`-separated path segment is percent-encoded individually via
/// `urlencoding::encode` (the same helper every other ecosystem uses), so `/` survives
/// as the legitimate path separator in Go module paths (e.g.
/// `github.com/gin-gonic/gin`) while every other character — including `%`, which a
/// hand-rolled denylist would otherwise miss — is escaped.
pub fn package_url(module_path: &str) -> String {
    let encoded = module_path
        .split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("{PKG_GO_DEV_URL}/{encoded}")
}

/// Builds a `/@v/{version}.{suffix}` proxy URL (e.g. `.info`, `.mod`) for a module.
///
/// Both `module_path` and `version` are escaped via `escape_module_path` and
/// `escape_version` respectively before interpolation, so a version string
/// carrying `?`, `#`, or whitespace cannot retarget the request to a
/// different endpoint or inject a query string / fragment (#377).
fn version_url(module_path: &str, version: &str, suffix: &str) -> String {
    let escaped_module = escape_module_path(module_path);
    let escaped_version = escape_version(version);
    format!("{PROXY_BASE}/{escaped_module}/@v/{escaped_version}.{suffix}")
}

/// Converts a 404 response into `DepsError::PackageNotFound`, passing through
/// any other error unchanged.
fn not_found_or(err: DepsError, module_path: &str) -> DepsError {
    if matches!(err, DepsError::HttpStatus { status: 404, .. }) {
        DepsError::PackageNotFound {
            package: module_path.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
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
            .map_err(|e| not_found_or(e, module_path))?;

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

        let url = version_url(module_path, version, "info");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| not_found_or(e, module_path))?;

        parse_version_info(module_path, &data)
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
            .map_err(|e| not_found_or(e, module_path))?;

        parse_version_info(module_path, &data)
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

        let url = version_url(module_path, version, "mod");

        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| not_found_or(e, module_path))?;

        std::str::from_utf8(&data)
            .map(std::string::ToString::to_string)
            .map_err(|e| DepsError::CacheError(format!("Invalid UTF-8 in go.mod: {e}")))
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
    let content = std::str::from_utf8(data).map_err(|e| {
        DepsError::InvalidVersionReq(format!("Invalid UTF-8 in version list response: {e}"))
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
                // `/@v/list` carries no dates — a documented Go-specific
                // limitation of this Ch2 path, not a parse failure.
                published_at: None,
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
fn parse_version_info(module_path: &str, data: &[u8]) -> Result<GoVersion> {
    let info: VersionInfo = serde_json::from_slice(data).map_err(|e| DepsError::ApiResponse {
        package: module_path.to_string(),
        registry: REGISTRY,
        source: e,
    })?;

    let is_pseudo = is_pseudo_version(&info.version);
    Ok(GoVersion {
        version: info.version,
        published_at: deps_core::PublishTime::parse_rfc3339(&info.time),
        is_pseudo,
        retracted: false,
    })
}

impl deps_core::Registry for GoRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>>
    {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        _req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn deps_core::Version>>>>
    {
        Box::pin(async move {
            // Try /@latest first (fast path)
            if let Ok(version) = self.get_latest(name.as_str()).await {
                return Ok(Some(Box::new(version) as Box<dyn deps_core::Version>));
            }
            // Fallback to /@v/list (/@latest is optional per Go proxy spec)
            let versions = self.get_versions(name.as_str()).await?;
            let latest = versions.into_iter().find(|v| !v.is_pseudo && !v.retracted);
            Ok(latest.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>>
    {
        // proxy.golang.org doesn't support search
        Box::pin(async move { Ok(vec![]) })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        _req: &deps_core::VersionReq,
    ) -> Option<usize> {
        // Mirrors the `/@v/list` fallback branch of the inherent `get_latest_matching`
        // above (the `/@latest` fast path isn't reachable here: this method is a pure,
        // no-I/O pick over an already-fetched list). `req` is ignored, matching that
        // fallback — Go module requirements are exact pins/MVS, not ranges.
        //
        // Go deliberately opts out of the shared existence-check ladder
        // (`deps_core::select_latest_for_existence`, see #364): Go has no real per-version
        // retraction (`retracted` is hardcoded `false`, see `reports_yanked` below), so the
        // ladder's rung 3 would return `Some(0)` unconditionally on an all-prerelease `/@v/
        // list` and short-circuit the `/@latest` fallback in `lifecycle.rs`, which resolves
        // pseudo-versions `/@v/list` never enumerates.
        versions
            .iter()
            .position(|v| !v.is_prerelease() && !v.removal_status().blocks_resolution())
    }

    // `Version::removal_status` is hardcoded to `Available` (`registry.rs:354`, `:401`) —
    // the proxy's `/@v/list` fast path never surfaces `retract` data, so a
    // yanked-check probe here would always come back empty (#233).
    fn reports_yanked(&self) -> bool {
        false
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
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert_eq!(version.version, "v1.9.1");
        assert_eq!(
            version.published_at,
            deps_core::PublishTime::parse_rfc3339("2023-07-18T14:30:00Z")
        );
        assert!(!version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_with_malformed_time() {
        let json = r#"{"Version":"v1.9.1","Time":"not-a-timestamp"}"#;
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert!(
            version.published_at.is_none(),
            "malformed Time degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_version_info_pseudo() {
        let json =
            r#"{"Version":"v0.0.0-20191109021931-daa7c04131f5","Time":"2019-11-09T02:19:31Z"}"#;
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert_eq!(version.version, "v0.0.0-20191109021931-daa7c04131f5");
        assert!(version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_invalid_json() {
        let json = b"not json";
        let result = parse_version_info("github.com/gin-gonic/gin", json);
        assert!(result.is_err());
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://proxy.golang.org/github.com/x/y/@v/list".into(),
            status: 404,
        };
        let result = not_found_or(err, "github.com/x/y");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "github.com/x/y" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        let err = DepsError::HttpStatus {
            url: "https://proxy.golang.org/github.com/x/y/@v/list".into(),
            status: 500,
        };
        let result = not_found_or(err, "github.com/x/y");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
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

    #[test]
    fn test_package_url_encodes_malicious_chars() {
        let url = package_url("github.com/evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
        assert!(
            url.contains("github.com/evil"),
            "legitimate path preserved: {url}"
        );
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("github.com/evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_module_path() {
        assert_eq!(package_url(""), "https://pkg.go.dev/");
    }

    /// Exercises `version_url` — the exact helper `get_version_info`/`get_go_mod` call —
    /// with a legitimate version, proving no regression: the URL is the expected literal
    /// string, not just "doesn't panic". Binds the guard to the production sink: deleting
    /// escaping from `version_url` would fail this test.
    #[test]
    fn test_info_url_construction_legitimate_version() {
        let url = version_url("github.com/gin-gonic/gin", "v1.9.1", "info");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.info"
        );
    }

    /// Same as above for a pseudo-version, which carries a `-` and digits only — must
    /// also pass through unescaped.
    #[test]
    fn test_info_url_construction_pseudo_version() {
        let url = version_url(
            "github.com/user/repo",
            "v0.0.0-20210101000000-abcdef123456",
            "info",
        );
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/user/repo/@v/v0.0.0-20210101000000-abcdef123456.info"
        );
    }

    /// #377 regression guard: a version string carrying `?`/`#`/space (which
    /// `validate_version_string` does NOT reject — only `..`, `/`, `\` are rejected) must
    /// not be able to inject a query string or fragment into the `.info` URL. Calls
    /// `version_url` directly (the same helper `get_version_info` calls) rather than
    /// duplicating its `format!` logic, so removing the escaping from the production sink
    /// fails this test.
    #[test]
    fn test_info_url_construction_rejects_query_and_fragment_injection() {
        let cases = [
            ("v1?a=b", "v1%3Fa%3Db"),
            ("v1#frag", "v1%23frag"),
            ("v1 x", "v1%20x"),
            ("v1&x=y", "v1%26x%3Dy"),
        ];

        for (raw_version, expected_escaped) in cases {
            let url = version_url("github.com/gin-gonic/gin", raw_version, "info");
            let expected_url = format!(
                "https://proxy.golang.org/github.com/gin-gonic/gin/@v/{expected_escaped}.info"
            );
            assert_eq!(url, expected_url, "raw version: {raw_version:?}");

            // The base URL up to the module path is fixed and query/fragment-free;
            // everything after MUST stay within the path component.
            let after_base = url
                .strip_prefix("https://proxy.golang.org/")
                .expect("URL must start with the proxy base");
            assert!(
                !after_base.contains('?'),
                "constructed URL must not contain a bare '?' for input {raw_version:?}: {url}"
            );
            assert!(
                !after_base.contains('#'),
                "constructed URL must not contain a bare '#' for input {raw_version:?}: {url}"
            );
            assert!(
                !after_base.contains(' '),
                "constructed URL must not contain a raw space for input {raw_version:?}: {url}"
            );
        }
    }

    /// Same construction proof for `get_go_mod`'s `.mod` URL via `version_url`.
    #[test]
    fn test_mod_url_construction_legitimate_version() {
        let url = version_url("github.com/gin-gonic/gin", "v1.9.1", "mod");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.mod"
        );
    }

    /// #377 regression guard for the `.mod` endpoint — same injection proof as
    /// `test_info_url_construction_rejects_query_and_fragment_injection`, mirroring
    /// `get_go_mod`'s URL construction instead of `get_version_info`'s.
    #[test]
    fn test_mod_url_construction_rejects_query_and_fragment_injection() {
        let cases = [
            ("v1?a=b", "v1%3Fa%3Db"),
            ("v1#frag", "v1%23frag"),
            ("v1 x", "v1%20x"),
        ];

        for (raw_version, expected_escaped) in cases {
            let url = version_url("github.com/gin-gonic/gin", raw_version, "mod");
            let expected_url = format!(
                "https://proxy.golang.org/github.com/gin-gonic/gin/@v/{expected_escaped}.mod"
            );
            assert_eq!(url, expected_url, "raw version: {raw_version:?}");

            let after_base = url
                .strip_prefix("https://proxy.golang.org/")
                .expect("URL must start with the proxy base");
            assert!(!after_base.contains('?'), "raw version: {raw_version:?}");
            assert!(!after_base.contains('#'), "raw version: {raw_version:?}");
        }
    }

    /// #377 S1 regression guard: `version_url` must case-fold uppercase in the version
    /// segment the same way `escape_module_path` folds module paths — a raw uppercase
    /// segment 404s against the real proxy (live-verified during review).
    #[test]
    fn test_info_url_construction_case_folds_uppercase_version() {
        let url = version_url("github.com/user/repo", "v1.7.0-RC", "info");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/user/repo/@v/v1.7.0-!r!c.info"
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
        assert!(info.published_at.is_some());
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
        let result = parse_version_info("github.com/gin-gonic/gin", json.as_bytes());
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

    /// S8 regression guard: `select_latest_matching`'s pure pick must agree with
    /// `get_latest_matching`'s `/@v/list` fallback branch (the `/@latest` fast path is
    /// unreachable from `select_latest_matching`, which is pure and has no I/O) for an
    /// ordinary, non-empty version list — the exact class of divergence Maven's S3/S7 hit.
    #[test]
    fn test_select_latest_matching_agrees_with_get_latest_matching_list_fallback() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let typed = vec![
            GoVersion {
                version: "v2.0.0-pseudo".to_string(),
                published_at: None,
                is_pseudo: true,
                retracted: false,
            },
            GoVersion {
                version: "v1.5.0".to_string(),
                published_at: None,
                is_pseudo: false,
                retracted: true,
            },
            GoVersion {
                version: "v1.0.0".to_string(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            },
        ];

        // Mirrors get_latest_matching's `/@v/list` fallback branch exactly.
        let fallback_pick = typed
            .iter()
            .find(|v| !v.is_pseudo && !v.retracted)
            .map(|v| v.version.clone());

        let boxed: Vec<Box<dyn deps_core::Version>> = typed
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(Some(boxed[idx].version_string().to_string()), fallback_pick);
        assert_eq!(fallback_pick.as_deref(), Some("v1.0.0"));
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(GoVersion {
                version: "v2.0.0".to_string(),
                published_at: None,
                is_pseudo: false,
                retracted: true,
            }),
            Box::new(GoVersion {
                version: "v1.0.0".to_string(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #364 regression guard: Go deliberately does NOT adopt the shared existence-check
    /// ladder's rung 3 (`deps_core::select_latest_for_existence`'s unconditional "newest
    /// overall" fallback). A non-empty but all-pseudo-version `/@v/list` (every entry
    /// `is_prerelease()`) must still yield `None` here so the fetch loop's `/@latest`
    /// fallback in `lifecycle.rs` keeps firing — adopting rung 3 would return `Some(0)`
    /// unconditionally and short-circuit that fallback, silently returning a pseudo-version
    /// instead of resolving through the more complete `/@latest` endpoint.
    #[test]
    fn test_select_latest_matching_all_prerelease_stays_none_go_opts_out_of_ladder() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(GoVersion {
                version: "v0.0.0-20191109021931-daa7c04131f5".to_string(),
                published_at: None,
                is_pseudo: true,
                retracted: false,
            }),
            Box::new(GoVersion {
                version: "v1.0.0-beta.1".to_string(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            None,
            "Go must not fall through to rung 3; a non-empty all-prerelease list must \
             still yield None so the /@latest fallback fires"
        );
    }
}
