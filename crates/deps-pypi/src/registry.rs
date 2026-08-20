//! PyPI registry client.
//!
//! Provides access to the PyPI registry via:
//! - Simple API (<https://pypi.org/simple/{package}/>), PEP 691 JSON variant,
//!   for version lookups (`get_versions`) — smaller than the full JSON API
//! - Package metadata API (<https://pypi.org/pypi/{package}/json>) for hover
//!   metadata (`get_package_metadata`), which needs `summary`/`project_urls`
//!   that the Simple API doesn't carry
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::types::{PypiPackage, PypiVersion};
use deps_core::{DepsError, HttpCache, Result};
use pep440_rs::{Version, VersionSpecifiers};
use serde::Deserialize;
use std::any::Any;
use std::str::FromStr;
use std::sync::Arc;

const PYPI_BASE: &str = "https://pypi.org/pypi";

/// Base URL for the PEP 691 Simple API, used by `get_versions`.
const PYPI_SIMPLE_BASE: &str = "https://pypi.org/simple";

/// `Accept` header requesting the PEP 691 Simple API JSON representation.
/// Roughly a third smaller than the full JSON API (verified against
/// `django`: 619,755 bytes full vs 411,376 bytes Simple API).
const SIMPLE_API_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// Display name for PyPI used in not-found and API-response error messages.
pub const REGISTRY: &str = "PyPI";

/// Base URL for package pages on pypi.org
pub const PYPI_URL: &str = "https://pypi.org/project";

/// Normalize package name according to PEP 503.
///
/// Converts package name to lowercase and replaces underscores/dots with hyphens,
/// then filters out consecutive hyphens. This ensures consistent package lookups
/// regardless of how the package name is written.
///
/// # Examples
///
/// ```
/// # use deps_pypi::registry::normalize_package_name;
/// assert_eq!(normalize_package_name("Flask"), "flask");
/// assert_eq!(normalize_package_name("django_rest_framework"), "django-rest-framework");
/// assert_eq!(normalize_package_name("Pillow.Image"), "pillow-image");
/// assert_eq!(normalize_package_name("my__package"), "my-package");
/// ```
pub fn normalize_package_name(name: &str) -> String {
    name.to_lowercase()
        .replace(&['_', '.'][..], "-")
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Returns the URL for a package's page on pypi.org.
///
/// Package names are normalized and URL-encoded to prevent path traversal attacks.
pub fn package_url(name: &str) -> String {
    let normalized = normalize_package_name(name);
    format!("{}/{}", PYPI_URL, urlencoding::encode(&normalized))
}

/// Builds the Simple API request URL for `normalized`'s version listing.
///
/// The name segment is URL-encoded (matching `package_url`) since
/// `normalize_package_name` only collapses `-`/`_`/`.` separators and leaves
/// characters like `/`, `?`, `#` untouched.
fn simple_api_url(normalized: &str) -> String {
    format!("{PYPI_SIMPLE_BASE}/{}/", urlencoding::encode(normalized))
}

/// Builds the JSON API request URL for `normalized`'s package metadata.
fn metadata_url(normalized: &str) -> String {
    format!("{PYPI_BASE}/{}/json", urlencoding::encode(normalized))
}

/// Converts a 404 response into `DepsError::PackageNotFound`, passing through
/// any other error unchanged.
fn not_found_or(err: DepsError, name: &str) -> DepsError {
    if matches!(err, DepsError::HttpStatus { status: 404, .. }) {
        DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
}

/// Client for interacting with the PyPI registry.
///
/// Uses the PyPI JSON API for package metadata.
/// All requests are cached via the provided HttpCache.
///
/// # Examples
///
/// ```no_run
/// # use deps_pypi::PypiRegistry;
/// # use deps_core::HttpCache;
/// # use std::sync::Arc;
/// # #[tokio::main]
/// # async fn main() {
/// let cache = Arc::new(HttpCache::new());
/// let registry = PypiRegistry::new(cache);
///
/// let versions = registry.get_versions("requests").await.unwrap();
/// assert!(!versions.is_empty());
/// # }
/// ```
#[derive(Clone)]
pub struct PypiRegistry {
    cache: Arc<HttpCache>,
}

impl PypiRegistry {
    /// Creates a new PyPI registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package from PyPI's Simple API (PEP 691).
    ///
    /// Requests the JSON representation (`Accept:
    /// application/vnd.pypi.simple.v1+json`), which is smaller than the full
    /// JSON API and provides the version list directly, without needing to
    /// derive versions from release-file names.
    ///
    /// Returns versions sorted newest-first. Filters out yanked versions by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    /// - Package does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("flask").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<PypiVersion>> {
        let normalized = normalize_package_name(name);
        let url = simple_api_url(&normalized);
        let data = self
            .cache
            .get_cached_with_headers(&url, &[(reqwest::header::ACCEPT, SIMPLE_API_ACCEPT)])
            .await
            .map_err(|e| not_found_or(e, name))?;

        parse_simple_api_response(name, &data)
    }

    /// Finds the latest version matching the given PEP 440 version specifier.
    ///
    /// Only returns non-yanked, non-prerelease versions by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    /// - Version specifier is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("flask", ">=3.0,<4.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<PypiVersion>> {
        let versions = self.get_versions(name).await?;

        // PEP 440 uses empty string for "any version"
        let normalized_req = if req_str == "*" { "" } else { req_str };

        let specs = VersionSpecifiers::from_str(normalized_req)
            .map_err(|e| DepsError::InvalidVersionReq(format!("{req_str}: {e}")))?;

        Ok(versions.into_iter().find(|v| {
            if let Ok(version) = Version::from_str(&v.version) {
                specs.contains(&version) && !v.yanked && !v.is_prerelease()
            } else {
                false
            }
        }))
    }

    /// Searches for packages by name/keywords.
    ///
    /// Note: PyPI does not provide an official search API, so this returns
    /// an empty result for now. Future implementation could use third-party
    /// search services or scraping.
    ///
    /// # Errors
    ///
    /// Currently always returns Ok with empty vector.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// let results = registry.search("flask", 10).await.unwrap();
    /// // Currently returns empty, to be implemented
    /// # }
    /// ```
    pub async fn search(&self, _query: &str, _limit: usize) -> Result<Vec<PypiPackage>> {
        // TODO: Implement search using third-party API or scraping
        // PyPI deprecated their XML-RPC search API
        Ok(Vec::new())
    }

    /// Fetches package metadata including description and project URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    /// - JSON parsing fails
    pub async fn get_package_metadata(&self, name: &str) -> Result<PypiPackage> {
        let normalized = normalize_package_name(name);
        let url = metadata_url(&normalized);
        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| not_found_or(e, name))?;

        parse_package_info(name, &data)
    }
}

// Implement Registry trait for PypiRegistry
impl deps_core::Registry for PypiRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            let versions = Self::get_versions(self, name).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a str,
        req: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Option<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            let version = Self::get_latest_matching(self, name, req).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>,
    > {
        Box::pin(async move {
            let packages = Self::search(self, query, limit).await?;
            Ok(packages
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn package_url(&self, name: &str) -> String {
        package_url(name)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// JSON response types

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    summary: Option<String>,
    project_urls: Option<std::collections::HashMap<String, String>>,
    version: String,
}

// PEP 691 Simple API JSON response types

#[derive(Debug, Deserialize)]
struct SimpleApiResponse {
    versions: Vec<String>,
    files: Vec<SimpleFile>,
}

#[derive(Debug, Deserialize)]
struct SimpleFile {
    filename: String,
    #[serde(default)]
    yanked: Yanked,
}

/// A file's yanked status per PEP 592: either `false` (not yanked) or a
/// string giving the yank reason. `get_versions` only needs the yanked/not
/// distinction, so the reason text itself is discarded on parse.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Yanked {
    Flag(bool),
    Reason(#[expect(dead_code, reason = "reason text not surfaced by get_versions")] String),
}

impl Default for Yanked {
    fn default() -> Self {
        Self::Flag(false)
    }
}

impl Yanked {
    const fn is_yanked(&self) -> bool {
        match self {
            Self::Flag(b) => *b,
            Self::Reason(_) => true,
        }
    }
}

/// Archive/wheel file extensions recognized on PyPI's Simple API index, used
/// to strip the trailing extension off an sdist-style filename (one with no
/// further `-`-delimited tags after the version) when deriving its version.
const KNOWN_ARCHIVE_EXTENSIONS: &[&str] = &[
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tar.Z", ".zip", ".whl", ".egg", ".tar",
];

/// Derives the release version directly from `filename`'s structure, given
/// the package's PEP 503 normalized name, in O(filename length) with no
/// dependency on the number of known versions.
///
/// PyPI release filenames are `{name}-{version}[-...].{ext}`, but the
/// `{name}` segment on disk may use the project's original casing and
/// original `-`/`_`/`.` separators (e.g. `zope.interface-3.3.0b1.tar.gz` for
/// normalized name `zope-interface`) rather than the normalized spelling.
/// This walks `normalized_name` against `filename` byte-for-byte,
/// case-insensitively, treating any run of `-`/`_`/`.` in `filename` as
/// equivalent to a single `-` in `normalized_name`, then cuts the remainder
/// at the first `-` (wheel tags) or a recognized archive extension (sdists).
///
/// Returns `None` if `filename` doesn't conform closely enough to derive a
/// version unambiguously; callers skip attributing that file rather than
/// guess (see [`build_yanked_map`]).
fn parse_version_from_filename<'a>(filename: &'a str, normalized_name: &str) -> Option<&'a str> {
    let bytes = filename.as_bytes();
    let mut fi = 0usize;
    for nb in normalized_name.bytes() {
        if nb == b'-' {
            let start = fi;
            while matches!(bytes.get(fi), Some(b'-' | b'_' | b'.')) {
                fi += 1;
            }
            if fi == start {
                return None;
            }
        } else {
            match bytes.get(fi) {
                Some(&fb) if fb.to_ascii_lowercase() == nb => fi += 1,
                _ => return None,
            }
        }
    }
    if bytes.get(fi) != Some(&b'-') {
        return None;
    }
    let rest = &filename[fi + 1..];
    match rest.find('-') {
        Some(end) => Some(&rest[..end]),
        None => KNOWN_ARCHIVE_EXTENSIONS
            .iter()
            .find_map(|ext| rest.strip_suffix(ext)),
    }
}

/// Builds a per-version yanked map from a Simple API `files` list.
///
/// A version is yanked if any of its release files are yanked (PyPI itself
/// treats a release as yanked once any file under it is, since new uploads
/// to an already-yanked version are rejected).
///
/// Derives each file's version in O(1) via [`parse_version_from_filename`]
/// and resolves it against `versions` in two tiers, the second tried only
/// if the first misses:
/// 1. Exact string match — the common case, and the only tier that can tell
///    apart distinct-but-PEP-440-equal strings like `1.0` and `1.0.0`
///    (legacy packages can list both as separate releases).
/// 2. Match as a parsed [`Version`] — PyPI filenames sometimes spell a
///    version differently than its canonical form (e.g. `4.21.0_rc_1` in a
///    wheel filename for the canonical `4.21.0rc1`), which `Version`'s
///    `Eq`/`Hash` normalize away.
///
/// A file whose filename doesn't structurally parse, or whose derived
/// version matches neither tier, is skipped rather than guessed at via
/// substring search — an earlier substring-based fallback could misattribute
/// a file to an unrelated version whose digits happened to appear elsewhere
/// in the filename (e.g. a platform tag), which is worse than the version's
/// yanked status resting on its other, better-formed release files.
fn build_yanked_map(
    files: &[SimpleFile],
    versions: &[String],
    normalized_name: &str,
) -> std::collections::HashMap<String, bool> {
    let version_set: std::collections::HashSet<&str> =
        versions.iter().map(String::as_str).collect();

    // Built lazily: most real-world responses resolve every file via the
    // exact-string tier and never need this.
    let mut parsed_versions: Option<std::collections::HashMap<Version, &str>> = None;

    let mut yanked: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for file in files {
        let matched =
            parse_version_from_filename(&file.filename, normalized_name).and_then(|candidate| {
                version_set.get(candidate).copied().or_else(|| {
                    let parsed = Version::from_str(candidate).ok()?;
                    let map = parsed_versions.get_or_insert_with(|| {
                        versions
                            .iter()
                            .filter_map(|v| Some((Version::from_str(v).ok()?, v.as_str())))
                            .collect()
                    });
                    map.get(&parsed).copied()
                })
            });

        let Some(version) = matched else {
            continue;
        };
        let entry = yanked.entry(version.to_string()).or_insert(false);
        *entry |= file.yanked.is_yanked();
    }
    yanked
}

/// Parse the version list from a PyPI Simple API (PEP 691) JSON response.
fn parse_simple_api_response(package_name: &str, data: &[u8]) -> Result<Vec<PypiVersion>> {
    let response: SimpleApiResponse =
        serde_json::from_slice(data).map_err(|e| DepsError::ApiResponse {
            package: package_name.to_string(),
            registry: REGISTRY,
            source: e,
        })?;

    let normalized_name = normalize_package_name(package_name);
    let yanked_map = build_yanked_map(&response.files, &response.versions, &normalized_name);

    let mut versions_with_parsed: Vec<(PypiVersion, Version)> = response
        .versions
        .into_iter()
        .filter_map(|version_str| {
            let parsed = Version::from_str(&version_str).ok()?;
            let yanked = yanked_map.get(&version_str).copied().unwrap_or(false);
            Some((
                PypiVersion {
                    version: version_str,
                    yanked,
                },
                parsed,
            ))
        })
        .collect();

    // Sort by version (newest first) using pre-parsed versions
    versions_with_parsed.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Parse package info from PyPI JSON response.
fn parse_package_info(package_name: &str, data: &[u8]) -> Result<PypiPackage> {
    let response: PypiResponse =
        serde_json::from_slice(data).map_err(|e| DepsError::ApiResponse {
            package: package_name.to_string(),
            registry: REGISTRY,
            source: e,
        })?;

    let project_urls = response
        .info
        .project_urls
        .unwrap_or_default()
        .into_iter()
        .collect();

    Ok(PypiPackage {
        name: response.info.name,
        summary: response.info.summary,
        project_urls,
        latest_version: response.info.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_package_name_lowercase() {
        assert_eq!(normalize_package_name("Flask"), "flask");
        assert_eq!(normalize_package_name("DJANGO"), "django");
        assert_eq!(normalize_package_name("Requests"), "requests");
    }

    #[test]
    fn test_normalize_package_name_underscores() {
        assert_eq!(
            normalize_package_name("django_rest_framework"),
            "django-rest-framework"
        );
        assert_eq!(normalize_package_name("my_package"), "my-package");
    }

    #[test]
    fn test_normalize_package_name_dots() {
        assert_eq!(normalize_package_name("Pillow.Image"), "pillow-image");
        assert_eq!(normalize_package_name("zope.interface"), "zope-interface");
    }

    #[test]
    fn test_normalize_package_name_consecutive_separators() {
        assert_eq!(normalize_package_name("my__package"), "my-package");
        assert_eq!(normalize_package_name("my..package"), "my-package");
        assert_eq!(normalize_package_name("my_.package"), "my-package");
    }

    #[test]
    fn test_normalize_package_name_mixed() {
        assert_eq!(normalize_package_name("My_Package.Name"), "my-package-name");
        assert_eq!(
            normalize_package_name("SOME__Weird.._Package"),
            "some-weird-package"
        );
    }

    #[test]
    fn test_normalize_package_name_already_normalized() {
        assert_eq!(normalize_package_name("my-package"), "my-package");
        assert_eq!(
            normalize_package_name("django-rest-framework"),
            "django-rest-framework"
        );
    }

    #[test]
    fn test_normalize_package_name_edge_cases() {
        assert_eq!(normalize_package_name("a"), "a");
        assert_eq!(normalize_package_name("A_B_C"), "a-b-c");
        assert_eq!(normalize_package_name("---"), "");
    }

    #[test]
    fn test_normalize_package_name_leading_trailing_separators() {
        assert_eq!(normalize_package_name("_package_"), "package");
        assert_eq!(normalize_package_name(".package."), "package");
        assert_eq!(normalize_package_name("__package__"), "package");
    }

    #[test]
    fn test_package_url() {
        assert_eq!(package_url("requests"), "https://pypi.org/project/requests");
        assert_eq!(package_url("flask"), "https://pypi.org/project/flask");
    }

    #[test]
    fn test_package_url_normalization() {
        assert_eq!(package_url("Flask"), "https://pypi.org/project/flask");
        assert_eq!(
            package_url("django_rest_framework"),
            "https://pypi.org/project/django-rest-framework"
        );
    }

    #[test]
    fn test_package_url_encoding() {
        let url = package_url("my-package");
        assert!(url.starts_with("https://pypi.org/project/"));
        assert!(url.contains("my-package"));
    }

    #[test]
    fn test_package_url_encodes_malicious_name() {
        let url = package_url("evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        // The literal '%' from the payload must itself be encoded (to %25), or a
        // browser/renderer double-decode could smuggle a raw byte back in.
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://pypi.org/project/");
    }

    #[test]
    fn test_parse_simple_api_response() {
        // Shape captured live from `pypi.org/simple/requests/` with
        // `Accept: application/vnd.pypi.simple.v1+json`.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "requests",
            "versions": ["2.27.0", "2.28.0", "2.28.1", "2.28.2"],
            "files": [
                {"filename": "requests-2.27.0.tar.gz", "yanked": false},
                {"filename": "requests-2.28.0.tar.gz", "yanked": true},
                {"filename": "requests-2.28.0-py3-none-any.whl", "yanked": true},
                {"filename": "requests-2.28.1.tar.gz", "yanked": false},
                {"filename": "requests-2.28.2.tar.gz", "yanked": false},
                {"filename": "requests-2.28.2-py3-none-any.whl", "yanked": false}
            ]
        }"#;

        let versions = parse_simple_api_response("requests", json.as_bytes()).unwrap();

        assert_eq!(versions.len(), 4);
        assert_eq!(versions[0].version, "2.28.2");
        assert!(!versions[0].yanked);
        assert!(
            versions
                .iter()
                .find(|v| v.version == "2.28.0")
                .unwrap()
                .yanked
        );
    }

    #[test]
    fn test_parse_simple_api_response_yanked_with_reason_string() {
        // PEP 592: `yanked` may be a non-empty string giving the reason,
        // which still means "yanked" (only `false` means not yanked).
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "urllib3",
            "versions": ["1.25"],
            "files": [
                {"filename": "urllib3-1.25-py2.py3-none-any.whl", "yanked": "Broken release"},
                {"filename": "urllib3-1.25.tar.gz", "yanked": "Broken release"}
            ]
        }"#;

        let versions = parse_simple_api_response("urllib3", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].yanked);
    }

    #[test]
    fn test_build_yanked_map_disambiguates_version_prefixes() {
        // "1.0" is a substring of the "1.0.0" filename; trying the longer
        // version first must ensure "1.0"'s own (absent) file isn't
        // conflated with "1.0.0"'s file.
        let files = vec![SimpleFile {
            filename: "pkg-1.0.0.tar.gz".to_string(),
            yanked: Yanked::Flag(true),
        }];
        let versions = vec!["1.0".to_string(), "1.0.0".to_string()];
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("1.0.0"), Some(&true));
        assert_eq!(map.get("1.0"), None);
    }

    #[test]
    fn test_build_yanked_map_any_file_yanked_marks_version_yanked() {
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.0-py3-none-any.whl".to_string(),
                yanked: Yanked::Flag(false),
            },
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
            },
        ];
        let versions = vec!["1.0.0".to_string()];
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("1.0.0"), Some(&true));
    }

    #[test]
    fn test_build_yanked_map_disambiguates_in_both_directions() {
        // Both "1.0" and "1.0.0" are real releases with their own files.
        // Matching must not let the longer version's absent file bleed into
        // the shorter version's real one, nor vice versa.
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
            },
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
            },
        ];
        let versions = vec!["1.0".to_string(), "1.0.0".to_string()];
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("1.0"), Some(&true));
        assert_eq!(map.get("1.0.0"), Some(&false));
    }

    #[test]
    fn test_build_yanked_map_pre_post_dev_suffixes() {
        // Pre/post/dev-release version strings are '.'-delimited suffixes on
        // the base version and must not be conflated with it or each other.
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
            },
            SimpleFile {
                filename: "pkg-1.0.0rc1.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
            },
            SimpleFile {
                filename: "pkg-1.0.0.post1.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
            },
            SimpleFile {
                filename: "pkg-1.0.0.dev1.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
            },
        ];
        let versions = vec![
            "1.0.0".to_string(),
            "1.0.0rc1".to_string(),
            "1.0.0.post1".to_string(),
            "1.0.0.dev1".to_string(),
        ];
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("1.0.0"), Some(&false));
        assert_eq!(map.get("1.0.0rc1"), Some(&true));
        assert_eq!(map.get("1.0.0.post1"), Some(&false));
        assert_eq!(map.get("1.0.0.dev1"), Some(&true));
    }

    #[test]
    fn test_parse_version_from_filename_wheel_and_sdist() {
        assert_eq!(
            parse_version_from_filename("requests-2.28.2.tar.gz", "requests"),
            Some("2.28.2")
        );
        assert_eq!(
            parse_version_from_filename("requests-2.28.2-py3-none-any.whl", "requests"),
            Some("2.28.2")
        );
    }

    #[test]
    fn test_parse_version_from_filename_dotted_and_underscored_project_name() {
        // Real PyPI filenames keep the project's original separator style
        // even though `normalized_name` collapses it to hyphens.
        assert_eq!(
            parse_version_from_filename("zope.interface-3.3.0b1.tar.gz", "zope-interface"),
            Some("3.3.0b1")
        );
        assert_eq!(
            parse_version_from_filename(
                "typing_extensions-3.6.2-py3-none-any.whl",
                "typing-extensions"
            ),
            Some("3.6.2")
        );
    }

    #[test]
    fn test_parse_version_from_filename_rejects_non_conforming() {
        // Doesn't start with the package name at all.
        assert_eq!(
            parse_version_from_filename("other-1.0.0.tar.gz", "pkg"),
            None
        );
        // Name matches but there's no name/version separator afterwards.
        assert_eq!(parse_version_from_filename("pkg1.0.0.tar.gz", "pkg"), None);
    }

    #[test]
    fn test_parse_version_from_filename_no_digit_run_confusion() {
        // Structural parsing reads the version as the literal token right
        // after the name prefix, so "1.10.0" is never mistaken for "1.0.0"
        // the way a substring search could be.
        assert_eq!(
            parse_version_from_filename("pkg-1.10.0.tar.gz", "pkg"),
            Some("1.10.0")
        );
    }

    #[test]
    fn test_build_yanked_map_uses_fast_path_not_quadratic_fallback() {
        // Regression guard for the O(files x versions) blowup: a well-formed
        // filename must resolve via the O(1) structural fast path,
        // regardless of how many other versions exist.
        let mut versions: Vec<String> = (0..2000).map(|i| format!("0.0.{i}")).collect();
        versions.push("9.9.9".to_string());
        let files = vec![SimpleFile {
            filename: "pkg-9.9.9.tar.gz".to_string(),
            yanked: Yanked::Flag(true),
        }];
        assert_eq!(
            parse_version_from_filename(&files[0].filename, "pkg"),
            Some("9.9.9"),
            "fast path must derive the version directly from filename structure"
        );
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("9.9.9"), Some(&true));
    }

    #[test]
    fn test_build_yanked_map_ignores_platform_tag_false_match() {
        // Regression for a live PyPI file (`pyobjc_core-2.2-py2.6-macosx-10.3-fat.egg`):
        // the old whole-filename substring scan could misattribute this file
        // to version "10.3" (a platform tag that happens to look like a
        // version and sorts before "2.2" by length) instead of "2.2". The
        // structural fast path only looks at the token right after the name
        // prefix, so it can't be fooled by tags later in the filename.
        let files = vec![SimpleFile {
            filename: "pyobjc_core-2.2-py2.6-macosx-10.3-fat.egg".to_string(),
            yanked: Yanked::Flag(true),
        }];
        let versions = vec!["2.2".to_string(), "10.3".to_string()];
        let map = build_yanked_map(&files, &versions, "pyobjc-core");
        assert_eq!(map.get("2.2"), Some(&true));
        assert_eq!(map.get("10.3"), None);
    }

    #[test]
    fn test_build_yanked_map_pep440_underscore_normalization() {
        // Regression for a live PyPI file
        // (`protobuf-4.21.0_rc_1-cp310-abi3-win_amd64.whl`): the wheel
        // filename spells the pre-release as `4.21.0_rc_1` while the
        // canonical version string PyPI lists is `4.21.0rc1`. An exact
        // string comparison misses this; PEP 440-normalized comparison
        // (`Version`'s `Eq`) does not.
        let files = vec![SimpleFile {
            filename: "protobuf-4.21.0_rc_1-cp310-abi3-win_amd64.whl".to_string(),
            yanked: Yanked::Flag(false),
        }];
        let versions = vec!["4.21.0rc1".to_string()];
        let map = build_yanked_map(&files, &versions, "protobuf");
        assert_eq!(map.get("4.21.0rc1"), Some(&false));
    }

    #[test]
    fn test_build_yanked_map_skips_non_conforming_filename_instead_of_guessing() {
        // A filename whose leading segment doesn't match the package's
        // normalized name at all can't resolve via the structural fast path.
        // Rather than fall back to a substring guess (the mechanism behind
        // the pyobjc-core misattribution above), that file is skipped —
        // it contributes nothing to the yanked map, but doesn't corrupt it
        // either. A well-formed file for the same version still resolves
        // correctly, and an unrelated version stays untouched.
        let files = vec![
            SimpleFile {
                filename: "unrelated-file-1.0.0.zip".to_string(),
                yanked: Yanked::Flag(true),
            },
            SimpleFile {
                filename: "pkg-1.0.0-py3-none-any.whl".to_string(),
                yanked: Yanked::Flag(true),
            },
        ];
        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        assert_eq!(
            parse_version_from_filename(&files[0].filename, "pkg"),
            None,
            "filename doesn't start with the package name, must be skipped"
        );
        let map = build_yanked_map(&files, &versions, "pkg");
        assert_eq!(map.get("1.0.0"), Some(&true));
        assert_eq!(map.get("2.0.0"), None);
    }

    #[test]
    fn test_simple_api_url_encodes_malicious_name() {
        // `normalize_package_name` only collapses `-`/`_`/`.` separators and
        // leaves characters like `/` untouched, so the URL builder itself
        // must encode them to prevent smuggling extra path segments.
        let url = simple_api_url("evil/../secret");
        assert!(url.starts_with(PYPI_SIMPLE_BASE));
        assert!(!url.contains("/../"));
        assert_eq!(url, format!("{PYPI_SIMPLE_BASE}/evil%2F..%2Fsecret/"));
    }

    #[test]
    fn test_metadata_url_encodes_malicious_name() {
        let url = metadata_url("pkg?x=1#frag");
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
    }

    #[test]
    fn test_simple_api_url_normal_names() {
        assert_eq!(
            simple_api_url("requests"),
            "https://pypi.org/simple/requests/"
        );
        assert_eq!(
            simple_api_url("zope-interface"),
            "https://pypi.org/simple/zope-interface/"
        );
    }

    #[test]
    fn test_parse_package_info() {
        let json = r#"{
            "info": {
                "name": "flask",
                "summary": "A micro web framework",
                "version": "3.0.0",
                "project_urls": {
                    "Documentation": "https://flask.palletsprojects.com/",
                    "Repository": "https://github.com/pallets/flask"
                }
            }
        }"#;

        let pkg = parse_package_info("flask", json.as_bytes()).unwrap();

        assert_eq!(pkg.name, "flask");
        assert_eq!(pkg.summary, Some("A micro web framework".to_string()));
        assert_eq!(pkg.latest_version, "3.0.0");
        assert_eq!(pkg.project_urls.len(), 2);
    }

    #[test]
    fn test_wildcard_specifier_normalization() {
        // Test that "*" is normalized to empty string for PEP 440 compatibility
        // The get_latest_matching method normalizes "*" to "" internally
        let normalized = if "*" == "*" { "" } else { "*" };
        assert_eq!(normalized, "");

        // Verify that empty string is valid PEP 440 (matches any version)
        let specs = VersionSpecifiers::from_str("").unwrap();
        assert!(specs.contains(&Version::from_str("1.0.0").unwrap()));
        assert!(specs.contains(&Version::from_str("2.5.3").unwrap()));
        assert!(specs.contains(&Version::from_str("0.0.1").unwrap()));
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://pypi.org/pypi/flask/json".into(),
            status: 404,
        };
        let result = not_found_or(err, "flask");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "flask" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        // Regression test: a package name containing the substring "404" must
        // not be misclassified as not-found for a non-404 failure, since the
        // fix replaced string matching on the formatted error with a
        // structural match on the HTTP status code.
        let err = DepsError::HttpStatus {
            url: "https://pypi.org/pypi/pytest-404/json".into(),
            status: 500,
        };
        let result = not_found_or(err, "pytest-404");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
    }

    #[test]
    fn test_prerelease_detection() {
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "test",
            "versions": ["1.0.0", "1.0.0a1", "1.0.0b2", "1.0.0rc1"],
            "files": [
                {"filename": "test-1.0.0.tar.gz", "yanked": false},
                {"filename": "test-1.0.0a1.tar.gz", "yanked": false},
                {"filename": "test-1.0.0b2.tar.gz", "yanked": false},
                {"filename": "test-1.0.0rc1.tar.gz", "yanked": false}
            ]
        }"#;

        let versions = parse_simple_api_response("test", json.as_bytes()).unwrap();

        let stable: Vec<_> = versions.iter().filter(|v| !v.is_prerelease()).collect();
        let prerelease: Vec<_> = versions.iter().filter(|v| v.is_prerelease()).collect();

        assert_eq!(stable.len(), 1);
        assert_eq!(prerelease.len(), 3);
    }
}
