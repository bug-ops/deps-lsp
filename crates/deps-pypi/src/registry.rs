//! PyPI registry client.
//!
//! Provides access to the PyPI registry via:
//! - Package metadata API (<https://pypi.org/pypi/{package}/json>) for version lookups
//! - Simple API (<https://pypi.org/simple/{package}/>) for version index (future)
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::error::{PypiError, Result};
use crate::types::{PypiPackage, PypiVersion};
use async_trait::async_trait;
use deps_core::{HttpCache, PackageRegistry};
use pep440_rs::{Version, VersionSpecifiers};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;

const PYPI_BASE: &str = "https://pypi.org/pypi";

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
pub fn package_url(name: &str) -> String {
    format!("{}/{}", PYPI_URL, normalize_package_name(name))
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
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package from PyPI.
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
        let url = format!("{}/{}/json", PYPI_BASE, normalized);
        let data = self.cache.get_cached(&url).await.map_err(|e| {
            if e.to_string().contains("404") {
                PypiError::PackageNotFound {
                    package: name.to_string(),
                }
            } else {
                PypiError::registry_error(name, e)
            }
        })?;

        parse_package_metadata(name, &data)
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

        // Parse PEP 440 version specifiers
        let specs = VersionSpecifiers::from_str(req_str).map_err(|e| {
            PypiError::InvalidVersionSpecifier {
                specifier: req_str.to_string(),
                source: e,
            }
        })?;

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
        let url = format!("{}/{}/json", PYPI_BASE, normalized);
        let data = self.cache.get_cached(&url).await.map_err(|e| {
            if e.to_string().contains("404") {
                PypiError::PackageNotFound {
                    package: name.to_string(),
                }
            } else {
                PypiError::registry_error(name, e)
            }
        })?;

        parse_package_info(name, &data)
    }
}

#[async_trait]
impl PackageRegistry for PypiRegistry {
    type Version = PypiVersion;
    type Metadata = PypiPackage;
    type VersionReq = String;

    async fn get_versions(&self, name: &str) -> deps_core::error::Result<Vec<Self::Version>> {
        PypiRegistry::get_versions(self, name)
            .await
            .map_err(|e| deps_core::error::DepsError::CacheError(e.to_string()))
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        req: &Self::VersionReq,
    ) -> deps_core::error::Result<Option<Self::Version>> {
        PypiRegistry::get_latest_matching(self, name, req)
            .await
            .map_err(|e| deps_core::error::DepsError::CacheError(e.to_string()))
    }

    async fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> deps_core::error::Result<Vec<Self::Metadata>> {
        PypiRegistry::search(self, query, limit)
            .await
            .map_err(|e| deps_core::error::DepsError::CacheError(e.to_string()))
    }
}

// JSON response types

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
    releases: std::collections::HashMap<String, Vec<PypiRelease>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    summary: Option<String>,
    project_urls: Option<std::collections::HashMap<String, String>>,
    version: String,
}

#[derive(Debug, Deserialize)]
struct PypiRelease {
    yanked: Option<bool>,
}

/// Parse package metadata from PyPI JSON response.
fn parse_package_metadata(package_name: &str, data: &[u8]) -> Result<Vec<PypiVersion>> {
    let response: PypiResponse =
        serde_json::from_slice(data).map_err(|e| PypiError::api_response_error(package_name, e))?;

    // Parse versions once and cache with the parsed Version for sorting
    let mut versions_with_parsed: Vec<(PypiVersion, Version)> = response
        .releases
        .into_iter()
        .filter_map(|(version_str, releases)| {
            // Check if any release file is yanked
            let yanked = releases.iter().any(|r| r.yanked.unwrap_or(false));

            // Parse version to validate it's a valid PEP 440 version
            Version::from_str(&version_str).ok().map(|parsed| {
                (
                    PypiVersion {
                        version: version_str,
                        yanked,
                    },
                    parsed,
                )
            })
        })
        .collect();

    // Sort by version (newest first) using pre-parsed versions
    versions_with_parsed.sort_by(|a, b| b.1.cmp(&a.1));

    // Extract sorted versions, discarding parsed data
    let versions: Vec<PypiVersion> = versions_with_parsed
        .into_iter()
        .map(|(v, _)| v)
        .collect();

    Ok(versions)
}

/// Parse package info from PyPI JSON response.
fn parse_package_info(package_name: &str, data: &[u8]) -> Result<PypiPackage> {
    let response: PypiResponse =
        serde_json::from_slice(data).map_err(|e| PypiError::api_response_error(package_name, e))?;

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
    fn test_package_url() {
        assert_eq!(package_url("requests"), "https://pypi.org/project/requests");
        assert_eq!(package_url("flask"), "https://pypi.org/project/flask");
    }

    #[test]
    fn test_parse_package_metadata() {
        let json = r#"{
            "info": {
                "name": "requests",
                "summary": "Python HTTP for Humans.",
                "version": "2.28.2",
                "project_urls": {
                    "Homepage": "https://requests.readthedocs.io"
                }
            },
            "releases": {
                "2.28.2": [{"yanked": false}],
                "2.28.1": [{"yanked": false}],
                "2.28.0": [{"yanked": true}],
                "2.27.0": [{"yanked": false}]
            }
        }"#;

        let versions = parse_package_metadata("requests", json.as_bytes()).unwrap();

        assert_eq!(versions.len(), 4);
        assert_eq!(versions[0].version, "2.28.2");
        assert!(!versions[0].yanked);
        assert!(versions[2].yanked); // 2.28.0 is yanked
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
            },
            "releases": {}
        }"#;

        let pkg = parse_package_info("flask", json.as_bytes()).unwrap();

        assert_eq!(pkg.name, "flask");
        assert_eq!(pkg.summary, Some("A micro web framework".to_string()));
        assert_eq!(pkg.latest_version, "3.0.0");
        assert_eq!(pkg.project_urls.len(), 2);
    }

    #[test]
    fn test_prerelease_detection() {
        let json = r#"{
            "info": {
                "name": "test",
                "version": "1.0.0",
                "project_urls": null
            },
            "releases": {
                "1.0.0": [{"yanked": false}],
                "1.0.0a1": [{"yanked": false}],
                "1.0.0b2": [{"yanked": false}],
                "1.0.0rc1": [{"yanked": false}]
            }
        }"#;

        let versions = parse_package_metadata("test", json.as_bytes()).unwrap();

        let stable: Vec<_> = versions.iter().filter(|v| !v.is_prerelease()).collect();
        let prerelease: Vec<_> = versions.iter().filter(|v| v.is_prerelease()).collect();

        assert_eq!(stable.len(), 1);
        assert_eq!(prerelease.len(), 3);
    }
}
