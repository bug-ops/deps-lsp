//! npm registry client.
//!
//! Provides access to the npm registry via:
//! - Package metadata API (<https://registry.npmjs.org/{package}>) for version lookups
//! - Search API (<https://registry.npmjs.org/-/v1/search>) for package search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::types::{NpmPackage, NpmVersion};
use deps_core::{DepsError, HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const REGISTRY_BASE: &str = "https://registry.npmjs.org";

/// Base URL for package pages on npmjs.com
pub const NPMJS_URL: &str = "https://www.npmjs.com/package";

/// Returns the URL for a package's page on npmjs.com.
///
/// Package names are URL-encoded to prevent path traversal attacks.
pub fn package_url(name: &str) -> String {
    format!("{}/{}", NPMJS_URL, urlencoding::encode(name))
}

/// Client for interacting with the npm registry.
///
/// Uses the npm registry API for package metadata and search.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct NpmRegistry {
    cache: Arc<HttpCache>,
}

impl NpmRegistry {
    /// Creates a new npm registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package from the npm registry.
    ///
    /// Returns versions sorted newest-first. Includes deprecated versions.
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
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("express").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<NpmVersion>> {
        let url = format!("{REGISTRY_BASE}/{name}");
        let data = self.cache.get_cached(&url).await?;

        parse_package_metadata(&data)
    }

    /// Finds the latest version matching the given npm semver requirement.
    ///
    /// Only returns non-deprecated versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("express", "^4.0.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<NpmVersion>> {
        let versions = self.get_versions(name).await?;

        // Parse npm semver requirement
        let req = node_semver::Range::parse(req_str)
            .map_err(|e| DepsError::InvalidVersionReq(e.to_string()))?;

        Ok(versions.into_iter().find(|v| {
            let version = node_semver::Version::parse(&v.version).ok();
            version.is_some_and(|ver| req.satisfies(&ver) && !v.deprecated)
        }))
    }

    /// Searches for packages by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let results = registry.search("express", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<NpmPackage>> {
        let url = format!(
            "{}/-/v1/search?text={}&size={}",
            REGISTRY_BASE,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Package metadata response from npm registry.
#[derive(Deserialize)]
struct PackageMetadata {
    versions: std::collections::HashMap<String, VersionMetadata>,
}

/// Version metadata from npm registry.
#[derive(Deserialize)]
struct VersionMetadata {
    #[serde(default)]
    deprecated: Option<String>,
}

/// Parses JSON response from npm package metadata API.
fn parse_package_metadata(data: &[u8]) -> Result<Vec<NpmVersion>> {
    let metadata: PackageMetadata = serde_json::from_slice(data)?;

    // Parse versions once and cache the parsed Version for sorting
    let mut versions_with_parsed: Vec<(NpmVersion, node_semver::Version)> = metadata
        .versions
        .into_iter()
        .filter_map(|(version, meta)| {
            let parsed = node_semver::Version::parse(&version).ok()?;
            Some((
                NpmVersion {
                    version,
                    deprecated: meta.deprecated.is_some(),
                },
                parsed,
            ))
        })
        .collect();

    // Sort using already-parsed versions (newest first)
    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    // Extract sorted versions
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Search response from npm registry.
#[derive(Deserialize)]
struct SearchResponse {
    objects: Vec<SearchObject>,
}

/// Search result object.
#[derive(Deserialize)]
struct SearchObject {
    package: SearchPackage,
}

/// Package information in search result.
#[derive(Deserialize)]
struct SearchPackage {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    links: Option<PackageLinks>,
    version: String,
}

/// Package links in search result.
#[derive(Deserialize)]
struct PackageLinks {
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

/// Parses JSON response from npm search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<NpmPackage>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .objects
        .into_iter()
        .map(|obj| {
            let pkg = obj.package;
            NpmPackage {
                name: pkg.name,
                description: pkg.description,
                homepage: pkg.links.as_ref().and_then(|l| l.homepage.clone()),
                repository: pkg.links.as_ref().and_then(|l| l.repository.clone()),
                latest_version: pkg.version,
            }
        })
        .collect())
}

// Implement PackageRegistry trait for NpmRegistry
#[async_trait::async_trait]
impl deps_core::PackageRegistry for NpmRegistry {
    type Version = NpmVersion;
    type Metadata = NpmPackage;
    type VersionReq = node_semver::Range;

    async fn get_versions(&self, name: &str) -> Result<Vec<Self::Version>> {
        self.get_versions(name).await
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        req: &Self::VersionReq,
    ) -> Result<Option<Self::Version>> {
        self.get_latest_matching(name, &req.to_string()).await
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Self::Metadata>> {
        self.search(query, limit).await
    }
}

// Implement Registry trait for NpmRegistry
#[async_trait::async_trait]
impl deps_core::Registry for NpmRegistry {
    async fn get_versions(&self, name: &str) -> Result<Vec<Box<dyn deps_core::Version>>> {
        let versions = self.get_versions(name).await?;
        Ok(versions
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect())
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<Box<dyn deps_core::Version>>> {
        let version = self.get_latest_matching(name, req).await?;
        Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Box<dyn deps_core::Metadata>>> {
        let packages = self.search(query, limit).await?;
        Ok(packages
            .into_iter()
            .map(|p| Box::new(p) as Box<dyn deps_core::Metadata>)
            .collect())
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
    fn test_parse_package_metadata() {
        let json = r#"{
  "versions": {
    "1.0.0": {},
    "1.0.1": {"deprecated": "Use 1.0.2 instead"},
    "1.0.2": {}
  },
  "dist-tags": {
    "latest": "1.0.2"
  }
}"#;

        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);

        // Sorted newest first
        assert_eq!(versions[0].version, "1.0.2");
        assert!(!versions[0].deprecated);

        assert_eq!(versions[1].version, "1.0.1");
        assert!(versions[1].deprecated);

        assert_eq!(versions[2].version, "1.0.0");
        assert!(!versions[2].deprecated);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
  "objects": [
    {
      "package": {
        "name": "express",
        "description": "Fast, unopinionated web framework",
        "version": "4.18.2",
        "links": {
          "homepage": "http://expressjs.com/",
          "repository": "https://github.com/expressjs/express"
        }
      }
    }
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);

        let pkg = &packages[0];
        assert_eq!(pkg.name, "express");
        assert_eq!(
            pkg.description,
            Some("Fast, unopinionated web framework".into())
        );
        assert_eq!(pkg.latest_version, "4.18.2");
        assert_eq!(pkg.homepage, Some("http://expressjs.com/".into()));
    }

    #[test]
    fn test_parse_search_response_minimal() {
        let json = r#"{
  "objects": [
    {
      "package": {
        "name": "minimal-pkg",
        "version": "1.0.0"
      }
    }
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "minimal-pkg");
        assert_eq!(packages[0].description, None);
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_express_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions = registry.get_versions("express").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.version.starts_with("4.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let results = registry.search("express", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "express"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_latest_matching_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let latest = registry
            .get_latest_matching("express", "^4.0.0")
            .await
            .unwrap();

        assert!(latest.is_some());
        let version = latest.unwrap();
        assert!(version.version.starts_with("4."));
        assert!(!version.deprecated);
    }
}
