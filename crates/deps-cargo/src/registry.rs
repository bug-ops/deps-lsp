//! crates.io registry client.
//!
//! Provides access to crates.io via:
//! - Sparse index protocol (<https://index.crates.io>) for version lookups
//! - REST API (<https://crates.io/api/v1>) for search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::CratesIoRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let registry = CratesIoRegistry::new(cache);
//!
//!     let versions = registry.get_versions("serde").await.unwrap();
//!     println!("Latest serde: {}", versions[0].num);
//! }
//! ```

use crate::types::{CargoVersion, CrateInfo};
use deps_core::{DepsError, HttpCache, Result};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

const SPARSE_INDEX_BASE: &str = "https://index.crates.io";
const SEARCH_API_BASE: &str = "https://crates.io/api/v1";

/// Base URL for crate pages on crates.io
pub const CRATES_IO_URL: &str = "https://crates.io/crates";

/// Returns the URL for a crate's page on crates.io.
pub fn crate_url(name: &str) -> String {
    format!("{}/{}", CRATES_IO_URL, name)
}

/// Client for interacting with crates.io registry.
///
/// Uses the sparse index protocol for fast version lookups and the REST API
/// for package search. All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct CratesIoRegistry {
    cache: Arc<HttpCache>,
}

impl CratesIoRegistry {
    /// Creates a new registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a crate from the sparse index.
    ///
    /// Returns versions sorted newest-first. Includes yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("serde").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<CargoVersion>> {
        let path = sparse_index_path(name);
        let url = format!("{}/{}", SPARSE_INDEX_BASE, path);

        let data = self.cache.get_cached(&url).await?;

        parse_index_json(&data, name)
    }

    /// Finds the latest version matching the given semver requirement.
    ///
    /// Only returns non-yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Version requirement string is invalid semver
    /// - HTTP request fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("serde", "^1.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<CargoVersion>> {
        let versions = self.get_versions(name).await?;

        let req = req_str
            .parse::<VersionReq>()
            .map_err(|e| DepsError::InvalidVersionReq(e.to_string()))?;

        Ok(versions.into_iter().find(|v| {
            let version = v.num.parse::<Version>().ok();
            version.is_some_and(|ver| req.matches(&ver) && !v.yanked)
        }))
    }

    /// Searches for crates by name/keywords.
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
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let results = registry.search("serde", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<CrateInfo>> {
        let url = format!(
            "{}/crates?q={}&per_page={}",
            SEARCH_API_BASE,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Converts a crate name to its sparse index path.
///
/// Based on Cargo RFC 2789 specification:
/// - 1 char: "1/{name}"
/// - 2 chars: "2/{name}"
/// - 3 chars: "3/{first_char}/{name}"
/// - 4+ chars: "{first_2}/{next_2}/{name}"
fn sparse_index_path(name: &str) -> String {
    let name_lower = name.to_lowercase();
    match name_lower.len() {
        1 => format!("1/{}", name_lower),
        2 => format!("2/{}", name_lower),
        3 => format!("3/{}/{}", &name_lower[0..1], name_lower),
        _ => format!("{}/{}/{}", &name_lower[0..2], &name_lower[2..4], name_lower),
    }
}

/// Entry in the sparse index (one line of newline-delimited JSON).
#[derive(Deserialize)]
struct IndexEntry {
    #[serde(rename = "vers")]
    version: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    features: HashMap<String, Vec<String>>,
}

/// Parses newline-delimited JSON from sparse index.
fn parse_index_json(data: &[u8], _crate_name: &str) -> Result<Vec<CargoVersion>> {
    let content = std::str::from_utf8(data)
        .map_err(|e| DepsError::CacheError(format!("Invalid UTF-8: {}", e)))?;

    let mut versions: Vec<CargoVersion> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let entry: IndexEntry = serde_json::from_str(line).ok()?;
            Some(CargoVersion {
                num: entry.version,
                yanked: entry.yanked,
                features: entry.features,
            })
        })
        .collect();

    versions.sort_by(|a, b| {
        let ver_a = a.num.parse::<Version>().ok();
        let ver_b = b.num.parse::<Version>().ok();
        match (ver_a, ver_b) {
            (Some(a), Some(b)) => b.cmp(&a),
            _ => std::cmp::Ordering::Equal,
        }
    });

    Ok(versions)
}

/// Response from crates.io search API.
#[derive(Deserialize)]
struct SearchResponse {
    crates: Vec<SearchCrate>,
}

/// Crate entry in search response.
#[derive(Deserialize)]
struct SearchCrate {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
    max_version: String,
}

/// Parses JSON response from crates.io search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<CrateInfo>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .crates
        .into_iter()
        .map(|c| CrateInfo {
            name: c.name,
            description: c.description,
            repository: c.repository,
            documentation: c.documentation,
            max_version: c.max_version,
        })
        .collect())
}

// Implement PackageRegistry trait for CratesIoRegistry
#[async_trait::async_trait]
impl deps_core::PackageRegistry for CratesIoRegistry {
    type Version = CargoVersion;
    type Metadata = CrateInfo;
    type VersionReq = VersionReq;

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

// Implement VersionInfo trait for CargoVersion
impl deps_core::VersionInfo for CargoVersion {
    fn version_string(&self) -> &str {
        &self.num
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn features(&self) -> Vec<String> {
        self.features.keys().cloned().collect()
    }
}

// Implement PackageMetadata trait for CrateInfo
impl deps_core::PackageMetadata for CrateInfo {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.repository.as_deref()
    }

    fn documentation(&self) -> Option<&str> {
        self.documentation.as_deref()
    }

    fn latest_version(&self) -> &str {
        &self.max_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_index_path() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn test_sparse_index_path_uppercase() {
        assert_eq!(sparse_index_path("SERDE"), "se/rd/serde");
    }

    #[test]
    fn test_parse_index_json() {
        let json = r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}
{"name":"serde","vers":"1.0.1","yanked":false,"features":{"derive":["serde_derive"]},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "serde").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "1.0.1");
        assert_eq!(versions[1].num, "1.0.0");
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_index_json_with_yanked() {
        let json = r#"{"name":"test","vers":"0.1.0","yanked":true,"features":{},"deps":[]}
{"name":"test","vers":"0.2.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions[1].yanked);
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "crates": [
                {
                    "name": "serde",
                    "description": "A serialization framework",
                    "repository": "https://github.com/serde-rs/serde",
                    "documentation": "https://docs.rs/serde",
                    "max_version": "1.0.214"
                }
            ]
        }"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "serde");
        assert_eq!(results[0].max_version, "1.0.214");
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_serde_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions = registry.get_versions("serde").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.num.starts_with("1.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let results = registry.search("serde", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "serde"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_latest_matching_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let latest = registry.get_latest_matching("serde", "^1.0").await.unwrap();

        assert!(latest.is_some());
        let version = latest.unwrap();
        assert!(version.num.starts_with("1."));
        assert!(!version.yanked);
    }
}
