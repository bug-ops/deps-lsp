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

/// `Accept` header requesting the abbreviated packument format, which omits
/// README, changelog, and per-version `dist.signatures` data that
/// `get_versions` never uses. Cuts response size by roughly 60% (verified
/// against `express`: 804,975 bytes full vs 339,376 bytes abbreviated).
const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";

/// Display name for the npm registry used in not-found and API-response
/// error messages.
pub const REGISTRY: &str = "npm";

/// Base URL for package pages on npmjs.com
pub const NPMJS_URL: &str = "https://www.npmjs.com/package";

/// Returns the URL for a package's page on npmjs.com.
///
/// Scoped packages (`@scope/name`) keep their `@` and `/` structure — each segment is
/// percent-encoded individually so the URL still resolves, while everything else
/// (including any attempt to smuggle extra path or Markdown syntax into a segment) is
/// escaped.
pub fn package_url(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@')
        && let Some((scope, pkg)) = rest.split_once('/')
    {
        return format!(
            "{NPMJS_URL}/@{}/{}",
            urlencoding::encode(scope),
            urlencoding::encode(pkg)
        );
    }
    format!("{}/{}", NPMJS_URL, urlencoding::encode(name))
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
    /// Requests the abbreviated packument (`Accept:
    /// application/vnd.npm.install-v1+json`), which omits README, changelog,
    /// and other fields `get_versions` doesn't need while keeping per-version
    /// `deprecated` status.
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
        let data = self
            .cache
            .get_cached_with_headers(&url, &[(reqwest::header::ACCEPT, ABBREVIATED_ACCEPT)])
            .await
            .map_err(|e| not_found_or(e, name))?;

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

// Implement Registry trait for NpmRegistry
impl deps_core::Registry for NpmRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name).await?;
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
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self.get_latest_matching(name, req).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let packages = self.search(query, limit).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url_plain() {
        assert_eq!(package_url("react"), "https://www.npmjs.com/package/react");
    }

    #[test]
    fn test_package_url_scoped_preserves_structure() {
        assert_eq!(
            package_url("@types/node"),
            "https://www.npmjs.com/package/@types/node"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_name() {
        let url = package_url("evil)[pkg](https://evil.example");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_scoped_encodes_malicious_segments() {
        let url = package_url("@evil)[/pkg](x");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_scoped_encodes_newline_and_percent() {
        let url = package_url("@evil\n<%/pkg");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://www.npmjs.com/package/");
    }

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

    #[test]
    fn test_parse_abbreviated_packument() {
        // Realistic shape of `Accept: application/vnd.npm.install-v1+json`
        // response (captured live from `registry.npmjs.org/left-pad`):
        // no README/changelog, per-version `dist`/`devDependencies` kept.
        let json = r#"{
  "name": "left-pad",
  "dist-tags": {
    "latest": "1.3.0"
  },
  "versions": {
    "1.2.0": {
      "name": "left-pad",
      "version": "1.2.0",
      "dist": {
        "shasum": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
        "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
      }
    },
    "1.3.0": {
      "name": "left-pad",
      "version": "1.3.0",
      "dist": {
        "shasum": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
        "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
      },
      "deprecated": "use String.prototype.padStart()"
    }
  },
  "modified": "2022-01-01T00:00:00.000Z"
}"#;

        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "1.3.0");
        assert!(versions[0].deprecated);
        assert_eq!(versions[1].version, "1.2.0");
        assert!(!versions[1].deprecated);
    }

    #[test]
    fn test_parse_abbreviated_packument_zero_versions() {
        let json = r#"{"name": "empty-pkg", "dist-tags": {}, "versions": {}}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_abbreviated_packument_all_deprecated() {
        let json = r#"{
  "name": "old-pkg",
  "versions": {
    "1.0.0": {"deprecated": "use new-pkg instead"},
    "2.0.0": {"deprecated": "use new-pkg instead"}
  }
}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.deprecated));
    }

    #[test]
    fn test_parse_abbreviated_packument_unusual_version_strings_skipped() {
        // Non-semver keys (build metadata typos, unicode, empty string) must
        // be filtered out rather than panicking or corrupting the sort.
        let json = r#"{
  "name": "weird-pkg",
  "versions": {
    "1.0.0": {},
    "not-a-version": {},
    "": {},
    "1.0.0-😀": {},
    "1.0.0+build.1": {}
  }
}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().any(|v| v.version == "1.0.0"));
        assert!(versions.iter().any(|v| v.version == "1.0.0+build.1"));
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://registry.npmjs.org/left-pad".into(),
            status: 404,
        };
        let result = not_found_or(err, "left-pad");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "left-pad" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        let err = DepsError::HttpStatus {
            url: "https://registry.npmjs.org/pkg-404".into(),
            status: 500,
        };
        let result = not_found_or(err, "pkg-404");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
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
