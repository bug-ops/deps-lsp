//! Packagist registry client.
//!
//! Provides access to the Packagist registry via:
//! - Package metadata API (<https://repo.packagist.org/p2/{vendor}/{package}.json>) for version lookups
//! - Search API (<https://packagist.org/search.json>) for package search
//!
//! The Packagist v2 API returns minified metadata where only the first version entry
//! is complete. Subsequent entries contain only changed fields and must be expanded
//! by inheriting from the previous complete entry.

use crate::types::{ComposerPackage, ComposerVersion};
use deps_core::{DepsError, HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PACKAGIST_BASE: &str = "https://repo.packagist.org";
const PACKAGIST_SEARCH: &str = "https://packagist.org/search.json";

/// Client for interacting with the Packagist registry.
///
/// Uses the Packagist v2 API for package metadata and search.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct PackagistRegistry {
    cache: Arc<HttpCache>,
}

impl PackagistRegistry {
    /// Creates a new Packagist registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package from the Packagist v2 API.
    ///
    /// Filters out dev versions (starting with `dev-` or ending with `-dev`).
    /// Returns versions in the order returned by the API (newest first).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request or JSON parsing fails.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<ComposerVersion>> {
        // Packagist names are vendor/package; encode each segment separately
        let url = if let Some((vendor, package)) = name.split_once('/') {
            format!(
                "{PACKAGIST_BASE}/p2/{}/{}.json",
                urlencoding::encode(vendor),
                urlencoding::encode(package)
            )
        } else {
            format!("{PACKAGIST_BASE}/p2/{}.json", urlencoding::encode(name))
        };
        let data = self.cache.get_cached(&url).await?;
        parse_package_metadata(name, &data)
    }

    /// Finds the latest non-abandoned version satisfying the given requirement.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<ComposerVersion>> {
        let versions = self.get_versions(name).await?;
        let formatter = crate::formatter::ComposerFormatter;
        use deps_core::lsp_helpers::EcosystemFormatter;

        Ok(versions
            .into_iter()
            .find(|v| !v.abandoned && formatter.version_satisfies_requirement(&v.version, req_str)))
    }

    /// Searches for packages by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request or JSON parsing fails.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<ComposerPackage>> {
        let url = format!(
            "{}?q={}&per_page={}",
            PACKAGIST_SEARCH,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Packagist v2 API response (outer wrapper).
#[derive(Deserialize)]
struct PackagistResponse {
    packages: std::collections::HashMap<String, Vec<MinifiedVersion>>,
}

/// Minified version entry from Packagist v2 API.
///
/// The v2 API returns only the first version as complete. Subsequent entries
/// contain only fields that changed from the previous entry.
#[derive(Deserialize, Clone, Default)]
struct MinifiedVersion {
    version: Option<String>,
    version_normalized: Option<String>,
    abandoned: Option<serde_json::Value>,
}

/// Expands minified Packagist v2 versions using field inheritance.
///
/// The v2 API compresses responses: only the first entry is complete.
/// Each subsequent entry inherits fields from the previous one and overrides
/// only the fields that changed.
///
/// Dev versions (`dev-*` or `*-dev`) are filtered out.
fn expand_minified_versions(entries: Vec<MinifiedVersion>) -> Vec<ComposerVersion> {
    let mut result = Vec::new();
    let mut current = MinifiedVersion::default();

    for entry in entries {
        // Inherit previous state, then apply overrides
        if entry.version.is_some() {
            current.version = entry.version;
        }
        if entry.version_normalized.is_some() {
            current.version_normalized = entry.version_normalized;
        }
        if entry.abandoned.is_some() {
            current.abandoned = entry.abandoned;
        }

        let Some(ref version) = current.version else {
            continue;
        };

        // Filter dev versions
        if version.starts_with("dev-") || version.ends_with("-dev") {
            continue;
        }

        let abandoned = current
            .abandoned
            .as_ref()
            .is_some_and(|v| v.as_bool() == Some(true) || v.is_string());

        result.push(ComposerVersion {
            version: version.clone(),
            version_normalized: current
                .version_normalized
                .clone()
                .unwrap_or_else(|| version.clone()),
            abandoned,
        });
    }

    result
}

/// Parses Packagist v2 API response JSON.
fn parse_package_metadata(name: &str, data: &[u8]) -> Result<Vec<ComposerVersion>> {
    let response: PackagistResponse = serde_json::from_slice(data).map_err(DepsError::Json)?;

    // Packagist uses lowercase package names as keys
    let key = name.to_lowercase();
    let entries = response.packages.get(&key).cloned().unwrap_or_default();

    Ok(expand_minified_versions(entries))
}

/// Packagist search API response.
#[derive(Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

/// Individual search result.
#[derive(Deserialize)]
struct SearchResult {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

/// Parses Packagist search API response.
fn parse_search_response(data: &[u8]) -> Result<Vec<ComposerPackage>> {
    let response: SearchResponse = serde_json::from_slice(data).map_err(DepsError::Json)?;

    Ok(response
        .results
        .into_iter()
        .map(|r| ComposerPackage {
            name: r.name,
            description: r.description,
            repository: r.repository,
            homepage: r.url,
            latest_version: r.version.unwrap_or_default(),
        })
        .collect())
}

impl deps_core::Registry for PackagistRegistry {
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
        format!("https://packagist.org/packages/{name}")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_minified_versions_basic() {
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
            },
            MinifiedVersion {
                version: Some("2.0.0".into()),
                version_normalized: Some("2.0.0.0".into()),
                abandoned: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[1].version, "2.0.0");
        assert!(!versions[0].abandoned);
    }

    #[test]
    fn test_expand_minified_versions_field_inheritance() {
        // Second entry inherits version_normalized from first, only version changes
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
            },
            MinifiedVersion {
                version: Some("2.9.0".into()),
                version_normalized: None, // inherited
                abandoned: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].version, "2.9.0");
        assert_eq!(versions[1].version_normalized, "3.0.0.0"); // inherited
    }

    #[test]
    fn test_expand_minified_versions_filters_dev() {
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
            },
            MinifiedVersion {
                version: Some("dev-main".into()),
                version_normalized: None,
                abandoned: None,
            },
            MinifiedVersion {
                version: Some("2.0.0-dev".into()),
                version_normalized: None,
                abandoned: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "3.0.0");
    }

    #[test]
    fn test_expand_minified_versions_abandoned() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: Some(serde_json::Value::String("Use other/package".into())),
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(versions[0].abandoned);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
  "results": [
    {
      "name": "symfony/console",
      "description": "Symfony Console Component",
      "version": "6.0.0",
      "url": "https://packagist.org/packages/symfony/console",
      "repository": "https://github.com/symfony/console"
    }
  ],
  "total": 1
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);

        let pkg = &packages[0];
        assert_eq!(pkg.name, "symfony/console");
        assert_eq!(pkg.description, Some("Symfony Console Component".into()));
        assert_eq!(pkg.latest_version, "6.0.0");
    }

    #[test]
    fn test_parse_package_metadata() {
        let json = r#"{
  "packages": {
    "monolog/monolog": [
      {
        "version": "3.0.0",
        "version_normalized": "3.0.0.0",
        "abandoned": null
      },
      {
        "version": "2.0.0",
        "version_normalized": "2.0.0.0"
      }
    ]
  }
}"#;

        let versions = parse_package_metadata("monolog/monolog", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "3.0.0");
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_monolog_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = registry.get_versions("monolog/monolog").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.version.starts_with("3.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let results = registry.search("symfony", 5).await.unwrap();

        assert!(!results.is_empty());
    }
}
