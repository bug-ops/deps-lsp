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
const PACKAGIST_WEB: &str = "https://packagist.org/packages";

/// Returns the URL for a package's page on packagist.org.
///
/// Packagist names are `vendor/package`; each segment is percent-encoded
/// individually so the `/` separator survives while any Markdown/URL-breaking
/// characters in a segment are escaped.
pub fn package_url(name: &str) -> String {
    if let Some((vendor, package)) = name.split_once('/') {
        format!(
            "{PACKAGIST_WEB}/{}/{}",
            urlencoding::encode(vendor),
            urlencoding::encode(package)
        )
    } else {
        format!("{PACKAGIST_WEB}/{}", urlencoding::encode(name))
    }
}

/// Display name for Packagist used in not-found and API-response error messages.
pub const REGISTRY: &str = "Packagist";

/// Client for interacting with the Packagist registry.
///
/// Uses the Packagist v2 API for package metadata and search.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct PackagistRegistry {
    cache: Arc<HttpCache>,
    base: String,
}

impl PackagistRegistry {
    /// Creates a new Packagist registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_registry_base(cache, PACKAGIST_BASE.to_string())
    }

    /// Registry base URL — `PACKAGIST_BASE` in production, overridden to a mockito
    /// server URL in tests (mirrors `deps-npm`'s `with_registry_base`).
    fn with_registry_base(cache: Arc<HttpCache>, base: String) -> Self {
        Self { cache, base }
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
        let base = &self.base;
        let url = if let Some((vendor, package)) = name.split_once('/') {
            format!(
                "{base}/p2/{}/{}.json",
                urlencoding::encode(vendor),
                urlencoding::encode(package)
            )
        } else {
            format!("{base}/p2/{}.json", urlencoding::encode(name))
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
            .find(|v| formatter.version_satisfies_requirement(&v.version, req_str)))
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
///
/// `time` is deliberately excluded from this inheritance scheme (see
/// [`expand_minified_versions`]): every entry carries its own `time` (87/87
/// live-verified on `monolog/monolog`), and inheriting it across entries
/// would attribute one release's publish date to another.
#[derive(Deserialize, Clone, Default)]
struct MinifiedVersion {
    version: Option<String>,
    version_normalized: Option<String>,
    abandoned: Option<serde_json::Value>,
    /// Publish timestamp (RFC 3339, e.g. `"2026-01-02T08:56:05+00:00"`).
    #[serde(default)]
    time: Option<String>,
}

/// Expands minified Packagist v2 versions using field inheritance.
///
/// The v2 API compresses responses: only the first entry is complete.
/// Each subsequent entry inherits fields from the previous one and overrides
/// only the fields that changed. `time` is the one exception: it is read
/// only from the entry itself, never inherited, since a missing `time` means
/// the release genuinely has no known publish date, not that it shares the
/// previous release's date.
///
/// Dev versions (`dev-*` or `*-dev`) are filtered out.
fn expand_minified_versions(entries: Vec<MinifiedVersion>) -> Vec<ComposerVersion> {
    let mut result = Vec::new();
    let mut current = MinifiedVersion::default();

    for entry in entries {
        // `time` is not part of the inherited state; read it before `entry`
        // is partially consumed below.
        let published_at = entry
            .time
            .as_deref()
            .and_then(deps_core::PublishTime::parse_rfc3339);

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
            published_at,
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
            name: r.name.into(),
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
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
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
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching(name.as_str(), req.as_str())
                .await?;
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

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        let formatter = crate::formatter::ComposerFormatter;
        use deps_core::lsp_helpers::EcosystemFormatter;

        versions.iter().position(|v| {
            // Always true for Composer (`abandoned` maps to `AdvisoryDeprecated`, which
            // never blocks resolution) — kept to document the contract (#347).
            !v.removal_status().blocks_resolution()
                && formatter.version_satisfies_requirement(v.version_string(), req.as_str())
        })
    }

    // Packagist's `abandoned` is package-level, not per-version: `removal_status`
    // reports `AdvisoryDeprecated` for "this package is abandoned", inherited by
    // every version via the p2 minified-inheritance loop. Enabling the yanked
    // diagnostic here would fire on nearly every version of an abandoned package
    // (#233 R2, #205).
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
    fn test_package_url_preserves_vendor_package() {
        assert_eq!(
            package_url("symfony/console"),
            "https://packagist.org/packages/symfony/console"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_segments() {
        let url = package_url("evil)[/pkg](x");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<%>/pkg");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://packagist.org/packages/");
    }

    #[test]
    fn test_expand_minified_versions_basic() {
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("2.0.0".into()),
                version_normalized: Some("2.0.0.0".into()),
                abandoned: None,
                time: None,
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
                time: None,
            },
            MinifiedVersion {
                version: Some("2.9.0".into()),
                version_normalized: None, // inherited
                abandoned: None,
                time: None,
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
                time: None,
            },
            MinifiedVersion {
                version: Some("dev-main".into()),
                version_normalized: None,
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("2.0.0-dev".into()),
                version_normalized: None,
                abandoned: None,
                time: None,
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
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(versions[0].abandoned);
    }

    #[test]
    fn test_expand_minified_versions_with_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: Some("2026-01-02T08:56:05+00:00".into()),
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            deps_core::PublishTime::parse_rfc3339("2026-01-02T08:56:05+00:00")
        );
    }

    #[test]
    fn test_expand_minified_versions_without_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_expand_minified_versions_with_malformed_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: Some("not-a-timestamp".into()),
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed time degrades to None, not an error"
        );
    }

    #[test]
    fn test_expand_minified_versions_time_is_not_inherited() {
        // Correctness requirement: an entry with no `time` must yield `None`
        // for that entry, never the previous entry's `time` — unlike
        // `version_normalized`/`abandoned`, which do inherit.
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: Some("2026-01-02T08:56:05+00:00".into()),
            },
            MinifiedVersion {
                version: Some("2.9.0".into()),
                version_normalized: None, // inherited
                abandoned: None,
                time: None, // must NOT inherit the previous entry's time
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert!(versions[0].published_at.is_some());
        assert!(
            versions[1].published_at.is_none(),
            "time must not be inherited from the previous entry"
        );
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

    #[test]
    fn test_select_latest_matching_not_default_none() {
        // Regression for #347's mixed case: the newest version is abandoned, an older
        // version is clean. Composer has no npm-style ranking preference for a
        // non-abandoned version over a newer abandoned one (unlike deps-npm's #338
        // NFR-002) — `abandoned` is advisory, not a hard removal from resolution, so
        // the newest version resolves as latest regardless of its abandoned flag.
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0".into(),
                version_normalized: "2.0.0.0".into(),
                abandoned: true,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_select_latest_matching_all_abandoned_still_resolves() {
        // Regression test for #347: an abandoned package's versions must
        // still resolve under a wildcard requirement — `abandoned` is
        // advisory, not a hard removal from resolution.
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0".into(),
                version_normalized: "2.0.0.0".into(),
                abandoned: true,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: true,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #347's other half (S2): the inherent `get_latest_matching` —
    /// the fetch loop's fallback when the pure list-based `select_latest_matching`
    /// pick finds nothing, and the path `diagnostics.rs`'s live-lookup exercises
    /// directly — must also resolve an all-abandoned package instead of treating it
    /// as non-existent. Mirrors `deps-npm`'s
    /// `test_get_latest_matching_wildcard_all_deprecated_returns_newest` shape.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_all_abandoned_still_resolves() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/abandoned-pkg.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/abandoned-pkg": [
                    {"version": "2.0.0", "version_normalized": "2.0.0.0", "abandoned": true},
                    {"version": "1.0.0", "version_normalized": "1.0.0.0", "abandoned": true}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("vendor/abandoned-pkg", "*")
            .await
            .unwrap();

        let version = latest.expect("an all-abandoned package still exists and resolves");
        assert_eq!(version.version, "2.0.0");
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
