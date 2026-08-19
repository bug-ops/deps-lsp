//! NuGet V3 registry client.
//!
//! NuGet base URLs are not hardcodable: the service index
//! (`https://api.nuget.org/v3/index.json`) must be resolved first, then consulted for the
//! flat-container ("PackageBaseAddress"), search ("SearchQueryService"), and (future,
//! see D1 below) registration ("RegistrationsBaseUrl") resource URLs.

use crate::types::{NuGetVersion, PackageInfo};
use crate::version::compare_versions;
use deps_core::{HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;
use tokio::sync::OnceCell;

const SERVICE_INDEX_URL: &str = "https://api.nuget.org/v3/index.json";

#[derive(Debug, Deserialize)]
struct ServiceIndexResponse {
    resources: Vec<ServiceResource>,
}

#[derive(Debug, Deserialize)]
struct ServiceResource {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
}

/// Resolved base URLs from the NuGet service index.
#[derive(Debug, Clone)]
struct ServiceIndex {
    /// `PackageBaseAddress/3.0.0` — flat-container version enumeration.
    package_base_address: String,
    /// `SearchQueryService/3.5.0` (preferred) or bare `SearchQueryService`.
    search_query_service: String,
}

fn pick_resource(resources: &[ServiceResource], type_preference: &[&str]) -> Option<String> {
    for want in type_preference {
        if let Some(r) = resources.iter().find(|r| r.r#type == *want) {
            return Some(r.id.trim_end_matches('/').to_string());
        }
    }
    None
}

impl ServiceIndex {
    fn resolve(response: &ServiceIndexResponse) -> Result<Self> {
        let package_base_address =
            pick_resource(&response.resources, &["PackageBaseAddress/3.0.0"]).ok_or_else(|| {
                deps_core::DepsError::ParseError {
                    file_type: "NuGet service index".into(),
                    source: Box::new(std::io::Error::other(
                        "missing PackageBaseAddress/3.0.0 resource",
                    )),
                }
            })?;
        let search_query_service = pick_resource(
            &response.resources,
            &["SearchQueryService/3.5.0", "SearchQueryService"],
        )
        .ok_or_else(|| deps_core::DepsError::ParseError {
            file_type: "NuGet service index".into(),
            source: Box::new(std::io::Error::other("missing SearchQueryService resource")),
        })?;

        Ok(Self {
            package_base_address,
            search_query_service,
        })
    }
}

#[derive(Debug, Deserialize)]
struct FlatContainerIndex {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    data: Vec<SearchResultDoc>,
}

#[derive(Debug, Deserialize)]
struct SearchResultDoc {
    id: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "projectUrl")]
    project_url: Option<String>,
}

/// Returns the nuget.org package page URL for `name`.
pub fn package_url(name: &str) -> String {
    format!("https://www.nuget.org/packages/{name}")
}

#[derive(Clone)]
pub struct NuGetRegistry {
    cache: Arc<HttpCache>,
    service_index_url: String,
    service_index: Arc<OnceCell<ServiceIndex>>,
}

impl NuGetRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_service_index_url(cache, SERVICE_INDEX_URL.to_string())
    }

    fn with_service_index_url(cache: Arc<HttpCache>, service_index_url: String) -> Self {
        Self {
            cache,
            service_index_url,
            service_index: Arc::new(OnceCell::new()),
        }
    }

    /// Resolves the service index once per process, retrying on the next call if
    /// resolution failed. `get_or_try_init` (not `get_or_init`) is load-bearing: it leaves
    /// the cell empty on `Err` so a transient failure does not permanently poison lookups,
    /// and it serializes concurrent initializers so a cold start with many dependencies
    /// does not stampede the index endpoint.
    async fn service_index(&self) -> Result<&ServiceIndex> {
        self.service_index
            .get_or_try_init(|| async {
                let data = self.cache.get_cached(&self.service_index_url).await?;
                let response: ServiceIndexResponse = serde_json::from_slice(&data)?;
                ServiceIndex::resolve(&response)
            })
            .await
    }

    /// Fetches all available versions for `name` from the flat-container endpoint,
    /// sorted newest-first.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<NuGetVersion>> {
        let index = self.service_index().await?;
        let url = flat_container_url(&index.package_base_address, name);

        let data = self.cache.get_cached(&url).await?;
        parse_flat_container(&data)
    }

    /// Finds the highest version of `name` matching `req` (exact pin, interval notation,
    /// or floating pattern). Prerelease versions are excluded unless `req` itself is
    /// prerelease-bearing.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<NuGetVersion>> {
        let versions = self.get_versions_typed(name).await?;
        Ok(pick_latest_matching(versions, req))
    }

    /// Searches the NuGet `SearchQueryService` for `query`, returning up to `limit` results.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the search request fails.
    pub async fn search_typed(&self, query: &str, limit: usize) -> Result<Vec<PackageInfo>> {
        let index = self.service_index().await?;
        let url = search_url(&index.search_query_service, query, limit);

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data, limit)
    }
}

/// Builds the flat-container version-enumeration URL for `name`.
///
/// The package id is lowercased (NuGet ids are case-insensitive and every V3 API path
/// segment is lowercased) and percent-encoded before being interpolated into the path.
/// Encoding is load-bearing, not cosmetic: an unencoded id lets a crafted
/// `PackageReference Include="..."` value inject path segments (`../../etc/passwd`
/// collapses dot-segments) or truncate the path at `#`/`?`/control characters, making
/// deps-lsp silently resolve and display a *different* real package's version data under
/// an attacker-chosen name.
pub fn flat_container_url(base: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    format!("{base}/{}/index.json", urlencoding::encode(&lower))
}

/// Builds the `SearchQueryService` URL for `query`, limited to `limit` results.
///
/// `semVerLevel=2.0.0` is mandatory (spec §1) — omitting it silently hides every package
/// whose latest version uses a dotted prerelease label.
pub fn search_url(base: &str, query: &str, limit: usize) -> String {
    format!(
        "{base}?q={}&take={limit}&prerelease=false&semVerLevel=2.0.0",
        urlencoding::encode(query),
    )
}

/// Parses a flat-container `index.json` response into descending-sorted versions.
pub fn parse_flat_container(data: &[u8]) -> Result<Vec<NuGetVersion>> {
    let parsed: FlatContainerIndex = serde_json::from_slice(data)?;

    let mut versions = parsed.versions;
    // Sort locally, descending: the flat container's observed ascending order is not a
    // documented contract, so relying on `.reverse()` would silently corrupt "latest" if
    // the CDN/backend ever changes it (rev2, S3).
    versions.sort_by(|a, b| compare_versions(b, a));

    Ok(versions
        .into_iter()
        .map(|version| NuGetVersion { version })
        .collect())
}

/// Picks the highest version matching `req` from an already-fetched, descending-sorted
/// version list. `req` is treated as `"*"` when empty. Prerelease versions are excluded
/// unless `req` itself is prerelease-bearing (contains `-`) or is a floating pattern whose
/// own prerelease inclusion is handled by `crate::version::resolve_float`.
fn pick_latest_matching(versions: Vec<NuGetVersion>, req: &str) -> Option<NuGetVersion> {
    if versions.is_empty() {
        return None;
    }

    let req = if req.is_empty() { "*" } else { req };

    if req.contains('*') {
        let strings: Vec<String> = versions.iter().map(|v| v.version.clone()).collect();
        return crate::version::resolve_float(&strings, req).map(|v| NuGetVersion {
            version: v.to_string(),
        });
    }

    let req_is_prerelease_bearing = req.contains('-');
    versions.into_iter().find(|v| {
        crate::version::satisfies(&v.version, req)
            && (req_is_prerelease_bearing || !crate::version::is_prerelease(&v.version))
    })
}

fn parse_search_response(data: &[u8], limit: usize) -> Result<Vec<PackageInfo>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .data
        .into_iter()
        .take(limit)
        .map(|d| PackageInfo {
            name: d.id,
            description: d.description,
            repository: d.project_url,
            documentation: None,
            latest_version: d.version.unwrap_or_default(),
        })
        .collect())
}

// TODO(critic): unlisted versions are reported as listed; enrich from
// RegistrationsBaseUrl/3.6.0 on hover only (D1). The flat container used by get_versions
// carries no `listed` flag, and paying the extra registration-hive hop on every dependency
// in an open file is the wrong trade for the inlay-hint path.

impl deps_core::Registry for NuGetRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions_typed(name).await?;
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
            let version = self.get_latest_matching_typed(name, req).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let results = self.search_typed(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
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

    fn service_index_body(package_base_address: &str, search_query_service: &str) -> String {
        format!(
            r#"{{
                "version": "3.0.0",
                "resources": [
                    {{"@id": "{package_base_address}", "@type": "PackageBaseAddress/3.0.0"}},
                    {{"@id": "{search_query_service}", "@type": "SearchQueryService/3.5.0"}}
                ]
            }}"#
        )
    }

    #[test]
    fn test_package_url() {
        assert_eq!(
            package_url("Newtonsoft.Json"),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
    }

    #[test]
    fn test_flat_container_url_lowercases_and_encodes() {
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Newtonsoft.Json"),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_path_traversal_attempt() {
        // A crafted `Include="../../../../etc/passwd"` must not produce raw dot-segments
        // that a URL-parsing layer could collapse across path boundaries.
        let url = flat_container_url(
            "https://api.nuget.org/v3-flatcontainer",
            "../../../../etc/passwd",
        );
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/..%2F..%2F..%2F..%2Fetc%2Fpasswd/index.json"
        );
        assert!(
            !url.contains("/../"),
            "raw path traversal segment leaked into URL: {url}"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_fragment_and_query_delimiters() {
        // '#'/'?' must not be able to truncate the path and silently resolve as a
        // different, shorter package name.
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo#x"),
            "https://api.nuget.org/v3-flatcontainer/foo%23x/index.json"
        );
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo?x=1"),
            "https://api.nuget.org/v3-flatcontainer/foo%3Fx%3D1/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_control_characters() {
        let url = flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo\tBar");
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/foo%09bar/index.json"
        );
    }

    #[test]
    fn test_search_url_includes_mandatory_semver_level_and_prerelease_false() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "json", 10);
        assert_eq!(
            url,
            "https://azuresearch-usnc.nuget.org/query?q=json&take=10&prerelease=false&semVerLevel=2.0.0"
        );
    }

    #[test]
    fn test_search_url_encodes_query() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "a b&c", 5);
        assert!(url.contains("q=a%20b%26c"), "query not encoded: {url}");
    }

    #[test]
    fn test_service_index_resolve_success() {
        let response: ServiceIndexResponse = serde_json::from_str(&service_index_body(
            "https://api.nuget.org/v3-flatcontainer/",
            "https://azuresearch-usnc.nuget.org/query",
        ))
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(
            index.package_base_address,
            "https://api.nuget.org/v3-flatcontainer"
        );
        assert_eq!(
            index.search_query_service,
            "https://azuresearch-usnc.nuget.org/query"
        );
    }

    #[test]
    fn test_service_index_resolve_missing_resource_errors() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [{"@id": "https://x", "@type": "SomeOtherType"}]}"#,
        )
        .unwrap();
        assert!(ServiceIndex::resolve(&response).is_err());
    }

    #[test]
    fn test_service_index_search_query_service_fallback() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(index.search_query_service, "https://search");
    }

    #[test]
    fn test_parse_flat_container_sorted_descending() {
        let data = br#"{"versions": ["12.0.1", "13.0.3", "13.0.0-beta1"]}"#;
        let versions = parse_flat_container(data).unwrap();
        let strings: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(strings, vec!["13.0.3", "13.0.0-beta1", "12.0.1"]);
    }

    #[test]
    fn test_parse_flat_container_empty() {
        let data = br#"{"versions": []}"#;
        let versions = parse_flat_container(data).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_flat_container_invalid_json_errors() {
        assert!(parse_flat_container(b"not json").is_err());
    }

    #[test]
    fn test_parse_search_response() {
        let data = br#"{"totalHits": 1, "data": [{"id": "Newtonsoft.Json", "version": "13.0.3", "description": "JSON framework", "projectUrl": "https://example.com"}]}"#;
        let results = parse_search_response(data, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Newtonsoft.Json");
        assert_eq!(results[0].latest_version, "13.0.3");
        assert_eq!(
            results[0].repository.as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn test_parse_search_response_respects_limit() {
        let data = br#"{"totalHits": 2, "data": [
            {"id": "A", "version": "1.0.0"},
            {"id": "B", "version": "2.0.0"}
        ]}"#;
        let results = parse_search_response(data, 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "A");
    }

    fn v(s: &str) -> NuGetVersion {
        NuGetVersion {
            version: s.to_string(),
        }
    }

    #[test]
    fn test_pick_latest_matching_wildcard_excludes_prerelease() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "*");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_empty_req_behaves_like_wildcard() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_exact_pin() {
        let versions = vec![v("1.0.1"), v("1.0.0")];
        let matched = pick_latest_matching(versions, "[1.0.0]");
        assert_eq!(matched.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_floating_prefix() {
        let versions = vec![v("1.2.0"), v("1.1.5"), v("1.1.0")];
        let matched = pick_latest_matching(versions, "1.1.*");
        assert_eq!(matched.unwrap().version, "1.1.5");
    }

    #[test]
    fn test_pick_latest_matching_prerelease_bearing_requirement_allows_prerelease() {
        let versions = vec![v("1.0.0-rc.2"), v("0.9.0")];
        let matched = pick_latest_matching(versions, "[1.0.0-rc.2]");
        assert_eq!(matched.unwrap().version, "1.0.0-rc.2");
    }

    #[test]
    fn test_pick_latest_matching_empty_versions_returns_none() {
        assert!(pick_latest_matching(vec![], "*").is_none());
    }

    #[test]
    fn test_pick_latest_matching_no_match_returns_none() {
        let versions = vec![v("2.0.0")];
        assert!(pick_latest_matching(versions, "[1.0.0]").is_none());
    }

    #[test]
    fn test_registry_creation_and_trait_impls() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert_eq!(
            registry.package_url("Newtonsoft.Json"),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
        assert!(registry.as_any().is::<NuGetRegistry>());
    }

    #[test]
    fn test_with_service_index_url_used_by_new() {
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert_eq!(registry.service_index_url, SERVICE_INDEX_URL);
    }
}
