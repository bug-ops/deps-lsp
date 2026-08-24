//! pub.dev registry client.

use crate::types::{DartVersion, PackageInfo};
use crate::version::compare_versions;
use deps_core::{DepsError, HttpCache, Result, is_dot_segment, lsp_helpers::warn_rejected_value};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PUB_DEV_API_BASE: &str = "https://pub.dev/api";

/// Display name for pub.dev used in not-found and API-response error messages.
pub const REGISTRY: &str = "pub.dev";

pub fn package_url(name: &str) -> String {
    format!("https://pub.dev/packages/{}", urlencoding::encode(name))
}

/// Builds the pub.dev registry request URL for a package's metadata (versions or info —
/// both live at the same `/api/packages/{name}` endpoint).
///
/// Unlike `package_url` (a display link, never fetched), this is a fetch sink: `name` is
/// percent-encoded, but a `name` of exactly `.`/`..` survives encoding unchanged (`.` is an
/// unreserved character) and is only rejected by the caller's [`is_dot_segment`] guard, run
/// *before* this function — see that predicate's doc for why encoding alone is insufficient
/// (#349). Takes `base` (rather than reading [`PUB_DEV_API_BASE`] directly) so tests can
/// point it at a mockito server.
fn package_metadata_url(base: &str, name: &str) -> String {
    format!("{base}/packages/{}", urlencoding::encode(name))
}

/// Rejects a dot-segment `name` before it would reach [`package_metadata_url`], as
/// `DepsError::PackageNotFound` — mirroring `deps-npm`'s identical guard for the same
/// vulnerability class (#341/#349): percent-encoding a pub.dev package name does not stop
/// the URL parser's dot-segment normalization from retargeting the request (`..` escapes
/// the `/api/packages/` prefix entirely; `.` collapses it to `/api/packages/`).
fn reject_dot_segment(name: &str) -> Result<()> {
    if is_dot_segment(name) {
        warn_rejected_value(
            "is_dot_segment",
            "pub.dev package metadata request URL",
            name,
        );
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct PubDevRegistry {
    cache: Arc<HttpCache>,
    /// API base URL — [`PUB_DEV_API_BASE`] in production, overridden to a mockito server
    /// URL in tests via [`Self::with_base`] (mirrors `deps-npm`'s
    /// `NpmRegistry::with_registry_base`).
    base: String,
}

impl PubDevRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            cache,
            base: PUB_DEV_API_BASE.to_string(),
        }
    }

    /// Creates a registry client pointed at a custom API base URL, for pointing at a
    /// mockito server in tests.
    #[cfg(test)]
    fn with_base(cache: Arc<HttpCache>, base: String) -> Self {
        Self { cache, base }
    }

    pub async fn get_versions(&self, name: &str) -> Result<Vec<DartVersion>> {
        reject_dot_segment(name)?;
        let url = package_metadata_url(&self.base, name);
        let data = self.cache.get_cached(&url).await?;
        parse_versions_response(&data)
    }

    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<DartVersion>> {
        let versions = self.get_versions(name).await?;
        Ok(versions.into_iter().find(|v| {
            crate::version::version_matches_constraint(&v.version, req_str) && !v.retracted
        }))
    }

    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<PackageInfo>> {
        let url = format!("{}/search?q={}", self.base, urlencoding::encode(query));
        let data = self.cache.get_cached(&url).await?;
        let search_result: SearchResponse = serde_json::from_slice(&data)?;

        let mut results = Vec::new();
        for entry in search_result.packages.into_iter().take(limit) {
            // Fetch metadata for each package. `entry.package` is registry-derived (the
            // search response), exactly as untrusted as a manifest-declared name — routed
            // through the same guard + encoding as `get_versions`/`get_package_info` rather
            // than interpolated directly (#349).
            if reject_dot_segment(&entry.package).is_err() {
                continue;
            }
            let pkg_url = package_metadata_url(&self.base, &entry.package);
            if let Ok(pkg_data) = self.cache.get_cached(&pkg_url).await
                && let Ok(info) = parse_package_info(&pkg_data)
            {
                results.push(info);
            }
        }

        Ok(results)
    }

    pub async fn get_package_info(&self, name: &str) -> Result<PackageInfo> {
        reject_dot_segment(name)?;
        let url = package_metadata_url(&self.base, name);
        let data = self.cache.get_cached(&url).await?;
        parse_package_info(&data)
    }
}

#[derive(Deserialize)]
struct PackageResponse {
    name: String,
    latest: VersionDetail,
    versions: Vec<VersionEntry>,
}

#[derive(Deserialize)]
struct VersionEntry {
    version: String,
    #[serde(default)]
    retracted: bool,
    published: Option<String>,
}

#[derive(Deserialize)]
struct VersionDetail {
    version: String,
    pubspec: Option<PubspecMeta>,
}

#[derive(Deserialize)]
struct PubspecMeta {
    name: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    documentation: Option<String>,
}

#[derive(Deserialize)]
struct SearchResponse {
    #[serde(default)]
    packages: Vec<SearchEntry>,
}

#[derive(Deserialize)]
struct SearchEntry {
    package: String,
}

fn parse_versions_response(data: &[u8]) -> Result<Vec<DartVersion>> {
    let response: PackageResponse = serde_json::from_slice(data)?;

    let mut versions: Vec<DartVersion> = response
        .versions
        .into_iter()
        .map(|e| DartVersion {
            version: e.version,
            retracted: e.retracted,
            published_at: e
                .published
                .as_deref()
                .and_then(deps_core::PublishTime::parse_rfc3339),
        })
        .collect();

    versions.sort_by(|a, b| compare_versions(&b.version, &a.version));

    Ok(versions)
}

fn parse_package_info(data: &[u8]) -> Result<PackageInfo> {
    let response: PackageResponse = serde_json::from_slice(data)?;
    let pubspec = response.latest.pubspec.unwrap_or(PubspecMeta {
        name: Some(response.name.clone()),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
    });

    Ok(PackageInfo {
        name: pubspec.name.unwrap_or(response.name).into(),
        description: pubspec.description,
        homepage: pubspec.homepage,
        repository: pubspec.repository,
        documentation: pubspec.documentation,
        version: response.latest.version,
        license: None,
    })
}

impl deps_core::Version for DartVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.retracted
    }

    fn is_prerelease(&self) -> bool {
        crate::version::is_prerelease(&self.version)
    }

    fn published_at(&self) -> Option<deps_core::PublishTime> {
        self.published_at
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl deps_core::Metadata for PackageInfo {
    fn name(&self) -> &deps_core::PackageName {
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
        &self.version
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Registry trait (trait object support)
impl deps_core::Registry for PubDevRegistry {
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
            let results = self.search(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        versions.iter().position(|v| {
            crate::version::version_matches_constraint(v.version_string(), req.as_str())
                && !v.is_yanked()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url() {
        assert_eq!(package_url("provider"), "https://pub.dev/packages/provider");
        assert_eq!(package_url("http"), "https://pub.dev/packages/http");
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
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://pub.dev/packages/");
    }

    #[test]
    fn test_parse_versions_response() {
        let json = r#"{
            "name": "http",
            "latest": {"version": "1.2.0", "pubspec": {"name": "http"}},
            "versions": [
                {"version": "1.0.0", "retracted": false},
                {"version": "1.2.0", "retracted": false},
                {"version": "1.1.0", "retracted": false},
                {"version": "0.9.0", "retracted": true}
            ]
        }"#;

        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 4);
        assert_eq!(versions[0].version, "1.2.0");
        assert_eq!(versions[1].version, "1.1.0");
        assert_eq!(versions[2].version, "1.0.0");
        assert!(versions[3].retracted);
    }

    #[test]
    fn test_parse_versions_response_with_published() {
        let json = r#"{
            "name": "http",
            "latest": {"version": "1.2.0"},
            "versions": [
                {"version": "1.2.0", "retracted": false, "published": "2025-03-10T14:22:05.123Z"}
            ]
        }"#;

        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            deps_core::PublishTime::parse_rfc3339("2025-03-10T14:22:05.123Z")
        );
    }

    #[test]
    fn test_parse_versions_response_without_published() {
        let json = r#"{
            "name": "http",
            "latest": {"version": "1.2.0"},
            "versions": [
                {"version": "1.2.0", "retracted": false}
            ]
        }"#;

        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_parse_versions_response_with_malformed_published() {
        let json = r#"{
            "name": "http",
            "latest": {"version": "1.2.0"},
            "versions": [
                {"version": "1.2.0", "retracted": false, "published": "not-a-timestamp"}
            ]
        }"#;

        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed published degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_versions_response_empty() {
        let json = r#"{
            "name": "test",
            "latest": {"version": "1.0.0"},
            "versions": []
        }"#;
        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_package_info() {
        let json = r#"{
            "name": "provider",
            "latest": {
                "version": "6.1.2",
                "pubspec": {
                    "name": "provider",
                    "description": "A wrapper around InheritedWidget",
                    "homepage": "https://pub.dev/packages/provider",
                    "repository": "https://github.com/rrousselGit/provider",
                    "documentation": "https://pub.dev/documentation/provider"
                }
            },
            "versions": []
        }"#;

        let info = parse_package_info(json.as_bytes()).unwrap();
        assert_eq!(info.name, "provider");
        assert_eq!(
            info.description,
            Some("A wrapper around InheritedWidget".into())
        );
        assert_eq!(info.version, "6.1.2");
    }

    #[test]
    fn test_parse_package_info_minimal() {
        let json = r#"{
            "name": "minimal",
            "latest": {"version": "0.1.0"},
            "versions": []
        }"#;

        let info = parse_package_info(json.as_bytes()).unwrap();
        assert_eq!(info.name, "minimal");
        assert_eq!(info.version, "0.1.0");
        assert!(info.description.is_none());
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "packages": [
                {"package": "provider"},
                {"package": "riverpod"}
            ]
        }"#;
        let response: SearchResponse = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(response.packages.len(), 2);
        assert_eq!(response.packages[0].package, "provider");
    }

    #[test]
    fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = PubDevRegistry::new(cache);
    }

    /// #349: `../../search` must not escape the `/api/packages/` prefix via dot-segment
    /// normalization — the raw `.`/`/` characters have to be percent-encoded. Asserted on
    /// the *parsed* URL's path (`url::Url::parse`), not the raw format-string output: a
    /// `!url.contains("../")` check alone would pass even while the unencoded segments
    /// still normalized away the `packages` path component at the transport layer. Calls
    /// the actual production `package_metadata_url` helper, not a re-implemented copy of
    /// its `format!`, so a future encoding regression here fails this test.
    #[test]
    fn test_package_metadata_url_encodes_path_traversal() {
        let name = "../../search";
        let url = package_metadata_url(PUB_DEV_API_BASE, name);
        let parsed = url::Url::parse(&url).unwrap();
        let segments: Vec<&str> = parsed.path_segments().unwrap().collect();
        assert_eq!(segments.len(), 3, "segments: {segments:?}");
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "packages");
        assert_eq!(urlencoding::decode(segments[2]).unwrap(), name);
    }

    // --- S1 (impl-critic): a name of exactly `.`/`..` survives percent-encoding (`.` is
    // an unreserved RFC 3986 character) and is collapsed by the URL parser's dot-segment
    // normalization — identical to #341's npm bug, reachable here via `get_versions`,
    // `get_package_info`, and search's inner per-result fetch. `reject_dot_segment` must
    // catch it before `package_metadata_url` is ever called. ---

    /// Demonstrates the vulnerability `reject_dot_segment` exists to prevent:
    /// `package_metadata_url` alone (with no caller-side guard) builds a URL that, once
    /// parsed, has already lost the `packages` path component — `..` normalizes two
    /// levels up to the bare `/api/` root instead of a 404 for a literal package named
    /// `..`.
    #[test]
    fn test_package_metadata_url_dot_dot_normalizes_above_packages_prefix() {
        let url = package_metadata_url(PUB_DEV_API_BASE, "..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/api/", "parsed path: {}", parsed.path());
    }

    #[test]
    fn test_reject_dot_segment_rejects_bare_dot_dot() {
        assert!(reject_dot_segment("..").is_err());
    }

    #[test]
    fn test_reject_dot_segment_rejects_bare_dot() {
        assert!(reject_dot_segment(".").is_err());
    }

    #[test]
    fn test_reject_dot_segment_accepts_normal_names() {
        assert!(reject_dot_segment("provider").is_ok());
        assert!(reject_dot_segment("../../search").is_ok());
    }

    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_as_not_found() {
        let registry = PubDevRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("..").await.unwrap_err();
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn test_get_package_info_rejects_bare_dot_as_not_found() {
        let registry = PubDevRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_package_info(".").await.unwrap_err();
        assert!(err.is_not_found());
    }

    // --- S2 (impl-critic): `search`'s inner per-result fetch (`entry.package`) was
    // fully unencoded and unguarded, 12 lines below the encoded `get_versions` sink — a
    // missed #349 call site. Covered end-to-end via mockito, matching the guard/encoding
    // now shared with `get_versions`/`get_package_info` through `package_metadata_url` and
    // `reject_dot_segment`. ---

    #[tokio::test]
    async fn test_search_inner_fetch_encodes_malicious_package_name() {
        let mut server = mockito::Server::new_async().await;
        let search_mock = server
            .mock("GET", "/search?q=widget")
            .with_status(200)
            .with_body(r#"{"packages": [{"package": "../../search"}]}"#)
            .create_async()
            .await;
        // The traversal-shaped name must be percent-encoded into a single opaque path
        // segment under `/api/packages/`, never resolved as a literal traversal against
        // the mock server's own routes.
        let pkg_mock = server
            .mock("GET", "/packages/..%2F..%2Fsearch")
            .with_status(200)
            .with_body(r#"{"name": "search", "latest": {"version": "1.0.0"}, "versions": []}"#)
            .create_async()
            .await;

        let registry = PubDevRegistry::with_base(Arc::new(HttpCache::new()), server.url());
        let results = registry.search("widget", 10).await.unwrap();

        assert_eq!(results.len(), 1);
        search_mock.assert_async().await;
        pkg_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_search_inner_fetch_skips_dot_segment_package_name() {
        let mut server = mockito::Server::new_async().await;
        let search_mock = server
            .mock("GET", "/search?q=widget")
            .with_status(200)
            .with_body(r#"{"packages": [{"package": ".."}, {"package": "provider"}]}"#)
            .create_async()
            .await;
        let pkg_mock = server
            .mock("GET", "/packages/provider")
            .with_status(200)
            .with_body(r#"{"name": "provider", "latest": {"version": "1.0.0"}, "versions": []}"#)
            .create_async()
            .await;
        // No mock registered for a request resolving to the bare `/api/` root — if the
        // dot-segment guard regressed, that unexpected request would fail the test.

        let registry = PubDevRegistry::with_base(Arc::new(HttpCache::new()), server.url());
        let results = registry.search("widget", 10).await.unwrap();

        assert_eq!(
            results.len(),
            1,
            "the dot-segment entry must be skipped, not fetched"
        );
        search_mock.assert_async().await;
        pkg_mock.assert_async().await;
    }

    #[test]
    fn test_version_trait() {
        use deps_core::Version;
        let ver = DartVersion {
            version: "1.0.0".into(),
            retracted: true,
            published_at: None,
        };
        assert_eq!(ver.version_string(), "1.0.0");
        assert!(ver.is_yanked());
        assert!(ver.features().is_empty());
    }

    #[test]
    fn test_metadata_trait() {
        use deps_core::Metadata;
        let info = PackageInfo {
            name: "test".into(),
            description: Some("A test package".into()),
            homepage: None,
            repository: Some("https://github.com/test/test".into()),
            documentation: None,
            version: "1.0.0".into(),
            license: None,
        };
        assert_eq!(info.name(), "test");
        assert_eq!(info.description(), Some("A test package"));
        assert_eq!(info.repository(), Some("https://github.com/test/test"));
        assert!(info.documentation().is_none());
    }

    #[test]
    fn test_registry_as_any() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = PubDevRegistry::new(cache);
        assert!(registry.as_any().is::<PubDevRegistry>());
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PubDevRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(DartVersion {
                version: "2.0.0".into(),
                retracted: true,
                published_at: None,
            }),
            Box::new(DartVersion {
                version: "1.0.0".into(),
                retracted: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }
}
