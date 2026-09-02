//! Swift package registry using GitHub API.
//!
//! Fetches package versions from GitHub tags and searches repositories.
//! Non-GitHub URLs get empty version lists with a tracing warning.

use crate::types::{SwiftPackage, SwiftVersion};
use deps_core::github::{
    GithubTag, GithubTagsClient, ReleaseDatesCache, github_rate_limit_error, normalize_tag,
    paginate_tags, validate_owner_repo,
};
use deps_core::{DepsError, HttpCache, PublishTime, Result};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Display name for the registry backing Swift package version lookups,
/// used in not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Client for fetching Swift package information from GitHub.
#[derive(Clone)]
pub struct SwiftRegistry {
    github: GithubTagsClient,
    /// Per-package memoized GitHub Release publish times (#223 §3.1). `Arc` because
    /// `SwiftRegistry` is `Clone` and clones must share one memo, the same reason
    /// `github`'s cache is an `Arc`.
    release_dates: Arc<ReleaseDatesCache>,
}

impl SwiftRegistry {
    /// Creates a new Swift registry client with the given HTTP cache.
    ///
    /// Reads `GITHUB_TOKEN` from environment for authenticated requests
    /// (5000 req/h vs 60 req/h unauthenticated).
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            github: GithubTagsClient::new(cache),
            release_dates: Arc::new(ReleaseDatesCache::new()),
        }
    }

    /// Fetches all semver-tagged versions for a package.
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped.
    /// Follows GitHub tags pagination up to `MAX_TAG_PAGES` pages, stopping
    /// as soon as a page comes back with fewer than 100 entries (no further
    /// pages exist).
    pub async fn get_versions(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        validate_owner_repo(name)?;
        let tags = paginate_tags("Swift", name, |page| async move {
            self.github
                .fetch_tags_page(name, page)
                .await
                .map_err(|e| match &e {
                    DepsError::HttpStatus { status: 403, .. } if !self.github.has_token() => {
                        github_rate_limit_error()
                    }
                    DepsError::HttpStatus { status: 404, .. } => DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: REGISTRY,
                    },
                    _ => e,
                })
        })
        .await?;
        Ok(tags_to_versions(tags))
    }

    /// Like [`SwiftRegistry::get_versions`], but also attaches GitHub Release publish
    /// times via `SwiftRegistry::release_dates`.
    ///
    /// Runs the tags fetch and the release-dates fetch concurrently
    /// (`tokio::join!`) — `release_dates` is infallible (empty map on any failure),
    /// so it can never perturb `get_versions`'s error propagation. This removes one
    /// round trip out of the tag-pagination loop's `P+1`, not half the latency (#223
    /// R7), and on a memo hit the join costs nothing at all.
    pub async fn get_versions_with_release_dates(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        let (versions, dates) = tokio::join!(self.get_versions(name), self.release_dates(name));
        let mut versions = versions?;
        attach_publish_times(&mut versions, &dates);
        Ok(versions)
    }

    /// Fetches the newest ~100 GitHub Releases for `name` and returns a
    /// normalized-tag -> publish-time map, memoized behind a per-package TTL.
    ///
    /// Thin wrapper around the shared [`ReleaseDatesCache::fetch`] — see its docs for
    /// the best-effort/memoization contract.
    async fn release_dates(&self, name: &str) -> Arc<HashMap<String, PublishTime>> {
        self.release_dates.fetch(&self.github, name, "Swift").await
    }

    /// Finds the latest version satisfying the given semver requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<SwiftVersion>> {
        let versions = self.get_versions(name).await?;

        let req = match semver::VersionReq::parse(req_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse version req '{}': {}", req_str, e);
                return Ok(None);
            }
        };

        Ok(versions.into_iter().find(|v| {
            semver::Version::parse(v.version.as_str()).is_ok_and(|ver| req.matches(&ver))
        }))
    }

    /// Searches GitHub repositories for Swift packages.
    ///
    /// Returns up to `limit` results. `latest_version` is left empty to avoid
    /// N+1 API calls per search result.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SwiftPackage>> {
        let url = format!(
            "{}/search/repositories?q={}+language:swift&per_page={limit}",
            self.github.api_base(),
            urlencoding::encode(query)
        );
        let data = self.github.fetch_authenticated(&url).await?;
        parse_search_response(&data)
    }
}

/// Converts raw tags (possibly accumulated across pages) into a
/// newest-first `SwiftVersion` list. Non-semver tags are skipped.
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<SwiftVersion> {
    let mut versions_with_parsed: Vec<(SwiftVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            let name = normalize_tag(&tag.name).to_string();
            let parsed = semver::Version::parse(&name).ok()?;
            let prerelease = !parsed.pre.is_empty();
            Some((
                SwiftVersion {
                    version: name.into(),
                    yanked: false,
                    published_at: None,
                    prerelease,
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    versions_with_parsed.into_iter().map(|(v, _)| v).collect()
}

/// Attaches release publish times onto an already-fetched version list, in place.
///
/// Pure and network-free: `versions` came from [`SwiftRegistry::get_versions`],
/// `dates` from [`SwiftRegistry::release_dates`]. A version with no matching entry in
/// `dates` keeps `published_at: None` — exactly the pre-feature rendering (#223).
fn attach_publish_times(versions: &mut [SwiftVersion], dates: &HashMap<String, PublishTime>) {
    for version in versions {
        version.published_at = dates.get(version.version.as_str()).copied();
    }
}

/// Parses a single GitHub tags API response page into a `SwiftVersion`
/// list. Test-only convenience wrapper composing
/// [`deps_core::github::parse_tags_page`] and [`tags_to_versions`] for
/// single-page fixtures.
#[cfg(test)]
fn parse_tags_response(data: &[u8]) -> Result<Vec<SwiftVersion>> {
    Ok(tags_to_versions(deps_core::github::parse_tags_page(data)?))
}

/// GitHub search API response.
#[derive(Deserialize)]
struct SearchResponse {
    items: Vec<SearchItem>,
}

/// GitHub search result item.
#[derive(Deserialize)]
struct SearchItem {
    full_name: String,
    #[serde(default)]
    description: Option<String>,
    html_url: String,
}

/// Parses GitHub search API response into SwiftPackage list.
fn parse_search_response(data: &[u8]) -> Result<Vec<SwiftPackage>> {
    let response: SearchResponse = deps_core::parse_json_checked(data)?;
    Ok(response
        .items
        .into_iter()
        .map(|item| SwiftPackage {
            name: item.full_name.into(),
            description: item.description,
            repository: Some(item.html_url.clone()),
            homepage: Some(item.html_url),
            latest_version: deps_core::ConcreteVersion::new(""),
        })
        .collect())
}

impl deps_core::Registry for SwiftRegistry {
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

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = if freshness.enabled {
                self.get_versions_with_release_dates(name.as_str()).await?
            } else {
                self.get_versions(name.as_str()).await?
            };
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

    /// Under a wildcard/empty `req` (see [`deps_core::is_existence_wildcard`]) this is an
    /// existence check, not an upgrade recommendation — deferred to
    /// [`deps_core::select_latest_for_existence`], matching
    /// `deps-cargo`/`deps-pypi`/`deps-dart`/`deps-npm`. Without this gate, a package whose
    /// only tags so far are prerelease could never resolve under `*`: the `semver` crate's
    /// `VersionReq::parse("*")` does not match a prerelease `Version` unless the requirement
    /// itself carries a prerelease component (found via #421's cross-ecosystem conformance
    /// test in `deps-lsp`).
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        let parsed_req = semver::VersionReq::parse(req.as_str()).ok()?;
        versions.iter().position(|v| {
            semver::Version::parse(v.version_string().as_str())
                .is_ok_and(|ver| parsed_req.matches(&ver))
        })
    }

    // `Version::removal_status` is hardcoded `Available` (`registry.rs:173`) —
    // Swift package registries expose no per-tag yank/deprecation signal (#233).
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
    use deps_core::test_util::capture_tracing_output_async;

    #[test]
    fn test_parse_tags_response() {
        let json = r#"[
            {"name": "2.62.0", "commit": {}},
            {"name": "v2.40.0", "commit": {}},
            {"name": "2.61.0", "commit": {}},
            {"name": "not-semver", "commit": {}}
        ]"#;

        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "2.62.0");
        assert_eq!(versions[1].version, "2.61.0");
        assert_eq!(versions[2].version, "2.40.0");
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "items": [
                {
                    "full_name": "apple/swift-nio",
                    "description": "Networking framework",
                    "html_url": "https://github.com/apple/swift-nio"
                }
            ]
        }"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "apple/swift-nio");
        assert_eq!(packages[0].description, Some("Networking framework".into()));
        assert!(packages[0].latest_version.as_str().is_empty());
    }

    #[test]
    fn test_parse_search_no_description() {
        let json =
            r#"{"items": [{"full_name": "foo/bar", "html_url": "https://github.com/foo/bar"}]}"#;
        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].description, None);
    }

    #[test]
    fn test_parse_tags_empty_array() {
        let json = r"[]";
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_tags_all_non_semver_skipped() {
        let json = r#"[
            {"name": "latest", "commit": {}},
            {"name": "stable", "commit": {}},
            {"name": "nightly-2024-01-01", "commit": {}}
        ]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_tags_sorted_newest_first() {
        let json = r#"[
            {"name": "1.0.0"},
            {"name": "3.0.0"},
            {"name": "2.0.0"}
        ]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[1].version, "2.0.0");
        assert_eq!(versions[2].version, "1.0.0");
    }

    #[test]
    fn test_parse_tags_invalid_json_returns_empty() {
        let result = parse_tags_response(b"not json").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_tags_github_rate_limit_returns_error() {
        let json = r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#;
        let result = parse_tags_response(json.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    #[test]
    fn test_parse_search_empty_items() {
        let json = r#"{"items": []}"#;
        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_search_invalid_json_returns_error() {
        let result = parse_search_response(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tags_v_prefix_stripped() {
        let json = r#"[{"name": "v1.2.3"}, {"name": "v0.9.0"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        // Versions should have 'v' prefix stripped
        assert!(!versions[0].version.as_str().starts_with('v'));
        assert!(!versions[1].version.as_str().starts_with('v'));
    }

    #[test]
    fn test_parse_tags_uppercase_v_prefix_stripped() {
        let json = r#"[{"name": "V1.2.3"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    // `validate_owner_repo`, `page_has_more`, `warn_if_pagination_truncated`,
    // `paginate_tags`, `parse_tags_page`, and `normalize_tag` are now shared with
    // `deps-github-actions` via `deps_core::github` (#472, #486); their unit tests
    // moved there. This module keeps only tests for Swift-specific logic
    // (`tags_to_versions`) and end-to-end coverage that exercises the shared
    // primitives through `SwiftRegistry`'s own public API.

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let versions = registry.get_versions("apple/swift-nio").await.unwrap();
        assert!(!versions.is_empty());
    }

    #[test]
    fn test_tags_to_versions_accumulated_across_pages_sorts_and_dedupes_none() {
        // Simulates two accumulated pages being merged before sorting, the
        // shape `get_versions` produces when pagination fetches page 2.
        let page1 =
            deps_core::github::parse_tags_page(br#"[{"name": "3.0.0"}, {"name": "2.0.0"}]"#)
                .unwrap();
        let page2 = deps_core::github::parse_tags_page(br#"[{"name": "1.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[2].version, "1.0.0");
    }

    #[test]
    fn test_tags_to_versions_later_page_can_hold_the_highest_semver() {
        // Regression guard for N1: GitHub returns tags in lexicographic order,
        // not semver order, so a page fetched *later* in pagination can still
        // contain the highest real version (e.g. `v`-prefixed tags sort
        // lexicographically ahead of unrelated subproject tags that fill
        // earlier pages on large monorepos). The final list must be sorted by
        // parsed semver regardless of fetch/page order.
        let page1 = deps_core::github::parse_tags_page(
            br#"[{"name": "DataTransport-1.0.0"}, {"name": "1.0.0"}]"#,
        )
        .unwrap();
        let page2 = deps_core::github::parse_tags_page(br#"[{"name": "v12.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions[0].version, "12.0.0");
        assert_eq!(versions[1].version, "1.0.0");
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(SwiftVersion {
                version: "2.0.0".into(),
                yanked: false,
                published_at: None,
                prerelease: false,
            }),
            Box::new(SwiftVersion {
                version: "1.0.0".into(),
                yanked: false,
                published_at: None,
                prerelease: false,
            }),
        ];
        let req = VersionReq::new("^1.0.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    // `normalize_tag`, `parse_releases_page`, `classify_release_fetch`, and the
    // TTL/eviction/memo-hit behavior of the release-dates cache now live in
    // `deps_core::github::ReleaseDatesCache` (#486); their unit tests moved there. This
    // module keeps only tests for Swift-specific joining (`attach_publish_times`) and
    // end-to-end coverage exercising `SwiftRegistry`'s own public API.

    // --- attach_publish_times ---

    #[test]
    fn test_attach_publish_times_match() {
        let mut versions = vec![SwiftVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("1.0.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, Some(published));
    }

    #[test]
    fn test_attach_publish_times_miss_stays_none() {
        let mut versions = vec![SwiftVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let dates = HashMap::new();
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, None);
    }

    #[test]
    fn test_attach_publish_times_prefix_mismatch_stays_none() {
        // A dates entry for a *different* version string must never leak onto an
        // unrelated version, even when one is a textual prefix of the other.
        let mut versions = vec![SwiftVersion {
            version: "1.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("1.0.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, None);
    }

    /// Builds a `SwiftRegistry` pointed at a mock server `base` (typically a
    /// `mockito::Server::url()`) instead of the real GitHub API, for tests driving
    /// `Registry::get_versions_with` end-to-end without a live network call.
    fn mock_registry(base: &str, has_token: bool) -> SwiftRegistry {
        SwiftRegistry {
            github: GithubTagsClient::for_test(Arc::new(HttpCache::new()), base, has_token),
            release_dates: Arc::new(deps_core::github::ReleaseDatesCache::new()),
        }
    }

    // --- Registry::get_versions_with: freshness.enabled gate (M2) ---

    #[tokio::test]
    async fn test_get_versions_with_disabled_freshness_skips_release_dates_fetch() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"[{"name": "1.0.0"}]"#)
            .create_async()
            .await;
        // Asserted at the end: the disabled path must never touch the releases
        // endpoint at all, not merely tolerate it failing.
        let releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: false,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_none()));
        releases_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_freshness_attaches_publish_dates() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"[{"name": "1.0.0"}]"#)
            .create_async()
            .await;
        let _releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"[{"tag_name": "1.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": false}]"#,
            )
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: true,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_some()));
    }

    /// Regression for #472 critic M3: `get_versions` must label its pagination-cap
    /// truncation warning `"Swift"`, not some other ecosystem's name or a stale literal
    /// left over from the shared `deps_core::github::paginate_tags` extraction. A
    /// hardcoded/rearranged `paginate_tags("Swift", ...)` call site would silently break
    /// this without failing any other test, since `deps_core::github`'s own tests only
    /// exercise `paginate_tags` with an arbitrary ecosystem string.
    #[tokio::test]
    async fn test_get_versions_pagination_cap_warning_is_labeled_swift() {
        let mut server = mockito::Server::new_async().await;
        let full_page: String = format!(
            "[{}]",
            (0..100)
                .map(|i| format!(r#"{{"name":"{i}.0.0"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(full_page)
            .expect(deps_core::github::MAX_TAG_PAGES as usize)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let output = capture_tracing_output_async(async {
            registry.get_versions("owner/repo").await.unwrap();
        })
        .await;

        assert!(output.contains("Swift"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
        assert!(!output.contains("GitHub Actions"), "output was: {output}");
    }
}
