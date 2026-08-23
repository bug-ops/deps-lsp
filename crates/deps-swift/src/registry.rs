//! Swift package registry using GitHub API.
//!
//! Fetches package versions from GitHub tags and searches repositories.
//! Non-GitHub URLs get empty version lists with a tracing warning.

use crate::types::{SwiftPackage, SwiftVersion};
use deps_core::{DepsError, HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const GITHUB_API: &str = "https://api.github.com";

/// Display name for the registry backing Swift package version lookups,
/// used in not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Maximum number of `tags` pages fetched per package (100 tags/page).
///
/// This is a **safety ceiling, not the correctness mechanism** — the loop
/// already stops as soon as a page comes back with fewer than 100 entries
/// (`page_has_more`), which is GitHub's documented signal that no further
/// page exists. Every real repository terminates via that signal well
/// before this bound is reached.
///
/// The bound exists only to protect against a pathological repo with an
/// unbounded number of tags. It must stay high enough that it never
/// truncates a real repository's tag list, because GitHub returns tags in
/// **lexicographic, not semver, order** — verified live on
/// `firebase/firebase-ios-sdk` (1131 tags): page 1 is headed by `v8.15.0`
/// (a `v`-prefixed tag lexicographically outranks unprefixed ones), pages
/// 2-9 are entirely unrelated `DataTransport-*`/`Core-*` subproject tags
/// with zero semver-parseable entries, and the real `11.x`/`12.x` releases
/// only appear around pages 10-11. A low page cap (previously 5, i.e. 500
/// tags) silently dropped those newer tags out of `available` entirely —
/// no amount of sorting the *fetched* subset fixes that, since the highest
/// real versions were never fetched at all. This produced two distinct
/// bugs: an ordinary pin like `from: "11.0.0"` read as "unsatisfiable",
/// and hover/completion/update-all reported the stale `8.15.0` as
/// `latest`. 3000 tags (30 pages) comfortably covers this repository and
/// any other known real-world package with room to spare, while still
/// bounding worst-case request count for an adversarial input.
const MAX_TAG_PAGES: u32 = 30;

/// Validates that `name` is a valid `owner/repo` GitHub identifier.
///
/// Accepts characters `[a-zA-Z0-9._-]` in both owner and repo segments.
fn validate_owner_repo(name: &str) -> Result<()> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$").expect("hardcoded regex is valid")
    });
    if re.is_match(name) {
        Ok(())
    } else {
        Err(DepsError::InvalidUri(format!(
            "invalid owner/repo format: '{name}'"
        )))
    }
}

/// Client for fetching Swift package information from GitHub.
#[derive(Clone)]
pub struct SwiftRegistry {
    cache: Arc<HttpCache>,
    auth_headers: Vec<(reqwest::header::HeaderName, String)>,
    has_token: bool,
}

impl SwiftRegistry {
    /// Creates a new Swift registry client with the given HTTP cache.
    ///
    /// Reads `GITHUB_TOKEN` from environment for authenticated requests
    /// (5000 req/h vs 60 req/h unauthenticated).
    pub fn new(cache: Arc<HttpCache>) -> Self {
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        let has_token = token.is_some();
        let auth_headers = token
            .map(|token| {
                tracing::info!("GITHUB_TOKEN detected, using authenticated GitHub API requests");
                vec![(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))]
            })
            .unwrap_or_default();

        Self {
            cache,
            auth_headers,
            has_token,
        }
    }

    fn headers(&self) -> Vec<(reqwest::header::HeaderName, &str)> {
        self.auth_headers
            .iter()
            .map(|(k, v): &(reqwest::header::HeaderName, String)| (k.clone(), v.as_str()))
            .collect()
    }

    /// Fetches all semver-tagged versions for a package.
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped.
    /// Follows GitHub tags pagination up to `MAX_TAG_PAGES` pages, stopping
    /// as soon as a page comes back with fewer than 100 entries (no further
    /// pages exist).
    pub async fn get_versions(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        validate_owner_repo(name)?;
        let mut tags = Vec::new();
        for page in 1..=MAX_TAG_PAGES {
            let url = format!("{GITHUB_API}/repos/{name}/tags?per_page=100&page={page}");
            let data = self
                .cache
                .get_cached_with_headers(&url, &self.headers())
                .await
                .map_err(|e| match &e {
                    DepsError::HttpStatus { status: 403, .. } if !self.has_token => {
                        DepsError::CacheError(
                            "GitHub API rate limit exceeded. Set GITHUB_TOKEN to increase the limit (5000 req/h). Run: export GITHUB_TOKEN=$(gh auth token)".into(),
                        )
                    }
                    DepsError::HttpStatus { status: 404, .. } => DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: REGISTRY,
                    },
                    _ => e,
                })?;
            let page_tags = parse_tags_page(&data)?;
            let page_len = page_tags.len();
            tags.extend(page_tags);
            if !page_has_more(page_len) {
                break;
            }
        }
        Ok(tags_to_versions(tags))
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

        Ok(versions
            .into_iter()
            .find(|v| semver::Version::parse(&v.version).is_ok_and(|ver| req.matches(&ver))))
    }

    /// Searches GitHub repositories for Swift packages.
    ///
    /// Returns up to `limit` results. `latest_version` is left empty to avoid
    /// N+1 API calls per search result.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SwiftPackage>> {
        let url = format!(
            "{GITHUB_API}/search/repositories?q={}+language:swift&per_page={limit}",
            urlencoding::encode(query)
        );
        let data = self
            .cache
            .get_cached_with_headers(&url, &self.headers())
            .await?;
        parse_search_response(&data)
    }
}

/// GitHub tags API response item.
#[derive(Deserialize)]
struct GithubTag {
    name: String,
}

/// GitHub API error response (rate limit, not found, etc.).
#[derive(Deserialize)]
struct GithubErrorResponse {
    message: String,
}

/// Returns `true` when a fetched page came back full (`per_page=100`
/// entries), meaning a subsequent page may exist and should be fetched too.
/// A page with fewer entries is necessarily the last one.
const fn page_has_more(page_len: usize) -> bool {
    page_len >= 100
}

/// Parses a single GitHub tags API page into raw tag entries.
///
/// GitHub returns an error object instead of array when rate-limited or on
/// other errors. Detect this and return a descriptive error.
fn parse_tags_page(data: &[u8]) -> Result<Vec<GithubTag>> {
    match serde_json::from_slice(data) {
        Ok(tags) => Ok(tags),
        Err(_) => {
            if let Ok(err) = serde_json::from_slice::<GithubErrorResponse>(data) {
                Err(DepsError::CacheError(format!(
                    "GitHub API error: {}",
                    err.message
                )))
            } else {
                Ok(vec![])
            }
        }
    }
}

/// Converts raw tags (possibly accumulated across pages) into a
/// newest-first `SwiftVersion` list. Non-semver tags are skipped.
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<SwiftVersion> {
    let mut versions_with_parsed: Vec<(SwiftVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            // Both cases are real GitHub tag conventions ("v2.62.0", "V2.62.0"); stripping
            // only lowercase 'v' would leave "V2.62.0" unparseable as semver, silently
            // dropping a real, installable tag out of `available` — the same false-positive
            // class this PR's diagnostic guards against elsewhere.
            let name = tag
                .name
                .strip_prefix(['v', 'V'])
                .unwrap_or(&tag.name)
                .to_string();
            let parsed = semver::Version::parse(&name).ok()?;
            Some((
                SwiftVersion {
                    version: name,
                    yanked: false,
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    versions_with_parsed.into_iter().map(|(v, _)| v).collect()
}

/// Parses a single GitHub tags API response page into a `SwiftVersion`
/// list. Test-only convenience wrapper composing [`parse_tags_page`] and
/// [`tags_to_versions`] for single-page fixtures.
#[cfg(test)]
fn parse_tags_response(data: &[u8]) -> Result<Vec<SwiftVersion>> {
    Ok(tags_to_versions(parse_tags_page(data)?))
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
    let response: SearchResponse = serde_json::from_slice(data)?;
    Ok(response
        .items
        .into_iter()
        .map(|item| SwiftPackage {
            name: item.full_name.into(),
            description: item.description,
            repository: Some(item.html_url.clone()),
            homepage: Some(item.html_url),
            latest_version: String::new(),
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

    fn package_url(&self, name: &deps_core::PackageName) -> String {
        let name = name.as_str();
        if validate_owner_repo(name).is_ok() {
            format!("https://github.com/{name}")
        } else {
            String::new()
        }
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        let parsed_req = semver::VersionReq::parse(req.as_str()).ok()?;
        versions.iter().position(|v| {
            semver::Version::parse(v.version_string()).is_ok_and(|ver| parsed_req.matches(&ver))
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
        assert!(packages[0].latest_version.is_empty());
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
        assert!(!versions[0].version.starts_with('v'));
        assert!(!versions[1].version.starts_with('v'));
    }

    #[test]
    fn test_parse_tags_uppercase_v_prefix_stripped() {
        let json = r#"[{"name": "V1.2.3"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    #[test]
    fn test_validate_owner_repo_invalid_format_message() {
        let err = validate_owner_repo("no-slash").unwrap_err();
        assert!(err.to_string().contains("invalid owner/repo format"));
    }

    #[test]
    fn test_validate_owner_repo_valid() {
        assert!(validate_owner_repo("apple/swift-nio").is_ok());
        assert!(validate_owner_repo("foo/bar").is_ok());
        assert!(validate_owner_repo("org.name/repo_name-v2").is_ok());
    }

    #[test]
    fn test_validate_owner_repo_invalid() {
        assert!(validate_owner_repo("no-slash").is_err());
        assert!(validate_owner_repo("../../etc/passwd").is_err());
        assert!(validate_owner_repo("owner/repo/extra").is_err());
        assert!(validate_owner_repo("owner/ repo").is_err());
        assert!(validate_owner_repo("").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let versions = registry.get_versions("apple/swift-nio").await.unwrap();
        assert!(!versions.is_empty());
    }

    #[test]
    fn test_page_has_more_full_page_continues() {
        assert!(page_has_more(100));
    }

    #[test]
    fn test_page_has_more_partial_page_stops() {
        assert!(!page_has_more(99));
        assert!(!page_has_more(0));
    }

    #[test]
    fn test_parse_tags_page_returns_raw_tags() {
        let json = r#"[{"name": "v1.0.0"}, {"name": "not-semver"}]"#;
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "v1.0.0");
    }

    #[test]
    fn test_tags_to_versions_accumulated_across_pages_sorts_and_dedupes_none() {
        // Simulates two accumulated pages being merged before sorting, the
        // shape `get_versions` produces when pagination fetches page 2.
        let page1 = parse_tags_page(br#"[{"name": "3.0.0"}, {"name": "2.0.0"}]"#).unwrap();
        let page2 = parse_tags_page(br#"[{"name": "1.0.0"}]"#).unwrap();
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
        let page1 =
            parse_tags_page(br#"[{"name": "DataTransport-1.0.0"}, {"name": "1.0.0"}]"#).unwrap();
        let page2 = parse_tags_page(br#"[{"name": "v12.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions[0].version, "12.0.0");
        assert_eq!(versions[1].version, "1.0.0");
    }

    #[test]
    fn test_registry_package_url_valid() {
        use deps_core::{PackageName, Registry};
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        assert_eq!(
            registry.package_url(&PackageName::new("apple/swift-nio")),
            "https://github.com/apple/swift-nio"
        );
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
            }),
            Box::new(SwiftVersion {
                version: "1.0.0".into(),
                yanked: false,
            }),
        ];
        let req = VersionReq::new("^1.0.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    #[test]
    fn test_registry_package_url_invalid_returns_empty() {
        use deps_core::{PackageName, Registry};
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        assert_eq!(
            registry.package_url(&PackageName::new("../../etc/passwd")),
            ""
        );
        assert_eq!(registry.package_url(&PackageName::new("no-slash")), "");
        assert_eq!(
            registry.package_url(&PackageName::new("owner/repo/extra")),
            ""
        );
    }
}
