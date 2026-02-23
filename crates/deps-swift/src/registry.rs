//! Swift package registry using GitHub API.
//!
//! Fetches package versions from GitHub tags and searches repositories.
//! Non-GitHub URLs get empty version lists with a tracing warning.

use crate::error::SwiftError;
use crate::types::{SwiftPackage, SwiftVersion};
use deps_core::{HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const GITHUB_API: &str = "https://api.github.com";

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
        Err(SwiftError::registry_error(name, InvalidOwnerRepo(name.to_string())).into())
    }
}

#[derive(Debug)]
struct InvalidOwnerRepo(String);

impl std::fmt::Display for InvalidOwnerRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid owner/repo format: '{}'", self.0)
    }
}

impl std::error::Error for InvalidOwnerRepo {}

/// Client for fetching Swift package information from GitHub.
#[derive(Clone)]
pub struct SwiftRegistry {
    cache: Arc<HttpCache>,
}

impl SwiftRegistry {
    /// Creates a new Swift registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all semver-tagged versions for a package.
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        validate_owner_repo(name)?;
        let url = format!("{GITHUB_API}/repos/{name}/tags?per_page=100");
        let data = self.cache.get_cached(&url).await?;
        parse_tags_response(&data)
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
        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// GitHub tags API response item.
#[derive(Deserialize)]
struct GithubTag {
    name: String,
}

/// Parses GitHub tags API response into SwiftVersion list.
fn parse_tags_response(data: &[u8]) -> Result<Vec<SwiftVersion>> {
    let tags: Vec<GithubTag> = serde_json::from_slice(data)?;

    let mut versions_with_parsed: Vec<(SwiftVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            let name = tag.name.strip_prefix('v').unwrap_or(&tag.name).to_string();
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
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
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
            name: item.full_name,
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
        format!("https://github.com/{name}")
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
    fn test_parse_tags_invalid_json_returns_error() {
        let result = parse_tags_response(b"not json");
        assert!(result.is_err());
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
}
