//! rubygems.org registry client.
//!
//! Provides access to rubygems.org API for version lookups and search.

use crate::types::{BundlerVersion, GemInfo};
use crate::version::{compare_versions, version_matches_requirement};
use deps_core::{HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const RUBYGEMS_API_BASE: &str = "https://rubygems.org/api/v1";

/// Base URL for gem pages on rubygems.org.
pub const RUBYGEMS_URL: &str = "https://rubygems.org/gems";

/// Returns the URL for a gem's page on rubygems.org.
pub fn gem_url(name: &str) -> String {
    format!("{RUBYGEMS_URL}/{name}")
}

/// Client for interacting with rubygems.org registry.
#[derive(Clone)]
pub struct RubyGemsRegistry {
    cache: Arc<HttpCache>,
}

impl RubyGemsRegistry {
    /// Creates a new registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a gem.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<BundlerVersion>> {
        let url = format!("{}/versions/{}.json", RUBYGEMS_API_BASE, name);
        let data = self.cache.get_cached(&url).await?;
        parse_versions_response(&data, name)
    }

    /// Finds the latest version matching the given requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<BundlerVersion>> {
        let versions = self.get_versions(name).await?;
        Ok(versions
            .into_iter()
            .find(|v| version_matches_requirement(&v.number, req_str) && !v.yanked))
    }

    /// Searches for gems by name/keywords.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<GemInfo>> {
        let url = format!(
            "{}/search.json?query={}",
            RUBYGEMS_API_BASE,
            urlencoding::encode(query)
        );
        let data = self.cache.get_cached(&url).await?;
        let gems = parse_search_response(&data)?;
        Ok(gems.into_iter().take(limit).collect())
    }

    /// Gets detailed gem information.
    pub async fn get_gem_info(&self, name: &str) -> Result<GemInfo> {
        let url = format!("{}/gems/{}.json", RUBYGEMS_API_BASE, name);
        let data = self.cache.get_cached(&url).await?;
        parse_gem_info(&data)
    }
}

#[derive(Deserialize)]
struct VersionEntry {
    number: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    yanked: bool,
    created_at: Option<String>,
    #[serde(default = "default_platform")]
    platform: String,
}

fn default_platform() -> String {
    "ruby".to_string()
}

fn parse_versions_response(data: &[u8], _gem_name: &str) -> Result<Vec<BundlerVersion>> {
    let entries: Vec<VersionEntry> = serde_json::from_slice(data)?;

    let mut versions: Vec<BundlerVersion> = entries
        .into_iter()
        .map(|e| BundlerVersion {
            number: e.number,
            prerelease: e.prerelease,
            yanked: e.yanked,
            created_at: e.created_at,
            platform: e.platform,
        })
        .collect();

    // Sort by version descending (newest first)
    versions.sort_by(|a, b| compare_versions(&b.number, &a.number));

    Ok(versions)
}

#[derive(Deserialize)]
struct SearchEntry {
    name: String,
    info: Option<String>,
    version: String,
    #[serde(default)]
    downloads: u64,
}

fn parse_search_response(data: &[u8]) -> Result<Vec<GemInfo>> {
    let entries: Vec<SearchEntry> = serde_json::from_slice(data)?;

    Ok(entries
        .into_iter()
        .map(|e| GemInfo {
            name: e.name,
            info: e.info,
            homepage_uri: None,
            source_code_uri: None,
            documentation_uri: None,
            version: e.version,
            licenses: vec![],
            authors: None,
            downloads: e.downloads,
        })
        .collect())
}

#[derive(Deserialize)]
struct GemInfoResponse {
    name: String,
    info: Option<String>,
    version: String,
    homepage_uri: Option<String>,
    source_code_uri: Option<String>,
    documentation_uri: Option<String>,
    #[serde(default)]
    licenses: Vec<String>,
    authors: Option<String>,
    #[serde(default)]
    downloads: u64,
}

fn parse_gem_info(data: &[u8]) -> Result<GemInfo> {
    let response: GemInfoResponse = serde_json::from_slice(data)?;

    Ok(GemInfo {
        name: response.name,
        info: response.info,
        homepage_uri: response.homepage_uri,
        source_code_uri: response.source_code_uri,
        documentation_uri: response.documentation_uri,
        version: response.version,
        licenses: response.licenses,
        authors: response.authors,
        downloads: response.downloads,
    })
}

// Implement PackageRegistry trait
#[async_trait::async_trait]
impl deps_core::PackageRegistry for RubyGemsRegistry {
    type Version = BundlerVersion;
    type Metadata = GemInfo;
    type VersionReq = String;

    async fn get_versions(&self, name: &str) -> Result<Vec<Self::Version>> {
        self.get_versions(name).await
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        req: &Self::VersionReq,
    ) -> Result<Option<Self::Version>> {
        self.get_latest_matching(name, req).await
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Self::Metadata>> {
        self.search(query, limit).await
    }
}

// Implement VersionInfo trait
impl deps_core::VersionInfo for BundlerVersion {
    fn version_string(&self) -> &str {
        &self.number
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }
}

// Implement PackageMetadata trait
impl deps_core::PackageMetadata for GemInfo {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.info.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.source_code_uri.as_deref()
    }

    fn documentation(&self) -> Option<&str> {
        self.documentation_uri.as_deref()
    }

    fn latest_version(&self) -> &str {
        &self.version
    }
}

// Implement Registry trait for trait object support
#[async_trait::async_trait]
impl deps_core::Registry for RubyGemsRegistry {
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
        let results = self.search(query, limit).await?;
        Ok(results
            .into_iter()
            .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
            .collect())
    }

    fn package_url(&self, name: &str) -> String {
        gem_url(name)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gem_url() {
        assert_eq!(gem_url("rails"), "https://rubygems.org/gems/rails");
        assert_eq!(gem_url("nokogiri"), "https://rubygems.org/gems/nokogiri");
    }

    #[test]
    fn test_gem_url_special_chars() {
        assert_eq!(
            gem_url("rspec-rails"),
            "https://rubygems.org/gems/rspec-rails"
        );
        assert_eq!(
            gem_url("activerecord-import"),
            "https://rubygems.org/gems/activerecord-import"
        );
    }

    #[test]
    fn test_parse_versions_response() {
        let json = r#"[
            {"number": "7.0.8", "prerelease": false, "yanked": false, "platform": "ruby"},
            {"number": "7.0.7", "prerelease": false, "yanked": false, "platform": "ruby"},
            {"number": "7.1.0.beta1", "prerelease": true, "yanked": false, "platform": "ruby"}
        ]"#;

        let versions = parse_versions_response(json.as_bytes(), "rails").unwrap();
        assert_eq!(versions.len(), 3);
        assert!(versions[0].prerelease); // 7.1.0.beta1 should be sorted first due to higher major
    }

    #[test]
    fn test_parse_versions_response_with_yanked() {
        let json = r#"[
            {"number": "1.0.0", "prerelease": false, "yanked": true, "platform": "ruby"},
            {"number": "0.9.0", "prerelease": false, "yanked": false, "platform": "ruby"}
        ]"#;

        let versions = parse_versions_response(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions[0].yanked);
        assert!(!versions[1].yanked);
    }

    #[test]
    fn test_parse_versions_response_with_created_at() {
        let json = r#"[
            {"number": "1.0.0", "prerelease": false, "yanked": false, "created_at": "2024-01-15T10:30:00Z", "platform": "ruby"}
        ]"#;

        let versions = parse_versions_response(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].created_at,
            Some("2024-01-15T10:30:00Z".to_string())
        );
    }

    #[test]
    fn test_parse_versions_response_default_platform() {
        let json = r#"[
            {"number": "1.0.0", "prerelease": false, "yanked": false}
        ]"#;

        let versions = parse_versions_response(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].platform, "ruby");
    }

    #[test]
    fn test_parse_versions_response_sorting() {
        let json = r#"[
            {"number": "1.0.0", "prerelease": false, "yanked": false},
            {"number": "2.0.0", "prerelease": false, "yanked": false},
            {"number": "1.5.0", "prerelease": false, "yanked": false}
        ]"#;

        let versions = parse_versions_response(json.as_bytes(), "test").unwrap();
        assert_eq!(versions[0].number, "2.0.0");
        assert_eq!(versions[1].number, "1.5.0");
        assert_eq!(versions[2].number, "1.0.0");
    }

    #[test]
    fn test_parse_versions_response_empty() {
        let json = r"[]";
        let versions = parse_versions_response(json.as_bytes(), "test").unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"[
            {"name": "rails", "info": "Ruby on Rails", "version": "7.0.8", "downloads": 500000000},
            {"name": "railties", "info": "Core", "version": "7.0.8", "downloads": 100000000}
        ]"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "rails");
        assert_eq!(results[0].info, Some("Ruby on Rails".to_string()));
        assert_eq!(results[0].version, "7.0.8");
        assert_eq!(results[0].downloads, 500_000_000);
    }

    #[test]
    fn test_parse_search_response_minimal() {
        let json = r#"[
            {"name": "test", "version": "1.0.0"}
        ]"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "test");
        assert!(results[0].info.is_none());
        assert_eq!(results[0].downloads, 0);
    }

    #[test]
    fn test_parse_search_response_empty() {
        let json = r"[]";
        let results = parse_search_response(json.as_bytes()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_gem_info_full() {
        let json = r#"{
            "name": "rails",
            "info": "Full-stack web application framework",
            "version": "7.0.8",
            "homepage_uri": "https://rubyonrails.org",
            "source_code_uri": "https://github.com/rails/rails",
            "documentation_uri": "https://api.rubyonrails.org",
            "licenses": ["MIT"],
            "authors": "David Heinemeier Hansson",
            "downloads": 500000000
        }"#;

        let info = parse_gem_info(json.as_bytes()).unwrap();
        assert_eq!(info.name, "rails");
        assert_eq!(
            info.info,
            Some("Full-stack web application framework".to_string())
        );
        assert_eq!(info.version, "7.0.8");
        assert_eq!(
            info.homepage_uri,
            Some("https://rubyonrails.org".to_string())
        );
        assert_eq!(
            info.source_code_uri,
            Some("https://github.com/rails/rails".to_string())
        );
        assert_eq!(
            info.documentation_uri,
            Some("https://api.rubyonrails.org".to_string())
        );
        assert_eq!(info.licenses, vec!["MIT"]);
        assert_eq!(info.authors, Some("David Heinemeier Hansson".to_string()));
        assert_eq!(info.downloads, 500_000_000);
    }

    #[test]
    fn test_parse_gem_info_minimal() {
        let json = r#"{
            "name": "minimal",
            "version": "0.1.0"
        }"#;

        let info = parse_gem_info(json.as_bytes()).unwrap();
        assert_eq!(info.name, "minimal");
        assert_eq!(info.version, "0.1.0");
        assert!(info.info.is_none());
        assert!(info.homepage_uri.is_none());
        assert!(info.source_code_uri.is_none());
        assert!(info.documentation_uri.is_none());
        assert!(info.licenses.is_empty());
        assert!(info.authors.is_none());
        assert_eq!(info.downloads, 0);
    }

    #[test]
    fn test_parse_gem_info_with_multiple_licenses() {
        let json = r#"{
            "name": "test",
            "version": "1.0.0",
            "licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"]
        }"#;

        let info = parse_gem_info(json.as_bytes()).unwrap();
        assert_eq!(info.licenses.len(), 3);
        assert!(info.licenses.contains(&"MIT".to_string()));
        assert!(info.licenses.contains(&"Apache-2.0".to_string()));
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = RubyGemsRegistry::new(cache);
    }

    #[test]
    fn test_version_info_trait() {
        use deps_core::VersionInfo;

        let version = BundlerVersion {
            number: "1.0.0".into(),
            prerelease: false,
            yanked: true,
            created_at: None,
            platform: "ruby".into(),
        };

        assert_eq!(version.version_string(), "1.0.0");
        assert!(version.is_yanked());
        assert!(version.features().is_empty());
    }

    #[test]
    fn test_package_metadata_trait() {
        use deps_core::PackageMetadata;

        let gem = GemInfo {
            name: "test".into(),
            info: Some("A test gem".into()),
            homepage_uri: None,
            source_code_uri: Some("https://github.com/test/test".into()),
            documentation_uri: Some("https://docs.test.com".into()),
            version: "1.0.0".into(),
            licenses: vec![],
            authors: None,
            downloads: 0,
        };

        assert_eq!(gem.name(), "test");
        assert_eq!(gem.description(), Some("A test gem"));
        assert_eq!(gem.repository(), Some("https://github.com/test/test"));
        assert_eq!(gem.documentation(), Some("https://docs.test.com"));
        assert_eq!(gem.latest_version(), "1.0.0");
    }

    #[test]
    fn test_package_metadata_trait_empty_optionals() {
        use deps_core::PackageMetadata;

        let gem = GemInfo {
            name: "empty".into(),
            info: None,
            homepage_uri: None,
            source_code_uri: None,
            documentation_uri: None,
            version: "0.1.0".into(),
            licenses: vec![],
            authors: None,
            downloads: 0,
        };

        assert!(gem.description().is_none());
        assert!(gem.repository().is_none());
        assert!(gem.documentation().is_none());
    }

    #[test]
    fn test_registry_package_url() {
        use deps_core::Registry;

        let cache = Arc::new(HttpCache::new());
        let registry = RubyGemsRegistry::new(cache);

        assert_eq!(
            registry.package_url("rails"),
            "https://rubygems.org/gems/rails"
        );
    }

    #[test]
    fn test_registry_as_any() {
        use deps_core::Registry;

        let cache = Arc::new(HttpCache::new());
        let registry = RubyGemsRegistry::new(cache);

        let any = registry.as_any();
        assert!(any.is::<RubyGemsRegistry>());
        assert!(any.downcast_ref::<RubyGemsRegistry>().is_some());
    }

    #[test]
    fn test_default_platform_function() {
        assert_eq!(default_platform(), "ruby");
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_fetch_real_rails_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = RubyGemsRegistry::new(cache);
        let versions = registry.get_versions("rails").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.number.starts_with("7.")));
    }
}
