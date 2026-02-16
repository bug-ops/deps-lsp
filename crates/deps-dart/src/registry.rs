//! pub.dev registry client.

use crate::types::{DartVersion, PackageInfo};
use crate::version::compare_versions;
use deps_core::{HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PUB_DEV_API_BASE: &str = "https://pub.dev/api";

pub fn package_url(name: &str) -> String {
    format!("https://pub.dev/packages/{name}")
}

#[derive(Clone)]
pub struct PubDevRegistry {
    cache: Arc<HttpCache>,
}

impl PubDevRegistry {
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    pub async fn get_versions(&self, name: &str) -> Result<Vec<DartVersion>> {
        let url = format!("{PUB_DEV_API_BASE}/packages/{name}");
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
        let url = format!("{PUB_DEV_API_BASE}/search?q={}", urlencoding::encode(query));
        let data = self.cache.get_cached(&url).await?;
        let search_result: SearchResponse = serde_json::from_slice(&data)?;

        let mut results = Vec::new();
        for entry in search_result.packages.into_iter().take(limit) {
            // Fetch metadata for each package
            let pkg_url = format!("{PUB_DEV_API_BASE}/packages/{}", entry.package);
            if let Ok(pkg_data) = self.cache.get_cached(&pkg_url).await
                && let Ok(info) = parse_package_info(&pkg_data)
            {
                results.push(info);
            }
        }

        Ok(results)
    }

    pub async fn get_package_info(&self, name: &str) -> Result<PackageInfo> {
        let url = format!("{PUB_DEV_API_BASE}/packages/{name}");
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
            published: e.published,
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
        name: pubspec.name.unwrap_or(response.name),
        description: pubspec.description,
        homepage: pubspec.homepage,
        repository: pubspec.repository,
        documentation: pubspec.documentation,
        version: response.latest.version,
        license: None,
    })
}

// PackageRegistry trait
#[async_trait::async_trait]
impl deps_core::PackageRegistry for PubDevRegistry {
    type Version = DartVersion;
    type Metadata = PackageInfo;
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

// VersionInfo trait
impl deps_core::VersionInfo for DartVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.retracted
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }
}

// PackageMetadata trait
impl deps_core::PackageMetadata for PackageInfo {
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
        &self.version
    }
}

// Registry trait (trait object support)
#[async_trait::async_trait]
impl deps_core::Registry for PubDevRegistry {
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
    fn test_package_url() {
        assert_eq!(package_url("provider"), "https://pub.dev/packages/provider");
        assert_eq!(package_url("http"), "https://pub.dev/packages/http");
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

    #[test]
    fn test_version_info_trait() {
        use deps_core::VersionInfo;
        let ver = DartVersion {
            version: "1.0.0".into(),
            retracted: true,
            published: None,
        };
        assert_eq!(ver.version_string(), "1.0.0");
        assert!(ver.is_yanked());
        assert!(ver.features().is_empty());
    }

    #[test]
    fn test_package_metadata_trait() {
        use deps_core::PackageMetadata;
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
    fn test_registry_package_url_trait() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = PubDevRegistry::new(cache);
        assert_eq!(
            registry.package_url("http"),
            "https://pub.dev/packages/http"
        );
    }

    #[test]
    fn test_registry_as_any() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = PubDevRegistry::new(cache);
        assert!(registry.as_any().is::<PubDevRegistry>());
    }
}
