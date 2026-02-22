//! Maven Central registry client.

use crate::types::{ArtifactInfo, MavenVersion};
use crate::version::compare_versions;
use deps_core::{HttpCache, Result};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const MAVEN_SEARCH_BASE: &str = "https://search.maven.org/solrsearch/select";

pub fn package_url(name: &str) -> String {
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    if parts.len() == 2 {
        format!(
            "https://central.sonatype.com/artifact/{}/{}",
            parts[0], parts[1]
        )
    } else {
        format!(
            "https://central.sonatype.com/search?q={}",
            urlencoding::encode(name)
        )
    }
}

#[derive(Clone)]
pub struct MavenCentralRegistry {
    cache: Arc<HttpCache>,
}

impl MavenCentralRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<MavenVersion>> {
        let parts: Vec<&str> = name.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(vec![]);
        }
        let (group_id, artifact_id) = (parts[0], parts[1]);

        let url = format!(
            "{MAVEN_SEARCH_BASE}?q=g:{group}+AND+a:{artifact}&core=gav&rows=200&wt=json",
            group = urlencoding::encode(group_id),
            artifact = urlencoding::encode(artifact_id),
        );

        let data = self.cache.get_cached(&url).await?;
        parse_versions_response(&data)
    }

    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<MavenVersion>> {
        let versions = self.get_versions_typed(name).await?;
        // For Maven MVP: exact string match, or latest stable if req is empty/wildcard
        if req.is_empty() || req == "*" {
            return Ok(versions
                .into_iter()
                .find(|v| !crate::version::is_prerelease(&v.version)));
        }
        Ok(versions.into_iter().find(|v| v.version == req))
    }

    pub async fn search_typed(&self, query: &str, limit: usize) -> Result<Vec<ArtifactInfo>> {
        let url = format!(
            "{MAVEN_SEARCH_BASE}?q={q}&rows={limit}&wt=json",
            q = urlencoding::encode(query),
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data, limit)
    }
}

#[derive(Deserialize)]
struct SolrVersionResponse {
    response: SolrVersionBody,
}

#[derive(Deserialize)]
struct SolrVersionBody {
    #[serde(default)]
    docs: Vec<VersionDoc>,
}

#[derive(Deserialize)]
struct SolrSearchResponse {
    response: SolrSearchBody,
}

#[derive(Deserialize)]
struct SolrSearchBody {
    #[serde(default)]
    docs: Vec<SearchDoc>,
}

#[derive(Deserialize)]
struct VersionDoc {
    #[serde(rename = "v")]
    version: String,
    #[serde(default)]
    timestamp: Option<u64>,
}

#[derive(Deserialize)]
struct SearchDoc {
    g: String,
    a: String,
    #[serde(rename = "latestVersion")]
    latest_version: Option<String>,
}

fn parse_versions_response(data: &[u8]) -> Result<Vec<MavenVersion>> {
    let response: SolrVersionResponse = serde_json::from_slice(data)?;

    let mut versions: Vec<MavenVersion> = response
        .response
        .docs
        .into_iter()
        .map(|d| MavenVersion {
            version: d.version,
            timestamp: d.timestamp,
        })
        .collect();

    versions.sort_by(|a, b| compare_versions(&b.version, &a.version));
    Ok(versions)
}

fn parse_search_response(data: &[u8], limit: usize) -> Result<Vec<ArtifactInfo>> {
    let response: SolrSearchResponse = serde_json::from_slice(data)?;

    let results = response
        .response
        .docs
        .into_iter()
        .take(limit)
        .map(|d| {
            let name = format!("{}:{}", d.g, d.a);
            ArtifactInfo {
                group_id: d.g,
                artifact_id: d.a,
                name,
                description: None,
                latest_version: d.latest_version.unwrap_or_default(),
                repository: None,
            }
        })
        .collect();

    Ok(results)
}

// Registry trait (trait-object based)
#[async_trait::async_trait]
impl deps_core::Registry for MavenCentralRegistry {
    async fn get_versions(&self, name: &str) -> Result<Vec<Box<dyn deps_core::Version>>> {
        let versions = self.get_versions_typed(name).await?;
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
        let version = self.get_latest_matching_typed(name, req).await?;
        Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Box<dyn deps_core::Metadata>>> {
        let results = self.search_typed(query, limit).await?;
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
        assert_eq!(
            package_url("org.apache.commons:commons-lang3"),
            "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3"
        );
    }

    #[test]
    fn test_package_url_no_colon() {
        let url = package_url("bad");
        assert!(url.contains("search.maven") || url.contains("sonatype.com"));
    }

    #[test]
    fn test_parse_versions_response() {
        let json = r#"{
            "response": {
                "numFound": 3,
                "docs": [
                    {"g": "org.apache.commons", "a": "commons-lang3", "v": "3.14.0"},
                    {"g": "org.apache.commons", "a": "commons-lang3", "v": "3.13.0"},
                    {"g": "org.apache.commons", "a": "commons-lang3", "v": "3.12.0"}
                ]
            }
        }"#;

        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.14.0");
        assert_eq!(versions[1].version, "3.13.0");
    }

    #[test]
    fn test_parse_versions_response_empty() {
        let json = r#"{"response": {"numFound": 0, "docs": []}}"#;
        let versions = parse_versions_response(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "response": {
                "numFound": 2,
                "docs": [
                    {"g": "org.apache.commons", "a": "commons-lang3", "latestVersion": "3.14.0"},
                    {"g": "org.apache.commons", "a": "commons-math3", "latestVersion": "3.6.1"}
                ]
            }
        }"#;

        let results = parse_search_response(json.as_bytes(), 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(results[0].latest_version, "3.14.0");
    }

    #[test]
    fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = MavenCentralRegistry::new(cache);
    }

    #[test]
    fn test_registry_package_url_trait() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        assert_eq!(
            registry.package_url("com.example:lib"),
            "https://central.sonatype.com/artifact/com.example/lib"
        );
    }

    #[test]
    fn test_registry_as_any() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        assert!(registry.as_any().is::<MavenCentralRegistry>());
    }
}
