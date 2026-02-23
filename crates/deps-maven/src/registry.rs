//! Maven Central registry client.
//!
//! Uses `maven-metadata.xml` from Maven Central CDN for version fetching
//! (fast, CDN-cached) and Solr search API for package search (full-text).

use crate::types::{ArtifactInfo, MavenVersion};
use crate::version::compare_versions;
use deps_core::{HttpCache, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const MAVEN_REPO_BASE: &str = "https://repo1.maven.org/maven2";
const GOOGLE_MAVEN_BASE: &str = "https://dl.google.com/dl/android/maven2";
const GRADLE_PLUGIN_PORTAL_BASE: &str = "https://plugins.gradle.org/m2";
const MAVEN_SEARCH_BASE: &str = "https://search.maven.org/solrsearch/select";

const GOOGLE_PREFIXES: &[&str] = &[
    "androidx.",
    "com.google.firebase.",
    "com.google.android.",
    "com.google.gms.",
    "com.android.",
];

fn is_google_group(group_id: &str) -> bool {
    GOOGLE_PREFIXES.iter().any(|p| group_id.starts_with(p))
}

fn repo_base_for_group(group_id: &str) -> &'static str {
    if is_google_group(group_id) {
        GOOGLE_MAVEN_BASE
    } else {
        MAVEN_REPO_BASE
    }
}

pub fn package_url(name: &str) -> String {
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    if parts.len() == 2 {
        let group_id = parts[0];
        let artifact_id = parts[1];
        if is_google_group(group_id) {
            format!(
                "https://maven.google.com/web/index.html#{}:{}",
                group_id, artifact_id
            )
        } else {
            format!(
                "https://central.sonatype.com/artifact/{}/{}",
                group_id, artifact_id
            )
        }
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
        let urls = metadata_urls(name);
        if urls.is_empty() {
            tracing::debug!(package = %name, "skipping: invalid groupId:artifactId format");
            return Ok(vec![]);
        }

        let mut last_err = None;
        for url in &urls {
            match self.cache.get_cached(url).await {
                Ok(data) => return parse_metadata_xml(&data),
                Err(e) => {
                    tracing::debug!(package = %name, url = %url, error = %e, "metadata fetch failed, trying next");
                    last_err = Some(e);
                }
            }
        }

        let e = last_err.expect("urls is non-empty");
        tracing::warn!(package = %name, error = %e, "all metadata URLs failed");
        Err(e)
    }

    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<MavenVersion>> {
        let versions = self.get_versions_typed(name).await?;
        // For Maven MVP: exact string match, or latest stable if req is empty/wildcard
        if req.is_empty() || req == "*" {
            // Prefer latest stable; fall back to latest pre-release if no stable exists
            let latest = versions
                .iter()
                .find(|v| !crate::version::is_prerelease(&v.version))
                .or_else(|| versions.first())
                .cloned();
            return Ok(latest);
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

/// Returns ordered list of maven-metadata.xml URLs to try for the given package.
///
/// Non-Google packages get two URLs: Maven Central (primary) and Gradle Plugin Portal (fallback).
/// Google-hosted packages get only the Google Maven URL — they are not mirrored elsewhere.
fn metadata_urls(name: &str) -> Vec<String> {
    let Some((group_id, artifact_id)) = name.split_once(':') else {
        return vec![];
    };
    let group_path = group_id.replace('.', "/");
    let primary_base = repo_base_for_group(group_id);
    let primary = format!("{primary_base}/{group_path}/{artifact_id}/maven-metadata.xml");

    if is_google_group(group_id) {
        vec![primary]
    } else {
        vec![
            primary,
            format!("{GRADLE_PLUGIN_PORTAL_BASE}/{group_path}/{artifact_id}/maven-metadata.xml"),
        ]
    }
}

/// Parses maven-metadata.xml to extract version list.
fn parse_metadata_xml(data: &[u8]) -> Result<Vec<MavenVersion>> {
    let mut reader = Reader::from_reader(data);
    let mut versions = Vec::new();
    let mut in_versions = false;
    let mut in_version = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"versions" => in_versions = true,
                b"version" if in_versions => in_version = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"versions" => in_versions = false,
                b"version" => in_version = false,
                _ => {}
            },
            Ok(Event::Text(e)) if in_version => {
                let Ok(decoded) = e.decode() else {
                    continue;
                };
                let text = quick_xml::escape::unescape(&decoded).unwrap_or_default();
                let version = text.trim().to_string();
                if !version.is_empty() {
                    versions.push(MavenVersion {
                        version,
                        timestamp: None,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    versions.sort_by(|a, b| compare_versions(&b.version, &a.version));
    Ok(versions)
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
struct SearchDoc {
    g: String,
    a: String,
    #[serde(rename = "latestVersion")]
    latest_version: Option<String>,
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

impl deps_core::Registry for MavenCentralRegistry {
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

    #[test]
    fn test_repo_base_for_group_central() {
        assert_eq!(repo_base_for_group("org.apache.commons"), MAVEN_REPO_BASE);
        assert_eq!(repo_base_for_group("com.example"), MAVEN_REPO_BASE);
        // com.google.protobuf is on Maven Central, not Google Maven
        assert_eq!(repo_base_for_group("com.google.protobuf"), MAVEN_REPO_BASE);
    }

    #[test]
    fn test_repo_base_for_group_google() {
        assert_eq!(repo_base_for_group("androidx.core"), GOOGLE_MAVEN_BASE);
        assert_eq!(
            repo_base_for_group("com.google.firebase.crashlytics"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(
            repo_base_for_group("com.google.android.gms"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(
            repo_base_for_group("com.google.gms.google-services"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(repo_base_for_group("com.android.tools"), GOOGLE_MAVEN_BASE);
    }

    #[test]
    fn test_package_url_central() {
        assert_eq!(
            package_url("org.apache.commons:commons-lang3"),
            "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3"
        );
    }

    #[test]
    fn test_package_url_google() {
        assert_eq!(
            package_url("androidx.core:core-ktx"),
            "https://maven.google.com/web/index.html#androidx.core:core-ktx"
        );
        assert_eq!(
            package_url("com.google.firebase.crashlytics:firebase-crashlytics"),
            "https://maven.google.com/web/index.html#com.google.firebase.crashlytics:firebase-crashlytics"
        );
    }

    #[test]
    fn test_package_url_no_colon() {
        let url = package_url("bad");
        assert!(url.contains("search.maven") || url.contains("sonatype.com"));
    }

    #[test]
    fn test_metadata_urls_central_has_two_urls() {
        let urls = metadata_urls("org.apache.commons:commons-lang3");
        assert_eq!(urls.len(), 2);
        assert_eq!(
            urls[0],
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
        assert_eq!(
            urls[1],
            "https://plugins.gradle.org/m2/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
    }

    #[test]
    fn test_metadata_urls_google_has_one_url() {
        let urls = metadata_urls("androidx.core:core-ktx");
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0],
            "https://dl.google.com/dl/android/maven2/androidx/core/core-ktx/maven-metadata.xml"
        );

        let urls = metadata_urls("com.google.firebase.crashlytics:firebase-crashlytics");
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0],
            "https://dl.google.com/dl/android/maven2/com/google/firebase/crashlytics/firebase-crashlytics/maven-metadata.xml"
        );
    }

    #[test]
    fn test_metadata_urls_no_colon() {
        assert!(metadata_urls("bad").is_empty());
    }

    #[test]
    fn test_parse_metadata_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <versioning>
    <latest>3.14.0</latest>
    <release>3.14.0</release>
    <versions>
      <version>3.12.0</version>
      <version>3.13.0</version>
      <version>3.14.0</version>
    </versions>
  </versioning>
</metadata>"#;

        let versions = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.14.0");
        assert_eq!(versions[1].version, "3.13.0");
        assert_eq!(versions[2].version, "3.12.0");
    }

    #[test]
    fn test_parse_metadata_xml_empty() {
        let xml = r#"<?xml version="1.0"?><metadata><versioning><versions></versions></versioning></metadata>"#;
        let versions = parse_metadata_xml(xml.as_bytes()).unwrap();
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
