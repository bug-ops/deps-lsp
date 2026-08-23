//! Maven Central registry client.
//!
//! Uses `maven-metadata.xml` from Maven Central CDN for version fetching
//! (fast, CDN-cached) and Solr search API for package search (full-text).

use crate::types::{ArtifactInfo, MavenVersion};
use crate::version::compare_versions;
use deps_core::{DepsError, HttpCache, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const MAVEN_REPO_BASE: &str = "https://repo1.maven.org/maven2";

/// Display name for Maven Central used in not-found and API-response error
/// messages. Reused by `deps-gradle`, which resolves through this registry.
pub const REGISTRY: &str = "Maven Central";
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
                urlencoding::encode(group_id),
                urlencoding::encode(artifact_id)
            )
        } else {
            format!(
                "https://central.sonatype.com/artifact/{}/{}",
                urlencoding::encode(group_id),
                urlencoding::encode(artifact_id)
            )
        }
    } else {
        format!(
            "https://central.sonatype.com/search?q={}",
            urlencoding::encode(name)
        )
    }
}

/// Moves the entry that should be considered "latest" to the front of `versions`, in place:
///
/// - If `release` (maven-metadata.xml's `<release>` element — the authoritative "last
///   deployed" version, which is not necessarily the qualifier-sorted top entry: it can
///   legitimately be a milestone/RC that was the most recent deploy) names an entry present
///   in `versions`, that entry moves to the front. A `release` naming something absent from
///   `versions` (malformed/inconsistent metadata) leaves the list untouched — there's
///   nothing in it to move, and nothing can be synthesized without violating the "index into
///   an existing slice" contract `select_latest_matching` needs.
/// - If `release` is absent (`<release>` missing from the metadata entirely, common for
///   Gradle Plugin Portal and older artifacts), the first non-prerelease entry moves to the
///   front instead — reproducing `get_latest_matching_typed`'s pre-existing else-branch, so
///   an artifact without `<release>` doesn't report a prerelease as "latest" just because it
///   happens to sort first (S7: this was the actual bug behind an earlier version of this
///   fix, which only handled the `release`-present case).
///
/// This lets every consumer of the (already sorted) list — `select_latest_matching`'s
/// pure `Some(0)` pick (`Registry::get_versions` is the only round trip available to it,
/// with no side channel for `<release>`), hover's "Recent versions" `*(latest)*` marker,
/// and completion's version list — agree with the wildcard pick without a second registry
/// call: `get_versions_typed` and `get_latest_matching_typed` already fetch
/// `(versions, release)` from the same single `get_metadata` call, so reordering here is free.
fn move_release_to_front(versions: &mut Vec<MavenVersion>, release: Option<&str>) {
    let target = match release {
        Some(release) => versions.iter().position(|v| v.version == release),
        None => versions
            .iter()
            .position(|v| !crate::version::is_prerelease(&v.version)),
    };
    let Some(pos) = target else { return };
    if pos != 0 {
        let entry = versions.remove(pos);
        versions.insert(0, entry);
    }
}

/// Picks the "latest" version for a wildcard (`*`/empty) requirement from already-fetched
/// `(versions, release)` metadata: prefers the `<release>`-designated entry — synthesizing a
/// placeholder `MavenVersion` if `release` names something absent from `versions`, since
/// `<release>` is still authoritative even when the metadata is otherwise inconsistent — else
/// the first non-prerelease entry, else the first entry.
///
/// Shares its release-present/absent decision shape with [`move_release_to_front`], but
/// differs in the one case that function structurally cannot handle: `release` naming an
/// entry absent from `versions`. `move_release_to_front` must return an index into the
/// existing slice (or no-op), so it can't invent an entry; this function returns an owned
/// `MavenVersion` and has no such constraint, so it trusts `release` unconditionally instead
/// — the same asymmetry `get_latest_matching_typed` had before this extraction.
fn pick_wildcard_latest(versions: &[MavenVersion], release: Option<&str>) -> Option<MavenVersion> {
    if let Some(rel) = release {
        return Some(
            versions
                .iter()
                .find(|v| v.version == rel)
                .cloned()
                .unwrap_or(MavenVersion {
                    version: rel.to_string(),
                    timestamp: None,
                }),
        );
    }
    versions
        .iter()
        .find(|v| !crate::version::is_prerelease(&v.version))
        .or_else(|| versions.first())
        .cloned()
}

#[derive(Clone)]
pub struct MavenCentralRegistry {
    cache: Arc<HttpCache>,
}

impl MavenCentralRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    async fn get_metadata(&self, name: &str) -> Result<(Vec<MavenVersion>, Option<String>)> {
        let urls = metadata_urls(name);
        if urls.is_empty() {
            tracing::debug!(package = %name, "skipping: invalid groupId:artifactId format");
            return Ok((vec![], None));
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

    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<MavenVersion>> {
        let (mut versions, release) = self.get_metadata(name).await?;
        move_release_to_front(&mut versions, release.as_deref());
        Ok(versions)
    }

    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<MavenVersion>> {
        let (versions, release) = self.get_metadata(name).await?;
        // For Maven MVP: exact string match, or latest stable if req is empty/wildcard
        if req.is_empty() || req == "*" {
            return Ok(pick_wildcard_latest(&versions, release.as_deref()));
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

/// Parses maven-metadata.xml to extract version list and the authoritative release version.
///
/// Returns `(versions, release)` where `release` is the `<release>` element from
/// `<versioning>`, if present. Use `release` as the authoritative latest stable version
/// instead of sorting all versions.
///
/// # Errors
///
/// Returns `DepsError::CacheError` if the XML is malformed. A truncated `versions` list from
/// silently stopping at the parse error, rather than surfacing it, would itself be a source
/// of the same "real version missing from `available`" false-positive class this PR's
/// diagnostic guards against elsewhere.
fn parse_metadata_xml(data: &[u8]) -> Result<(Vec<MavenVersion>, Option<String>)> {
    let mut reader = Reader::from_reader(data);
    let mut versions = Vec::new();
    let mut release: Option<String> = None;
    let mut in_versions = false;
    let mut in_version = false;
    let mut in_release = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"versions" => in_versions = true,
                b"version" if in_versions => in_version = true,
                b"release" if !in_versions => in_release = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"versions" => in_versions = false,
                b"version" => in_version = false,
                b"release" => in_release = false,
                _ => {}
            },
            Ok(Event::Text(e)) => {
                let Ok(decoded) = e.decode() else {
                    buf.clear();
                    continue;
                };
                let text = quick_xml::escape::unescape(&decoded).unwrap_or_default();
                let s = text.trim().to_string();
                if s.is_empty() {
                    buf.clear();
                    continue;
                }
                if in_version {
                    versions.push(MavenVersion {
                        version: s,
                        timestamp: None,
                    });
                } else if in_release {
                    release = Some(s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DepsError::CacheError(format!(
                    "malformed maven-metadata.xml: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    versions.sort_by(|a, b| compare_versions(&b.version, &a.version));
    Ok((versions, release))
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
                name: name.into(),
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
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions_typed(name.as_str()).await?;
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
                .get_latest_matching_typed(name.as_str(), req.as_str())
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
            let results = self.search_typed(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn package_url(&self, name: &deps_core::PackageName) -> String {
        package_url(name.as_str())
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        // `versions` is `get_versions`'s output, which already moved the
        // maven-metadata.xml `<release>` entry to the front (`move_release_to_front`) — so
        // index 0 *is* the authoritative "latest" here, not just a sort-order guess. This
        // keeps `select_latest_matching` (no I/O, no side channel) in agreement with
        // `get_latest_matching_typed`'s `<release>`-preferring pick without a second
        // registry round trip.
        let req_str = req.as_str();
        if req_str.is_empty() || req_str == "*" {
            return if versions.is_empty() { None } else { Some(0) };
        }
        versions.iter().position(|v| v.version_string() == req_str)
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
    fn test_package_url_encodes_malicious_group_and_artifact() {
        let url = package_url("evil)[:pkg](x");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_google_encodes_malicious_group_and_artifact() {
        let url = package_url("androidx.evil)[:pkg](x");
        assert!(url.contains("maven.google.com"));
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<%:pkg>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
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

        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.14.0");
        assert_eq!(versions[1].version, "3.13.0");
        assert_eq!(versions[2].version, "3.12.0");
        assert_eq!(release.as_deref(), Some("3.14.0"));
    }

    #[test]
    fn test_parse_metadata_xml_empty() {
        let xml = r#"<?xml version="1.0"?><metadata><versioning><versions></versions></versioning></metadata>"#;
        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert!(versions.is_empty());
        assert!(release.is_none());
    }

    #[test]
    fn test_parse_metadata_xml_legacy_versions_release_wins() {
        // Guava scenario: legacy bare-qualifier r03-r09 releases must sort below
        // properly-formed numeric releases, and <release> is authoritative for latest stable.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>33.5.0-jre</latest>
    <release>33.5.0-jre</release>
    <versions>
      <version>r03</version>
      <version>r05</version>
      <version>r09</version>
      <version>14.0</version>
      <version>33.4.0-jre</version>
      <version>33.5.0-jre</version>
    </versions>
  </versioning>
</metadata>"#;

        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(versions.len(), 6);
        assert_eq!(release.as_deref(), Some("33.5.0-jre"));

        let ordered: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(
            ordered,
            vec!["33.5.0-jre", "33.4.0-jre", "14.0", "r09", "r05", "r03"],
            "numeric releases must sort above legacy bare qualifiers"
        );
    }

    #[test]
    fn test_parse_metadata_xml_mixed_segment_count_sort_does_not_panic() {
        // C1 regression guard: an artifact publishing both a 2- and 3-segment
        // spelling of the same release plus a same-base above-release
        // qualifier build used to make compare_versions a non-total order
        // (#182's absent-as-zero rule collided with qualifier ranking at the
        // flat segment index), which panics `Vec::sort_by`'s total-order
        // detector. compare_versions must stay total-order; range/interval
        // normalization lives in compare_versions_for_range instead.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>widget</artifactId>
  <versioning>
    <versions>
      <version>1.0</version>
      <version>1.0.0</version>
      <version>1.0-jre</version>
    </versions>
  </versioning>
</metadata>"#;

        let (versions, _release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        let ordered: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(ordered, vec!["1.0.0", "1.0-jre", "1.0"]);
    }

    /// Minor item: malformed XML must surface as an error, not silently return a truncated
    /// `versions` list — a truncation could itself drop a real, installable version out of
    /// `available`, the exact false-positive class this PR's diagnostic guards against.
    #[test]
    fn test_parse_metadata_xml_malformed_returns_error_instead_of_silent_truncation() {
        let xml = b"<metadata><versioning><versions><version>1.0.0</version></versions></wrong></metadata>";
        let result = parse_metadata_xml(xml);
        assert!(result.is_err());
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
            registry.package_url(&deps_core::PackageName::new("com.example:lib")),
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

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        // `select_latest_matching`'s contract is "index 0 of a `get_versions`-shaped list
        // is latest" — `get_versions_typed` is what puts the right entry at index 0 (via
        // `move_release_to_front`), not `select_latest_matching` itself, so this fixture
        // reflects an already-correctly-ordered list rather than an unordered one.
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(MavenVersion {
                version: "1.0.0".into(),
                timestamp: None,
            }),
            Box::new(MavenVersion {
                version: "2.0.0-SNAPSHOT".into(),
                timestamp: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_move_release_to_front_reorders() {
        let mut versions = vec![
            MavenVersion {
                version: "3.4.0".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "4.0.0-M1".into(),
                timestamp: None,
            },
        ];
        // <release> designates the milestone even though it isn't the "stable-looking"
        // entry — the exact `spring-core` scenario this fix targets.
        move_release_to_front(&mut versions, Some("4.0.0-M1"));
        assert_eq!(versions[0].version, "4.0.0-M1");
        assert_eq!(versions[1].version, "3.4.0");
    }

    #[test]
    fn test_move_release_to_front_already_first_is_a_no_op() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                timestamp: None,
            },
        ];
        move_release_to_front(&mut versions, Some("1.0.0"));
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "0.9.0");
    }

    #[test]
    fn test_move_release_to_front_release_absent_from_list_is_a_no_op() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                timestamp: None,
            },
        ];
        move_release_to_front(&mut versions, Some("2.0.0"));
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "0.9.0");
    }

    #[test]
    fn test_move_release_to_front_no_release_is_a_no_op() {
        let mut versions = vec![MavenVersion {
            version: "1.0.0".into(),
            timestamp: None,
        }];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "1.0.0");
    }

    /// S7 regression: an artifact without a `<release>` element used to leave index 0 at
    /// whatever the raw qualifier sort put first, which can be a prerelease.
    #[test]
    fn test_move_release_to_front_no_release_falls_back_to_first_non_prerelease() {
        let mut versions = vec![
            MavenVersion {
                version: "1.5.0-alpha01".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "1.4.0".into(),
                timestamp: None,
            },
        ];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "1.4.0");
        assert_eq!(versions[1].version, "1.5.0-alpha01");
    }

    #[test]
    fn test_move_release_to_front_no_release_and_all_prerelease_leaves_sorted_top() {
        let mut versions = vec![
            MavenVersion {
                version: "2.0.0-alpha".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "1.0.0-beta".into(),
                timestamp: None,
            },
        ];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "2.0.0-alpha");
    }

    #[test]
    fn test_pick_wildcard_latest_prefers_release() {
        let versions = vec![
            MavenVersion {
                version: "1.4.0".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "1.5.0-M1".into(),
                timestamp: None,
            },
        ];
        let picked = pick_wildcard_latest(&versions, Some("1.5.0-M1")).unwrap();
        assert_eq!(picked.version, "1.5.0-M1");
    }

    #[test]
    fn test_pick_wildcard_latest_release_absent_from_list_synthesizes() {
        // The one documented case where pick_wildcard_latest and
        // move_release_to_front/select_latest_matching structurally cannot agree: <release>
        // is still trusted here since this function can return an owned value, but
        // move_release_to_front can only return an index into the existing slice.
        let versions = vec![MavenVersion {
            version: "1.0.0".into(),
            timestamp: None,
        }];
        let picked = pick_wildcard_latest(&versions, Some("9.9.9")).unwrap();
        assert_eq!(picked.version, "9.9.9");
    }

    #[test]
    fn test_pick_wildcard_latest_no_release_prefers_non_prerelease() {
        let versions = vec![
            MavenVersion {
                version: "2.0.0-alpha".into(),
                timestamp: None,
            },
            MavenVersion {
                version: "1.0.0".into(),
                timestamp: None,
            },
        ];
        let picked = pick_wildcard_latest(&versions, None).unwrap();
        assert_eq!(picked.version, "1.0.0");
    }

    /// S8: `select_latest_matching` (via `move_release_to_front`) and
    /// `get_latest_matching_typed` (via `pick_wildcard_latest`) must agree on the same
    /// `(versions, release)` fixture across the three scenarios that previously diverged
    /// (S3/S7): release present, release absent with a non-prerelease available, release
    /// absent with only prereleases available.
    fn assert_select_latest_matching_agrees_with_pick_wildcard_latest(
        versions: Vec<MavenVersion>,
        release: Option<&str>,
    ) {
        use deps_core::{Registry, VersionReq};

        let wildcard_pick = pick_wildcard_latest(&versions, release);

        let mut reordered = versions;
        move_release_to_front(&mut reordered, release);
        let boxed: Vec<Box<dyn deps_core::Version>> = reordered
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();

        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(
            boxed[idx].version_string(),
            wildcard_pick.expect("fixture always has a pick").version
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_present() {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "1.4.0".into(),
                    timestamp: None,
                },
                MavenVersion {
                    version: "1.5.0-M1".into(),
                    timestamp: None,
                },
            ],
            Some("1.5.0-M1"),
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_absent_non_prerelease_exists()
     {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "1.5.0-alpha01".into(),
                    timestamp: None,
                },
                MavenVersion {
                    version: "1.4.0".into(),
                    timestamp: None,
                },
            ],
            None,
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_absent_only_prereleases()
     {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "2.0.0-alpha".into(),
                    timestamp: None,
                },
                MavenVersion {
                    version: "1.0.0-beta".into(),
                    timestamp: None,
                },
            ],
            None,
        );
    }
}
