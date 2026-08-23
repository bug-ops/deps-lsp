//! Maven Central registry client.
//!
//! Uses `maven-metadata.xml` from Maven Central CDN for version fetching
//! (fast, CDN-cached) and Solr search API for package search (full-text).

use crate::types::{ArtifactInfo, MavenVersion};
use crate::version::compare_versions;
use deps_core::{DepsError, HttpCache, PublishTime, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
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
                    published_at: None,
                }),
        );
    }
    versions
        .iter()
        .find(|v| !crate::version::is_prerelease(&v.version))
        .or_else(|| versions.first())
        .cloned()
}

/// Whether `base` (a metadata directory URL returned by `get_metadata`) is served by
/// Maven Central specifically, i.e. whether fetching its directory listing is worth the
/// request.
///
/// Google Maven's listing always 404s (no negative caching in [`HttpCache`], so an
/// unconditional fetch would retry forever) and the Gradle Plugin Portal's listing has no
/// date column (a wasted fetch+parse every time) — both must cost zero extra requests, not
/// one doomed one, so this checks the specific winning base rather than "some base exists".
fn should_fetch_listing(base: &str) -> bool {
    base.starts_with(MAVEN_REPO_BASE)
}

/// Attaches `published_at` to each version whose string matches an entry in `times`.
///
/// A version present in `versions` but absent from `times` (or vice versa) is not an
/// error: it simply keeps/never gets a `published_at`. Order is untouched — this must run
/// before [`move_release_to_front`] so ordering stays governed by that function alone.
fn attach_publish_times(versions: &mut [MavenVersion], times: &HashMap<String, PublishTime>) {
    for v in versions {
        v.published_at = times.get(&v.version).copied();
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

    /// Fetches and parses `maven-metadata.xml`, also returning the directory URL of
    /// whichever repository base (Maven Central, Google Maven, or the Gradle Plugin
    /// Portal fallback) actually served it — `metadata_urls`' bases differ per group, so
    /// the winning base can only be known after the fetch succeeds, not guessed upfront.
    async fn get_metadata(
        &self,
        name: &str,
    ) -> Result<(Vec<MavenVersion>, Option<String>, Option<String>)> {
        let urls = metadata_urls(name);
        if urls.is_empty() {
            tracing::debug!(package = %name, "skipping: invalid groupId:artifactId format");
            return Ok((vec![], None, None));
        }

        let mut last_err = None;
        for url in &urls {
            match self.cache.get_cached(url).await {
                Ok(data) => {
                    let (versions, release) = parse_metadata_xml(&data)?;
                    let base = url.strip_suffix("maven-metadata.xml").map(str::to_string);
                    return Ok((versions, release, base));
                }
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

    /// Fetches the directory listing at `base` (a Maven Central artifact directory URL,
    /// trailing slash) and returns the version → publish-time map parsed from it.
    ///
    /// Never fails the caller: any fetch error, timeout, or unparseable body degrades to
    /// an empty map, logged at `debug`, so a listing outage never affects the version list
    /// itself — only whether ages are shown alongside it.
    async fn fetch_publish_times(&self, base: &str) -> HashMap<String, PublishTime> {
        match self.cache.get_cached(base).await {
            Ok(data) => parse_publish_times(&data),
            Err(e) => {
                tracing::debug!(url = %base, error = %e, "listing fetch failed, publish times unavailable");
                HashMap::new()
            }
        }
    }

    /// Same as [`Self::get_versions_typed`], but attaches [`MavenVersion::published_at`]
    /// from the `repo1.maven.org` directory listing when `freshness_enabled` and the
    /// artifact resolved through Maven Central.
    ///
    /// The listing fetch is gated on the winning base being Maven Central specifically —
    /// not merely present — because Google Maven's listing always 404s (no negative
    /// caching in [`HttpCache`], so an unconditional fetch would retry forever) and the
    /// Gradle Plugin Portal's listing has no date column (a wasted fetch+parse on every
    /// call). Both degrade to zero extra requests here rather than one doomed one.
    pub async fn get_versions_typed_with(
        &self,
        name: &str,
        freshness_enabled: bool,
    ) -> Result<Vec<MavenVersion>> {
        let (mut versions, release, base) = self.get_metadata(name).await?;
        if freshness_enabled && let Some(base) = base.as_deref().filter(|b| should_fetch_listing(b))
        {
            let times = self.fetch_publish_times(base).await;
            attach_publish_times(&mut versions, &times);
        }
        move_release_to_front(&mut versions, release.as_deref());
        Ok(versions)
    }

    /// Fetches all available versions, without publish-time enrichment.
    ///
    /// Delegates to [`Self::get_versions_typed_with`] with freshness disabled so the two
    /// paths cannot drift apart.
    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<MavenVersion>> {
        self.get_versions_typed_with(name, false).await
    }

    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<MavenVersion>> {
        let (versions, release, _base) = self.get_metadata(name).await?;
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
                        published_at: None,
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

/// Parses a Maven Central directory listing (`repo1.maven.org/maven2/{g}/{a}/`) into a
/// version → publish-time map.
///
/// Line-oriented, not a full HTML parser: each line is checked independently for both an
/// anchor `href` (never the display text, which Maven Central sometimes pads or wraps in
/// a `title=` attribute) and a `YYYY-MM-DD HH:MM` timestamp anywhere on the line; a line
/// missing either yields nothing. This is what makes the Gradle Plugin Portal's dateless
/// `<pre><a href="X/">X/</a></pre>` listing format — and any other listing that carries no
/// date column — parse to an empty map instead of a guess.
///
/// Bounded by the same 32 MiB response cap [`HttpCache`] applies to every fetch (not a
/// meaningfully tight bound on its own); real listings are far smaller (up to ~245 KB /
/// ~2000 anchors observed for a large artifact).
fn parse_publish_times(html: &[u8]) -> HashMap<String, PublishTime> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(html);
    let Some(pre) = extract_pre_block(&text) else {
        return map;
    };

    for line in pre.lines() {
        let Some(href) = extract_href(line) else {
            continue;
        };
        // Only directory entries (trailing `/`) are version directories — a sibling file
        // entry (`maven-metadata.xml`, `.md5`, `.sha1`, ...) also carries an href and a
        // date, but is never a version, so keeping it out of the map avoids polluting it
        // with keys that will just never be looked up.
        let Some(version) = href.strip_suffix('/') else {
            continue;
        };
        if version.is_empty() || version == ".." {
            continue;
        }
        let Some(date_str) = find_date_time(line) else {
            continue;
        };
        let rfc3339 = format!("{}T{}:00Z", &date_str[..10], &date_str[11..16]);
        if let Some(published) = PublishTime::parse_rfc3339(&rfc3339) {
            map.insert(version.to_string(), published);
        }
    }

    map
}

/// Slices out the body of the first `<pre>...</pre>` block, case-sensitively (Maven
/// Central and the Gradle Plugin Portal both emit lowercase tags). Returns `None` when no
/// `<pre>` block is present, so a page shaped nothing like a directory listing yields an
/// empty map rather than scanning arbitrary HTML for anchor-shaped text.
fn extract_pre_block(html: &str) -> Option<&str> {
    let open = html.find("<pre")?;
    let content_start = html[open..].find('>')? + open + 1;
    let close = html[content_start..].find("</pre")?;
    Some(&html[content_start..content_start + close])
}

/// Extracts an anchor's `href` attribute value from a listing line, ignoring display text.
fn extract_href(line: &str) -> Option<&str> {
    let idx = line.find("href=\"")?;
    let rest = &line[idx + 6..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Finds the first `YYYY-MM-DD HH:MM` substring anywhere in `line`, independent of column
/// alignment or padding. All matched bytes are ASCII, so the returned slice's byte offsets
/// are always valid `str` char boundaries.
fn find_date_time(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let window = 16; // "YYYY-MM-DD HH:MM"
    if bytes.len() < window {
        return None;
    }
    for start in 0..=(bytes.len() - window) {
        let candidate = &bytes[start..start + window];
        if is_date_time_shape(candidate) {
            return Some(&line[start..start + window]);
        }
    }
    None
}

fn is_date_time_shape(b: &[u8]) -> bool {
    let digit = u8::is_ascii_digit;
    digit(&b[0])
        && digit(&b[1])
        && digit(&b[2])
        && digit(&b[3])
        && b[4] == b'-'
        && digit(&b[5])
        && digit(&b[6])
        && b[7] == b'-'
        && digit(&b[8])
        && digit(&b[9])
        && b[10] == b' '
        && digit(&b[11])
        && digit(&b[12])
        && b[13] == b':'
        && digit(&b[14])
        && digit(&b[15])
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

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self
                .get_versions_typed_with(name.as_str(), freshness.enabled)
                .await?;
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

    // Maven Central has no retraction concept (`types.rs:98`) — `is_yanked`
    // is hardcoded `false`. Also covers Gradle, whose `registry()` returns
    // its own instance of this same `MavenCentralRegistry` type (#233).
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
                published_at: None,
            }),
            Box::new(MavenVersion {
                version: "2.0.0-SNAPSHOT".into(),
                published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "4.0.0-M1".into(),
                published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                published_at: None,
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
            published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "1.4.0".into(),
                published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "1.0.0-beta".into(),
                published_at: None,
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
                published_at: None,
            },
            MavenVersion {
                version: "1.5.0-M1".into(),
                published_at: None,
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
            published_at: None,
        }];
        let picked = pick_wildcard_latest(&versions, Some("9.9.9")).unwrap();
        assert_eq!(picked.version, "9.9.9");
    }

    #[test]
    fn test_pick_wildcard_latest_no_release_prefers_non_prerelease() {
        let versions = vec![
            MavenVersion {
                version: "2.0.0-alpha".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
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
                    published_at: None,
                },
                MavenVersion {
                    version: "1.5.0-M1".into(),
                    published_at: None,
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
                    published_at: None,
                },
                MavenVersion {
                    version: "1.4.0".into(),
                    published_at: None,
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
                    published_at: None,
                },
                MavenVersion {
                    version: "1.0.0-beta".into(),
                    published_at: None,
                },
            ],
            None,
        );
    }

    // --- parse_publish_times: fixtures captured live from repo1.maven.org and
    // plugins.gradle.org on 2026-08-24 (see handoff for the exact `curl` commands) ---

    /// A trimmed excerpt of the real `repo1.maven.org/maven2/org/apache/commons/commons-lang3/`
    /// listing: the `../` parent anchor, several version directories (padded display text +
    /// `title=` attribute, exactly as Maven Central emits), and a couple of sibling file
    /// entries (`maven-metadata.xml.md5` etc.) that carry dates too but are not versions.
    const REPO1_FIXTURE: &str = r#"<pre id="contents">
<a href="../">../</a>
<a href="3.12.0/" title="3.12.0/">3.12.0/</a>                                           2021-02-26 20:40         -
<a href="3.13.0/" title="3.13.0/">3.13.0/</a>                                           2023-07-23 19:44         -
<a href="3.14.0/" title="3.14.0/">3.14.0/</a>                                           2023-11-18 15:03         -
<a href="maven-metadata.xml" title="maven-metadata.xml">maven-metadata.xml</a>                                2025-11-16 12:55       817
<a href="maven-metadata.xml.md5" title="maven-metadata.xml.md5">maven-metadata.xml.md5</a>                            2025-11-16 12:55        32
</pre>"#;

    #[test]
    fn test_parse_publish_times_repo1_fixture() {
        let map = parse_publish_times(REPO1_FIXTURE.as_bytes());

        assert_eq!(
            map.get("3.14.0").copied(),
            PublishTime::parse_rfc3339("2023-11-18T15:03:00Z")
        );
        assert_eq!(
            map.get("3.12.0").copied(),
            PublishTime::parse_rfc3339("2021-02-26T20:40:00Z")
        );
        // The `../` parent anchor never becomes a "version".
        assert!(!map.contains_key(".."));
        assert!(!map.contains_key(""));
        // Sibling file entries (no trailing `/` in their href) are not versions either,
        // even though they carry a date too (M2).
        assert!(!map.contains_key("maven-metadata.xml"));
        assert!(!map.contains_key("maven-metadata.xml.md5"));
    }

    /// Real `plugins.gradle.org/m2/.../spring-boot-gradle-plugin/` shape: one `<pre>` per
    /// anchor, no date column at all. `extract_pre_block` only ever sees the first `<pre>`,
    /// but the outcome is the same either way — no line here carries a date, so nothing
    /// is ever inserted.
    const GRADLE_PLUGIN_PORTAL_FIXTURE: &str = r#"<pre><a href="1.4.2.RELEASE/">1.4.2.RELEASE/</a></pre>
<pre><a href="1.5.0.RELEASE/">1.5.0.RELEASE/</a></pre>"#;

    #[test]
    fn test_parse_publish_times_gradle_plugin_portal_dateless_is_empty() {
        let map = parse_publish_times(GRADLE_PLUGIN_PORTAL_FIXTURE.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_publish_times_malformed_date_entry_absent_rest_parsed() {
        let html = r#"<pre id="contents">
<a href="1.0.0/" title="1.0.0/">1.0.0/</a>                                            2011-13-45 99:99         -
<a href="1.0.1/" title="1.0.1/">1.0.1/</a>                                            2011-09-28 16:04         -
</pre>"#;
        let map = parse_publish_times(html.as_bytes());
        assert!(!map.contains_key("1.0.0"));
        assert_eq!(
            map.get("1.0.1").copied(),
            PublishTime::parse_rfc3339("2011-09-28T16:04:00Z")
        );
    }

    #[test]
    fn test_parse_publish_times_no_pre_block_is_empty() {
        let html = r"<html><body>not a listing at all</body></html>";
        let map = parse_publish_times(html.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_publish_times_empty_body_is_empty() {
        let map = parse_publish_times(b"");
        assert!(map.is_empty());
    }

    // --- should_fetch_listing (S2: gate on the winning base, not "some base exists") ---

    #[test]
    fn test_should_fetch_listing_maven_central_base() {
        assert!(should_fetch_listing(
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/"
        ));
    }

    #[test]
    fn test_should_fetch_listing_google_maven_base_is_false() {
        assert!(!should_fetch_listing(
            "https://dl.google.com/dl/android/maven2/androidx/core/core/"
        ));
    }

    #[test]
    fn test_should_fetch_listing_gradle_plugin_portal_base_is_false() {
        assert!(!should_fetch_listing(
            "https://plugins.gradle.org/m2/org/example/plugin/"
        ));
    }

    // --- attach_publish_times: version/date pairing edge cases ---

    #[test]
    fn test_attach_publish_times_matches_by_version_string() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "2.0.0".into(),
                published_at: None,
            },
        ];
        let mut times = HashMap::new();
        times.insert(
            "1.0.0".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        attach_publish_times(&mut versions, &times);

        assert_eq!(
            versions[0].published_at,
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z")
        );
        assert_eq!(versions[1].published_at, None);
        // Order is untouched.
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "2.0.0");
    }

    #[test]
    fn test_attach_publish_times_extra_map_entry_does_not_panic_or_cross_assign() {
        let mut versions = vec![MavenVersion {
            version: "1.0.0".into(),
            published_at: None,
        }];
        let mut times = HashMap::new();
        // A version present in the listing but absent from maven-metadata.xml — must not
        // be assigned to an unrelated entry, and must not panic.
        times.insert(
            "9.9.9-not-in-metadata".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        attach_publish_times(&mut versions, &times);
        assert_eq!(versions[0].published_at, None);
    }

    #[test]
    fn test_attach_publish_times_empty_map_leaves_all_none() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "2.0.0".into(),
                published_at: None,
            },
        ];
        attach_publish_times(&mut versions, &HashMap::new());
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    // --- fetch_publish_times: HTTP degradation (mockito) ---

    #[tokio::test]
    async fn test_fetch_publish_times_success_parses_and_attaches() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/org/example/widget/")
            .with_status(200)
            .with_body(REPO1_FIXTURE)
            .expect(1)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert_eq!(
            times.get("3.14.0").copied(),
            PublishTime::parse_rfc3339("2023-11-18T15:03:00Z")
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_publish_times_404_degrades_to_empty_map() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/org/example/widget/")
            .with_status(404)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert!(times.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_publish_times_500_degrades_to_empty_map() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/org/example/widget/")
            .with_status(500)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert!(times.is_empty());
    }

    // --- get_versions_typed_with: end-to-end gating and degradation on the metadata path ---

    #[tokio::test]
    async fn test_get_versions_typed_with_invalid_name_short_circuits_before_any_request() {
        // No colon in the name => `metadata_urls` returns empty and `get_metadata` never
        // issues a request at all, so this also exercises `get_versions_typed`'s delegation
        // to `get_versions_typed_with(name, false)` (M1) without needing a network mock.
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        assert!(
            registry
                .get_versions_typed("bad-name")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            registry
                .get_versions_typed_with("bad-name", true)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // --- NFR-006 live verification (real network, run explicitly with `--ignored`) ---

    #[tokio::test]
    #[ignore]
    async fn test_live_maven_central_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("org.apache.commons:commons-lang3", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        // Maven Central: the listing exists, so at least the most recent releases carry a
        // publish date (some very old/legacy entries may not, but recent ones always do).
        assert!(versions.iter().take(5).any(|v| v.published_at.is_some()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_google_maven_never_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("androidx.core:core", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        // Google Maven's listing 404s by design (§1.3) — the version list itself must be
        // unaffected, exactly as before this feature.
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_gradle_plugin_portal_never_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        // The Gradle plugin marker artifact for `com.gradle.develocity` (404s on Maven
        // Central; verified `repo1` 404 / plugin portal 200 on 2026-08-24) — resolves only
        // via the Gradle Plugin Portal fallback.
        let versions = registry
            .get_versions_typed_with(
                "com.gradle.develocity:com.gradle.develocity.gradle.plugin",
                true,
            )
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }
}
