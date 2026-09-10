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

/// Returns the URL for a package's page on pub.dev.
///
/// Display link only, never fetched by this process — unlike `package_metadata_url`
/// (a fetch sink), so it is deliberately not gated against a `.`/`..` name (see
/// [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link scope split, #379).
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

/// pub.dev registry client implementing [`deps_core::Registry`] for Dart/Pub.
#[derive(Clone)]
pub struct PubDevRegistry {
    cache: Arc<HttpCache>,
    /// API base URL — [`PUB_DEV_API_BASE`] in production, overridden to a mockito server
    /// URL in tests via [`Self::with_base`] (mirrors `deps-npm`'s
    /// `NpmRegistry::with_registry_base`).
    base: String,
}

impl PubDevRegistry {
    /// Creates a client backed by the given shared HTTP cache, pointed at the real pub.dev API.
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

    /// Fetches all published versions of a package from pub.dev.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is a dot-segment, the request fails, or the
    /// response body fails to parse.
    #[tracing::instrument(skip_all, fields(package = ?name), level = "debug")]
    pub async fn get_versions(&self, name: &str) -> Result<Vec<DartVersion>> {
        reject_dot_segment(name)?;
        let url = package_metadata_url(&self.base, name);
        let data = self.cache.get_cached(&url).await?;
        parse_versions_response(&data)
    }

    /// Returns the newest non-retracted version of `name` matching `req_str`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching the package's versions fails.
    #[tracing::instrument(skip_all, fields(package = ?name, version = ?req_str), level = "debug")]
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<DartVersion>> {
        let versions = self.get_versions(name).await?;
        Ok(versions.into_iter().find(|v| {
            crate::version::version_matches_constraint(v.version.as_str(), req_str) && !v.retracted
        }))
    }

    /// Searches pub.dev for packages matching `query`, returning at most `limit` results.
    ///
    /// # Errors
    ///
    /// Returns an error if the search request fails or its response body fails to parse.
    #[tracing::instrument(skip_all, fields(query = ?query), level = "debug")]
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<PackageInfo>> {
        let url = format!("{}/search?q={}", self.base, urlencoding::encode(query));
        let data = self.cache.get_cached(&url).await?;
        let search_result: SearchResponse = deps_core::parse_json_checked(&data)?;

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

    /// Fetches package metadata (description, homepage, license, etc.) from pub.dev.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is a dot-segment, the request fails, or the
    /// response body fails to parse.
    #[tracing::instrument(skip_all, fields(package = ?name), level = "debug")]
    pub async fn get_package_info(&self, name: &str) -> Result<PackageInfo> {
        reject_dot_segment(name)?;
        let url = package_metadata_url(&self.base, name);
        let data = self.cache.get_cached(&url).await?;
        parse_package_info(&data)
    }

    /// Fetches pub.dev's per-package `/score` response and extracts its best-effort
    /// license tag (issue #660, spec 010 plan §1 "Dart source" row).
    ///
    /// pub.dev's package/version API (the endpoint [`Self::get_versions`]/
    /// [`Self::get_package_info`] already fetch) has no SPDX license field at all
    /// (live-verified during #204 planning) — the only license signal anywhere in
    /// pub.dev's API is a `license:<slug>` entry in this separate `/score` endpoint's
    /// `tags` array, itself the output of pub.dev's own automated license detector
    /// (`package:pana`), not an author-declared field. Callers must label this
    /// "detected", never plain "License", per spec 010 NFR-005's documented exception —
    /// see [`deps_core::lsp_helpers`]'s `push_license_hover_section` doc.
    ///
    /// Returns an empty `Vec` (never an error) when the fetch fails or no `license:`
    /// tag is present — graceful degradation (NFR-003), since this is a best-effort
    /// secondary signal, not core version data.
    pub async fn get_license(&self, name: &str) -> Vec<String> {
        if reject_dot_segment(name).is_err() {
            return Vec::new();
        }
        let url = score_url(&self.base, name);
        match self.cache.get_cached(&url).await {
            Ok(data) => parse_score_license(&data),
            Err(e) => {
                tracing::debug!(package = name, error = %e, "pub.dev score fetch failed");
                Vec::new()
            }
        }
    }
}

/// Builds the pub.dev request URL for a package's `/score` response (license detector
/// tags, likes, download counts). Mirrors [`package_metadata_url`]'s encoding — `name`
/// must already be dot-segment-checked by the caller.
fn score_url(base: &str, name: &str) -> String {
    format!("{base}/packages/{}/score", urlencoding::encode(name))
}

/// The subset of pub.dev's `/score` response this client needs.
#[derive(Deserialize)]
struct ScoreResponse {
    #[serde(default)]
    tags: Vec<String>,
}

/// pana's non-SPDX tags in the `license:` namespace (`PanaTags` in
/// `dart-lang/pana`'s `lib/src/tag/pana_tags.dart`, live-verified 2026-09-08): every
/// other `license:<slug>` tag is `license:${l.spdxIdentifier.toLowerCase()}`, a real
/// SPDX identifier, but pana also always emits these three meta-tags alongside it —
/// `fsf-libre`/`osi-approved` classify an already-reported license, and `unknown` marks
/// its *absence*, so none of the three is itself a license (critic C3). Live-verified
/// against pub.dev's `/api/packages/http/score`: its `tags` includes
/// `license:bsd-3-clause`, `license:fsf-libre`, `license:osi-approved` together — an
/// unfiltered extraction would render hover as "BSD-3-Clause, FSF-Libre, OSI-Approved".
const PANA_NON_LICENSE_TAGS: [&str; 3] = ["fsf-libre", "osi-approved", "unknown"];

/// Extracts every `license:<slug>` tag from a `/score` response and formats each slug
/// for display. A package can carry more than one (e.g. a dual-licensed package), so
/// this collects all of them rather than just the first — consistent with every other
/// ecosystem's `license: Vec<String>` shape (spec 010 plan §1 "License shape" decision).
///
/// [`PANA_NON_LICENSE_TAGS`] slugs are dropped rather than formatted — `unknown` in
/// particular must become an empty `Vec`, not `["Unknown"]`: a non-empty `Vec` for "no
/// license data" would be evaluated against an allow/deny list and can produce a false
/// `NotAllowed` diagnostic, breaking `deps_core::licenses`' NFR-003 "unknown license
/// never violates a policy" guarantee (critic C3).
fn parse_score_license(data: &[u8]) -> Vec<String> {
    let Ok(response) = deps_core::parse_json_checked::<ScoreResponse>(data) else {
        return Vec::new();
    };
    response
        .tags
        .iter()
        .filter_map(|t| t.strip_prefix("license:"))
        .filter(|slug| !slug.is_empty() && !PANA_NON_LICENSE_TAGS.contains(slug))
        .map(format_detected_license_tag)
        .collect()
}

/// Best-effort formatting of a pub.dev `license:<slug>` tag (e.g. `"bsd-3-clause"`) into
/// something closer to its SPDX identifier (`"BSD-3-Clause"`) for display.
///
/// This is deliberately a heuristic, not a lookup against the full SPDX license list
/// (spec 010 §8 "Ask First": no new dependency for this): splits on `-`, uppercasing a
/// short (≤4 char) all-alphabetic segment (acronyms like `mit`, `bsd`, `gpl`, `lgpl`,
/// `mpl`, `isc`) and title-casing a longer one (`unlicense` → `Unlicense`,
/// `clause` → `Clause`), while a segment containing a digit (`2.0`, `3.0`) passes
/// through unchanged. Covers every license tag pub.dev commonly reports; an unusual
/// slug this heuristic mis-cases is still legible and still correctly labeled
/// "(detected)" in hover, so no functional harm from an imperfect guess.
fn format_detected_license_tag(slug: &str) -> String {
    slug.split('-')
        .map(|segment| {
            if segment.chars().any(|c| c.is_ascii_digit()) || segment.is_empty() {
                segment.to_string()
            } else if segment.len() <= 4 {
                segment.to_ascii_uppercase()
            } else {
                let mut chars = segment.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join("-")
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
    let response: PackageResponse = deps_core::parse_json_checked(data)?;

    let mut versions: Vec<DartVersion> = response
        .versions
        .into_iter()
        .map(|e| DartVersion {
            version: e.version.into(),
            retracted: e.retracted,
            published_at: e
                .published
                .as_deref()
                .and_then(deps_core::PublishTime::parse_rfc3339),
        })
        .collect();

    versions.sort_by(|a, b| compare_versions(b.version.as_str(), a.version.as_str()));

    Ok(versions)
}

fn parse_package_info(data: &[u8]) -> Result<PackageInfo> {
    let response: PackageResponse = deps_core::parse_json_checked(data)?;
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
        version: response.latest.version.into(),
        license: None,
    })
}

impl deps_core::Version for DartVersion {
    fn version_string(&self) -> &deps_core::ConcreteVersion {
        &self.version
    }

    fn removal_status(&self) -> deps_core::RemovalStatus {
        deps_core::RemovalStatus::from_yanked(self.retracted)
    }

    fn is_prerelease(&self) -> bool {
        crate::version::is_prerelease(self.version.as_str())
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

    fn latest_version(&self) -> &deps_core::ConcreteVersion {
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
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        versions.iter().position(|v| {
            crate::version::version_matches_constraint(v.version_string().as_str(), req.as_str())
                && !v.removal_status().blocks_resolution()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

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

    // #758: this hostile newline/autolink/percent payload case is now covered universally by
    // deps-lsp's `test_registered_ecosystems_universal_invariants` (Layer 1), via
    // `deps_core::conformance::HOSTILE_DISPLAY_LINK_PAYLOAD` — this crate's own copy is
    // redundant and has been removed.

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

    // #758: the shared JSON-nesting-depth cap — deps-dart had no prior nesting-depth test.
    deps_core::json_depth_conformance! {
        mod dart_json_depth_conformance;
        parse: |bytes: &[u8]| parse_package_info(bytes);
        wrap: |nested: &str| format!(r#"{{"name": "test", "latest": {{"version": "0.1.0"}}, "versions": [], "extra": {nested}}}"#);
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

    /// #365 regression sweep: exercises the real production pair (`is_dot_segment` gate +
    /// `package_metadata_url` sink) against the shared adversarial input set, guarding
    /// against a 6th recurrence of #349's defect class.
    #[test]
    fn test_package_metadata_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| (!is_dot_segment(seg)).then(|| package_metadata_url(PUB_DEV_API_BASE, seg)),
            "pub.dev",
            "/api/packages/",
        );
    }

    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_as_not_found() {
        // #365 R1: asserts the exact `PackageNotFound` variant (gate rejected before any
        // request), not the broader `is_not_found()` (also true for a live 404 `HttpStatus`)
        // — pub.dev 404ing for this path today would make a deleted gate go undetected by
        // this test.
        let registry = PubDevRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("..").await.unwrap_err();
        assert_matches!(err, DepsError::PackageNotFound { .. });
    }

    #[tokio::test]
    async fn test_get_package_info_rejects_bare_dot_as_not_found() {
        let registry = PubDevRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_package_info(".").await.unwrap_err();
        assert_matches!(err, DepsError::PackageNotFound { .. });
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
        assert!(ver.removal_status().blocks_resolution());
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

    deps_core::registry_conformance! {
        mod dart_registry_conformance;
        build: PubDevRegistry::new(Arc::new(HttpCache::new()));
        select_latest_matching: {
            versions: vec![
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
            req: "*";
            expected_index: 1;
        };
    }

    #[test]
    fn test_select_latest_matching_all_retracted_returns_newest_retracted() {
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
                retracted: true,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_select_latest_matching_all_prerelease_returns_newest_prerelease() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PubDevRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(DartVersion {
                version: "2.0.0-beta.1".into(),
                retracted: false,
                published_at: None,
            }),
            Box::new(DartVersion {
                version: "1.0.0-alpha.1".into(),
                retracted: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    // --- issue #660: license detection ---

    #[test]
    fn format_detected_license_tag_common_slugs() {
        assert_eq!(format_detected_license_tag("mit"), "MIT");
        assert_eq!(format_detected_license_tag("bsd-3-clause"), "BSD-3-Clause");
        assert_eq!(format_detected_license_tag("bsd-2-clause"), "BSD-2-Clause");
        assert_eq!(format_detected_license_tag("apache-2.0"), "Apache-2.0");
        assert_eq!(format_detected_license_tag("gpl-3.0"), "GPL-3.0");
        assert_eq!(format_detected_license_tag("lgpl-3.0"), "LGPL-3.0");
        assert_eq!(format_detected_license_tag("mpl-2.0"), "MPL-2.0");
        assert_eq!(format_detected_license_tag("isc"), "ISC");
        assert_eq!(format_detected_license_tag("unlicense"), "Unlicense");
    }

    #[test]
    fn parse_score_license_extracts_license_tag() {
        // Live-verified pana meta-tag shape (critic C3): `fsf-libre`/`osi-approved`
        // ride alongside the real SPDX slug and must not appear in the result.
        let body = br#"{"tags":["sdk:dart","license:bsd-3-clause","license:fsf-libre","license:osi-approved"]}"#;
        assert_eq!(parse_score_license(body), vec!["BSD-3-Clause".to_string()]);
    }

    #[test]
    fn parse_score_license_no_license_tag_is_empty() {
        let body = br#"{"tags":["sdk:dart","platform:web"]}"#;
        assert!(parse_score_license(body).is_empty());
    }

    #[test]
    fn parse_score_license_unknown_tag_is_empty_not_a_literal_unknown_string() {
        // Critic C3: `license:unknown` must map to an empty Vec, not `["Unknown"]` — a
        // non-empty Vec for "no license data" would violate NFR-003's "unknown license
        // never violates a policy" guarantee once evaluated against an allow/deny list.
        let body = br#"{"tags":["sdk:dart","license:unknown"]}"#;
        assert!(parse_score_license(body).is_empty());
    }

    #[test]
    fn parse_score_license_meta_tags_alone_are_empty() {
        let body = br#"{"tags":["license:fsf-libre","license:osi-approved"]}"#;
        assert!(parse_score_license(body).is_empty());
    }

    #[test]
    fn parse_score_license_malformed_json_degrades_to_empty() {
        assert!(parse_score_license(b"not json").is_empty());
    }

    #[tokio::test]
    async fn get_license_fetches_score_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/packages/http/score")
            .with_status(200)
            .with_body(r#"{"tags":["license:mit"]}"#)
            .create_async()
            .await;

        let registry = PubDevRegistry::with_base(Arc::new(HttpCache::new()), server.url());
        assert_eq!(registry.get_license("http").await, vec!["MIT".to_string()]);
    }

    #[tokio::test]
    async fn get_license_dot_segment_name_returns_empty_without_network() {
        let registry =
            PubDevRegistry::with_base(Arc::new(HttpCache::new()), "http://[::1]:1".into());
        assert!(registry.get_license("..").await.is_empty());
    }

    #[tokio::test]
    async fn get_license_fetch_failure_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/packages/missing/score")
            .with_status(404)
            .create_async()
            .await;

        let registry = PubDevRegistry::with_base(Arc::new(HttpCache::new()), server.url());
        assert!(registry.get_license("missing").await.is_empty());
    }
}
