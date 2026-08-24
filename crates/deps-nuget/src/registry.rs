//! NuGet V3 registry client.
//!
//! NuGet base URLs are not hardcodable: the service index
//! (`https://api.nuget.org/v3/index.json`) must be resolved first, then consulted for the
//! flat-container ("PackageBaseAddress"), search ("SearchQueryService"), and (future,
//! see D1 below) registration ("RegistrationsBaseUrl") resource URLs.

use crate::types::{NuGetVersion, PackageInfo};
use crate::version::compare_versions;
use deps_core::{HOVER_RECENT_VERSIONS, HttpCache, PublishTime, Result};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::OnceCell;

const SERVICE_INDEX_URL: &str = "https://api.nuget.org/v3/index.json";

/// Safety bound on external (non-inline) registration page fetches per `get_versions_with`
/// call. Real packages need at most one (§1.1); this only guards a pathological feed.
const MAX_EXTERNAL_PAGE_FETCHES: usize = 2;

/// Display name for NuGet used in not-found and API-response error messages.
pub const REGISTRY: &str = "NuGet";

#[derive(Debug, Deserialize)]
struct ServiceIndexResponse {
    resources: Vec<ServiceResource>,
}

#[derive(Debug, Deserialize)]
struct ServiceResource {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
}

/// Resolved base URLs from the NuGet service index.
#[derive(Debug, Clone)]
struct ServiceIndex {
    /// `PackageBaseAddress/3.0.0` — flat-container version enumeration.
    package_base_address: String,
    /// `SearchQueryService/3.5.0` (preferred) or bare `SearchQueryService`.
    search_query_service: String,
    /// `RegistrationsBaseUrl/3.6.0` (SemVer 2.0.0, preferred), falling back to `3.4.0`
    /// (SemVer 1) or the bare, undated resource. `Option`, not error-gated: a private V3
    /// feed (Azure Artifacts, BaGet, GitHub Packages) may omit this resource entirely, in
    /// which case freshness degrades to `published_at == None` everywhere rather than
    /// failing `get_versions` for that feed.
    registrations_base_url: Option<String>,
}

fn pick_resource(resources: &[ServiceResource], type_preference: &[&str]) -> Option<String> {
    for want in type_preference {
        if let Some(r) = resources.iter().find(|r| r.r#type == *want) {
            return Some(r.id.trim_end_matches('/').to_string());
        }
    }
    None
}

impl ServiceIndex {
    fn resolve(response: &ServiceIndexResponse) -> Result<Self> {
        let package_base_address =
            pick_resource(&response.resources, &["PackageBaseAddress/3.0.0"]).ok_or_else(|| {
                deps_core::DepsError::ParseError {
                    file_type: "NuGet service index".into(),
                    source: Box::new(std::io::Error::other(
                        "missing PackageBaseAddress/3.0.0 resource",
                    )),
                }
            })?;
        let search_query_service = pick_resource(
            &response.resources,
            &["SearchQueryService/3.5.0", "SearchQueryService"],
        )
        .ok_or_else(|| deps_core::DepsError::ParseError {
            file_type: "NuGet service index".into(),
            source: Box::new(std::io::Error::other("missing SearchQueryService resource")),
        })?;
        let registrations_base_url = pick_resource(
            &response.resources,
            &[
                "RegistrationsBaseUrl/3.6.0",
                "RegistrationsBaseUrl/3.4.0",
                "RegistrationsBaseUrl",
            ],
        );

        Ok(Self {
            package_base_address,
            search_query_service,
            registrations_base_url,
        })
    }
}

/// Registration hive index (`RegistrationsBaseUrl/{id}/index.json`): a list of pages, each
/// either inline (`items` present) or an external stub (`items` absent, fetched via `id`).
#[derive(Debug, Deserialize)]
struct RegistrationIndex {
    #[serde(default)]
    items: Vec<RegistrationPage>,
}

#[derive(Debug, Deserialize)]
struct RegistrationPage {
    #[serde(rename = "@id")]
    id: String,
    /// Present for an inline page; `None` for an externalized page, which must be fetched
    /// separately at `id` to obtain the same shape as [`RegistrationPageBody`].
    #[serde(default)]
    items: Option<Vec<CatalogEntryWrapper>>,
}

/// Body of a fetched external registration page — structurally identical to a
/// [`RegistrationPage`]'s inline `items`.
#[derive(Debug, Deserialize)]
struct RegistrationPageBody {
    #[serde(default)]
    items: Vec<CatalogEntryWrapper>,
}

#[derive(Debug, Deserialize)]
struct CatalogEntryWrapper {
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntry,
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    version: String,
    /// Absent/malformed degrades to no publish time for that version, not an error. The
    /// unlisted sentinel (`1900-01-01T00:00:00+00:00`) parses successfully but is filtered
    /// out by [`accumulate_catalog_entries`] rather than rendered as a bogus 126-year age.
    #[serde(default)]
    published: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FlatContainerIndex {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    data: Vec<SearchResultDoc>,
}

#[derive(Debug, Deserialize)]
struct SearchResultDoc {
    id: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "projectUrl")]
    project_url: Option<String>,
}

/// Returns the nuget.org package page URL for `name`.
pub fn package_url(name: &str) -> String {
    format!(
        "https://www.nuget.org/packages/{}",
        urlencoding::encode(name)
    )
}

#[derive(Clone)]
pub struct NuGetRegistry {
    cache: Arc<HttpCache>,
    service_index_url: String,
    service_index: Arc<OnceCell<ServiceIndex>>,
}

impl NuGetRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_service_index_url(cache, SERVICE_INDEX_URL.to_string())
    }

    fn with_service_index_url(cache: Arc<HttpCache>, service_index_url: String) -> Self {
        Self {
            cache,
            service_index_url,
            service_index: Arc::new(OnceCell::new()),
        }
    }

    /// Resolves the service index once per process, retrying on the next call if
    /// resolution failed. `get_or_try_init` (not `get_or_init`) is load-bearing: it leaves
    /// the cell empty on `Err` so a transient failure does not permanently poison lookups,
    /// and it serializes concurrent initializers so a cold start with many dependencies
    /// does not stampede the index endpoint.
    async fn service_index(&self) -> Result<&ServiceIndex> {
        self.service_index
            .get_or_try_init(|| async {
                let data = self.cache.get_cached(&self.service_index_url).await?;
                let response: ServiceIndexResponse = serde_json::from_slice(&data)?;
                ServiceIndex::resolve(&response)
            })
            .await
    }

    /// Fetches all available versions for `name` from the flat-container endpoint,
    /// sorted newest-first.
    ///
    /// Delegates to [`Self::get_versions_typed_with`] with freshness disabled so the two
    /// paths cannot drift apart.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<NuGetVersion>> {
        self.get_versions_typed_with(name, false).await
    }

    /// Same as [`Self::get_versions_typed`], but attaches [`NuGetVersion::published_at`]
    /// from the registration hive when `freshness_enabled` and the feed exposes a
    /// `RegistrationsBaseUrl` resource.
    ///
    /// The flat-container fetch (version list) and the registration-index fetch (for
    /// publish times) are independent once the service index is resolved, so they run
    /// concurrently via `tokio::join!` rather than sequentially — this matters because
    /// `complete_versions_generic` is a per-keystroke completion path and `HttpCache` has
    /// no TTL, so every call revalidates over the network.
    ///
    /// A registration-index fetch or parse failure degrades to no publish times, never to
    /// an error: the version list itself must be unaffected by a listing problem.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_versions_typed_with(
        &self,
        name: &str,
        freshness_enabled: bool,
    ) -> Result<Vec<NuGetVersion>> {
        let index = self.service_index().await?;
        let flat_url = flat_container_url(&index.package_base_address, name);
        let registration_base = if freshness_enabled {
            index.registrations_base_url.clone()
        } else {
            None
        };

        if let Some(base) = registration_base {
            let registration_url = registration_index_url(&base, name);
            let (flat_result, registration_result) = tokio::join!(
                self.cache.get_cached(&flat_url),
                self.cache.get_cached(&registration_url),
            );
            let mut versions = parse_flat_container(&flat_result?)?;
            match registration_result {
                Ok(registration_body) => {
                    let times = self
                        .publish_times_from_index(&registration_body, &base)
                        .await;
                    attach_publish_times(&mut versions, &times);
                }
                Err(e) => {
                    tracing::debug!(package = %name, error = %e, "registration index fetch failed, publish times unavailable");
                }
            }
            Ok(versions)
        } else {
            let data = self.cache.get_cached(&flat_url).await?;
            parse_flat_container(&data)
        }
    }

    /// Walks the registration hive backwards from the last page, collecting `published`
    /// dates until at least [`HOVER_RECENT_VERSIONS`] entries have been examined.
    ///
    /// Pages are ordered ascending by version (mirroring the flat container's descending
    /// order in reverse), so the tail of `index.items` holds the most recent versions —
    /// exactly what hover renders. Terminates on whichever comes first: enough entries
    /// collected, the index exhausted (packages with fewer total versions than the target),
    /// or [`MAX_EXTERNAL_PAGE_FETCHES`] external pages fetched (a safety bound; real
    /// packages need at most one, per the live measurements this plan is based on).
    ///
    /// Never fails the caller: a malformed index, an unreachable page, or a page `@id`
    /// outside `base`'s origin all degrade to fewer (or zero) entries in the returned map.
    async fn publish_times_from_index(
        &self,
        index_body: &[u8],
        base: &str,
    ) -> HashMap<String, PublishTime> {
        let mut times = HashMap::new();
        let Ok(index) = serde_json::from_slice::<RegistrationIndex>(index_body) else {
            return times;
        };

        let mut collected = 0usize;
        let mut external_fetches = 0usize;
        let trusted_prefix = format!("{base}/");

        for page in index.items.iter().rev() {
            if collected >= HOVER_RECENT_VERSIONS {
                break;
            }

            match &page.items {
                Some(inline) => accumulate_catalog_entries(&mut times, &mut collected, inline),
                None => {
                    // A page `@id` outside the resolved registration base is skipped, not
                    // trusted — the feed chooses `@id` values, and `ensure_https` blocks
                    // non-HTTPS but not cross-origin redirection of our fetch (S2/M2).
                    if !page.id.starts_with(&trusted_prefix) {
                        continue;
                    }
                    if external_fetches >= MAX_EXTERNAL_PAGE_FETCHES {
                        break;
                    }
                    external_fetches += 1;
                    let Ok(body) = self.cache.get_cached(&page.id).await else {
                        continue;
                    };
                    let Ok(parsed) = serde_json::from_slice::<RegistrationPageBody>(&body) else {
                        continue;
                    };
                    accumulate_catalog_entries(&mut times, &mut collected, &parsed.items);
                }
            }
        }

        times
    }

    /// Finds the highest version of `name` matching `req` (exact pin, interval notation,
    /// or floating pattern). Prerelease versions are excluded unless `req` itself is
    /// prerelease-bearing.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<NuGetVersion>> {
        let versions = self.get_versions_typed(name).await?;
        Ok(pick_latest_matching(versions, req))
    }

    /// Searches the NuGet `SearchQueryService` for `query`, returning up to `limit` results.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the search request fails.
    pub async fn search_typed(&self, query: &str, limit: usize) -> Result<Vec<PackageInfo>> {
        let index = self.service_index().await?;
        let url = search_url(&index.search_query_service, query, limit);

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data, limit)
    }
}

/// Builds the flat-container version-enumeration URL for `name`.
///
/// The package id is lowercased (NuGet ids are case-insensitive and every V3 API path
/// segment is lowercased) and percent-encoded before being interpolated into the path.
/// Encoding is load-bearing, not cosmetic: an unencoded id lets a crafted
/// `PackageReference Include="..."` value inject path segments (`../../etc/passwd`
/// collapses dot-segments) or truncate the path at `#`/`?`/control characters, making
/// deps-lsp silently resolve and display a *different* real package's version data under
/// an attacker-chosen name.
pub fn flat_container_url(base: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    format!("{base}/{}/index.json", urlencoding::encode(&lower))
}

/// Builds the registration-hive index URL for `name`. Same lowercasing/encoding rationale
/// as [`flat_container_url`].
pub fn registration_index_url(base: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    format!("{base}/{}/index.json", urlencoding::encode(&lower))
}

/// Attaches `published_at` to each version whose string matches an entry in `times`.
///
/// A version present in `versions` but absent from `times` (or vice versa) is not an
/// error: it simply keeps/never gets a `published_at`. Order is untouched.
fn attach_publish_times(versions: &mut [NuGetVersion], times: &HashMap<String, PublishTime>) {
    for v in versions {
        v.published_at = times.get(&v.version).copied();
    }
}

/// Extracts `(version, published)` pairs from a page's catalog entries into `times`,
/// filtering the unlisted sentinel (`published <= epoch`) and any unparseable timestamp.
/// Advances `collected` by the entry count regardless of whether a time was extracted, since
/// the walk target in [`NuGetRegistry::publish_times_from_index`] is "entries examined", not
/// "entries successfully timed".
fn accumulate_catalog_entries(
    times: &mut HashMap<String, PublishTime>,
    collected: &mut usize,
    entries: &[CatalogEntryWrapper],
) {
    for entry in entries {
        let published = entry
            .catalog_entry
            .published
            .as_deref()
            .and_then(PublishTime::parse_rfc3339)
            .filter(|t| t.as_unix_secs() > 0);
        if let Some(published) = published {
            times.insert(entry.catalog_entry.version.clone(), published);
        }
        *collected += 1;
    }
}

/// Builds the `SearchQueryService` URL for `query`, limited to `limit` results.
///
/// `semVerLevel=2.0.0` is mandatory (spec §1) — omitting it silently hides every package
/// whose latest version uses a dotted prerelease label.
pub fn search_url(base: &str, query: &str, limit: usize) -> String {
    format!(
        "{base}?q={}&take={limit}&prerelease=false&semVerLevel=2.0.0",
        urlencoding::encode(query),
    )
}

/// Parses a flat-container `index.json` response into descending-sorted versions.
pub fn parse_flat_container(data: &[u8]) -> Result<Vec<NuGetVersion>> {
    let parsed: FlatContainerIndex = serde_json::from_slice(data)?;

    let mut versions = parsed.versions;
    // Sort locally, descending: the flat container's observed ascending order is not a
    // documented contract, so relying on `.reverse()` would silently corrupt "latest" if
    // the CDN/backend ever changes it (rev2, S3).
    versions.sort_by(|a, b| compare_versions(b, a));

    Ok(versions
        .into_iter()
        .map(|version| NuGetVersion {
            version,
            published_at: None,
        })
        .collect())
}

/// Picks the highest version matching `req` from an already-fetched, descending-sorted
/// version list. `req` is treated as `"*"` when empty. Prerelease versions are excluded
/// unless `req` itself is prerelease-bearing (contains `-`) or is a floating pattern whose
/// own prerelease inclusion is handled by `crate::version::resolve_float`.
fn pick_latest_matching(versions: Vec<NuGetVersion>, req: &str) -> Option<NuGetVersion> {
    if versions.is_empty() {
        return None;
    }

    let req = if req.is_empty() { "*" } else { req };

    if req.contains('*') {
        let strings: Vec<String> = versions.iter().map(|v| v.version.clone()).collect();
        return crate::version::resolve_float(&strings, req).map(|v| NuGetVersion {
            version: v.to_string(),
            published_at: None,
        });
    }

    let req_is_prerelease_bearing = req.contains('-');
    versions.into_iter().find(|v| {
        crate::version::satisfies(&v.version, req)
            && (req_is_prerelease_bearing || !crate::version::is_prerelease(&v.version))
    })
}

fn parse_search_response(data: &[u8], limit: usize) -> Result<Vec<PackageInfo>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .data
        .into_iter()
        .take(limit)
        .map(|d| PackageInfo {
            name: d.id.into(),
            description: d.description,
            repository: d.project_url,
            documentation: None,
            latest_version: d.version.unwrap_or_default(),
        })
        .collect())
}

// TODO(critic): unlisted versions are reported as listed; enrich from
// RegistrationsBaseUrl/3.6.0 on hover only (D1). The flat container used by get_versions
// carries no `listed` flag, and paying the extra registration-hive hop on every dependency
// in an open file is the wrong trade for the inlay-hint path.

impl deps_core::Registry for NuGetRegistry {
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
        if versions.is_empty() {
            return None;
        }
        let req_str = req.as_str();
        let req_str = if req_str.is_empty() { "*" } else { req_str };

        if req_str.contains('*') {
            let strings: Vec<String> = versions
                .iter()
                .map(|v| v.version_string().to_string())
                .collect();
            let matched = crate::version::resolve_float(&strings, req_str)?;
            return strings.iter().position(|s| s == matched);
        }

        let req_is_prerelease_bearing = req_str.contains('-');
        versions.iter().position(|v| {
            crate::version::satisfies(v.version_string(), req_str)
                && (req_is_prerelease_bearing || !crate::version::is_prerelease(v.version_string()))
        })
    }

    // `Version::is_yanked` is hardcoded `false` (`types.rs:63`) — the flat
    // versions container `get_versions` reads has no `listed` flag (see the
    // TODO above at `registry.rs:274`) (#233).
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

    fn service_index_body(package_base_address: &str, search_query_service: &str) -> String {
        format!(
            r#"{{
                "version": "3.0.0",
                "resources": [
                    {{"@id": "{package_base_address}", "@type": "PackageBaseAddress/3.0.0"}},
                    {{"@id": "{search_query_service}", "@type": "SearchQueryService/3.5.0"}}
                ]
            }}"#
        )
    }

    fn service_index_body_with_registrations(
        package_base_address: &str,
        search_query_service: &str,
        registrations_base_url: &str,
    ) -> String {
        format!(
            r#"{{
                "version": "3.0.0",
                "resources": [
                    {{"@id": "{package_base_address}", "@type": "PackageBaseAddress/3.0.0"}},
                    {{"@id": "{search_query_service}", "@type": "SearchQueryService/3.5.0"}},
                    {{"@id": "{registrations_base_url}", "@type": "RegistrationsBaseUrl/3.6.0"}}
                ]
            }}"#
        )
    }

    #[test]
    fn test_package_url() {
        assert_eq!(
            package_url("Newtonsoft.Json"),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_name() {
        let url = package_url("evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://www.nuget.org/packages/");
    }

    #[test]
    fn test_flat_container_url_lowercases_and_encodes() {
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Newtonsoft.Json"),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_path_traversal_attempt() {
        // A crafted `Include="../../../../etc/passwd"` must not produce raw dot-segments
        // that a URL-parsing layer could collapse across path boundaries.
        let url = flat_container_url(
            "https://api.nuget.org/v3-flatcontainer",
            "../../../../etc/passwd",
        );
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/..%2F..%2F..%2F..%2Fetc%2Fpasswd/index.json"
        );
        assert!(
            !url.contains("/../"),
            "raw path traversal segment leaked into URL: {url}"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_fragment_and_query_delimiters() {
        // '#'/'?' must not be able to truncate the path and silently resolve as a
        // different, shorter package name.
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo#x"),
            "https://api.nuget.org/v3-flatcontainer/foo%23x/index.json"
        );
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo?x=1"),
            "https://api.nuget.org/v3-flatcontainer/foo%3Fx%3D1/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_control_characters() {
        let url = flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo\tBar");
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/foo%09bar/index.json"
        );
    }

    #[test]
    fn test_search_url_includes_mandatory_semver_level_and_prerelease_false() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "json", 10);
        assert_eq!(
            url,
            "https://azuresearch-usnc.nuget.org/query?q=json&take=10&prerelease=false&semVerLevel=2.0.0"
        );
    }

    #[test]
    fn test_search_url_encodes_query() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "a b&c", 5);
        assert!(url.contains("q=a%20b%26c"), "query not encoded: {url}");
    }

    #[test]
    fn test_service_index_resolve_success() {
        let response: ServiceIndexResponse = serde_json::from_str(&service_index_body(
            "https://api.nuget.org/v3-flatcontainer/",
            "https://azuresearch-usnc.nuget.org/query",
        ))
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(
            index.package_base_address,
            "https://api.nuget.org/v3-flatcontainer"
        );
        assert_eq!(
            index.search_query_service,
            "https://azuresearch-usnc.nuget.org/query"
        );
    }

    #[test]
    fn test_service_index_resolve_missing_resource_errors() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [{"@id": "https://x", "@type": "SomeOtherType"}]}"#,
        )
        .unwrap();
        assert!(ServiceIndex::resolve(&response).is_err());
    }

    #[test]
    fn test_service_index_search_query_service_fallback() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(index.search_query_service, "https://search");
    }

    #[test]
    fn test_parse_flat_container_sorted_descending() {
        let data = br#"{"versions": ["12.0.1", "13.0.3", "13.0.0-beta1"]}"#;
        let versions = parse_flat_container(data).unwrap();
        let strings: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(strings, vec!["13.0.3", "13.0.0-beta1", "12.0.1"]);
    }

    #[test]
    fn test_parse_flat_container_empty() {
        let data = br#"{"versions": []}"#;
        let versions = parse_flat_container(data).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_flat_container_invalid_json_errors() {
        assert!(parse_flat_container(b"not json").is_err());
    }

    #[test]
    fn test_parse_search_response() {
        let data = br#"{"totalHits": 1, "data": [{"id": "Newtonsoft.Json", "version": "13.0.3", "description": "JSON framework", "projectUrl": "https://example.com"}]}"#;
        let results = parse_search_response(data, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Newtonsoft.Json");
        assert_eq!(results[0].latest_version, "13.0.3");
        assert_eq!(
            results[0].repository.as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn test_parse_search_response_respects_limit() {
        let data = br#"{"totalHits": 2, "data": [
            {"id": "A", "version": "1.0.0"},
            {"id": "B", "version": "2.0.0"}
        ]}"#;
        let results = parse_search_response(data, 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "A");
    }

    fn v(s: &str) -> NuGetVersion {
        NuGetVersion {
            version: s.to_string(),
            published_at: None,
        }
    }

    #[test]
    fn test_pick_latest_matching_wildcard_excludes_prerelease() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "*");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_empty_req_behaves_like_wildcard() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_exact_pin() {
        let versions = vec![v("1.0.1"), v("1.0.0")];
        let matched = pick_latest_matching(versions, "[1.0.0]");
        assert_eq!(matched.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_floating_prefix() {
        let versions = vec![v("1.2.0"), v("1.1.5"), v("1.1.0")];
        let matched = pick_latest_matching(versions, "1.1.*");
        assert_eq!(matched.unwrap().version, "1.1.5");
    }

    #[test]
    fn test_pick_latest_matching_prerelease_bearing_requirement_allows_prerelease() {
        let versions = vec![v("1.0.0-rc.2"), v("0.9.0")];
        let matched = pick_latest_matching(versions, "[1.0.0-rc.2]");
        assert_eq!(matched.unwrap().version, "1.0.0-rc.2");
    }

    #[test]
    fn test_pick_latest_matching_empty_versions_returns_none() {
        assert!(pick_latest_matching(vec![], "*").is_none());
    }

    #[test]
    fn test_pick_latest_matching_no_match_returns_none() {
        let versions = vec![v("2.0.0")];
        assert!(pick_latest_matching(versions, "[1.0.0]").is_none());
    }

    #[test]
    fn test_registry_creation_and_trait_impls() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert_eq!(
            registry.package_url(&deps_core::PackageName::new("Newtonsoft.Json")),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
        assert!(registry.as_any().is::<NuGetRegistry>());
    }

    #[test]
    fn test_with_service_index_url_used_by_new() {
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert_eq!(registry.service_index_url, SERVICE_INDEX_URL);
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("1.1.0-rc.1")), Box::new(v("1.0.0"))];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    // --- ServiceIndex::resolve: registrations_base_url preference (S2/rev2 OQ6) ---

    #[test]
    fn test_service_index_resolve_registrations_base_url_prefers_3_6_0() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"},
                {"@id": "https://reg-semver1/", "@type": "RegistrationsBaseUrl/3.4.0"},
                {"@id": "https://reg-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"}
            ]}"#,
        )
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(
            index.registrations_base_url.as_deref(),
            Some("https://reg-semver2")
        );
    }

    #[test]
    fn test_service_index_resolve_registrations_base_url_falls_back_to_3_4_0() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"},
                {"@id": "https://reg-semver1/", "@type": "RegistrationsBaseUrl/3.4.0"}
            ]}"#,
        )
        .unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert_eq!(
            index.registrations_base_url.as_deref(),
            Some("https://reg-semver1")
        );
    }

    #[test]
    fn test_service_index_resolve_registrations_base_url_absent_is_none() {
        let response: ServiceIndexResponse =
            serde_json::from_str(&service_index_body("https://flat/", "https://search/")).unwrap();
        let index = ServiceIndex::resolve(&response).unwrap();
        assert!(index.registrations_base_url.is_none());
    }

    #[test]
    fn test_registration_index_url_lowercases_and_encodes() {
        assert_eq!(
            registration_index_url(
                "https://api.nuget.org/v3/registration5-gz-semver2",
                "Newtonsoft.Json"
            ),
            "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"
        );
    }

    // --- attach_publish_times ---

    #[test]
    fn test_attach_publish_times_matches_by_version_string() {
        let mut versions = vec![v("1.0.0"), v("2.0.0")];
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
    }

    #[test]
    fn test_attach_publish_times_empty_map_leaves_all_none() {
        let mut versions = vec![v("1.0.0"), v("2.0.0")];
        attach_publish_times(&mut versions, &HashMap::new());
        assert!(versions.iter().all(|ver| ver.published_at.is_none()));
    }

    // --- publish_times_from_index: pure fixtures, no network for inline pages ---

    fn inline_registration_index(base: &str, entries: &[(&str, Option<&str>)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(version, published)| match published {
                Some(p) => {
                    format!(r#"{{"catalogEntry": {{"version": "{version}", "published": "{p}"}}}}"#)
                }
                None => format!(r#"{{"catalogEntry": {{"version": "{version}"}}}}"#),
            })
            .collect();
        format!(
            r#"{{"count": 1, "items": [{{"@id": "{base}/pkg/page/0.json", "count": {n}, "items": [{items}]}}]}}"#,
            n = entries.len(),
            items = items.join(",")
        )
    }

    #[tokio::test]
    async fn test_publish_times_from_index_inline_happy_path() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("2020-01-01T00:00:00Z")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let times = registry
            .publish_times_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg")
            .await;
        assert_eq!(
            times.get("2.0.0").copied(),
            PublishTime::parse_rfc3339("2021-01-01T00:00:00Z")
        );
        assert_eq!(times.len(), 2);
    }

    #[tokio::test]
    async fn test_publish_times_from_index_sentinel_filtered() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("1900-01-01T00:00:00+00:00")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let times = registry
            .publish_times_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg")
            .await;
        assert!(!times.contains_key("1.0.0"));
        assert!(times.contains_key("2.0.0"));
    }

    #[tokio::test]
    async fn test_publish_times_from_index_missing_published_is_absent_rest_intact() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[("1.0.0", None), ("2.0.0", Some("2021-01-01T00:00:00Z"))],
        );
        let times = registry
            .publish_times_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg")
            .await;
        assert!(!times.contains_key("1.0.0"));
        assert!(times.contains_key("2.0.0"));
    }

    #[tokio::test]
    async fn test_publish_times_from_index_malformed_json_returns_empty_map() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let times = registry
            .publish_times_from_index(b"not json", "https://api.nuget.org/v3/reg")
            .await;
        assert!(times.is_empty());
    }

    #[tokio::test]
    async fn test_publish_times_from_index_foreign_origin_page_skipped_no_request() {
        // A page @id outside `base`'s origin must be skipped without ever being fetched —
        // if the implementation issued a real request here, this test would hang/fail on
        // network access rather than complete instantly.
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = r#"{"count": 1, "items": [
            {"@id": "https://evil.example/pkg/page/0.json", "count": 1}
        ]}"#;
        let times = registry
            .publish_times_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg")
            .await;
        assert!(times.is_empty());
    }

    #[tokio::test]
    async fn test_publish_times_from_index_lookalike_origin_page_skipped_no_request() {
        // A prefix-lookalike host (`…nuget.org.evil.test`) must also be rejected — the
        // trailing-slash check in the trust boundary is what catches this.
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = r#"{"count": 1, "items": [
            {"@id": "https://api.nuget.org.evil.test/v3/reg/pkg/page/0.json", "count": 1}
        ]}"#;
        let times = registry
            .publish_times_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg")
            .await;
        assert!(times.is_empty());
    }

    // --- get_versions_typed_with: end-to-end gating and registration-hive walk (mockito) ---

    #[tokio::test]
    async fn test_get_versions_typed_with_disabled_issues_zero_registration_requests() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "2.0.0"]}"#)
            .create_async()
            .await;
        // No mock registered for /registrations/* — a request there would fail the test.

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );

        let versions = registry
            .get_versions_typed_with("widget", false)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_enabled_matches_disabled_set_and_order() {
        // FR-006 regression guard: enabling freshness must not change the returned list's
        // set or order, only populate `published_at`.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "2.0.0"]}"#)
            .create_async()
            .await;
        let registration_body = inline_registration_index(
            &format!("{base}/registrations"),
            &[
                ("1.0.0", Some("2020-01-01T00:00:00Z")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(registration_body)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );

        let disabled = registry
            .get_versions_typed_with("widget", false)
            .await
            .unwrap();
        let enabled = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        let disabled_strings: Vec<&str> = disabled.iter().map(|v| v.version.as_str()).collect();
        let enabled_strings: Vec<&str> = enabled.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(disabled_strings, enabled_strings);
        assert!(enabled.iter().all(|v| v.published_at.is_some()));
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_externalized_index_fetches_only_needed_pages() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let reg_base = format!("{base}/registrations");

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &reg_base,
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["9.0.0", "8.0.0", "7.0.0"]}"#)
            .create_async()
            .await;

        // Two external stub pages; only the last one (page 1) should ever be requested,
        // since it alone already covers >= HOVER_RECENT_VERSIONS entries.
        let index_body = format!(
            r#"{{"count": 2, "items": [
                {{"@id": "{reg_base}/widget/page/0.json", "count": 5}},
                {{"@id": "{reg_base}/widget/page/1.json", "count": 5}}
            ]}}"#
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(index_body)
            .create_async()
            .await;

        // Page 1 alone carries HOVER_RECENT_VERSIONS (8) entries, so the walk must stop
        // here and never touch page 0.
        let page1_body = r#"{"items": [
            {"catalogEntry": {"version": "2.0.0", "published": "2015-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "3.0.0", "published": "2016-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "4.0.0", "published": "2017-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "5.0.0", "published": "2018-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "6.0.0", "published": "2019-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "7.0.0", "published": "2020-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "8.0.0", "published": "2021-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "9.0.0", "published": "2022-01-01T00:00:00Z"}}
        ]}"#;
        let page1_mock = server
            .mock("GET", "/registrations/widget/page/1.json")
            .with_status(200)
            .with_body(page1_body)
            .expect(1)
            .create_async()
            .await;
        let page0_mock = server
            .mock("GET", "/registrations/widget/page/0.json")
            .with_status(200)
            .with_body(r#"{"items": []}"#)
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 3);
        assert!(versions.iter().all(|v| v.published_at.is_some()));
        page1_mock.assert_async().await;
        page0_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_external_fetch_cap_stops_walk_at_two_pages() {
        // Tester gap: MAX_EXTERNAL_PAGE_FETCHES = 2 was never actually hit by any prior
        // test. Three external pages, each carrying too few entries to reach
        // HOVER_RECENT_VERSIONS alone or even combined two-at-a-time, so the walk must stop
        // after exactly 2 external fetches (pages 2 and 1) and never touch page 0 — proving
        // the cap terminates the walk rather than the count or exhaustion terminators.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let reg_base = format!("{base}/registrations");

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &reg_base,
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["6.0.0", "5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0"]}"#)
            .create_async()
            .await;

        let index_body = format!(
            r#"{{"count": 3, "items": [
                {{"@id": "{reg_base}/widget/page/0.json", "count": 2}},
                {{"@id": "{reg_base}/widget/page/1.json", "count": 2}},
                {{"@id": "{reg_base}/widget/page/2.json", "count": 2}}
            ]}}"#
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(index_body)
            .create_async()
            .await;

        let page2_body = r#"{"items": [
            {"catalogEntry": {"version": "5.0.0", "published": "2021-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "6.0.0", "published": "2022-01-01T00:00:00Z"}}
        ]}"#;
        let page2_mock = server
            .mock("GET", "/registrations/widget/page/2.json")
            .with_status(200)
            .with_body(page2_body)
            .expect(1)
            .create_async()
            .await;

        let page1_body = r#"{"items": [
            {"catalogEntry": {"version": "3.0.0", "published": "2019-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "4.0.0", "published": "2020-01-01T00:00:00Z"}}
        ]}"#;
        let page1_mock = server
            .mock("GET", "/registrations/widget/page/1.json")
            .with_status(200)
            .with_body(page1_body)
            .expect(1)
            .create_async()
            .await;

        // Only 4 entries collected across the two allowed external fetches (< 8), so a
        // buggy implementation would keep walking into page 0. This mock must see zero hits.
        let page0_mock = server
            .mock("GET", "/registrations/widget/page/0.json")
            .with_status(200)
            .with_body(
                r#"{"items": [
                {"catalogEntry": {"version": "1.0.0", "published": "2017-01-01T00:00:00Z"}},
                {"catalogEntry": {"version": "2.0.0", "published": "2018-01-01T00:00:00Z"}}
            ]}"#,
            )
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 6);
        // Only the 4 versions covered by the two allowed external pages got a date.
        for v in ["3.0.0", "4.0.0", "5.0.0", "6.0.0"] {
            assert!(
                versions
                    .iter()
                    .find(|ver| ver.version == v)
                    .unwrap()
                    .published_at
                    .is_some(),
                "{v} should have a published_at"
            );
        }
        for v in ["1.0.0", "2.0.0"] {
            assert!(
                versions
                    .iter()
                    .find(|ver| ver.version == v)
                    .unwrap()
                    .published_at
                    .is_none(),
                "{v} is beyond the external-fetch cap and must have no published_at"
            );
        }
        page2_mock.assert_async().await;
        page1_mock.assert_async().await;
        page0_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_single_version_package_terminates() {
        // S3 regression: a package with fewer total versions than HOVER_RECENT_VERSIONS
        // must terminate via index exhaustion rather than hanging or looping.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/orchard.core/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"]}"#)
            .create_async()
            .await;
        let registration_body = inline_registration_index(
            &format!("{base}/registrations"),
            &[("1.0.0", Some("2020-01-01T00:00:00Z"))],
        );
        let _reg_mock = server
            .mock("GET", "/registrations/orchard.core/index.json")
            .with_status(200)
            .with_body(registration_body)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("orchard.core", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_some());
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_no_registrations_base_url_degrades_gracefully() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"]}"#)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    // --- NFR-006 live verification (real network, run explicitly with `--ignored`) ---

    #[tokio::test]
    #[ignore]
    async fn test_live_nuget_attaches_publish_times() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("Newtonsoft.Json", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().take(5).any(|v| v.published_at.is_some()));
    }
}
