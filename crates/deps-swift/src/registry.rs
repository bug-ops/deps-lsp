//! Swift package registry: a router over GitHub tags (`url:` dependencies) and SE-0292 registries
//! (`id:` dependencies).
//!
//! `Registry` dependencies fetch versions from GitHub tags and search repositories. An
//! `AlternateRegistry` dependency is dispatched to the SE-0292 client registered for its URL; with
//! no client registered the lookup fails closed, and an `id:` name is never sent to GitHub.

use crate::config::ResolvedSwiftRegistry;
use crate::package_location::RegistryIdentity;
use crate::package_registry::{
    PackageRegistryClient, PublishedAtLookup, REGISTRY as SE_0292_REGISTRY,
};
use crate::types::{SwiftPackage, SwiftVersion};
use dashmap::DashMap;
use deps_core::github::{
    GithubTag, GithubTagsClient, ReleaseDatesCache, classify_tags_fetch_error, paginate_tags,
    semver_tags_newest_first, validate_owner_repo,
};
use deps_core::parser::DependencySource;
use deps_core::registry::{CapResult, KeyShape, register_capped_with_occupied};
use deps_core::{DepsError, EcosystemId, HttpCache, PublishTime, Result, Version};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Display name for the registry backing Swift package version lookups,
/// used in not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Client for fetching Swift package information from GitHub, plus the router that sends
/// `id:` dependencies to their registered SE-0292 registry clients.
#[derive(Clone)]
pub struct SwiftRegistry {
    github: GithubTagsClient,
    /// Per-package memoized GitHub Release publish times (#223 §3.1). `Arc` because
    /// `SwiftRegistry` is `Clone` and clones must share one memo, the same reason
    /// `github`'s cache is an `Arc`.
    release_dates: Arc<ReleaseDatesCache>,
    cache: Arc<HttpCache>,
    /// SE-0292 clients keyed by normalized registry URL; `Arc` for the same sharing reason.
    alternates: Arc<DashMap<String, Arc<PackageRegistryClient>>>,
}

impl SwiftRegistry {
    /// Creates a new Swift registry client with the given HTTP cache.
    ///
    /// Reads `GITHUB_TOKEN` from environment for authenticated requests
    /// (5000 req/h vs 60 req/h unauthenticated).
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            github: GithubTagsClient::new(Arc::clone(&cache)),
            release_dates: Arc::new(ReleaseDatesCache::new()),
            cache,
            alternates: Arc::new(DashMap::new()),
        }
    }

    /// Registers (or refreshes) the SE-0292 client for `registry`'s URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::HttpCache;
    /// use deps_core::registry::CapResult;
    /// use deps_swift::{SwiftParseContext, SwiftRegistry, parse_package_swift_with_context};
    /// use std::sync::Arc;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let config = dir.path().join(".swiftpm/configuration/registries.json");
    /// std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    /// std::fs::write(
    ///     &config,
    ///     r#"{"registries": {"acme": {"url": "https://swift.acme.dev/api"}}, "version": 1}"#,
    /// )
    /// .unwrap();
    /// let uri = url::Url::from_file_path(dir.path().join("Package.swift")).unwrap();
    /// let parsed = parse_package_swift_with_context(
    ///     r#".package(id: "acme.net", from: "1.0.0")"#,
    ///     &uri,
    ///     &SwiftParseContext::default(),
    /// )
    /// .unwrap();
    ///
    /// let registry = SwiftRegistry::new(Arc::new(HttpCache::new()));
    /// for resolved in parsed.resolved_registries {
    ///     assert_eq!(registry.register_alternate(resolved), CapResult::Inserted);
    /// }
    /// ```
    ///
    /// An already-registered URL keeps its client unless its trust or credential changed, in
    /// which case the client is rebuilt. Once the shared alternate-registry cap is reached a new
    /// URL is refused rather than evicting a client a live document may still use; the
    /// returned [`CapResult`] says so, and the caller must not leave a dependency tagged as
    /// resolvable through a refused URL.
    pub fn register_alternate(&self, registry: ResolvedSwiftRegistry) -> CapResult {
        let key = registry.url.as_str().to_string();
        let digest = registry.digest();
        let build = || {
            Arc::new(PackageRegistryClient::new(
                Arc::clone(&self.cache),
                registry.clone(),
            ))
        };
        register_capped_with_occupied(
            &self.alternates,
            key,
            EcosystemId::Swift,
            KeyShape::Url,
            build,
            |current| {
                if current.digest() != digest {
                    self.cache
                        .evict_url_prefix(&format!("{}/", registry.url.as_str()));
                    *current = build();
                }
            },
        )
    }

    /// Lists `name`'s (`scope.name`) releases from the client registered for `index`.
    ///
    /// Never falls back to GitHub: an unregistered `index` or an unparsable identity is
    /// `PackageNotFound`.
    async fn registry_versions(
        &self,
        index: &str,
        name: &str,
        lookup: PublishedAtLookup,
    ) -> Result<Vec<SwiftVersion>> {
        let not_found = || DepsError::PackageNotFound {
            package: name.into(),
            registry: SE_0292_REGISTRY,
        };
        let identity = RegistryIdentity::parse(name).ok_or_else(not_found)?;
        let Some(client) = self.alternates.get(index).map(|entry| Arc::clone(&entry)) else {
            tracing::debug!("no SE-0292 client registered for the dependency's registry");
            return Err(not_found());
        };
        client.list_releases(&identity, lookup).await
    }

    /// Fetches all semver-tagged versions for a package.
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped.
    /// Follows GitHub tags pagination up to `MAX_TAG_PAGES` pages, stopping
    /// as soon as a page comes back with fewer than 100 entries (no further
    /// pages exist).
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is not a valid `owner/repo` string or the GitHub tags
    /// API request fails (including a rate-limit or not-found response).
    #[tracing::instrument(skip_all, fields(package = %deps_core::net_policy::redact_declaration_key(name)), level = "debug")]
    pub async fn get_versions(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        validate_owner_repo(name)?;
        let tags = paginate_tags(EcosystemId::Swift, name, |page| async move {
            self.github
                .fetch_tags_page(name, page)
                .await
                .map_err(|e| classify_tags_fetch_error(e, name, REGISTRY, self.github.has_token()))
        })
        .await?;
        Ok(tags_to_versions(tags.items))
    }

    /// Like [`SwiftRegistry::get_versions`], but also attaches GitHub Release publish
    /// times via `SwiftRegistry::release_dates`.
    ///
    /// Runs the tags fetch and the release-dates fetch concurrently
    /// (`tokio::join!`) — `release_dates` is infallible (empty map on any failure),
    /// so it can never perturb `get_versions`'s error propagation. This removes one
    /// round trip out of the tag-pagination loop's `P+1`, not half the latency (#223
    /// R7), and on a memo hit the join costs nothing at all.
    ///
    /// Takes a [`deps_core::FreshnessSettings`] parameter (ignored, like `deps-cargo`'s
    /// identical `_freshness`) purely so this inherent method's signature matches every
    /// other ecosystem's `get_versions_with` exactly — the same name never means three
    /// different call shapes across crates (#834 critic S1). The `Registry` trait impl
    /// still does the enabled/disabled dispatch itself, choosing this method or the plain
    /// [`Self::get_versions`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_versions`] — the release-dates fetch is infallible and never
    /// contributes an error.
    #[tracing::instrument(skip_all, fields(package = %deps_core::net_policy::redact_declaration_key(name)), level = "debug")]
    pub async fn get_versions_with(
        &self,
        name: &str,
        _freshness: deps_core::FreshnessSettings,
    ) -> Result<Vec<SwiftVersion>> {
        let (versions, dates) = tokio::join!(self.get_versions(name), self.release_dates(name));
        let mut versions = versions?;
        attach_publish_times(&mut versions, &dates);
        Ok(versions)
    }

    /// Fetches the newest ~100 GitHub Releases for `name` and returns a
    /// normalized-tag -> publish-time map, memoized behind a per-package TTL.
    ///
    /// Thin wrapper around the shared [`ReleaseDatesCache::fetch`] — see its docs for
    /// the best-effort/memoization contract.
    #[tracing::instrument(skip_all, fields(package = %deps_core::net_policy::redact_declaration_key(name)), level = "debug")]
    async fn release_dates(&self, name: &str) -> Arc<HashMap<String, PublishTime>> {
        self.release_dates
            .fetch(&self.github, name, EcosystemId::Swift)
            .await
    }

    /// Fetches `name`'s (`owner/repo`) SPDX license identifier from the GitHub
    /// repository API (issue #660, spec 010 plan §1 — live-verified 2026-09-08 against
    /// `apple/swift-nio`: `GET /repos/{owner}/{repo}` returns `license.spdx_id`, a real
    /// SPDX identifier, e.g. `"Apache-2.0"`).
    ///
    /// Returns an empty `Vec` (never an error) on any fetch failure, a missing
    /// `license` field, or GitHub's `"NOASSERTION"` sentinel (a detected-but-
    /// unclassified `LICENSE` file, not a real SPDX identifier) — graceful degradation
    /// (NFR-003), since this is a best-effort secondary signal, not core version data.
    #[tracing::instrument(skip_all, fields(package = %deps_core::net_policy::redact_declaration_key(name)), level = "debug")]
    pub async fn get_license(&self, name: &str) -> Vec<String> {
        if validate_owner_repo(name).is_err() {
            return Vec::new();
        }
        let url = format!("{}/repos/{name}", self.github.api_base());
        match self.github.fetch_authenticated(&url).await {
            Ok(data) => parse_license_response(&data),
            Err(e) => {
                tracing::debug!(
                    package = %deps_core::net_policy::redact_declaration_key(name),
                    error = %e,
                    "github repo license fetch failed"
                );
                Vec::new()
            }
        }
    }

    /// Finds the latest version satisfying the given semver requirement.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_versions`]. An unparseable `req_str` is not an error: it
    /// resolves to `Ok(None)`.
    #[tracing::instrument(skip_all, fields(package = %deps_core::net_policy::redact_declaration_key(name), version = ?req_str), level = "debug")]
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<SwiftVersion>> {
        Ok(pick_latest_matching(
            self.get_versions(name).await?,
            req_str,
        ))
    }

    /// Searches GitHub repositories for Swift packages.
    ///
    /// Returns up to `limit` results. `latest_version` is left empty to avoid
    /// N+1 API calls per search result.
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub search API request fails or the response body is
    /// not valid JSON matching the expected repository-search shape.
    ///
    /// `query` is redacted via [`deps_core::net_policy::url_for_tracing`] in the `query` span
    /// field (#1206) — a caller-supplied search query can itself carry credential-shaped
    /// userinfo (e.g. a `.package(url: "...")` literal's raw text), and this `debug`-level span
    /// is otherwise the same unredacted-log sink every other URL-bearing `tracing` field in
    /// this workspace already guards against.
    #[tracing::instrument(
        skip_all,
        fields(query = %deps_core::net_policy::url_for_tracing(query)),
        level = "debug"
    )]
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SwiftPackage>> {
        let url = format!(
            "{}/search/repositories?q={}+language:swift&per_page={limit}",
            self.github.api_base(),
            urlencoding::encode(query)
        );
        let data = self.github.fetch_authenticated(&url).await?;
        parse_search_response(&data)
    }
}

/// The newest non-yanked version in `versions` (newest-first) matching `req_str`.
///
/// An unparseable `req_str` is not an error: it resolves to `None`.
fn pick_latest_matching(versions: Vec<SwiftVersion>, req_str: &str) -> Option<SwiftVersion> {
    let req = match semver::VersionReq::parse(req_str) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(req = ?req_str, error = %e, "failed to parse version req");
            return None;
        }
    };
    versions.into_iter().find(|v| {
        !v.removal_status().blocks_resolution()
            && semver::Version::parse(v.version.as_str()).is_ok_and(|ver| req.matches(&ver))
    })
}

/// Converts raw tags (possibly accumulated across pages) into a
/// newest-first `SwiftVersion` list. Non-semver tags are skipped.
///
/// Unlike GitHub Actions/GitLab CI, Swift tracks no per-tag SHA, so `build` never rejects an
/// entry — the only behavior change from adopting the shared
/// [`semver_tags_newest_first`] helper (#1480 item 1) is that an exact-duplicate tag pair
/// (`1.0.0` and `v1.0.0` both present) now dedupes to one entry instead of two, since the
/// helper always dedupes by normalized name.
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<SwiftVersion> {
    semver_tags_newest_first(
        tags,
        |tag| tag.name.as_str(),
        |_tag, normalized, parsed| {
            let prerelease = !parsed.pre.is_empty();
            Some(SwiftVersion {
                version: normalized.into(),
                yanked: false,
                published_at: None,
                prerelease,
            })
        },
    )
}

/// Attaches release publish times onto an already-fetched version list, in place.
///
/// Pure and network-free: `versions` came from [`SwiftRegistry::get_versions`],
/// `dates` from [`SwiftRegistry::release_dates`]. A version with no matching entry in
/// `dates` keeps `published_at: None` — exactly the pre-feature rendering (#223).
fn attach_publish_times(versions: &mut [SwiftVersion], dates: &HashMap<String, PublishTime>) {
    for version in versions {
        version.published_at = dates.get(version.version.as_str()).copied();
    }
}

/// Parses a single GitHub tags API response page into a `SwiftVersion`
/// list. Test-only convenience wrapper composing
/// [`deps_core::github::parse_tags_page`] and [`tags_to_versions`] for
/// single-page fixtures.
#[cfg(test)]
fn parse_tags_response(data: &[u8]) -> Result<Vec<SwiftVersion>> {
    Ok(tags_to_versions(deps_core::github::parse_tags_page(data)?))
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
    let response: SearchResponse = deps_core::parse_json_checked(data)?;
    Ok(response
        .items
        .into_iter()
        .map(|item| SwiftPackage {
            name: item.full_name.into(),
            description: item.description,
            repository: Some(item.html_url.clone()),
            homepage: Some(item.html_url),
            latest_version: deps_core::ConcreteVersion::new(""),
        })
        .collect())
}

/// GitHub repository API response, license subset only (issue #660).
#[derive(Deserialize)]
struct RepoResponse {
    #[serde(default)]
    license: Option<RepoLicense>,
}

/// `GET /repos/{owner}/{repo}`'s `license` object.
#[derive(Deserialize)]
struct RepoLicense {
    #[serde(default)]
    spdx_id: Option<String>,
}

/// GitHub's sentinel `spdx_id` for a `LICENSE` file it detected but could not classify
/// against a known SPDX identifier — not a real license, must not be shown as one.
const GITHUB_LICENSE_NOASSERTION: &str = "NOASSERTION";

fn parse_license_response(data: &[u8]) -> Vec<String> {
    let Ok(response) = deps_core::parse_json_checked::<RepoResponse>(data) else {
        return Vec::new();
    };
    response
        .license
        .and_then(|l| l.spdx_id)
        .filter(|id| !id.is_empty() && id != GITHUB_LICENSE_NOASSERTION)
        .map_or_default(|id| vec![id])
}

/// Where a dependency's lookups go.
enum Route<'a> {
    GithubTags,
    Se0292(&'a str),
    NotFetchable,
}

/// The single source-to-backend decision for every lookup.
fn route(source: &DependencySource) -> Route<'_> {
    match source {
        DependencySource::Registry => Route::GithubTags,
        DependencySource::AlternateRegistry { index, .. } => Route::Se0292(index),
        DependencySource::Git { .. }
        | DependencySource::Path { .. }
        | DependencySource::Url { .. }
        | DependencySource::Sdk { .. }
        | DependencySource::Workspace
        | DependencySource::CustomRegistry { .. } => Route::NotFetchable,
        // `DependencySource` is `#[non_exhaustive]`: a future variant is not fetchable until
        // routed explicitly.
        _ => Route::NotFetchable,
    }
}

/// A lookup for a source this router does not fetch: `PackageNotFound`, never a GitHub request.
fn not_fetchable<T: Send + 'static>(
    name: &deps_core::PackageName,
) -> deps_core::ecosystem::BoxFuture<'static, Result<T>> {
    Box::pin(std::future::ready(Err(DepsError::PackageNotFound {
        package: name.as_str().into(),
        registry: SE_0292_REGISTRY,
    })))
}

fn box_versions(versions: Vec<SwiftVersion>) -> Vec<Box<dyn deps_core::Version>> {
    versions
        .into_iter()
        .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
        .collect()
}

impl deps_core::Registry for SwiftRegistry {
    deps_core::impl_registry_versions_method!(get_versions);

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = if freshness.is_enabled() {
                self.get_versions_with(name.as_str(), freshness).await?
            } else {
                self.get_versions(name.as_str()).await?
            };
            Ok(box_versions(versions))
        })
    }

    /// Routes by `source`: `Registry` to GitHub tags, `AlternateRegistry` to its registered
    /// SE-0292 client, anything else (e.g. an unresolved `CustomRegistry`) to `PackageNotFound`,
    /// so a name is never sent to a registry the dependency did not resolve to.
    fn get_versions_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        match route(source) {
            Route::GithubTags => deps_core::Registry::get_versions_with(self, name, freshness),
            Route::Se0292(index) => Box::pin(async move {
                let lookup = if freshness.is_enabled() {
                    PublishedAtLookup::Fetch
                } else {
                    PublishedAtLookup::Skip
                };
                Ok(box_versions(
                    self.registry_versions(index, name.as_str(), lookup).await?,
                ))
            }),
            Route::NotFetchable => not_fetchable(name),
        }
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
        _selection_context: &'a deps_core::SelectionContext,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        req: &'a deps_core::VersionReq,
        selection_context: &'a deps_core::SelectionContext,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        match route(source) {
            Route::GithubTags => {
                deps_core::Registry::get_latest_matching(self, name, req, selection_context)
            }
            Route::Se0292(index) => Box::pin(async move {
                let versions = self
                    .registry_versions(index, name.as_str(), PublishedAtLookup::Skip)
                    .await?;
                Ok(pick_latest_matching(versions, req.as_str())
                    .map(|v| Box::new(v) as Box<dyn deps_core::Version>))
            }),
            Route::NotFetchable => not_fetchable(name),
        }
    }

    fn search_raw<'a>(
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

    /// Under a wildcard/empty `req` (see [`deps_core::is_existence_wildcard`]) this is an
    /// existence check, not an upgrade recommendation — deferred to
    /// [`deps_core::select_latest_for_existence`], matching
    /// `deps-cargo`/`deps-pypi`/`deps-dart`/`deps-npm`. Without this gate, a package whose
    /// only tags so far are prerelease could never resolve under `*`: the `semver` crate's
    /// `VersionReq::parse("*")` does not match a prerelease `Version` unless the requirement
    /// itself carries a prerelease component (found via #421's cross-ecosystem conformance
    /// test in `deps-lsp`).
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
        _selection_context: &deps_core::SelectionContext,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        let parsed_req = semver::VersionReq::parse(req.as_str()).ok()?;
        versions.iter().position(|v| {
            !v.removal_status().blocks_resolution()
                && semver::Version::parse(v.version_string().as_str())
                    .is_ok_and(|ver| parsed_req.matches(&ver))
        })
    }

    // SE-0292 releases with a `problem` are yanked; the GitHub path yields only `Available`
    // (tags carry no yank signal, #233).
    fn reports_yanked(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::test_util::capture_tracing_output_async;

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
        assert!(packages[0].latest_version.as_str().is_empty());
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

    // #758: the shared JSON-nesting-depth cap — this crate had no such coverage for
    // `parse_search_response` before (issue named deps-swift as missing it).
    deps_core::json_depth_conformance! {
        mod swift_json_depth_conformance;
        parse: |bytes: &[u8]| parse_search_response(bytes);
        wrap: |nested: &str| format!(r#"{{"items": [], "extra": {nested}}}"#);
    }

    #[test]
    fn test_parse_tags_v_prefix_stripped() {
        let json = r#"[{"name": "v1.2.3"}, {"name": "v0.9.0"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(!versions[0].version.as_str().starts_with('v'));
        assert!(!versions[1].version.as_str().starts_with('v'));
    }

    #[test]
    fn test_parse_tags_uppercase_v_prefix_stripped() {
        let json = r#"[{"name": "V1.2.3"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    // `validate_owner_repo`, `page_has_more`, `warn_if_pagination_truncated`,
    // `paginate_tags`, `parse_tags_page`, and `normalize_tag` are now shared with
    // `deps-github-actions` via `deps_core::github` (#472, #486); their unit tests
    // moved there. This module keeps only tests for Swift-specific logic
    // (`tags_to_versions`) and end-to-end coverage that exercises the shared
    // primitives through `SwiftRegistry`'s own public API.

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_real_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let Some(versions) = deps_core::test_util::unwrap_or_skip_github_rate_limit(
            registry.get_versions("apple/swift-nio").await,
            "test_fetch_real_versions",
        ) else {
            return;
        };
        assert!(!versions.is_empty());
    }

    #[test]
    fn test_tags_to_versions_accumulated_across_pages_sorts_and_dedupes_none() {
        // Simulates two accumulated pages being merged before sorting, the
        // shape `get_versions` produces when pagination fetches page 2.
        let page1 =
            deps_core::github::parse_tags_page(br#"[{"name": "3.0.0"}, {"name": "2.0.0"}]"#)
                .unwrap();
        let page2 = deps_core::github::parse_tags_page(br#"[{"name": "1.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[2].version, "1.0.0");
    }

    /// #1480 item 1 accepted side effect: adopting the shared `semver_tags_newest_first`
    /// helper gives Swift dedupe by normalized name for free — a repository tagging both
    /// `v1.0.0` and `1.0.0` (the same release under two conventions) now surfaces one
    /// entry, not two, matching GitHub Actions/GitLab CI's existing dedupe behavior.
    #[test]
    fn test_tags_to_versions_dedupes_exact_duplicate_v_prefix_and_bare() {
        let tags =
            deps_core::github::parse_tags_page(br#"[{"name": "v1.0.0"}, {"name": "1.0.0"}]"#)
                .unwrap();
        let versions = tags_to_versions(tags);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
    }

    #[test]
    fn test_tags_to_versions_later_page_can_hold_the_highest_semver() {
        // Regression guard for N1: GitHub returns tags in lexicographic order,
        // not semver order, so a page fetched *later* in pagination can still
        // contain the highest real version (e.g. `v`-prefixed tags sort
        // lexicographically ahead of unrelated subproject tags that fill
        // earlier pages on large monorepos). The final list must be sorted by
        // parsed semver regardless of fetch/page order.
        let page1 = deps_core::github::parse_tags_page(
            br#"[{"name": "DataTransport-1.0.0"}, {"name": "1.0.0"}]"#,
        )
        .unwrap();
        let page2 = deps_core::github::parse_tags_page(br#"[{"name": "v12.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions[0].version, "12.0.0");
        assert_eq!(versions[1].version, "1.0.0");
    }

    deps_core::registry_conformance! {
        mod swift_registry_conformance;
        build: SwiftRegistry::new(Arc::new(HttpCache::new()));
        select_latest_matching: {
            versions: vec![
                Box::new(SwiftVersion {
                    version: "2.0.0".into(),
                    yanked: false,
                    published_at: None,
                    prerelease: false,
                }),
                Box::new(SwiftVersion {
                    version: "1.0.0".into(),
                    yanked: false,
                    published_at: None,
                    prerelease: false,
                }),
            ];
            req: "^1.0.0";
            expected_index: 1;
        };
    }

    deps_core::registry_conformance! {
        mod swift_registry_api_conformance;
        ty: SwiftRegistry;
    }

    // `normalize_tag`, `parse_releases_page`, `classify_release_fetch`, and the
    // TTL/eviction/memo-hit behavior of the release-dates cache now live in
    // `deps_core::github::ReleaseDatesCache` (#486); their unit tests moved there. This
    // module keeps only tests for Swift-specific joining (`attach_publish_times`) and
    // end-to-end coverage exercising `SwiftRegistry`'s own public API.

    // --- attach_publish_times ---

    #[test]
    fn test_attach_publish_times_match() {
        let mut versions = vec![SwiftVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("1.0.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, Some(published));
    }

    #[test]
    fn test_attach_publish_times_miss_stays_none() {
        let mut versions = vec![SwiftVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let dates = HashMap::new();
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, None);
    }

    #[test]
    fn test_attach_publish_times_prefix_mismatch_stays_none() {
        // A dates entry for a *different* version string must never leak onto an
        // unrelated version, even when one is a textual prefix of the other.
        let mut versions = vec![SwiftVersion {
            version: "1.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("1.0.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, None);
    }

    /// Builds a `SwiftRegistry` pointed at a mock server `base` (typically a
    /// `mockito::Server::url()`) instead of the real GitHub API, for tests driving
    /// `Registry::get_versions_with` end-to-end without a live network call.
    fn mock_registry(base: &str, has_token: bool) -> SwiftRegistry {
        let cache = Arc::new(HttpCache::new());
        SwiftRegistry {
            github: GithubTagsClient::for_test(Arc::clone(&cache), base, has_token),
            release_dates: Arc::new(deps_core::github::ReleaseDatesCache::new()),
            cache,
            alternates: Arc::new(DashMap::new()),
        }
    }

    // --- SE-0292 routing (spec 077) ---

    const RELEASES: &str = r#"{"releases": {
        "1.0.0": {"url": "https://r.example/acme/net/1.0.0"},
        "1.2.0": {"url": "https://r.example/acme/net/1.2.0"},
        "1.5.0": {"url": "https://r.example/acme/net/1.5.0", "problem": {"status": 410}},
        "2.0.0": {"url": "https://r.example/acme/net/2.0.0"}
    }}"#;

    fn alternate_source(index: &str) -> DependencySource {
        DependencySource::AlternateRegistry {
            index: index.to_string(),
            mirrors_crates_io: false,
        }
    }

    fn resolved_for(
        base: &str,
        trust: crate::config::RegistryTrust,
    ) -> crate::config::ResolvedSwiftRegistry {
        crate::config::ResolvedSwiftRegistry {
            url: crate::config::SwiftRegistryUrl::for_test(base, trust),
            auth: None,
        }
    }

    /// A GitHub mock server that fails the test on any request, proving an `id:` name never
    /// reaches GitHub.
    async fn forbidden_github() -> (mockito::ServerGuard, mockito::Mock) {
        let mut github = mockito::Server::new_async().await;
        let mock = github
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        (github, mock)
    }

    #[tokio::test]
    async fn test_unregistered_alternate_registry_is_package_not_found_and_never_hits_github() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let (github, never) = forbidden_github().await;
        let registry = mock_registry(&github.url(), false);
        let name = PackageName::new("acme.net");

        let err = Registry::get_versions_from(
            &registry,
            &name,
            &alternate_source("https://unregistered.example/api"),
            FreshnessSettings::default(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }), "{err:?}");

        let req = deps_core::VersionReq::new("^1.0.0");
        let err = Registry::get_latest_matching_from(
            &registry,
            &name,
            &alternate_source("https://unregistered.example/api"),
            &req,
            &deps_core::SelectionContext::none(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }), "{err:?}");
        never.assert_async().await;
    }

    #[tokio::test]
    async fn test_custom_registry_is_never_fetched() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let (github, never) = forbidden_github().await;
        let registry = mock_registry(&github.url(), false);
        let source = DependencySource::CustomRegistry {
            url: "acme".to_string(),
        };
        let err = Registry::get_versions_from(
            &registry,
            &PackageName::new("acme.net"),
            &source,
            FreshnessSettings::default(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }), "{err:?}");
        never.assert_async().await;
    }

    #[tokio::test]
    async fn test_registered_alternate_is_routed_to_its_client_not_github() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let (github, never) = forbidden_github().await;
        let mut se_0292 = mockito::Server::new_async().await;
        let listing = se_0292
            .mock("GET", "/acme/net")
            .with_status(200)
            .with_body(RELEASES)
            .expect(2)
            .create_async()
            .await;
        let registry = mock_registry(&github.url(), false);
        let base = se_0292.url();
        registry.register_alternate(resolved_for(
            &base,
            crate::config::RegistryTrust::WorkspaceDeclared,
        ));
        let source = alternate_source(&base);
        let name = PackageName::new("Acme.Net");

        let versions =
            Registry::get_versions_from(&registry, &name, &source, FreshnessSettings::default())
                .await
                .unwrap();
        assert_eq!(versions.len(), 4);
        assert!(registry.reports_yanked());
        assert!(
            versions
                .iter()
                .any(|v| v.removal_status().blocks_resolution())
        );

        // `1.5.0` is yanked, so `^1.0.0` resolves to `1.2.0`.
        let req = deps_core::VersionReq::new("^1.0.0");
        let latest = Registry::get_latest_matching_from(
            &registry,
            &name,
            &source,
            &req,
            &deps_core::SelectionContext::none(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(latest.version_string(), "1.2.0");

        listing.assert_async().await;
        never.assert_async().await;
    }

    #[test]
    fn test_select_latest_matching_skips_yanked_versions() {
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(SwiftVersion {
                version: "1.5.0".into(),
                yanked: true,
                published_at: None,
                prerelease: false,
            }),
            Box::new(SwiftVersion {
                version: "1.2.0".into(),
                yanked: false,
                published_at: None,
                prerelease: false,
            }),
        ];
        let registry = mock_registry("https://api.github.invalid", false);
        let picked = deps_core::Registry::select_latest_matching(
            &registry,
            &versions,
            &deps_core::VersionReq::new("^1.0.0"),
            &deps_core::SelectionContext::none(),
        );
        assert_eq!(picked, Some(1));
    }

    #[tokio::test]
    async fn test_reregistration_rebuilds_the_client_only_when_trust_or_credential_changed() {
        use crate::config::RegistryTrust::{Trusted, WorkspaceDeclared};

        let registry = mock_registry("https://api.github.invalid", false);
        let key = "https://r.example/api";
        registry.register_alternate(resolved_for(key, WorkspaceDeclared));
        let first = registry
            .alternates
            .get(key)
            .map(|c| Arc::clone(&c))
            .unwrap();

        registry.register_alternate(resolved_for(key, WorkspaceDeclared));
        let same = registry
            .alternates
            .get(key)
            .map(|c| Arc::clone(&c))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &same));

        registry.register_alternate(resolved_for(key, Trusted));
        let rebuilt = registry
            .alternates
            .get(key)
            .map(|c| Arc::clone(&c))
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(registry.alternates.len(), 1);
    }

    #[tokio::test]
    async fn test_dropping_the_credential_never_serves_the_authenticated_body() {
        use crate::auth::{CredentialLookup, SwiftCredential, bind_credential};
        use crate::config::{RegistryTrust, SwiftRegistryUrl, UserTier};
        use deps_core::{PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let url = SwiftRegistryUrl::for_test(&base, RegistryTrust::Trusted);
        let tier = UserTier::for_test(&[&base], HashMap::new());
        let credential = SwiftCredential::Token(deps_core::secret::Redacted::new("t".into()));
        let registry = mock_registry("https://api.github.invalid", false);
        let name = PackageName::new("acme.net");
        let source = alternate_source(&base);
        let fetch = || {
            Registry::get_versions_from(
                &registry,
                &name,
                &source,
                deps_core::FreshnessSettings::default(),
            )
        };

        let authenticated = server
            .mock("GET", "/acme/net")
            .match_header("authorization", "Bearer t")
            .with_status(200)
            .with_body(RELEASES)
            .create_async()
            .await;
        registry.register_alternate(crate::config::ResolvedSwiftRegistry {
            auth: bind_credential(&url, &tier, CredentialLookup::Shared(&credential)),
            url: url.clone(),
        });
        assert_eq!(fetch().await.unwrap().len(), 4);
        authenticated.remove_async().await;

        let _rejected = server
            .mock("GET", "/acme/net")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(401)
            .create_async()
            .await;
        registry.register_alternate(crate::config::ResolvedSwiftRegistry { url, auth: None });
        assert!(
            fetch().await.is_err(),
            "the stale authenticated body was served"
        );
    }

    // --- get_versions: 403 classification (#1295) ---

    /// A confirmed rate limit (`X-RateLimit-Remaining: 0`) classifies as a *verified*
    /// `RateLimited`, via the shared `deps_core::github::classify_tags_fetch_error`.
    #[tokio::test]
    async fn test_get_versions_403_with_confirmed_evidence_is_verified_rate_limited() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_header("x-ratelimit-remaining", "0")
            .with_body("{}")
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let err = registry.get_versions("owner/repo").await.unwrap_err();
        assert!(
            matches!(
                err,
                deps_core::DepsError::RateLimited {
                    verified: deps_core::RateLimitEvidence::Confirmed,
                    ..
                }
            ),
            "expected verified RateLimited, got {err:?}"
        );
    }

    /// An unconfirmed no-token 403 still classifies as `RateLimited` for its actionable hint,
    /// but `verified: RateLimitEvidence::Inferred` — distinguishable from the confirmed case
    /// above (#1295).
    #[tokio::test]
    async fn test_get_versions_403_without_evidence_is_unverified_rate_limited() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let err = registry.get_versions("owner/repo").await.unwrap_err();
        assert!(
            matches!(
                err,
                deps_core::DepsError::RateLimited {
                    verified: deps_core::RateLimitEvidence::Inferred,
                    ..
                }
            ),
            "expected unverified RateLimited, got {err:?}"
        );
    }

    // --- Registry::get_versions_with: freshness.is_enabled() gate (M2) ---

    #[tokio::test]
    async fn test_get_versions_with_disabled_freshness_skips_release_dates_fetch() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"[{"name": "1.0.0"}]"#)
            .create_async()
            .await;
        // Asserted at the end: the disabled path must never touch the releases
        // endpoint at all, not merely tolerate it failing.
        let releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings::Disabled;

        let versions = Registry::get_versions_with(&registry, &name, freshness)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_none()));
        releases_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_freshness_attaches_publish_dates() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"[{"name": "1.0.0"}]"#)
            .create_async()
            .await;
        let _releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"[{"tag_name": "1.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": false}]"#,
            )
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings::default();

        let versions = Registry::get_versions_with(&registry, &name, freshness)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_some()));
    }

    /// Regression for #472 critic M3: `get_versions` must label its pagination-cap
    /// truncation warning `EcosystemId::Swift`, not some other ecosystem's id or a stale
    /// literal left over from the shared `deps_core::github::paginate_tags` extraction. A
    /// hardcoded/rearranged `paginate_tags(EcosystemId::Swift, ...)` call site would silently
    /// break this without failing any other test, since `deps_core::github`'s own tests only
    /// exercise `paginate_tags` with an arbitrary `EcosystemId`.
    #[tokio::test]
    async fn test_get_versions_pagination_cap_warning_is_labeled_swift() {
        let mut server = mockito::Server::new_async().await;
        let full_page: String = format!(
            "[{}]",
            (0..100)
                .map(|i| format!(r#"{{"name":"{i}.0.0"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(full_page)
            .expect(deps_core::github::MAX_TAG_PAGES as usize)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let output = capture_tracing_output_async(async {
            registry.get_versions("owner/repo").await.unwrap();
        })
        .await;

        assert!(output.contains("swift"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
        assert!(!output.contains("github-actions"), "output was: {output}");
    }

    // --- issue #660: license detection ---

    #[test]
    fn parse_license_response_extracts_spdx_id() {
        let body = br#"{"license":{"key":"apache-2.0","spdx_id":"Apache-2.0"}}"#;
        assert_eq!(parse_license_response(body), vec!["Apache-2.0".to_string()]);
    }

    #[test]
    fn parse_license_response_filters_noassertion() {
        let body = br#"{"license":{"key":null,"spdx_id":"NOASSERTION"}}"#;
        assert!(parse_license_response(body).is_empty());
    }

    #[test]
    fn parse_license_response_no_license_field_is_empty() {
        let body = br#"{"full_name":"owner/repo"}"#;
        assert!(parse_license_response(body).is_empty());
    }

    #[test]
    fn parse_license_response_malformed_json_degrades_to_empty() {
        assert!(parse_license_response(b"not json").is_empty());
    }

    #[tokio::test]
    async fn get_license_fetches_repo_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/owner/repo")
            .with_status(200)
            .with_body(r#"{"license":{"spdx_id":"MIT"}}"#)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        assert_eq!(
            registry.get_license("owner/repo").await,
            vec!["MIT".to_string()]
        );
    }

    #[tokio::test]
    async fn get_license_invalid_owner_repo_returns_empty_without_network() {
        let registry = mock_registry("http://[::1]:1", false);
        assert!(registry.get_license("not-a-valid-name").await.is_empty());
    }

    #[tokio::test]
    async fn get_license_fetch_failure_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/owner/missing")
            .with_status(404)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        assert!(registry.get_license("owner/missing").await.is_empty());
    }

    /// #1505 finding 3: an unparseable `req_str` used to be interpolated raw into the warn
    /// message text (`"Failed to parse version req '{}': {}"`), letting a manifest-declared
    /// version requirement forge a log line. `req` is now a `?`-Debug field, which escapes a
    /// raw newline to the two-character sequence `\n` rather than emitting a real line break.
    #[tokio::test]
    async fn test_1505_get_latest_matching_bad_req_does_not_forge_log_line() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{}"}}}}]"#,
                "a".repeat(40)
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let malicious_req = "not-a-req\r\n\x1b[31mERROR deps_lsp: FORGED";

        let log = deps_core::test_util::capture_tracing_output_async(async {
            let result = registry
                .get_latest_matching("owner/repo", malicious_req)
                .await
                .unwrap();
            assert!(result.is_none());
        })
        .await;

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted req_str must not forge an extra log line: {log:?}"
        );
        assert!(
            !log.contains(malicious_req),
            "the raw, un-escaped payload (with its literal CR/ESC bytes) must not survive \
             intact: {log:?}"
        );
    }
}
