//! npm registry client.
//!
//! Provides access to the npm registry via:
//! - Package metadata API (<https://registry.npmjs.org/{package}>) for version lookups
//! - Search API (<https://registry.npmjs.org/-/v1/search>) for package search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::types::{NpmPackage, NpmVersion};
use dashmap::DashMap;
use deps_core::{DepsError, HOVER_RECENT_VERSIONS, HttpCache, PublishTime, Result};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const REGISTRY_BASE: &str = "https://registry.npmjs.org";

/// `Accept` header requesting the abbreviated packument format, which omits
/// README, changelog, and per-version `dist.signatures` data that
/// `get_versions` never uses. Cuts response size by roughly 60% (verified
/// against `express`: 804,975 bytes full vs 339,376 bytes abbreviated).
const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";

/// How long a derived publish-time map is trusted before a full-packument refetch, absent a
/// top-8 version-set change. Publish times of already-existing versions are immutable, so
/// this is sized for bandwidth (avoiding re-downloading a multi-MB packument on every
/// hover/keystroke), not for staleness — the top-8 set comparison below is what surfaces a
/// brand-new release promptly, independent of this TTL.
const PUBLISH_TIMES_TTL: Duration = Duration::from_hours(1);

/// Cap on the number of packages [`NpmRegistry::publish_times`] retains derived maps for.
/// Not a copy of `HttpCache::evict_entries`'s byte-budget eviction — [`parse_package_times`]
/// retains only entries whose version is in the package's actual published-version list
/// (security S-2), which bounds each entry's map to the registry-authoritative version count
/// for that package (not an attacker-controlled `time` object), so a plain count-based cap on
/// the number of packages is sufficient even though an individual package's map is no longer
/// a small constant size.
const PUBLISH_TIMES_MAX_ENTRIES: usize = 256;

/// Display name for the npm registry used in not-found and API-response
/// error messages.
pub const REGISTRY: &str = "npm";

/// Base URL for package pages on npmjs.com
pub const NPMJS_URL: &str = "https://www.npmjs.com/package";

/// Returns the URL for a package's page on npmjs.com.
///
/// Scoped packages (`@scope/name`) keep their `@` and `/` structure — each segment is
/// percent-encoded individually so the URL still resolves, while everything else
/// (including any attempt to smuggle extra path or Markdown syntax into a segment) is
/// escaped.
pub fn package_url(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@')
        && let Some((scope, pkg)) = rest.split_once('/')
    {
        return format!(
            "{NPMJS_URL}/@{}/{}",
            urlencoding::encode(scope),
            urlencoding::encode(pkg)
        );
    }
    format!("{}/{}", NPMJS_URL, urlencoding::encode(name))
}

/// Builds the npm registry request URL for a package's version metadata.
///
/// Mirrors `package_url`'s per-segment encoding for scoped packages (`@scope/name`
/// keeps its `/` structure, with `scope` and `name` each percent-encoded
/// individually) so a malicious or unusual name can't inject extra path
/// segments or query syntax into the request.
fn versions_url(base: &str, name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@')
        && let Some((scope, pkg)) = rest.split_once('/')
    {
        return format!(
            "{base}/@{}/{}",
            urlencoding::encode(scope),
            urlencoding::encode(pkg)
        );
    }
    format!("{base}/{}", urlencoding::encode(name))
}

/// Converts a 404 response into `DepsError::PackageNotFound`, passing through
/// any other error unchanged.
fn not_found_or(err: DepsError, name: &str) -> DepsError {
    if matches!(err, DepsError::HttpStatus { status: 404, .. }) {
        DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
}

/// A TTL'd, derived `{version -> PublishTime}` map built from one package's full packument,
/// plus the top-8 version set it was built against.
///
/// `top_seen` is what [`NpmRegistry::publish_times`]'s invalidation predicate compares the
/// *current* top-8 set to — comparing the map's own contents instead (e.g. "is a top-8
/// version missing from `times`") cannot self-limit when a version is genuinely, permanently
/// absent from the registry's `time` field: restamping `fetched_at` would clear the TTL
/// disjunct but leave the miss disjunct true on every subsequent call, causing an unbounded
/// refetch loop on the per-keystroke completion path.
struct CachedTimes {
    fetched_at: Instant,
    times: Arc<HashMap<String, PublishTime>>,
    top_seen: Box<[String]>,
}

/// Full packument response, narrowed to the one field [`NpmRegistry::fetch_publish_times`]
/// needs. `time`'s values are untyped: most are RFC 3339 timestamp strings, but a
/// fully-unpublished package's `time.unpublished` entry is an object
/// (`{"time": ..., "versions": [...]}`), so typing this `HashMap<String, String>` would fail
/// deserialization of the whole document for that package.
#[derive(Deserialize)]
struct PackageTimes {
    #[serde(default)]
    time: HashMap<String, serde_json::Value>,
}

/// Client for interacting with the npm registry.
///
/// Uses the npm registry API for package metadata and search.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct NpmRegistry {
    cache: Arc<HttpCache>,
    /// Registry base URL — `REGISTRY_BASE` in production, overridden to a mockito server URL
    /// in tests via [`Self::with_registry_base`] (mirrors `deps-nuget`'s
    /// `NuGetRegistry::with_service_index_url`).
    registry_base: String,
    /// Derived publish-time maps, keyed by package name. Separate from `cache`: the full
    /// packument body itself is never retained anywhere (fetched via
    /// `HttpCache::get_transport_only_with_headers`, which bypasses the entry-map cache) —
    /// only the small `{version: date}` map this holds survives past one call.
    publish_times: Arc<DashMap<String, CachedTimes>>,
}

impl NpmRegistry {
    /// Creates a new npm registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_registry_base(cache, REGISTRY_BASE.to_string())
    }

    fn with_registry_base(cache: Arc<HttpCache>, registry_base: String) -> Self {
        Self {
            cache,
            registry_base,
            publish_times: Arc::new(DashMap::new()),
        }
    }

    /// Fetches all versions for a package from the npm registry.
    ///
    /// Requests the abbreviated packument (`Accept:
    /// application/vnd.npm.install-v1+json`), which omits README, changelog,
    /// and other fields `get_versions` doesn't need while keeping per-version
    /// `deprecated` status.
    ///
    /// Returns versions sorted newest-first. Includes deprecated versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    /// - Package does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("express").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<NpmVersion>> {
        let url = versions_url(&self.registry_base, name);
        let data = self
            .cache
            .get_cached_with_headers(&url, &[(reqwest::header::ACCEPT, ABBREVIATED_ACCEPT)])
            .await
            .map_err(|e| not_found_or(e, name))?;

        parse_package_metadata(&data)
    }

    /// Returns a TTL'd, derived `{version -> PublishTime}` map for `name`, refetching the
    /// full packument only when the cached entry is TTL-expired or `current_top8` differs
    /// from the top-8 set it was last built against (see [`CachedTimes`]).
    ///
    /// `all_versions` is the package's full, registry-authoritative version list (from the
    /// abbreviated packument already fetched via [`Self::get_versions`]) — it bounds what
    /// [`Self::fetch_publish_times`] retains from the `time` field (security S-2), so npm
    /// coverage is not limited to the top-8 window the way `current_top8`-based invalidation
    /// is. `current_top8` is used *only* for the TTL-invalidation predicate and `top_seen`,
    /// never for retention.
    ///
    /// Never fails the caller: a fetch or parse error degrades to an empty map, logged at
    /// `debug` — ages vanish, the version list (already fetched via [`Self::get_versions`])
    /// does not.
    async fn publish_times(
        &self,
        name: &str,
        all_versions: &[String],
        current_top8: &[String],
    ) -> Arc<HashMap<String, PublishTime>> {
        if let Some(cached) = self.publish_times.get(name)
            && !publish_times_stale(&cached, Instant::now(), current_top8)
        {
            return Arc::clone(&cached.times);
        }

        if self.publish_times.len() >= PUBLISH_TIMES_MAX_ENTRIES {
            self.evict_publish_times();
        }

        let times = Arc::new(self.fetch_publish_times(name, all_versions).await);
        self.publish_times.insert(
            name.to_string(),
            CachedTimes {
                fetched_at: Instant::now(),
                times: Arc::clone(&times),
                top_seen: current_top8.to_vec().into_boxed_slice(),
            },
        );
        times
    }

    /// Fetches the full packument (bypassing `HttpCache`'s entry map via
    /// `get_transport_only_with_headers`, so the multi-MB body is never retained in the
    /// shared cache budget) and derives a `{version -> PublishTime}` map from its `time`
    /// field, retaining only entries whose version is in `known_versions`.
    ///
    /// The `known_versions` filter (security S-2) bounds the retained map to the package's
    /// actual published-version count regardless of how many keys a pathological or
    /// malicious `time` object carries — without it, a crafted full packument could retain up
    /// to `MAX_RESPONSE_BYTES` (32 MiB) worth of entries per package across
    /// `PUBLISH_TIMES_MAX_ENTRIES` cached packages. It also drops the `created`/`modified`
    /// pseudo-entries, which are never queried (lookups are always by a real version
    /// string), for free. Callers pass the package's full version list here, not just the
    /// top-8 window, so npm's coverage has no NuGet-style tail gap.
    async fn fetch_publish_times(
        &self,
        name: &str,
        known_versions: &[String],
    ) -> HashMap<String, PublishTime> {
        let url = versions_url(&self.registry_base, name);
        let body = match self
            .cache
            .get_transport_only_with_headers(&url, &[(reqwest::header::ACCEPT, "application/json")])
            .await
        {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(package = %name, error = %e, "full packument fetch failed, publish times unavailable");
                return HashMap::new();
            }
        };

        match parse_package_times(&body, known_versions) {
            Ok(times) => times,
            Err(e) => {
                tracing::debug!(package = %name, error = %e, "full packument parse failed, publish times unavailable");
                HashMap::new()
            }
        }
    }

    /// Drops TTL-expired entries; if still at capacity, clears the whole map. A plain cap,
    /// not a copy of `HttpCache::evict_entries`'s byte-budget eviction shape — entries here
    /// are small enough that count-based eviction is sufficient.
    fn evict_publish_times(&self) {
        let now = Instant::now();
        self.publish_times.retain(|_, cached| {
            now.saturating_duration_since(cached.fetched_at) < PUBLISH_TIMES_TTL
        });
        if self.publish_times.len() >= PUBLISH_TIMES_MAX_ENTRIES {
            self.publish_times.clear();
        }
    }

    /// Finds the latest version matching the given npm semver requirement.
    ///
    /// Only returns non-deprecated versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("express", "^4.0.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<NpmVersion>> {
        let versions = self.get_versions(name).await?;

        // Parse npm semver requirement
        let req = node_semver::Range::parse(req_str)
            .map_err(|e| DepsError::InvalidVersionReq(e.to_string()))?;

        Ok(versions.into_iter().find(|v| {
            let version = node_semver::Version::parse(&v.version).ok();
            version.is_some_and(|ver| req.satisfies(&ver) && !v.deprecated)
        }))
    }

    /// Searches for packages by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_npm::NpmRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = NpmRegistry::new(cache);
    ///
    /// let results = registry.search("express", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<NpmPackage>> {
        let url = format!(
            "{}/-/v1/search?text={}&size={}",
            self.registry_base,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Package metadata response from npm registry.
#[derive(Deserialize)]
struct PackageMetadata {
    versions: std::collections::HashMap<String, VersionMetadata>,
}

/// Version metadata from npm registry.
#[derive(Deserialize)]
struct VersionMetadata {
    #[serde(default)]
    deprecated: Option<String>,
}

/// Parses JSON response from npm package metadata API.
fn parse_package_metadata(data: &[u8]) -> Result<Vec<NpmVersion>> {
    let metadata: PackageMetadata = serde_json::from_slice(data)?;

    // Parse versions once and cache the parsed Version for sorting
    let mut versions_with_parsed: Vec<(NpmVersion, node_semver::Version)> = metadata
        .versions
        .into_iter()
        .filter_map(|(version, meta)| {
            let parsed = node_semver::Version::parse(&version).ok()?;
            Some((
                NpmVersion {
                    version,
                    deprecated: meta.deprecated.is_some(),
                    published_at: None,
                },
                parsed,
            ))
        })
        .collect();

    // Sort using already-parsed versions (newest first)
    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    // Extract sorted versions
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Search response from npm registry.
#[derive(Deserialize)]
struct SearchResponse {
    objects: Vec<SearchObject>,
}

/// Search result object.
#[derive(Deserialize)]
struct SearchObject {
    package: SearchPackage,
}

/// Package information in search result.
#[derive(Deserialize)]
struct SearchPackage {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    links: Option<PackageLinks>,
    version: String,
}

/// Package links in search result.
#[derive(Deserialize)]
struct PackageLinks {
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

/// Returns up to `n` version strings from the front of `versions`, which must already be
/// sorted newest-first (true of [`NpmRegistry::get_versions`]'s output) — this is the input
/// set [`NpmRegistry::publish_times`] invalidates its TTL cache against.
fn top_n(versions: &[NpmVersion], n: usize) -> Box<[String]> {
    versions.iter().take(n).map(|v| v.version.clone()).collect()
}

/// Whether a [`CachedTimes`] entry must be refetched: expired by TTL, **or** the top-8 set
/// it was built against no longer matches `current_top8`.
///
/// Deliberately reads only `cached.fetched_at`/`cached.top_seen`, never `cached.times`'
/// contents — comparing the *input* set this way is what makes the predicate self-limiting.
/// An earlier design invalidated on "a top-8 version is missing from `times`" instead, which
/// cannot self-limit: a version permanently absent from the registry's `time` field would
/// stay a miss on every call, restamping `fetched_at` only clears the TTL half of the `||`,
/// and the result is an unbounded refetch loop on the per-keystroke completion path. This
/// predicate cannot regress into that shape because it has no way to see `times` at all.
fn publish_times_stale(cached: &CachedTimes, now: Instant, current_top8: &[String]) -> bool {
    now.saturating_duration_since(cached.fetched_at) >= PUBLISH_TIMES_TTL
        || current_top8 != &*cached.top_seen
}

/// Parses a full packument's `time` field into a `{version -> PublishTime}` map, retaining
/// only entries whose version string is in `known_versions` (security S-2: bounds the
/// retained map to the package's actual published-version count regardless of how many keys
/// the source `time` object carries — see [`NpmRegistry::fetch_publish_times`]).
///
/// `known_versions` is looked up via a `HashSet` built once up front rather than
/// `Vec::contains`: callers now pass a package's full version list (some npm packages carry
/// several thousand versions), and a per-entry linear scan over that list inside the `time`
/// object's filter would be O(n²).
///
/// # Errors
///
/// Returns a `DepsError::JsonError`-wrapping error if `data` is not valid JSON matching
/// [`PackageTimes`]'s shape.
fn parse_package_times(
    data: &[u8],
    known_versions: &[String],
) -> Result<HashMap<String, PublishTime>> {
    let parsed: PackageTimes = serde_json::from_slice(data)?;
    let known: std::collections::HashSet<&str> =
        known_versions.iter().map(String::as_str).collect();
    Ok(parsed
        .time
        .into_iter()
        .filter(|(version, _)| known.contains(version.as_str()))
        .filter_map(|(version, value)| {
            let published = PublishTime::parse_rfc3339(value.as_str()?)?;
            Some((version, published))
        })
        .collect())
}

/// Attaches `published_at` to each version whose string matches an entry in `times`.
///
/// A version present in `versions` but absent from `times` is not an error: it simply keeps
/// `published_at == None`. Order and set of `versions` are untouched (FR-006 guard).
fn attach_publish_times(versions: &mut [NpmVersion], times: &HashMap<String, PublishTime>) {
    for v in versions {
        v.published_at = times.get(&v.version).copied();
    }
}

/// Parses JSON response from npm search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<NpmPackage>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .objects
        .into_iter()
        .map(|obj| {
            let pkg = obj.package;
            NpmPackage {
                name: pkg.name.into(),
                description: pkg.description,
                homepage: pkg.links.as_ref().and_then(|l| l.homepage.clone()),
                repository: pkg.links.as_ref().and_then(|l| l.repository.clone()),
                latest_version: pkg.version,
            }
        })
        .collect())
}

// Implement Registry trait for NpmRegistry
impl deps_core::Registry for NpmRegistry {
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

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let mut versions = self.get_versions(name.as_str()).await?;
            if freshness.enabled {
                let all_versions: Vec<String> =
                    versions.iter().map(|v| v.version.clone()).collect();
                let top8 = top_n(&versions, HOVER_RECENT_VERSIONS);
                let times = self
                    .publish_times(name.as_str(), &all_versions, &top8)
                    .await;
                attach_publish_times(&mut versions, &times);
            }
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
            let packages = self.search(query, limit).await?;
            Ok(packages
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn deps_core::Metadata>)
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
        let parsed_req = node_semver::Range::parse(req.as_str()).ok()?;
        versions.iter().position(|v| {
            node_semver::Version::parse(v.version_string())
                .is_ok_and(|ver| parsed_req.satisfies(&ver) && !v.is_yanked())
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url_plain() {
        assert_eq!(package_url("react"), "https://www.npmjs.com/package/react");
    }

    #[test]
    fn test_package_url_scoped_preserves_structure() {
        assert_eq!(
            package_url("@types/node"),
            "https://www.npmjs.com/package/@types/node"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_name() {
        let url = package_url("evil)[pkg](https://evil.example");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_scoped_encodes_malicious_segments() {
        let url = package_url("@evil)[/pkg](x");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
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
    fn test_package_url_scoped_encodes_newline_and_percent() {
        let url = package_url("@evil\n<%/pkg");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://www.npmjs.com/package/");
    }

    #[test]
    fn test_versions_url_plain() {
        assert_eq!(
            versions_url(REGISTRY_BASE, "express"),
            "https://registry.npmjs.org/express"
        );
    }

    #[test]
    fn test_versions_url_scoped_preserves_structure() {
        assert_eq!(
            versions_url(REGISTRY_BASE, "@types/node"),
            "https://registry.npmjs.org/@types/node"
        );
    }

    #[test]
    fn test_versions_url_encodes_malicious_name() {
        // A raw `/`, `?`, or `#` in an unscoped name must not survive into
        // the path/query, since `get_versions` doesn't normalize `name`
        // before building the request URL.
        let url = versions_url(REGISTRY_BASE, "evil/../secret?x=1#frag");
        assert!(!url.contains("/../"));
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
    }

    #[test]
    fn test_versions_url_scoped_encodes_malicious_segments() {
        let url = versions_url(REGISTRY_BASE, "@evil/../secret?x=1#frag");
        assert!(!url.contains("/../"));
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
    }

    #[test]
    fn test_parse_package_metadata() {
        let json = r#"{
  "versions": {
    "1.0.0": {},
    "1.0.1": {"deprecated": "Use 1.0.2 instead"},
    "1.0.2": {}
  },
  "dist-tags": {
    "latest": "1.0.2"
  }
}"#;

        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);

        // Sorted newest first
        assert_eq!(versions[0].version, "1.0.2");
        assert!(!versions[0].deprecated);

        assert_eq!(versions[1].version, "1.0.1");
        assert!(versions[1].deprecated);

        assert_eq!(versions[2].version, "1.0.0");
        assert!(!versions[2].deprecated);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
  "objects": [
    {
      "package": {
        "name": "express",
        "description": "Fast, unopinionated web framework",
        "version": "4.18.2",
        "links": {
          "homepage": "http://expressjs.com/",
          "repository": "https://github.com/expressjs/express"
        }
      }
    }
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);

        let pkg = &packages[0];
        assert_eq!(pkg.name, "express");
        assert_eq!(
            pkg.description,
            Some("Fast, unopinionated web framework".into())
        );
        assert_eq!(pkg.latest_version, "4.18.2");
        assert_eq!(pkg.homepage, Some("http://expressjs.com/".into()));
    }

    #[test]
    fn test_parse_search_response_minimal() {
        let json = r#"{
  "objects": [
    {
      "package": {
        "name": "minimal-pkg",
        "version": "1.0.0"
      }
    }
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "minimal-pkg");
        assert_eq!(packages[0].description, None);
    }

    #[test]
    fn test_parse_abbreviated_packument() {
        // Realistic shape of `Accept: application/vnd.npm.install-v1+json`
        // response (captured live from `registry.npmjs.org/left-pad`):
        // no README/changelog, per-version `dist`/`devDependencies` kept.
        let json = r#"{
  "name": "left-pad",
  "dist-tags": {
    "latest": "1.3.0"
  },
  "versions": {
    "1.2.0": {
      "name": "left-pad",
      "version": "1.2.0",
      "dist": {
        "shasum": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
        "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
      }
    },
    "1.3.0": {
      "name": "left-pad",
      "version": "1.3.0",
      "dist": {
        "shasum": "5b8a3a7765dfe001261dde915589e782f8c94d1e",
        "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
      },
      "deprecated": "use String.prototype.padStart()"
    }
  },
  "modified": "2022-01-01T00:00:00.000Z"
}"#;

        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "1.3.0");
        assert!(versions[0].deprecated);
        assert_eq!(versions[1].version, "1.2.0");
        assert!(!versions[1].deprecated);
    }

    #[test]
    fn test_parse_abbreviated_packument_zero_versions() {
        let json = r#"{"name": "empty-pkg", "dist-tags": {}, "versions": {}}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_abbreviated_packument_all_deprecated() {
        let json = r#"{
  "name": "old-pkg",
  "versions": {
    "1.0.0": {"deprecated": "use new-pkg instead"},
    "2.0.0": {"deprecated": "use new-pkg instead"}
  }
}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.deprecated));
    }

    #[test]
    fn test_parse_abbreviated_packument_unusual_version_strings_skipped() {
        // Non-semver keys (build metadata typos, unicode, empty string) must
        // be filtered out rather than panicking or corrupting the sort.
        let json = r#"{
  "name": "weird-pkg",
  "versions": {
    "1.0.0": {},
    "not-a-version": {},
    "": {},
    "1.0.0-😀": {},
    "1.0.0+build.1": {}
  }
}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().any(|v| v.version == "1.0.0"));
        assert!(versions.iter().any(|v| v.version == "1.0.0+build.1"));
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://registry.npmjs.org/left-pad".into(),
            status: 404,
        };
        let result = not_found_or(err, "left-pad");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "left-pad" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        let err = DepsError::HttpStatus {
            url: "https://registry.npmjs.org/pkg-404".into(),
            status: 500,
        };
        let result = not_found_or(err, "pkg-404");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_express_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions = registry.get_versions("express").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.version.starts_with("4.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let results = registry.search("express", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "express"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_latest_matching_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let latest = registry
            .get_latest_matching("express", "^4.0.0")
            .await
            .unwrap();

        assert!(latest.is_some());
        let version = latest.unwrap();
        assert!(version.version.starts_with("4."));
        assert!(!version.deprecated);
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(NpmVersion {
                version: "2.0.0".into(),
                deprecated: true,
                published_at: None,
            }),
            Box::new(NpmVersion {
                version: "1.0.0".into(),
                deprecated: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    fn npm_v(s: &str) -> NpmVersion {
        NpmVersion {
            version: s.to_string(),
            deprecated: false,
            published_at: None,
        }
    }

    // --- top_n ---

    #[test]
    fn test_top_n_takes_front_of_already_sorted_list() {
        let versions = vec![npm_v("3.0.0"), npm_v("2.0.0"), npm_v("1.0.0")];
        let top = top_n(&versions, 2);
        assert_eq!(&*top, &["3.0.0".to_string(), "2.0.0".to_string()]);
    }

    #[test]
    fn test_top_n_fewer_than_n_returns_all() {
        let versions = vec![npm_v("1.0.0")];
        let top = top_n(&versions, 8);
        assert_eq!(&*top, &["1.0.0".to_string()]);
    }

    // --- attach_publish_times (FR-006: set/order untouched) ---

    #[test]
    fn test_attach_publish_times_matches_by_version_string() {
        let mut versions = vec![npm_v("1.0.0"), npm_v("2.0.0")];
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
        // Order/set untouched.
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "2.0.0");
    }

    #[test]
    fn test_attach_publish_times_empty_map_leaves_all_none() {
        let mut versions = vec![npm_v("1.0.0"), npm_v("2.0.0")];
        attach_publish_times(&mut versions, &HashMap::new());
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    // --- parse_package_times: C2 (object-valued time.unpublished) and absence handling ---

    #[test]
    fn test_parse_package_times_happy_path() {
        let json = r#"{"time": {
            "created": "2015-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "1.0.0": "2015-01-02T00:00:00.000Z",
            "2.0.0": "2020-06-15T12:00:00.000Z"
        }}"#;
        let known = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        let times = parse_package_times(json.as_bytes(), &known).unwrap();
        assert_eq!(
            times.get("2.0.0").copied(),
            PublishTime::parse_rfc3339("2020-06-15T12:00:00.000Z")
        );
        // created/modified are pseudo-entries, never a real version string, so the
        // known-versions filter (security S-2) drops them even though they parse fine.
        assert!(!times.contains_key("created"));
        assert!(!times.contains_key("modified"));
    }

    #[test]
    fn test_parse_package_times_filters_to_known_versions() {
        // Security S-2: a version present in `time` but outside the known-versions set
        // (e.g. old history far below the top-8 window) must not be retained.
        let json = r#"{"time": {
            "1.0.0": "2015-01-02T00:00:00.000Z",
            "2.0.0": "2020-06-15T12:00:00.000Z"
        }}"#;
        let known = vec!["2.0.0".to_string()];
        let times = parse_package_times(json.as_bytes(), &known).unwrap();
        assert!(times.contains_key("2.0.0"));
        assert!(!times.contains_key("1.0.0"));
    }

    #[test]
    fn test_parse_package_times_object_valued_unpublished_does_not_error() {
        // Live-verified shape (Finding E): a fully-unpublished package's `time.unpublished`
        // is an object, not a string. Typing the field `HashMap<String, String>` would fail
        // deserialization of the whole document; `serde_json::Value` + `.as_str()` tolerates
        // it by simply excluding that one entry from the map. `"unpublished"` is included in
        // `known` here specifically to prove exclusion is due to the non-string value, not
        // the known-versions filter.
        let json = r#"{"time": {
            "1.0.0": "2015-01-02T00:00:00.000Z",
            "unpublished": {"time": "2016-03-28T22:22:57.991Z", "versions": ["1.0.0"]}
        }}"#;
        let known = vec!["1.0.0".to_string(), "unpublished".to_string()];
        let times = parse_package_times(json.as_bytes(), &known).unwrap();
        assert!(times.contains_key("1.0.0"));
        assert!(!times.contains_key("unpublished"));
    }

    #[test]
    fn test_parse_package_times_missing_time_field_is_empty_map() {
        let times = parse_package_times(br#"{"name": "widget"}"#, &[]).unwrap();
        assert!(times.is_empty());
    }

    #[test]
    fn test_parse_package_times_invalid_json_errors() {
        assert!(parse_package_times(b"not json", &[]).is_err());
    }

    // --- publish_times_stale: the S1 regression this predicate must never reintroduce ---

    fn cached_times(top_seen: &[&str]) -> CachedTimes {
        CachedTimes {
            fetched_at: Instant::now(),
            times: Arc::new(HashMap::new()),
            top_seen: top_seen.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn test_publish_times_stale_fresh_and_unchanged_top8_is_not_stale() {
        let cached = cached_times(&["2.0.0", "1.0.0"]);
        let current = vec!["2.0.0".to_string(), "1.0.0".to_string()];
        assert!(!publish_times_stale(&cached, Instant::now(), &current));
    }

    #[test]
    fn test_publish_times_stale_ttl_expired_is_stale() {
        let mut cached = cached_times(&["2.0.0", "1.0.0"]);
        cached.fetched_at = Instant::now()
            .checked_sub(PUBLISH_TIMES_TTL + Duration::from_secs(1))
            .unwrap();
        let current = vec!["2.0.0".to_string(), "1.0.0".to_string()];
        assert!(publish_times_stale(&cached, Instant::now(), &current));
    }

    #[test]
    fn test_publish_times_stale_top8_changed_is_stale_even_within_ttl() {
        let cached = cached_times(&["2.0.0", "1.0.0"]);
        let current = vec!["3.0.0".to_string(), "2.0.0".to_string()];
        assert!(publish_times_stale(&cached, Instant::now(), &current));
    }

    #[test]
    fn test_publish_times_stale_never_reads_map_contents() {
        // The flagship S1 regression guard: a top-8 version permanently absent from the
        // cached map (simulated here by an empty `times`) must NOT make the predicate stale
        // as long as the top-8 *set* is unchanged and the TTL hasn't expired — otherwise a
        // version genuinely absent from the registry's `time` field would refetch on every
        // call forever. `cached_times` always builds an empty `times` map, so every
        // `publish_times_stale` call in this test file already exercises this by
        // construction; this test makes the property explicit.
        let cached = cached_times(&["9.0.0-missing", "1.0.0"]);
        assert!(cached.times.is_empty());
        let current = vec!["9.0.0-missing".to_string(), "1.0.0".to_string()];
        // Repeated calls, as completion would issue on every keystroke: never stale.
        for _ in 0..10 {
            assert!(!publish_times_stale(&cached, Instant::now(), &current));
        }
    }

    // --- evict_publish_times ---

    #[test]
    fn test_evict_publish_times_drops_only_expired_entries() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        registry.publish_times.insert(
            "expired".to_string(),
            CachedTimes {
                fetched_at: Instant::now()
                    .checked_sub(PUBLISH_TIMES_TTL + Duration::from_secs(1))
                    .unwrap(),
                times: Arc::new(HashMap::new()),
                top_seen: Box::new([]),
            },
        );
        registry.publish_times.insert(
            "fresh".to_string(),
            CachedTimes {
                fetched_at: Instant::now(),
                times: Arc::new(HashMap::new()),
                top_seen: Box::new([]),
            },
        );

        registry.evict_publish_times();

        assert!(registry.publish_times.get("expired").is_none());
        assert!(registry.publish_times.get("fresh").is_some());
    }

    #[test]
    fn test_evict_publish_times_clears_all_when_still_at_capacity_after_ttl_sweep() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        for i in 0..PUBLISH_TIMES_MAX_ENTRIES {
            registry.publish_times.insert(
                format!("pkg-{i}"),
                CachedTimes {
                    fetched_at: Instant::now(),
                    times: Arc::new(HashMap::new()),
                    top_seen: Box::new([]),
                },
            );
        }

        registry.evict_publish_times();

        assert!(registry.publish_times.is_empty());
    }

    // --- publish_times: cache-hit path via directly-manipulated cache state ---
    //
    // Pre-seeding `publish_times` with a fresh, matching entry exercises the cache-hit
    // branch without a real network fetch. The miss/refetch path is exercised end-to-end via
    // `mockito` below, using `with_registry_base`.

    #[tokio::test]
    async fn test_publish_times_cache_hit_returns_same_arc_without_refetch() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let mut times = HashMap::new();
        times.insert(
            "1.0.0".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        let times = Arc::new(times);
        registry.publish_times.insert(
            "widget".to_string(),
            CachedTimes {
                fetched_at: Instant::now(),
                times: Arc::clone(&times),
                top_seen: vec!["1.0.0".to_string()].into_boxed_slice(),
            },
        );

        let current_top8 = vec!["1.0.0".to_string()];
        let result = registry
            .publish_times("widget", &current_top8, &current_top8)
            .await;

        assert!(Arc::ptr_eq(&result, &times));
    }

    // --- publish_times / get_versions_with: end-to-end via mockito (S3 — the mandatory
    // plan §5 hit-count regression guards) ---

    fn full_packument_body(entries: &[(&str, &str)]) -> String {
        let time_entries: Vec<String> = entries
            .iter()
            .map(|(version, published)| format!(r#""{version}": "{published}""#))
            .collect();
        format!(r#"{{"time": {{{}}}}}"#, time_entries.join(","))
    }

    #[tokio::test]
    async fn test_publish_times_end_to_end_missing_version_causes_exactly_one_fetch_across_repeated_calls()
     {
        // The flagship S1 regression guard (plan §5): a top-8 version permanently absent
        // from `time` (simulated here — it is simply never in the mocked body) must not
        // cause a refetch on every call. Mock hit count must stay at 1 across 10 calls.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        let body = full_packument_body(&[
            ("1.0.0", "2020-01-01T00:00:00Z"),
            ("2.0.0", "2021-01-01T00:00:00Z"),
        ]);
        let mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;

        let top8 = vec![
            "3.0.0-missing".to_string(),
            "2.0.0".to_string(),
            "1.0.0".to_string(),
        ];

        for _ in 0..10 {
            let times = registry.publish_times("widget", &top8, &top8).await;
            assert!(!times.contains_key("3.0.0-missing"));
            assert!(times.contains_key("2.0.0"));
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_publish_times_end_to_end_top8_change_triggers_exactly_one_refetch_then_stable() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        // Pre-seed a fresh, cached entry for an *old* top8 — the fetch below must happen
        // exactly once, triggered by the top8 mismatch, never by TTL expiry (fetched_at is
        // `now`, well inside the TTL).
        registry.publish_times.insert(
            "widget".to_string(),
            CachedTimes {
                fetched_at: Instant::now(),
                times: Arc::new(HashMap::new()),
                top_seen: vec!["1.0.0".to_string()].into_boxed_slice(),
            },
        );

        let body = full_packument_body(&[
            ("1.0.0", "2020-01-01T00:00:00Z"),
            ("2.0.0", "2022-06-01T00:00:00Z"),
        ]);
        let mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;

        let new_top8 = vec!["2.0.0".to_string(), "1.0.0".to_string()];

        let first = registry.publish_times("widget", &new_top8, &new_top8).await;
        assert!(first.contains_key("2.0.0"));

        // Repeated calls with the now-current top8: no further refetch.
        for _ in 0..5 {
            registry.publish_times("widget", &new_top8, &new_top8).await;
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_disabled_issues_only_abbreviated_request() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        let abbrev_mock = server
            .mock("GET", "/widget")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}}}"#)
            .create_async()
            .await;
        // No mock registered for `Accept: application/json` — a request there fails the test.

        let versions = registry
            .get_versions_with(
                &PackageName::new("widget"),
                FreshnessSettings {
                    enabled: false,
                    cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
                },
            )
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at().is_none());
        abbrev_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_issues_both_requests_and_attaches_times() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        let abbrev_mock = server
            .mock("GET", "/widget")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}}}"#)
            .create_async()
            .await;
        let full_mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(r#"{"time": {"1.0.0": "2020-01-01T00:00:00Z"}}"#)
            .create_async()
            .await;

        let versions = registry
            .get_versions_with(&PackageName::new("widget"), FreshnessSettings::default())
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at().is_some());
        abbrev_mock.assert_async().await;
        full_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_covers_version_outside_top8_window() {
        // Regression guard: the retention filter passed to `fetch_publish_times` /
        // `parse_package_times` must be the package's full version list, not just the
        // top-8 slice used for TTL invalidation — otherwise npm silently regains the
        // NuGet-style "only the newest ~8 versions get an age" tail gap.
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        let abbrev_versions: String = (1..=10)
            .map(|n| format!(r#""{n}.0.0": {{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let abbrev_mock = server
            .mock("GET", "/widget")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(format!(r#"{{"versions": {{{abbrev_versions}}}}}"#))
            .create_async()
            .await;

        let time_entries: String = (1..=10)
            .map(|n| format!(r#""{n}.0.0": "20{n:02}-01-01T00:00:00Z""#))
            .collect::<Vec<_>>()
            .join(",");
        let full_mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(format!(r#"{{"time": {{{time_entries}}}}}"#))
            .create_async()
            .await;

        let versions = registry
            .get_versions_with(&PackageName::new("widget"), FreshnessSettings::default())
            .await
            .unwrap();

        // 10 versions sorted newest-first (10.0.0 .. 1.0.0); the top-8 window is
        // 10.0.0..=3.0.0, so 2.0.0 and 1.0.0 fall outside it.
        assert_eq!(versions.len(), 10);
        let outside_top8 = versions
            .iter()
            .find(|v| v.version_string() == "1.0.0")
            .unwrap();
        assert!(outside_top8.published_at().is_some());

        abbrev_mock.assert_async().await;
        full_mock.assert_async().await;
    }

    // --- NFR-006 live verification (real network, run explicitly with `--ignored`) ---

    #[tokio::test]
    #[ignore]
    async fn test_live_npm_get_versions_with_attaches_publish_times() {
        use deps_core::{FreshnessSettings, PackageName, Registry};

        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_with(&PackageName::new("express"), FreshnessSettings::default())
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().take(5).any(|v| v.published_at().is_some()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_npm_publish_times_ttl_cache_avoids_second_fetch() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let top8 = vec!["4.18.2".to_string()];

        let first = registry.publish_times("express", &top8, &top8).await;
        assert!(!first.is_empty());

        // Within TTL and unchanged top-8: must return the identical Arc, not refetch.
        let second = registry.publish_times("express", &top8, &top8).await;
        assert!(Arc::ptr_eq(&first, &second));
    }
}
