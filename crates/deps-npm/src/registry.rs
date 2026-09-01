//! npm registry client.
//!
//! Provides access to the npm registry via:
//! - Package metadata API (<https://registry.npmjs.org/{package}>) for version lookups
//! - Search API (<https://registry.npmjs.org/-/v1/search>) for package search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::types::{NpmPackage, NpmVersion};
use dashmap::DashMap;
use deps_core::{
    DepsError, HOVER_RECENT_VERSIONS, HttpCache, PublishTime, Result, is_dot_segment,
    lsp_helpers::warn_rejected_value,
};
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

/// Per-request timeout for the full-packument fetch inside
/// [`NpmRegistry::fetch_publish_times`].
///
/// Unlike the abbreviated packument `get_versions` uses, the full packument this fetches
/// (for `published_at`/freshness) can be multi-MB and has no timeout of its own beyond
/// `HttpCache`'s generic client timeout. Since #339 routes this through the bulk
/// diagnostics-cache-population pass (`deps-lsp`'s `fetch_latest_versions_parallel`), a
/// slow full-packument response now shares the same outer per-package
/// `tokio::time::timeout` (10s default) as the abbreviated fetch it runs alongside —
/// without a tighter inner cap, a hanging full-packument request could consume that
/// entire outer budget and lose the package's whole version list ("Registry lookup
/// failed") where it previously succeeded. Mirrors `deps-swift`'s
/// `RELEASE_DATES_FETCH_TIMEOUT` pattern: elapsing this timeout is treated the same as
/// any other fetch failure — an empty map, never propagated as an error.
///
/// This is a mitigation, not a structural bound: it is a fixed, independent cap, not
/// derived from whatever outer budget remains after the abbreviated fetch that runs first
/// in the same `get_versions_with` call. `fetch_timeout_secs` is user-configurable down to
/// 1s (`deps-lsp`'s `default_fetch_timeout_secs`/config bounds), and even at the 10s
/// default a slow-but-under-cap abbreviated fetch plus a full 5s of this timeout can still
/// exceed the outer budget. Deriving this from the remaining outer time would close that
/// gap but needs threading the outer deadline into this call — left as a known limitation
/// rather than a blocking fix.
const PUBLISH_TIMES_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

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
///
/// Display link only, never fetched by this process — unlike the packument-fetch URL (see
/// `get_versions`'s `has_dot_segment` gate), so it is deliberately not gated against a
/// `.`/`..` segment (see [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link
/// scope split, #379).
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

/// Whether `name` (a bare package name, or `@scope/pkg` scoped form) has a path segment
/// that is exactly `.` or `..` once split the same way [`versions_url`] splits it. See
/// [`deps_core::lsp_helpers::is_dot_segment`]'s doc for why this must be rejected rather
/// than encoded (#341).
fn has_dot_segment(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix('@')
        && let Some((scope, pkg)) = rest.split_once('/')
    {
        return is_dot_segment(scope) || is_dot_segment(pkg);
    }
    is_dot_segment(name)
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
        Self::build(cache, REGISTRY_BASE.to_string())
    }

    /// Creates a new npm registry client pointed at a custom registry base URL, for
    /// pointing at a mockito server in tests.
    ///
    /// `pub` but gated behind `cfg(test)`/the `test-util` feature (M7/#312) rather than
    /// unconditionally public API: it exists purely so other workspace crates' own test
    /// builds can construct a mockable [`NpmRegistry`] (`cfg(test)` alone would not apply
    /// there, since deps-npm is a normal, non-dev dependency for e.g. `deps-deno`) —
    /// enabled via `deps-npm = { workspace = true, features = ["test-util"] }` under
    /// `[dev-dependencies]`, mirroring `deps-core`'s own `test-util` feature. Never
    /// reachable from a non-test build of a downstream crate.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_registry_base(cache: Arc<HttpCache>, registry_base: String) -> Self {
        Self::build(cache, registry_base)
    }

    fn build(cache: Arc<HttpCache>, registry_base: String) -> Self {
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
    /// - `name`'s scope or package segment is exactly `.` or `..` (#341) — rejected as
    ///   [`DepsError::PackageNotFound`] rather than encoded, since percent-encoding alone
    ///   does not stop the URL parser's dot-segment normalization from retargeting the
    ///   request
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
        if has_dot_segment(name) {
            warn_rejected_value("npm_dot_segment_guard", "npm packument request URL", name);
            return Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            });
        }

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
        let fetch = self.cache.get_transport_only_with_headers(
            &url,
            &[(reqwest::header::ACCEPT, "application/json")],
        );
        let body = match tokio::time::timeout(PUBLISH_TIMES_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                tracing::debug!(package = %name, error = %e, "full packument fetch failed, publish times unavailable");
                return HashMap::new();
            }
            Err(_) => {
                tracing::debug!(
                    package = %name,
                    timeout_secs = PUBLISH_TIMES_FETCH_TIMEOUT.as_secs(),
                    "full packument fetch timed out, publish times unavailable"
                );
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
    /// Only returns non-deprecated, non-prerelease versions unless explicitly requested in
    /// the version requirement (e.g. `^1.0.0-beta.1` legitimately matches and returns
    /// `1.0.0-beta.2`), with one exception: under a wildcard/empty requirement
    /// (`"*"`/`""`), which answers "does this package exist / what is its newest version"
    /// for existence checks rather than "what should I recommend installing". That call
    /// prefers the newest non-deprecated, non-prerelease version; if none exists it falls
    /// straight through to the newest version overall — deprecated, a prerelease, or both
    /// (#338 NFR-001) — rather than reporting "no version found" for a package that
    /// genuinely exists. Mirrors
    /// [`Registry::select_latest_matching`](deps_core::Registry::select_latest_matching)'s
    /// wildcard branch exactly, so the two never disagree on the same input; hover
    /// (`generate_hover`) resolves "latest" through that same method rather than
    /// re-deriving it, so hover, diagnostics, and this fallback can never disagree either
    /// (#347/#348 S1).
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

        if deps_core::is_existence_wildcard_str(req_str) {
            // Rung 1 deliberately does not use the generic `is_stable()` (which now also
            // accepts `AdvisoryDeprecated`, #347/#348): npm's own #338 NFR-002 wants a
            // non-deprecated version preferred over a deprecated one whenever both exist,
            // which is a ranking preference, not a resolvability question.
            let idx =
                deps_core::select_latest_for_existence(&versions, |v| v as &dyn deps_core::Version);
            return Ok(idx.and_then(|idx| versions.into_iter().nth(idx)));
        }

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

/// Derives a #205 [`Deprecation`](deps_core::Deprecation) payload from npm's free-text
/// `deprecated` field, or `None` if there is nothing worth telling the user.
///
/// M2: an all-whitespace `deprecated` string (`"deprecated": ""` is how a package is
/// *un*-deprecated in practice) must produce `None`, not a `Deprecation` with a
/// dangling, empty reason — `removal_status()` above is unaffected (it still treats
/// `Some("")` as flagged, matching pre-#205 behavior; this is only about the payload
/// shown to the user). Never populates `replacement`: npm has no structured successor
/// field, only free text (see [`NpmVersion::deprecation`]'s docs).
fn deprecation_from_message(message: Option<&str>) -> Option<deps_core::Deprecation> {
    let reason = message.map(str::trim).filter(|s| !s.is_empty())?;
    Some(deps_core::Deprecation {
        reason: Some(reason.to_string()),
        replacement: None,
    })
}

/// Parses JSON response from npm package metadata API.
fn parse_package_metadata(data: &[u8]) -> Result<Vec<NpmVersion>> {
    let metadata: PackageMetadata = deps_core::parse_json_checked(data)?;

    // Parse versions once and cache the parsed Version for sorting
    let mut versions_with_parsed: Vec<(NpmVersion, node_semver::Version)> = metadata
        .versions
        .into_iter()
        .filter_map(|(version, meta)| {
            let parsed = node_semver::Version::parse(&version).ok()?;
            Some((
                NpmVersion {
                    version: version.into(),
                    deprecated: meta.deprecated.is_some(),
                    deprecation: deprecation_from_message(meta.deprecated.as_deref()),
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
    versions
        .iter()
        .take(n)
        .map(|v| v.version.to_string())
        .collect()
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
/// Returns a [`DepsError::Json`]-wrapping error if `data` is not valid JSON matching
/// [`PackageTimes`]'s shape, or nests deeper than [`deps_core::MAX_JSON_NESTING_DEPTH`].
fn parse_package_times(
    data: &[u8],
    known_versions: &[String],
) -> Result<HashMap<String, PublishTime>> {
    let parsed: PackageTimes = deps_core::parse_json_checked(data)?;
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
        v.published_at = times.get(v.version.as_str()).copied();
    }
}

/// Parses JSON response from npm search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<NpmPackage>> {
    let response: SearchResponse = deps_core::parse_json_checked(data)?;

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
                latest_version: pkg.version.into(),
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
                    versions.iter().map(|v| v.version.to_string()).collect();
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

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            // Existence/latest-for-display resolution (#338): prefer the newest
            // non-flagged, non-prerelease version. Rung 2 (`!blocks_resolution()`) is where
            // this ladder actually lands when rung 1 finds nothing: npm never produces
            // `RemovalStatus::Yanked` (`types.rs` only maps `deprecated` via
            // `from_advisory`, never a real yank), so `blocks_resolution()` is always
            // `false` here and rung 2 always matches the very first (newest) entry. In
            // practice this means: prefer the newest clean stable release; otherwise fall
            // straight through to the newest release overall — deprecated, a prerelease, or
            // both — rather than reporting "no version found" for a package that genuinely
            // exists (#338 NFR-001). Mirrored by `get_latest_matching`'s identical wildcard
            // branch above so the two never disagree. Hover (`deps-core`'s `generate_hover`)
            // resolves "latest" through this exact method rather than re-deriving it with a
            // different predicate, so hover and this ranking preference can never disagree
            // either (#347/#348 S1).
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        let req_str = req.as_str();
        let parsed_req = node_semver::Range::parse(req_str).ok()?;
        versions.iter().position(|v| {
            node_semver::Version::parse(v.version_string()).is_ok_and(|ver| {
                parsed_req.satisfies(&ver) && !v.removal_status().blocks_resolution()
            })
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

    // --- #341: `.`/`..` path segments survive percent-encoding and are collapsed by the
    // URL parser's own dot-segment normalization, which a raw `!url.contains(...)` check
    // (as used by the tests above) cannot detect. These assert on the *parsed* URL.

    /// Demonstrates the vulnerability `has_dot_segment` exists to prevent: `versions_url`
    /// alone (with no caller-side guard) builds a URL that, once parsed, has already lost
    /// the package segment — `@a/..` normalizes away to the registry root instead of a
    /// 404 for a literal package named `..`.
    #[test]
    fn test_versions_url_scoped_dot_dot_segment_normalizes_to_registry_root() {
        let url = versions_url(REGISTRY_BASE, "@a/..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/", "parsed path: {}", parsed.path());
    }

    #[test]
    fn test_versions_url_bare_dot_dot_normalizes_to_registry_root() {
        let url = versions_url(REGISTRY_BASE, "..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/", "parsed path: {}", parsed.path());
    }

    /// #365 regression sweep: exercises the real production pair (`has_dot_segment` gate +
    /// `versions_url` sink) against the shared adversarial input set, guarding against a 6th
    /// recurrence of #341's defect class.
    #[test]
    fn test_versions_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| (!has_dot_segment(seg)).then(|| versions_url(REGISTRY_BASE, seg)),
            "registry.npmjs.org",
            "/",
        );
    }

    #[test]
    fn test_has_dot_segment_rejects_scoped_dot_dot_package() {
        assert!(has_dot_segment("@a/.."));
    }

    #[test]
    fn test_has_dot_segment_rejects_scoped_dot_package() {
        assert!(has_dot_segment("@a/."));
    }

    #[test]
    fn test_has_dot_segment_rejects_bare_dot_dot() {
        assert!(has_dot_segment(".."));
    }

    #[test]
    fn test_has_dot_segment_accepts_normal_names() {
        assert!(!has_dot_segment("express"));
        assert!(!has_dot_segment("@types/node"));
        assert!(!has_dot_segment("left-pad"));
    }

    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_as_not_found() {
        // #365 R1: asserts the exact `PackageNotFound` variant (gate rejected before any
        // request), not the broader `is_not_found()` (also true for a live 404 `HttpStatus`)
        // — registry.npmjs.org 404ing for this path today would make a deleted gate go
        // undetected by this test.
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("..").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_rejects_scoped_dot_dot_package_as_not_found() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("@a/..").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_rejects_scoped_dot_package_as_not_found() {
        let registry = NpmRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("@a/.").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
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
    fn test_parse_package_metadata_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"versions": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_package_metadata(json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_package_metadata_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"versions": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_package_metadata(json.as_bytes()).is_err());
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
    fn test_parse_search_response_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"objects": [], "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_search_response(json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_search_response_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"objects": [], "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_search_response(json.as_bytes()).is_err());
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
        assert_eq!(
            versions[0]
                .deprecation
                .as_ref()
                .and_then(|d| d.reason.as_deref()),
            Some("use String.prototype.padStart()")
        );
        assert_eq!(versions[1].version, "1.2.0");
        assert!(!versions[1].deprecated);
        assert!(versions[1].deprecation.is_none());
    }

    /// #205 M2: `"deprecated": ""` is npm's own convention for *un*-deprecating a
    /// package — the `Deprecation` payload must be `None`, not `Some` with a dangling
    /// empty reason, even though `removal_status()` (unaffected, pre-existing behavior)
    /// still treats `Some("")` as flagged.
    #[test]
    fn test_parse_abbreviated_packument_empty_string_deprecated_has_no_payload() {
        let json = r#"{
  "name": "pkg",
  "versions": {
    "1.0.0": {"deprecated": ""}
  }
}"#;
        let versions = parse_package_metadata(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].deprecated,
            "removal_status derivation is unaffected"
        );
        assert!(versions[0].deprecation.is_none());
    }

    #[test]
    fn test_deprecation_from_message_trims_and_rejects_empty() {
        assert_eq!(deprecation_from_message(None), None);
        assert_eq!(deprecation_from_message(Some("")), None);
        assert_eq!(deprecation_from_message(Some("   ")), None);
        assert_eq!(
            deprecation_from_message(Some("  use foo instead  ")),
            Some(deps_core::Deprecation {
                reason: Some("use foo instead".to_string()),
                replacement: None,
            })
        );
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
        assert!(
            versions
                .iter()
                .any(|v| v.version.as_str().starts_with("4."))
        );
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
        assert!(version.version.as_str().starts_with("4."));
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
                deprecation: None,
                published_at: None,
            }),
            Box::new(NpmVersion {
                version: "1.0.0".into(),
                deprecated: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #338: every version is deprecated, but the wildcard existence/latest-for-display
    /// resolution must still return the newest one rather than `None` — a deprecated
    /// package still exists.
    #[test]
    fn test_select_latest_matching_wildcard_all_deprecated_returns_newest() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(NpmVersion {
                version: "1.3.0".into(),
                deprecated: true,
                deprecation: None,
                published_at: None,
            }),
            Box::new(NpmVersion {
                version: "1.2.0".into(),
                deprecated: true,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Same guarantee for the empty-requirement string, which `lifecycle.rs` treats
    /// identically to `"*"`.
    #[test]
    fn test_select_latest_matching_empty_req_all_deprecated_returns_newest() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![Box::new(NpmVersion {
            version: "1.0.0".into(),
            deprecated: true,
            deprecation: None,
            published_at: None,
        })];
        let req = VersionReq::new("");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// B1 regression: the wildcard existence check must still skip a prerelease sitting
    /// at index 0 (npm's abbreviated packument sorts newest-first regardless of
    /// prerelease status — a package that publishes canary/beta builds routinely has one
    /// at the front) and pick the newest *stable* version instead, matching pre-#338
    /// behavior and hover's `is_stable()`-based pick. #338's deprecated-fallback must not
    /// have loosened this.
    #[test]
    fn test_select_latest_matching_wildcard_skips_prerelease_at_front() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(NpmVersion {
                version: "19.2.0-canary.1".into(),
                deprecated: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(NpmVersion {
                version: "19.1.0".into(),
                deprecated: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// B1/FR-002-style fallback: when every version is a prerelease (no stable release
    /// exists at all), the wildcard existence check still resolves to the newest version
    /// rather than `None` — a prerelease-only package still exists.
    #[test]
    fn test_select_latest_matching_wildcard_all_prerelease_falls_back_to_newest() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NpmRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(NpmVersion {
                version: "2.0.0-alpha".into(),
                deprecated: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(NpmVersion {
                version: "1.0.0-beta".into(),
                deprecated: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// B2: `get_latest_matching`'s wildcard branch must agree with
    /// `select_latest_matching`'s on the same prerelease-at-front shape.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_skips_prerelease_at_front() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/react")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(
                r#"{"versions": {
                    "19.2.0-canary.1": {},
                    "19.1.0": {}
                }}"#,
            )
            .create_async()
            .await;

        let latest = registry.get_latest_matching("react", "*").await.unwrap();

        let version = latest.expect("react has a stable version");
        assert_eq!(version.version, "19.1.0");
    }

    /// N4: `get_latest_matching` and `select_latest_matching` must agree under `"*"` on
    /// the same version data, mirroring `deps-maven`'s S8 helper pattern. `entries` must
    /// already be newest-first (matching `parse_package_metadata`'s sort), since that's
    /// what both the mocked packument response and the directly-built `Vec` assume.
    /// Returns the agreed-upon version string so a caller can additionally assert on
    /// exactly which version was picked, not just that the two methods agree.
    async fn assert_get_latest_matching_agrees_with_select_latest_matching(
        name: &str,
        entries: &[(&str, bool)],
    ) -> String {
        use deps_core::{Registry, VersionReq};

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        let versions_json: Vec<String> = entries
            .iter()
            .map(|(version, deprecated)| {
                if *deprecated {
                    format!(r#""{version}": {{"deprecated": "old"}}"#)
                } else {
                    format!(r#""{version}": {{}}"#)
                }
            })
            .collect();
        server
            .mock("GET", format!("/{name}").as_str())
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(format!(
                r#"{{"versions": {{{}}}}}"#,
                versions_json.join(",")
            ))
            .create_async()
            .await;

        let via_get_latest = registry
            .get_latest_matching(name, "*")
            .await
            .unwrap()
            .expect("fixture always has a pick");

        let boxed: Vec<Box<dyn deps_core::Version>> = entries
            .iter()
            .map(|(version, deprecated)| {
                Box::new(NpmVersion {
                    version: (*version).into(),
                    deprecated: *deprecated,
                    deprecation: None,
                    published_at: None,
                }) as Box<dyn deps_core::Version>
            })
            .collect();
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("fixture always has a pick");

        assert_eq!(
            via_get_latest.version.as_str(),
            boxed[idx].version_string().as_str()
        );
        via_get_latest.version.to_string()
    }

    #[tokio::test]
    async fn test_wildcard_agreement_mixed_prerelease_and_stable() {
        assert_get_latest_matching_agrees_with_select_latest_matching(
            "react",
            &[("19.2.0-canary.1", false), ("19.1.0", false)],
        )
        .await;
    }

    #[tokio::test]
    async fn test_wildcard_agreement_all_deprecated() {
        assert_get_latest_matching_agrees_with_select_latest_matching(
            "left-pad-agree",
            &[("1.3.0", true), ("1.2.0", true)],
        )
        .await;
    }

    #[tokio::test]
    async fn test_wildcard_agreement_all_prerelease_none_deprecated() {
        assert_get_latest_matching_agrees_with_select_latest_matching(
            "canary-only",
            &[("2.0.0-alpha", false), ("1.0.0-beta", false)],
        )
        .await;
    }

    /// #347/#348 S3: rung 2 of the wildcard ladder (`!blocks_resolution()`) is always
    /// `true` for npm (it never produces `RemovalStatus::Yanked`), so it collapses
    /// straight to the newest entry overall rather than preferring an older *clean*
    /// entry over a newer *deprecated* one. Pre-refactor (when rung 2 excluded
    /// deprecated versions) this same input returned `1.0.0-beta`; it now returns
    /// `2.0.0` — a real, intentional behavior change this test pins down so it stays
    /// verified going forward instead of silently drifting.
    #[tokio::test]
    async fn test_wildcard_agreement_newest_deprecated_beats_older_clean_prerelease() {
        let picked = assert_get_latest_matching_agrees_with_select_latest_matching(
            "newest-deprecated-beats-older-clean-prerelease",
            &[("2.0.0", true), ("1.0.0-beta", false)],
        )
        .await;
        assert_eq!(picked, "2.0.0");
    }

    /// N4 (tier 2): `get_latest_matching`'s all-prerelease/none-deprecated case (W1) —
    /// the async path's own dedicated regression, alongside the shared-fixture agreement
    /// test above.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_all_prerelease_none_deprecated_returns_newest() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/canary-only-solo")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(
                r#"{"versions": {
                    "2.0.0-alpha": {},
                    "1.0.0-beta": {}
                }}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("canary-only-solo", "*")
            .await
            .unwrap();

        let version = latest.expect("a prerelease-only, non-deprecated package still exists");
        assert_eq!(version.version, "2.0.0-alpha");
        assert!(!version.deprecated);
    }

    /// #338 NFR-001: `get_latest_matching` under a wildcard requirement, mirroring the
    /// `left-pad`-shaped real-world case (every published version deprecated), must return
    /// the newest version rather than `None`.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_all_deprecated_returns_newest() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/left-pad")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(
                r#"{"versions": {
                    "1.3.0": {"deprecated": "use String.prototype.padStart()"},
                    "1.2.0": {"deprecated": "use String.prototype.padStart()"}
                }}"#,
            )
            .create_async()
            .await;

        let latest = registry.get_latest_matching("left-pad", "*").await.unwrap();

        let version = latest.expect("an all-deprecated package must still resolve a latest");
        assert_eq!(version.version, "1.3.0");
        assert!(version.deprecated);
        assert!(
            version.deprecation.is_some(),
            "T3/C1: when every non-prerelease version is deprecated, rung 1 finds \
             nothing and rung 2 returns a deprecated pick — the #205 finding must fire"
        );
    }

    /// #338 NFR-002 (regression): a mix of deprecated and non-deprecated versions under a
    /// wildcard requirement must still prefer the newest non-deprecated one, unchanged.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_prefers_non_deprecated_when_available() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/widget")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(
                r#"{"versions": {
                    "2.0.0": {"deprecated": "use widget-next"},
                    "1.0.0": {}
                }}"#,
            )
            .create_async()
            .await;

        let latest = registry.get_latest_matching("widget", "*").await.unwrap();

        let version = latest.expect("widget has a non-deprecated version");
        assert_eq!(version.version, "1.0.0");
        assert!(!version.deprecated);
        assert!(
            version.deprecation.is_none(),
            "T3/C1: a partially-deprecated version list must yield no #205 finding — \
             rung 1 finds the clean 1.0.0 before rung 2 (the all-deprecated fallback) \
             ever runs; a developer expecting 'latest is deprecated' semantics here \
             would wrongly conclude the plumbing is broken"
        );
    }

    fn npm_v(s: &str) -> NpmVersion {
        NpmVersion {
            version: s.into(),
            deprecated: false,
            deprecation: None,
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

    #[test]
    fn test_parse_package_times_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `time` value must be rejected by the depth
        // guard rather than handed to `serde_json::from_slice`.
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let deeply_nested = format!(r#"{{"time":{}1{}}}"#, "[".repeat(depth), "]".repeat(depth));
        assert!(parse_package_times(deeply_nested.as_bytes(), &[]).is_err());
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

    /// H1: `fetch_publish_times`'s internal timeout must stay strictly tighter than the
    /// bulk fetch loop's outer per-package timeout (10s default, `deps-lsp`'s
    /// `default_fetch_timeout_secs`) — otherwise a hanging full-packument request could
    /// consume the entire outer budget and lose the abbreviated fetch's own result too,
    /// reproducing the "Registry lookup failed" regression #339 introduced by routing
    /// this fetch through the bulk diagnostics-cache-population pass. A live
    /// elapsed-timeout test is deliberately not included here (mockito has no built-in
    /// response-delay primitive in this workspace, and sleeping for real seconds in a
    /// unit test would slow the suite); this asserts the invariant the fix exists for.
    #[test]
    fn test_publish_times_fetch_timeout_is_tighter_than_default_outer_fetch_timeout() {
        assert!(PUBLISH_TIMES_FETCH_TIMEOUT < Duration::from_secs(10));
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

    // --- #312: NpmRegistry::clone shares the publish_times cache and HttpCache, the
    // mechanism DenoRegistry::with_npm relies on to dedupe the freshness-path
    // full-packument fetch for a package appearing in both package.json and deno.json ---

    #[tokio::test]
    async fn test_clone_shares_publish_times_cache_avoiding_duplicate_full_packument_fetch() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = NpmRegistry::with_registry_base(Arc::new(HttpCache::new()), base);
        let shared = registry.clone();

        let abbrev_mock = server
            .mock("GET", "/widget")
            .match_header("accept", ABBREVIATED_ACCEPT)
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}}}"#)
            .expect(2)
            .create_async()
            .await;
        let full_mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(r#"{"time": {"1.0.0": "2020-01-01T00:00:00Z"}}"#)
            .expect(1)
            .create_async()
            .await;

        use deps_core::{FreshnessSettings, PackageName, Registry};

        let first = registry
            .get_versions_with(&PackageName::new("widget"), FreshnessSettings::default())
            .await
            .unwrap();
        assert!(first[0].published_at().is_some());

        // A clone — standing in for a second ecosystem instance (e.g. DenoRegistry::npm)
        // sharing this NpmRegistry — must reuse the cached publish-time map rather than
        // refetching the full packument.
        let second = shared
            .get_versions_with(&PackageName::new("widget"), FreshnessSettings::default())
            .await
            .unwrap();
        assert!(second[0].published_at().is_some());

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
