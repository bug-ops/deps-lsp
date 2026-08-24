//! Swift package registry using GitHub API.
//!
//! Fetches package versions from GitHub tags and searches repositories.
//! Non-GitHub URLs get empty version lists with a tracing warning.

use crate::types::{SwiftPackage, SwiftVersion};
use bytes::Bytes;
use dashmap::DashMap;
use deps_core::{DepsError, HttpCache, PublishTime, Result};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const GITHUB_API: &str = "https://api.github.com";

/// Display name for the registry backing Swift package version lookups,
/// used in not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Maximum number of `tags` pages fetched per package (100 tags/page).
///
/// This is a **safety ceiling, not the correctness mechanism** — the loop
/// already stops as soon as a page comes back with fewer than 100 entries
/// (`page_has_more`), which is GitHub's documented signal that no further
/// page exists. Every real repository terminates via that signal well
/// before this bound is reached.
///
/// The bound exists only to protect against a pathological repo with an
/// unbounded number of tags. It must stay high enough that it never
/// truncates a real repository's tag list, because GitHub returns tags in
/// **lexicographic, not semver, order** — verified live on
/// `firebase/firebase-ios-sdk` (1131 tags): page 1 is headed by `v8.15.0`
/// (a `v`-prefixed tag lexicographically outranks unprefixed ones), pages
/// 2-9 are entirely unrelated `DataTransport-*`/`Core-*` subproject tags
/// with zero semver-parseable entries, and the real `11.x`/`12.x` releases
/// only appear around pages 10-11. A low page cap (previously 5, i.e. 500
/// tags) silently dropped those newer tags out of `available` entirely —
/// no amount of sorting the *fetched* subset fixes that, since the highest
/// real versions were never fetched at all. This produced two distinct
/// bugs: an ordinary pin like `from: "11.0.0"` read as "unsatisfiable",
/// and hover/completion/update-all reported the stale `8.15.0` as
/// `latest`. 3000 tags (30 pages) comfortably covers this repository and
/// any other known real-world package with room to spare, while still
/// bounding worst-case request count for an adversarial input.
const MAX_TAG_PAGES: u32 = 30;

/// TTL for a successful `/releases` memo entry (§3.1 of #223's plan). Chosen so a
/// newly published release surfaces within a coffee break while keeping the
/// per-package cost at 4 requests/hour worst case.
const RELEASE_DATES_TTL: Duration = Duration::from_mins(15);

/// TTL for a memo entry recording a *failed* `/releases` fetch (network error, rate
/// limit, unparseable body). Deliberately distinct and much shorter than
/// [`RELEASE_DATES_TTL`]: caching a failure for the full positive TTL would black out
/// a package's dates for 15 minutes after one transient error, while not caching it at
/// all would let a rate-limit storm or a non-GitHub identity re-fire the request on
/// every keystroke (#223 M5).
const RELEASE_DATES_ERROR_TTL: Duration = Duration::from_secs(90);

/// Per-request timeout for the `/releases` fetch inside [`SwiftRegistry::release_dates`].
///
/// `release_dates` runs concurrently with the tags fetch under `tokio::join!`
/// (`get_versions_with_release_dates`), which otherwise has no timeout of its own
/// beyond `HttpCache`'s generic client timeout — a slow or hanging release-dates
/// response must not hold up hover/completion or eat into their latency budget.
/// Elapsing this timeout is treated the same as any other fetch failure: an empty
/// map, memoized under [`RELEASE_DATES_ERROR_TTL`], never propagated.
const RELEASE_DATES_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of packages held in [`SwiftRegistry::release_dates`] at once.
/// Comfortably above the distinct-Swift-package count of any realistic workspace
/// while bounding the memo at a few hundred KB (#223 M7).
const MAX_MEMO_ENTRIES: usize = 256;

/// Validates that `name` is a valid `owner/repo` GitHub identifier.
///
/// Accepts characters `[a-zA-Z0-9._-]` in both owner and repo segments.
fn validate_owner_repo(name: &str) -> Result<()> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$").expect("hardcoded regex is valid")
    });
    if re.is_match(name) {
        Ok(())
    } else {
        Err(DepsError::InvalidUri(format!(
            "invalid owner/repo format: '{name}'"
        )))
    }
}

/// One memoized `/releases` lookup for a single package.
///
/// A release's publish time is immutable once published, so a stale entry can only
/// ever *lack* a very recent release — never report a wrong date. The TTL therefore
/// governs how quickly a brand-new release acquires a date, not correctness.
struct ReleaseDatesEntry {
    fetched_at: Instant,
    dates: Arc<HashMap<String, PublishTime>>,
    /// TTL for *this* entry — [`RELEASE_DATES_TTL`] on success, the much shorter
    /// [`RELEASE_DATES_ERROR_TTL`] on failure. Carried per entry rather than derived
    /// at read time so one expiry check covers both outcomes, and an empty-but
    /// -successful fetch (a repo with genuinely no releases) is never mistaken for a
    /// failure (#223 M5).
    ttl: Duration,
}

/// Evicts entries from `map` when it is already at [`MAX_MEMO_ENTRIES`], ahead of an
/// insert that would otherwise grow it further: first every entry expired against its
/// own `ttl`, then — only if that freed nothing — the single oldest entry by
/// `fetched_at`. The O(n) scan runs only on an insert that finds the map full (#223 M7).
fn evict_if_full(map: &DashMap<String, ReleaseDatesEntry>) {
    if map.len() < MAX_MEMO_ENTRIES {
        return;
    }
    let now = Instant::now();
    map.retain(|_, entry| now.duration_since(entry.fetched_at) < entry.ttl);
    if map.len() >= MAX_MEMO_ENTRIES
        && let Some(oldest) = map
            .iter()
            .min_by_key(|e| e.fetched_at)
            .map(|e| e.key().clone())
    {
        map.remove(&oldest);
    }
}

/// Client for fetching Swift package information from GitHub.
#[derive(Clone)]
pub struct SwiftRegistry {
    cache: Arc<HttpCache>,
    auth_headers: Vec<(reqwest::header::HeaderName, String)>,
    has_token: bool,
    /// Per-package memoized GitHub Release publish times (#223 §3.1). `Arc` because
    /// `SwiftRegistry` is `Clone` and clones must share one memo, the same reason
    /// `cache` is an `Arc`.
    release_dates: Arc<DashMap<String, ReleaseDatesEntry>>,
    /// Set once the first skipped release-date enrichment (no `GITHUB_TOKEN`) has
    /// been logged, so the informational message fires at most once per process
    /// rather than once per hover/completion/document-open (#223).
    enrichment_skip_logged: Arc<AtomicBool>,
    /// Base URL for the GitHub API, `GITHUB_API` in production. A field rather than
    /// always reading the constant so tests can point it at a `mockito` server —
    /// `get_versions`/`release_dates`/`search` build every request URL from it.
    api_base: String,
}

impl SwiftRegistry {
    /// Creates a new Swift registry client with the given HTTP cache.
    ///
    /// Reads `GITHUB_TOKEN` from environment for authenticated requests
    /// (5000 req/h vs 60 req/h unauthenticated).
    pub fn new(cache: Arc<HttpCache>) -> Self {
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        let has_token = token.is_some();
        let auth_headers = token
            .map(|token| {
                tracing::info!("GITHUB_TOKEN detected, using authenticated GitHub API requests");
                vec![(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))]
            })
            .unwrap_or_default();

        Self {
            cache,
            auth_headers,
            has_token,
            release_dates: Arc::new(DashMap::new()),
            enrichment_skip_logged: Arc::new(AtomicBool::new(false)),
            api_base: GITHUB_API.to_string(),
        }
    }

    fn headers(&self) -> Vec<(reqwest::header::HeaderName, &str)> {
        self.auth_headers
            .iter()
            .map(|(k, v): &(reqwest::header::HeaderName, String)| (k.clone(), v.as_str()))
            .collect()
    }

    /// Fetches all semver-tagged versions for a package.
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped.
    /// Follows GitHub tags pagination up to `MAX_TAG_PAGES` pages, stopping
    /// as soon as a page comes back with fewer than 100 entries (no further
    /// pages exist).
    pub async fn get_versions(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        validate_owner_repo(name)?;
        let tags = paginate_tags(name, |page| async move {
            let url = format!(
                "{}/repos/{name}/tags?per_page=100&page={page}",
                self.api_base
            );
            self.cache
                .get_cached_with_headers(&url, &self.headers())
                .await
                .map_err(|e| match &e {
                    DepsError::HttpStatus { status: 403, .. } if !self.has_token => {
                        DepsError::CacheError(
                            "GitHub API rate limit exceeded. Set GITHUB_TOKEN to increase the limit (5000 req/h). Run: export GITHUB_TOKEN=$(gh auth token)".into(),
                        )
                    }
                    DepsError::HttpStatus { status: 404, .. } => DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: REGISTRY,
                    },
                    _ => e,
                })
        })
        .await?;
        Ok(tags_to_versions(tags))
    }

    /// Like [`SwiftRegistry::get_versions`], but also attaches GitHub Release publish
    /// times via `SwiftRegistry::release_dates`.
    ///
    /// Runs the tags fetch and the release-dates fetch concurrently
    /// (`tokio::join!`) — `release_dates` is infallible (empty map on any failure),
    /// so it can never perturb `get_versions`'s error propagation. This removes one
    /// round trip out of the tag-pagination loop's `P+1`, not half the latency (#223
    /// R7), and on a memo hit the join costs nothing at all.
    pub async fn get_versions_with_release_dates(&self, name: &str) -> Result<Vec<SwiftVersion>> {
        let (versions, dates) = tokio::join!(self.get_versions(name), self.release_dates(name));
        let mut versions = versions?;
        attach_publish_times(&mut versions, &dates);
        Ok(versions)
    }

    /// Fetches the newest ~100 GitHub Releases for `name` and returns a
    /// normalized-tag -> publish-time map, memoized behind a per-package TTL.
    ///
    /// Best-effort by construction (#223): a malformed identity or a validation
    /// failure returns an empty map with **zero requests**; a missing
    /// `GITHUB_TOKEN` returns an empty map (logged once per process) with zero
    /// requests; any live-fetch error (network, rate limit, unparseable body,
    /// or exceeding [`RELEASE_DATES_FETCH_TIMEOUT`]) returns an empty map,
    /// memoized under the short [`RELEASE_DATES_ERROR_TTL`] rather than the
    /// positive [`RELEASE_DATES_TTL`]. Never propagates an error — callers under
    /// `tokio::join!` must not have their tags fetch perturbed by a release-dates
    /// failure.
    ///
    /// Runs its own [`validate_owner_repo`] guard: `get_versions` validates before
    /// building its own URL, but under `get_versions_with_release_dates`'s
    /// `tokio::join!` that guard no longer runs first, and this method interpolates
    /// `name` into an `api.github.com` path of its own (#223 M6).
    async fn release_dates(&self, name: &str) -> Arc<HashMap<String, PublishTime>> {
        if validate_owner_repo(name).is_err() {
            return Arc::new(HashMap::new());
        }

        let now = Instant::now();
        if let Some(entry) = self.release_dates.get(name)
            && now.duration_since(entry.fetched_at) < entry.ttl
        {
            return Arc::clone(&entry.dates);
        }

        if !self.has_token {
            if !self.enrichment_skip_logged.swap(true, Ordering::Relaxed) {
                tracing::info!(
                    "GITHUB_TOKEN not set — Swift release dates are unavailable; hover and \
                     completion will omit publish ages. Run: export GITHUB_TOKEN=$(gh auth token)"
                );
            }
            return Arc::new(HashMap::new());
        }

        let url = format!("{}/repos/{name}/releases?per_page=100", self.api_base);
        let fetch_result = tokio::time::timeout(
            RELEASE_DATES_FETCH_TIMEOUT,
            self.cache.get_cached_with_headers(&url, &self.headers()),
        )
        .await;
        match &fetch_result {
            Ok(Err(e)) => tracing::debug!(package = name, error = %e, "release dates fetch failed"),
            Err(_) => tracing::debug!(package = name, "release dates fetch timed out"),
            Ok(Ok(_)) => {}
        }
        let (dates, ttl) = classify_release_fetch(fetch_result.ok());
        let dates = Arc::new(dates);

        // Refreshing an already-present key (the common case: this package's own
        // entry just expired) doesn't grow the map, so evicting ahead of it would
        // drop an unrelated live entry for no reason.
        if !self.release_dates.contains_key(name) {
            evict_if_full(&self.release_dates);
        }
        self.release_dates.insert(
            name.to_string(),
            ReleaseDatesEntry {
                fetched_at: now,
                dates: Arc::clone(&dates),
                ttl,
            },
        );
        dates
    }

    /// Finds the latest version satisfying the given semver requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<SwiftVersion>> {
        let versions = self.get_versions(name).await?;

        let req = match semver::VersionReq::parse(req_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse version req '{}': {}", req_str, e);
                return Ok(None);
            }
        };

        Ok(versions
            .into_iter()
            .find(|v| semver::Version::parse(&v.version).is_ok_and(|ver| req.matches(&ver))))
    }

    /// Searches GitHub repositories for Swift packages.
    ///
    /// Returns up to `limit` results. `latest_version` is left empty to avoid
    /// N+1 API calls per search result.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SwiftPackage>> {
        let url = format!(
            "{GITHUB_API}/search/repositories?q={}+language:swift&per_page={limit}",
            urlencoding::encode(query)
        );
        let data = self
            .cache
            .get_cached_with_headers(&url, &self.headers())
            .await?;
        parse_search_response(&data)
    }
}

/// GitHub tags API response item.
#[derive(Deserialize)]
struct GithubTag {
    name: String,
}

/// GitHub API error response (rate limit, not found, etc.).
#[derive(Deserialize)]
struct GithubErrorResponse {
    message: String,
}

/// Returns `true` when a fetched page came back full (`per_page=100`
/// entries), meaning a subsequent page may exist and should be fetched too.
/// A page with fewer entries is necessarily the last one.
const fn page_has_more(page_len: usize) -> bool {
    page_len >= 100
}

/// Logs a warning when tag pagination for `name` stops at [`MAX_TAG_PAGES`]
/// while GitHub still had more pages available (`page_has_more(page_len)`).
///
/// Without this, hitting the safety ceiling on a pathological repo is
/// indistinguishable in logs from "the repo genuinely has no matching
/// version" — this makes truncation diagnosable.
fn warn_if_pagination_truncated(name: &str, page: u32, page_len: usize) {
    if page == MAX_TAG_PAGES && page_has_more(page_len) {
        tracing::warn!(
            package = name,
            pages_fetched = MAX_TAG_PAGES,
            "Swift tags pagination for '{name}' stopped at the {MAX_TAG_PAGES}-page cap while \
             GitHub reported more pages available; the fetched version list may be truncated"
        );
    }
}

/// Drives the GitHub tags pagination loop, fetching pages via `fetch_page`
/// until a partial page is seen or [`MAX_TAG_PAGES`] is reached.
///
/// Extracted out of [`SwiftRegistry::get_versions`] so tests can inject a
/// fake `fetch_page` and exercise the real loop — including the
/// [`warn_if_pagination_truncated`] call site — without a live GitHub API.
async fn paginate_tags<F, Fut>(name: &str, mut fetch_page: F) -> Result<Vec<GithubTag>>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<Bytes>>,
{
    let mut tags = Vec::new();
    for page in 1..=MAX_TAG_PAGES {
        let data = fetch_page(page).await?;
        let page_tags = parse_tags_page(&data)?;
        let page_len = page_tags.len();
        tags.extend(page_tags);
        if !page_has_more(page_len) {
            break;
        }
        warn_if_pagination_truncated(name, page, page_len);
    }
    Ok(tags)
}

/// Parses a single GitHub tags API page into raw tag entries.
///
/// GitHub returns an error object instead of array when rate-limited or on
/// other errors. Detect this and return a descriptive error.
fn parse_tags_page(data: &[u8]) -> Result<Vec<GithubTag>> {
    match serde_json::from_slice(data) {
        Ok(tags) => Ok(tags),
        Err(_) => {
            if let Ok(err) = serde_json::from_slice::<GithubErrorResponse>(data) {
                Err(DepsError::CacheError(format!(
                    "GitHub API error: {}",
                    err.message
                )))
            } else {
                Ok(vec![])
            }
        }
    }
}

/// Strips a leading `v`/`V` tag prefix, shared by the tag-name and release-tag-name
/// parsing paths so a `V`-prefixed release always joins its tag (#223) — a divergent
/// strip between the two would silently drop the release date for that repo.
fn normalize_tag(name: &str) -> &str {
    // Both cases are real GitHub tag conventions ("v2.62.0", "V2.62.0"); stripping
    // only lowercase 'v' would leave "V2.62.0" unparseable as semver, silently
    // dropping a real, installable tag out of `available` — the same false-positive
    // class this PR's diagnostic guards against elsewhere.
    name.strip_prefix(['v', 'V']).unwrap_or(name)
}

/// Converts raw tags (possibly accumulated across pages) into a
/// newest-first `SwiftVersion` list. Non-semver tags are skipped.
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<SwiftVersion> {
    let mut versions_with_parsed: Vec<(SwiftVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            let name = normalize_tag(&tag.name).to_string();
            let parsed = semver::Version::parse(&name).ok()?;
            Some((
                SwiftVersion {
                    version: name,
                    yanked: false,
                    published_at: None,
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    versions_with_parsed.into_iter().map(|(v, _)| v).collect()
}

/// GitHub releases API response item.
#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
}

/// Parses a GitHub `/releases` page into a normalized-tag -> publish-time map.
///
/// Returns `None` for malformed JSON, an unexpected shape, or a GitHub error object —
/// a genuine *parse failure*, distinct from `Some(HashMap::new())`, which means the
/// page parsed successfully and the repo simply has no (non-draft, dated) releases.
/// The caller relies on this distinction to memoize a parse failure under the short
/// [`RELEASE_DATES_ERROR_TTL`] rather than the positive [`RELEASE_DATES_TTL`] (#223
/// S3) — release dates are still strictly best-effort overall, since neither case
/// ever propagates an error out of [`SwiftRegistry::release_dates`]. Skips draft
/// releases and releases with no `published_at`. GitHub returns releases in
/// `created_at` descending order, so `entry(..).or_insert(..)` keeps the *first*
/// (newest) release seen for a given normalized tag — the deterministic collision
/// policy for the rare case of two releases pointing at the same tag (#223 M2).
fn parse_releases_page(data: &[u8]) -> Option<HashMap<String, PublishTime>> {
    let releases: Vec<GithubRelease> = serde_json::from_slice(data).ok()?;
    let mut dates = HashMap::new();
    for release in releases {
        if release.draft {
            continue;
        }
        let Some(published) = release
            .published_at
            .as_deref()
            .and_then(PublishTime::parse_rfc3339)
        else {
            continue;
        };
        dates
            .entry(normalize_tag(&release.tag_name).to_string())
            .or_insert(published);
    }
    Some(dates)
}

/// Classifies a `/releases` fetch outcome into the `(dates, ttl)` pair to memoize.
///
/// `None` represents an elapsed [`RELEASE_DATES_FETCH_TIMEOUT`] (the outer
/// `tokio::time::timeout::Elapsed` collapsed via `.ok()` at the call site, since it
/// carries no useful data of its own). Every failure path — timeout, HTTP/network
/// error, or a response that parses as JSON but isn't a valid `/releases` page —
/// gets the short [`RELEASE_DATES_ERROR_TTL`]; only a successfully parsed page
/// (which may itself be an empty map, for a repo with no releases) gets the positive
/// [`RELEASE_DATES_TTL`] (#223 S3). Extracted as a pure function so the TTL decision
/// itself — not just the memo's read-side retention behavior — is directly
/// unit-testable without a live fetch or a real `Elapsed`.
fn classify_release_fetch(
    outcome: Option<Result<Bytes>>,
) -> (HashMap<String, PublishTime>, Duration) {
    match outcome {
        Some(Ok(data)) => match parse_releases_page(&data) {
            Some(dates) => (dates, RELEASE_DATES_TTL),
            None => (HashMap::new(), RELEASE_DATES_ERROR_TTL),
        },
        Some(Err(_)) | None => (HashMap::new(), RELEASE_DATES_ERROR_TTL),
    }
}

/// Attaches release publish times onto an already-fetched version list, in place.
///
/// Pure and network-free: `versions` came from [`SwiftRegistry::get_versions`],
/// `dates` from [`SwiftRegistry::release_dates`]. A version with no matching entry in
/// `dates` keeps `published_at: None` — exactly the pre-feature rendering (#223).
fn attach_publish_times(versions: &mut [SwiftVersion], dates: &HashMap<String, PublishTime>) {
    for version in versions {
        version.published_at = dates.get(&version.version).copied();
    }
}

/// Parses a single GitHub tags API response page into a `SwiftVersion`
/// list. Test-only convenience wrapper composing [`parse_tags_page`] and
/// [`tags_to_versions`] for single-page fixtures.
#[cfg(test)]
fn parse_tags_response(data: &[u8]) -> Result<Vec<SwiftVersion>> {
    Ok(tags_to_versions(parse_tags_page(data)?))
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
    let response: SearchResponse = serde_json::from_slice(data)?;
    Ok(response
        .items
        .into_iter()
        .map(|item| SwiftPackage {
            name: item.full_name.into(),
            description: item.description,
            repository: Some(item.html_url.clone()),
            homepage: Some(item.html_url),
            latest_version: String::new(),
        })
        .collect())
}

impl deps_core::Registry for SwiftRegistry {
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
            let versions = if freshness.enabled {
                self.get_versions_with_release_dates(name.as_str()).await?
            } else {
                self.get_versions(name.as_str()).await?
            };
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
        let parsed_req = semver::VersionReq::parse(req.as_str()).ok()?;
        versions.iter().position(|v| {
            semver::Version::parse(v.version_string()).is_ok_and(|ver| parsed_req.matches(&ver))
        })
    }

    // `Version::is_yanked` is hardcoded `false` (`registry.rs:173`) — Swift
    // package registries expose no per-tag yank/deprecation signal (#233).
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
        assert!(packages[0].latest_version.is_empty());
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

    #[test]
    fn test_parse_tags_v_prefix_stripped() {
        let json = r#"[{"name": "v1.2.3"}, {"name": "v0.9.0"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        // Versions should have 'v' prefix stripped
        assert!(!versions[0].version.starts_with('v'));
        assert!(!versions[1].version.starts_with('v'));
    }

    #[test]
    fn test_parse_tags_uppercase_v_prefix_stripped() {
        let json = r#"[{"name": "V1.2.3"}]"#;
        let versions = parse_tags_response(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    #[test]
    fn test_validate_owner_repo_invalid_format_message() {
        let err = validate_owner_repo("no-slash").unwrap_err();
        assert!(err.to_string().contains("invalid owner/repo format"));
    }

    #[test]
    fn test_validate_owner_repo_valid() {
        assert!(validate_owner_repo("apple/swift-nio").is_ok());
        assert!(validate_owner_repo("foo/bar").is_ok());
        assert!(validate_owner_repo("org.name/repo_name-v2").is_ok());
    }

    #[test]
    fn test_validate_owner_repo_invalid() {
        assert!(validate_owner_repo("no-slash").is_err());
        assert!(validate_owner_repo("../../etc/passwd").is_err());
        assert!(validate_owner_repo("owner/repo/extra").is_err());
        assert!(validate_owner_repo("owner/ repo").is_err());
        assert!(validate_owner_repo("").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let versions = registry.get_versions("apple/swift-nio").await.unwrap();
        assert!(!versions.is_empty());
    }

    #[test]
    fn test_page_has_more_full_page_continues() {
        assert!(page_has_more(100));
    }

    #[test]
    fn test_page_has_more_partial_page_stops() {
        assert!(!page_has_more(99));
        assert!(!page_has_more(0));
    }

    #[derive(Clone, Default)]
    struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capturing_subscriber() -> (CapturingWriter, impl tracing::Subscriber) {
        let writer = CapturingWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            // INFO (not WARN) so the release-dates token-gate skip (`tracing::info!`)
            // is captured too, alongside the WARN-level pagination-truncation tests
            // that already use this helper.
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .with_target(false)
            .finish();
        (writer, subscriber)
    }

    /// Captures `tracing` output emitted during `f` into a `String`, so
    /// pagination-truncation warnings can be asserted on without a real
    /// GitHub server (the tags endpoint's base URL isn't test-injectable).
    fn capture_tracing_output(f: impl FnOnce()) -> String {
        let (writer, subscriber) = capturing_subscriber();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
    }

    /// Async counterpart of [`capture_tracing_output`]: sets the capturing
    /// subscriber as the thread-local default for the duration of `fut`.
    /// Relies on the `#[tokio::test]` current-thread runtime polling `fut`
    /// on the same thread that installed the default.
    async fn capture_tracing_output_async(fut: impl std::future::Future<Output = ()>) -> String {
        let (writer, subscriber) = capturing_subscriber();
        let guard = tracing::subscriber::set_default(subscriber);
        fut.await;
        drop(guard);
        String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
    }

    #[test]
    fn test_pagination_warns_when_truncated_at_cap() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("owner/repo", MAX_TAG_PAGES, 100);
        });
        assert!(output.contains("owner/repo"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
    }

    #[test]
    fn test_pagination_silent_when_under_cap() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("owner/repo", MAX_TAG_PAGES - 1, 100);
        });
        assert!(output.is_empty(), "output was: {output}");
    }

    #[test]
    fn test_pagination_silent_when_last_page_at_cap_is_partial() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("owner/repo", MAX_TAG_PAGES, 42);
        });
        assert!(output.is_empty(), "output was: {output}");
    }

    /// Builds a JSON tags page with `count` uniquely named entries.
    fn tags_page_json(count: usize) -> Bytes {
        let entries: Vec<String> = (0..count)
            .map(|i| format!(r#"{{"name":"tag{i}"}}"#))
            .collect();
        Bytes::from(format!("[{}]", entries.join(",")))
    }

    /// Drives [`paginate_tags`] with a full page followed by a partial page,
    /// then a third page that must never be fetched. This exercises the
    /// real loop (accumulation + `break` on a partial page) end-to-end,
    /// unlike the tests above which only call [`warn_if_pagination_truncated`]
    /// directly — a reordered or dropped call site inside the loop, or a
    /// broken `break` condition, would surface here as a wrong tag count,
    /// an unexpected third fetch, or a spurious warning.
    #[tokio::test]
    async fn test_paginate_tags_stops_after_partial_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let mut tags = Vec::new();
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("owner/repo", |page| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    match page {
                        1 => Ok(tags_page_json(100)),
                        2 => Ok(tags_page_json(42)),
                        _ => panic!("page {page} must not be fetched after a partial page"),
                    }
                }
            })
            .await
            .unwrap();
            tags = result;
        })
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "must stop after the partial page 2"
        );
        assert_eq!(tags.len(), 142);
        assert!(
            output.is_empty(),
            "must not warn below the page cap: {output}"
        );
    }

    /// Drives [`paginate_tags`] to the [`MAX_TAG_PAGES`] cap with every page
    /// full, so the loop exits via the `for` bound rather than the `break`.
    /// Only the real call site inside the loop can produce this warning —
    /// dropping it, or moving it outside the loop where `page`/`page_len`
    /// are unavailable, fails this test where it would not fail a test of
    /// `warn_if_pagination_truncated` in isolation.
    #[tokio::test]
    async fn test_paginate_tags_warns_when_cap_reached_with_full_last_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("owner/repo", |_page| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { Ok(tags_page_json(100)) }
            })
            .await
            .unwrap();
            assert_eq!(result.len(), 100 * MAX_TAG_PAGES as usize);
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), MAX_TAG_PAGES);
        assert!(output.contains("owner/repo"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
    }

    #[test]
    fn test_parse_tags_page_returns_raw_tags() {
        let json = r#"[{"name": "v1.0.0"}, {"name": "not-semver"}]"#;
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "v1.0.0");
    }

    #[test]
    fn test_tags_to_versions_accumulated_across_pages_sorts_and_dedupes_none() {
        // Simulates two accumulated pages being merged before sorting, the
        // shape `get_versions` produces when pagination fetches page 2.
        let page1 = parse_tags_page(br#"[{"name": "3.0.0"}, {"name": "2.0.0"}]"#).unwrap();
        let page2 = parse_tags_page(br#"[{"name": "1.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[2].version, "1.0.0");
    }

    #[test]
    fn test_tags_to_versions_later_page_can_hold_the_highest_semver() {
        // Regression guard for N1: GitHub returns tags in lexicographic order,
        // not semver order, so a page fetched *later* in pagination can still
        // contain the highest real version (e.g. `v`-prefixed tags sort
        // lexicographically ahead of unrelated subproject tags that fill
        // earlier pages on large monorepos). The final list must be sorted by
        // parsed semver regardless of fetch/page order.
        let page1 =
            parse_tags_page(br#"[{"name": "DataTransport-1.0.0"}, {"name": "1.0.0"}]"#).unwrap();
        let page2 = parse_tags_page(br#"[{"name": "v12.0.0"}]"#).unwrap();
        let mut all = page1;
        all.extend(page2);
        let versions = tags_to_versions(all);
        assert_eq!(versions[0].version, "12.0.0");
        assert_eq!(versions[1].version, "1.0.0");
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = SwiftRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(SwiftVersion {
                version: "2.0.0".into(),
                yanked: false,
                published_at: None,
            }),
            Box::new(SwiftVersion {
                version: "1.0.0".into(),
                yanked: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    // --- normalize_tag ---

    #[test]
    fn test_normalize_tag_strips_lowercase_v() {
        assert_eq!(normalize_tag("v1.2.3"), "1.2.3");
    }

    #[test]
    fn test_normalize_tag_strips_uppercase_v() {
        assert_eq!(normalize_tag("V1.2.3"), "1.2.3");
    }

    #[test]
    fn test_normalize_tag_no_prefix_unchanged() {
        assert_eq!(normalize_tag("1.2.3"), "1.2.3");
    }

    // --- parse_releases_page ---

    #[test]
    fn test_parse_releases_page_happy_path() {
        let json = br#"[
            {"tag_name": "2.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": false},
            {"tag_name": "1.0.0", "published_at": "2025-06-01T00:00:00Z", "draft": false}
        ]"#;
        let dates = parse_releases_page(json).unwrap();
        assert_eq!(dates.len(), 2);
        assert!(dates.contains_key("2.0.0"));
        assert!(dates.contains_key("1.0.0"));
    }

    #[test]
    fn test_parse_releases_page_skips_draft() {
        let json = br#"[
            {"tag_name": "2.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": true},
            {"tag_name": "1.0.0", "published_at": "2025-06-01T00:00:00Z", "draft": false}
        ]"#;
        let dates = parse_releases_page(json).unwrap();
        assert_eq!(dates.len(), 1);
        assert!(!dates.contains_key("2.0.0"));
        assert!(dates.contains_key("1.0.0"));
    }

    #[test]
    fn test_parse_releases_page_skips_null_published_at() {
        let json = br#"[
            {"tag_name": "2.0.0", "published_at": null, "draft": false}
        ]"#;
        let dates = parse_releases_page(json).unwrap();
        assert!(dates.is_empty());
    }

    #[test]
    fn test_parse_releases_page_v_prefix_joins_tag() {
        let json =
            br#"[{"tag_name": "V1.2.3", "published_at": "2026-01-02T08:56:05Z", "draft": false}]"#;
        let dates = parse_releases_page(json).unwrap();
        assert!(dates.contains_key("1.2.3"));
        assert!(!dates.contains_key("V1.2.3"));
    }

    #[test]
    fn test_parse_releases_page_empty_array_is_a_successful_zero_release_page() {
        // A repo with genuinely no releases must parse as `Some(empty)`, not `None`
        // — the caller relies on this to pick the positive TTL, not the error TTL
        // (#223 S3).
        let dates = parse_releases_page(b"[]");
        assert_eq!(dates, Some(HashMap::new()));
    }

    #[test]
    fn test_parse_releases_page_malformed_json_returns_none() {
        assert_eq!(parse_releases_page(b"not json"), None);
    }

    #[test]
    fn test_parse_releases_page_github_error_object_returns_none() {
        let json = br#"{"message":"API rate limit exceeded for 1.2.3.4."}"#;
        assert_eq!(parse_releases_page(json), None);
    }

    #[test]
    fn test_parse_releases_page_duplicate_normalized_keys_first_wins() {
        // GitHub returns releases in `created_at` desc order, so the first entry in
        // the array is the newest; a second release pointing at the same normalized
        // tag must not overwrite it (#223 M2).
        let json = br#"[
            {"tag_name": "v1.0.0", "published_at": "2026-06-01T00:00:00Z", "draft": false},
            {"tag_name": "1.0.0", "published_at": "2025-01-01T00:00:00Z", "draft": false}
        ]"#;
        let dates = parse_releases_page(json).unwrap();
        assert_eq!(dates.len(), 1);
        assert_eq!(
            dates.get("1.0.0").copied(),
            PublishTime::parse_rfc3339("2026-06-01T00:00:00Z")
        );
    }

    // --- classify_release_fetch (the memo's write-side TTL decision, #223 S3) ---

    #[test]
    fn test_classify_release_fetch_success_gets_positive_ttl() {
        let json =
            br#"[{"tag_name": "1.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": false}]"#;
        let (dates, ttl) = classify_release_fetch(Some(Ok(Bytes::from_static(json))));
        assert_eq!(dates.len(), 1);
        assert_eq!(ttl, RELEASE_DATES_TTL);
    }

    #[test]
    fn test_classify_release_fetch_empty_but_valid_page_gets_positive_ttl() {
        let (dates, ttl) = classify_release_fetch(Some(Ok(Bytes::from_static(b"[]"))));
        assert!(dates.is_empty());
        assert_eq!(ttl, RELEASE_DATES_TTL);
    }

    #[test]
    fn test_classify_release_fetch_unparseable_body_gets_error_ttl() {
        let (dates, ttl) = classify_release_fetch(Some(Ok(Bytes::from_static(b"not json"))));
        assert!(dates.is_empty());
        assert_eq!(ttl, RELEASE_DATES_ERROR_TTL);
    }

    #[test]
    fn test_classify_release_fetch_http_error_gets_error_ttl() {
        let (dates, ttl) =
            classify_release_fetch(Some(Err(DepsError::CacheError("boom".to_string()))));
        assert!(dates.is_empty());
        assert_eq!(ttl, RELEASE_DATES_ERROR_TTL);
    }

    #[test]
    fn test_classify_release_fetch_timeout_gets_error_ttl() {
        let (dates, ttl) = classify_release_fetch(None);
        assert!(dates.is_empty());
        assert_eq!(ttl, RELEASE_DATES_ERROR_TTL);
    }

    // --- attach_publish_times ---

    #[test]
    fn test_attach_publish_times_match() {
        let mut versions = vec![SwiftVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
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
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("1.0.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, None);
    }

    // --- evict_if_full ---

    fn entry_at(secs_ago: u64, ttl: Duration) -> ReleaseDatesEntry {
        ReleaseDatesEntry {
            fetched_at: Instant::now()
                .checked_sub(Duration::from_secs(secs_ago))
                .unwrap(),
            dates: Arc::new(HashMap::new()),
            ttl,
        }
    }

    #[test]
    fn test_evict_if_full_noop_under_cap() {
        let map = DashMap::new();
        map.insert("a/a".to_string(), entry_at(0, RELEASE_DATES_TTL));
        evict_if_full(&map);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_evict_if_full_drops_expired_entries_first() {
        let map = DashMap::new();
        for i in 0..MAX_MEMO_ENTRIES {
            // Every entry expired against its own (error) TTL.
            map.insert(
                format!("owner/repo{i}"),
                entry_at(1000, RELEASE_DATES_ERROR_TTL),
            );
        }
        assert_eq!(map.len(), MAX_MEMO_ENTRIES);
        evict_if_full(&map);
        assert!(
            map.is_empty(),
            "all entries were expired and must be dropped"
        );
    }

    #[test]
    fn test_evict_if_full_drops_oldest_when_none_expired() {
        let map = DashMap::new();
        for i in 0..MAX_MEMO_ENTRIES {
            // All alive (well within TTL), but with distinct ages so one is oldest.
            map.insert(
                format!("owner/repo{i}"),
                entry_at(i as u64, RELEASE_DATES_TTL),
            );
        }
        assert_eq!(map.len(), MAX_MEMO_ENTRIES);
        evict_if_full(&map);
        assert_eq!(
            map.len(),
            MAX_MEMO_ENTRIES - 1,
            "exactly one entry (the oldest) must be evicted"
        );
        // The oldest entry (largest secs_ago == MAX_MEMO_ENTRIES - 1) must be gone.
        assert!(!map.contains_key(&format!("owner/repo{}", MAX_MEMO_ENTRIES - 1)));
        // The newest entry must survive.
        assert!(map.contains_key("owner/repo0"));
    }

    // --- release_dates: memo behavior ---

    /// Builds a `SwiftRegistry` with `has_token` pinned to `false`, independent of
    /// the ambient `GITHUB_TOKEN` environment variable (CI runners, e.g. GitHub
    /// Actions, often inject one automatically), so these tests stay deterministic
    /// and never attempt a real network request.
    fn untokened_registry() -> SwiftRegistry {
        SwiftRegistry {
            cache: Arc::new(HttpCache::new()),
            auth_headers: Vec::new(),
            has_token: false,
            release_dates: Arc::new(DashMap::new()),
            enrichment_skip_logged: Arc::new(AtomicBool::new(false)),
            api_base: GITHUB_API.to_string(),
        }
    }

    /// Builds a `SwiftRegistry` pointed at a mock server `base` (typically a
    /// `mockito::Server::url()`) instead of the real GitHub API, for tests driving
    /// `Registry::get_versions_with` end-to-end without a live network call.
    fn mock_registry(base: &str, has_token: bool) -> SwiftRegistry {
        let auth_headers = if has_token {
            vec![(
                reqwest::header::AUTHORIZATION,
                "Bearer test-token".to_string(),
            )]
        } else {
            Vec::new()
        };
        SwiftRegistry {
            cache: Arc::new(HttpCache::new()),
            auth_headers,
            has_token,
            release_dates: Arc::new(DashMap::new()),
            enrichment_skip_logged: Arc::new(AtomicBool::new(false)),
            api_base: base.to_string(),
        }
    }

    #[tokio::test]
    async fn test_release_dates_validate_owner_repo_rejection_issues_zero_requests() {
        let registry = untokened_registry();
        let dates = registry.release_dates("../../etc/passwd").await;
        assert!(dates.is_empty());
        // Nothing stored: a validation failure is cheaper to re-check than to memoize
        // (#223 M6), and this also proves no fetch-and-store path ran.
        assert!(registry.release_dates.is_empty());
    }

    #[tokio::test]
    async fn test_release_dates_positive_ttl_hit_returns_memoized_value_without_refetch() {
        let registry = untokened_registry();
        // has_token is false, so any code path that falls through to a live fetch
        // would both return an *empty* map and log the skip message — this fixture
        // (a non-empty, synthetic dataset a real GitHub call could never produce)
        // is only observable if the positive-TTL memo-hit branch returned early.
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        registry.release_dates.insert(
            "owner/repo".to_string(),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::from([("9.9.9".to_string(), published)])),
                ttl: RELEASE_DATES_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = registry.release_dates("owner/repo").await;
            assert_eq!(dates.get("9.9.9").copied(), Some(published));
        })
        .await;
        assert!(
            output.is_empty(),
            "memo hit must not log the token-gate skip: {output}"
        );
    }

    #[tokio::test]
    async fn test_release_dates_empty_but_successful_fetch_retained_under_positive_ttl() {
        let registry = untokened_registry();
        // An empty dates map stored under the *positive* TTL (simulating a repo with
        // genuinely no releases) must be trusted as-is, not treated as if it had
        // failed and needed a retry within the (much shorter) error TTL.
        registry.release_dates.insert(
            "owner/repo".to_string(),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = registry.release_dates("owner/repo").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.is_empty(),
            "an empty-but-successful entry within its positive TTL must not refetch: {output}"
        );
    }

    #[tokio::test]
    async fn test_release_dates_unexpired_error_ttl_entry_is_memo_hit() {
        let registry = untokened_registry();
        // A failure recorded under the (short) error TTL, 60s ago, is still within
        // that 90s window: it must be honored as a memo hit, not treated as expired.
        registry.release_dates.insert(
            "owner/repo".to_string(),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_ERROR_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = registry.release_dates("owner/repo").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.is_empty(),
            "an unexpired error-TTL entry must not refetch: {output}"
        );
    }

    #[tokio::test]
    async fn test_release_dates_expired_error_ttl_entry_falls_through_to_token_gate() {
        let registry = untokened_registry();
        // 100s ago exceeds RELEASE_DATES_ERROR_TTL (90s): the entry must be treated
        // as expired and a refetch attempted. `has_token` is false, so the refetch
        // resolves locally (no network) via the token-gate skip, which logs.
        registry.release_dates.insert(
            "owner/repo".to_string(),
            ReleaseDatesEntry {
                fetched_at: Instant::now()
                    .checked_sub(Duration::from_secs(100))
                    .unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_ERROR_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = registry.release_dates("owner/repo").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.contains("GITHUB_TOKEN not set"),
            "expiry must trigger a refetch attempt: {output}"
        );
    }

    #[tokio::test]
    async fn test_release_dates_token_gate_skip_logs_once_per_registry() {
        let registry = untokened_registry();

        let output = capture_tracing_output_async(async {
            let _ = registry.release_dates("owner/repo-a").await;
            let _ = registry.release_dates("owner/repo-b").await;
        })
        .await;

        assert_eq!(
            output.matches("GITHUB_TOKEN not set").count(),
            1,
            "the skip message must fire at most once per process: {output}"
        );
    }

    #[test]
    fn test_error_ttl_is_shorter_than_positive_ttl() {
        assert!(RELEASE_DATES_ERROR_TTL < RELEASE_DATES_TTL);
    }

    // --- Registry::get_versions_with: freshness.enabled gate (M2) ---

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
        let freshness = FreshnessSettings {
            enabled: false,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

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
        let freshness = FreshnessSettings {
            enabled: true,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_some()));
    }
}
