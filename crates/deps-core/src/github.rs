//! Shared GitHub tags-API client, used by every ecosystem that resolves package versions
//! from GitHub repository tags rather than a dedicated package registry (`deps-swift`,
//! `deps-github-actions`).
//!
//! Each ecosystem crate layers its own extras on top of [`GithubTagsClient`] —
//! `deps-swift` adds GitHub Releases publish-date enrichment, `deps-github-actions` adds a
//! rate-limit cooldown gate, in-flight request coalescing, and a tag<->SHA cross-reference.
//! Only the pieces that were byte-for-byte identical between the two — constants,
//! owner/repo validation, auth-header setup, the tags-pagination loop, and page parsing —
//! live here, so the two crates cannot silently diverge on this shared behavior (#472).

use crate::error::{DepsError, Result};
use crate::freshness::PublishTime;
use crate::lsp_helpers::{is_dot_segment, warn_rejected_value};
use bytes::Bytes;
use dashmap::DashMap;
use reqwest::header::{AUTHORIZATION, HeaderName};
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::cache::HttpCache;

/// Base URL for the GitHub REST API.
pub const GITHUB_API: &str = "https://api.github.com";

/// Maximum number of `tags` pages fetched per repository (100 tags/page).
///
/// This is a **safety ceiling, not the correctness mechanism** — the loop already stops as
/// soon as a page comes back with fewer than 100 entries ([`page_has_more`]), which is
/// GitHub's documented signal that no further page exists. Every real repository
/// terminates via that signal well before this bound is reached.
///
/// The bound exists only to protect against a pathological repo with an unbounded number
/// of tags. It must stay high enough that it never truncates a real repository's tag
/// list, because GitHub returns tags in **lexicographic, not semver, order** — verified
/// live on `firebase/firebase-ios-sdk` (1131 tags): page 1 is headed by `v8.15.0` (a
/// `v`-prefixed tag lexicographically outranks unprefixed ones), pages 2-9 are entirely
/// unrelated subproject tags with zero semver-parseable entries, and the real
/// `11.x`/`12.x` releases only appear around pages 10-11. A low page cap silently drops
/// those newer tags out of the result entirely — no amount of sorting the *fetched*
/// subset fixes that, since the highest real versions were never fetched at all.
pub const MAX_TAG_PAGES: u32 = 30;

/// Number of tag pages [`paginate_tags`] fetches concurrently per batch.
///
/// Sequential pagination (one page RTT at a time) is what made a many-tag repo (e.g. 1327
/// tags / 14 pages) exceed `deps-lsp`'s per-dependency fetch timeout (#553). 5 keeps
/// wall-clock time comfortably under that timeout while staying low enough to avoid
/// tripping GitHub's secondary (abuse) rate limiter, which reacts to burst concurrency
/// independent of the hourly quota. Total request count is unchanged for the common
/// single-page-repo case; for multi-page repos it may grow by up to `CONCURRENCY - 1` pages
/// (see [`paginate_tags`]'s doc comment). Negligible against the 5000/h *tokened* quota; a
/// multi-page repo fetched *without* a `GITHUB_TOKEN` can cost up to 3x its pre-fix request
/// count against the much smaller 60/h unauthenticated quota.
///
/// Known limitation: there is no process-wide cap on concurrent GitHub requests across
/// dependencies — a workspace with many GitHub-tags-backed dependencies fetched at once can
/// multiply this per-dependency concurrency well past `CONCURRENCY`. Evaluated and shipped
/// as-is (see PR discussion); add a shared `Semaphore` in `GithubTagsClient` if this is ever
/// observed as a real problem.
const CONCURRENCY: usize = 5;

/// Whether `name` matches the `owner/repo` GitHub identifier shape every GitHub-tags-backed
/// ecosystem accepts.
///
/// Accepts `[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`, with neither segment being exactly `.`/`..`
/// (see [`is_dot_segment`]).
///
/// Shared by each ecosystem's `registry::validate_owner_repo` (a credential-bearing
/// fetch-URL gate) and its formatter's display-URL gate, so the two predicates cannot drift
/// out of sync on what counts as a valid identity.
///
/// # Examples
///
/// ```
/// use deps_core::github::is_valid_github_identity;
///
/// assert!(is_valid_github_identity("actions/checkout"));
/// assert!(!is_valid_github_identity("not-a-valid-identifier"));
/// assert!(!is_valid_github_identity("owner/.."));
/// ```
#[must_use]
pub fn is_valid_github_identity(name: &str) -> bool {
    let Some((owner, repo)) = name.split_once('/') else {
        return false;
    };
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return false;
    }
    let charset_ok = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    charset_ok(owner) && charset_ok(repo) && !is_dot_segment(owner) && !is_dot_segment(repo)
}

/// Validates that `name` is a valid `owner/repo` GitHub identifier before it reaches a
/// `{api_base}/repos/{name}/...` fetch as a bare path segment.
///
/// The charset regex alone allows `.`, so a repo half of exactly `..` would otherwise
/// retarget the request one path segment up (`{api_base}/repos/{owner}/../releases` ->
/// `{api_base}/repos/releases`, #357) — [`is_valid_github_identity`] closes that gap via
/// [`is_dot_segment`].
///
/// # Errors
///
/// Returns [`DepsError::InvalidUri`] when `name` is not a valid `owner/repo` identifier.
pub fn validate_owner_repo(name: &str) -> Result<()> {
    if is_valid_github_identity(name) {
        return Ok(());
    }
    if let Some((owner, repo)) = name.split_once('/')
        && (is_dot_segment(owner) || is_dot_segment(repo))
    {
        warn_rejected_value("is_dot_segment", "GitHub owner/repo request URL", name);
    }
    Err(DepsError::InvalidUri(format!(
        "invalid owner/repo format: '{name}'"
    )))
}

/// The actionable error returned when a request hits GitHub's unauthenticated rate limit
/// (60 req/h per IP, vs 5000 req/h with a token).
#[must_use]
pub fn github_rate_limit_error() -> DepsError {
    DepsError::RateLimited {
        message: "GitHub API rate limit exceeded. Set GITHUB_TOKEN to increase the limit \
                   (5000 req/h). Run: export GITHUB_TOKEN=$(gh auth token)"
            .into(),
    }
}

/// A `GITHUB_TOKEN` bearer-header value, redacted everywhere except the one call site
/// ([`GithubTagsClient::headers`]) that hands it to a request as a header value.
///
/// `Debug`/`Display` are hand-implemented to redact the value so it cannot leak via a log
/// line, a panic message, or a future `#[derive(Debug)]` added to [`GithubTagsClient`] or a
/// struct embedding it — mirrors `deps_cargo::config::AuthToken`.
#[derive(Clone, PartialEq, Eq)]
struct AuthToken(String);

impl AuthToken {
    /// The raw header value, for attaching to a request. Never logged, printed, or
    /// otherwise surfaced — callers must not pass this to anything but a header value.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(***)")
    }
}

impl std::fmt::Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Shared cache, auth-header, and API-base state for a GitHub-tags-backed registry client.
///
/// Callers embed this alongside their own ecosystem-specific state (caches, coalescing
/// locks, cross-reference indexes) rather than re-deriving token/header handling
/// themselves.
#[derive(Clone)]
pub struct GithubTagsClient {
    cache: Arc<HttpCache>,
    auth_headers: Vec<(HeaderName, AuthToken)>,
    has_token: bool,
    api_base: String,
    /// `{api_base}/`, precomputed once so [`Self::fetch_authenticated`] never re-`format!`s
    /// it per request; the trailing slash is load-bearing (see that method's docs).
    trusted_origin: String,
}

impl GithubTagsClient {
    /// Creates a new client backed by `cache`.
    ///
    /// Reads `GITHUB_TOKEN` from the environment for authenticated requests (5000 req/h vs
    /// 60 req/h unauthenticated).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::HttpCache;
    /// use deps_core::github::GithubTagsClient;
    /// use std::sync::Arc;
    ///
    /// let client = GithubTagsClient::new(Arc::new(HttpCache::new()));
    /// assert_eq!(client.api_base(), deps_core::github::GITHUB_API);
    /// ```
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        let has_token = token.is_some();
        let auth_headers = token
            .map(|token| {
                tracing::info!("GITHUB_TOKEN detected, using authenticated GitHub API requests");
                vec![(AUTHORIZATION, AuthToken(format!("Bearer {token}")))]
            })
            .unwrap_or_default();

        Self {
            cache,
            auth_headers,
            has_token,
            trusted_origin: format!("{GITHUB_API}/"),
            api_base: GITHUB_API.to_string(),
        }
    }

    /// Creates a client with `has_token`/`api_base` set directly, bypassing the
    /// environment.
    ///
    /// For `mockito`-backed tests that need deterministic behavior regardless of the
    /// ambient `GITHUB_TOKEN` (CI runners often inject one automatically) and a
    /// request URL pointed at a mock server instead of the real GitHub API.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(cache: Arc<HttpCache>, api_base: impl Into<String>, has_token: bool) -> Self {
        let auth_headers = if has_token {
            vec![(AUTHORIZATION, AuthToken("Bearer test-token".to_string()))]
        } else {
            Vec::new()
        };
        let api_base = api_base.into();
        Self {
            cache,
            auth_headers,
            has_token,
            trusted_origin: format!("{api_base}/"),
            api_base,
        }
    }

    /// Whether a `GITHUB_TOKEN` was present at construction.
    #[must_use]
    pub const fn has_token(&self) -> bool {
        self.has_token
    }

    /// The API base URL requests are built against (`GITHUB_API` in production, or a
    /// mock server URL in tests).
    #[must_use]
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// Borrowed auth-header pairs to send on each request; empty when no token is set.
    ///
    /// `pub(crate)` rather than `pub`: this is the one place [`AuthToken`]'s redaction
    /// boundary is crossed back into a plain `&str`, so it must not hand the raw token to
    /// another crate. Ecosystem crates needing an authenticated GitHub request go through
    /// [`Self::fetch_authenticated`] instead, which applies these headers internally.
    #[must_use]
    pub(crate) fn headers(&self) -> Vec<(HeaderName, &str)> {
        self.auth_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str()))
            .collect()
    }

    /// The shared HTTP cache this client fetches through.
    ///
    /// Exposed for ecosystem-specific endpoints beyond the tags API that don't carry a
    /// credential (e.g. parsing a response this client already fetched) — anything that
    /// needs this client's `Authorization` header should go through
    /// [`GithubTagsClient::fetch_authenticated`] instead of rebuilding the header list here.
    #[must_use]
    pub const fn cache(&self) -> &Arc<HttpCache> {
        &self.cache
    }

    /// Fetches `url` with this client's auth headers, pinning every redirect hop to
    /// [`Self::api_base`].
    ///
    /// The single entry point for an authenticated request against the GitHub API: every
    /// caller needing this client's `Authorization` header — the tags API
    /// ([`Self::fetch_tags_page`]), `deps-swift`'s release-dates and search endpoints —
    /// goes through here rather than combining [`Self::cache`] and `headers()`
    /// itself, so the origin pin can't be forgotten at a new call site.
    ///
    /// Fetches through [`HttpCache::get_cached_trusted_origin_with_headers`] rather than
    /// [`HttpCache::get_cached_with_headers`], pinning every redirect hop to `api_base` so
    /// the `Authorization` header can never follow a cross-origin redirect off the GitHub
    /// API — defense-in-depth alongside reqwest's own default header-stripping on
    /// cross-origin redirects.
    ///
    /// `url` must itself be under `api_base` — this only pins *redirects*, not the initial
    /// request, so a caller building `url` from a different base (e.g. a hardcoded
    /// production constant instead of [`Self::api_base`]) both escapes the pin and, in
    /// tests, silently bypasses the mock server this client was built with.
    ///
    /// # Errors
    ///
    /// Propagates the underlying HTTP/cache error unchanged.
    pub async fn fetch_authenticated(&self, url: &str) -> Result<Bytes> {
        self.cache
            .get_cached_trusted_origin_with_headers(url, &self.trusted_origin, &self.headers())
            .await
    }

    /// Fetches one page of the GitHub tags API for `name` (`owner/repo`), authenticated
    /// with this client's headers.
    ///
    /// Centralizes the `{api_base}/repos/{name}/tags?per_page=100&page={page}` URL so
    /// callers never re-derive it (#472 critic S2) — every caller still supplies its own
    /// error mapping (rate-limit/not-found translation) via `map_err` on the result.
    ///
    /// # Errors
    ///
    /// Propagates the underlying HTTP/cache error unchanged.
    pub async fn fetch_tags_page(&self, name: &str, page: u32) -> Result<Bytes> {
        let url = format!(
            "{}/repos/{name}/tags?per_page=100&page={page}",
            self.api_base
        );
        self.fetch_authenticated(&url).await
    }
}

/// GitHub tags API response item.
#[derive(Debug, Default, Deserialize)]
pub struct GithubTag {
    pub name: String,
    /// The tagged commit. Defaults when the field is absent so fixtures that omit it (or
    /// omit `commit.sha` within it) still deserialize — callers that need the SHA (e.g.
    /// `deps-github-actions`, for SHA-pin resolution) validate it themselves.
    #[serde(default)]
    pub commit: GithubTagCommit,
}

/// The `commit` object nested in a [`GithubTag`].
#[derive(Debug, Default, Deserialize)]
pub struct GithubTagCommit {
    #[serde(default)]
    pub sha: String,
}

/// GitHub API error response (rate limit, not found, etc.).
#[derive(Deserialize)]
struct GithubErrorResponse {
    message: String,
}

/// Returns `true` when a fetched page came back full (`per_page=100` entries), meaning a
/// subsequent page may exist and should be fetched too. A page with fewer entries is
/// necessarily the last one.
#[must_use]
pub const fn page_has_more(page_len: usize) -> bool {
    page_len >= 100
}

/// Logs a warning when tag pagination for `name` stops at [`MAX_TAG_PAGES`] while GitHub
/// still had more pages available (`page_has_more(page_len)`).
///
/// Without this, hitting the safety ceiling on a pathological repo is indistinguishable in
/// logs from "the repo genuinely has no matching version" — this makes truncation
/// diagnosable. `ecosystem` names the caller (e.g. `"Swift"`, `"GitHub Actions"`) in the
/// warning text.
pub fn warn_if_pagination_truncated(ecosystem: &str, name: &str, page: u32, page_len: usize) {
    if page == MAX_TAG_PAGES && page_has_more(page_len) {
        tracing::warn!(
            package = name,
            pages_fetched = MAX_TAG_PAGES,
            "{ecosystem} tags pagination for '{name}' stopped at the {MAX_TAG_PAGES}-page cap \
             while GitHub reported more pages available; the fetched version list may be \
             truncated"
        );
    }
}

/// Drives the GitHub tags pagination loop: page 1 alone, then subsequent pages in batches
/// of up to `CONCURRENCY` pages.
///
/// Page 1 is always fetched by itself before any batching starts, for two reasons: most
/// repos fit in one page, so this keeps the common case at exactly the one request it took
/// before this function gained concurrency; and an error on page 1 (bad auth, tripped rate
/// limit, unknown repo) is now surfaced from a single request instead of fanning a doomed
/// request out to `CONCURRENCY` pages at once.
///
/// Once page 1 is confirmed full, pages 2+ are fetched in batches of `CONCURRENCY`,
/// stopping once a partial/empty page is seen or [`MAX_TAG_PAGES`] is reached. Pages within
/// a batch are fetched concurrently, but always processed in page order — the pages
/// dispatched *after* the batch's partial page are simply discarded once found, not
/// avoided, since by the time a batch's first result comes back the rest of that batch's
/// requests are already in flight and cannot be un-sent. This bounds, but does not
/// eliminate, extra requests: at most `CONCURRENCY - 1` pages beyond a repo's true last page
/// may be fetched and discarded, only when that last page doesn't land on a batch boundary.
/// `deps-github-actions`'s tag-to-SHA index dedups "first tag wins" on page order, so
/// out-of-order processing (not just fetching) would change which tag is picked as
/// canonical for a shared SHA — hence ordered `buffered`, not `buffer_unordered`.
///
/// `ecosystem` is forwarded to [`warn_if_pagination_truncated`] to name the caller in the
/// truncation warning. Extracted so ecosystem crates' tests can inject a fake `fetch_page`
/// and exercise the real loop — including that warning's call site — without a live
/// GitHub API.
///
/// # Errors
///
/// Propagates the first error seen among `fetch_page`'s results (page 1's own error, or the
/// first in page order within a batch — any other in-flight futures in that batch are
/// dropped), or the error from [`parse_tags_page`] when a page's body is a GitHub error
/// object.
pub async fn paginate_tags<F, Fut>(
    ecosystem: &str,
    name: &str,
    mut fetch_page: F,
) -> Result<Vec<GithubTag>>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<Bytes>>,
{
    use futures::stream::{self, StreamExt};

    let mut tags = Vec::new();

    let first_page = fetch_page(1).await?;
    let first_tags = parse_tags_page(&first_page)?;
    let first_page_len = first_tags.len();
    tags.extend(first_tags);
    if !page_has_more(first_page_len) {
        // No call to `warn_if_pagination_truncated` here: it only fires at
        // `page == MAX_TAG_PAGES`, which page 1 can never equal since `MAX_TAG_PAGES > 1`.
        return Ok(tags);
    }

    let mut page = 2u32;
    'batches: while page <= MAX_TAG_PAGES {
        let batch_end = (page + CONCURRENCY as u32 - 1).min(MAX_TAG_PAGES);
        let mut stream = stream::iter(page..=batch_end)
            .map(&mut fetch_page)
            .buffered(CONCURRENCY);

        let mut current_page = page;
        while let Some(data) = stream.next().await {
            let page_tags = parse_tags_page(&data?)?;
            let page_len = page_tags.len();
            tags.extend(page_tags);
            if !page_has_more(page_len) {
                break 'batches;
            }
            warn_if_pagination_truncated(ecosystem, name, current_page, page_len);
            current_page += 1;
        }
        page = batch_end + 1;
    }
    Ok(tags)
}

/// Parses a single GitHub tags API response page into raw tag entries.
///
/// GitHub returns an error object instead of an array when rate-limited or on other
/// errors. Detect this and return a descriptive error; a body that is neither a tags array
/// nor a recognizable error object is treated as an empty page.
///
/// # Errors
///
/// Returns [`DepsError::CacheError`] when `data` parses as a GitHub error object.
pub fn parse_tags_page(data: &[u8]) -> Result<Vec<GithubTag>> {
    match crate::parser::parse_json_checked(data) {
        Ok(tags) => Ok(tags),
        Err(_) => {
            if let Ok(err) = crate::parser::parse_json_checked::<GithubErrorResponse>(data) {
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

/// Strips a leading `v`/`V` tag prefix.
///
/// Shared by every ecosystem that joins a GitHub Release's `tag_name` against a
/// tags-API-derived version — a divergent strip between the two would silently drop a
/// release's publish date for the affected tag (#223). Both cases are real GitHub tag
/// conventions (`v2.62.0`, `V2.62.0`); stripping only lowercase `v` would leave `V2.62.0`
/// unparseable as semver, silently dropping a real, installable tag.
///
/// # Examples
///
/// ```
/// use deps_core::github::normalize_tag;
///
/// assert_eq!(normalize_tag("v1.2.3"), "1.2.3");
/// assert_eq!(normalize_tag("V1.2.3"), "1.2.3");
/// assert_eq!(normalize_tag("1.2.3"), "1.2.3");
/// ```
#[must_use]
pub fn normalize_tag(name: &str) -> &str {
    name.strip_prefix(['v', 'V']).unwrap_or(name)
}

/// TTL for a successful `/releases` memo entry (§3.1 of #223's plan). Chosen so a newly
/// published release surfaces within a coffee break while keeping the per-package cost at 4
/// requests/hour worst case.
const RELEASE_DATES_TTL: Duration = Duration::from_mins(15);

/// TTL for a memo entry recording a *failed* `/releases` fetch (network error, rate limit,
/// unparseable body). Deliberately distinct and much shorter than [`RELEASE_DATES_TTL`]:
/// caching a failure for the full positive TTL would black out a package's dates for 15
/// minutes after one transient error, while not caching it at all would let a rate-limit
/// storm or a non-GitHub identity re-fire the request on every keystroke (#223 M5).
const RELEASE_DATES_ERROR_TTL: Duration = Duration::from_secs(90);

/// Per-request timeout for the `/releases` fetch inside [`ReleaseDatesCache::fetch`].
///
/// `fetch` is meant to run concurrently with a tags fetch under `tokio::join!`, which
/// otherwise has no timeout of its own beyond [`HttpCache`]'s generic client timeout — a
/// slow or hanging release-dates response must not hold up hover/completion or eat into
/// their latency budget. Elapsing this timeout is treated the same as any other fetch
/// failure: an empty map, memoized under [`RELEASE_DATES_ERROR_TTL`], never propagated.
const RELEASE_DATES_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of packages held in a [`ReleaseDatesCache`] at once. Comfortably above the
/// distinct-package count of any realistic workspace while bounding the memo at a few
/// hundred KB (#223 M7).
const MAX_RELEASE_DATES_MEMO_ENTRIES: usize = 256;

/// One memoized `/releases` lookup for a single package.
///
/// A release's publish time is immutable once published, so a stale entry can only ever
/// *lack* a very recent release — never report a wrong date. The TTL therefore governs how
/// quickly a brand-new release acquires a date, not correctness.
struct ReleaseDatesEntry {
    fetched_at: Instant,
    dates: Arc<HashMap<String, PublishTime>>,
    /// TTL for *this* entry — [`RELEASE_DATES_TTL`] on success, the much shorter
    /// [`RELEASE_DATES_ERROR_TTL`] on failure. Carried per entry rather than derived at read
    /// time so one expiry check covers both outcomes, and an empty-but-successful fetch (a
    /// repo with genuinely no releases) is never mistaken for a failure (#223 M5).
    ttl: Duration,
}

/// Evicts entries from `map` when it is already at [`MAX_RELEASE_DATES_MEMO_ENTRIES`], ahead
/// of an insert that would otherwise grow it further: first every entry expired against its
/// own `ttl`, then — only if that freed nothing — the single oldest entry by `fetched_at`.
/// The O(n) scan runs only on an insert that finds the map full (#223 M7).
fn evict_release_dates_if_full(map: &DashMap<String, ReleaseDatesEntry>) {
    if map.len() < MAX_RELEASE_DATES_MEMO_ENTRIES {
        return;
    }
    let now = Instant::now();
    map.retain(|_, entry| now.duration_since(entry.fetched_at) < entry.ttl);
    if map.len() >= MAX_RELEASE_DATES_MEMO_ENTRIES
        && let Some(oldest) = map
            .iter()
            .min_by_key(|e| e.fetched_at)
            .map(|e| e.key().clone())
    {
        map.remove(&oldest);
    }
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
/// Returns `None` for malformed JSON, an unexpected shape, or a GitHub error object — a
/// genuine *parse failure*, distinct from `Some(HashMap::new())`, which means the page
/// parsed successfully and the repo simply has no (non-draft, dated) releases. The caller
/// relies on this distinction to memoize a parse failure under the short
/// [`RELEASE_DATES_ERROR_TTL`] rather than the positive [`RELEASE_DATES_TTL`] (#223 S3) —
/// release dates are still strictly best-effort overall, since neither case ever propagates
/// an error out of [`ReleaseDatesCache::fetch`]. Skips draft releases and releases with no
/// `published_at`; a prerelease is deliberately *kept* — it is still a real, dated release
/// and its tag should still get a publish date. GitHub returns releases in `created_at`
/// descending order, so `entry(..).or_insert(..)` keeps the *first* (newest) release seen
/// for a given normalized tag — the deterministic collision policy for the rare case of two
/// releases pointing at the same tag (#223 M2).
fn parse_releases_page(data: &[u8]) -> Option<HashMap<String, PublishTime>> {
    let releases: Vec<GithubRelease> = crate::parser::parse_json_checked(data).ok()?;
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
/// `tokio::time::timeout::Elapsed` collapsed via `.ok()` at the call site, since it carries
/// no useful data of its own). Every failure path — timeout, HTTP/network error, or a
/// response that parses as JSON but isn't a valid `/releases` page — gets the short
/// [`RELEASE_DATES_ERROR_TTL`]; only a successfully parsed page (which may itself be an
/// empty map, for a repo with no releases) gets the positive [`RELEASE_DATES_TTL`] (#223
/// S3). Extracted as a pure function so the TTL decision itself — not just the memo's
/// read-side retention behavior — is directly unit-testable without a live fetch or a real
/// `Elapsed`.
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

/// Memoized, best-effort GitHub Releases publish-date cache.
///
/// Shared by every ecosystem that resolves package versions from GitHub tags but wants to
/// enrich them with a release's `published_at` (`deps-swift`, `deps-github-actions`).
/// Fetching `/releases` is a *second*, separate request from the tags fetch that produces
/// the version list itself — [`Self::fetch`] is meant to run concurrently with that tags
/// fetch (e.g. via `tokio::join!`) and is infallible by construction, so it can never
/// perturb the tags fetch's error propagation. A caller joins the returned map onto its own
/// already-fetched, ecosystem-specific version list by [`normalize_tag`]ing each version's
/// tag text (#223).
///
/// One cache may safely be shared across [`Self::fetch`] calls passing different
/// [`GithubTagsClient`]s (e.g. a caller that swaps in a mock client under test): entries are
/// keyed on `(client.api_base(), name)`, not `name` alone, so a hit fetched via one origin's
/// client can never serve a read for another origin (#486 critic M1).
#[derive(Default)]
pub struct ReleaseDatesCache {
    dates: DashMap<String, ReleaseDatesEntry>,
    /// Set once the first skipped release-date enrichment (no `GITHUB_TOKEN`) has been
    /// logged, so the informational message fires at most once per cache instance rather
    /// than once per hover/completion/document-open (#223). A process running more than
    /// one cache (e.g. `deps-swift` and `deps-github-actions` each own one) logs it once
    /// per cache, not once globally.
    enrichment_skip_logged: AtomicBool,
}

impl ReleaseDatesCache {
    /// Creates an empty cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::github::ReleaseDatesCache;
    ///
    /// let _cache = ReleaseDatesCache::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetches the newest ~100 GitHub Releases for `name` (`owner/repo`) via `github`, and
    /// returns a normalized-tag -> publish-time map, memoized behind a per-package TTL.
    ///
    /// Best-effort by construction (#223): a malformed identity or a validation failure
    /// returns an empty map with **zero requests**; a missing `GITHUB_TOKEN` returns an
    /// empty map (logged once per cache instance, naming `ecosystem`) with zero requests; any
    /// live-fetch error (network, rate limit, unparseable body, or exceeding the fetch
    /// timeout) returns an empty map, memoized under the short error TTL rather than the
    /// positive success TTL. Never propagates an error — a caller running this under
    /// `tokio::join!` alongside a tags fetch must not have that fetch perturbed by a
    /// release-dates failure.
    ///
    /// Runs its own [`validate_owner_repo`] guard, independent of any validation the tags
    /// fetch performs: under a `tokio::join!` that guard may not run first, and this method
    /// interpolates `name` into an `api.github.com` path of its own (#223 M6).
    ///
    /// # Examples
    ///
    /// A malformed identity is rejected before any request is built — deterministic and
    /// network-free, so it doubles as a runnable example:
    ///
    /// ```
    /// use deps_core::HttpCache;
    /// use deps_core::github::{GithubTagsClient, ReleaseDatesCache};
    /// use std::sync::Arc;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = ReleaseDatesCache::new();
    /// let github = GithubTagsClient::new(Arc::new(HttpCache::new()));
    /// let dates = cache.fetch(&github, "not-a-valid-owner-repo", "Example").await;
    /// assert!(dates.is_empty());
    /// # }
    /// ```
    pub async fn fetch(
        &self,
        github: &GithubTagsClient,
        name: &str,
        ecosystem: &'static str,
    ) -> Arc<HashMap<String, PublishTime>> {
        if validate_owner_repo(name).is_err() {
            return Arc::new(HashMap::new());
        }

        // Keyed on `(api_base, name)`, not `name` alone: `fetch` takes an arbitrary
        // `GithubTagsClient` per call, so one cache shared across clients pointed at
        // different origins (a mock server beside the real API, or a future GitHub
        // Enterprise base) must not let a hit fetched via one origin's client serve
        // another's read (#486 critic M1). `\0` cannot occur in either half:
        // `validate_owner_repo` already rejected `name`, and a URL cannot carry a raw
        // NUL byte.
        let key = format!("{}\0{name}", github.api_base());

        let now = Instant::now();
        if let Some(entry) = self.dates.get(&key)
            && now.duration_since(entry.fetched_at) < entry.ttl
        {
            return Arc::clone(&entry.dates);
        }

        if !github.has_token() {
            if !self.enrichment_skip_logged.swap(true, Ordering::Relaxed) {
                tracing::info!(
                    "GITHUB_TOKEN not set — {ecosystem} release dates are unavailable; hover \
                     and completion will omit publish ages. Run: export GITHUB_TOKEN=$(gh auth token)"
                );
            }
            return Arc::new(HashMap::new());
        }

        let url = format!("{}/repos/{name}/releases?per_page=100", github.api_base());
        let fetch_result = tokio::time::timeout(
            RELEASE_DATES_FETCH_TIMEOUT,
            github.fetch_authenticated(&url),
        )
        .await;
        match &fetch_result {
            Ok(Err(e)) => tracing::debug!(package = name, error = %e, "release dates fetch failed"),
            Err(_) => tracing::debug!(package = name, "release dates fetch timed out"),
            Ok(Ok(_)) => {}
        }
        let (dates, ttl) = classify_release_fetch(fetch_result.ok());
        let dates = Arc::new(dates);

        // Refreshing an already-present key (the common case: this package's own entry just
        // expired) doesn't grow the map, so evicting ahead of it would drop an unrelated
        // live entry for no reason.
        if !self.dates.contains_key(&key) {
            evict_release_dates_if_full(&self.dates);
        }
        self.dates.insert(
            key,
            ReleaseDatesEntry {
                fetched_at: now,
                dates: Arc::clone(&dates),
                ttl,
            },
        );
        dates
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{capture_tracing_output, capture_tracing_output_async};

    // --- is_valid_github_identity / validate_owner_repo ---

    #[test]
    fn test_is_valid_github_identity_accepts_owner_repo() {
        assert!(is_valid_github_identity("actions/checkout"));
        assert!(is_valid_github_identity("org.name/repo_name-v2"));
    }

    #[test]
    fn test_is_valid_github_identity_rejects_malformed() {
        assert!(!is_valid_github_identity("no-slash"));
        assert!(!is_valid_github_identity(""));
        assert!(!is_valid_github_identity("owner/repo/extra"));
        assert!(!is_valid_github_identity("owner/ repo"));
        assert!(!is_valid_github_identity("../../etc/passwd"));
    }

    #[test]
    fn test_is_valid_github_identity_rejects_dot_segment() {
        assert!(!is_valid_github_identity("owner/.."));
        assert!(!is_valid_github_identity("owner/."));
        assert!(!is_valid_github_identity("../repo"));
        assert!(!is_valid_github_identity("./repo"));
    }

    #[test]
    fn test_validate_owner_repo_invalid_format_message() {
        let err = validate_owner_repo("no-slash").unwrap_err();
        assert!(err.to_string().contains("invalid owner/repo format"));
    }

    #[test]
    fn test_validate_owner_repo_valid() {
        assert!(validate_owner_repo("apple/swift-nio").is_ok());
        assert!(validate_owner_repo("actions/checkout").is_ok());
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

    #[test]
    fn test_validate_owner_repo_rejects_dot_segment_repo() {
        // Regression for #357: the charset regex alone allows `.`, so a repo half of
        // exactly `..` previously passed — retargeting the request one path segment up.
        assert!(validate_owner_repo("owner/..").is_err());
        assert!(validate_owner_repo("owner/.").is_err());
    }

    #[test]
    fn test_validate_owner_repo_rejects_dot_segment_owner() {
        assert!(validate_owner_repo("../repo").is_err());
        assert!(validate_owner_repo("./repo").is_err());
    }

    // --- page_has_more / warn_if_pagination_truncated ---

    #[test]
    fn test_page_has_more_full_page_continues() {
        assert!(page_has_more(100));
    }

    #[test]
    fn test_page_has_more_partial_page_stops() {
        assert!(!page_has_more(99));
        assert!(!page_has_more(0));
    }

    #[test]
    fn test_pagination_warns_when_truncated_at_cap() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("Swift", "owner/repo", MAX_TAG_PAGES, 100);
        });
        assert!(output.contains("owner/repo"), "output was: {output}");
        assert!(output.contains("Swift"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
    }

    #[test]
    fn test_pagination_silent_when_under_cap() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("Swift", "owner/repo", MAX_TAG_PAGES - 1, 100);
        });
        assert!(output.is_empty(), "output was: {output}");
    }

    #[test]
    fn test_pagination_silent_when_last_page_at_cap_is_partial() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("Swift", "owner/repo", MAX_TAG_PAGES, 42);
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

    #[tokio::test]
    async fn test_paginate_tags_single_page_repo_fetches_exactly_once() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let result = paginate_tags("Swift", "owner/repo", |page| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                match page {
                    1 => Ok(tags_page_json(42)),
                    _ => panic!("page {page} must not be fetched: page 1 is fetched alone and is already partial"),
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the common single-page-repo case must not pay for batching"
        );
        assert_eq!(result.len(), 42);
    }

    #[tokio::test]
    async fn test_paginate_tags_stops_after_partial_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // Page 2 is the partial (true last) page, but it falls inside the first batch
        // dispatched after page 1 (pages 2-6, CONCURRENCY=5): by the time page 2's short
        // response is processed, pages 3-6 are already in flight and get fetched too, then
        // discarded. This is the documented, bounded overfetch tradeoff of batched
        // concurrency (see `paginate_tags`'s doc comment) — page 7+ is a separate batch that
        // must never be dispatched.
        let calls = AtomicU32::new(0);
        let mut tags = Vec::new();
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("Swift", "owner/repo", |page| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    match page {
                        1 => Ok(tags_page_json(100)),
                        2 => Ok(tags_page_json(42)),
                        3..=6 => Ok(tags_page_json(0)),
                        _ => panic!(
                            "page {page} must not be fetched outside the batch containing the partial page"
                        ),
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
            6,
            "page 1 fetched alone, then the whole batch containing partial page 2 (2-6)"
        );
        assert_eq!(
            tags.len(),
            142,
            "only tags through the true last page (2) are kept, despite pages 3-6 being fetched"
        );
        assert!(
            output.is_empty(),
            "must not warn below the page cap: {output}"
        );
    }

    #[tokio::test]
    async fn test_paginate_tags_preserves_page_order_despite_inverted_completion() {
        /// Builds a JSON tags page with `count` entries named `{prefix}-{i}`, so the
        /// origin page of each output tag is identifiable.
        fn named_page(prefix: &str, count: usize) -> Bytes {
            let entries: Vec<String> = (0..count)
                .map(|i| format!(r#"{{"name":"{prefix}-{i}"}}"#))
                .collect();
            Bytes::from(format!("[{}]", entries.join(",")))
        }

        // Pages 2-5 (one batch's full pages) resolve slowest-first (page 2 waits longest,
        // page 5 barely waits); page 6 (the partial page ending the batch) resolves
        // instantly. If `paginate_tags` used `buffer_unordered` instead of ordered
        // `buffered`, the output would be ordered by this completion order (6,5,4,3,2)
        // instead of page order (1,2,3,4,5,6) — `deps-github-actions`'s tag-to-SHA
        // "first tag wins" dedup depends on the latter.
        let result = paginate_tags("Swift", "owner/repo", |page| async move {
            match page {
                1 => Ok(named_page("page1", 100)),
                2 => {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    Ok(named_page("page2", 100))
                }
                3 => {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(named_page("page3", 100))
                }
                4 => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(named_page("page4", 100))
                }
                5 => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(named_page("page5", 100))
                }
                6 => Ok(named_page("page6", 1)),
                _ => panic!("page {page} must not be fetched"),
            }
        })
        .await
        .unwrap();

        assert_eq!(result.len(), 501);
        for (expected_prefix, start, len) in [
            ("page1", 0, 100),
            ("page2", 100, 100),
            ("page3", 200, 100),
            ("page4", 300, 100),
            ("page5", 400, 100),
            ("page6", 500, 1),
        ] {
            for i in 0..len {
                assert!(
                    result[start + i].name.starts_with(expected_prefix),
                    "expected {expected_prefix} at index {}, got {}",
                    start + i,
                    result[start + i].name
                );
            }
        }
    }

    #[tokio::test]
    async fn test_paginate_tags_mid_batch_error_propagates_as_that_pages_error() {
        // Page 4 errors while pages 5-6 (later in page order, but faster to resolve) are
        // still in flight. The error returned must be page 4's own, not silently swapped
        // for a sibling's outcome or swallowed into an `Ok` with a truncated result.
        let err = paginate_tags("Swift", "owner/repo", |page| async move {
            match page {
                1..=3 => Ok(tags_page_json(100)),
                4 => Err(DepsError::CacheError("boom from page 4".to_string())),
                5..=6 => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(tags_page_json(100))
                }
                _ => panic!("page {page} must not be fetched"),
            }
        })
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("boom from page 4"),
            "must propagate page 4's own error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_paginate_tags_warns_when_cap_reached_with_full_last_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("Swift", "owner/repo", |_page| {
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

    // --- parse_tags_page ---

    #[test]
    fn test_parse_tags_page_returns_raw_tags() {
        let json = r#"[{"name": "v1.0.0"}, {"name": "not-semver"}]"#;
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, "v1.0.0");
    }

    #[test]
    fn test_parse_tags_page_missing_commit_defaults() {
        // The GitHub Actions caller needs `commit.sha`; the Swift caller ignores it
        // entirely. Both must deserialize a page whose entries omit `commit` outright.
        let json = r#"[{"name": "1.0.0"}]"#;
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].commit.sha, "");
    }

    #[test]
    fn test_parse_tags_page_invalid_json_returns_empty() {
        let result = parse_tags_page(b"not json").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_tags_page_github_rate_limit_returns_error() {
        let json = r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#;
        let result = parse_tags_page(json.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    // --- GithubTagsClient ---

    #[test]
    fn test_github_tags_client_for_test_sets_token_header() {
        let client = GithubTagsClient::for_test(Arc::new(HttpCache::new()), "http://example", true);
        assert!(client.has_token());
        assert_eq!(client.api_base(), "http://example");
        assert_eq!(client.headers().len(), 1);
    }

    #[test]
    fn test_github_tags_client_for_test_no_token_has_no_headers() {
        let client =
            GithubTagsClient::for_test(Arc::new(HttpCache::new()), "http://example", false);
        assert!(!client.has_token());
        assert!(client.headers().is_empty());
    }

    // --- AuthToken redaction ---

    #[test]
    fn test_auth_token_debug_redacts_value() {
        let token = AuthToken("Bearer super-secret-value".to_string());
        assert_eq!(format!("{token:?}"), "AuthToken(***)");
    }

    #[test]
    fn test_auth_token_display_redacts_value() {
        let token = AuthToken("Bearer super-secret-value".to_string());
        assert_eq!(format!("{token}"), "***");
    }

    #[test]
    fn test_auth_token_debug_redacts_when_embedded_in_header_vec() {
        // Guards against a future `#[derive(Debug)]` on `GithubTagsClient` (or a struct
        // embedding it) accidentally printing a raw `GITHUB_TOKEN` value: exercises the
        // exact shape `GithubTagsClient::auth_headers` stores, `Vec<(HeaderName,
        // AuthToken)>`, not just a bare `AuthToken`.
        let token = AuthToken("Bearer super-secret-value".to_string());
        let headers = vec![(AUTHORIZATION, token)];
        let debug_output = format!("{headers:?}");
        assert!(
            !debug_output.contains("super-secret-value"),
            "{debug_output}"
        );
        assert!(debug_output.contains("AuthToken(***)"), "{debug_output}");
    }

    // --- fetch_authenticated: wire-level behavior ---

    #[tokio::test]
    async fn test_fetch_authenticated_sends_token_on_the_wire() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/repos/owner/repo/tags?per_page=100&page=1")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_body("[]")
            .create_async()
            .await;

        let client = GithubTagsClient::for_test(Arc::new(HttpCache::new()), server.url(), true);
        client.fetch_tags_page("owner/repo", 1).await.unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_authenticated_blocks_cross_origin_redirect() {
        // Two separate `mockito::Server` instances bind to distinct ports, so a 302 from
        // one to the other is a genuine cross-origin redirect the trusted-origin pin must
        // stop (mirrors `cache::tests::test_get_cached_trusted_origin_stops_cross_origin_redirect`).
        let mut trusted_server = mockito::Server::new_async().await;
        let mut other_server = mockito::Server::new_async().await;

        let escape_target = format!("{}/stolen", other_server.url());
        let _redirect = trusted_server
            .mock("GET", "/repos/owner/repo/tags?per_page=100&page=1")
            .with_status(302)
            .with_header("location", &escape_target)
            .create_async()
            .await;
        let escape = other_server
            .mock("GET", "/stolen")
            .with_status(200)
            .with_body("must not be returned")
            .expect(0)
            .create_async()
            .await;

        let client =
            GithubTagsClient::for_test(Arc::new(HttpCache::new()), trusted_server.url(), true);
        let result = client.fetch_tags_page("owner/repo", 1).await;

        // Extract only the status code rather than formatting `result` itself: the error
        // carries no sensitive data, but CodeQL's cleartext-logging check flags any format
        // of a value derived from a call chain that touched the client's auth headers.
        let status = match result {
            Err(DepsError::HttpStatus { status, .. }) => Some(status),
            _ => None,
        };
        assert_eq!(
            status,
            Some(302),
            "expected the cross-origin redirect to be stopped"
        );
        escape.assert_async().await;
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
        // A repo with genuinely no releases must parse as `Some(empty)`, not `None` — the
        // caller relies on this to pick the positive TTL, not the error TTL (#223 S3).
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
        // GitHub returns releases in `created_at` desc order, so the first entry in the
        // array is the newest; a second release pointing at the same normalized tag must
        // not overwrite it (#223 M2).
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

    // --- evict_release_dates_if_full ---

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
    fn test_evict_release_dates_if_full_noop_under_cap() {
        let map = DashMap::new();
        map.insert("a/a".to_string(), entry_at(0, RELEASE_DATES_TTL));
        evict_release_dates_if_full(&map);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_evict_release_dates_if_full_drops_expired_entries_first() {
        let map = DashMap::new();
        for i in 0..MAX_RELEASE_DATES_MEMO_ENTRIES {
            // Every entry expired against its own (error) TTL.
            map.insert(
                format!("owner/repo{i}"),
                entry_at(1000, RELEASE_DATES_ERROR_TTL),
            );
        }
        assert_eq!(map.len(), MAX_RELEASE_DATES_MEMO_ENTRIES);
        evict_release_dates_if_full(&map);
        assert!(
            map.is_empty(),
            "all entries were expired and must be dropped"
        );
    }

    #[test]
    fn test_evict_release_dates_if_full_drops_oldest_when_none_expired() {
        let map = DashMap::new();
        for i in 0..MAX_RELEASE_DATES_MEMO_ENTRIES {
            // All alive (well within TTL), but with distinct ages so one is oldest.
            map.insert(
                format!("owner/repo{i}"),
                entry_at(i as u64, RELEASE_DATES_TTL),
            );
        }
        assert_eq!(map.len(), MAX_RELEASE_DATES_MEMO_ENTRIES);
        evict_release_dates_if_full(&map);
        assert_eq!(
            map.len(),
            MAX_RELEASE_DATES_MEMO_ENTRIES - 1,
            "exactly one entry (the oldest) must be evicted"
        );
        // The oldest entry (largest secs_ago == MAX_RELEASE_DATES_MEMO_ENTRIES - 1) must be
        // gone.
        assert!(!map.contains_key(&format!("owner/repo{}", MAX_RELEASE_DATES_MEMO_ENTRIES - 1)));
        // The newest entry must survive.
        assert!(map.contains_key("owner/repo0"));
    }

    // --- ReleaseDatesCache::fetch: memo behavior ---

    /// Builds a [`GithubTagsClient`] with `has_token` pinned to `false`, independent of the
    /// ambient `GITHUB_TOKEN` environment variable (CI runners, e.g. GitHub Actions, often
    /// inject one automatically), so these tests stay deterministic and never attempt a real
    /// network request.
    fn untokened_client() -> GithubTagsClient {
        GithubTagsClient::for_test(Arc::new(HttpCache::new()), GITHUB_API, false)
    }

    #[tokio::test]
    async fn test_fetch_validate_owner_repo_rejection_issues_zero_requests() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();
        let dates = cache.fetch(&github, "../../etc/passwd", "Test").await;
        assert!(dates.is_empty());
        // Nothing stored: a validation failure is cheaper to re-check than to memoize
        // (#223 M6), and this also proves no fetch-and-store path ran.
        assert!(cache.dates.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_positive_ttl_hit_returns_memoized_value_without_refetch() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();
        // has_token is false, so any code path that falls through to a live fetch would
        // both return an *empty* map and log the skip message — this fixture (a non-empty,
        // synthetic dataset a real GitHub call could never produce) is only observable if
        // the positive-TTL memo-hit branch returned early.
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        cache.dates.insert(
            format!("{GITHUB_API}\0owner/repo"),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::from([("9.9.9".to_string(), published)])),
                ttl: RELEASE_DATES_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = cache.fetch(&github, "owner/repo", "Test").await;
            assert_eq!(dates.get("9.9.9").copied(), Some(published));
        })
        .await;
        assert!(
            output.is_empty(),
            "memo hit must not log the token-gate skip: {output}"
        );
    }

    #[tokio::test]
    async fn test_fetch_empty_but_successful_fetch_retained_under_positive_ttl() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();
        // An empty dates map stored under the *positive* TTL (simulating a repo with
        // genuinely no releases) must be trusted as-is, not treated as if it had failed and
        // needed a retry within the (much shorter) error TTL.
        cache.dates.insert(
            format!("{GITHUB_API}\0owner/repo"),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = cache.fetch(&github, "owner/repo", "Test").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.is_empty(),
            "an empty-but-successful entry within its positive TTL must not refetch: {output}"
        );
    }

    #[tokio::test]
    async fn test_fetch_unexpired_error_ttl_entry_is_memo_hit() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();
        // A failure recorded under the (short) error TTL, 60s ago, is still within that 90s
        // window: it must be honored as a memo hit, not treated as expired.
        cache.dates.insert(
            format!("{GITHUB_API}\0owner/repo"),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_ERROR_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = cache.fetch(&github, "owner/repo", "Test").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.is_empty(),
            "an unexpired error-TTL entry must not refetch: {output}"
        );
    }

    #[tokio::test]
    async fn test_fetch_expired_error_ttl_entry_falls_through_to_token_gate() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();
        // 100s ago exceeds RELEASE_DATES_ERROR_TTL (90s): the entry must be treated as
        // expired and a refetch attempted. `has_token` is false, so the refetch resolves
        // locally (no network) via the token-gate skip, which logs.
        cache.dates.insert(
            format!("{GITHUB_API}\0owner/repo"),
            ReleaseDatesEntry {
                fetched_at: Instant::now()
                    .checked_sub(Duration::from_secs(100))
                    .unwrap(),
                dates: Arc::new(HashMap::new()),
                ttl: RELEASE_DATES_ERROR_TTL,
            },
        );

        let output = capture_tracing_output_async(async {
            let dates = cache.fetch(&github, "owner/repo", "Test").await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.contains("GITHUB_TOKEN not set"),
            "expiry must trigger a refetch attempt: {output}"
        );
    }

    #[tokio::test]
    async fn test_fetch_token_gate_skip_logs_once_per_cache_and_names_ecosystem() {
        let cache = ReleaseDatesCache::new();
        let github = untokened_client();

        let output = capture_tracing_output_async(async {
            let _ = cache.fetch(&github, "owner/repo-a", "Test").await;
            let _ = cache.fetch(&github, "owner/repo-b", "Test").await;
        })
        .await;

        assert_eq!(
            output.matches("GITHUB_TOKEN not set").count(),
            1,
            "the skip message must fire at most once per cache instance: {output}"
        );
        assert!(
            output.contains("Test release dates are unavailable"),
            "{output}"
        );
    }

    #[test]
    fn test_error_ttl_is_shorter_than_positive_ttl() {
        assert!(RELEASE_DATES_ERROR_TTL < RELEASE_DATES_TTL);
    }

    #[tokio::test]
    async fn test_fetch_does_not_serve_a_hit_seeded_under_a_different_api_base() {
        // #486 critic M1: the cache is keyed on `(api_base, name)`, not `name` alone, so two
        // `GithubTagsClient`s pointed at different origins sharing one cache (a mock server
        // beside the real API, or a future GitHub Enterprise base) cannot cross-serve a hit.
        let cache = ReleaseDatesCache::new();
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        cache.dates.insert(
            format!("{GITHUB_API}\0owner/repo"),
            ReleaseDatesEntry {
                fetched_at: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                dates: Arc::new(HashMap::from([("9.9.9".to_string(), published)])),
                ttl: RELEASE_DATES_TTL,
            },
        );

        // A client pointed at a different origin, but the same `owner/repo`, must not see
        // the entry seeded under `GITHUB_API` above — it falls through to the (untokened)
        // fetch path instead, observable via the token-gate skip log.
        let other_origin_client =
            GithubTagsClient::for_test(Arc::new(HttpCache::new()), "http://127.0.0.1:1", false);
        let output = capture_tracing_output_async(async {
            let dates = cache
                .fetch(&other_origin_client, "owner/repo", "Test")
                .await;
            assert!(dates.is_empty());
        })
        .await;
        assert!(
            output.contains("GITHUB_TOKEN not set"),
            "a different api_base must miss the memo and fall through: {output}"
        );
    }
}
