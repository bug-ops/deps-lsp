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
use crate::lsp_helpers::{is_dot_segment, warn_rejected_value};
use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, HeaderName};
use serde::Deserialize;
use std::future::Future;
use std::sync::Arc;

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

/// Drives the GitHub tags pagination loop, fetching pages via `fetch_page` until a partial
/// page is seen or [`MAX_TAG_PAGES`] is reached.
///
/// `ecosystem` is forwarded to [`warn_if_pagination_truncated`] to name the caller in the
/// truncation warning. Extracted so ecosystem crates' tests can inject a fake `fetch_page`
/// and exercise the real loop — including that warning's call site — without a live
/// GitHub API.
///
/// # Errors
///
/// Propagates any error `fetch_page` returns, or the error from [`parse_tags_page`] when a
/// page's body is a GitHub error object.
pub async fn paginate_tags<F, Fut>(
    ecosystem: &str,
    name: &str,
    mut fetch_page: F,
) -> Result<Vec<GithubTag>>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<Bytes>>,
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
        warn_if_pagination_truncated(ecosystem, name, page, page_len);
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
    async fn test_paginate_tags_stops_after_partial_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let mut tags = Vec::new();
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("Swift", "owner/repo", |page| {
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

        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected the cross-origin redirect to be stopped, got {result:?}"
        );
        escape.assert_async().await;
    }
}
