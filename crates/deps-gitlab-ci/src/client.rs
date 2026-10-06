//! GitLab REST API client — fetches repository tags (`project:` includes) and project
//! releases (`component:` includes) from a per-call, per-instance host.
//!
//! Parallel to, but not derived from, `deps_core::github::GithubTagsClient`: GitLab
//! references may target a self-hosted instance (NFR-008), so the host is a per-call
//! argument rather than a compile-time constant — the one structural difference driving
//! every choice below.

use bytes::Bytes;
use dashmap::DashSet;
use deps_core::cache::{CredentialHeader, HttpCache, RequestHeader};
use deps_core::error::{DepsError, RateLimitEvidence, Result};
use deps_core::secret::ApiToken;
use serde::Deserialize;
use std::sync::Arc;

use crate::host::GitlabHost;
use crate::token::TokenBinding;

/// Maximum number of pages fetched per (host, project, endpoint) combination.
///
/// Mirrors `deps_core::github::MAX_TAG_PAGES`'s role — a safety ceiling, not the
/// correctness mechanism (`deps_core::pagination::page_has_more` already stops as soon as a
/// page comes back partial). Kept at the same value since GitLab's `order_by=version`
/// ordering (§4.2) does not have GitHub's lexicographic-ordering hazard that justified a
/// generously high cap there, but there is no reason to pick a materially different number.
pub const MAX_GITLAB_PAGES: u32 = 30;

/// Fixed message for a GitLab rate-limit/auth-rejection error, regardless of
/// [`RateLimitEvidence`] — the message itself never varies with confidence for this
/// ecosystem (unlike GitHub's, see `deps_core::github::github_rate_limit_error`'s two
/// distinct messages).
const GITLAB_RATE_LIMIT_MESSAGE: &str = "GitLab API rate limit exceeded or authentication required. Set \
     GITLAB_TOKEN to a GitLab Personal/Project Access Token to increase the \
     limit and access private projects. If the instance is self-hosted, also set \
     GITLAB_TOKEN_HOST to its hostname.";

/// The actionable error returned when a request hits GitLab's rate limit, or a 401/403
/// with no `GITLAB_TOKEN` configured (spec FR-014).
///
/// A single `fn(RateLimitEvidence)` (#1480 item 8), not the two separate
/// `gitlab_rate_limit_error`/`gitlab_rate_limit_error_verified` constructors this replaced —
/// see [`deps_core::rate_limit::RateLimitGate::evidence`] for the matching gate-side
/// projection every call site now uses instead of its own `if gate.verified() { .. } else
/// { .. }` branch.
///
/// `crate::registry::GitlabCiRegistry::map_error`/`fetch_route` use this instead of passing
/// a `deps_core::cache`-classified error through with its registry-neutral message, so a
/// confirmed rate limit still gets GitLab's `GITLAB_TOKEN` remedy rather than a strictly less
/// helpful generic message than the unverified guess gives (#1295 critic N2).
#[must_use]
pub fn gitlab_rate_limit_error(verified: RateLimitEvidence) -> DepsError {
    // `DepsError::rate_limited`, not a struct literal: `RateLimited` is `#[non_exhaustive]`.
    DepsError::rate_limited(GITLAB_RATE_LIMIT_MESSAGE, verified)
}

/// GitLab tags API response item (`GET /projects/:id/repository/tags`).
///
/// Output-only, like its siblings [`GitlabRelease`]/[`GitlabCommit`] below: constructed by
/// this crate's own `serde` deserialization, never by external code — no constructor is
/// provided.
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
pub struct GitlabTag {
    /// The tag name (e.g. `"v1.2.3"`).
    pub name: String,
    /// The tagged commit.
    #[serde(default)]
    pub commit: GitlabCommit,
}

/// GitLab releases API response item (`GET /projects/:id/releases`).
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
pub struct GitlabRelease {
    /// The release's associated tag name.
    pub tag_name: String,
    /// The tagged commit.
    #[serde(default)]
    pub commit: GitlabCommit,
    /// When the release was published, if GitLab reports it.
    #[serde(default)]
    pub released_at: Option<String>,
}

/// The `commit` object nested in a [`GitlabTag`]/[`GitlabRelease`].
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
pub struct GitlabCommit {
    /// The full commit SHA the tag/release points at.
    #[serde(default)]
    pub id: String,
}

/// GitLab API error response.
#[derive(Deserialize)]
struct GitlabErrorResponse {
    #[serde(default)]
    message: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

/// Parses a single GitLab tags API response page.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] when `data` parses as a GitLab error object.
pub fn parse_tags_page(data: &[u8]) -> Result<Vec<GitlabTag>> {
    parse_gitlab_page(data)
}

/// Parses a single GitLab releases API response page.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] when `data` parses as a GitLab error object.
pub fn parse_releases_page(data: &[u8]) -> Result<Vec<GitlabRelease>> {
    parse_gitlab_page(data)
}

fn parse_gitlab_page<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<Vec<T>> {
    match deps_core::parser::parse_json_checked(data) {
        Ok(items) => Ok(items),
        Err(_) => {
            if let Ok(err) = deps_core::parser::parse_json_checked::<GitlabErrorResponse>(data) {
                let text = err
                    .message
                    .map(|v| v.to_string())
                    .or(err.error)
                    .unwrap_or_default();
                Err(DepsError::parse_error("GitLab API response", &text))
            } else {
                Ok(vec![])
            }
        }
    }
}

/// Client for fetching repository tags and project releases from a per-call GitLab
/// instance host.
#[derive(Clone)]
pub struct GitlabApiClient {
    cache: Arc<HttpCache>,
    token: TokenBinding,
    /// Origins already known (H3, #466 review) to reject `order_by=version` with a `400`
    /// — a pre-16.0 self-hosted instance. Memoized per host so the degradation is
    /// discovered once, not rediscovered (and repaid with a wasted round trip) on every
    /// page of every subsequent fetch against that host.
    degraded_order_by_hosts: Arc<DashSet<String>>,
}

impl GitlabApiClient {
    /// Creates a new client backed by `cache`.
    ///
    /// Reads `GITLAB_TOKEN` from the environment for authenticated requests, sent as the
    /// `PRIVATE-TOKEN` header only to `gitlab.com` or to the host named by the
    /// `GITLAB_TOKEN_HOST` environment variable — never to a host taken from LSP settings.
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        let token = TokenBinding::from_env();
        if let Some(origin) = token.bound_origin() {
            tracing::info!(%origin, "GITLAB_TOKEN detected, sending it only to this GitLab origin");
        }
        Self {
            cache,
            token,
            degraded_order_by_hosts: Arc::new(DashSet::new()),
        }
    }

    /// Whether requests to `origin` carry `GITLAB_TOKEN`: only the env-bound origin does.
    #[must_use]
    pub fn sends_token_to(&self, origin: &str) -> bool {
        self.token.token_for_origin(origin).is_some()
    }

    /// Creates a client with `token` bound directly, bypassing the environment — for tests
    /// that need a deterministic token without mutating `std::env` (which is `unsafe` since
    /// Rust 2024 and forbidden workspace-wide).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(cache: Arc<HttpCache>, token: TokenBinding) -> Self {
        Self {
            cache,
            token,
            degraded_order_by_hosts: Arc::new(DashSet::new()),
        }
    }

    /// Fetches one page of `host`'s repository-tags API for `project_path`.
    ///
    /// Requests `order_by=version&sort=desc` (GitLab 16.0+) — `updated` ordering sorts by
    /// *commit* date, so a backport tag cut from an old commit can fall past the page cap
    /// (the same class of hazard `deps_core::github::MAX_TAG_PAGES`'s doc documents for
    /// GitHub's lexicographic ordering). An older self-hosted instance answers an unknown
    /// `order_by` with `400`; on such a `400`, for **any** page, this retries once with no
    /// `order_by` parameter, logs the degradation at `debug`, and memoizes `host`'s origin in
    /// `degraded_order_by_hosts` (H3, #466 review) so every later page of this fetch —
    /// and every subsequent fetch against the same host — skips straight to the fallback URL
    /// instead of re-discovering (and repaying the round trip for) the same `400`.
    ///
    /// # Errors
    ///
    /// Propagates the underlying HTTP/cache error unchanged.
    pub async fn fetch_tags_page(
        &self,
        host: &GitlabHost,
        project_path: &str,
        page: u32,
    ) -> Result<Bytes> {
        let enc = urlencoding::encode(project_path);
        let fallback_url = format!(
            "{}/api/v4/projects/{enc}/repository/tags?per_page=100&page={page}",
            host.origin()
        );
        if self.degraded_order_by_hosts.contains(host.origin()) {
            return self.fetch_pinned(host, &fallback_url).await;
        }
        let url = format!(
            "{}/api/v4/projects/{enc}/repository/tags?per_page=100&page={page}&order_by=version&sort=desc",
            host.origin()
        );
        match self.fetch_pinned(host, &url).await {
            Err(DepsError::HttpStatus { status: 400, .. }) => {
                tracing::debug!(
                    host = host.host(),
                    page,
                    "GitLab instance rejected order_by=version; retrying without it and \
                     memoizing the degradation for this host"
                );
                self.degraded_order_by_hosts
                    .insert(host.origin().to_string());
                self.fetch_pinned(host, &fallback_url).await
            }
            other => other,
        }
    }

    /// Fetches one page of `host`'s project-releases API for `project_path`.
    ///
    /// No `order_by=version` here (GitLab's `/releases` has none) — its default ordering
    /// is release-date descending, which is fine: `releases_to_versions` (this crate's own
    /// releases-to-versions conversion step) re-sorts the parsed list newest-first by parsed
    /// semver itself, and [`crate::component::resolve_component_pin`]'s FR-007 ladder
    /// likewise selects by parsed semver rather than trusting fetch order — neither pass
    /// depends on API ordering, and catalogs are small.
    ///
    /// # Errors
    ///
    /// Propagates the underlying HTTP/cache error unchanged.
    pub async fn fetch_releases_page(
        &self,
        host: &GitlabHost,
        project_path: &str,
        page: u32,
    ) -> Result<Bytes> {
        let enc = urlencoding::encode(project_path);
        let url = format!(
            "{}/api/v4/projects/{enc}/releases?per_page=100&page={page}",
            host.origin()
        );
        self.fetch_pinned(host, &url).await
    }

    /// Fetches `url` through the origin-pinned, connect-address-guarded `CacheTier::Pinned`
    /// transport — the only sanctioned way to send a credential to a workspace-declared
    /// host (issue #561/#562 precedent) — attaching `PRIVATE-TOKEN` only when `host` is the
    /// env-bound token host.
    async fn fetch_pinned(&self, host: &GitlabHost, url: &str) -> Result<Bytes> {
        let token = self.token.token_for(host);
        let auth_id =
            deps_core::secret::auth_digest(host.origin(), token.map(ApiToken::expose_secret));
        let headers: Vec<RequestHeader<'_>> = token
            .map(|t| {
                RequestHeader::Credential(CredentialHeader::GitlabPrivateToken, t.as_redacted())
            })
            .into_iter()
            .collect();

        self.cache
            .get_cached_pinned_with_headers(url, host.origin(), token.is_some(), auth_id, &headers)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_tags_page / parse_releases_page ---

    #[test]
    fn test_parse_tags_page_happy_path() {
        let sha = "a".repeat(40);
        let json = format!(r#"[{{"name":"v1.0.0","commit":{{"id":"{sha}"}}}}]"#);
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "v1.0.0");
        assert_eq!(tags[0].commit.id, sha);
    }

    #[test]
    fn test_parse_releases_page_happy_path() {
        let sha = "a".repeat(40);
        let json = format!(
            r#"[{{"tag_name":"1.0.0","commit":{{"id":"{sha}"}},"released_at":"2026-01-02T08:56:05Z"}}]"#
        );
        let releases = parse_releases_page(json.as_bytes()).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].tag_name, "1.0.0");
        assert_eq!(
            releases[0].released_at.as_deref(),
            Some("2026-01-02T08:56:05Z")
        );
    }

    #[test]
    fn test_parse_gitlab_page_error_object_returns_error() {
        let json = r#"{"message":"404 Project Not Found"}"#;
        let result: Result<Vec<GitlabTag>> = parse_gitlab_page(json.as_bytes());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DepsError::ParseError { .. }));
    }

    #[test]
    fn test_parse_gitlab_page_invalid_json_returns_empty() {
        let result: Result<Vec<GitlabTag>> = parse_gitlab_page(b"not json");
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_gitlab_page_missing_commit_defaults() {
        let json = r#"[{"name":"1.0.0"}]"#;
        let tags = parse_tags_page(json.as_bytes()).unwrap();
        assert_eq!(tags[0].commit.id, "");
    }

    // --- GitlabApiClient: token presence and host targeting ---

    #[tokio::test]
    async fn test_client_for_test_no_token_by_default_in_unit_tests() {
        // `GITLAB_TOKEN` should not be relied upon in unit tests; this only asserts the
        // constructor is usable without one.
        let client = GitlabApiClient::new(Arc::new(HttpCache::new()));
        let _ = client.sends_token_to(crate::host::GITLAB_COM_ORIGIN);
    }

    #[tokio::test]
    async fn test_fetch_tags_page_wire_and_pagination() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("order_by".into(), "version".into()),
                mockito::Matcher::UrlEncoded("sort".into(), "desc".into()),
                mockito::Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(r#"[{"name":"1.0.0","commit":{"id":"a"}}]"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let client = GitlabApiClient::new(Arc::clone(&cache));

        let data = client
            .fetch_tags_page(&test_host_for(&server.url()), "org/proj", 1)
            .await
            .unwrap();
        let tags = parse_tags_page(&data).unwrap();
        assert_eq!(tags.len(), 1);
        mock.assert_async().await;
    }

    /// Builds a [`GitlabHost`] pointed at a `mockito` server, bypassing
    /// [`GitlabHost::parse`]'s https-only gate (tests need `http://127.0.0.1:PORT`).
    fn test_host_for(base_url: &str) -> GitlabHost {
        GitlabHost::for_test(base_url)
    }

    #[tokio::test]
    async fn test_fetch_tags_page_order_by_400_retries_without_it() {
        let mut server = mockito::Server::new_async().await;
        // Anchored/substring regexes disambiguate the two requests without a `Matcher::Not`
        // (not available in this mockito version): the first request's query contains
        // `order_by=version` as a substring; the retry's query is *exactly*
        // `per_page=100&page=1`.
        let _reject = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Regex("order_by=version".into()))
            .with_status(400)
            .create_async()
            .await;
        let fallback = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Regex("^per_page=100&page=1$".into()))
            .with_status(200)
            .with_body(r#"[{"name":"1.0.0","commit":{"id":"a"}}]"#)
            .create_async()
            .await;

        let client = GitlabApiClient::new(Arc::new(HttpCache::new()));
        let data = client
            .fetch_tags_page(&test_host_for(&server.url()), "org/proj", 1)
            .await
            .unwrap();
        assert_eq!(parse_tags_page(&data).unwrap().len(), 1);
        fallback.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_releases_page_wire() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::UrlEncoded("page".into(), "1".into()))
            .with_status(200)
            .with_body(r#"[{"tag_name":"1.0.0","commit":{"id":"a"}}]"#)
            .create_async()
            .await;

        let client = GitlabApiClient::new(Arc::new(HttpCache::new()));
        let data = client
            .fetch_releases_page(&test_host_for(&server.url()), "org/proj", 1)
            .await
            .unwrap();
        assert_eq!(parse_releases_page(&data).unwrap().len(), 1);
        mock.assert_async().await;
    }

    // --- Token-host containment (spec FR-005a/§9.2 regression, security-relevant) ---

    #[tokio::test]
    async fn test_private_token_present_for_bound_token_host() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .match_header("private-token", "test-gitlab-token")
            .with_status(200)
            .with_body("[]")
            .create_async()
            .await;

        let host = test_host_for(&server.url());
        let client = GitlabApiClient::for_test(
            Arc::new(HttpCache::new()),
            TokenBinding::for_test("test-gitlab-token", host.origin()),
        );
        client.fetch_tags_page(&host, "org/proj", 1).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_private_token_absent_for_non_bound_host() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .match_header("private-token", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("[]")
            .create_async()
            .await;

        let host = test_host_for(&server.url());
        let client = GitlabApiClient::for_test(
            Arc::new(HttpCache::new()),
            TokenBinding::for_test("test-gitlab-token", "https://gitlab.other-instance.example"),
        );
        client.fetch_tags_page(&host, "org/proj", 1).await.unwrap();
        mock.assert_async().await;
    }

    /// Regression for #1790: with the token bound to `gitlab.com` (no `GITLAB_TOKEN_HOST`), a
    /// request to a settings-supplied host carries no `PRIVATE-TOKEN`.
    #[tokio::test]
    async fn test_private_token_absent_for_settings_supplied_host() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .match_header("private-token", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("[]")
            .create_async()
            .await;

        let host = test_host_for(&server.url());
        let client = GitlabApiClient::for_test(
            Arc::new(HttpCache::new()),
            TokenBinding::for_test("test-gitlab-token", crate::host::GITLAB_COM_ORIGIN),
        );
        client.fetch_tags_page(&host, "org/proj", 1).await.unwrap();
        mock.assert_async().await;
    }
}
