//! GitLab REST API client — fetches repository tags (`project:` includes) and project
//! releases (`component:` includes) from a per-call, per-instance host.
//!
//! Parallel to, but not derived from, `deps_core::github::GithubTagsClient`: GitLab
//! references may target a self-hosted instance (NFR-008), so the host is a per-call
//! argument rather than a compile-time constant — the one structural difference driving
//! every choice below.

use bytes::Bytes;
use dashmap::DashSet;
use deps_core::cache::HttpCache;
use deps_core::error::{DepsError, Result};
use reqwest::header::HeaderName;
use serde::Deserialize;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::{Arc, OnceLock};

use crate::host::{GitlabHost, GitlabInstanceHost, token_host_origin};

/// GitLab's credential header — a distinct scheme from GitHub's `Authorization: Bearer`
/// (NFR-006); this crate and `deps_core::github` deliberately do not share an auth-scheme
/// abstraction for it (spec plan §1 "Ask First" item).
fn private_token_header() -> HeaderName {
    HeaderName::from_static("private-token")
}

/// Maximum number of pages fetched per (host, project, endpoint) combination.
///
/// Mirrors `deps_core::github::MAX_TAG_PAGES`'s role — a safety ceiling, not the
/// correctness mechanism (`deps_core::pagination::page_has_more` already stops as soon as a
/// page comes back partial). Kept at the same value since GitLab's `order_by=version`
/// ordering (§4.2) does not have GitHub's lexicographic-ordering hazard that justified a
/// generously high cap there, but there is no reason to pick a materially different number.
pub const MAX_GITLAB_PAGES: u32 = 30;

/// A `GITLAB_TOKEN` header value, redacted everywhere except the one call site that hands
/// it to a request as a header value. Mirrors `deps_core::github`'s `AuthToken` (module-
/// private there too — this crate keeps its own copy rather than widening that
/// visibility for a ~15-line type).
#[derive(Clone, PartialEq, Eq)]
struct AuthToken(deps_core::secret::Redacted);

impl AuthToken {
    fn new(value: String) -> Self {
        Self(deps_core::secret::Redacted::new(value))
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(***)")
    }
}

/// A per-process random salt, mixed into [`own_auth_digest`] so the digest cannot be
/// reconstructed offline from a known origin/token pair — mirrors
/// `deps_nuget::registry::digest_salt`.
fn digest_salt() -> u64 {
    static SALT: OnceLock<u64> = OnceLock::new();
    *SALT.get_or_init(|| {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        std::process::id().hash(&mut hasher);
        std::time::SystemTime::now().hash(&mut hasher);
        hasher.finish()
    })
}

/// A per-request auth identity for `HttpCache::get_cached_pinned_with_headers`'s `auth_id`
/// argument — `None` when unauthenticated, otherwise a salted hash of `origin` and the
/// token's header value. Ensures a response fetched without the token can never be served
/// back to a request that would have carried it, or vice versa (spec §4.5's cache-key
/// consequence of authenticating some hosts and not others for the same project).
fn own_auth_digest(origin: &str, token: Option<&str>) -> Option<u64> {
    let token = token?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    digest_salt().hash(&mut hasher);
    origin.hash(&mut hasher);
    token.hash(&mut hasher);
    Some(hasher.finish())
}

/// The actionable error returned when a request hits GitLab's rate limit, or a 401/403
/// with no `GITLAB_TOKEN` configured (spec FR-014).
#[must_use]
pub fn gitlab_rate_limit_error() -> DepsError {
    DepsError::RateLimited {
        message: "GitLab API rate limit exceeded or authentication required. Set \
                   GITLAB_TOKEN to a GitLab Personal/Project Access Token to increase the \
                   limit and access private projects."
            .into(),
    }
}

/// GitLab tags API response item (`GET /projects/:id/repository/tags`).
#[derive(Debug, Default, Deserialize)]
pub struct GitlabTag {
    pub name: String,
    #[serde(default)]
    pub commit: GitlabCommit,
}

/// GitLab releases API response item (`GET /projects/:id/releases`).
#[derive(Debug, Default, Deserialize)]
pub struct GitlabRelease {
    pub tag_name: String,
    #[serde(default)]
    pub commit: GitlabCommit,
    #[serde(default)]
    pub released_at: Option<String>,
}

/// The `commit` object nested in a [`GitlabTag`]/[`GitlabRelease`].
#[derive(Debug, Default, Deserialize)]
pub struct GitlabCommit {
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
/// Returns [`DepsError::CacheError`] when `data` parses as a GitLab error object.
pub fn parse_tags_page(data: &[u8]) -> Result<Vec<GitlabTag>> {
    parse_gitlab_page(data)
}

/// Parses a single GitLab releases API response page.
///
/// # Errors
///
/// Returns [`DepsError::CacheError`] when `data` parses as a GitLab error object.
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
                Err(DepsError::CacheError(format!("GitLab API error: {text}")))
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
    token: Option<AuthToken>,
    instance_host: Arc<GitlabInstanceHost>,
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
    /// `PRIVATE-TOKEN` header — but only to the single token host (spec FR-005a, see
    /// [`crate::host::token_host_origin`]).
    #[must_use]
    pub fn new(cache: Arc<HttpCache>, instance_host: Arc<GitlabInstanceHost>) -> Self {
        let token = std::env::var("GITLAB_TOKEN")
            .ok()
            .map(zeroize::Zeroizing::new)
            .filter(|t| !t.is_empty());
        if token.is_some() {
            tracing::info!("GITLAB_TOKEN detected, using authenticated GitLab API requests");
        }
        Self {
            cache,
            token: token.map(|t| AuthToken::new((*t).clone())),
            instance_host,
            degraded_order_by_hosts: Arc::new(DashSet::new()),
        }
    }

    /// Whether a `GITLAB_TOKEN` was present at construction.
    #[must_use]
    pub const fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Creates a client with `token` set directly, bypassing the environment — for tests
    /// that need a deterministic token without mutating `std::env` (which is `unsafe` since
    /// Rust 2024 and forbidden workspace-wide).
    #[cfg(test)]
    #[must_use]
    fn for_test(
        cache: Arc<HttpCache>,
        instance_host: Arc<GitlabInstanceHost>,
        token: Option<&str>,
    ) -> Self {
        Self {
            cache,
            token: token.map(|t| AuthToken::new(t.to_string())),
            instance_host,
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
    /// single token host (spec FR-005a).
    async fn fetch_pinned(&self, host: &GitlabHost, url: &str) -> Result<Bytes> {
        // `is_some_and`, never `.unwrap_or(...)`: an invalid `registries.gitlab_instance_host`
        // must disable the token outright (`token_host_origin` returns `None`), not silently
        // fall back to comparing against a default that could coincidentally match `host`
        // (security review, issue #466).
        let is_token_host =
            token_host_origin(&self.instance_host).is_some_and(|origin| origin == host.origin());
        let token_value = if is_token_host {
            self.token.as_ref().map(AuthToken::expose_secret)
        } else {
            None
        };
        let auth_id = own_auth_digest(host.origin(), token_value);
        let headers: Vec<(HeaderName, &str)> = token_value
            .map(|t| vec![(private_token_header(), t)])
            .unwrap_or_default();

        self.cache
            .get_cached_pinned_with_headers(
                url,
                host.origin(),
                token_value.is_some(),
                auth_id,
                &headers,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
    use std::sync::RwLock;

    fn instance_host(configured: Option<&str>) -> Arc<GitlabInstanceHost> {
        let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
        Arc::new(GitlabInstanceHost::new(
            Arc::new(RwLock::new(configured.map(str::to_string))),
            policy,
        ))
    }

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
        assert!(result.unwrap_err().to_string().contains("GitLab API error"));
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
        let client = GitlabApiClient::new(Arc::new(HttpCache::new()), instance_host(None));
        let _ = client.has_token();
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
        let client = GitlabApiClient::new(Arc::clone(&cache), instance_host(None));

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

        let client = GitlabApiClient::new(Arc::new(HttpCache::new()), instance_host(None));
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

        let client = GitlabApiClient::new(Arc::new(HttpCache::new()), instance_host(None));
        let data = client
            .fetch_releases_page(&test_host_for(&server.url()), "org/proj", 1)
            .await
            .unwrap();
        assert_eq!(parse_releases_page(&data).unwrap().len(), 1);
        mock.assert_async().await;
    }

    // --- Token-host containment (spec FR-005a/§9.2 regression, security-relevant) ---

    #[tokio::test]
    async fn test_private_token_present_for_configured_token_host() {
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
        // `instance_host`'s raw-string path can't reach a `mockito` `127.0.0.1:PORT`
        // host — it fails `GitlabHost::parse`'s port-rejecting validation, which is
        // correct for production but unusable here — so this uses the test-only bypass
        // that stores an already-constructed `GitlabHost` directly.
        let instance = Arc::new(GitlabInstanceHost::for_test(host.clone()));
        let client = GitlabApiClient::for_test(
            Arc::new(HttpCache::new()),
            instance,
            Some("test-gitlab-token"),
        );
        client.fetch_tags_page(&host, "org/proj", 1).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_private_token_absent_for_non_token_host() {
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
        // instance_host configured for a DIFFERENT host than the mock server — the mock
        // server's host is therefore never the token host.
        let instance = instance_host(Some("gitlab.other-instance.example"));
        let client = GitlabApiClient::for_test(
            Arc::new(HttpCache::new()),
            instance,
            Some("test-gitlab-token"),
        );
        client.fetch_tags_page(&host, "org/proj", 1).await.unwrap();
        mock.assert_async().await;
    }
}
