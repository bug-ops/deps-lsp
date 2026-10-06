//! SE-0292 package registry client: `GET {base}/{scope}/{name}` lists a package's releases.
//!
//! One client per registry URL. A `Trusted` registry goes through the origin-pinned, baseline
//! guarded transport and may carry the environment credential; a `WorkspaceDeclared` one goes
//! through the connect-address-guarded pinned transport, unauthenticated.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use deps_core::HOVER_RECENT_VERSIONS;
use deps_core::cache::{CachedResponse, CredentialPartition};
use deps_core::error::PaginationStop;
use deps_core::github::semver_tags_newest_first;
use deps_core::keychain_credentials::{KeychainGeneration, KeychainSnapshot};
use deps_core::pagination::{NextPage, next_page};
use deps_core::policy_config::KeychainCredentials;
use deps_core::{CredentialHeader, DepsError, HttpCache, RequestHeader, Result, not_found_or};
use serde::Deserialize;
use url::Url;

use crate::auth::{KeychainAuthorization, RegistryAuth};
use crate::config::{RegistryTrust, ResolvedSwiftRegistry};
use crate::package_location::{CanonicalIdentity, RegistryIdentity};
use crate::published_at::{PublishedAtCache, ReleaseVersion};
use crate::types::SwiftVersion;

const ACCEPT: &str = "application/vnd.swift.registry.v1+json";

/// Bounds on fetching one release list across all its pages.
#[derive(Debug, Clone, Copy)]
struct ListLimits {
    /// Most pages fetched before giving up.
    pages: usize,
    /// Most distinct releases merged before giving up.
    releases: usize,
    /// Most response-body bytes read across all pages.
    body_bytes: usize,
    /// Overall time for all pages.
    budget: Duration,
}

impl ListLimits {
    const DEFAULT: Self = Self {
        pages: 10,
        releases: 10_000,
        body_bytes: 32 * 1024 * 1024,
        budget: Duration::from_secs(15),
    };
}

/// How long a failed pagination is remembered, so repeated calls fail fast.
const PAGINATION_FAILURE_TTL: Duration = Duration::from_secs(90);

/// Entries after which the pagination-failure memo is cleared.
const MAX_PAGINATION_FAILURES: usize = 4096;

/// Display name of an SE-0292 registry in error messages.
pub(crate) const REGISTRY: &str = "Swift package registry";

/// Which `HttpCache` transport a registry's requests use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportKind {
    /// Origin-pinned redirects, baseline connect guard, credential allowed.
    TrustedOrigin,
    /// Origin-pinned redirects, workspace-policy connect guard, never authenticated.
    Pinned,
}

/// The only place a transport is chosen.
pub(crate) const fn transport_for(trust: RegistryTrust) -> TransportKind {
    match trust {
        RegistryTrust::Trusted => TransportKind::TrustedOrigin,
        RegistryTrust::WorkspaceDeclared => TransportKind::Pinned,
    }
}

#[derive(Deserialize)]
struct ReleasesResponse {
    releases: BTreeMap<String, Release>,
}

#[derive(Deserialize)]
struct Release {
    #[serde(default)]
    problem: Option<serde::de::IgnoredAny>,
}

/// Whether a release listing also looks up each recent release's publication date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishedAtLookup {
    /// Only the release list is fetched.
    Skip,
    /// The newest releases' `publishedAt` is fetched, best-effort.
    Fetch,
}

/// A client for one SE-0292 registry.
pub(crate) struct PackageRegistryClient {
    cache: Arc<HttpCache>,
    registry: ResolvedSwiftRegistry,
    digest: u64,
    pagination_failures: DashMap<CanonicalIdentity, (PaginationStop, Instant)>,
    published_at: PublishedAtCache,
    credential_state: Mutex<Option<CredentialState>>,
}

/// Whether a request carried a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CredentialPresence {
    Anonymous,
    Credentialed,
}

/// What the cached responses of a Keychain-bound registry were fetched under: a response
/// obtained anonymously (lookup pending, refused, not found) must not answer a later
/// credentialed request, nor the reverse after the setting changed.
///
/// [`Self::partition`] is folded into the cache key, so the separation holds even when two
/// fetches under different states interleave; evicting on a change only frees memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CredentialState {
    presence: CredentialPresence,
    generation: KeychainGeneration,
}

impl CredentialState {
    fn partition(self, digest: u64) -> CredentialPartition {
        let mut hasher = DefaultHasher::new();
        (digest, self.presence, self.generation).hash(&mut hasher);
        CredentialPartition::new(hasher.finish())
    }
}

impl PackageRegistryClient {
    pub(crate) fn new(cache: Arc<HttpCache>, registry: ResolvedSwiftRegistry) -> Self {
        let digest = registry.digest();
        Self {
            cache,
            registry,
            digest,
            pagination_failures: DashMap::new(),
            published_at: PublishedAtCache::new(),
            credential_state: Mutex::new(None),
        }
    }

    /// Records what the next request is sent under and drops this registry's cached responses
    /// when that differs from the previous request's, to free bodies of a state that no longer
    /// applies.
    fn note_credential_state(&self, state: CredentialState) {
        let previous = self
            .credential_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(state);
        if previous.is_some_and(|previous| previous != state) {
            self.cache
                .evict_url_prefix(&format!("{}/", self.registry.url.as_str()));
        }
    }

    /// The partition an offline read uses: the last online state's, but only while that state is
    /// still current (same generation, setting still enabled). Otherwise the anonymous state at
    /// the current generation, whose partition no credentialed response was stored under, so the
    /// read misses and fails closed instead of serving a body fetched under a credential the
    /// setting has since withdrawn.
    fn offline_partition(&self, current: KeychainSnapshot) -> CredentialPartition {
        let last = *self
            .credential_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let state = match last {
            Some(state)
                if state.generation == current.generation
                    && current.setting == KeychainCredentials::Enabled =>
            {
                state
            }
            Some(_) | None => CredentialState {
                presence: CredentialPresence::Anonymous,
                generation: current.generation,
            },
        };
        state.partition(self.digest)
    }

    /// The trust and credential digest this client was built from.
    pub(crate) const fn digest(&self) -> u64 {
        self.digest
    }

    fn releases_url(&self, identity: &RegistryIdentity<'_>) -> String {
        format!(
            "{}/{}/{}",
            self.registry.url.as_str(),
            identity.scope_key(),
            identity.name_key()
        )
    }

    /// Fetches one page of a release list over this registry's transport, with its credential
    /// when `Trusted`.
    async fn fetch_page(&self, url: &str, origin: &str) -> Result<CachedResponse> {
        let mut headers = vec![RequestHeader::Accept(ACCEPT)];
        match transport_for(self.registry.url.trust()) {
            TransportKind::TrustedOrigin => {
                // Offline, no request is sent, so `security` must not run (it could prompt); the
                // cache is then read under the last online state.
                let (auth, auth_id) = match &self.registry.auth {
                    Some(RegistryAuth::Header(auth)) => (Some(Cow::Borrowed(auth)), None),
                    Some(RegistryAuth::Keychain(credential)) if !self.cache.is_offline() => {
                        let KeychainAuthorization { auth, generation } =
                            credential.authorization().await;
                        let state = CredentialState {
                            presence: if auth.is_some() {
                                CredentialPresence::Credentialed
                            } else {
                                CredentialPresence::Anonymous
                            },
                            generation,
                        };
                        self.note_credential_state(state);
                        (auth.map(Cow::Owned), Some(state.partition(self.digest)))
                    }
                    Some(RegistryAuth::Keychain(credential)) => {
                        (None, Some(self.offline_partition(credential.snapshot())))
                    }
                    None => (None, None),
                };
                if let Some(auth) = auth.as_deref() {
                    headers.push(RequestHeader::Credential(
                        CredentialHeader::Authorization,
                        auth.as_redacted(),
                    ));
                }
                self.cache
                    .get_cached_trusted_origin_response(url, origin, auth_id, &headers)
                    .await
            }
            TransportKind::Pinned => {
                self.cache
                    .get_cached_pinned_response(url, origin, false, None, &headers)
                    .await
            }
        }
    }

    fn recent_pagination_failure(&self, package: &CanonicalIdentity) -> Option<PaginationStop> {
        let entry = self.pagination_failures.get(package)?;
        let (reason, until) = *entry;
        (Instant::now() < until).then_some(reason)
    }

    fn remember_pagination_failure(&self, package: &CanonicalIdentity, reason: PaginationStop) {
        if self.pagination_failures.len() >= MAX_PAGINATION_FAILURES {
            self.pagination_failures.clear();
        }
        self.pagination_failures.insert(
            package.clone(),
            (reason, Instant::now() + PAGINATION_FAILURE_TTL),
        );
    }

    /// Follows `Link: rel="next"` pages from the first releases URL and merges them.
    ///
    /// Every page is revalidated on every call, so a merged list can only be torn when one
    /// page's revalidation fails and that page is served stale (#1802).
    ///
    /// Exceeding any of the [`ListLimits`] fails the whole list.
    async fn fetch_all_releases(
        &self,
        identity: &RegistryIdentity<'_>,
        limits: ListLimits,
        merged_pages: &AtomicUsize,
    ) -> Result<BTreeMap<String, Release>> {
        let package = identity.canonical();
        let incomplete = |reason| DepsError::PaginatedListIncomplete {
            package: package.as_str().into(),
            registry: REGISTRY,
            reason,
        };
        let first_url = self.releases_url(identity);
        let origin = format!("{}/", self.registry.url.as_str());
        let parse_url = |raw: &str| Url::parse(raw).map_err(|_| DepsError::InvalidUri(raw.into()));
        let (first, trusted) = (parse_url(&first_url)?, parse_url(&origin)?);

        let mut seen = HashSet::from([first.clone()]);
        let mut current = first.clone();
        let mut releases = BTreeMap::new();
        let mut body_bytes = 0usize;
        for page_number in 1..=limits.pages {
            let response = self
                .fetch_page(current.as_str(), &origin)
                .await
                .map_err(|e| match (page_number, e.is_not_found()) {
                    (1, _) => not_found_or(e, package.as_str(), REGISTRY, &[410]),
                    (_, true) => incomplete(PaginationStop::InvalidNextLink),
                    (_, false) => e,
                })?;
            body_bytes = body_bytes.saturating_add(response.body.len());
            if body_bytes > limits.body_bytes {
                return Err(incomplete(PaginationStop::PageCap));
            }
            let page: ReleasesResponse =
                deps_core::parse_json_checked(&response.body).map_err(|source| {
                    DepsError::ApiResponse {
                        package: package.as_str().into(),
                        registry: REGISTRY,
                        source,
                    }
                })?;
            for (key, mut release) in page.releases {
                releases
                    .entry(key)
                    .and_modify(|merged: &mut Release| {
                        merged.problem = merged.problem.take().or(release.problem.take());
                    })
                    .or_insert(release);
            }
            merged_pages.fetch_add(1, Ordering::Relaxed);
            if releases.len() > limits.releases {
                return Err(incomplete(PaginationStop::PageCap));
            }

            match next_page(&current, response.link.as_deref(), &trusted) {
                NextPage::Last => return Ok(releases),
                NextPage::Next(next)
                    if next.path() == first.path() && seen.insert(next.clone()) =>
                {
                    current = next;
                }
                NextPage::Next(_) | NextPage::Rejected => {
                    return Err(incomplete(PaginationStop::InvalidNextLink));
                }
            }
        }
        Err(incomplete(PaginationStop::PageCap))
    }

    /// Fetches one release's metadata page, `{releases url}/{raw version}`.
    async fn fetch_release_metadata(
        &self,
        identity: &RegistryIdentity<'_>,
        raw_version: &ReleaseVersion,
    ) -> Result<CachedResponse> {
        let releases_url = self.releases_url(identity);
        let mut url =
            Url::parse(&releases_url).map_err(|_| DepsError::InvalidUri(releases_url.clone()))?;
        url.path_segments_mut()
            .map_err(|()| DepsError::InvalidUri(releases_url))?
            .push(raw_version.as_str());
        self.fetch_page(url.as_str(), &format!("{}/", self.registry.url.as_str()))
            .await
    }

    /// Fills `published_at` of the newest non-yanked releases from the memoized per-release
    /// metadata, fetching what is missing within one bounded batch.
    async fn attach_published_at(
        &self,
        identity: &RegistryIdentity<'_>,
        versions: &mut [SwiftVersion],
        raw_by_version: &HashMap<String, ReleaseVersion>,
    ) {
        let package = identity.canonical();
        let raw_of = |version: &SwiftVersion| raw_by_version.get(version.version.as_str());
        let candidates: Vec<ReleaseVersion> = versions
            .iter()
            .filter(|version| !version.yanked)
            .take(HOVER_RECENT_VERSIONS)
            .filter_map(|version| raw_of(version).cloned())
            .collect();
        self.published_at
            .resolve(&package, &candidates, |raw| {
                let raw = raw.clone();
                async move { self.fetch_release_metadata(identity, &raw).await }
            })
            .await;
        for version in versions
            .iter_mut()
            .filter(|version| !version.yanked)
            .take(HOVER_RECENT_VERSIONS)
        {
            version.published_at =
                raw_of(version).and_then(|raw| self.published_at.get(&package, raw));
        }
    }

    /// Lists `identity`'s releases newest-first; a `releases` key that is not semver is skipped
    /// and a release with a `problem` is marked yanked.
    ///
    /// With [`PublishedAtLookup::Fetch`], the newest [`HOVER_RECENT_VERSIONS`] non-yanked
    /// releases also get their `publishedAt` (see [`crate::published_at`]).
    ///
    /// Follows `Link: rel="next"` pages (bounded by [`ListLimits::DEFAULT`]: pages, merged
    /// releases, total body bytes and time; same origin and path, same credential rules as the
    /// first page) and merges them.
    ///
    /// # Errors
    ///
    /// `PackageNotFound` for 404/410 on the first page, `PaginatedListIncomplete` when the pages
    /// cannot be followed to the last one (the partial list is never returned; the outcome is
    /// remembered for [`PAGINATION_FAILURE_TTL`]), the transport error otherwise, or an
    /// API-response error for an invalid body.
    #[tracing::instrument(skip_all, level = "debug")]
    pub(crate) async fn list_releases(
        &self,
        identity: &RegistryIdentity<'_>,
        lookup: PublishedAtLookup,
    ) -> Result<Vec<SwiftVersion>> {
        let package = identity.canonical();
        if let Some(reason) = self.recent_pagination_failure(&package) {
            return Err(DepsError::PaginatedListIncomplete {
                package: package.as_str().into(),
                registry: REGISTRY,
                reason,
            });
        }
        self.list_releases_within(identity, lookup, ListLimits::DEFAULT)
            .await
    }

    async fn list_releases_within(
        &self,
        identity: &RegistryIdentity<'_>,
        lookup: PublishedAtLookup,
        limits: ListLimits,
    ) -> Result<Vec<SwiftVersion>> {
        let package = identity.canonical();
        let merged_pages = AtomicUsize::new(0);
        let fetched = tokio::time::timeout(
            limits.budget,
            self.fetch_all_releases(identity, limits, &merged_pages),
        )
        .await
        .unwrap_or_else(|_elapsed| {
            if merged_pages.load(Ordering::Relaxed) == 0 {
                // A slow first page is an ordinary transient failure, not a partial list.
                Err(DepsError::CacheError(
                    "registry did not answer within the time budget".into(),
                ))
            } else {
                Err(DepsError::PaginatedListIncomplete {
                    package: package.as_str().into(),
                    registry: REGISTRY,
                    reason: PaginationStop::TimeBudget,
                })
            }
        });
        let releases = fetched.inspect_err(|e| {
            if let DepsError::PaginatedListIncomplete { reason, .. } = e {
                self.remember_pagination_failure(&package, *reason);
            }
        })?;
        let mut raw_by_version = HashMap::new();
        let mut versions = semver_tags_newest_first(
            releases,
            |(key, _)| key.as_str(),
            |(key, release), normalized, parsed| {
                raw_by_version
                    .entry(normalized.to_string())
                    .or_insert(ReleaseVersion::new(key));
                Some(SwiftVersion {
                    version: normalized.into(),
                    yanked: release.problem.is_some(),
                    published_at: None,
                    prerelease: !parsed.pre.is_empty(),
                })
            },
        );
        match lookup {
            PublishedAtLookup::Skip => {}
            PublishedAtLookup::Fetch => {
                self.attach_published_at(identity, &mut versions, &raw_by_version)
                    .await;
            }
        }
        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SwiftCredential;
    use crate::config::{SwiftRegistryUrl, UserTier};
    use deps_core::secret::Redacted;
    use std::assert_matches;

    #[test]
    fn credential_partitions_differ_by_presence_generation_and_digest() {
        let state = |presence, generation| CredentialState {
            presence,
            generation,
        };
        let anonymous = state(CredentialPresence::Anonymous, KeychainGeneration::INITIAL);
        let credentialed = state(
            CredentialPresence::Credentialed,
            KeychainGeneration::INITIAL,
        );
        let later = state(
            CredentialPresence::Credentialed,
            KeychainGeneration::INITIAL.next(),
        );
        let partitions = [
            anonymous.partition(1),
            credentialed.partition(1),
            later.partition(1),
            credentialed.partition(2),
        ];
        let distinct: HashSet<_> = partitions.into_iter().collect();
        assert_eq!(distinct.len(), partitions.len());
    }

    const RELEASES: &str = r#"{"releases": {
        "1.0.0": {"url": "https://r/acme/net/1.0.0"},
        "2.0.0": {"url": "https://r/acme/net/2.0.0"},
        "1.5.0": {"url": "https://r/acme/net/1.5.0", "problem": {"status": 410, "title": "gone"}},
        "latest": {"url": "https://r/acme/net/latest"},
        "2.1.0-beta.1": {"url": "https://r/acme/net/2.1.0-beta.1"}
    }}"#;

    fn identity() -> RegistryIdentity<'static> {
        RegistryIdentity::parse("Acme.Net").unwrap()
    }

    fn client(base: &str, trust: RegistryTrust, token: Option<&str>) -> PackageRegistryClient {
        let url = SwiftRegistryUrl::for_test(base, trust);
        let credential = token.map(|t| SwiftCredential::Token(Redacted::new(t.to_string())));
        let user_tier = UserTier::for_test(&[base], std::collections::HashMap::new());
        let auth = crate::auth::bind_credential(
            &url,
            &user_tier,
            crate::auth::CredentialLookup::shared(credential.as_ref()),
        );
        PackageRegistryClient::new(
            Arc::new(HttpCache::new()),
            ResolvedSwiftRegistry { url, auth },
        )
    }

    #[test]
    fn test_transport_selection_is_a_pure_function_of_trust() {
        assert_eq!(
            transport_for(RegistryTrust::Trusted),
            TransportKind::TrustedOrigin
        );
        assert_eq!(
            transport_for(RegistryTrust::WorkspaceDeclared),
            TransportKind::Pinned
        );
    }

    #[test]
    fn test_releases_url_is_lowercase_with_one_slash() {
        for base in ["https://r.example/api", "https://r.example/api/"] {
            let c = client(base, RegistryTrust::Trusted, None);
            assert_eq!(
                c.releases_url(&identity()),
                "https://r.example/api/acme/net"
            );
        }
        let root = client("https://r.example", RegistryTrust::Trusted, None);
        assert_eq!(root.releases_url(&identity()), "https://r.example/acme/net");
    }

    #[tokio::test]
    async fn test_trusted_request_carries_accept_and_authorization() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/acme/net")
            .match_header("accept", ACCEPT)
            .match_header("authorization", "Bearer t0k")
            .with_status(200)
            .with_body(RELEASES)
            .create_async()
            .await;
        let c = client(
            &format!("{}/api", server.url()),
            RegistryTrust::Trusted,
            Some("t0k"),
        );
        let versions = c
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap();
        mock.assert_async().await;

        let listed: Vec<_> = versions
            .iter()
            .map(|v| (v.version.as_str().to_string(), v.yanked, v.prerelease))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("2.1.0-beta.1".to_string(), false, true),
                ("2.0.0".to_string(), false, false),
                ("1.5.0".to_string(), true, false),
                ("1.0.0".to_string(), false, false),
            ]
        );
    }

    #[tokio::test]
    async fn test_workspace_declared_request_has_no_authorization() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/acme/net")
            .match_header("accept", ACCEPT)
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_body(RELEASES)
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::WorkspaceDeclared, Some("t0k"));
        c.list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_404_and_410_are_package_not_found_and_others_stay_http_status() {
        let mut server = mockito::Server::new_async().await;
        for (status, not_found) in [(404, true), (410, true), (500, false), (401, false)] {
            let mock = server
                .mock("GET", "/acme/net")
                .with_status(status)
                .create_async()
                .await;
            let c = client(&server.url(), RegistryTrust::Trusted, None);
            let err = c
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap_err();
            if not_found {
                assert_matches!(err, DepsError::PackageNotFound { .. }, "{status}");
            } else {
                assert_matches!(err, DepsError::HttpStatus { .. }, "{status}");
            }
            mock.remove_async().await;
        }
    }

    fn next_link(url: &str) -> String {
        format!(r#"<{url}>; rel="next""#)
    }

    async fn mock_page(
        server: &mut mockito::ServerGuard,
        path_and_query: &str,
        link: Option<String>,
        releases: &str,
    ) -> mockito::Mock {
        let mut mock = server.mock("GET", path_and_query).with_status(200);
        if let Some(link) = link {
            mock = mock.with_header("link", &link);
        }
        mock.with_body(format!(r#"{{"releases": {{{releases}}}}}"#))
            .create_async()
            .await
    }

    fn versions_of(versions: &[SwiftVersion]) -> Vec<(String, bool)> {
        versions
            .iter()
            .map(|v| (v.version.as_str().to_string(), v.yanked))
            .collect()
    }

    #[tokio::test]
    async fn test_rel_next_pages_are_followed_and_merged() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _p1 = mock_page(
            &mut server,
            "/acme/net",
            Some(next_link(&format!("{base}/acme/net?page=2"))),
            r#""1.0.0": {}, "1.1.0": {}"#,
        )
        .await;
        let _p2 = mock_page(
            &mut server,
            "/acme/net?page=2",
            Some(next_link(&format!("{base}/acme/net?page=3"))),
            r#""2.0.0": {}, "1.1.0": {"problem": {"status": 410}}"#,
        )
        .await;
        let _p3 = mock_page(&mut server, "/acme/net?page=3", None, r#""3.0.0": {}"#).await;

        let c = client(&base, RegistryTrust::Trusted, None);
        let versions = c
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap();
        assert_eq!(
            versions_of(&versions),
            vec![
                ("3.0.0".to_string(), false),
                ("2.0.0".to_string(), false),
                ("1.1.0".to_string(), true),
                ("1.0.0".to_string(), false),
            ]
        );
    }

    #[tokio::test]
    async fn test_authorization_is_sent_on_every_page_when_trusted_and_never_when_declared() {
        for (trust, expected) in [
            (
                RegistryTrust::Trusted,
                mockito::Matcher::Exact("Bearer t0k".to_string()),
            ),
            (RegistryTrust::WorkspaceDeclared, mockito::Matcher::Missing),
        ] {
            let mut server = mockito::Server::new_async().await;
            let base = server.url();
            let _p1 = server
                .mock("GET", "/acme/net")
                .with_header("link", &next_link(&format!("{base}/acme/net?page=2")))
                .with_body(r#"{"releases": {"1.0.0": {}}}"#)
                .create_async()
                .await;
            let p2 = server
                .mock("GET", "/acme/net?page=2")
                .match_header("authorization", expected)
                .with_body(r#"{"releases": {"2.0.0": {}}}"#)
                .create_async()
                .await;
            let c = client(&base, trust, Some("t0k"));
            assert_eq!(
                c.list_releases(&identity(), PublishedAtLookup::Skip)
                    .await
                    .unwrap()
                    .len(),
                2
            );
            p2.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_page_cap_fails_and_the_failure_is_memoized() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let mut pages = Vec::new();
        for n in 1..=ListLimits::DEFAULT.pages {
            let path = if n == 1 {
                "/acme/net".to_string()
            } else {
                format!("/acme/net?page={n}")
            };
            let link = next_link(&format!("{base}/acme/net?page={}", n + 1));
            pages.push(
                server
                    .mock("GET", path.as_str())
                    .with_header("link", &link)
                    .with_body(format!(r#"{{"releases": {{"{n}.0.0": {{}}}}}}"#))
                    .expect(1)
                    .create_async()
                    .await,
            );
        }
        let c = client(&base, RegistryTrust::Trusted, None);
        for _ in 0..2 {
            let err = c
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap_err();
            assert_matches!(
                err,
                DepsError::PaginatedListIncomplete {
                    reason: PaginationStop::PageCap,
                    ..
                }
            );
        }
        for page in pages {
            page.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_unusable_next_links_fail_without_following_them() {
        let mut server = mockito::Server::new_async().await;
        let mut other = mockito::Server::new_async().await;
        let base = server.url();
        let escaped = other
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let wrong_path = server
            .mock("GET", "/acme/other?page=2")
            .expect(0)
            .create_async()
            .await;
        let userinfo = base.replacen("http://", "http://u:p@", 1);
        let links = [
            format!(r#"<{}/acme/net>; rel="next""#, other.url()),
            format!(r#"<{base}/acme/other?page=2>; rel="next""#),
            format!(r#"<{userinfo}/acme/net?page=2>; rel="next""#),
            r#"<>; rel="next""#.to_string(),
            format!(r#"<{base}/acme/net>; rel="next""#),
            format!(
                r#"<{base}/acme/net?page=2>; rel="next", <{base}/acme/net?page=3>; rel="next""#
            ),
        ];
        for link in links {
            let first = server
                .mock("GET", "/acme/net")
                .with_header("link", &link)
                .with_body(r#"{"releases": {"1.0.0": {}}}"#)
                .create_async()
                .await;
            let c = client(&base, RegistryTrust::Trusted, Some("t0k"));
            let err = c
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap_err();
            assert_matches!(
                err,
                DepsError::PaginatedListIncomplete {
                    reason: PaginationStop::InvalidNextLink,
                    ..
                },
                "{link}"
            );
            first.remove_async().await;
        }
        escaped.assert_async().await;
        wrong_path.assert_async().await;
    }

    fn limits_with(change: impl FnOnce(&mut ListLimits)) -> ListLimits {
        let mut limits = ListLimits::DEFAULT;
        change(&mut limits);
        limits
    }

    #[tokio::test]
    async fn test_release_count_and_body_size_caps_fail_the_list_and_are_memoized() {
        let tight = [
            limits_with(|limits| limits.releases = 3),
            limits_with(|limits| limits.body_bytes = 40),
        ];
        for limits in tight {
            let mut server = mockito::Server::new_async().await;
            let base = server.url();
            let page1 = mock_page(
                &mut server,
                "/acme/net",
                Some(next_link(&format!("{base}/acme/net?page=2"))),
                r#""1.0.0": {}, "1.1.0": {}"#,
            )
            .await
            .expect(1);
            let page2 = mock_page(
                &mut server,
                "/acme/net?page=2",
                None,
                r#""2.0.0": {}, "2.1.0": {}"#,
            )
            .await
            .expect(1);
            let c = client(&base, RegistryTrust::Trusted, None);
            let first = c
                .list_releases_within(&identity(), PublishedAtLookup::Skip, limits)
                .await;
            let second = c.list_releases(&identity(), PublishedAtLookup::Skip).await;
            for err in [first.unwrap_err(), second.unwrap_err()] {
                assert_matches!(
                    err,
                    DepsError::PaginatedListIncomplete {
                        reason: PaginationStop::PageCap,
                        ..
                    },
                    "{limits:?}"
                );
            }
            page1.assert_async().await;
            page2.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_a_slow_later_page_hits_the_overall_budget_and_is_memoized() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _p1 = mock_page(
            &mut server,
            "/acme/net",
            Some(next_link(&format!("{base}/acme/net?page=2"))),
            r#""1.0.0": {}"#,
        )
        .await;
        let _slow = server
            .mock("GET", "/acme/net?page=2")
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_millis(600));
                writer.write_all(br#"{"releases": {"2.0.0": {}}}"#)
            })
            .create_async()
            .await;
        let c = client(&base, RegistryTrust::Trusted, None);
        let limits = limits_with(|limits| limits.budget = Duration::from_millis(300));
        let first = c
            .list_releases_within(&identity(), PublishedAtLookup::Skip, limits)
            .await;
        let again = c.list_releases(&identity(), PublishedAtLookup::Skip).await;
        for err in [first.unwrap_err(), again.unwrap_err()] {
            assert_matches!(
                err,
                DepsError::PaginatedListIncomplete {
                    reason: PaginationStop::TimeBudget,
                    ..
                }
            );
        }
    }

    #[tokio::test]
    async fn test_a_slow_first_page_is_a_transient_failure_not_a_partial_list() {
        let mut server = mockito::Server::new_async().await;
        let _slow = server
            .mock("GET", "/acme/net")
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_millis(600));
                writer.write_all(br#"{"releases": {"1.0.0": {}}}"#)
            })
            .expect_at_least(2)
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::Trusted, None);
        let limits = limits_with(|limits| limits.budget = Duration::from_millis(100));
        let err = c
            .list_releases_within(&identity(), PublishedAtLookup::Skip, limits)
            .await
            .unwrap_err();
        assert_matches!(err.fetch_failure(), deps_core::FetchFailure::Transient);
        assert_matches!(
            c.list_releases_within(&identity(), PublishedAtLookup::Skip, limits)
                .await
                .unwrap_err()
                .fetch_failure(),
            deps_core::FetchFailure::Transient,
            "not memoized: the second call goes to the registry again"
        );
    }

    #[tokio::test]
    async fn test_a_cycle_back_to_an_earlier_page_fails() {
        for (page2_next, page3_next) in [(2, 3), (3, 2)] {
            let mut server = mockito::Server::new_async().await;
            let base = server.url();
            let link = |n: u32| Some(next_link(&format!("{base}/acme/net?page={n}")));
            let _p1 = mock_page(&mut server, "/acme/net", link(2), r#""1.0.0": {}"#).await;
            let _p2 = mock_page(
                &mut server,
                "/acme/net?page=2",
                link(page2_next),
                r#""2.0.0": {}"#,
            )
            .await;
            let _p3 = mock_page(
                &mut server,
                "/acme/net?page=3",
                link(page3_next),
                r#""3.0.0": {}"#,
            )
            .await;
            let c = client(&base, RegistryTrust::Trusted, None);
            assert_matches!(
                c.list_releases(&identity(), PublishedAtLookup::Skip)
                    .await
                    .unwrap_err(),
                DepsError::PaginatedListIncomplete {
                    reason: PaginationStop::InvalidNextLink,
                    ..
                },
                "{page2_next}->{page3_next}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_missing_later_page_is_an_incomplete_list_not_an_unknown_package() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _p1 = mock_page(
            &mut server,
            "/acme/net",
            Some(next_link(&format!("{base}/acme/net?page=2"))),
            r#""1.0.0": {}"#,
        )
        .await;
        let _p2 = server
            .mock("GET", "/acme/net?page=2")
            .with_status(404)
            .create_async()
            .await;
        let c = client(&base, RegistryTrust::Trusted, None);
        let err = c
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap_err();
        assert!(!err.is_not_found(), "{err:?}");
        assert_matches!(err, DepsError::PaginatedListIncomplete { .. });
    }

    fn many_releases() -> String {
        let releases: Vec<String> = (1..=10)
            .map(|n| format!(r#""{n}.0.0": {{}}"#))
            .chain(std::iter::once(
                r#""11.0.0": {"problem": {"status": 410}}"#.to_string(),
            ))
            .collect();
        format!(r#"{{"releases": {{{}}}}}"#, releases.join(","))
    }

    #[tokio::test]
    async fn test_published_at_covers_the_newest_eight_non_yanked_releases_once() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/acme/net")
            .with_body(many_releases())
            .create_async()
            .await;
        let mut dated = Vec::new();
        for n in 3..=10 {
            dated.push(
                server
                    .mock("GET", format!("/acme/net/{n}.0.0").as_str())
                    .match_header("authorization", "Bearer t0k")
                    .with_body(format!(
                        r#"{{"publishedAt": "2025-01-{n:02}T00:00:00.500Z"}}"#
                    ))
                    .expect(1)
                    .create_async()
                    .await,
            );
        }
        let untouched = [
            server
                .mock("GET", "/acme/net/11.0.0")
                .expect(0)
                .create_async()
                .await,
            server
                .mock("GET", "/acme/net/2.0.0")
                .expect(0)
                .create_async()
                .await,
            server
                .mock("GET", "/acme/net/1.0.0")
                .expect(0)
                .create_async()
                .await,
        ];

        let c = client(&server.url(), RegistryTrust::Trusted, Some("t0k"));
        for _ in 0..2 {
            let versions = c
                .list_releases(&identity(), PublishedAtLookup::Fetch)
                .await
                .unwrap();
            let dates: Vec<bool> = versions.iter().map(|v| v.published_at.is_some()).collect();
            assert_eq!(
                dates,
                [
                    false, true, true, true, true, true, true, true, true, false, false
                ]
            );
        }
        for mock in dated.iter().chain(untouched.iter()) {
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_published_at_failures_never_fail_the_list_and_skip_sends_no_requests() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/acme/net")
            .with_body(RELEASES)
            .create_async()
            .await;
        let _broken = server
            .mock("GET", "/acme/net/2.0.0")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let _garbage = server
            .mock("GET", "/acme/net/1.0.0")
            .with_body("not json")
            .expect(1)
            .create_async()
            .await;
        let _gone = server
            .mock("GET", "/acme/net/2.1.0-beta.1")
            .with_status(410)
            .expect(1)
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::Trusted, None);

        let versions = c
            .list_releases(&identity(), PublishedAtLookup::Fetch)
            .await
            .unwrap();
        assert_eq!(versions.len(), 4);
        assert!(versions.iter().all(|v| v.published_at.is_none()));

        let skipped = client(&server.url(), RegistryTrust::Trusted, None);
        let none_requested = server
            .mock("GET", mockito::Matcher::Regex("^/acme/net/.+".into()))
            .expect(0)
            .create_async()
            .await;
        skipped
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap();
        none_requested.assert_async().await;
    }

    #[tokio::test]
    async fn test_a_policy_blocked_registry_host_is_actionable() {
        let server = mockito::Server::new_async().await;
        let port = server.socket_address().port();
        // Built directly against a `localhost` name, bypassing config validation.
        let c = client(
            &format!("http://localhost:{port}"),
            RegistryTrust::WorkspaceDeclared,
            None,
        );
        let err = c
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap_err();
        assert_matches!(
            err.fetch_failure(),
            deps_core::FetchFailure::Actionable(message)
                if message.contains("loopback") && message.contains("never a registry")
        );
    }

    #[tokio::test]
    async fn test_non_next_link_relations_do_not_truncate() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/acme/net")
            .with_status(200)
            .with_header(
                "link",
                r#"<https://r.example/acme/net>; rel="latest-version", <https://r.example/c>; rel="canonical""#,
            )
            .with_body(RELEASES)
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::Trusted, None);
        assert_eq!(
            c.list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap()
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn test_invalid_body_is_an_api_response_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/acme/net")
            .with_status(200)
            .with_body("not json")
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::Trusted, None);
        assert_matches!(
            c.list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap_err(),
            DepsError::ApiResponse { .. }
        );
    }

    #[tokio::test]
    async fn test_basic_credential_is_sent_as_a_basic_authorization_header() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let mock = server
            .mock("GET", "/acme/net")
            .match_header("authorization", "Basic dTpw")
            .with_status(200)
            .with_body(RELEASES)
            .create_async()
            .await;
        let url = SwiftRegistryUrl::for_test(&base, RegistryTrust::Trusted);
        let host = crate::config::RegistryHostKey::parse(&format!(
            "{}:{}",
            url::Url::parse(&base).unwrap().host_str().unwrap(),
            url::Url::parse(&base).unwrap().port().unwrap()
        ))
        .unwrap();
        let tier = UserTier::for_test(
            &[&base],
            std::collections::HashMap::from([(host, crate::config::SwiftAuthType::Basic)]),
        );
        let credential = SwiftCredential::Login {
            username: Redacted::new("u".to_string()),
            password: Redacted::new("p".to_string()),
        };
        let auth = crate::auth::bind_credential(
            &url,
            &tier,
            crate::auth::CredentialLookup::Shared(&credential),
        );
        let client = PackageRegistryClient::new(
            Arc::new(HttpCache::new()),
            ResolvedSwiftRegistry { url, auth },
        );
        client
            .list_releases(&identity(), PublishedAtLookup::Skip)
            .await
            .unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_same_origin_redirect_outside_the_base_path_is_refused() {
        for trust in [RegistryTrust::Trusted, RegistryTrust::WorkspaceDeclared] {
            let mut server = mockito::Server::new_async().await;
            let target = format!("{}/other/acme/net", server.url());
            let _redirect = server
                .mock("GET", "/api/acme/net")
                .with_status(302)
                .with_header("location", &target)
                .create_async()
                .await;
            let escaped = server
                .mock("GET", "/other/acme/net")
                .with_status(200)
                .with_body(RELEASES)
                .expect(0)
                .create_async()
                .await;
            let c = client(&format!("{}/api", server.url()), trust, Some("t0k"));
            assert!(
                c.list_releases(&identity(), PublishedAtLookup::Skip)
                    .await
                    .is_err(),
                "{trust:?}"
            );
            escaped.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_same_origin_redirect_inside_the_base_path_is_followed() {
        let mut server = mockito::Server::new_async().await;
        let target = format!("{}/api/moved/acme/net", server.url());
        let _redirect = server
            .mock("GET", "/api/acme/net")
            .with_status(302)
            .with_header("location", &target)
            .create_async()
            .await;
        let _moved = server
            .mock("GET", "/api/moved/acme/net")
            .with_status(200)
            .with_body(RELEASES)
            .create_async()
            .await;
        let c = client(
            &format!("{}/api", server.url()),
            RegistryTrust::Trusted,
            None,
        );
        assert_eq!(
            c.list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap()
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn test_cross_origin_redirect_is_refused_on_both_transports() {
        for trust in [RegistryTrust::Trusted, RegistryTrust::WorkspaceDeclared] {
            let mut server = mockito::Server::new_async().await;
            let mut other = mockito::Server::new_async().await;
            let target = format!("{}/acme/net", other.url());
            let _redirect = server
                .mock("GET", "/acme/net")
                .with_status(302)
                .with_header("location", &target)
                .create_async()
                .await;
            let escaped = other
                .mock("GET", "/acme/net")
                .with_status(200)
                .with_body(RELEASES)
                .expect(0)
                .create_async()
                .await;
            let c = client(&server.url(), trust, Some("t0k"));
            assert!(
                c.list_releases(&identity(), PublishedAtLookup::Skip)
                    .await
                    .is_err(),
                "{trust:?}"
            );
            escaped.assert_async().await;
        }
    }

    mod keychain {
        use super::*;
        use crate::auth::{CredentialLookup, KeychainBinding};
        use crate::keychain::KeychainError;
        use crate::keychain::KeychainStore;
        use crate::keychain::fake::Fake;
        use deps_core::keychain_credentials::KeychainCredentialsHandle;
        use deps_core::policy_config::KeychainCredentials;

        fn keychain_client(
            base: &str,
            fake: &Fake,
        ) -> (PackageRegistryClient, Arc<KeychainCredentialsHandle>) {
            let handle = Arc::new(KeychainCredentialsHandle::new(KeychainCredentials::Enabled));
            let store = Arc::new(KeychainStore::new(fake.clone(), handle.resolved_sender()));
            let binding = KeychainBinding::new(store, Arc::clone(&handle));
            let url = SwiftRegistryUrl::for_test(base, RegistryTrust::Trusted);
            let user_tier = UserTier::for_test(&[base], std::collections::HashMap::new());
            let auth = crate::auth::bind_credential(
                &url,
                &user_tier,
                CredentialLookup::Keychain(&binding),
            );
            let client = PackageRegistryClient::new(
                Arc::new(HttpCache::new()),
                ResolvedSwiftRegistry { url, auth },
            );
            (client, handle)
        }

        #[tokio::test]
        async fn test_found_credential_is_sent_as_basic_authorization() {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", "Basic dXNlcjpodW50ZXIy")
                .with_status(200)
                .with_body(RELEASES)
                .create_async()
                .await;
            let fake = Fake::found();
            let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            mock.assert_async().await;
        }

        #[tokio::test]
        async fn test_not_found_sends_no_credential() {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .with_status(200)
                .with_body(RELEASES)
                .create_async()
                .await;
            let fake = Fake::new(Err(KeychainError::NotFound), Ok("unused"));
            let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            mock.assert_async().await;
        }

        #[tokio::test]
        async fn test_a_401_never_triggers_another_lookup() {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/api/acme/net")
                .with_status(401)
                .expect_at_least(2)
                .create_async()
                .await;
            let fake = Fake::found();
            let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            for _ in 0..2 {
                assert!(
                    client
                        .list_releases(&identity(), PublishedAtLookup::Skip)
                        .await
                        .is_err()
                );
            }
            mock.assert_async().await;
            assert_eq!(fake.secret_calls(), 1);
        }

        #[tokio::test]
        async fn test_refused_and_transient_send_no_credential() {
            for reply in [KeychainError::Refused, KeychainError::Transient] {
                let mut server = mockito::Server::new_async().await;
                let mock = server
                    .mock("GET", "/api/acme/net")
                    .match_header("authorization", mockito::Matcher::Missing)
                    .with_status(200)
                    .with_body(RELEASES)
                    .create_async()
                    .await;
                let fake = Fake::new(Ok("user"), Err(reply));
                let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);
                client
                    .list_releases(&identity(), PublishedAtLookup::Skip)
                    .await
                    .unwrap();
                mock.assert_async().await;
            }
        }

        const ANON_RELEASES: &str =
            r#"{"releases": {"1.0.0": {"url": "https://r/acme/net/1.0.0"}}}"#;
        const BASIC: &str = "Basic dXNlcjpodW50ZXIy";

        fn versions_of(versions: &[SwiftVersion]) -> Vec<String> {
            versions
                .iter()
                .map(|v| v.version.as_str().to_string())
                .collect()
        }

        #[tokio::test]
        async fn test_an_anonymous_response_never_answers_the_credentialed_request() {
            let mut server = mockito::Server::new_async().await;
            let anonymous = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .with_status(200)
                .with_header("etag", "\"v1\"")
                .with_body(ANON_RELEASES)
                .create_async()
                .await;
            let stale_revalidation = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", BASIC)
                .match_header("if-none-match", "\"v1\"")
                .with_status(304)
                .expect(0)
                .create_async()
                .await;
            let credentialed = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", BASIC)
                .match_header("if-none-match", mockito::Matcher::Missing)
                .with_status(200)
                .with_body(RELEASES)
                .create_async()
                .await;
            let fake = Fake::new(Ok("user"), Err(KeychainError::Transient));
            let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);

            let first = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            assert_eq!(versions_of(&first), ["1.0.0"]);

            fake.set_secret(Ok("hunter2"));
            let second = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            assert!(versions_of(&second).contains(&"2.0.0".to_string()));
            anonymous.assert_async().await;
            credentialed.assert_async().await;
            stale_revalidation.assert_async().await;
        }

        #[tokio::test]
        async fn test_a_credentialed_response_is_not_served_after_the_setting_is_disabled() {
            let mut server = mockito::Server::new_async().await;
            let credentialed = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", BASIC)
                .with_status(200)
                .with_header("etag", "\"v2\"")
                .with_body(RELEASES)
                .create_async()
                .await;
            let stale_revalidation = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .match_header("if-none-match", "\"v2\"")
                .with_status(304)
                .expect(0)
                .create_async()
                .await;
            let anonymous = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .match_header("if-none-match", mockito::Matcher::Missing)
                .with_status(200)
                .with_body(ANON_RELEASES)
                .create_async()
                .await;
            let fake = Fake::found();
            let (client, handle) = keychain_client(&format!("{}/api", server.url()), &fake);

            let first = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            assert!(versions_of(&first).contains(&"2.0.0".to_string()));

            handle.set(KeychainCredentials::Disabled);
            let second = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            assert_eq!(versions_of(&second), ["1.0.0"]);
            credentialed.assert_async().await;
            anonymous.assert_async().await;
            stale_revalidation.assert_async().await;
        }

        #[tokio::test]
        async fn test_offline_never_runs_the_keychain_lookup() {
            let fake = Fake::found();
            let (client, _handle) = keychain_client("https://r.example/api", &fake);
            client.cache.set_offline(deps_core::NetworkMode::Offline);
            let result = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await;
            assert!(result.is_err());
            assert_eq!(fake.find_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(fake.secret_calls(), 0);
        }

        /// Mocks the credentialed releases response, served exactly once.
        async fn credentialed_releases_mock(server: &mut mockito::ServerGuard) -> mockito::Mock {
            server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", "Basic dXNlcjpodW50ZXIy")
                .with_status(200)
                .with_body(RELEASES)
                .expect(1)
                .create_async()
                .await
        }

        /// While the last online state is still current, an offline read is served from the
        /// cache under that state's partition.
        #[tokio::test]
        async fn test_offline_reads_under_the_last_online_partition_while_it_is_current() {
            let mut server = mockito::Server::new_async().await;
            let mock = credentialed_releases_mock(&mut server).await;
            let fake = Fake::found();
            let (client, _handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            client.cache.set_offline(deps_core::NetworkMode::Offline);

            let offline = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await;
            assert!(offline.is_ok(), "{offline:?}");
            mock.assert_async().await;
        }

        /// L1: after the setting is disabled, an offline read must not be answered from a body
        /// that was fetched under the withdrawn credential.
        #[tokio::test]
        async fn test_offline_does_not_serve_a_credentialed_body_after_the_setting_is_disabled() {
            let mut server = mockito::Server::new_async().await;
            let mock = credentialed_releases_mock(&mut server).await;
            let fake = Fake::found();
            let (client, handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            handle.set(KeychainCredentials::Disabled);
            client.cache.set_offline(deps_core::NetworkMode::Offline);

            let offline = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await;
            assert!(offline.is_err(), "{offline:?}");
            mock.assert_async().await;
        }

        /// A body fetched anonymously (setting off) never answers an offline request once the
        /// setting is enabled again: the generation moved on, so the read misses.
        #[tokio::test]
        async fn test_offline_anonymous_body_cannot_answer_after_the_setting_is_enabled() {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .with_status(200)
                .with_body(RELEASES)
                .expect(1)
                .create_async()
                .await;
            let fake = Fake::found();
            let (client, handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            handle.set(KeychainCredentials::Disabled);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            handle.set(KeychainCredentials::Enabled);
            client.cache.set_offline(deps_core::NetworkMode::Offline);

            let offline = client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await;
            assert!(offline.is_err(), "{offline:?}");
            mock.assert_async().await;
        }

        #[tokio::test]
        async fn test_disabling_the_setting_stops_sending_the_credential() {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/api/acme/net")
                .match_header("authorization", mockito::Matcher::Missing)
                .with_status(200)
                .with_body(RELEASES)
                .create_async()
                .await;
            let fake = Fake::found();
            let (client, handle) = keychain_client(&format!("{}/api", server.url()), &fake);
            handle.set(KeychainCredentials::Disabled);
            client
                .list_releases(&identity(), PublishedAtLookup::Skip)
                .await
                .unwrap();
            mock.assert_async().await;
            assert_eq!(fake.secret_calls(), 0);
        }
    }
}
