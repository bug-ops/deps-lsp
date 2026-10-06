//! SE-0292 package registry client: `GET {base}/{scope}/{name}` lists a package's releases.
//!
//! One client per registry URL. A `Trusted` registry goes through the origin-pinned, baseline
//! guarded transport and may carry the environment credential; a `WorkspaceDeclared` one goes
//! through the connect-address-guarded pinned transport, unauthenticated.

use std::collections::BTreeMap;
use std::sync::Arc;

use deps_core::github::semver_tags_newest_first;
use deps_core::pagination::ListCoverage;
use deps_core::{DepsError, HttpCache, Result, not_found_or};
use reqwest::header;
use serde::Deserialize;

use crate::config::{RegistryTrust, ResolvedSwiftRegistry};
use crate::package_location::RegistryIdentity;
use crate::types::SwiftVersion;

const ACCEPT: &str = "application/vnd.swift.registry.v1+json";

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

/// A client for one SE-0292 registry.
pub(crate) struct PackageRegistryClient {
    cache: Arc<HttpCache>,
    registry: ResolvedSwiftRegistry,
    digest: u64,
}

impl PackageRegistryClient {
    pub(crate) fn new(cache: Arc<HttpCache>, registry: ResolvedSwiftRegistry) -> Self {
        let digest = registry.digest();
        Self {
            cache,
            registry,
            digest,
        }
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

    /// Lists `identity`'s releases newest-first; a `releases` key that is not semver is skipped
    /// and a release with a `problem` is marked yanked.
    ///
    /// # Errors
    ///
    /// `PackageNotFound` for 404/410, `PaginatedListUnsupported` when the response carries a
    /// `Link` with `rel="next"` (the page is discarded, never reported as the full list), the
    /// transport error otherwise, or an API-response error for an invalid body.
    #[tracing::instrument(skip_all, level = "debug")]
    pub(crate) async fn list_releases(
        &self,
        identity: &RegistryIdentity<'_>,
    ) -> Result<Vec<SwiftVersion>> {
        let package = identity.canonical();
        let url = self.releases_url(identity);
        let origin = format!("{}/", self.registry.url.as_str());

        let mut headers = vec![(header::ACCEPT, ACCEPT)];
        let response = match transport_for(self.registry.url.trust()) {
            TransportKind::TrustedOrigin => {
                if let Some(auth) = &self.registry.auth {
                    headers.push((header::AUTHORIZATION, auth.header_value()));
                }
                self.cache
                    .get_cached_trusted_origin_response(&url, &origin, &headers)
                    .await
            }
            TransportKind::Pinned => {
                self.cache
                    .get_cached_pinned_response(&url, &origin, false, None, &headers)
                    .await
            }
        }
        .map_err(|e| not_found_or(e, &package, REGISTRY, &[410]))?;

        if ListCoverage::from_link_header(response.link.as_deref()) == ListCoverage::Truncated {
            return Err(DepsError::PaginatedListUnsupported {
                package: package.as_str().into(),
                registry: REGISTRY,
            });
        }

        let parsed: ReleasesResponse =
            deps_core::parse_json_checked(&response.body).map_err(|source| {
                DepsError::ApiResponse {
                    package: package.as_str().into(),
                    registry: REGISTRY,
                    source,
                }
            })?;
        Ok(semver_tags_newest_first(
            parsed.releases,
            |(key, _)| key.as_str(),
            |(_, release), normalized, parsed| {
                Some(SwiftVersion {
                    version: normalized.into(),
                    yanked: release.problem.is_some(),
                    published_at: None,
                    prerelease: !parsed.pre.is_empty(),
                })
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SwiftEnvCredential;
    use crate::config::{SwiftRegistryUrl, UserTier};
    use deps_core::secret::Redacted;
    use std::assert_matches;

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
        let credential = token.map(|t| SwiftEnvCredential::Token(Redacted::new(t.to_string())));
        let user_tier = UserTier::for_test(&[base], std::collections::HashMap::new());
        let auth = crate::auth::bind_credential(&url, &user_tier, credential.as_ref());
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
        let versions = c.list_releases(&identity()).await.unwrap();
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
        c.list_releases(&identity()).await.unwrap();
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
            let err = c.list_releases(&identity()).await.unwrap_err();
            if not_found {
                assert_matches!(err, DepsError::PackageNotFound { .. }, "{status}");
            } else {
                assert_matches!(err, DepsError::HttpStatus { .. }, "{status}");
            }
            mock.remove_async().await;
        }
    }

    #[tokio::test]
    async fn test_rel_next_link_discards_the_page() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/acme/net")
            .with_status(200)
            .with_header("link", r#"<https://r.example/acme/net?page=2>; rel="next""#)
            .with_body(RELEASES)
            .create_async()
            .await;
        let c = client(&server.url(), RegistryTrust::Trusted, None);
        let err = c.list_releases(&identity()).await.unwrap_err();
        assert_matches!(err, DepsError::PaginatedListUnsupported { .. });
        assert_matches!(
            err.fetch_failure(),
            deps_core::FetchFailure::Actionable(message)
                if message == "registry paginates its release list; pagination is not supported yet"
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
        assert_eq!(c.list_releases(&identity()).await.unwrap().len(), 4);
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
            c.list_releases(&identity()).await.unwrap_err(),
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
        let credential = SwiftEnvCredential::Login {
            username: Redacted::new("u".to_string()),
            password: Redacted::new("p".to_string()),
        };
        let auth = crate::auth::bind_credential(&url, &tier, Some(&credential));
        let client = PackageRegistryClient::new(
            Arc::new(HttpCache::new()),
            ResolvedSwiftRegistry { url, auth },
        );
        client.list_releases(&identity()).await.unwrap();
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
            assert!(c.list_releases(&identity()).await.is_err(), "{trust:?}");
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
        assert_eq!(c.list_releases(&identity()).await.unwrap().len(), 4);
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
            assert!(c.list_releases(&identity()).await.is_err(), "{trust:?}");
            escaped.assert_async().await;
        }
    }
}
