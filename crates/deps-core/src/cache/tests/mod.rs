use std::assert_matches;

use super::auth::CredentialHeader;
use super::auth::KeyAuth;
use super::auth::RateLimitRevocation;
use super::auth::RequestAuth;
use super::auth::RequestHeader;
use super::auth::WireHeader;
use super::auth::apply_request_headers;
use super::body::BodyLimit;
use super::body::MAX_RESPONSE_BYTES;
use super::errors::confirmed_rate_limit_exhaustion;
use super::errors::preflight_error;
use super::errors::send_error;
use super::guard::AddrGuard;
use super::guard::ensure_https;
use super::guard::hop_targets_blocked_host;
use super::guard::is_https_downgrade;
use super::redirect::RedirectScope;
use super::redirect::redirect_policy;
use super::redirect::trusted_origin_redirect_policy;
use super::resolver::BlockedAddrResolver;
use super::resolver::ResolveGuardError;
use super::resolver::TestLookup;
use super::resolver::validate_resolved_addrs;
use super::response::CachedResponse;
use super::response::CredentialPartition;
use super::response::RevalidationFailure;
use super::transport::HTTP_CONNECT_TIMEOUT_SECS;
use super::transport::HTTP_TIMEOUT_SECS;
use super::transport::ProxyRoute;
use super::transport::Transport;
use super::transport::base_client_builder;
use super::transport::build_guarded_client_with_lookup;
use super::*;
use crate::error::RateLimitEvidence;
use crate::net_policy::{
    AccessSnapshot, BlockedHost, GuardedEgress, PrivateRegistryAllowlist, SystemProxy,
    normalize_host,
};
use crate::secret::{AuthorizationValue, Redacted, bearer_auth_header};
use bytes::Bytes;
use reqwest::{Client, StatusCode, Url, header};
use std::time::Instant;

mod auth;
mod contact;
mod entries;
mod errors;
mod guard;
mod offline;
mod proxy;
mod redirect;
mod resolver;
mod revalidation;
mod transport_only;

fn bearer(token: &str) -> AuthorizationValue {
    bearer_auth_header(&Redacted::new(token.to_string()))
}

fn workspace_guard(level: WorkspaceRegistryAccess, allowlist: &[&str]) -> AddrGuard {
    AddrGuard::WorkspaceDeclared(AccessSnapshot {
        level,
        allowlist: Arc::new(PrivateRegistryAllowlist::for_test(allowlist)),
    })
}

fn authorization(token: &AuthorizationValue) -> WireHeader<'_> {
    WireHeader::Credential(CredentialHeader::Authorization(token))
}

fn test_token() -> &'static AuthorizationValue {
    static TOKEN: std::sync::OnceLock<AuthorizationValue> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| bearer("test-token"))
}

fn cred_in(partition: u64) -> RequestAuth<'static> {
    RequestAuth::credential_in(
        CredentialHeader::Authorization(test_token()),
        CredentialPartition::new(partition),
    )
}

fn prefix(raw: &str) -> TrustedPrefix {
    TrustedPrefix::parse(raw).unwrap()
}

fn credential<'a>(token: &'a AuthorizationValue, prefix: &TrustedPrefix) -> RequestAuth<'a> {
    RequestAuth::credential(CredentialHeader::Authorization(token), prefix)
}

const NEXT_LINK: &str = r#"<https://r.example/p?page=2>; rel="next""#;

fn dummy_response(size: usize) -> CachedResponse {
    CachedResponse {
        body: Bytes::from(vec![0u8; size]),
        etag: None,
        last_modified: None,
        link: None,
        fetched_at: Instant::now(),
    }
}

fn pinned_tier(digest: u64) -> CacheTier {
    CacheTier::Pinned { digest }
}

fn partition(raw: u64) -> CredentialPartition {
    CredentialPartition::new(raw)
}

async fn warm_entry_under(
    server: &mut mockito::ServerGuard,
    cache: &HttpCache,
    auth: RequestAuth<'_>,
) -> (String, String) {
    let origin = format!("{}/", server.url());
    let url = format!("{}/api/data", server.url());
    let _warm = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_header("etag", "\"abc123\"")
        .with_body("private data")
        .create_async()
        .await;
    cache
        .get_cached_trusted_origin(&url, &prefix(&origin), auth, None)
        .await
        .unwrap();
    assert_eq!(cache.len(), 1);
    (origin, url)
}

/// A TCP listener standing in for an HTTP proxy: records the first line of every request
/// head it receives and answers 502.
async fn recording_proxy() -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                if let Ok(read) = stream.read(&mut buf).await {
                    let head = String::from_utf8_lossy(&buf[..read]);
                    let first = head.lines().next().unwrap_or_default().to_string();
                    recorded.lock().unwrap().push(first);
                    let _ = stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    (port, seen)
}

/// Maps `proxy_name` to loopback (where the recording proxy listens) and every other name
/// to `target_addr`.
fn lookup_for(proxy_name: &'static str, target_addr: &'static str) -> TestLookup {
    TestLookup(Arc::new(move |host: &str| {
        let addr = if normalize_host(host) == proxy_name {
            "127.0.0.1:0"
        } else {
            target_addr
        };
        vec![addr.parse().unwrap()]
    }))
}

fn proxied_transport(
    guard: AddrGuard,
    egress: GuardedEgress,
    proxy_name: &str,
    port: u16,
    lookup: TestLookup,
) -> Transport {
    let route = ProxyRoute::Fixed(Url::parse(&format!("http://{proxy_name}:{port}")).unwrap());
    let resolver = BlockedAddrResolver::with_lookup(guard.clone(), route.exempt_hosts(), lookup);
    let tier = CacheTier::Baseline;
    Transport::from_parts(
        redirect_policy(guard, RedirectScope::for_egress(egress)),
        resolver,
        egress,
        &route,
        tier,
    )
}

async fn fetch_via(transport: &Transport) -> Result<CachedResponse> {
    fetch_url_via("https://registry.test/index", transport).await
}

async fn fetch_url_via(url: &str, transport: &Transport) -> Result<CachedResponse> {
    HttpCache::new()
        .get_cached_via(
            url,
            &[],
            transport,
            KeyAuth::ANONYMOUS,
            RevalidationFailure::ServeStale,
            RateLimitRevocation::default(),
        )
        .await
}
