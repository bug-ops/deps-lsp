use super::*;
use crate::endpoint_contact::{Contact, ContactLedger, ResponseSeen};
use std::time::Duration;

#[tokio::test]
async fn a_live_fetch_records_request_and_response() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/pkg")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;
    let cache = HttpCache::new();
    let url = format!("{}/pkg", server.url());
    let ledger = ContactLedger::new();

    ledger
        .scope(async {
            cache.get_cached(&url).await.unwrap();
        })
        .await;

    let contact = ledger.snapshot(tokio::time::Instant::now());
    assert_eq!(contact.response, ResponseSeen::Yes);
    assert_eq!(contact.stall, Duration::ZERO);
}

#[tokio::test]
async fn an_error_status_still_counts_as_a_response() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/pkg")
        .with_status(404)
        .create_async()
        .await;
    let cache = HttpCache::new();
    let url = format!("{}/pkg", server.url());
    let ledger = ContactLedger::new();

    ledger
        .scope(async {
            cache.get_cached(&url).await.unwrap_err();
        })
        .await;

    assert_eq!(
        ledger.snapshot(tokio::time::Instant::now()).response,
        ResponseSeen::Yes
    );
}

fn proxied_cache() -> HttpCache {
    use crate::net_policy::{MapEnv, RegistryEnvironment, SystemProxy};
    let env = MapEnv::new().with_proxy(SystemProxy::for_test(Some("http://proxy.corp:3128"), None));
    HttpCache::with_policy(Arc::new(RegistryAccessPolicy::with_environment(
        WorkspaceRegistryAccess::All,
        &RegistryEnvironment::read(&env),
    )))
}

#[tokio::test]
async fn only_a_guarded_request_earns_the_proxy_notice() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/pkg")
        .with_status(200)
        .with_body("ok")
        .expect_at_least(1)
        .create_async()
        .await;
    let url = format!("{}/pkg", server.url());

    let cache = proxied_cache();
    cache.get_cached(&url).await.unwrap();
    assert!(
        cache.registry_policy().take_egress_notice().is_none(),
        "a baseline (operator-owned or public) request connects through the proxy path"
    );

    cache.get_cached_workspace(&url).await.unwrap();
    assert!(cache.registry_policy().take_egress_notice().is_some());
}

#[tokio::test]
async fn a_refused_connection_closes_the_request_without_a_response() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let cache = HttpCache::new();
    let url = format!("http://127.0.0.1:{port}/pkg");
    let ledger = ContactLedger::new();

    let started = tokio::time::Instant::now();
    ledger
        .scope(async {
            cache.get_cached(&url).await.unwrap_err();
        })
        .await;
    let elapsed = started.elapsed();

    let contact = ledger.snapshot(tokio::time::Instant::now());
    assert_eq!(contact.response, ResponseSeen::No);
    assert!(
        contact.stall <= elapsed,
        "a transport error accumulates no stall beyond the request's own duration"
    );
}

/// Serves one request by writing each `(delay, bytes)` step after sleeping `delay`, then goes
/// silent without closing the connection.
fn scripted_server(script: Vec<(Duration, &'static [u8])>) -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        for (delay, bytes) in script {
            std::thread::sleep(delay);
            if stream.write_all(bytes).is_err() {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    });
    addr
}

const HEADERS: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";

/// Fetches from `addr` until `deadline` drops the request, then reads the ledger.
async fn contact_after_cancelling(addr: std::net::SocketAddr, deadline: Duration) -> Contact {
    let cache = HttpCache::new();
    let url = format!("http://{addr}/pkg");
    let ledger = ContactLedger::new();
    ledger
        .scope(async {
            tokio::time::timeout(deadline, cache.get_cached(&url))
                .await
                .unwrap_err();
        })
        .await;
    ledger.snapshot(tokio::time::Instant::now())
}

#[tokio::test]
async fn a_body_that_stalls_after_its_headers_reads_as_stalled() {
    let addr = scripted_server(vec![(Duration::ZERO, HEADERS), (Duration::ZERO, b"part")]);

    let contact = contact_after_cancelling(addr, Duration::from_millis(400)).await;

    assert_eq!(contact.response, ResponseSeen::Yes);
    assert!(
        contact.stall >= Duration::from_millis(150),
        "a body stalled since its last chunk is busy time, got {:?}",
        contact.stall
    );
}

#[tokio::test]
async fn a_drip_fed_body_restarts_the_stall_with_every_chunk() {
    let gap = Duration::from_millis(50);
    let mut script = vec![(Duration::ZERO, HEADERS)];
    script.extend(std::iter::repeat_n((gap, b"x" as &'static [u8]), 40));
    let addr = scripted_server(script);

    let contact = contact_after_cancelling(addr, Duration::from_millis(500)).await;

    assert_eq!(contact.response, ResponseSeen::Yes);
    assert!(
        contact.stall < Duration::from_millis(300),
        "chunks arriving every {gap:?} must keep the stall short, got {:?}",
        contact.stall
    );
}

#[tokio::test]
async fn the_wait_for_headers_does_not_count_once_they_arrive() {
    let addr = scripted_server(vec![(Duration::from_millis(300), HEADERS)]);

    let contact = contact_after_cancelling(addr, Duration::from_millis(450)).await;

    assert_eq!(contact.response, ResponseSeen::Yes);
    assert!(
        contact.stall < Duration::from_millis(300),
        "the time before the headers is answered, got {:?}",
        contact.stall
    );
}
