use super::*;

/// The resolved-address decision and its label come from one method: the floor tier
/// refuses exactly the never-a-registry classes, and the workspace tier refuses whatever
/// its snapshot refuses, labelled with the live level.
#[test]
fn test_addr_guard_refusal_decides_and_labels_in_one_place() {
    use crate::net_policy::HostClass;
    let ip = |raw: &str| -> std::net::IpAddr { raw.parse().unwrap() };

    assert_eq!(
        AddrGuard::Baseline.refusal("h", ip("127.0.0.1"), HostClass::Loopback),
        BlockedHost::floor(HostClass::Loopback)
    );
    assert_eq!(
        AddrGuard::Baseline.refusal("h", ip("10.0.0.1"), HostClass::PrivateV4),
        None
    );
    assert_eq!(
        AddrGuard::Baseline.refusal("h", ip("8.8.8.8"), HostClass::Global),
        None
    );

    let public_only = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
    assert_eq!(
        public_only.refusal("h", ip("10.0.0.1"), HostClass::PrivateV4),
        Some(BlockedHost::new(
            HostClass::PrivateV4,
            WorkspaceRegistryAccess::PublicOnly
        ))
    );
    assert_eq!(
        public_only.refusal("h", ip("127.0.0.1"), HostClass::Loopback),
        BlockedHost::floor(HostClass::Loopback)
    );
    assert_eq!(
        public_only.refusal("h", ip("8.8.8.8"), HostClass::Global),
        None
    );
}

// Guards the non-loopback path of `ensure_https`: every other test in this
// module reaches it only through loopback `mockito` URLs, so without this
// test the "reject any other HTTP host" branch would never run.
#[test]
fn test_ensure_https_rejects_non_loopback_http() {
    assert!(ensure_https("http://example.com").is_err());
}

/// #767 M2: `ensure_https`'s `CacheError` used to bake the raw rejected URL in
/// verbatim, the same message-level leak class fixed in `deps-cargo::sparse`'s
/// fail-closed log on the same `window/showMessage` path.
#[test]
fn test_ensure_https_rejection_message_redacts_query_string() {
    let err = ensure_https("http://example.com/pkg?token=super-secret-value").unwrap_err();
    assert!(
        !err.to_string().contains("super-secret-value"),
        "err: {err}"
    );
}

// `http://example.com` alone would still pass under a regressed, substring-based
// `is_loopback_host` (e.g. `url.contains("localhost")`) — these hosts embed a
// loopback token without actually being loopback, and must still be rejected.
#[test]
fn test_ensure_https_rejects_hosts_resembling_loopback() {
    assert!(ensure_https("http://localhost.evil.com/").is_err());
    assert!(ensure_https("http://127.0.0.1.evil.com/").is_err());
    assert!(ensure_https("http://evil.com/?cb=127.0.0.1").is_err());
}

// The sole exerciser of `is_loopback_host`'s bracketed-IPv6 branch
// (`strip_prefix('[')`/`split(']')`) — every other test/mockito URL in this
// module uses `127.0.0.1`.
#[test]
fn test_ensure_https_accepts_bracketed_ipv6_loopback() {
    assert!(ensure_https("http://[::1]:1234/x").is_ok());
}

// #1562: a naive `:`-split misread userinfo as the host boundary, so a loopback-looking
// userinfo let a plain-HTTP request to a public host slip past the HTTPS requirement.
#[test]
fn test_ensure_https_rejects_userinfo_spoofed_loopback() {
    assert!(ensure_https("http://localhost:80@evil.com/x").is_err());
    assert!(ensure_https("http://localhost:@evil.com/").is_err());
}

// reqwest's `Attempt` has no public constructor, so the redirect closure can't be
// unit-tested directly; this exercises the pure detection logic it delegates to (mockito is
// http-only, so an actual https->http redirect isn't testable end-to-end here).
#[test]
fn test_is_https_downgrade() {
    let https = Url::parse("https://example.com/a").unwrap();
    let http = Url::parse("http://example.com/a").unwrap();

    assert!(is_https_downgrade(&https, &http));
    assert!(!is_https_downgrade(&http, &https));
    assert!(!is_https_downgrade(&https, &https));
    assert!(!is_https_downgrade(&http, &http));
}

#[test]
fn test_hop_targets_blocked_host_blocks_cloud_metadata() {
    let url = Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
    assert!(hop_targets_blocked_host(&url));
}

#[test]
fn test_hop_targets_blocked_host_allows_global() {
    let url = Url::parse("https://index.crates.io/").unwrap();
    assert!(!hop_targets_blocked_host(&url));
}

// The loopback carve-out (identical to `ensure_https`'s) must still exempt
// loopback hops under `cfg(test)`, or every mockito redirect chain in this
// module's own tests would start failing.
#[test]
fn test_hop_targets_blocked_host_exempts_loopback_under_test_cfg() {
    let url = Url::parse("http://127.0.0.1:1234/api/target").unwrap();
    assert!(!hop_targets_blocked_host(&url));
}
