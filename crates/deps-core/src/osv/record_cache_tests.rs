//! Acceptance tests for #2065: an advisory cached for one package must never be served for
//! another package that is covered by the same advisory id.
//!
//! Written tests-first against the plan's contract: `record_cache` is keyed by
//! (advisory id, OSV ecosystem, OSV package name), and a second package that queries the same
//! `(id, modified)` reuses the raw record, so it causes no second `GET /v1/vulns/{id}`.
//! Declared in `osv/mod.rs` as `#[cfg(test)] mod record_cache_tests;`.

use super::*;
use crate::{ConcreteVersion, EcosystemId};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

async fn mock_client() -> (mockito::ServerGuard, OsvClient) {
    let server = mockito::Server::new_async().await;
    let client = OsvClient::with_base_url(Arc::new(HttpCache::new()), server.url());
    (server, client)
}

fn target(name: &str, version: &str) -> ScanTarget {
    ScanTarget::new(
        crate::test_util::vuln_key(name),
        OsvQueryName::Confirmed(OsvPackageName::new(name).unwrap()),
        OsvVersion::new(version),
        ConcreteVersion::new(version),
    )
}

const BATCH_BODY: &str =
    r#"{"results":[{"vulns":[{"id":"GHSA-cross-pkg","modified":"2023-01-01T00:00:00Z"}]}]}"#;

async fn scan_one(
    client: &OsvClient,
    ecosystem: EcosystemId,
    name: &str,
    version: &str,
) -> (VulnSeverity, Vec<OsvVersion>) {
    let outcomes = client
        .scan(ecosystem, &[target(name, version)], TEST_TIMEOUT)
        .await;
    let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key(name)) else {
        panic!("expected a Vulnerable outcome for {name}");
    };
    let advisory = &dv.advisories.items()[0];
    (advisory.severity, advisory.fixed_versions.clone())
}

/// regression for #2065: the second package reused the first package's cached advisory.
#[tokio::test]
async fn test_scan_second_package_of_shared_advisory_keeps_its_own_severity_and_fix() {
    let (mut server, client) = mock_client().await;
    let _batch = server
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(BATCH_BODY)
        .expect_at_least(1)
        .create_async()
        .await;
    let record = server
        .mock("GET", "/v1/vulns/GHSA-cross-pkg")
        .with_status(200)
        .with_body(
            r#"{"id":"GHSA-cross-pkg","modified":"2023-01-01T00:00:00Z",
               "affected":[
                 {"package":{"name":"log4j-api","ecosystem":"Maven"},
                  "ecosystem_specific":{"severity":"LOW"},
                  "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.0.0"}]}]},
                 {"package":{"name":"log4j-core","ecosystem":"Maven"},
                  "ecosystem_specific":{"severity":"CRITICAL"},
                  "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.17.1"}]}]}
               ]}"#,
        )
        .expect(1)
        .create_async()
        .await;

    let core = scan_one(&client, EcosystemId::Maven, "log4j-core", "2.14.1").await;
    let api = scan_one(&client, EcosystemId::Maven, "log4j-api", "0.9.0").await;

    assert_eq!(
        core,
        (VulnSeverity::Critical, vec![OsvVersion::new("2.17.1")])
    );
    assert_eq!(api, (VulnSeverity::Low, vec![OsvVersion::new("1.0.0")]));
    record.assert_async().await;
}

/// The ecosystem is part of the key: the same name in two ecosystems is two packages.
#[tokio::test]
async fn test_scan_same_name_in_another_ecosystem_keeps_its_own_severity_and_fix() {
    let (mut server, client) = mock_client().await;
    let _batch = server
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(BATCH_BODY)
        .expect_at_least(1)
        .create_async()
        .await;
    let _record = server
        .mock("GET", "/v1/vulns/GHSA-cross-pkg")
        .with_status(200)
        .with_body(
            r#"{"id":"GHSA-cross-pkg","modified":"2023-01-01T00:00:00Z",
               "affected":[
                 {"package":{"name":"shared","ecosystem":"Maven"},
                  "ecosystem_specific":{"severity":"LOW"},
                  "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.0.0"}]}]},
                 {"package":{"name":"shared","ecosystem":"npm"},
                  "ecosystem_specific":{"severity":"CRITICAL"},
                  "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.0.0"}]}]}
               ]}"#,
        )
        .create_async()
        .await;

    let maven = scan_one(&client, EcosystemId::Maven, "shared", "0.5.0").await;
    let npm = scan_one(&client, EcosystemId::Npm, "shared", "0.5.0").await;

    assert_eq!(maven, (VulnSeverity::Low, vec![OsvVersion::new("1.0.0")]));
    assert_eq!(
        npm,
        (VulnSeverity::Critical, vec![OsvVersion::new("2.0.0")])
    );
}
