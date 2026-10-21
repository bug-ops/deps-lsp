//! Which `identifiers` answer maps to which memoized outcome, and which identity a swizzled
//! dependency adopts (spec 088 FR-003/FR-004).

use std::time::Instant;

use deps_core::lsp_helpers::{ProbeEffect, ProbeReport};
use deps_core::policy_config::ScmToRegistry;
use mockito::Matcher;

use crate::package_location::RegistryIdentityBuf;
use crate::scm::{IdentityLookup, ScmLookupUrl, SwiftOrigin};
use crate::scm_tests::{Fixture, NIO};

const NIO_URL: &str = "https://github.com/apple/swift-nio";

fn unique(identity: &str) -> IdentityLookup {
    IdentityLookup::Unique(RegistryIdentityBuf::parse(identity).unwrap())
}

struct Answer {
    label: &'static str,
    status: usize,
    body: &'static str,
    outcome: IdentityLookup,
}

fn answers() -> Vec<Answer> {
    vec![
        Answer {
            label: "single valid identity",
            status: 200,
            body: r#"{"identifiers": ["mona.nio-fork"]}"#,
            outcome: unique("mona.nio-fork"),
        },
        Answer {
            label: "several identities",
            status: 200,
            body: r#"{"identifiers": ["apple.swift-nio", "other.nio"]}"#,
            outcome: IdentityLookup::Ambiguous,
        },
        Answer {
            label: "empty list",
            status: 200,
            body: r#"{"identifiers": []}"#,
            outcome: IdentityLookup::NotRegistered,
        },
        Answer {
            label: "invalid identity",
            status: 200,
            body: r#"{"identifiers": ["not an identity"]}"#,
            outcome: IdentityLookup::Rejected,
        },
        Answer {
            label: "404",
            status: 404,
            body: "",
            outcome: IdentityLookup::NotRegistered,
        },
        Answer {
            label: "5xx",
            status: 500,
            body: "boom",
            outcome: IdentityLookup::Failed,
        },
    ]
}

#[tokio::test]
async fn test_each_answer_is_memoized_as_its_own_outcome() {
    for Answer {
        label,
        status,
        body,
        outcome,
    } in answers()
    {
        let mut server = mockito::Server::new_async().await;
        let _lookup = server
            .mock("GET", "/identifiers")
            .match_query(Matcher::UrlEncoded("url".into(), NIO_URL.into()))
            .with_status(status)
            .with_body(body)
            .create();
        let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

        fixture.prefetch(&fixture.parse(NIO).await).await;

        let key = ScmLookupUrl::parse(NIO_URL).unwrap();
        let memoized = fixture
            .registry
            .identity_memo()
            .get(&fixture.key(&key), Instant::now())
            .map(|read| read.answer);
        assert_eq!(memoized, Some(outcome), "{label}");
    }
}

#[tokio::test]
async fn test_a_swizzled_dependency_adopts_the_identity_the_registry_returned() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = server
        .mock("GET", "/identifiers")
        .match_query(Matcher::UrlEncoded("url".into(), NIO_URL.into()))
        .with_status(200)
        .with_body(r#"{"identifiers": ["mona.nio-fork"]}"#)
        .create();
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

    let report: ProbeReport = fixture.prefetch(&fixture.parse(NIO).await).await;
    assert_eq!(report.effect, ProbeEffect::Reparse);

    let reparsed = fixture.parse(NIO).await;
    let dependency = &reparsed.dependencies[0];
    assert_eq!(dependency.name, "mona.nio-fork");
    assert!(matches!(dependency.origin, SwiftOrigin::Swizzled { .. }));
}

#[tokio::test]
async fn test_only_a_failed_answer_is_incomplete_and_only_a_unique_one_swaps() {
    for Answer {
        label,
        status,
        body,
        outcome,
    } in answers()
    {
        let mut server = mockito::Server::new_async().await;
        let _lookup = server
            .mock("GET", "/identifiers")
            .match_query(Matcher::UrlEncoded("url".into(), NIO_URL.into()))
            .with_status(status)
            .with_body(body)
            .create();
        let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

        let parsed = fixture.parse(NIO).await;
        let declared_name = parsed.dependencies[0].name.clone();
        let report = fixture.prefetch(&parsed).await;
        let reparsed = fixture.parse(NIO).await;
        let dependency = &reparsed.dependencies[0];

        let is_unique = matches!(outcome, IdentityLookup::Unique(_));
        assert_eq!(
            usize::from(outcome == IdentityLookup::Failed),
            report.incomplete_identity_lookups,
            "{label}"
        );
        assert_eq!(report.effect == ProbeEffect::Reparse, is_unique, "{label}");
        assert_eq!(
            matches!(dependency.origin, SwiftOrigin::Swizzled { .. }),
            is_unique,
            "{label}"
        );
        if !is_unique {
            assert_eq!(dependency.name, declared_name, "{label}");
        }
        assert_eq!(
            fixture.ecosystem.lookup_failed_notices(&parsed).len(),
            usize::from(outcome == IdentityLookup::Failed),
            "{label}"
        );
    }
}
