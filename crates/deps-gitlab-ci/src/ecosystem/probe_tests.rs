//! End-to-end tests of the background probes (specs 086, 087) against a mocked GitLab API.

use std::sync::{Arc, RwLock};

use deps_core::diagnostic::Severity;
use deps_core::lsp_helpers::{
    CommitSha, LatestRelease, NormalizeName, PackageRendering, ProbeEffect, ProbePhase,
    ProbeReport, RequirementGate, RequirementStatus,
};
use deps_core::pagination::ListCoverage;
use deps_core::parser::DependencySource;
use deps_core::{ConcreteVersion, Ecosystem, HttpCache, PackageName, VersionReq};

use super::{GitlabCiEcosystem, unknown_ref_target};
use crate::host::{GitlabHost, GitlabInstanceHost};
use crate::registry::populate_tag_index_entries;
use crate::types::{EndpointKind, GitlabCiParseResult, GitlabRoute};

const RELEASE: char = 'a';
const PIN: char = 'b';
const ROUTE_KEY: &str = "mock-gitlab";

fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

struct Fixture {
    eco: GitlabCiEcosystem,
    name: PackageName,
}

/// An ecosystem whose `org/proj` project lives on the mock server and has one release `v1.0.0`.
fn fixture(server: &mockito::ServerGuard) -> Fixture {
    let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
    let host = GitlabHost::for_test(&server.url());
    let name = PackageName::new(format!("{}/org/proj", host.host()));
    eco.registry.register_alternate(&[(
        ROUTE_KEY.to_string(),
        GitlabRoute {
            host,
            endpoint: EndpointKind::Tags,
        },
    )]);
    populate_tag_index_entries(
        &deps_core::RefreshSender::new(),
        &eco.registry.tag_index(),
        (EndpointKind::Tags, name.clone()),
        std::iter::once(("v1.0.0", sha(RELEASE).as_str())),
        ListCoverage::Complete,
    );
    eco.registry.probe_stores().record_latest(
        eco.formatter.normalize_package_name(&name),
        LatestRelease {
            tag: "v1.0.0".into(),
            commit: CommitSha::parse(&sha(RELEASE)).unwrap(),
        },
    );
    Fixture { eco, name }
}

fn include(refs: &[&str]) -> GitlabCiParseResult {
    let content: String = std::iter::once("include:\n".to_string())
        .chain(
            refs.iter()
                .map(|r| format!("  - project: org/proj\n    ref: {r}\n    file: a.yml\n")),
        )
        .collect();
    let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
    let policy = deps_core::net_policy::RegistryAccessPolicy::default();
    let instance_host = GitlabInstanceHost::new(
        Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
        Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
    );
    crate::parser::parse_gitlab_ci_yaml(&content, &uri, &policy, &instance_host).unwrap()
}

/// Points every parsed include at the mock project, as a self-hosted instance would resolve it.
fn on_mock(fx: &Fixture, mut parsed: GitlabCiParseResult) -> GitlabCiParseResult {
    for dep in &mut parsed.dependencies {
        dep.name = fx.name.clone();
        dep.source = DependencySource::AlternateRegistry {
            index: ROUTE_KEY.to_string(),
            mirrors_crates_io: false,
        };
    }
    parsed
}

async fn probe(fx: &Fixture, parsed: &GitlabCiParseResult) -> ProbeReport {
    fx.eco
        .background_probes(parsed, ProbePhase::PostFetch)
        .await
}

fn unknown_ref(fx: &Fixture, parsed: &GitlabCiParseResult, n: usize) -> Option<String> {
    unknown_ref_target(&fx.eco.formatter, &parsed.dependencies[n])?
        .diagnostic(&fx.name, Severity::Warning)
        .map(|d| d.message().to_string())
}

#[tokio::test]
async fn partial_ref_with_no_branch_becomes_unknown_ref() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let branch = server
        .mock(
            "GET",
            mockito::Matcher::Regex("projects/org%2Fproj/repository/branches/v40$".into()),
        )
        .with_status(404)
        .expect(1)
        .create_async()
        .await;
    let parsed = on_mock(&fx, include(&["v40"]));

    assert_eq!(unknown_ref(&fx, &parsed, 0), None);
    let report = probe(&fx, &parsed).await;

    branch.assert_async().await;
    assert_eq!(report.issued, 1);
    assert_eq!(report.effect, ProbeEffect::Republish);
    assert!(
        unknown_ref(&fx, &parsed, 0)
            .unwrap()
            .contains("neither a published tag nor a branch")
    );
    assert_eq!(probe(&fx, &parsed).await, ProbeReport::default());
}

#[tokio::test]
async fn existing_branch_and_inconclusive_answers_stay_silent() {
    for (status, inconclusive) in [(200, 0), (403, 1), (500, 1), (429, 1)] {
        let mut server = mockito::Server::new_async().await;
        let fx = fixture(&server);
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex("repository/branches/v40$".into()),
            )
            .with_status(status)
            .with_body("{}")
            .create_async()
            .await;
        let parsed = on_mock(&fx, include(&["v40"]));

        let report = probe(&fx, &parsed).await;

        assert_eq!(report.inconclusive, inconclusive, "{status}");
        assert_eq!(unknown_ref(&fx, &parsed, 0), None, "{status}");
    }
}

/// Security: a ref that cannot be a plain tag-shaped name never reaches a request URL.
#[tokio::test]
async fn hostile_refs_issue_no_request() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let any = server
        .mock(
            "GET",
            mockito::Matcher::Regex("repository/(branches|merge_base)".into()),
        )
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;
    let parsed = on_mock(
        &fx,
        include(&["\"1/../../../../user\"", "\"1?x#y\"", "\"1%2F..\""]),
    );

    assert_eq!(probe(&fx, &parsed).await, ProbeReport::default());
    any.assert_async().await;
}

/// A `component:` include is backed by a Releases index, which never proves a tag absent, so it
/// is never probed.
#[tokio::test]
async fn component_includes_are_never_probed() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let any = server
        .mock("GET", mockito::Matcher::Regex("repository".into()))
        .with_status(404)
        .expect(0)
        .create_async()
        .await;
    let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
    let policy = deps_core::net_policy::RegistryAccessPolicy::default();
    let instance_host = GitlabInstanceHost::new(
        Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
        Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
    );
    let mut parsed = crate::parser::parse_gitlab_ci_yaml(
        "include:\n  - component: gitlab.com/org/proj/comp@40\n",
        &uri,
        &policy,
        &instance_host,
    )
    .unwrap();
    for dep in &mut parsed.dependencies {
        dep.name = fx.name.clone();
        dep.source = DependencySource::AlternateRegistry {
            index: ROUTE_KEY.to_string(),
            mirrors_crates_io: false,
        };
    }

    assert_eq!(probe(&fx, &parsed).await, ProbeReport::default());
    any.assert_async().await;
}

fn merge_base_mock(
    server: &mut mockito::ServerGuard,
    first: &str,
    base: char,
) -> impl std::future::Future<Output = mockito::Mock> {
    server
        .mock(
            "GET",
            mockito::Matcher::Regex("repository/merge_base".into()),
        )
        .match_query(mockito::Matcher::Regex(first.to_string()))
        .with_status(200)
        .with_body(format!(r#"{{"id":"{}"}}"#, sha(base)))
        .expect(1)
        .create_async()
}

fn pin_status(fx: &Fixture, parsed: &GitlabCiParseResult) -> RequirementStatus {
    fx.eco.formatter.requirement_status_for(
        &parsed.dependencies[0],
        &VersionReq::new(sha(PIN)),
        &ConcreteVersion::new("v1.0.0"),
    )
}

#[tokio::test]
async fn commit_ahead_of_release_and_on_default_branch_is_up_to_date() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    // merge_base(release, pin) == release: ahead. merge_base(HEAD, pin) == pin: on HEAD.
    let lineage = merge_base_mock(&mut server, &sha(RELEASE), RELEASE).await;
    let membership = merge_base_mock(&mut server, "HEAD", PIN).await;
    let parsed = on_mock(&fx, include(&[&sha(PIN)]));
    assert_eq!(pin_status(&fx, &parsed), RequirementStatus::Outdated);

    let report = probe(&fx, &parsed).await;

    lineage.assert_async().await;
    membership.assert_async().await;
    assert_eq!(report.issued, 2);
    assert_eq!(pin_status(&fx, &parsed), RequirementStatus::UpToDate);
    let hover = fx.eco.formatter.hover_provenance(&parsed.dependencies[0]);
    assert_eq!(
        hover,
        Some(
            deps_core::lsp_helpers::HoverProvenance::CommitAheadOfLatestRelease {
                ahead_by: None,
                latest_tag: "v1.0.0".into(),
            }
        )
    );
}

#[tokio::test]
async fn commit_not_on_the_default_branch_keeps_todays_behavior() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let _lineage = merge_base_mock(&mut server, &sha(RELEASE), RELEASE).await;
    // merge_base(HEAD, pin) is some other commit: the pin is not reachable from HEAD.
    let _membership = merge_base_mock(&mut server, "HEAD", RELEASE).await;
    let parsed = on_mock(&fx, include(&[&sha(PIN)]));

    probe(&fx, &parsed).await;

    assert_eq!(pin_status(&fx, &parsed), RequirementStatus::Outdated);
    assert!(
        fx.eco
            .formatter
            .hover_provenance(&parsed.dependencies[0])
            .is_none()
    );
}

#[tokio::test]
async fn commit_whose_merge_base_is_older_is_not_ahead_and_costs_one_request() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let _lineage = merge_base_mock(&mut server, &sha(RELEASE), 'c').await;
    let membership = server
        .mock("GET", mockito::Matcher::Regex("merge_base".into()))
        .match_query(mockito::Matcher::Regex("HEAD".into()))
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;
    let parsed = on_mock(&fx, include(&[&sha(PIN)]));

    let report = probe(&fx, &parsed).await;

    membership.assert_async().await;
    assert_eq!(report.issued, 1);
    assert_eq!(pin_status(&fx, &parsed), RequirementStatus::Outdated);
}

#[tokio::test]
async fn anonymous_budget_bounds_the_requests_to_a_host() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let refs: Vec<String> = (10..30).map(|n| format!("v{n}")).collect();
    let slices: Vec<&str> = refs.iter().map(String::as_str).collect();
    let any = server
        .mock("GET", mockito::Matcher::Regex("repository/branches".into()))
        .with_status(404)
        .expect(4)
        .create_async()
        .await;
    let parsed = on_mock(&fx, include(&slices));

    let report = probe(&fx, &parsed).await;

    any.assert_async().await;
    assert_eq!((report.issued, report.skipped_over_budget), (4, 16));
}

#[tokio::test]
async fn pre_fetch_phase_does_nothing_and_evidence_is_announced() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let _m = server
        .mock("GET", mockito::Matcher::Regex("repository/branches".into()))
        .with_status(404)
        .create_async()
        .await;
    let parsed = on_mock(&fx, include(&["v40", "v41"]));
    let mut events = fx.eco.refresh_events().unwrap();

    let pre = fx
        .eco
        .background_probes(&parsed, ProbePhase::PreFetch)
        .await;
    assert_eq!(pre, ProbeReport::default());
    probe(&fx, &parsed).await;

    assert_eq!(
        events.try_recv().unwrap(),
        deps_core::RefreshEvent::ProbeEvidence(fx.eco.formatter.normalize_package_name(&fx.name))
    );
    assert!(events.try_recv().is_err());
}

/// SC-003 / FR-021: one budget per host, shared by every document.
#[tokio::test]
async fn the_probe_budget_is_shared_across_documents() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let any = server
        .mock("GET", mockito::Matcher::Regex("repository/branches".into()))
        .with_status(404)
        .expect(4)
        .create_async()
        .await;
    let mut skipped = 0;
    for doc in 0..5 {
        let refs: Vec<String> = (0..10)
            .map(|n| format!("v{}", 100 + doc * 10 + n))
            .collect();
        let slices: Vec<&str> = refs.iter().map(String::as_str).collect();
        let parsed = on_mock(&fx, include(&slices));
        skipped += probe(&fx, &parsed).await.skipped_over_budget;
    }

    any.assert_async().await;
    assert_eq!(skipped, 46);
}

/// FR-029: documents asking the same question at the same time send one request.
#[tokio::test]
async fn concurrent_documents_asking_the_same_question_send_one_request() {
    let mut server = mockito::Server::new_async().await;
    let fx = fixture(&server);
    let one = server
        .mock(
            "GET",
            mockito::Matcher::Regex("repository/branches/v40$".into()),
        )
        .with_status(404)
        .expect(1)
        .create_async()
        .await;
    let (a, b, c) = (
        on_mock(&fx, include(&["v40"])),
        on_mock(&fx, include(&["v40"])),
        on_mock(&fx, include(&["v40"])),
    );

    let (ra, rb, rc) = tokio::join!(probe(&fx, &a), probe(&fx, &b), probe(&fx, &c));

    one.assert_async().await;
    assert_eq!(ra.issued + rb.issued + rc.issued, 1);
}
