//! End-to-end tests of the background probes (specs 086, 087) against a mocked GitHub API.

use std::fmt::Write as _;
use std::sync::Arc;

use deps_core::diagnostic::Severity;
use deps_core::lsp_helpers::NormalizeName;
use deps_core::lsp_helpers::{
    PackageRendering, ProbePhase, ProbeReport, RequirementGate, RequirementStatus, UnpublishedRef,
};
use deps_core::{ConcreteVersion, Ecosystem, PackageName, VersionReq};

use super::{GithubActionsEcosystem, unknown_ref_target};
use crate::formatter::GithubActionsFormatter;
use crate::registry::GithubActionsRegistry;
use crate::types::GithubActionsDependency;

const RELEASE: char = 'a';
const PIN: char = 'b';

fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

async fn ecosystem(server: &mut mockito::ServerGuard, has_token: bool) -> GithubActionsEcosystem {
    let _tags = server
        .mock("GET", "/repos/o/r/tags")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(format!(
            r#"[{{"name": "v1.0.0", "commit": {{"sha": "{}"}}}}]"#,
            sha(RELEASE)
        ))
        .create_async()
        .await;
    let registry = GithubActionsRegistry::for_test(
        Arc::new(deps_core::HttpCache::new()),
        server.url(),
        has_token,
    );
    let formatter = GithubActionsFormatter::new(registry.tag_index())
        .with_probe_stores(registry.probe_stores());
    let eco = GithubActionsEcosystem {
        registry: Arc::new(registry),
        formatter,
    };
    eco.registry.get_versions("o/r").await.unwrap();
    eco
}

fn workflow(refs: &[&str]) -> Box<dyn deps_core::ParseResult> {
    let content = refs.iter().fold(String::new(), |mut acc, r| {
        let _ = writeln!(acc, "  - uses: o/r@{r}");
        acc
    });
    let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    Box::new(crate::parser::parse_workflow_yaml(&format!("steps:\n{content}"), &uri).unwrap())
}

async fn probe(eco: &GithubActionsEcosystem, parsed: &dyn deps_core::ParseResult) -> ProbeReport {
    eco.background_probes(parsed, ProbePhase::PostFetch).await
}

fn unknown_ref(
    eco: &GithubActionsEcosystem,
    parsed: &dyn deps_core::ParseResult,
    n: usize,
) -> Option<String> {
    let dep = parsed.dependencies()[n];
    let gha_dep = dep
        .as_any()
        .downcast_ref::<GithubActionsDependency>()
        .unwrap();
    unknown_ref_target(&eco.formatter, gha_dep)?
        .diagnostic(dep.name(), Severity::Warning)
        .map(|d| d.message().to_string())
}

#[tokio::test]
async fn partial_ref_with_no_branch_becomes_unknown_ref() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let ref_mock = server
        .mock("GET", "/repos/o/r/git/ref/heads/v40")
        .with_status(404)
        .expect(1)
        .create_async()
        .await;
    let parsed = workflow(&["v40"]);

    assert_eq!(unknown_ref(&eco, parsed.as_ref(), 0), None);
    let report = probe(&eco, parsed.as_ref()).await;

    ref_mock.assert_async().await;
    assert_eq!(report.issued, 1);
    assert_eq!(
        report.effect,
        deps_core::lsp_helpers::ProbeEffect::Republish
    );
    assert_eq!(
        unknown_ref(&eco, parsed.as_ref(), 0).as_deref(),
        Some("`v40` is neither a published tag nor a branch of o/r")
    );
    let second = probe(&eco, parsed.as_ref()).await;
    assert_eq!(
        second,
        ProbeReport::default(),
        "evidence hit draws no request"
    );
}

#[tokio::test]
async fn documented_branch_pin_stays_silent() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _m = server
        .mock("GET", "/repos/o/r/git/ref/heads/v1")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;
    let parsed = workflow(&["v1"]);

    probe(&eco, parsed.as_ref()).await;

    assert_eq!(unknown_ref(&eco, parsed.as_ref(), 0), None);
}

#[tokio::test]
async fn inconclusive_answers_store_nothing_and_stay_silent() {
    for status in [403, 409, 429, 500] {
        let mut server = mockito::Server::new_async().await;
        let eco = ecosystem(&mut server, true).await;
        let _m = server
            .mock("GET", "/repos/o/r/git/ref/heads/v40")
            .with_status(status)
            .create_async()
            .await;
        let parsed = workflow(&["v40"]);

        let report = probe(&eco, parsed.as_ref()).await;

        assert_eq!(report.inconclusive, 1, "{status}");
        assert_eq!(unknown_ref(&eco, parsed.as_ref(), 0), None, "{status}");
    }
}

/// Security: a ref that cannot be a plain tag-shaped name never reaches a request URL.
#[tokio::test]
async fn hostile_refs_issue_no_request() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let any = server
        .mock("GET", mockito::Matcher::Regex("git/ref|compare".into()))
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;
    let parsed = workflow(&["1/../../../../user", "1?x#y", "1%2F..", "v1@{u}"]);

    let report = probe(&eco, parsed.as_ref()).await;

    any.assert_async().await;
    assert_eq!(report, ProbeReport::default());
}

#[tokio::test]
async fn full_release_and_listed_refs_are_not_probed() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let any = server
        .mock("GET", mockito::Matcher::Regex("git/ref".into()))
        .with_status(404)
        .expect(0)
        .create_async()
        .await;
    let parsed = workflow(&["v1.0.0", "1.0.1", "main"]);

    assert_eq!(probe(&eco, parsed.as_ref()).await, ProbeReport::default());
    any.assert_async().await;
}

#[tokio::test]
async fn anonymous_budget_bounds_the_requests_of_a_large_document() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, false).await;
    let refs: Vec<String> = (10..30).map(|n| format!("v{n}")).collect();
    let ref_slices: Vec<&str> = refs.iter().map(String::as_str).collect();
    let any = server
        .mock("GET", mockito::Matcher::Regex("git/ref".into()))
        .with_status(404)
        .expect(4)
        .create_async()
        .await;
    let parsed = workflow(&ref_slices);

    let report = probe(&eco, parsed.as_ref()).await;

    any.assert_async().await;
    assert_eq!(report.issued, 4);
    assert_eq!(report.skipped_over_budget, 16);
}

async fn mock_compare(
    server: &mut mockito::ServerGuard,
    base: &str,
    status: &str,
) -> mockito::Mock {
    server
        .mock(
            "GET",
            format!("/repos/o/r/compare/{base}...{}", sha(PIN)).as_str(),
        )
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(format!(
            r#"{{"status":"{status}","ahead_by":3,"files":[]}}"#
        ))
        .expect(1)
        .create_async()
        .await
}

fn pin_status(
    eco: &GithubActionsEcosystem,
    parsed: &dyn deps_core::ParseResult,
) -> RequirementStatus {
    let dep = parsed.dependencies()[0];
    eco.formatter.requirement_status_for(
        dep,
        &VersionReq::new(sha(PIN)),
        &ConcreteVersion::new("v1.0.0"),
    )
}

#[tokio::test]
async fn commit_ahead_of_release_and_on_default_branch_is_up_to_date() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let lineage = mock_compare(&mut server, &sha(RELEASE), "ahead").await;
    let membership = mock_compare(&mut server, "HEAD", "behind").await;
    let parsed = workflow(&[&sha(PIN)]);
    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::Outdated
    );

    let report = probe(&eco, parsed.as_ref()).await;

    lineage.assert_async().await;
    membership.assert_async().await;
    assert_eq!(report.issued, 2);
    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::UpToDate
    );
    let hover = eco
        .formatter
        .hover_provenance(parsed.dependencies()[0])
        .unwrap();
    assert_eq!(
        hover,
        deps_core::lsp_helpers::HoverProvenance::CommitAheadOfLatestRelease {
            ahead_by: Some(3),
            latest_tag: "v1.0.0".into(),
        }
    );
}

/// An imposter (fork-network) commit compares ahead of the release but is not on HEAD.
#[tokio::test]
async fn ahead_commit_not_on_the_default_branch_keeps_todays_behavior() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _lineage = mock_compare(&mut server, &sha(RELEASE), "ahead").await;
    let _membership = mock_compare(&mut server, "HEAD", "diverged").await;
    let parsed = workflow(&[&sha(PIN)]);

    probe(&eco, parsed.as_ref()).await;

    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::Outdated
    );
    assert!(
        eco.formatter
            .hover_provenance(parsed.dependencies()[0])
            .is_none()
    );
}

#[tokio::test]
async fn commit_not_ahead_costs_one_request() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _lineage = mock_compare(&mut server, &sha(RELEASE), "diverged").await;
    let membership = server
        .mock("GET", mockito::Matcher::Regex("compare/HEAD".into()))
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;
    let parsed = workflow(&[&sha(PIN)]);

    let report = probe(&eco, parsed.as_ref()).await;

    membership.assert_async().await;
    assert_eq!(report.issued, 1);
    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::Outdated
    );
}

#[tokio::test]
async fn oversized_or_unknown_compare_answers_are_inconclusive() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _huge = server
        .mock("GET", mockito::Matcher::Regex("compare".into()))
        .with_status(200)
        .with_body(vec![b'x'; 300 * 1024])
        .create_async()
        .await;
    let parsed = workflow(&[&sha(PIN)]);

    let report = probe(&eco, parsed.as_ref()).await;

    assert_eq!((report.issued, report.inconclusive), (1, 1));
    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::Outdated
    );
}

#[tokio::test]
async fn commented_sha_pins_are_not_probed() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let any = server
        .mock("GET", mockito::Matcher::Regex("compare".into()))
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;
    let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    let parsed = crate::parser::parse_workflow_yaml(
        &format!("steps:\n  - uses: o/r@{} # v1.0.0\n", sha(PIN)),
        &uri,
    )
    .unwrap();

    assert_eq!(probe(&eco, &parsed).await, ProbeReport::default());
    any.assert_async().await;
}

#[tokio::test]
async fn pre_fetch_phase_does_nothing() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let parsed = workflow(&["v40"]);
    let report = eco
        .background_probes(parsed.as_ref(), ProbePhase::PreFetch)
        .await;
    assert_eq!(report, ProbeReport::default());
}

#[tokio::test]
async fn new_evidence_is_announced_once_per_repository_as_probe_evidence() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _m = server
        .mock("GET", mockito::Matcher::Regex("git/ref".into()))
        .with_status(404)
        .create_async()
        .await;
    let mut events = eco.refresh_events().unwrap();
    let parsed = workflow(&["v40", "v41"]);

    probe(&eco, parsed.as_ref()).await;

    assert_eq!(
        events.try_recv().unwrap(),
        deps_core::RefreshEvent::ProbeEvidence(deps_core::NormalizedName::for_test("o/r"))
    );
    assert!(events.try_recv().is_err());
}

#[test]
fn only_a_partial_tag_ref_is_a_probe_candidate() {
    let sha = deps_core::lsp_helpers::CommitSha::parse(&sha(RELEASE)).unwrap();
    let index = deps_core::lsp_helpers::TagIndex::from_tags([("v1.0.0", &sha)]);
    assert_eq!(
        index.unpublished_tag_ref("v40"),
        Some(UnpublishedRef::Partial)
    );
    assert_eq!(
        index.unpublished_tag_ref("4.3.1"),
        Some(UnpublishedRef::Release)
    );
    assert_eq!(PackageName::new("o/r").as_str(), "o/r");
}

/// Tester M4: a SHA that IS a release tag is not "ahead of the latest release", whatever the
/// stores say, so neither the status override nor the hover line may apply to it.
#[tokio::test]
async fn untagged_filter_keeps_a_tagged_sha_out_of_the_ahead_override() {
    use deps_core::lsp_helpers::{CommitLineage, CommitSha, DefaultBranchMembership};

    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let release = CommitSha::parse(&sha(RELEASE)).unwrap();
    let tagged = CommitSha::parse(&sha('c')).unwrap();
    let repository = eco
        .formatter
        .normalize_package_name(&PackageName::new("o/r"));
    // `c` also carries a tag in the index, yet probe evidence claims it is ahead and on HEAD.
    let mut index =
        deps_core::lsp_helpers::TagIndex::from_tags([("v1.0.0", &release), ("v1.0.1-rc", &tagged)]);
    index.insert_sha_pin(
        tagged.clone(),
        deps_core::lsp_helpers::ResolvedPin::most_specific(ConcreteVersion::new("v1.0.1-rc")),
    );
    eco.formatter
        .tag_index
        .insert(PackageName::new("o/r"), Arc::new(index));
    let stores = eco.registry.probe_stores();
    stores.commits.record_lineage(
        repository.clone(),
        release,
        tagged.clone(),
        CommitLineage::AheadOfLatest { ahead_by: Some(1) },
    );
    stores
        .commits
        .record_membership(repository, tagged, DefaultBranchMembership::Reachable);
    let parsed = workflow(&[&sha('c')]);

    assert!(
        eco.formatter
            .hover_provenance(parsed.dependencies()[0])
            .is_none()
    );
}

/// SC-003 / FR-021: one budget per registry, shared by every document; fifty large documents
/// with distinct partial refs still cost four requests.
#[tokio::test]
async fn the_probe_budget_is_shared_across_documents() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, false).await;
    let any = server
        .mock("GET", mockito::Matcher::Regex("git/ref".into()))
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
        skipped += probe(&eco, workflow(&slices).as_ref())
            .await
            .skipped_over_budget;
    }

    any.assert_async().await;
    assert_eq!(skipped, 46);
}

/// S3 / FR-029: documents asking the same question at the same time send one request.
#[tokio::test]
async fn concurrent_documents_asking_the_same_question_send_one_request() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let one = server
        .mock("GET", "/repos/o/r/git/ref/heads/v40")
        .with_status(404)
        .expect(1)
        .create_async()
        .await;
    let docs: Vec<_> = (0..4).map(|_| workflow(&["v40"])).collect();

    let (a, b, c, d) = tokio::join!(
        probe(&eco, docs[0].as_ref()),
        probe(&eco, docs[1].as_ref()),
        probe(&eco, docs[2].as_ref()),
        probe(&eco, docs[3].as_ref()),
    );

    one.assert_async().await;
    assert_eq!(a.issued + b.issued + c.issued + d.issued, 1);
}

/// S2: evidence that went stale is still served, so an idle document keeps its proven status.
#[tokio::test]
async fn stale_evidence_keeps_a_proven_pin_up_to_date() {
    let mut server = mockito::Server::new_async().await;
    let eco = ecosystem(&mut server, true).await;
    let _lineage = mock_compare(&mut server, &sha(RELEASE), "ahead").await;
    let _membership = mock_compare(&mut server, "HEAD", "behind").await;
    let parsed = workflow(&[&sha(PIN)]);
    probe(&eco, parsed.as_ref()).await;
    assert_eq!(
        pin_status(&eco, parsed.as_ref()),
        RequirementStatus::UpToDate
    );

    // Everything stored is now past its TTL: a zero-TTL store makes every entry stale at once.
    let stale = deps_core::lsp_helpers::ProbeStores::new(std::time::Duration::ZERO);
    let repository = eco
        .formatter
        .normalize_package_name(&PackageName::new("o/r"));
    let (release, pin) = (
        deps_core::lsp_helpers::CommitSha::parse(&sha(RELEASE)).unwrap(),
        deps_core::lsp_helpers::CommitSha::parse(&sha(PIN)).unwrap(),
    );
    stale.record_latest(
        repository.clone(),
        deps_core::lsp_helpers::LatestRelease {
            tag: "v1.0.0".into(),
            commit: release.clone(),
        },
    );
    stale.commits.record_lineage(
        repository.clone(),
        release,
        pin.clone(),
        deps_core::lsp_helpers::CommitLineage::AheadOfLatest { ahead_by: None },
    );
    stale.commits.record_membership(
        repository.clone(),
        pin.clone(),
        deps_core::lsp_helpers::DefaultBranchMembership::Reachable,
    );
    assert!(stale.commits.membership_fresh(&repository, &pin).is_none());
    assert!(
        stale.proof(&repository, &pin).is_some(),
        "stale evidence is served"
    );
}
