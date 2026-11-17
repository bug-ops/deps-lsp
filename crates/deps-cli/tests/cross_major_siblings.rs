//! Acceptance tests for #1719 / spec 103 through the real `check` / `update` pipeline: a tag pin
//! (`@v4`, `@v4.8.0`) and its update candidates are scanned against every release tag on their
//! commit, across majors, and the `--fail-on unchecked` coverage rules (plan N3) hold.
//!
//! Needs a dev-dependency the repository does not have yet:
//! `deps-github-actions = { workspace = true, features = ["test-util"] }` in `deps-cli`
//! (for `GithubActionsEcosystem::for_test`), gated on the `github-actions` feature.
//! Both a mock GitHub tags API and a mock OSV server are `mockito`-backed.

#![cfg(feature = "github-actions")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::exit::{EXIT_CLEAN, ExecutionOutcome, exit_code};
use deps_cli::report::{
    Category, CheckContext, CheckReport, FailOnPolicy, FailOnToken, OsvCoverage, check_manifest,
};
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::{Outcome, UpdatePlan, plan_updates};
use deps_core::diagnostic::DiagnosticKind;
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{Ecosystem, HttpCache};
use deps_github_actions::GithubActionsEcosystem;

const VULN_5: Option<(&str, &str)> = Some(("5.0.0", "5.0.1"));
const ADVISORY: &str = "GHSA-5555-5555-5555";

fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

struct Fixture {
    _github: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    _dir: tempfile::TempDir,
    manifest: PathBuf,
    content: String,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
}

/// `tags` are `(name, commit-sha)` pairs served as the repository's complete tag list;
/// `vulnerable` is the `(introduced, fixed)` range of the one advisory OSV reports, if any.
async fn fixture(
    uses_ref: &str,
    tags: &[(&str, String)],
    vulnerable: Option<(&str, &str)>,
) -> Fixture {
    let mut github = mockito::Server::new_async().await;
    let body = format!(
        "[{}]",
        tags.iter()
            .map(|(name, sha)| format!(
                    r#"{{"name":"{name}","commit":{{"sha":"{sha}","url":"https://api.github.com/repos/actions/checkout/commits/{sha}"}}}}"#
                ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let tags_mock = github
        .mock("GET", "/repos/actions/checkout/tags")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(body)
        .create_async()
        .await;

    let mut osv = mockito::Server::new_async().await;
    let (introduced, fixed) = vulnerable.unwrap_or(("0", "0"));
    let vulns = if vulnerable.is_some() {
        format!(r#"{{"id":"{ADVISORY}","modified":"2023-01-01T00:00:00Z"}}"#)
    } else {
        String::new()
    };
    let batch = osv
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(format!(r#"{{"results":[{{"vulns":[{vulns}]}}]}}"#))
        .expect_at_least(0)
        .create_async()
        .await;
    let record = osv
        .mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
        .with_status(200)
        .with_body(format!(
            r#"{{"id":"{ADVISORY}","modified":"2023-01-01T00:00:00Z","summary":"s",
            "database_specific":{{"severity":"HIGH"}},
            "affected":[{{"package":{{"name":"actions/checkout","ecosystem":"GitHub Actions"}},
            "ranges":[{{"type":"SEMVER","events":[{{"introduced":"{introduced}"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
        ))
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("project dir");
    let workflows = dir.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).expect("workflows dir");
    let manifest = workflows.join("ci.yml");
    let content = format!(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{uses_ref}\n"
    );
    std::fs::write(&manifest, &content).expect("write workflow");

    let cache = Arc::new(HttpCache::new());
    let policy = PolicyConfig::default();
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy,
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
    };
    let ecosystem: Arc<dyn Ecosystem> =
        Arc::new(GithubActionsEcosystem::for_test(cache, github.url()));

    Fixture {
        _github: github,
        _osv: osv,
        _mocks: vec![tags_mock, batch, record],
        _dir: dir,
        manifest,
        content,
        ctx,
        ecosystem,
    }
}

async fn check(f: &Fixture) -> (CheckReport, OsvCoverage) {
    let display = f.manifest.clone();
    let uri_path = f.manifest.clone();
    let result = check_manifest(&f.ecosystem, &uri_path, &display, &f.content, &f.ctx)
        .await
        .expect("check_manifest");
    let mut coverage = OsvCoverage::default();
    coverage.add(&result.osv_coverage);
    let report = CheckReport {
        findings: result.findings,
    };
    (report, coverage)
}

fn advisory_findings(report: &CheckReport) -> Vec<&deps_cli::report::CheckFinding> {
    report
        .findings
        .iter()
        .filter(|f| matches!(&f.kind, DiagnosticKind::Advisory(id) if id.as_str() == ADVISORY))
        .collect()
}

/// The OSV scan outcome of the fixture's only dependency, as its `Debug` text.
async fn scan_outcome(f: &Fixture) -> String {
    let analysis = analyze_manifest(
        &f.ecosystem,
        &f.manifest,
        &f.content,
        &f.ctx,
        AnalysisScope::all(),
    )
    .await
    .expect("analyze_manifest");
    let map = analysis.vulnerabilities.as_ref().expect("OSV scan ran");
    assert_eq!(map.len(), 1, "{map:?}");
    format!("{:?}", map.values().next().expect("one entry"))
}

fn unchecked_gate(report: &CheckReport, coverage: &OsvCoverage, ctx: &CheckContext) -> i32 {
    exit_code(
        report,
        &FailOnPolicy::from_tokens(&[FailOnToken::Unchecked]),
        coverage,
        ctx.policy.osv_checks(),
        ExecutionOutcome::Clean,
    )
}

fn tags_v4_and_v5_on_one_commit() -> Vec<(&'static str, String)> {
    vec![("v4", sha('a')), ("v5.0.0", sha('a'))]
}

// ---- F1-F4: floating pin ---------------------------------------------------------------------

/// F1: `@v4` on a commit that also carries `v5.0.0` (advisory on 5.0.0) is vulnerable and the
/// finding names the sibling it matched through.
#[tokio::test]
async fn check_floating_pin_is_vulnerable_through_a_cross_major_sibling() {
    let f = fixture("v4", &tags_v4_and_v5_on_one_commit(), VULN_5).await;

    let (report, _) = check(&f).await;

    let findings = advisory_findings(&report);
    assert_eq!(findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(findings[0].category(), Category::Vulnerable);
    assert!(
        findings[0].message.contains("v5.0.0"),
        "{}",
        findings[0].message
    );
}

/// F2: the same commit with no advisory is actually scanned and clean. A skipped
/// `ResolvedTagNotFullVersion` pin is not a coverage gap (`SkipReason::coverage_gap` is `None`),
/// so `--fail-on unchecked` passes either way and the scan outcome is the discriminator.
#[tokio::test]
async fn check_floating_pin_with_clean_cross_major_sibling_is_scanned_and_clean() {
    let f = fixture("v4", &tags_v4_and_v5_on_one_commit(), None).await;

    let (report, coverage) = check(&f).await;

    assert!(advisory_findings(&report).is_empty());
    let outcome = scan_outcome(&f).await;
    assert!(outcome.starts_with("Clean"), "{outcome}");
    assert_eq!(unchecked_gate(&report, &coverage, &f.ctx), EXIT_CLEAN);
}

/// F4: `v4` alone on its commit has no full release to scan: skipped as
/// `ResolvedTagNotFullVersion`, no finding (#1668); unchanged by this work.
#[tokio::test]
async fn check_floating_pin_without_any_full_release_is_not_scanned() {
    let f = fixture("v4", &[("v4", sha('a'))], VULN_5).await;

    let (report, coverage) = check(&f).await;

    assert!(
        advisory_findings(&report).is_empty(),
        "{:#?}",
        report.findings
    );
    let outcome = scan_outcome(&f).await;
    assert!(outcome.contains("ResolvedTagNotFullVersion"), "{outcome}");
    assert_eq!(unchecked_gate(&report, &coverage, &f.ctx), EXIT_CLEAN);
}

/// A full-release primary (`v4.2.2` next to `v4`) also scans the other major on the commit.
#[tokio::test]
async fn check_floating_pin_with_full_release_primary_scans_cross_major_sibling() {
    let tags = vec![("v4", sha('a')), ("v4.2.2", sha('a')), ("v5.0.0", sha('a'))];
    let f = fixture("v4", &tags, VULN_5).await;

    let (report, _) = check(&f).await;

    assert_eq!(
        advisory_findings(&report).len(),
        1,
        "{:#?}",
        report.findings
    );
}

// ---- exact tag pin ---------------------------------------------------------------------------

#[tokio::test]
async fn check_exact_tag_pin_is_vulnerable_through_a_cross_major_sibling() {
    let tags = vec![("v4.8.0", sha('a')), ("v5.0.0", sha('a'))];
    let f = fixture("v4.8.0", &tags, VULN_5).await;

    let (report, _) = check(&f).await;

    let findings = advisory_findings(&report);
    assert_eq!(findings.len(), 1, "{:#?}", report.findings);
    assert!(
        findings[0].message.contains("v5.0.0"),
        "{}",
        findings[0].message
    );
}

#[tokio::test]
async fn check_exact_tag_pin_on_a_commit_without_cross_major_tags_is_clean() {
    let tags = vec![("v4.8.0", sha('a')), ("v5.0.0", sha('b'))];
    let f = fixture("v4.8.0", &tags, VULN_5).await;

    let (report, _) = check(&f).await;

    assert!(
        advisory_findings(&report).is_empty(),
        "{:#?}",
        report.findings
    );
}

// ---- U1-U2 and R3: update path ---------------------------------------------------------------

async fn default_plan(f: &Fixture) -> UpdatePlan {
    let analysis = analyze_manifest(
        &f.ecosystem,
        &f.manifest,
        &f.content,
        &f.ctx,
        AnalysisScope::update_default(),
    )
    .await
    .expect("analyze_manifest");
    let reparse = deps_core::edit::EcosystemReparse {
        ecosystem: &f.ecosystem,
        uri: &analysis.uri,
    };
    plan_updates(
        &analysis,
        &f.content,
        &reparse,
        &[],
        &IgnoreRules::empty(),
        f.ctx.policy.freshness.to_freshness(),
        analysis.now,
    )
}

fn applied_targets(plan: &UpdatePlan) -> Vec<&str> {
    plan.items
        .iter()
        .filter_map(|item| match &item.outcome {
            Outcome::Applied { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect()
}

/// U1: the latest candidate `v4.9.0` shares its commit with `v3.9.9`, which an advisory
/// affects; the candidate is flagged through that cross-major sibling and never written.
#[tokio::test]
async fn update_never_writes_a_candidate_sharing_a_commit_with_a_vulnerable_cross_major_tag() {
    let tags = vec![
        ("v4.8.0", sha('a')),
        ("v4.9.0", sha('b')),
        ("v3.9.9", sha('b')),
    ];
    let f = fixture("v4.8.0", &tags, Some(("3.0.0", "3.9.10"))).await;

    let plan = default_plan(&f).await;

    let targets = applied_targets(&plan);
    assert!(!targets.contains(&"v4.9.0"), "{targets:?}");
}

/// U2: the same setup with a clean cross-major tag changes nothing: the latest is written.
#[tokio::test]
async fn update_with_clean_cross_major_sibling_still_writes_the_latest() {
    let tags = vec![
        ("v4.8.0", sha('a')),
        ("v4.9.0", sha('b')),
        ("v5.0.0", sha('b')),
    ];
    let f = fixture("v4.8.0", &tags, None).await;

    let plan = default_plan(&f).await;

    assert!(
        applied_targets(&plan).contains(&"v5.0.0"),
        "{:#?}",
        plan.items
    );
}

/// R3: a pin matched through a cross-major sibling gets that sibling's fix as the target
/// (the SHA-pin precedent), `v5.0.1` here.
#[tokio::test]
async fn security_update_proposes_the_cross_major_fix_target() {
    let tags = vec![
        ("v4.8.0", sha('a')),
        ("v5.0.0", sha('a')),
        ("v5.0.1", sha('c')),
    ];
    let f = fixture("v4.8.0", &tags, VULN_5).await;
    let analysis = analyze_manifest(
        &f.ecosystem,
        &f.manifest,
        &f.content,
        &f.ctx,
        AnalysisScope::vulnerabilities_only(),
    )
    .await
    .expect("analyze_manifest");

    let plan = deps_cli::update::security::plan_security_updates(
        &analysis,
        f.ecosystem.as_ref(),
        &f.ctx.osv,
        &[],
        &IgnoreRules::empty(),
        f.ctx.policy.cache.fetch_timeout,
    )
    .await;

    let written: Vec<&str> = plan
        .items
        .iter()
        .filter_map(|item| match &item.outcome {
            Outcome::Applied { edit, .. } => Some(edit.new_text.as_str()),
            _ => None,
        })
        .collect();
    assert!(written.contains(&"v5.0.1"), "{:#?}", plan.items);
}
