//! Acceptance tests for #1719 / spec 103, F3 and U3 end to end: a tag pin whose repository tag
//! list was cut off at the page cap fails closed (`SiblingTagsUnknown`, counted by
//! `--fail-on unchecked`), while the same pin on a complete list stays unaffected.
//!
//! The paged tag mock serves a full page of 100 tags for every page request, so the registry
//! reads `MAX_TAG_PAGES` full pages and marks the index truncated.
//!
//! Needs the same `deps-github-actions` dev-dependency (feature `test-util`) as
//! `cross_major_siblings.rs`.

#![cfg(feature = "github-actions")]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::exit::{EXIT_CLEAN, EXIT_POLICY_VIOLATION, ExecutionOutcome, exit_code};
use deps_cli::report::{CheckContext, FailOnPolicy, FailOnToken, OsvCoverage, check_manifest};
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{Ecosystem, HttpCache};
use deps_github_actions::GithubActionsEcosystem;

const FULL_PAGE: usize = 100;

fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

fn tag_json(name: &str, sha: &str) -> String {
    format!(
        r#"{{"name":"{name}","commit":{{"sha":"{sha}","url":"https://api.github.com/repos/actions/checkout/commits/{sha}"}}}}"#
    )
}

struct Fixture {
    _github: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    _dir: tempfile::TempDir,
    manifest: std::path::PathBuf,
    content: String,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
}

/// `named` are the interesting tags; `truncated` pads every page to `FULL_PAGE` entries with
/// non-release filler on another commit so the page cap is reached.
async fn fixture(uses_ref: &str, named: &[(&str, String)], truncated: bool) -> Fixture {
    let mut entries: Vec<String> = named.iter().map(|(n, s)| tag_json(n, s)).collect();
    if truncated {
        let filler = sha('b');
        let missing = FULL_PAGE - entries.len();
        entries.extend((0..missing).map(|i| tag_json(&format!("filler-{i}"), &filler)));
    }
    let mut github = mockito::Server::new_async().await;
    let tags = github
        .mock("GET", "/repos/actions/checkout/tags")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(format!("[{}]", entries.join(",")))
        .create_async()
        .await;

    let mut osv = mockito::Server::new_async().await;
    let batch = osv
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(r#"{"results":[{"vulns":[]}]}"#)
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
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy: PolicyConfig::default(),
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
    };
    let ecosystem: Arc<dyn Ecosystem> =
        Arc::new(GithubActionsEcosystem::for_test(cache, github.url()));

    Fixture {
        _github: github,
        _osv: osv,
        _mocks: vec![tags, batch],
        _dir: dir,
        manifest,
        content,
        ctx,
        ecosystem,
    }
}

async fn unchecked_gate_and_coverage(f: &Fixture) -> (i32, OsvCoverage) {
    let result = check_manifest(&f.ecosystem, &f.manifest, &f.manifest, &f.content, &f.ctx)
        .await
        .expect("check_manifest");
    let mut coverage = OsvCoverage::default();
    coverage.add(&result.osv_coverage);
    let report = deps_cli::report::CheckReport {
        findings: result.findings,
    };
    let code = exit_code(
        &report,
        &FailOnPolicy::from_tokens(&[FailOnToken::Unchecked]),
        &coverage,
        f.ctx.policy.osv_checks(),
        ExecutionOutcome::Clean,
    );
    (code, coverage)
}

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

fn floating() -> Vec<(&'static str, String)> {
    vec![("v4", sha('a')), ("v5.0.0", sha('a'))]
}

fn exact() -> Vec<(&'static str, String)> {
    vec![("v4.8.0", sha('a')), ("v5.0.0", sha('a'))]
}

/// F3: a truncated list may hide further tags on the commit, so the floating pin is unchecked.
#[tokio::test]
async fn check_floating_pin_on_a_truncated_tag_list_is_unchecked() {
    let f = fixture("v4", &floating(), true).await;

    let (code, coverage) = unchecked_gate_and_coverage(&f).await;

    assert!(coverage.unchecked() > 0, "{coverage:?}");
    assert_eq!(code, EXIT_POLICY_VIOLATION);
    let outcome = scan_outcome(&f).await;
    assert!(outcome.contains("SiblingTagsUnknown"), "{outcome}");
}

/// U3's pin-side twin: an exact tag pin on a truncated list fails closed the same way.
#[tokio::test]
async fn check_exact_tag_pin_on_a_truncated_tag_list_is_unchecked() {
    let f = fixture("v4.8.0", &exact(), true).await;

    let (code, coverage) = unchecked_gate_and_coverage(&f).await;

    assert!(coverage.unchecked() > 0, "{coverage:?}");
    assert_eq!(code, EXIT_POLICY_VIOLATION);
    let outcome = scan_outcome(&f).await;
    assert!(outcome.contains("SiblingTagsUnknown"), "{outcome}");
}

/// The same pins on a complete list are scanned and clean; `--fail-on unchecked` is unaffected.
#[tokio::test]
async fn check_pins_on_a_complete_tag_list_leave_unchecked_gate_clean() {
    for (uses_ref, tags) in [("v4", floating()), ("v4.8.0", exact())] {
        let f = fixture(uses_ref, &tags, false).await;

        let (code, coverage) = unchecked_gate_and_coverage(&f).await;

        assert_eq!(code, EXIT_CLEAN, "{uses_ref}: {coverage:?}");
        let outcome = scan_outcome(&f).await;
        assert!(outcome.starts_with("Clean"), "{uses_ref}: {outcome}");
    }
}
