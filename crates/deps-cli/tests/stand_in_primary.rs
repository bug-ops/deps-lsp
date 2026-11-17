//! Regression tests for the #1719 stand-in scan primary: the release that stands in for a
//! floating `@v4` in an OSV scan must not leak into update planning (#1684).
//!
//! The fixture mirrors `cross_major_siblings.rs`, a protected file this cannot extend.

#![cfg(feature = "github-actions")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::report::CheckContext;
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::{Outcome, UpdatePlan, plan_updates};
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{Ecosystem, HttpCache};
use deps_github_actions::GithubActionsEcosystem;

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

fn tags_v4_and_v5_on_one_commit() -> Vec<(&'static str, String)> {
    vec![("v4", sha('a')), ("v5.0.0", sha('a'))]
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

async fn plan_with_major_ignore(f: &Fixture) -> UpdatePlan {
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
    let rule: deps_cli::config::IgnoreRule =
        serde_json::from_str(r#"{"name":"actions/checkout","update_types":["major"]}"#)
            .expect("rule");
    let rules = IgnoreRules::new(vec![rule], f.ecosystem.formatter());
    plan_updates(
        &analysis,
        &f.content,
        &reparse,
        &[],
        &rules,
        f.ctx.policy.freshness.to_freshness(),
        analysis.now,
    )
}

/// An `update_types = ["major"]` ignore rule keeps `@v4` from being bumped to `@v5.0.0`, whether
/// or not `v5.0.0` shares the pin's commit (the OSV stand-in primary must not leak, #1684).
#[tokio::test]
async fn major_ignore_rule_holds_when_a_cross_major_release_shares_the_floating_commit() {
    for tags in [
        vec![("v4", sha('a')), ("v5.0.0", sha('b'))],
        tags_v4_and_v5_on_one_commit(),
    ] {
        let f = fixture("v4", &tags, None).await;
        let plan = plan_with_major_ignore(&f).await;
        assert!(
            applied_targets(&plan).is_empty(),
            "{tags:?}: {:#?}",
            plan.items
        );
    }
}
