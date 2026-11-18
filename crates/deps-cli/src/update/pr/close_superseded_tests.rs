//! Gate matrix of `--close-superseded` (#2073) against fake `gh` and `glab` shims.
//!
//! The shims answer by argv glob, log every call and never touch a network; the real hosts are
//! never contacted.

#![allow(clippy::expect_used, clippy::panic)]

use deps_core::EcosystemId;
use deps_engine::setup::CargoFormatter;
use serde_json::json;

use super::acceptance_tests::{Fixture, plan};
use super::{
    BODY_MAX_BYTES, BaseBranch, OpenedRequest, PrHost, RepoContext, RequestMarker, RequestUrl,
    RunMode, SupersedeReport, SweepCoverage, close_superseded,
};

const NEW_URL: &str = "https://example.test/pr/9";

fn marker(ctx: &RepoContext, updates: &[(&str, &str, &str)]) -> RequestMarker {
    RequestMarker::new(
        ctx,
        EcosystemId::Cargo,
        RunMode::Default,
        &plan(updates),
        &CargoFormatter,
        None,
    )
}

fn opened() -> OpenedRequest {
    OpenedRequest {
        url: RequestUrl(NEW_URL.to_owned()),
        base: BaseBranch::new("main".to_owned()).expect("base"),
    }
}

/// One answer of a fake host CLI: argv glob and what to print, `None` to exit 1.
type Rule = (String, Option<String>);

struct Shim<'a> {
    fx: &'a Fixture,
    name: &'a str,
    rules: Vec<Rule>,
}

impl<'a> Shim<'a> {
    fn new(fx: &'a Fixture, name: &'a str) -> Self {
        Self {
            fx,
            name,
            rules: Vec::new(),
        }
    }

    fn reply(mut self, glob: &str, output: impl ToString) -> Self {
        self.rules.push((glob.to_owned(), Some(output.to_string())));
        self
    }

    fn fail(mut self, glob: &str) -> Self {
        self.rules.push((glob.to_owned(), None));
        self
    }

    fn install(self) {
        let log = self.fx.record(&format!("{}.log", self.name));
        let mut script = format!("echo \"$*\" >> '{}'\ncase \"$*\" in\n", log.display());
        for (index, (glob, output)) in self.rules.iter().enumerate() {
            match output {
                Some(text) => {
                    let file = self.fx.record(&format!("{}.reply{index}", self.name));
                    std::fs::write(&file, text).expect("reply");
                    script.push_str(&format!(
                        "\"{glob}\"*) cat '{}'; exit 0;;\n",
                        file.display()
                    ));
                }
                None => script.push_str(&format!("\"{glob}\"*) exit 1;;\n")),
            }
        }
        script.push_str("*) exit 9;;\nesac\n");
        self.fx.shim(self.name, &script);
    }
}

fn calls(fx: &Fixture, name: &str) -> Vec<String> {
    std::fs::read_to_string(fx.record(&format!("{name}.log")))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn closes(fx: &Fixture, name: &str) -> Vec<String> {
    calls(fx, name)
        .into_iter()
        .filter(|call| call.starts_with("pr close ") || call.starts_with("mr close "))
        .collect()
}

#[derive(Clone)]
struct Candidate {
    number: u64,
    head: String,
    author: &'static str,
    bot: bool,
    cross_repository: bool,
    commits: usize,
    body: Option<String>,
}

impl Candidate {
    fn covered(ctx: &RepoContext, number: u64) -> Self {
        Self {
            number,
            head: format!("deps-cli/cargo/serde-1.1.0-{number:08x}"),
            author: "octo",
            bot: false,
            cross_repository: false,
            commits: 1,
            body: Some(body_with(&marker(ctx, &[("serde", "1.0.0", "1.1.0")]))),
        }
    }
}

fn body_with(marker: &RequestMarker) -> String {
    format!("table\n\n{}\n", marker.render().expect("marker"))
}

fn github<'a>(fx: &'a Fixture, new_author: (&str, bool), candidates: &[Candidate]) -> Shim<'a> {
    let meta =
        |number: u64, head: &str, author: (&str, bool), cross: bool, commits: usize, body: &str| {
            json!({
                "number": number,
                "author": {"login": author.0, "is_bot": author.1},
                "headRefName": head,
                "isCrossRepository": cross,
                "commits": commits,
                "body": body,
            })
        };
    let listed: Vec<_> = candidates
        .iter()
        .map(|c| json!({"number": c.number, "headRefName": c.head}))
        .collect();
    let mut shim = Shim::new(fx, "gh")
        .reply(
            &format!("pr view {NEW_URL} --json number"),
            meta(
                9,
                "deps-cli/cargo/serde-1.2.0-00000009",
                new_author,
                false,
                1,
                "",
            ),
        )
        .reply("pr list ", json!(listed));
    for c in candidates {
        let number = c.number;
        shim = shim
            .reply(
                &format!("pr view {number} --json number"),
                meta(
                    number,
                    &c.head,
                    (c.author, c.bot),
                    c.cross_repository,
                    c.commits,
                    c.body.as_deref().unwrap_or_default(),
                ),
            )
            .reply(&format!("pr close {number}"), "")
            .reply(&format!("pr comment {number}"), "");
    }
    shim
}

async fn sweep(host: PrHost, marker: &RequestMarker, ctx: &RepoContext) -> SupersedeReport {
    close_superseded(ctx, host, &opened(), marker, &CargoFormatter).await
}

#[tokio::test]
async fn test_closes_a_covered_request_with_a_comment_and_keeps_its_branch() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    github(&fx, ("octo", false), &[Candidate::covered(&ctx, 7)]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.closed.len(), 1);
    assert_eq!(closes(&fx, "gh"), ["pr close 7"]);
    assert!(calls(&fx, "gh").contains(&format!("pr comment 7 --body=Superseded by {NEW_URL}.")));
    let listing = calls(&fx, "gh")
        .into_iter()
        .find(|call| call.starts_with("pr list"))
        .expect("listed");
    for flag in ["--state=open", "--author=octo", "--limit=200"] {
        assert!(listing.contains(flag), "{flag} missing from {listing}");
    }
    assert!(
        !closes(&fx, "gh")
            .iter()
            .any(|c| c.contains("--delete-branch"))
    );
}

#[tokio::test]
async fn test_each_failed_gate_leaves_the_request_open() {
    type Change = fn(&mut Candidate, &RepoContext);
    let cases: [(&str, Change); 11] = [
        ("foreign author", |c, _| c.author = "mallory"),
        ("same login but a bot", |c, _| c.bot = true),
        ("cross repository", |c, _| c.cross_repository = true),
        ("foreign branch", |c, _| c.head = "feature/serde".to_owned()),
        ("other ecosystem branch", |c, _| {
            c.head = "deps-cli/npm/serde-1.1.0-00000007".to_owned();
        }),
        ("user commits", |c, _| c.commits = 2),
        ("no marker", |c, _| c.body = Some("plain body".to_owned())),
        ("no body", |c, _| c.body = None),
        ("other manifest", |c, ctx| {
            let mut other = marker(ctx, &[("serde", "1.0.0", "1.1.0")]);
            other.manifest = "app/Cargo.toml".to_owned();
            c.body = Some(body_with(&other));
        }),
        ("other mode", |c, ctx| {
            let mut other = marker(ctx, &[("serde", "1.0.0", "1.1.0")]);
            other.mode = RunMode::SecurityOnly;
            c.body = Some(body_with(&other));
        }),
        ("newer target than the new request", |c, ctx| {
            c.body = Some(body_with(&marker(ctx, &[("serde", "1.0.0", "1.3.0")])));
        }),
    ];
    for (label, change) in cases {
        let fx = Fixture::new();
        let ctx = fx.ctx("Cargo.toml").await;
        let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
        let mut candidate = Candidate::covered(&ctx, 7);
        change(&mut candidate, &ctx);
        github(&fx, ("octo", false), &[candidate]).install();

        let report = sweep(PrHost::Github, &new, &ctx).await;

        assert!(
            report.closed.is_empty(),
            "{label}: closed {:?}",
            report.closed
        );
        assert!(report.failures.is_empty(), "{label}: {:?}", report.failures);
        assert!(closes(&fx, "gh").is_empty(), "{label}");
    }
}

#[tokio::test]
async fn test_a_request_covering_only_part_of_the_old_set_stays_open() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut candidate = Candidate::covered(&ctx, 7);
    candidate.body = Some(body_with(&marker(
        &ctx,
        &[("serde", "1.0.0", "1.1.0"), ("tokio", "1.0.0", "1.1.0")],
    )));
    github(&fx, ("octo", false), &[candidate]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert!(report.closed.is_empty());
    assert!(closes(&fx, "gh").is_empty());
}

#[tokio::test]
async fn test_the_new_request_is_never_closed_by_itself() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut itself = Candidate::covered(&ctx, 9);
    itself.body = Some(body_with(&new));
    github(&fx, ("octo", false), &[itself]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert!(report.closed.is_empty());
    assert!(closes(&fx, "gh").is_empty());
}

#[tokio::test]
async fn test_a_failed_listing_is_a_warning_and_closes_nothing() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    Shim::new(&fx, "gh")
        .reply(
            &format!("pr view {NEW_URL} --json number"),
            json!({"number": 9, "author": {"login": "octo", "is_bot": false},
                   "headRefName": "deps-cli/cargo/x", "isCrossRepository": false, "commits": 1}),
        )
        .fail("pr list ")
        .install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.failures.len(), 1);
    assert!(report.closed.is_empty());
}

#[tokio::test]
async fn test_a_failed_author_lookup_is_a_warning_and_never_lists() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    Shim::new(&fx, "gh").fail("pr view ").install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.failures.len(), 1);
    assert!(
        !calls(&fx, "gh")
            .iter()
            .any(|call| call.starts_with("pr list"))
    );
}

#[tokio::test]
async fn test_a_failed_close_is_reported_and_the_other_requests_are_still_closed() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let candidates = [Candidate::covered(&ctx, 7), Candidate::covered(&ctx, 8)];
    let mut shim = github(&fx, ("octo", false), &candidates);
    shim.rules.insert(0, ("pr close 7".to_owned(), None));
    shim.install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.closed.len(), 1);
    assert_eq!(closes(&fx, "gh").len(), 2);
    assert!(
        !calls(&fx, "gh")
            .iter()
            .any(|call| call.starts_with("pr comment 7")),
        "a request that was not closed gets no comment"
    );
}

#[tokio::test]
async fn test_a_failed_comment_keeps_the_request_closed_and_is_reported() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut shim = github(&fx, ("octo", false), &[Candidate::covered(&ctx, 7)]);
    shim.rules.insert(0, ("pr comment 7".to_owned(), None));
    shim.install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.closed.len(), 1);
    assert_eq!(report.failures.len(), 1);
}

#[tokio::test]
async fn test_a_bot_author_is_listed_by_app_and_its_requests_are_closed() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut candidate = Candidate::covered(&ctx, 7);
    candidate.author = "app/github-actions";
    candidate.bot = true;
    github(&fx, ("app/github-actions", true), &[candidate]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.closed.len(), 1, "{:?}", report.failures);
    let listing = calls(&fx, "gh")
        .into_iter()
        .find(|call| call.starts_with("pr list"))
        .expect("listed");
    assert!(listing.contains("--app=github-actions"), "{listing}");
    assert!(!listing.contains("--author"), "{listing}");
}

#[tokio::test]
async fn test_a_full_listing_is_flagged_as_possibly_partial() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let rows: Vec<_> = (100..300)
        .map(|n| json!({"number": n, "headRefName": "feature/other"}))
        .collect();
    Shim::new(&fx, "gh")
        .reply(
            &format!("pr view {NEW_URL} --json number"),
            json!({"number": 9, "author": {"login": "octo", "is_bot": false},
                   "headRefName": "deps-cli/cargo/x", "isCrossRepository": false, "commits": 1}),
        )
        .reply("pr list ", json!(rows))
        .install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.coverage, SweepCoverage::ListingFull);
    assert!(report.closed.is_empty());
}

fn gitlab_mr(iid: u64, author: &str, source: u64, target: u64, body: &str) -> serde_json::Value {
    json!({
        "iid": iid,
        "author": {"username": author},
        "source_branch": format!("deps-cli/cargo/serde-1.1.0-{iid:08x}"),
        "source_project_id": source,
        "target_project_id": target,
        "description": body,
    })
}

#[tokio::test]
async fn test_gitlab_closes_a_covered_merge_request_with_a_note() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let old_body = body_with(&marker(&ctx, &[("serde", "1.0.0", "1.1.0")]));
    Shim::new(&fx, "glab")
        .reply(
            &format!("mr view {NEW_URL} "),
            gitlab_mr(9, "octo", 1, 1, ""),
        )
        .reply(
            "mr list ",
            json!([{"iid": 7, "source_branch": "deps-cli/cargo/serde-1.1.0-00000007"}]),
        )
        .reply("mr view 7 ", gitlab_mr(7, "octo", 1, 1, &old_body))
        .reply("api ", json!([{"id": "a"}]))
        .reply("mr note 7 ", "")
        .reply("mr close 7", "")
        .install();

    let report = sweep(PrHost::Gitlab, &new, &ctx).await;

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.closed.len(), 1);
    let log = calls(&fx, "glab");
    assert!(log.contains(&format!("mr note 7 --message=Superseded by {NEW_URL}.")));
    assert!(log.contains(&"mr close 7".to_owned()));
    let position = |prefix: &str| {
        log.iter()
            .position(|c| c.starts_with(prefix))
            .expect(prefix)
    };
    assert!(
        position("mr close 7") < position("mr note 7"),
        "close before the note"
    );
    assert!(
        log.iter()
            .any(|c| c.starts_with("api projects/:id/merge_requests/7/commits"))
    );
}

#[tokio::test]
async fn test_gitlab_foreign_project_or_extra_commits_stay_open() {
    for (label, source, target, commits) in [("fork", 2, 1, 1), ("user commits", 1, 1, 2)] {
        let fx = Fixture::new();
        let ctx = fx.ctx("Cargo.toml").await;
        let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
        let old_body = body_with(&marker(&ctx, &[("serde", "1.0.0", "1.1.0")]));
        let commit_rows: Vec<_> = (0..commits).map(|n| json!({"id": n})).collect();
        Shim::new(&fx, "glab")
            .reply(
                &format!("mr view {NEW_URL} "),
                gitlab_mr(9, "octo", 1, 1, ""),
            )
            .reply(
                "mr list ",
                json!([{"iid": 7, "source_branch": "deps-cli/cargo/serde-1.1.0-00000007"}]),
            )
            .reply(
                "mr view 7 ",
                gitlab_mr(7, "octo", source, target, &old_body),
            )
            .reply("api ", json!(commit_rows))
            .install();

        let report = sweep(PrHost::Gitlab, &new, &ctx).await;

        assert!(report.closed.is_empty(), "{label}");
        assert!(closes(&fx, "glab").is_empty(), "{label}");
    }
}

#[tokio::test]
async fn test_with_marker_keeps_the_marker_and_the_body_limit_for_a_huge_body() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut text = super::PullRequestText {
        title: "t".to_owned(),
        body: "x".repeat(BODY_MAX_BYTES),
        commit_body: String::new(),
        scope: super::PublishScope::default(),
    };
    text = text.with_marker(&new);

    assert!(text.body.len() <= BODY_MAX_BYTES, "{}", text.body.len());
    assert_eq!(RequestMarker::from_body(&text.body), Some(new));
}

#[tokio::test]
async fn test_an_ecosystem_without_a_version_ordering_never_calls_the_host() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let actions = RequestMarker::new(
        &ctx,
        EcosystemId::GithubActions,
        RunMode::Default,
        &plan(&[("actions/checkout", "v3", "v4")]),
        &CargoFormatter,
        None,
    );
    github(&fx, ("octo", false), &[Candidate::covered(&ctx, 7)]).install();

    let report = sweep(PrHost::Github, &actions, &ctx).await;

    assert_eq!(report.failures.len(), 1);
    assert!(report.closed.is_empty());
    assert!(calls(&fx, "gh").is_empty());
}

#[tokio::test]
async fn test_a_go_request_is_closed_through_the_native_ordering() {
    let go_marker = |ctx: &RepoContext, target: &str| {
        RequestMarker::new(
            ctx,
            EcosystemId::Go,
            RunMode::Default,
            &plan(&[("example.com/x", "v1.2.0", target)]),
            &deps_engine::setup::GoFormatter,
            None,
        )
    };
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = go_marker(&ctx, "v1.2.10");
    let mut older = Candidate::covered(&ctx, 7);
    older.head = "deps-cli/go/x-v1.2.9-00000007".to_owned();
    older.body = Some(body_with(&go_marker(&ctx, "v1.2.9")));
    let mut newer = Candidate::covered(&ctx, 8);
    newer.head = "deps-cli/go/x-v1.3.0-00000008".to_owned();
    newer.body = Some(body_with(&go_marker(&ctx, "v1.3.0")));
    github(&fx, ("octo", false), &[older, newer]).install();

    let report = close_superseded(
        &ctx,
        PrHost::Github,
        &opened(),
        &new,
        &deps_engine::setup::GoFormatter,
    )
    .await;

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(
        closes(&fx, "gh"),
        ["pr close 7"],
        "v1.2.9 < v1.2.10 closes; v1.3.0 stays"
    );
}

#[tokio::test]
async fn test_with_marker_cuts_on_a_line_so_an_open_code_fence_cannot_swallow_it() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let text = super::PullRequestText {
        title: "t".to_owned(),
        body: format!(
            "```\n{}",
            "line of fenced text\n".repeat(BODY_MAX_BYTES / 10)
        ),
        commit_body: String::new(),
        scope: super::PublishScope::default(),
    };

    let body = text.with_marker(&new).body;

    assert!(body.len() <= BODY_MAX_BYTES);
    let (before, marker_line) = body
        .rsplit_once("\n\n")
        .expect("blank line before the marker");
    assert!(before.ends_with("fenced text"), "cut on a whole line");
    assert_eq!(RequestMarker::from_body(marker_line), Some(new));
}

#[tokio::test]
async fn test_each_candidate_is_read_with_one_view_call() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    github(&fx, ("octo", false), &[Candidate::covered(&ctx, 7)]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.closed.len(), 1, "{:?}", report.failures);
    let views = calls(&fx, "gh")
        .into_iter()
        .filter(|call| call.starts_with("pr view 7 "))
        .count();
    assert_eq!(views, 1);
}

#[tokio::test]
async fn test_candidates_are_read_oldest_first_up_to_the_cap() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let candidates: Vec<_> = (100..160)
        .rev()
        .map(|number| Candidate::covered(&ctx, number))
        .collect();
    github(&fx, ("octo", false), &candidates).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.coverage, SweepCoverage::CandidateCapReached);
    let expected: Vec<String> = (100..150).map(|n| format!("pr close {n}")).collect();
    assert_eq!(closes(&fx, "gh"), expected);
    let read = calls(&fx, "gh")
        .iter()
        .filter(|call| call.starts_with("pr view ") && !call.contains(NEW_URL))
        .count();
    assert_eq!(read, 50);
}

#[tokio::test]
async fn test_candidates_are_filtered_by_the_manifest_directory_part() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let mut inside = Candidate::covered(&ctx, 7);
    inside.head = "deps-cli/cargo/app/serde-1.1.0-00000007".to_owned();
    let mut elsewhere = Candidate::covered(&ctx, 8);
    elsewhere.head = "deps-cli/cargo/other/serde-1.1.0-00000008".to_owned();
    let root_level = Candidate::covered(&ctx, 6);
    github(&fx, ("octo", false), &[inside, elsewhere, root_level]).install();

    let report = sweep(PrHost::Github, &new, &ctx).await;

    assert_eq!(report.coverage, SweepCoverage::Complete);
    assert_eq!(closes(&fx, "gh"), ["pr close 7"]);
    assert!(
        !calls(&fx, "gh")
            .iter()
            .any(|call| call.starts_with("pr view 8 ") || call.starts_with("pr view 6 ")),
        "branches outside the directory part are never read"
    );
}

#[tokio::test]
async fn test_gitlab_listing_beyond_the_default_capture_cap_is_read_whole() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let new = marker(&ctx, &[("serde", "1.0.0", "1.2.0")]);
    let rows: Vec<_> = (100..190)
        .map(|iid| {
            json!({
                "iid": iid,
                "source_branch": "feature/other",
                "description": "d".repeat(2048),
            })
        })
        .collect();
    Shim::new(&fx, "glab")
        .reply(
            &format!("mr view {NEW_URL} "),
            gitlab_mr(9, "octo", 1, 1, ""),
        )
        .reply("mr list ", json!(rows))
        .reply("api ", json!([{"id": "a"}]))
        .install();

    let report = sweep(PrHost::Gitlab, &new, &ctx).await;

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.coverage, SweepCoverage::Complete);
}
