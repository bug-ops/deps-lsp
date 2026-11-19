//! Acceptance tests for the review round on spec 104: what `--open-pr` may publish
//! (`readiness`, explicit staging, `UnexpectedChanges`), the order "URL before switching back"
//! (`OpenedRequest`), `RequestUrl` sanitizing, `BaseBranch`, the text caps and boundaries, the
//! cleanup hints, and the deterministic interrupt of the update phase.
//!
//! Written tests-first against plan sections 3, 4 and 6 (revision of 2026-11-18T09-05-47).
//! Declared in `update/pr/mod.rs` as `#[cfg(all(test, unix))] mod publish_safety_tests;`.
//! Needs the test-only constructor `DisplayLockPath::for_test(&str)` (`pub(in crate::update)`).
//! Shares `acceptance_tests`'s fixture.

#![allow(clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::policy_config::PolicyConfig;
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, EcosystemRegistry, HttpCache, NetworkMode,
};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use url::Url;

use super::acceptance_tests::{Fixture, STUB_FORMATTER, URL, error, git};
use super::git::{Step, Tool};
use super::{
    BaseBranch, BranchCheck, PrError, PrHost, PrOutcome, PrPhase, PrSignals, PullRequestText,
    Readiness, RepoContext, branch_for, check_branch, describe, open, preflight, readiness,
    require_tracked_tree, restore,
};
use crate::exit::{EXIT_POLICY_VIOLATION, update_exit_code};
use crate::format::DryRun;
use crate::update::group_tests::{applied, item, skipped};
use crate::update::regen::{
    Companion, DisplayLockPath, LockfileMode, LockfileOutcome, ManifestTarget, NotApplicableReason,
    Program, RegenerationError, RegenerationGate, SkipCause, UnsupportedReason,
    regenerate_lockfile_unlistened,
};
use crate::update::{
    CurrentVersion, Outcome, PlannedUpdateItem, SkipReason, UpdatePlan, UpdateRun,
};

// --- fixture additions ---

fn commit_all(fx: &Fixture, message: &str) {
    git(&fx.root, &["add", "--all"]);
    git(&fx.root, &["commit", &format!("--message={message}")]);
}

/// `Cargo.lock` becomes ignored and untracked, as in a Cargo library.
fn ignore_lock(fx: &Fixture) {
    git(&fx.root, &["rm", "--cached", "--quiet", "Cargo.lock"]);
    fx.write(".gitignore", "Cargo.lock\n");
    commit_all(fx, "ignore the lock file");
    git(&fx.root, &["push", "origin", "main"]);
}

fn origin_branches(fx: &Fixture) -> String {
    let output = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(&fx.origin)
        .args(["branch", "--list"])
        .output()
        .expect("run git");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A `gh` shim whose last stdout line is `printf`-formatted from `last_line`.
fn gh_shim(fx: &Fixture, last_line: &str) {
    fx.shim(
        "gh",
        &format!("echo 'Creating pull request...'\nprintf '{last_line}\\n'\n"),
    );
}

fn run_with(items: Vec<PlannedUpdateItem>, lockfile: LockfileOutcome) -> UpdateRun {
    UpdateRun {
        plan: UpdatePlan { items },
        lockfile,
    }
}

fn regenerated(fx: &Fixture, lock: &str) -> LockfileOutcome {
    LockfileOutcome::Regenerated {
        lockfile: DisplayLockPath::for_test(lock, &fx.root.join(lock)),
        tool: Program::Cargo,
        pins: Vec::new(),
        companions: Vec::new(),
    }
}

/// A regenerated lock file whose real path is not under any fixture: for runs that are never
/// described or restored.
fn regenerated_unplaced(lock: &str) -> LockfileOutcome {
    LockfileOutcome::Regenerated {
        lockfile: DisplayLockPath::for_test(lock, Path::new(lock)),
        tool: Program::Cargo,
        pins: Vec::new(),
        companions: Vec::new(),
    }
}

fn settled_run(lockfile: LockfileOutcome) -> UpdateRun {
    run_with(vec![item("serde", "1.0.0", applied("1.2.0"))], lockfile)
}

fn no_lock() -> LockfileOutcome {
    LockfileOutcome::NotApplicable(NotApplicableReason::NoLockfilePresent)
}

fn requires_lockfile_item(name: &str) -> PlannedUpdateItem {
    item(
        name,
        "1.0.0",
        Outcome::RequiresLockfileUpdate {
            target: ConcreteVersion::from("1.0.5"),
        },
    )
}

fn scope_files(text: &PullRequestText) -> Vec<&str> {
    text.scope
        .files
        .iter()
        .map(|file| file.0.as_str())
        .collect()
}

fn text_of(ctx: &RepoContext, run: &UpdateRun) -> PullRequestText {
    let Readiness::Ready(publishable) = readiness(run) else {
        panic!("the run must be publishable");
    };
    describe(ctx, &publishable, None)
}

/// Runs readiness, branch check, describe and open for `run` the way `main.rs` does.
async fn publish_to(
    ctx: &RepoContext,
    run: &UpdateRun,
    host: PrHost,
) -> Result<PrOutcome, PrError> {
    let proposed = branch_for(ctx, EcosystemId::Cargo, &run.plan, &STUB_FORMATTER, None)
        .expect("a proposed item");
    let Ok(BranchCheck::Free(free)) = check_branch(ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(ctx, run);
    open(ctx, host, free, &text).await
}

async fn publish(ctx: &RepoContext, run: &UpdateRun) -> Result<PrOutcome, PrError> {
    publish_to(ctx, run, PrHost::Github).await
}

fn plan_of_names(names: &[String], from: &str, to: &str) -> UpdateRun {
    run_with(
        names
            .iter()
            .map(|name| item(name, from, applied(to)))
            .collect(),
        regenerated_unplaced("Cargo.lock"),
    )
}

// --- readiness ---

#[test]
fn test_readiness_only_requires_lockfile_update_after_a_regeneration_is_nothing_settled() {
    // The impl-critic's reproducer: the lock moved but no item was proven fixed.
    let run = run_with(
        vec![requires_lockfile_item("foo")],
        regenerated_unplaced("Cargo.lock"),
    );

    assert_matches!(readiness(&run), Readiness::NothingSettled);
    assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
}

#[test]
fn test_readiness_nothing_applied_is_nothing_settled_even_with_a_clean_lockfile() {
    let run = run_with(
        vec![item("dep", "1.0.0", skipped(SkipReason::IgnoreRule))],
        LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
    );

    assert_matches!(readiness(&run), Readiness::NothingSettled);
}

#[test]
fn test_readiness_applied_or_applied_via_lockfile_is_ready() {
    let via_lockfile = item(
        "dep",
        "1.0.0",
        Outcome::AppliedViaLockfile {
            target: ConcreteVersion::from("1.0.5"),
        },
    );

    let applied_run = settled_run(regenerated_unplaced("Cargo.lock"));
    let mixed = run_with(
        vec![requires_lockfile_item("foo"), via_lockfile],
        regenerated_unplaced("Cargo.lock"),
    );

    assert_matches!(readiness(&applied_run), Readiness::Ready(_));
    assert_matches!(readiness(&mixed), Readiness::Ready(_));
}

#[test]
fn test_readiness_lockfile_not_regenerated_wins_over_settled_items() {
    let outcomes = [
        LockfileOutcome::Skipped(SkipCause::DryRun),
        LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::WorkspaceMemberLockfile,
        },
        LockfileOutcome::Failed(RegenerationError::TimedOut {
            after: Duration::from_secs(1),
        }),
    ];

    for lockfile in outcomes {
        let run = settled_run(lockfile);

        assert_matches!(readiness(&run), Readiness::LockfileNotRegenerated);
    }
}

// --- explicit staging and UnexpectedChanges ---

#[tokio::test]
async fn test_open_tracked_edit_outside_the_publishable_files_is_refused_with_nothing_published() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    fx.write("other/file.txt", "edited by someone else\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    assert_matches!(
        error(result),
        PrError::UnexpectedChanges { paths, more: 0 } if paths == ["other/file.txt"]
    );
    assert_eq!(origin_branches(&fx), "* main", "nothing is pushed");
    assert_eq!(git(&fx.root, &["branch", "--list"]), "* main");
    assert_eq!(fx.head(), "main");
    assert_eq!(
        git(&fx.root, &["diff", "--cached", "--name-only"]),
        "",
        "nothing staged"
    );
    assert_eq!(
        git(&fx.root, &["diff", "--name-only"]),
        "Cargo.toml\nother/file.txt",
        "nothing restored either"
    );
}

#[tokio::test]
async fn test_open_lists_at_most_ten_unexpected_paths_and_counts_the_rest() {
    let fx = Fixture::new();
    for index in 0..13 {
        fx.write(&format!("many/f{index:02}.txt"), "initial\n");
    }
    commit_all(&fx, "many files");
    git(&fx.root, &["push", "origin", "main"]);
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    for index in 0..13 {
        fx.write(&format!("many/f{index:02}.txt"), "edited\n");
    }
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    assert_matches!(
        error(result),
        PrError::UnexpectedChanges { paths, more: 3 } if paths.len() == 10
    );
}

#[tokio::test]
async fn test_open_commits_the_manifest_and_the_regenerated_lock_file_only() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked\n");
    fx.write("untracked.txt", "never committed\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    let Ok(PrOutcome::Opened(opened)) = result else {
        panic!("the request must be opened");
    };
    assert_eq!(opened.url(), URL);
    assert_eq!(
        git(&fx.root, &["show", "--name-only", "--format=", "HEAD"]),
        "Cargo.lock\nCargo.toml"
    );
}

#[tokio::test]
async fn test_open_ignored_lock_file_is_not_committed_and_the_manifest_is() {
    let fx = Fixture::new();
    ignore_lock(&fx);
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    assert_matches!(result, Ok(PrOutcome::Opened(_)));
    assert_eq!(
        git(&fx.root, &["show", "--name-only", "--format=", "HEAD"]),
        "Cargo.toml"
    );
}

#[tokio::test]
async fn test_open_tracked_lock_file_change_without_a_regeneration_is_unexpected() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked behind our back\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(no_lock())).await;

    assert_matches!(
        error(result),
        PrError::UnexpectedChanges { paths, .. } if paths == ["Cargo.lock"]
    );
}

#[tokio::test]
async fn test_open_without_a_change_in_a_publishable_file_is_nothing_to_commit() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    assert_matches!(result, Ok(PrOutcome::NothingToCommit));
    assert_eq!(git(&fx.root, &["branch", "--list"]), "* main");
}

// --- OpenedRequest: URL before switching back ---

#[tokio::test]
async fn test_open_returns_the_url_with_head_on_the_update_branch_and_switch_back_returns_to_base()
{
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    let Ok(PrOutcome::Opened(opened)) = result else {
        panic!("the request must be opened");
    };
    assert_eq!(opened.url(), URL);
    assert!(fx.head().starts_with("deps-cli/cargo/"), "{}", fx.head());
    opened.switch_back(&ctx).await.expect("switch back");
    assert_eq!(fx.head(), "main");
}

#[tokio::test]
async fn test_switch_back_failure_names_the_step_and_the_url_was_already_available() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    gh_shim(&fx, URL);
    let Ok(PrOutcome::Opened(opened)) =
        publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await
    else {
        panic!("the request must be opened");
    };
    let url = opened.url().to_owned();
    // An uncommitted edit that differs from both branches makes `git switch main` refuse.
    fx.write("Cargo.toml", "local edit that blocks the switch\n");

    let result = opened.switch_back(&ctx).await;

    assert_eq!(url, URL);
    let failure = error(result);
    assert_matches!(
        &failure,
        PrError::ToolFailed {
            step: Step::SwitchBack,
            ..
        }
    );
    assert!(failure.to_string().contains("git switch"), "{failure}");
}

// --- RequestUrl ---

#[tokio::test]
async fn test_request_url_has_control_characters_removed() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    gh_shim(&fx, "https://exam\\033ple.test/\\007pr/1\\r");

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    let Ok(PrOutcome::Opened(opened)) = result else {
        panic!("the request must be opened");
    };
    assert_eq!(opened.url(), "https://example.test/pr/1");
}

#[tokio::test]
async fn test_request_url_is_capped_at_2048_characters() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    gh_shim(&fx, &format!("https://example.test/{}", "a".repeat(3000)));

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    let Ok(PrOutcome::Opened(opened)) = result else {
        panic!("the request must be opened");
    };
    assert!(opened.url().chars().count() <= 2048);
    assert!(opened.url().starts_with("https://example.test/aaa"));
}

// --- BaseBranch ---

#[test]
fn test_base_branch_refuses_option_shaped_and_update_branch_names() {
    for name in ["-x", "--force", "deps-cli/x"] {
        assert!(BaseBranch::new(name.to_owned()).is_err(), "{name}");
    }
    assert!(BaseBranch::new("main".to_owned()).is_ok());
    assert!(BaseBranch::new("release/1.x".to_owned()).is_ok());
}

#[tokio::test]
async fn test_preflight_head_on_a_branch_starting_with_a_dash_is_refused() {
    let fx = Fixture::new();
    git(&fx.root, &["update-ref", "refs/heads/-x", "HEAD"]);
    git(&fx.root, &["symbolic-ref", "HEAD", "refs/heads/-x"]);

    let result = preflight(&fx.root.join("Cargo.toml")).await;

    assert_matches!(error(result), PrError::UnsafeBaseBranch { .. });
}

// --- text: plain title, byte-bounded body, publishable paths ---

#[tokio::test]
async fn test_describe_title_is_plain_text_while_the_body_uses_code_spans() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let run = run_with(
        vec![item("x|y", "1.0.0", applied("1.1.0"))],
        regenerated(&fx, "Cargo.lock"),
    );

    let text = text_of(&ctx, &run);

    assert_eq!(text.title, "Bump x|y from 1.0.0 to 1.1.0");
    assert!(text.body.contains("`x\\|y`"), "{}", text.body);
}

#[tokio::test]
async fn test_describe_title_and_commit_body_drop_backticks_and_control_characters() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let run = run_with(
        vec![item("a`b\nc", "1.0.0", applied("1.1.0"))],
        regenerated(&fx, "Cargo.lock"),
    );

    let text = text_of(&ctx, &run);

    assert_eq!(text.title, "Bump abc from 1.0.0 to 1.1.0");
    assert!(
        text.commit_body.contains("- abc 1.0.0 -> 1.1.0"),
        "{}",
        text.commit_body
    );
}

#[tokio::test]
async fn test_describe_body_of_a_thousand_four_byte_names_is_cut_at_60000_bytes() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let names: Vec<String> = (0..1000)
        .map(|i| format!("{i}{}", "\u{1F600}".repeat(300)))
        .collect();

    let wide_version = "\u{1F600}".repeat(300);

    let text = text_of(&ctx, &plan_of_names(&names, &wide_version, &wide_version));

    assert!(
        text.body.len() > 59_996 && text.body.len() <= 60_000,
        "{} bytes: the cut must land on the last character boundary below 60,000",
        text.body.len()
    );
    assert!(text.title.len() <= 250, "{} bytes", text.title.len());
}

#[tokio::test]
async fn test_describe_publishable_paths_are_the_manifest_and_a_regenerated_lock_file() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;

    let with = text_of(&ctx, &settled_run(regenerated(&fx, "Cargo.lock")));
    let without = text_of(&ctx, &settled_run(no_lock()));

    assert_eq!(scope_files(&with), ["Cargo.toml", "Cargo.lock"]);
    assert_eq!(scope_files(&without), ["Cargo.toml"]);
}

#[tokio::test]
async fn test_describe_row_cap_is_exactly_50_with_an_overflow_line_from_the_51st() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let rows = |text: &PullRequestText| text.body.lines().filter(|l| l.starts_with("| `")).count();
    let commit_lines = |text: &PullRequestText| {
        text.commit_body
            .lines()
            .filter(|l| l.starts_with("- "))
            .count()
    };
    let names = |count: usize| -> Vec<String> { (0..count).map(|i| format!("dep-{i}")).collect() };

    let fifty = text_of(&ctx, &plan_of_names(&names(50), "1.0.0", "1.1.0"));
    let fifty_one = text_of(&ctx, &plan_of_names(&names(51), "1.0.0", "1.1.0"));

    assert_eq!(rows(&fifty), 50);
    assert_eq!(commit_lines(&fifty), 50);
    assert!(!fifty.body.contains(" more"), "{}", fifty.body);
    assert!(
        !fifty.commit_body.contains(" more"),
        "{}",
        fifty.commit_body
    );
    assert_eq!(rows(&fifty_one), 50);
    assert_eq!(commit_lines(&fifty_one), 50);
    assert!(fifty_one.body.contains("and 1 more"), "{}", fifty_one.body);
    assert!(fifty_one.commit_body.contains("and 1 more"));
}

#[tokio::test]
async fn test_describe_title_of_exactly_250_bytes_is_kept_and_251_is_cut_with_an_ellipsis() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let title_with_from_len = |from_len: usize| {
        let name = "n".repeat(80);
        let run = run_with(
            vec![item(&name, &"1".repeat(from_len), applied(&"2".repeat(80)))],
            regenerated(&fx, "Cargo.lock"),
        );
        text_of(&ctx, &run).title
    };

    let exact = title_with_from_len(75);
    let over = title_with_from_len(76);

    assert_eq!(exact.len(), 250, "{exact}");
    assert!(!exact.ends_with("..."));
    assert_eq!(over.len(), 250, "{over}");
    assert!(over.ends_with("..."));
}

#[tokio::test]
async fn test_describe_body_rows_carry_the_update_kind() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let mut unknown = item("d", "1.0.0", applied("1.0.1"));
    unknown.current = CurrentVersion::Unknown;
    let run = run_with(
        vec![
            item("a", "1.0.0", applied("2.0.0")),
            item("b", "1.0.0", applied("1.1.0")),
            item("c", "1.0.0", applied("1.0.1")),
            unknown,
        ],
        regenerated(&fx, "Cargo.lock"),
    );

    let body = text_of(&ctx, &run).body;

    for (name, kind) in [
        ("a", "major"),
        ("b", "minor"),
        ("c", "patch"),
        ("d", "unknown"),
    ] {
        let row = body
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}`")))
            .unwrap_or_else(|| panic!("no row for {name} in {body}"));
        assert!(row.ends_with(&format!("| {kind} |")), "{row}");
    }
}

#[tokio::test]
async fn test_describe_body_counts_the_items_that_could_not_be_updated() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let unsafe_latest = || {
        item(
            "stuck",
            "1.0.0",
            skipped(SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::UnsafeLatestVersion,
            )),
        )
    };
    let ignored = item("quiet", "1.0.0", skipped(SkipReason::IgnoreRule));
    let applied_item = || item("serde", "1.0.0", applied("1.2.0"));

    let none = text_of(
        &ctx,
        &run_with(
            vec![applied_item(), ignored],
            regenerated(&fx, "Cargo.lock"),
        ),
    );
    let one = text_of(
        &ctx,
        &run_with(
            vec![applied_item(), unsafe_latest()],
            regenerated(&fx, "Cargo.lock"),
        ),
    );
    let two = text_of(
        &ctx,
        &run_with(
            vec![
                applied_item(),
                unsafe_latest(),
                requires_lockfile_item("lock-only"),
            ],
            regenerated(&fx, "Cargo.lock"),
        ),
    );

    assert!(!none.body.contains("could not be updated"), "{}", none.body);
    assert!(
        one.body
            .contains("1 dependency could not be updated automatically."),
        "{}",
        one.body
    );
    assert!(
        two.body
            .contains("2 dependencies could not be updated automatically."),
        "{}",
        two.body
    );
}

// --- branch label: the 48-character cut ---

#[tokio::test]
async fn test_branch_for_label_cut_lands_exactly_on_48_characters_and_fixes_a_lock_suffix() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let leaf_without_hash = |name: &str| {
        let run = plan_of_names(&[name.to_owned()], "1.0.0", "1.0.1");
        let branch = branch_for(&ctx, EcosystemId::Cargo, &run.plan, &STUB_FORMATTER, None)
            .expect("branch")
            .as_str()
            .to_owned();
        git(&fx.root, &["check-ref-format", "--branch", &branch]);
        let leaf = branch.rsplit('/').next().expect("leaf");
        leaf.rsplit_once('-').expect("hash suffix").0.to_owned()
    };

    // "<name>-1.0.1" is cut to 48 characters; a trailing '-' left by the cut is trimmed.
    assert_eq!(leaf_without_hash(&"a".repeat(47)), "a".repeat(47));
    assert_eq!(leaf_without_hash(&"a".repeat(48)), "a".repeat(48));
    assert_eq!(leaf_without_hash(&"a".repeat(60)), "a".repeat(48));
    // A cut that ends in ".lock" would be a reserved ref name.
    assert_eq!(
        leaf_without_hash(&format!("{}.lock", "a".repeat(43))),
        format!("{}-lock", "a".repeat(43))
    );
}

// --- cleanup hints and message text ---

#[test]
fn test_pr_error_text_names_the_cleanup_for_each_step() {
    let failed = |step: Step| {
        PrError::ToolFailed {
            tool: Tool::Git,
            step,
            code: Some(7),
        }
        .to_string()
    };

    for step in [Step::CreateRequest, Step::Push, Step::SwitchBack] {
        let text = failed(step);
        assert!(text.contains("git switch"), "{step:?}: {text}");
        assert!(
            text.contains("git push origin --delete"),
            "{step:?}: {text}"
        );
    }
    for step in [Step::Stage, Step::Commit] {
        let text = failed(step);
        assert!(text.contains("git branch -D"), "{step:?}: {text}");
        assert!(
            !text.contains("git push origin --delete"),
            "{step:?}: {text}"
        );
    }
    for step in [Step::Diff, Step::Status, Step::Switch, Step::Restore] {
        let text = failed(step);
        assert!(!text.contains("git switch"), "{step:?}: {text}");
        assert!(!text.contains("--delete"), "{step:?}: {text}");
    }
    assert!(failed(Step::Diff).contains("exit status 7"));
    let by_signal = PrError::ToolFailed {
        tool: Tool::Git,
        step: Step::Diff,
        code: None,
    }
    .to_string();
    assert!(by_signal.contains("terminated by a signal"), "{by_signal}");
}

#[test]
fn test_pr_error_interrupted_text_names_the_phase() {
    for (phase, word) in [
        (PrPhase::Preflight, "preflight"),
        (PrPhase::Update, "update"),
        (PrPhase::Publish, "publishing"),
    ] {
        let text = PrError::Interrupted { phase }.to_string();
        assert!(text.contains(word), "{phase:?}: {text}");
    }
}

#[tokio::test]
async fn test_open_without_the_host_cli_after_the_push_names_the_remote_branch_cleanup() {
    for (host, tool) in [(PrHost::Github, Tool::Gh), (PrHost::Gitlab, Tool::Glab)] {
        let fx = Fixture::new();
        let ctx = fx.ctx("Cargo.toml").await;
        fx.write("Cargo.toml", "bumped\n");

        let result = publish_to(&ctx, &settled_run(regenerated(&fx, "Cargo.lock")), host).await;

        let failure = error(result);
        assert_matches!(&failure, PrError::ToolMissing { tool: found } if *found == tool);
        assert!(
            failure.to_string().contains("git push origin --delete"),
            "{failure}"
        );
        assert!(failure.to_string().contains("git switch"), "{failure}");
    }
}

// --- the update phase has exactly one signal listener ---

const CHILD_MARKER: &str = "DEPS_CLI_UPDATE_SIGINT_CHILD";
const CHILD_TEST: &str =
    "test_update_phase_sigint_is_always_an_interrupted_phase_never_a_failed_lockfile";

/// The fake `cargo` must come first on `PATH`, and the process environment cannot be changed
/// from safe code, so the test re-runs itself as a child with that `PATH` and the marker set.
#[tokio::test]
async fn test_update_phase_sigint_is_always_an_interrupted_phase_never_a_failed_lockfile() {
    let Some(shim_dir) = std::env::var_os(CHILD_MARKER) else {
        run_as_child_with_a_slow_fake_cargo();
        return;
    };
    interrupt_the_update_phase_repeatedly(&PathBuf::from(shim_dir)).await;
}

fn run_as_child_with_a_slow_fake_cargo() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("shim dir");
    let shim = dir.path().join("cargo");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\nsleep 30 &\necho $! > '{}'\nwait\n",
            dir.path().join("cargo.pid").display()
        ),
    )
    .expect("write shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(dir.path().to_path_buf()).chain(std::env::split_paths(&inherited)),
    )
    .expect("join PATH");
    let module = module_path!().split_once("::").expect("crate prefix").1;

    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            &format!("{module}::{CHILD_TEST}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_MARKER, dir.path())
        .env("PATH", path)
        .output()
        .expect("re-run the test binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cargo_ecosystem() -> Arc<dyn Ecosystem> {
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, cache, &runtime);
    registry.get(EcosystemId::Cargo).expect("cargo registered")
}

async fn interrupt_the_update_phase_repeatedly(shim_dir: &Path) {
    let project = tempfile::tempdir().expect("project");
    let manifest = project.path().join("Cargo.toml");
    std::fs::write(&manifest, "[package]\nname = \"p\"\nversion = \"0.1.0\"\n").expect("manifest");
    std::fs::write(project.path().join("Cargo.lock"), "# lock\n").expect("lock");
    let ecosystem = cargo_ecosystem();
    let uri = Url::from_file_path(&manifest).expect("file url");
    let display = PathBuf::from("Cargo.toml");
    let original_text = std::fs::read_to_string(&manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display,
        uri: &uri,
        original: crate::update::regen::OriginalManifest::new(&original_text),
    };
    let gate = RegenerationGate::new(LockfileMode::Regenerate, DryRun::No, NetworkMode::Online);
    let plan = UpdatePlan {
        items: vec![item("serde", "1.0.0", applied("1.2.0"))],
    };
    let pid_file = shim_dir.join("cargo.pid");
    let mut signals = PrSignals::install();

    for round in 0..20 {
        let _ = std::fs::remove_file(&pid_file);
        let guarded = signals.guard(
            PrPhase::Update,
            regenerate_lockfile_unlistened(plan.clone(), &target, gate, project.path()),
        );
        let interrupter = async {
            let mut sleeper = None;
            for _ in 0..400 {
                if let Ok(text) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = text.trim().parse::<u32>()
                {
                    sleeper = Some(pid);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let sleeper = sleeper.expect("the fake cargo never started");
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
                .expect("raise SIGINT");
            sleeper
        };

        let (result, sleeper) = tokio::join!(guarded, interrupter);

        match result {
            Err(PrError::Interrupted {
                phase: PrPhase::Update,
            }) => {}
            Err(other) => panic!("round {round}: unexpected error {other:?}"),
            Ok(run) => panic!(
                "round {round}: the signal produced a finished run ({:?}) instead of an interrupted phase",
                run.lockfile
            ),
        }
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &sleeper.to_string()])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

// --- member lock files and companion trees ---

fn regenerated_with(fx: &Fixture, lock: &str, companions: Vec<Companion>) -> LockfileOutcome {
    LockfileOutcome::Regenerated {
        lockfile: DisplayLockPath::for_test(lock, &fx.root.join(lock)),
        tool: Program::Cargo,
        pins: Vec::new(),
        companions,
    }
}

fn vendor_tree(fx: &Fixture) {
    fx.write("app/vendor/a.txt", "initial\n");
    fx.write("app/vendor/modules.txt", "initial\n");
    commit_all(fx, "vendor");
    git(&fx.root, &["push", "origin", "main"]);
}

fn vendored_run(fx: &Fixture) -> UpdateRun {
    settled_run(regenerated_with(
        fx,
        "app/Cargo.lock",
        vec![Companion::Tree(fx.root.join("app/vendor"))],
    ))
}

fn committed_files(fx: &Fixture) -> Vec<String> {
    git(&fx.root, &["show", "--name-only", "--format=", "HEAD"])
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn test_describe_a_member_run_publishes_the_root_lock_file() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;

    let text = text_of(&ctx, &settled_run(regenerated(&fx, "Cargo.lock")));

    assert_eq!(scope_files(&text), ["app/Cargo.toml", "Cargo.lock"]);
}

#[tokio::test]
async fn test_open_commits_a_member_manifest_with_the_root_lock_file() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &settled_run(regenerated(&fx, "Cargo.lock"))).await;

    assert_matches!(result, Ok(PrOutcome::Opened(_)));
    assert_eq!(committed_files(&fx), ["Cargo.lock", "app/Cargo.toml"]);
}

#[tokio::test]
async fn test_restore_reverts_a_members_root_lock_file_and_nothing_else() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked\n");
    fx.write("other/file.txt", "edited by someone else\n");
    let run = run_with(
        vec![requires_lockfile_item("foo")],
        regenerated(&fx, "Cargo.lock"),
    );

    restore(&ctx, &run).await.expect("restore");

    assert_eq!(fx.status(), [" M other/file.txt"]);
}

#[tokio::test]
async fn test_restore_leaves_an_untracked_lock_file_alone() {
    let fx = Fixture::new();
    ignore_lock(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("Cargo.lock", "relocked\n");
    let run = run_with(
        vec![requires_lockfile_item("foo")],
        regenerated(&fx, "Cargo.lock"),
    );

    restore(&ctx, &run).await.expect("restore");

    assert_eq!(fx.status(), Vec::<String>::new());
    assert_eq!(fx.read("Cargo.lock"), "relocked\n");
}

#[tokio::test]
async fn test_open_stages_a_companion_tree_whole_and_never_lists_its_contents() {
    let fx = Fixture::new();
    vendor_tree(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write("app/vendor/a.txt", "revendored\n");
    fx.write("app/vendor/new.txt", "added\n");
    fx.write("app/untracked.txt", "never committed\n");
    gh_shim(&fx, URL);

    let result = publish(&ctx, &vendored_run(&fx)).await;

    assert_matches!(result, Ok(PrOutcome::Opened(_)));
    assert_eq!(
        committed_files(&fx),
        [
            "app/Cargo.lock",
            "app/Cargo.toml",
            "app/vendor/a.txt",
            "app/vendor/new.txt"
        ]
    );
}

#[tokio::test]
async fn test_restore_reverts_a_companion_tree_and_removes_its_untracked_residue() {
    let fx = Fixture::new();
    vendor_tree(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/vendor/a.txt", "revendored\n");
    fx.write("app/vendor/new.txt", "added\n");
    fx.write("app/untracked.txt", "keep me\n");

    restore(&ctx, &vendored_run(&fx)).await.expect("restore");

    assert_eq!(fx.status(), Vec::<String>::new());
    assert!(!fx.root.join("app/vendor/new.txt").exists());
    assert_eq!(fx.read("app/untracked.txt"), "keep me\n");
}

#[tokio::test]
async fn test_require_tracked_tree_accepts_a_tracked_directory_only() {
    let fx = Fixture::new();
    vendor_tree(&fx);
    fx.write("loose/file.txt", "untracked\n");
    let ctx = fx.ctx("app/Cargo.toml").await;

    assert_matches!(
        require_tracked_tree(&ctx, &fx.root.join("app/vendor")).await,
        Ok(())
    );
    for tree in ["loose", "missing"] {
        assert_matches!(
            require_tracked_tree(&ctx, &fx.root.join(tree)).await,
            Err(PrError::UntrackedTree { .. }),
            "{tree}"
        );
    }
}

#[tokio::test]
async fn test_open_refuses_a_publish_set_too_large_for_one_command_line_before_staging() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    let companions = (0..300)
        .map(|index| {
            let name = format!("big/{}{index}.txt", "x".repeat(90));
            fx.write(&name, "generated\n");
            Companion::File(fx.root.join(name))
        })
        .collect();
    let run = settled_run(regenerated_with(&fx, "Cargo.lock", companions));
    gh_shim(&fx, URL);

    let result = publish(&ctx, &run).await;

    assert_matches!(error(result), PrError::PublishSetTooLarge);
    assert_eq!(fx.head(), "main");
    assert_eq!(git(&fx.root, &["diff", "--cached", "--name-only"]), "");
}
