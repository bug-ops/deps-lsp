//! #2102 acceptance (publishing): what `--open-pr` stages, restores and describes for a Gradle
//! lock-layout migration (`Companion::Created` / `Companion::Removed`).
//!
//! Written tests-first against the final plan: created files are staged by literal path (a
//! gitignored one fails closed at `Step::Stage`), a removal is staged like an edit, `restore`
//! deletes created files with `git clean -f -x` and brings removed files back, `check_bound`
//! counts created files, and the PR body has a "Lock layout migration" section.
//! Declared in `update/pr/mod.rs` as `#[cfg(all(test, unix))] mod lock_migration_tests;`.
//! Shares `acceptance_tests`'s fixture; the small helpers below mirror `publish_safety_tests`'s
//! private ones.

#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::assert_matches;

use deps_core::EcosystemId;

use super::acceptance_tests::{Fixture, STUB_FORMATTER, URL, error, git};
use super::git::Step;
use super::{
    BranchCheck, PrError, PrHost, PrOutcome, PullRequestText, Readiness, RepoContext, branch_for,
    check_branch, describe, open, readiness, restore,
};
use crate::update::group_tests::{applied, item};
use crate::update::regen::{Companion, DisplayLockPath, LockfileOutcome, Program, Removal};
use crate::update::{UpdatePlan, UpdateRun};

const CREATED: &str = "other/created.lockfile";
const IGNORED: &str = "other/ignored.lockfile";
const REMOVED: &str = "other/file.txt";

fn commit_all(fx: &Fixture, message: &str) {
    git(&fx.root, &["add", "--all"]);
    git(&fx.root, &["commit", &format!("--message={message}")]);
}

fn ignore_generated_locks(fx: &Fixture) {
    fx.write(".gitignore", "ignored.lockfile\n");
    commit_all(fx, "ignore a generated lock");
    git(&fx.root, &["push", "origin", "main"]);
}

fn gh_shim(fx: &Fixture) {
    fx.shim(
        "gh",
        &format!("echo 'Creating pull request...'\nprintf '{URL}\\n'\n"),
    );
}

fn migration_run(fx: &Fixture, companions: Vec<Companion>) -> UpdateRun {
    UpdateRun {
        plan: UpdatePlan {
            items: vec![item("serde", "1.0.0", applied("1.2.0"))],
        },
        lockfile: LockfileOutcome::Regenerated {
            lockfile: DisplayLockPath::for_test("app/Cargo.lock", &fx.root.join("app/Cargo.lock")),
            tool: Program::Gradle,
            pins: Vec::new(),
            companions,
        },
    }
}

fn created(fx: &Fixture, rel: &str) -> Companion {
    Companion::Created(fx.root.join(rel))
}

fn removed(fx: &Fixture, rel: &str) -> Companion {
    removed_as(fx, rel, Removal::Migrated)
}

fn removed_as(fx: &Fixture, rel: &str, removal: Removal) -> Companion {
    Companion::Removed {
        path: fx.root.join(rel),
        removal,
    }
}

fn text_of(ctx: &RepoContext, run: &UpdateRun) -> PullRequestText {
    let Readiness::Ready(publishable) = readiness(run) else {
        panic!("the run must be publishable");
    };
    describe(ctx, &publishable, None)
}

async fn publish(ctx: &RepoContext, run: &UpdateRun) -> Result<PrOutcome, PrError> {
    let proposed = branch_for(ctx, EcosystemId::Cargo, &run.plan, &STUB_FORMATTER, None)
        .expect("a proposed item");
    let Ok(BranchCheck::Free(free)) = check_branch(ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(ctx, run);
    open(ctx, PrHost::Github, free, &text).await
}

fn committed_files(fx: &Fixture) -> Vec<String> {
    let mut files: Vec<String> = git(&fx.root, &["show", "--name-only", "--format=", "HEAD"])
        .lines()
        .map(str::to_owned)
        .collect();
    files.sort();
    files
}

#[tokio::test]
async fn test_open_commits_created_files_and_legacy_removals() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write(CREATED, "created\n");
    std::fs::remove_file(fx.root.join(REMOVED)).expect("remove the legacy file");
    fx.write("app/untracked.txt", "never committed\n");
    gh_shim(&fx);
    let run = migration_run(&fx, vec![created(&fx, CREATED), removed(&fx, REMOVED)]);

    let result = publish(&ctx, &run).await;

    assert_matches!(result, Ok(PrOutcome::Opened(_)));
    assert_eq!(
        committed_files(&fx),
        ["app/Cargo.lock", "app/Cargo.toml", CREATED, REMOVED]
    );
}

#[tokio::test]
async fn test_open_a_gitignored_created_file_fails_closed_at_the_stage_step() {
    let fx = Fixture::new();
    ignore_generated_locks(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write(IGNORED, "created but ignored\n");
    gh_shim(&fx);
    let run = migration_run(&fx, vec![created(&fx, IGNORED)]);

    let result = publish(&ctx, &run).await;

    assert_matches!(
        error(result),
        PrError::ToolFailed {
            step: Step::Stage,
            ..
        }
    );
}

#[tokio::test]
async fn test_restore_removes_created_files_ignored_or_not_and_brings_removed_files_back() {
    let fx = Fixture::new();
    ignore_generated_locks(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write(CREATED, "created\n");
    fx.write(IGNORED, "created but ignored\n");
    std::fs::remove_file(fx.root.join(REMOVED)).expect("remove the legacy file");
    fx.write("app/untracked.txt", "keep me\n");
    let run = migration_run(
        &fx,
        vec![
            created(&fx, CREATED),
            created(&fx, IGNORED),
            removed(&fx, REMOVED),
        ],
    );

    restore(&ctx, &run).await.expect("restore");

    assert!(!fx.root.join(CREATED).exists());
    assert!(!fx.root.join(IGNORED).exists());
    assert_eq!(fx.read(REMOVED), format!("initial {REMOVED}\n"));
    assert_eq!(fx.read("app/untracked.txt"), "keep me\n");
    assert_eq!(fx.status(), Vec::<String>::new());
}

#[tokio::test]
async fn test_open_refuses_a_publish_set_whose_created_files_do_not_fit_one_command_line() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    let companions = (0..300)
        .map(|index| {
            let name = format!("big/{}{index}.lockfile", "x".repeat(90));
            fx.write(&name, "generated\n");
            created(&fx, &name)
        })
        .collect();
    gh_shim(&fx);

    let result = publish(&ctx, &migration_run(&fx, companions)).await;

    assert_matches!(error(result), PrError::PublishSetTooLarge);
    assert_eq!(fx.head(), "main");
    assert_eq!(git(&fx.root, &["diff", "--cached", "--name-only"]), "");
}

#[tokio::test]
async fn test_describe_body_has_a_lock_layout_migration_section_listing_created_and_removed_files()
{
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let run = migration_run(&fx, vec![created(&fx, CREATED), removed(&fx, REMOVED)]);

    let text = text_of(&ctx, &run);

    assert!(text.body.contains("Lock layout migration"), "{}", text.body);
    assert!(text.body.contains("created.lockfile"), "{}", text.body);
    assert!(text.body.contains("file.txt"), "{}", text.body);
}

#[tokio::test]
async fn test_describe_body_lists_the_first_ten_migrated_files_then_counts_the_rest() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let companions = (0..12)
        .map(|index| created(&fx, &format!("other/c{index:02}.lockfile")))
        .collect();

    let text = text_of(&ctx, &migration_run(&fx, companions));

    assert!(text.body.contains("c09.lockfile"), "{}", text.body);
    assert!(!text.body.contains("c10.lockfile"), "{}", text.body);
    assert!(text.body.contains("and 2 more"), "{}", text.body);
}

#[tokio::test]
async fn test_describe_body_without_a_migration_has_no_lock_layout_section() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let run = migration_run(&fx, vec![Companion::File(fx.root.join("other/file.txt"))]);

    let text = text_of(&ctx, &run);

    assert!(
        !text.body.contains("Lock layout migration"),
        "{}",
        text.body
    );
}

#[tokio::test]
async fn test_describe_body_lists_dropped_lock_state_separately_only_for_stale_dropped_files() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let run = migration_run(
        &fx,
        vec![
            created(&fx, CREATED),
            removed(&fx, REMOVED),
            removed_as(&fx, "other/stale.lockfile", Removal::StaleDropped),
            removed_as(&fx, "other/empty.lockfile", Removal::StaleEmpty),
        ],
    );

    let text = text_of(&ctx, &run);

    assert!(text.body.contains("Dropped lock state"), "{}", text.body);
    let (_, dropped) = text
        .body
        .split_once("Dropped lock state")
        .expect("the dropped section");
    assert!(dropped.contains("stale.lockfile"), "{}", text.body);
    assert!(!dropped.contains("empty.lockfile"), "{}", text.body);
    assert!(!dropped.contains("file.txt"), "{}", text.body);
}

#[tokio::test]
async fn test_describe_body_has_no_dropped_lock_state_list_without_a_stale_dropped_file() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let run = migration_run(
        &fx,
        vec![
            removed(&fx, REMOVED),
            removed_as(&fx, "other/empty.lockfile", Removal::StaleEmpty),
        ],
    );

    let text = text_of(&ctx, &run);

    assert!(text.body.contains("Lock layout migration"), "{}", text.body);
    assert!(!text.body.contains("Dropped lock state"), "{}", text.body);
}

#[tokio::test]
async fn test_open_a_failed_stage_of_a_created_file_restores_the_whole_scope_before_any_branch() {
    let fx = Fixture::new();
    ignore_generated_locks(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write(IGNORED, "created but ignored\n");
    std::fs::remove_file(fx.root.join(REMOVED)).expect("remove the legacy file");
    gh_shim(&fx);
    let run = migration_run(&fx, vec![created(&fx, IGNORED), removed(&fx, REMOVED)]);

    let result = publish(&ctx, &run).await;

    assert_matches!(
        error(result),
        PrError::ToolFailed {
            step: Step::Stage,
            ..
        }
    );
    assert_eq!(fx.head(), "main");
    assert_eq!(git(&fx.root, &["diff", "--cached", "--name-only"]), "");
    assert_eq!(fx.status(), Vec::<String>::new());
    assert!(
        !fx.root.join(IGNORED).exists(),
        "the ignored created file must be gone"
    );
    assert_eq!(fx.read(REMOVED), format!("initial {REMOVED}\n"));
    assert_eq!(git(&fx.root, &["branch", "--list", "deps-cli/*"]), "");
    assert!(!fx.record("gh.argv").exists(), "gh must not have run");
    assert!(
        !git(&fx.origin, &["branch", "--list"]).contains("deps-cli/"),
        "nothing was pushed"
    );
}

#[tokio::test]
async fn test_open_a_failed_stage_unstages_and_removes_a_created_file_outside_the_manifest_dir() {
    let fx = Fixture::new();
    ignore_generated_locks(&fx);
    let ctx = fx.ctx("app/Cargo.toml").await;
    fx.write("app/Cargo.toml", "bumped\n");
    fx.write("app/Cargo.lock", "relocked\n");
    fx.write(CREATED, "created, not ignored\n");
    fx.write(IGNORED, "created but ignored\n");
    gh_shim(&fx);
    let run = migration_run(&fx, vec![created(&fx, CREATED), created(&fx, IGNORED)]);

    let result = publish(&ctx, &run).await;

    assert_matches!(
        error(result),
        PrError::ToolFailed {
            step: Step::Stage,
            ..
        }
    );
    assert_eq!(git(&fx.root, &["diff", "--cached", "--name-only"]), "");
    assert_eq!(git(&fx.root, &["status", "--porcelain"]), "");
    assert!(!fx.root.join(CREATED).exists());
    assert!(!fx.root.join(IGNORED).exists());
}
